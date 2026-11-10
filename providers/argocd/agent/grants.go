package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/token"
)

type keyCache struct {
	set token.KeySet
	at  time.Time
}

const keyMaxAge = 5 * time.Minute

// verificationKeys is GET /v1/keys, cached; force refetches (an unknown key id: the core rotated).
func (a *Agent) verificationKeys(ctx context.Context, force bool) (token.KeySet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !force && a.keys.set != nil && a.now().Sub(a.keys.at) < keyMaxAge {
		return a.keys.set, nil
	}
	raw, err := a.feeds.Keys(ctx)
	if err != nil {
		return nil, err
	}
	set, err := token.ParseJWKS(raw)
	if err != nil {
		return nil, err
	}
	a.keys = keyCache{set, a.now()}
	return set, nil
}

// feedBody is GET /v1/grant-feeds/{cluster}: the signed feed and the tokens listed beside it.
type feedBody struct {
	Feed   json.RawMessage `json:"feed"`
	Tokens []struct {
		ChangeID string         `json:"change_id"`
		DSSE     token.Envelope `json:"dsse"`
	} `json:"tokens"`
}

// verified is a feed that passed every check, with the claims of each token.
type verified struct {
	feed   *token.Feed
	claims []*token.Claims
}

// verifyFeed does steps 1 to 4 of docs/gate.md (The signed grant feed): the feed's signature, cluster, freshness
// and seq within its epoch, the tokens beside it exactly the entries, each token's signature and binding. Any failure
// leaves the grants alone.
func (a *Agent) verifyFeed(ctx context.Context, body []byte) (*verified, error) {
	var fb feedBody
	if err := json.Unmarshal(body, &fb); err != nil {
		return nil, fmt.Errorf("the grant feed answer: %w", err)
	}
	a.mu.Lock()
	epoch, seq := a.st.Epoch, a.st.Seq
	a.mu.Unlock()
	opts := token.FeedOptions{Issuer: a.cfg.Issuer, Cluster: a.cfg.Cluster, MinSeq: seq, Epoch: epoch, Now: a.now}
	var feed *token.Feed
	var keys token.KeySet
	for try := 0; ; try++ {
		var err error
		if keys, err = a.verificationKeys(ctx, try > 0); err != nil {
			return nil, fmt.Errorf("the verification keys: %w", err)
		}
		if feed, err = token.VerifyFeed(fb.Feed, keys, opts); err == nil {
			break
		} else if !errors.Is(err, token.ErrUnknownKey) || try > 0 {
			return nil, err
		}
	}
	if feed.Epoch == "" {
		return nil, errors.New("the grant feed names no epoch (a core older than this agent): refused")
	}
	envs := map[string]token.Envelope{}
	for _, t := range fb.Tokens {
		if _, dup := envs[t.ChangeID]; dup {
			return nil, fmt.Errorf("%w: %s listed twice", token.ErrFeedIncomplete, t.ChangeID)
		}
		envs[t.ChangeID] = t.DSSE
	}
	if err := feed.Match(envs); err != nil {
		return nil, err
	}
	out := &verified{feed: feed}
	for _, e := range feed.Entries {
		raw, err := json.Marshal(envs[e.ChangeID])
		if err != nil {
			return nil, err
		}
		c, err := token.Verify(ctx, raw, keys, token.Options{Issuer: a.cfg.Issuer, Now: a.now,
			Expect: token.Expect{Cluster: a.cfg.Cluster}})
		if err != nil {
			return nil, fmt.Errorf("token of %s: %w", e.ChangeID, err)
		}
		if c.Subject != e.ChangeID || c.Nonce != e.Nonce {
			return nil, fmt.Errorf("token of %s: is not the entry's issuance", e.ChangeID)
		}
		out.claims = append(out.claims, c)
	}
	return out, nil
}

// remember keeps the feed's epoch beside its seq (a new epoch restarts at 1).
func (a *Agent) remember(ctx context.Context, f *token.Feed) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st.Epoch == f.Epoch && a.st.Seq == f.Seq {
		return nil
	}
	if a.st.Epoch != f.Epoch && a.st.Epoch != "" {
		a.log.Warn("the grant feed has a new epoch (the core's database was rebuilt or restored): seq starts again",
			"from", a.st.Epoch, "to", f.Epoch, "seq", f.Seq)
	}
	a.st.Epoch, a.st.Seq = f.Epoch, f.Seq
	return a.saveLocked(ctx)
}

// SyncGrants is one pass of the grant loop. It reads and verifies the feed and writes the grants from it. Whatever
// it finds, it then expires the grants whose time has passed, on the agent's own clock: a feed that cannot be read
// changes no grant, and the grants run out.
func (a *Agent) SyncGrants(ctx context.Context) error {
	err := a.fetchAndApply(ctx)
	if xerr := a.expireGrants(ctx); xerr != nil {
		err = errors.Join(err, xerr)
	}
	return err
}

func (a *Agent) fetchAndApply(ctx context.Context) error {
	body, err := a.feeds.Feed(ctx, a.cfg.Cluster)
	if err != nil {
		return fmt.Errorf("reading the grant feed (grants stay as they are): %w", err)
	}
	v, err := a.verifyFeed(ctx, body)
	if err != nil {
		return fmt.Errorf("the grant feed is refused (grants stay as they are): %w", err)
	}
	if err := a.remember(ctx, v.feed); err != nil {
		return fmt.Errorf("saving the feed's epoch and seq: %w", err)
	}
	have, err := a.kube.ListGrants(ctx)
	if err != nil {
		return fmt.Errorf("listing the grants: %w", err)
	}
	return a.reconcile(ctx, desiredGrants(v.claims, a.now()), have)
}

// desiredGrants is one grant per cleared change and protected namespace it names, listing the change's objects in
// that namespace; the newest cleared grant of a namespace is the active one (the admission policy reads exactly one).
func desiredGrants(claims []*token.Claims, now time.Time) []Grant {
	type cand struct {
		g       Grant
		decided string
		iat     int64
	}
	var all []cand
	for _, c := range claims {
		byNS := map[string][]token.Object{}
		for _, o := range c.Objects {
			if o.Namespace != "" {
				byNS[o.Namespace] = append(byNS[o.Namespace], o)
			}
		}
		for ns, objs := range byNS {
			g := Grant{Namespace: ns, Name: c.Subject, Labels: map[string]string{LabelManagedBy: ManagedBy,
				LabelChange: c.Subject, LabelApp: c.Target.App}}
			g.Spec.Subject.Commit, g.Spec.Subject.Tree = c.Subjects.Commit, c.Subjects.TreeRoot
			g.Spec.ExpiresAt = time.Unix(c.Expires, 0).UTC().Format(time.RFC3339)
			g.Spec.Clearance.ID, g.Spec.Clearance.Tier = c.Clearance.ID, c.Tier
			g.Spec.Objects = map[string]GrantObject{}
			for _, o := range objs {
				group, _, _ := strings.Cut(o.APIVersion, "/")
				if !strings.Contains(o.APIVersion, "/") {
					group = ""
				}
				g.Spec.Objects[GrantKey(group, o.Kind, o.Name)] = GrantObject{Rendered: o.Rendered, Changed: o.Changed}
			}
			all = append(all, cand{g, c.Clearance.DecidedAt, c.IssuedAt})
		}
	}
	newest := map[string]int{}
	for i, c := range all {
		j, ok := newest[c.g.Namespace]
		if !ok {
			newest[c.g.Namespace] = i
			continue
		}
		b := all[j]
		if c.decided > b.decided || (c.decided == b.decided && (c.iat > b.iat || (c.iat == b.iat && c.g.Name > b.g.Name))) {
			newest[c.g.Namespace] = i
		}
	}
	out := make([]Grant, 0, len(all))
	for i, c := range all {
		if newest[c.g.Namespace] == i && expiryAfter(c.g.Spec.ExpiresAt, now) {
			c.g.Labels[LabelActive] = "true"
			// The active grant also carries the namespace's other live cleared trees (see carriedTrees).
			var others []carryCand
			for j, o := range all {
				if j != i && o.g.Namespace == c.g.Namespace {
					others = append(others, carryCand{o.g, o.decided, o.iat})
				}
			}
			c.g.Spec.Carried = carriedTrees(c.g, others, now)
		}
		out = append(out, c.g)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Namespace+"/"+out[i].Name < out[j].Namespace+"/"+out[j].Name
	})
	return out
}

type carryCand struct {
	g       Grant
	decided string
	iat     int64
}

// carriedTrees is what the active grant adds to its own objects: the objects of every other cleared change of the
// namespace that is still live in the feed and not past its own expiresAt on the agent's clock, newest first, at most
// MaxCarried changes. Only an object whose hash the active grant does not list itself is kept, and a change left with
// none is not listed. The admission policy admits an object at any hash the active grant or one carried entry lists
// for it, so the tree that is still running (or was cleared and has not merged) is not refused while a newer change
// is the active one. This is no "any cleared tree": an entry exists only while its change's token is in the signed
// feed (revoked, superseded, exception and expired changes are not), and the agent drops it at its own expiresAt.
func carriedTrees(active Grant, others []carryCand, now time.Time) []CarriedTree {
	sort.Slice(others, func(i, j int) bool {
		a, b := others[i], others[j]
		if a.decided != b.decided {
			return a.decided > b.decided
		}
		if a.iat != b.iat {
			return a.iat > b.iat
		}
		return a.g.Name > b.g.Name
	})
	var out []CarriedTree
	for _, o := range others {
		if !expiryAfter(o.g.Spec.ExpiresAt, now) {
			continue
		}
		extra := map[string]GrantObject{}
		for k, v := range o.g.Spec.Objects {
			if mine, ok := active.Spec.Objects[k]; !ok || mine.Rendered != v.Rendered {
				extra[k] = v
			}
		}
		if len(extra) == 0 {
			continue
		}
		out = append(out, CarriedTree{Change: o.g.Name, Tree: o.g.Spec.Subject.Tree, ExpiresAt: o.g.Spec.ExpiresAt, Objects: extra})
		if len(out) == MaxCarried {
			break
		}
	}
	return out
}

func expiryAfter(expiresAt string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, expiresAt)
	return err == nil && now.Before(t)
}

func gkey(g Grant) string { return g.Namespace + "/" + g.Name }

// reconcile makes the cluster's grants the desired ones, in an order that protects the namespaces (the admission
// policy refuses every matched write in a protected namespace that has no active, valid grant, and a second active
// grant is refused):
//
//  1. write every desired grant, a new one without the active label, and an existing active one that stays active as
//     it is; nothing is deactivated yet;
//  2. mark each one valid (status.valid), so that it is ready before it is activated;
//  3. per namespace, deactivate the grant that loses the label and at once activate the one that gains it: the only
//     moment a namespace has no active grant is between these two consecutive calls, and the policy refuses writes
//     there (Argo CD retries). A namespace whose new grant could not be written or validated keeps its old active
//     grant: the flip is skipped;
//  4. delete the grants no entry names (revoked, superseded, or out of the feed).
//
// Grants are written for namespaces whether or not they are labelled protected yet: an operator labels a namespace
// only once its grant is active (docs/gate.md), so the label never lands on a namespace without one.
func (a *Agent) reconcile(ctx context.Context, want, have []Grant) error {
	haveBy := map[string]Grant{}
	for _, g := range have {
		haveBy[gkey(g)] = g
	}
	wantBy := map[string]Grant{}
	for _, g := range want {
		wantBy[gkey(g)] = g
	}
	var errs []error
	failed := map[string]bool{} // namespaces whose desired grants are not all in place
	step := func(what string, g Grant, err error) bool {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s grant %s: %w", what, gkey(g), err))
			failed[g.Namespace] = true
		}
		return err == nil
	}
	pending := map[string]bool{} // namespaces with a winner still to activate
	for _, w := range want {
		if h := haveBy[gkey(w)]; w.Active() && !h.Active() {
			pending[w.Namespace] = true
		}
	}
	for _, w := range want { // 1. write; a grant that is active stays active until its replacement is ready
		h, ok := haveBy[gkey(w)]
		hold := w
		hold.Labels = map[string]string{}
		for k, v := range w.Labels {
			hold.Labels[k] = v
		}
		delete(hold.Labels, LabelActive)
		if ok && h.Active() && (w.Active() || pending[w.Namespace]) {
			hold.Labels[LabelActive] = "true"
			if !w.Active() {
				// Held active only until its replacement is ready: keep the trees it carries, so the running tree is
				// admitted right up to the flip (the replacement carries this grant's own tree from then on).
				hold.Spec.Carried = h.Spec.Carried
			}
		}
		if ok && reflect.DeepEqual(h.Spec, hold.Spec) && sameLabels(h.Labels, hold.Labels) {
			continue
		}
		var werr error
		if ok {
			werr = a.kube.UpdateGrant(ctx, hold, h)
		} else {
			werr = a.kube.CreateGrant(ctx, hold)
		}
		if step("writing", w, werr) {
			a.log.Info("grant written", "grant", gkey(w), "active", hold.Active())
			haveBy[gkey(w)] = Grant{Namespace: w.Namespace, Name: w.Name, Labels: hold.Labels, Spec: hold.Spec, Valid: h.Valid}
		}
	}
	for _, w := range want { // 2. valid
		if h := haveBy[gkey(w)]; (h.Valid == nil || !*h.Valid) && expiryAfter(w.Spec.ExpiresAt, a.now()) {
			if step("validating", w, a.kube.SetGrantValid(ctx, w.Namespace, w.Name, true, "verified against the signed grant feed", a.now())) {
				h.Valid = new(bool)
				*h.Valid = true
				haveBy[gkey(w)] = h
			}
		}
	}
	for _, w := range want { // 3. flip: out, then in, per namespace
		if failed[w.Namespace] || !w.Active() || haveBy[gkey(w)].Active() {
			continue
		}
		for _, h := range have {
			if h.Namespace != w.Namespace || !h.Active() || gkey(h) == gkey(w) {
				continue
			}
			if old, ok := wantBy[gkey(h)]; ok {
				if !step("deactivating", old, a.kube.UpdateGrant(ctx, old, h)) {
					break
				}
			} else {
				off := h
				off.Labels = map[string]string{}
				for k, v := range h.Labels {
					off.Labels[k] = v
				}
				delete(off.Labels, LabelActive)
				if !step("deactivating", h, a.kube.UpdateGrant(ctx, off, h)) {
					break
				}
			}
		}
		if failed[w.Namespace] {
			continue
		}
		if step("activating", w, a.kube.UpdateGrant(ctx, w, haveBy[gkey(w)])) {
			a.log.Info("grant activated", "grant", gkey(w))
		}
	}
	for _, h := range have { // 4. remove: no entry names it
		if _, ok := wantBy[gkey(h)]; !ok {
			if err := a.kube.DeleteGrant(ctx, h.Namespace, h.Name); err != nil {
				step("removing", h, err)
				continue
			}
			a.log.Info("grant removed", "grant", gkey(h))
		}
	}
	return errors.Join(errs...)
}

func sameLabels(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// expireGrants marks every grant whose expiresAt has passed invalid and takes its active label away, on this
// agent's clock (Kubernetes admission has none). It runs whether or not the feed could be read.
func (a *Agent) expireGrants(ctx context.Context) error {
	have, err := a.kube.ListGrants(ctx)
	if err != nil {
		return fmt.Errorf("listing the grants to expire: %w", err)
	}
	var errs []error
	for _, g := range have {
		if expiryAfter(g.Spec.ExpiresAt, a.now()) {
			// Still valid itself: drop the carried trees whose own clearance has run out (the policy has no clock).
			var keep []CarriedTree
			for _, c := range g.Spec.Carried {
				if expiryAfter(c.ExpiresAt, a.now()) {
					keep = append(keep, c)
				}
			}
			if len(keep) != len(g.Spec.Carried) {
				g.Spec.Carried = keep
				if err := a.kube.UpdateGrant(ctx, g, g); err != nil {
					errs = append(errs, fmt.Errorf("dropping expired carried trees of grant %s: %w", gkey(g), err))
					continue
				}
				a.log.Info("carried trees expired", "grant", gkey(g))
			}
			continue
		}
		if g.Valid == nil || *g.Valid {
			if err := a.kube.SetGrantValid(ctx, g.Namespace, g.Name, false, "expired", a.now()); err != nil {
				errs = append(errs, fmt.Errorf("expiring grant %s: %w", gkey(g), err))
				continue
			}
			a.log.Info("grant expired", "grant", gkey(g))
		}
		if g.Active() {
			delete(g.Labels, LabelActive)
			if err := a.kube.UpdateGrant(ctx, g, g); err != nil {
				errs = append(errs, fmt.Errorf("deactivating expired grant %s: %w", gkey(g), err))
			}
		}
	}
	return errors.Join(errs...)
}
