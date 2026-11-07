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
	protected, err := a.kube.ProtectedNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("listing the protected namespaces: %w", err)
	}
	have, err := a.kube.ListGrants(ctx)
	if err != nil {
		return fmt.Errorf("listing the grants: %w", err)
	}
	return a.reconcile(ctx, desiredGrants(v.claims, protected, a.now()), have)
}

// desiredGrants is one grant per cleared change and protected namespace it names, listing the change's objects in
// that namespace; the newest cleared grant of a namespace is the active one (the admission policy reads exactly one).
func desiredGrants(claims []*token.Claims, protected map[string]map[string]string, now time.Time) []Grant {
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
			if _, ok := protected[ns]; !ok {
				continue // the gate does not protect this namespace: a grant there would mean nothing
			}
			g := Grant{Namespace: ns, Name: c.Subject, Labels: map[string]string{LabelManagedBy: ManagedBy,
				LabelChange: c.Subject, LabelApp: c.Target.App}}
			g.Spec.Subject.Commit, g.Spec.Subject.Tree = c.Subjects.Commit, c.Subjects.TreeRoot
			g.Spec.ExpiresAt = time.Unix(c.Expires, 0).UTC().Format(time.RFC3339)
			g.Spec.Clearance.ID, g.Spec.Clearance.Tier = c.Clearance.ID, c.Tier
			g.Spec.Index = map[string]string{}
			for _, o := range objs {
				group, _, _ := strings.Cut(o.APIVersion, "/")
				if !strings.Contains(o.APIVersion, "/") {
					group = ""
				}
				g.Spec.Objects = append(g.Spec.Objects, GrantObject{Group: group, Kind: o.Kind, Name: o.Name,
					Rendered: o.Rendered, Changed: o.Changed})
				g.Spec.Index[GrantKey(group, o.Kind, o.Name)] = o.Rendered
			}
			sort.Slice(g.Spec.Objects, func(i, j int) bool {
				a, b := g.Spec.Objects[i], g.Spec.Objects[j]
				return GrantKey(a.Group, a.Kind, a.Name) < GrantKey(b.Group, b.Kind, b.Name)
			})
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
		}
		out = append(out, c.g)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Namespace+"/"+out[i].Name < out[j].Namespace+"/"+out[j].Name
	})
	return out
}

func expiryAfter(expiresAt string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, expiresAt)
	return err == nil && now.Before(t)
}

func gkey(g Grant) string { return g.Namespace + "/" + g.Name }

// reconcile makes the cluster's grants the desired ones: deactivate what loses the active label, create and update,
// mark valid, then delete the grants no entry names. Deactivating first means a namespace is never briefly under two
// active grants (every selected grant must pass); it can be briefly under none, which the policy refuses (fail
// closed) and Argo CD retries.
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
	step := func(what string, g Grant, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s grant %s: %w", what, gkey(g), err))
		}
	}
	for _, h := range have { // 1. deactivate what is no longer the active grant of its namespace
		w, ok := wantBy[gkey(h)]
		if !h.Active() || (ok && w.Active()) {
			continue
		}
		if ok {
			if err := a.kube.ApplyGrant(ctx, w); err != nil {
				step("deactivating", w, err)
				continue
			}
			haveBy[gkey(w)] = Grant{Namespace: w.Namespace, Name: w.Name, Labels: w.Labels, Spec: w.Spec, Valid: h.Valid}
			continue
		}
		delete(h.Labels, LabelActive)
		step("deactivating", h, a.kube.ApplyGrant(ctx, h))
	}
	for _, w := range want { // 2. create, update
		h, ok := haveBy[gkey(w)]
		if ok && reflect.DeepEqual(h.Spec, w.Spec) && sameLabels(h.Labels, w.Labels) {
			continue
		}
		if err := a.kube.ApplyGrant(ctx, w); err != nil {
			step("writing", w, err)
			continue
		}
		a.log.Info("grant written", "grant", gkey(w), "active", w.Active())
		haveBy[gkey(w)] = Grant{Namespace: w.Namespace, Name: w.Name, Labels: w.Labels, Spec: w.Spec, Valid: h.Valid}
	}
	for _, w := range want { // 3. valid
		if h := haveBy[gkey(w)]; (h.Valid == nil || !*h.Valid) && expiryAfter(w.Spec.ExpiresAt, a.now()) {
			step("validating", w, a.kube.SetGrantValid(ctx, w.Namespace, w.Name, true))
		}
	}
	for _, h := range have { // 4. remove: no entry names it (revoked, superseded, or its token left the feed)
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
			continue
		}
		if g.Valid == nil || *g.Valid {
			if err := a.kube.SetGrantValid(ctx, g.Namespace, g.Name, false); err != nil {
				errs = append(errs, fmt.Errorf("expiring grant %s: %w", gkey(g), err))
				continue
			}
			a.log.Info("grant expired", "grant", gkey(g))
		}
		if g.Active() {
			delete(g.Labels, LabelActive)
			if err := a.kube.ApplyGrant(ctx, g); err != nil {
				errs = append(errs, fmt.Errorf("deactivating expired grant %s: %w", gkey(g), err))
			}
		}
	}
	return errors.Join(errs...)
}
