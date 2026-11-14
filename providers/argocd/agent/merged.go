package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/token"
)

// The merged grant (G-ARGO-10c): one ClearanceGrant per namespace that a switched Application targets, built from the
// cleared trees of every such Application, so that two or more Applications can share a namespace under the one active
// grant the admission policy reads.
//
// What goes in. For each Application the agent has switched (it asks for protection, carries the agent's marker and
// is on the plugin): the objects of its newest live clearance (the change the core cleared for its app and
// environment, read from the signed feed the agent has verified) that are in the Application's own destination
// namespace. An object of the clearance in another namespace is not granted by this Application, so an Application cannot
// get an object into a namespace except through its own destination. Its older live clearances are carried (as
// the per-change grants carry them: only objects whose hash differs, newest first, at most MaxCarried). A clearance
// that belongs to an Application that is not protected, is not switched, or is not in the feed contributes nothing.
//
// THE RULE: a merged grant never contains an object, or a carried tree, that is not in the verified feed now. Everything
// that keeps a grant (a conflict, an overflow, nothing to merge) keeps the held grant INTERSECTED with what is live: a
// revoked clearance leaves the grant on the next pass, and when nothing is left the grant is written empty (it admits
// nothing), stays active and valid, and the namespace stays labelled. The label comes off only through the opt-out.
//
// Keyed by group, kind and name (the namespace is the grant's own), valued by the rendered hash, which is what the
// admission policy compares. Each object names its owner (`app`). Two Applications whose newest clearances list one key
// are a conflict, whatever the hashes: the incumbent (the owner in the held grant) keeps the key at its own newest
// hash and the newcomer's claim on it is left out; with no incumbent the key is left out for both. Every other key
// merges, so one team's claim never stops another's deploys.

// MergedGrantName is the name of a namespace's merged grant.
const MergedGrantName = "clearance-merged"

// maxGrantObjects is the CRD's maxProperties for spec.objects.
const maxGrantObjects = 2000

// How often a problem that lasts is reported again.
const problemRepeat = 24 * time.Hour

// mergeProblem is a conflict on some keys, or an overflow, in one namespace.
type mergeProblem struct {
	kind    string // "conflict" or "size"
	keys    []string
	apps    []string
	detail  string
	objects []token.Object // at least one
}

// mergeOutcome is what the merge of one namespace came to.
type mergeOutcome struct {
	grant    *Grant // the merged grant to have (nil: none to write and none held)
	problems []mergeProblem
}

type claimant struct {
	app    appClass
	newest *token.Claims
	older  []*token.Claims
	objs   []token.Object // newest's objects in the namespace
}

// newestFirst orders clearances as the per-change grants do: decided, then issued, then id, newest first.
func newestFirst(cs []*token.Claims) {
	sort.Slice(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Clearance.DecidedAt != b.Clearance.DecidedAt {
			return a.Clearance.DecidedAt > b.Clearance.DecidedAt
		}
		if a.IssuedAt != b.IssuedAt {
			return a.IssuedAt > b.IssuedAt
		}
		return a.Subject > b.Subject
	})
}

func keyOf(o token.Object) string {
	group := ""
	if g, _, ok := strings.Cut(o.APIVersion, "/"); ok {
		group = g
	}
	return GrantKey(group, o.Kind, o.Name)
}

func objectsIn(c *token.Claims, ns string) []token.Object {
	var out []token.Object
	for _, o := range c.Objects {
		if o.Namespace == ns {
			out = append(out, o)
		}
	}
	return out
}

// liveHeld is the held merged grant intersected with the verified feed: an object stays only if a clearance in the feed
// (not past its expiry) lists it at that hash in this namespace, and a carried tree only if its change is in the feed,
// with only the objects that change lists. The labels, the expiry and the rest are the held grant's, so an unchanged
// intersection writes nothing.
func (a *Agent) liveHeld(held Grant, ns string, claims []*token.Claims) Grant {
	now := a.now()
	type kh struct{ k, h string }
	live := map[kh]bool{}
	byChange := map[string]map[kh]bool{}
	for _, c := range claims {
		if !time.Unix(c.Expires, 0).After(now) {
			continue
		}
		set := map[kh]bool{}
		for _, o := range objectsIn(c, ns) {
			set[kh{keyOf(o), o.Rendered}] = true
			live[kh{keyOf(o), o.Rendered}] = true
		}
		byChange[c.Subject] = set
	}
	out := held
	out.Labels = map[string]string{}
	for k, v := range held.Labels {
		out.Labels[k] = v
	}
	out.Spec.Objects = map[string]GrantObject{}
	for k, o := range held.Spec.Objects {
		if live[kh{k, o.Rendered}] {
			out.Spec.Objects[k] = o
		}
	}
	out.Spec.Carried = nil
	for _, c := range held.Spec.Carried {
		set, ok := byChange[c.Change]
		if !ok {
			continue
		}
		keep := map[string]GrantObject{}
		for k, o := range c.Objects {
			if set[kh{k, o.Rendered}] {
				keep[k] = o
			}
		}
		if len(keep) > 0 {
			c.Objects = keep
			out.Spec.Carried = append(out.Spec.Carried, c)
		}
	}
	return out
}

// mergeNamespace builds the merged grant of one namespace from the clearances of the Applications that target it.
// held is the grant already in the cluster (nil: none): it names the incumbents, and is what a conflict-free merge
// cannot be built from (an overflow, nothing to merge) is kept as, intersected with the feed.
func (a *Agent) mergeNamespace(ns string, apps []appClass, claims []*token.Claims, held *Grant) mergeOutcome {
	now := a.now()
	keep := func(p ...mergeProblem) mergeOutcome {
		if held == nil {
			return mergeOutcome{problems: p}
		}
		g := a.liveHeld(*held, ns, claims)
		return mergeOutcome{grant: &g, problems: p}
	}
	var cl []claimant
	for _, app := range apps {
		var mine []*token.Claims
		for _, c := range claims {
			if c.Target.App == app.gateApp && c.Target.Env == app.env && c.Target.Cluster == a.cfg.Cluster &&
				time.Unix(c.Expires, 0).After(now) && len(objectsIn(c, ns)) > 0 {
				mine = append(mine, c)
			}
		}
		if len(mine) == 0 {
			continue
		}
		newestFirst(mine)
		cl = append(cl, claimant{app: app, newest: mine[0], older: mine[1:], objs: objectsIn(mine[0], ns)})
	}
	if len(cl) == 0 {
		return keep()
	}
	owners := map[string][]string{} // object key -> Applications whose newest clearance lists it
	objByKey := map[string]token.Object{}
	for _, c := range cl {
		for _, o := range c.objs {
			k := keyOf(o)
			if !contains(owners[k], c.app.key()) {
				owners[k] = append(owners[k], c.app.key())
			}
			objByKey[k] = o
		}
	}
	winner := map[string]string{} // key -> the Application that has it ("" for a clash with no incumbent: nobody)
	var clash []string
	for k, who := range owners {
		if len(who) == 1 {
			winner[k] = who[0]
			continue
		}
		clash = append(clash, k)
		inc := ""
		if held != nil {
			if o, ok := held.Spec.Objects[k]; ok && contains(who, o.App) {
				inc = o.App
			}
		}
		winner[k] = inc
	}
	var problems []mergeProblem
	if len(clash) > 0 {
		sort.Strings(clash)
		p := mergeProblem{kind: "conflict", keys: clash}
		involved := map[string]bool{}
		var lines []string
		for i, k := range clash {
			for _, w := range owners[k] {
				involved[w] = true
			}
			var losers []string
			for _, w := range owners[k] {
				if w != winner[k] {
					losers = append(losers, w)
				}
			}
			if winner[k] != "" {
				lines = append(lines, fmt.Sprintf("%s: %s keeps it, %s is left out", k, winner[k], strings.Join(losers, ", ")))
			} else {
				lines = append(lines, fmt.Sprintf("%s: no incumbent, left out for %s", k, strings.Join(losers, ", ")))
			}
			if i < 50 {
				o := objByKey[k]
				p.objects = append(p.objects, token.Object{APIVersion: o.APIVersion, Kind: o.Kind, Namespace: ns, Name: o.Name})
			}
		}
		for w := range involved {
			p.apps = append(p.apps, w)
		}
		sort.Strings(p.apps)
		if len(lines) > 20 {
			lines = append(lines[:20], fmt.Sprintf("and %d more", len(lines)-20))
		}
		p.detail = fmt.Sprintf("in %s %d key(s) are claimed by more than one protected Application: %s; every other key merges", ns, len(clash), strings.Join(lines, "; "))
		problems = append(problems, p)
	}

	g := Grant{Namespace: ns, Name: MergedGrantName, Labels: map[string]string{LabelManagedBy: ManagedBy, LabelMerged: "true", LabelActive: "true"}}
	g.Spec.Objects = map[string]GrantObject{}
	var expires int64
	var parts []string
	for _, c := range cl {
		mine := false
		for _, o := range c.objs {
			k := keyOf(o)
			if winner[k] != c.app.key() {
				continue
			}
			mine = true
			g.Spec.Objects[k] = GrantObject{Rendered: o.Rendered, Changed: o.Changed, App: c.app.key()}
		}
		if !mine {
			continue
		}
		if c.newest.Expires > expires {
			expires = c.newest.Expires
		}
		if c.newest.Tier > g.Spec.Clearance.Tier {
			g.Spec.Clearance.Tier = c.newest.Tier
		}
		parts = append(parts, c.app.key()+"|"+c.newest.Subject+"|"+c.newest.Subjects.TreeRoot)
	}
	if len(g.Spec.Objects) == 0 {
		return keep(problems...)
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	g.Spec.Subject.Tree = hex.EncodeToString(sum[:])
	g.Spec.ExpiresAt = time.Unix(expires, 0).UTC().Format(time.RFC3339)
	g.Spec.Clearance.ID = "merged"

	// The other live clearances of these Applications ride along as carried trees, minus any key another Application
	// has: an older tree of one cannot admit what another owns.
	var others []carryCand
	for _, c := range cl {
		for _, o := range c.older {
			og := Grant{Namespace: ns, Name: o.Subject}
			og.Spec.Subject.Tree = o.Subjects.TreeRoot
			og.Spec.ExpiresAt = time.Unix(o.Expires, 0).UTC().Format(time.RFC3339)
			og.Spec.Objects = map[string]GrantObject{}
			for _, x := range objectsIn(o, ns) {
				k := keyOf(x)
				if w, ok := winner[k]; ok && w != c.app.key() {
					continue
				}
				og.Spec.Objects[k] = GrantObject{Rendered: x.Rendered, Changed: x.Changed, App: c.app.key()}
			}
			others = append(others, carryCand{og, o.Clearance.DecidedAt, o.IssuedAt})
		}
	}
	g.Spec.Carried = carriedTrees(g, others, now)

	if len(g.Spec.Objects) > maxGrantObjects {
		return keep(append(problems, mergeProblem{kind: "size", keys: []string{ns},
			objects: []token.Object{{APIVersion: "clearance.hangar.io/v1", Kind: "ClearanceGrant", Namespace: ns, Name: MergedGrantName}},
			detail:  fmt.Sprintf("the merged grant of %s would list %d objects, over the limit of %d: refused, the held grant stays (only what is live)", ns, len(g.Spec.Objects), maxGrantObjects)})...)
	}
	raw, _ := json.Marshal(g.Spec)
	if len(raw) > a.cfg.OptIn.MaxGrantBytes {
		return keep(append(problems, mergeProblem{kind: "size", keys: []string{ns},
			objects: []token.Object{{APIVersion: "clearance.hangar.io/v1", Kind: "ClearanceGrant", Namespace: ns, Name: MergedGrantName}},
			detail:  fmt.Sprintf("the merged grant of %s would be %d bytes, over the limit of %d: refused, the held grant stays (only what is live)", ns, len(raw), a.cfg.OptIn.MaxGrantBytes)})...)
	}
	return mergeOutcome{grant: &g, problems: problems}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// applyMerged replaces, in the per-change grants the feed calls for, the namespaces a switched Application targets:
//
//   - a merged grant to write: it replaces every per-change grant of the namespace (one active grant per namespace);
//   - a refusal or nothing to merge, with a merged grant already in the cluster: that grant stays, intersected with the
//     feed (liveHeld), and the per-change grants of the namespace stay out of the way;
//   - a namespace labelled protected whose merged grant nothing else replaces: the grant stays, intersected with the
//     feed, even when it is empty: it admits nothing and the label stays;
//   - no merged grant, written or held: the namespace keeps the per-change grants it had.
//
// It also returns the problems, so they are reported.
func (a *Agent) applyMerged(want []Grant, have []Grant, v *optView, claims []*token.Claims, labelled map[string]map[string]string) (out []Grant, problems map[string][]mergeProblem) {
	problems = map[string][]mergeProblem{}
	held := map[string]Grant{}
	for _, g := range have {
		if g.Name == MergedGrantName {
			held[g.Namespace] = g
		}
	}
	replace := map[string]*Grant{} // namespace -> its grant
	for ns, apps := range v.merged {
		var h *Grant
		if x, ok := held[ns]; ok {
			h = &x
		}
		res := a.mergeNamespace(ns, apps, claims, h)
		if len(res.problems) > 0 {
			problems[ns] = res.problems
		}
		if res.grant != nil {
			replace[ns] = res.grant
		}
	}
	// A namespace the agent labelled is never left without its merged grant while the label is on: the grant stays
	// (what is live of it) until the label is off, which is the order of every removal. Likewise one an operator labelled.
	for ns, h := range held {
		if _, ok := replace[ns]; ok {
			continue
		}
		if labelled[ns][LabelProtected] == "true" && labelled[ns][LabelProtectedBy] == ProtectedByOptIn {
			g := a.liveHeld(h, ns, claims)
			replace[ns] = &g
		}
	}
	wanted := map[string]bool{} // namespaces the per-change grants still call for
	for _, g := range want {
		if _, ok := replace[g.Namespace]; ok {
			continue
		}
		wanted[g.Namespace] = true
		out = append(out, g)
	}
	for ns, h := range held {
		if _, ok := replace[ns]; !ok && !wanted[ns] && labelled[ns][LabelProtected] == "true" {
			g := a.liveHeld(h, ns, claims)
			replace[ns] = &g
		}
	}
	names := make([]string, 0, len(replace))
	for ns := range replace {
		names = append(names, ns)
	}
	sort.Strings(names)
	for _, ns := range names {
		out = append(out, *replace[ns])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace+"/"+out[i].Name < out[j].Namespace+"/"+out[j].Name })
	return out, problems
}

// reportMergeProblems tells the core, through the exception path (deploy.exception, out-of-band), about each conflict
// and overflow: once when it starts, again every 24 hours while it lasts (saying for how long), and once when it
// clears. What it needs to know (since when, and when last) is in the state ConfigMap, so a restart neither forgets a
// problem nor reports it again at once.
func (a *Agent) reportMergeProblems(ctx context.Context, problems map[string][]mergeProblem, v *optView) error {
	var errs []error
	type cur struct {
		fp string
		ns string
		p  mergeProblem
	}
	var now []cur
	for ns, ps := range problems {
		for _, p := range ps {
			sum := sha256.Sum256([]byte(p.kind + "|" + strings.Join(p.keys, ",") + "|" + strings.Join(p.apps, ",")))
			now = append(now, cur{"merge|" + ns + "|" + p.kind + "|" + hex.EncodeToString(sum[:8]), ns, p})
		}
	}
	sort.Slice(now, func(i, j int) bool { return now[i].fp < now[j].fp })
	have := map[string]bool{}
	post := func(ns, result string, p mergeProblem, detail string) error {
		env, app := a.cfg.Environment, ns
		if len(v.merged[ns]) > 0 {
			env, app = v.merged[ns][0].env, v.merged[ns][0].gateApp
		}
		objs := make([]map[string]any, 0, len(p.objects))
		for _, o := range p.objects {
			objs = append(objs, map[string]any{"apiVersion": o.APIVersion, "kind": o.Kind, "namespace": o.Namespace, "name": o.Name})
		}
		principal := "Applications " + strings.Join(p.apps, ", ")
		if p.kind == "size" {
			principal = "argocd-agent (merged grant)"
		}
		req := &client.RecordRequest{Kind: "deploy.exception", Record: client.ProviderEvent{
			Principal:   client.String(truncate(principal, 500)),
			Target:      client.String("namespace/" + ns),
			App:         client.String(app),
			Result:      client.String(result),
			Destination: map[string]any{"cluster": a.cfg.Cluster, "environment": env, "namespace": ns},
			Source:      map[string]any{"provider": a.Provider()},
			Exception: map[string]any{"kind": "out-of-band", "objects": objs, "detected_at": a.now().UTC().Format(time.RFC3339),
				"detail": truncate(detail, 1000)}}}
		ref, err := a.core.Record(ctx, req)
		if err != nil {
			return fmt.Errorf("posting deploy.exception for the merged grant of %s: %w", ns, err)
		}
		a.log.Warn("merged grant problem reported", "namespace", ns, "problem", p.kind, "result", result, "seq", ref.Seq)
		return nil
	}
	title := func(p mergeProblem) string {
		if p.kind == "size" {
			return "merged grant over the size limit"
		}
		return "two protected Applications claim one object"
	}
	for _, c := range now {
		have[c.fp] = true
		a.mu.Lock()
		st, known := a.st.Problems[c.fp]
		a.mu.Unlock()
		stamp := a.now().UTC().Format(time.RFC3339)
		switch {
		case !known:
			if err := post(c.ns, title(c.p), c.p, c.p.detail); err != nil {
				errs = append(errs, err)
				continue
			}
			st = ProblemState{Namespace: c.ns, Kind: c.p.kind, Since: stamp, Last: stamp, Detail: truncate(c.p.detail, 300)}
		default:
			last, _ := time.Parse(time.RFC3339, st.Last)
			if a.now().Sub(last) < problemRepeat {
				continue
			}
			since, _ := time.Parse(time.RFC3339, st.Since)
			lasted := a.now().Sub(since).Round(time.Minute)
			if err := post(c.ns, title(c.p)+" (still unresolved, "+lasted.String()+")", c.p, fmt.Sprintf("has lasted %s since %s: %s", lasted, st.Since, c.p.detail)); err != nil {
				errs = append(errs, err)
				continue
			}
			st.Last = stamp
		}
		a.mu.Lock()
		a.st.Problems[c.fp] = st
		err := a.saveLocked(ctx)
		a.mu.Unlock()
		if err != nil {
			errs = append(errs, err)
		}
	}
	// Problems that have gone: once each.
	a.mu.Lock()
	var gone []string
	for fp := range a.st.Problems {
		if !have[fp] {
			gone = append(gone, fp)
		}
	}
	a.mu.Unlock()
	sort.Strings(gone)
	for _, fp := range gone {
		a.mu.Lock()
		st := a.st.Problems[fp]
		a.mu.Unlock()
		since, _ := time.Parse(time.RFC3339, st.Since)
		lasted := a.now().Sub(since).Round(time.Minute)
		p := mergeProblem{kind: st.Kind, apps: nil, objects: []token.Object{{APIVersion: "clearance.hangar.io/v1", Kind: "ClearanceGrant", Namespace: st.Namespace, Name: MergedGrantName}}}
		if err := post(st.Namespace, "merged grant "+st.Kind+" cleared after "+lasted.String(), p, "cleared; it began "+st.Since+": "+st.Detail); err != nil {
			errs = append(errs, err)
			continue
		}
		a.mu.Lock()
		delete(a.st.Problems, fp)
		err := a.saveLocked(ctx)
		a.mu.Unlock()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
