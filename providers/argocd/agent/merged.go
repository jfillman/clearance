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
// Keyed by group, kind and name (the namespace is the grant's own), valued by the rendered hash, which is what the
// admission policy compares. Two Applications whose newest clearances list one object are a conflict, whatever the
// hashes: the namespace gets no new merged grant, the last good one stays, and the core is told.

// MergedGrantName is the name of a namespace's merged grant.
const MergedGrantName = "clearance-merged"

// maxGrantObjects is the CRD's maxProperties for spec.objects.
const maxGrantObjects = 2000

// mergeOutcome is what the merge of one namespace came to.
type mergeOutcome struct {
	grant   *Grant         // the merged grant to have (nil: none to write)
	problem string         // why there is none, when there should be ("conflict", "size")
	detail  string         // for the core's record
	objects []token.Object // the objects the problem is about (at least one)
	apps    []string       // the Applications involved
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

// mergeNamespace builds the merged grant of one namespace from the clearances of the Applications that target it.
func (a *Agent) mergeNamespace(ns string, apps []appClass, claims []*token.Claims) mergeOutcome {
	now := a.now()
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
		return mergeOutcome{}
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
	var clash []string
	for k, who := range owners {
		if len(who) > 1 {
			clash = append(clash, k)
		}
	}
	if len(clash) > 0 {
		sort.Strings(clash)
		out := mergeOutcome{problem: "conflict"}
		involved := map[string]bool{}
		for i, k := range clash {
			for _, w := range owners[k] {
				involved[w] = true
			}
			o := objByKey[k]
			if i < 50 {
				out.objects = append(out.objects, token.Object{APIVersion: o.APIVersion, Kind: o.Kind, Namespace: ns, Name: o.Name})
			}
		}
		for w := range involved {
			out.apps = append(out.apps, w)
		}
		sort.Strings(out.apps)
		out.detail = fmt.Sprintf("%d object(s) in %s are claimed by more than one protected Application (%s); the namespace keeps its last good merged grant",
			len(clash), ns, strings.Join(out.apps, ", "))
		return out
	}

	g := Grant{Namespace: ns, Name: MergedGrantName, Labels: map[string]string{LabelManagedBy: ManagedBy, LabelMerged: "true", LabelActive: "true"}}
	g.Spec.Objects = map[string]GrantObject{}
	var expires int64
	var parts []string
	for _, c := range cl {
		for _, o := range c.objs {
			g.Spec.Objects[keyOf(o)] = GrantObject{Rendered: o.Rendered, Changed: o.Changed}
		}
		if c.newest.Expires > expires {
			expires = c.newest.Expires
		}
		if c.newest.Tier > g.Spec.Clearance.Tier {
			g.Spec.Clearance.Tier = c.newest.Tier
		}
		parts = append(parts, c.app.key()+"|"+c.newest.Subject+"|"+c.newest.Subjects.TreeRoot)
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	g.Spec.Subject.Tree = hex.EncodeToString(sum[:])
	g.Spec.ExpiresAt = time.Unix(expires, 0).UTC().Format(time.RFC3339)
	g.Spec.Clearance.ID = "merged"

	// The other live clearances of these Applications ride along as carried trees, minus any object another
	// Application claims in its newest clearance: an older tree of one cannot admit what another owns.
	var others []carryCand
	for _, c := range cl {
		for _, o := range c.older {
			og := Grant{Namespace: ns, Name: o.Subject}
			og.Spec.Subject.Tree = o.Subjects.TreeRoot
			og.Spec.ExpiresAt = time.Unix(o.Expires, 0).UTC().Format(time.RFC3339)
			og.Spec.Objects = map[string]GrantObject{}
			for _, x := range objectsIn(o, ns) {
				k := keyOf(x)
				if len(owners[k]) > 0 && owners[k][0] != c.app.key() {
					continue
				}
				og.Spec.Objects[k] = GrantObject{Rendered: x.Rendered, Changed: x.Changed}
			}
			others = append(others, carryCand{og, o.Clearance.DecidedAt, o.IssuedAt})
		}
	}
	g.Spec.Carried = carriedTrees(g, others, now)

	if len(g.Spec.Objects) > maxGrantObjects {
		return mergeOutcome{problem: "size", objects: []token.Object{{APIVersion: "clearance.hangar.io/v1", Kind: "ClearanceGrant", Namespace: ns, Name: MergedGrantName}},
			detail: fmt.Sprintf("the merged grant of %s would list %d objects, over the limit of %d: refused, the last good grant stays", ns, len(g.Spec.Objects), maxGrantObjects)}
	}
	raw, _ := json.Marshal(g.Spec)
	if len(raw) > a.cfg.OptIn.MaxGrantBytes {
		return mergeOutcome{problem: "size", objects: []token.Object{{APIVersion: "clearance.hangar.io/v1", Kind: "ClearanceGrant", Namespace: ns, Name: MergedGrantName}},
			detail: fmt.Sprintf("the merged grant of %s would be %d bytes, over the limit of %d: refused, the last good grant stays", ns, len(raw), a.cfg.OptIn.MaxGrantBytes)}
	}
	return mergeOutcome{grant: &g}
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
//   - a conflict or a grant too big, with a merged grant already in the cluster: that one stays exactly as it is (the
//     last good), and the per-change grants of the namespace stay out;
//   - a namespace labelled protected whose merged grant nothing replaces: the merged grant stays;
//   - no merged grant, written or held (no clearance yet, or the first merge is refused): the namespace keeps the
//     per-change grants it had. Never an empty or partial merged grant.
//
// It also says which problems exist, so they are reported once each.
func (a *Agent) applyMerged(want []Grant, have []Grant, v *optView, claims []*token.Claims, labelled map[string]map[string]string) (out []Grant, problems map[string]mergeOutcome) {
	problems = map[string]mergeOutcome{}
	held := map[string]Grant{}
	for _, g := range have {
		if g.Name == MergedGrantName {
			held[g.Namespace] = g
		}
	}
	replace := map[string]*Grant{} // namespace -> its grant (nil: the per-change grants stay)
	for ns, apps := range v.merged {
		res := a.mergeNamespace(ns, apps, claims)
		switch {
		case res.grant != nil:
			replace[ns] = res.grant
		case res.problem != "":
			problems[ns] = res
			if h, ok := held[ns]; ok {
				hh := h
				replace[ns] = &hh
			}
		default: // no clearance for any of them yet
			if h, ok := held[ns]; ok {
				hh := h // the last good grant stays until it expires; the per-change grants stay out
				replace[ns] = &hh
			}
		}
	}
	// A namespace the agent labelled is never left without its merged grant while the label is on: the grant stays as
	// it is (it expires on its own clock) until the label is off, which is the order of every removal. Without this, the
	// feed's per-change grants would take the namespace over while it is still labelled.
	for ns, h := range held {
		if _, ok := replace[ns]; !ok && labelled[ns][LabelProtected] == "true" && labelled[ns][LabelProtectedBy] == ProtectedByOptIn {
			hh := h
			replace[ns] = &hh
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
	// Likewise a namespace an operator labelled: a merged grant nothing else replaces stays.
	for ns, h := range held {
		if _, ok := replace[ns]; !ok && !wanted[ns] && labelled[ns][LabelProtected] == "true" {
			hh := h
			replace[ns] = &hh
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

// reportMergeProblems posts, once each, the conflicts and the grants refused for size, through the exception path
// (deploy.exception, out-of-band), and forgets a problem that has gone, so that it is reported again if it comes back.
func (a *Agent) reportMergeProblems(ctx context.Context, problems map[string]mergeOutcome, v *optView) error {
	var errs []error
	current := map[string]bool{}
	names := make([]string, 0, len(problems))
	for ns := range problems {
		names = append(names, ns)
	}
	sort.Strings(names)
	for _, ns := range names {
		p := problems[ns]
		sum := sha256.Sum256([]byte(p.detail))
		fp := "merge|" + ns + "|" + p.problem + "|" + hex.EncodeToString(sum[:8])
		current[fp] = true
		a.mu.Lock()
		_, done := a.st.Exceptions[fp]
		a.mu.Unlock()
		if done {
			continue
		}
		env := a.cfg.Environment
		app := ns
		if len(v.merged[ns]) > 0 {
			env, app = v.merged[ns][0].env, v.merged[ns][0].gateApp
		}
		objs := make([]map[string]any, 0, len(p.objects))
		for _, o := range p.objects {
			objs = append(objs, map[string]any{"apiVersion": o.APIVersion, "kind": o.Kind, "namespace": o.Namespace, "name": o.Name})
		}
		result := "two protected Applications claim one object"
		principal := "Applications " + strings.Join(p.apps, ", ")
		if p.problem == "size" {
			result, principal = "merged grant over the size limit", "argocd-agent (merged grant)"
		}
		req := &client.RecordRequest{Kind: "deploy.exception", Record: client.ProviderEvent{
			Principal:   client.String(truncate(principal, 500)),
			Target:      client.String("namespace/" + ns),
			App:         client.String(app),
			Result:      client.String(result),
			Destination: map[string]any{"cluster": a.cfg.Cluster, "environment": env, "namespace": ns},
			Source:      map[string]any{"provider": a.Provider()},
			Exception: map[string]any{"kind": "out-of-band", "objects": objs, "detected_at": a.now().UTC().Format(time.RFC3339),
				"detail": truncate(p.detail, 1000)}}}
		ref, err := a.core.Record(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("posting deploy.exception for the merged grant of %s: %w", ns, err))
			continue
		}
		a.mu.Lock()
		a.st.Exceptions[fp] = a.now().UTC().Format(time.RFC3339)
		err = a.saveLocked(ctx)
		a.mu.Unlock()
		if err != nil {
			errs = append(errs, err)
		}
		a.log.Warn("merged grant problem reported", "namespace", ns, "problem", p.problem, "seq", ref.Seq)
	}
	a.mu.Lock()
	changed := false
	for fp := range a.st.Exceptions {
		if strings.HasPrefix(fp, "merge|") && !current[fp] {
			delete(a.st.Exceptions, fp)
			changed = true
		}
	}
	if changed {
		errs = append(errs, a.saveLocked(ctx))
	}
	a.mu.Unlock()
	return errors.Join(errs...)
}
