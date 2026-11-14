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
)

// The protected pairs and the namespace labels of the opt-in (G-ARGO-10c).
//
// Pairs. The agent reports to the core, as its own identity (PUT /v1/protection/{cluster}), the app and environment
// of every Application that asks for protection: the whole set each time, so that a removal is a report that leaves a
// pair out and names the Application in its reason. The core records a changed set once; an unchanged one only renews
// its time, which the agent does every ReportEvery so that the core can tell it is alive. Nothing is removed by the
// agent being silent.
//
// Labels. A namespace is labelled protected only after its merged grant is in the cluster, active and valid, and
// the label is taken off before the grant is removed: admission never sees a labelled namespace with no grant (the
// policy refuses every write there), and a namespace is never labelled on the strength of a tree nobody cleared.

// report is the last set of pairs the core took.
type report struct {
	digest string
	at     time.Time
}

// pairsOf is the sorted, de-duplicated set of pairs the Applications that ask for protection make, and its digest.
func pairsOf(classes []appClass) ([]client.ProtectedPair, string) {
	seen := map[client.ProtectedPair]bool{}
	for _, c := range classes {
		// A name the core would refuse (it is not a DNS label) cannot be a pair, and one such name would make the core
		// refuse the whole report: that Application is blocked in switchApp and left out here.
		if c.protectedIntent() && dnsLabel.MatchString(c.gateApp) && dnsLabel.MatchString(c.env) {
			seen[client.ProtectedPair{App: c.gateApp, Env: c.env}] = true
		}
	}
	out := make([]client.ProtectedPair, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].App != out[j].App {
			return out[i].App < out[j].App
		}
		return out[i].Env < out[j].Env
	})
	raw, _ := json.Marshal(out)
	sum := sha256.Sum256(raw)
	return out, hex.EncodeToString(sum[:])
}

// reportPairs makes sure the core holds the current set: it reports when the set changed since the core last took
// one, or the last report is older than ReportEvery. It says whether the core holds the current set; a pass that
// removes anything (a label, an Application's switch) goes on only when it does.
func (a *Agent) reportPairs(ctx context.Context, classes []appClass) bool {
	pairs, digest := pairsOf(classes)
	a.repMu.Lock()
	fresh := a.rep.digest == digest && a.now().Sub(a.rep.at) < a.cfg.OptIn.ReportEvery
	a.repMu.Unlock()
	if fresh {
		return true
	}
	req := &client.ProtectionRequest{Pairs: pairs, Reason: optOutReason(classes)}
	res, err := a.core.ReportProtection(ctx, a.cfg.Cluster, req)
	if err != nil {
		a.warnOnce("core/protection", "the protected pairs could not be reported to the core (removals wait; the core keeps the last set): "+truncate(err.Error(), 200))
		return false
	}
	delete(a.opt().warned, "core/protection")
	a.repMu.Lock()
	a.rep = report{digest: digest, at: a.now()}
	a.repMu.Unlock()
	if res.Changed {
		a.log.Info("protected pairs reported", "pairs", len(pairs), "added", len(res.Added), "removed", len(res.Removed), "seq", res.Seq)
	}
	for _, p := range res.StaticRemoved {
		a.log.Warn("a pair left the report and the core's CLEARANCE_PROTECTED_ENVIRONMENTS still protects it", "app", p.App, "env", p.Env)
	}
	return true
}

// optOutReason names the Applications that no longer ask for protection (or may not have it), for the core's record
// of the removal. It is claimed text.
func optOutReason(classes []appClass) string {
	var parts []string
	for _, c := range classes {
		switch {
		case c.pendingRestore() && c.denied:
			parts = append(parts, fmt.Sprintf("%s denied (%s/%s)", c.key(), c.gateApp, c.env))
		case c.pendingRestore():
			parts = append(parts, fmt.Sprintf("%s opted out (%s/%s)", c.key(), c.gateApp, c.env))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	r := strings.Join(parts, "; ")
	if len(r) > 480 {
		r = r[:477] + "..."
	}
	return r
}

// reportedMatches says whether the core holds the set the Applications make now: an unlabelling that follows an
// opt-out waits for this, so a removal is on the core's record before the namespace is touched.
func (a *Agent) reportedMatches(classes []appClass) bool {
	_, digest := pairsOf(classes)
	a.repMu.Lock()
	defer a.repMu.Unlock()
	return a.rep.digest == digest
}

// optView is the Applications as the grant loop needs them: which namespaces protected Applications target.
type optView struct {
	classes []appClass
	intent  map[string][]appClass // namespace -> the Applications that ask for protection and target it
	merged  map[string][]appClass // the same, the ones the agent has switched: their cleared trees make the merged grant
}

func (a *Agent) optInView(ctx context.Context) (*optView, error) {
	apps, _, err := a.kube.ListApplications(ctx)
	if err != nil {
		return nil, err
	}
	v := &optView{classes: a.classify(ctx, apps), intent: map[string][]appClass{}, merged: map[string][]appClass{}}
	for _, c := range v.classes {
		if !c.protectedIntent() || c.app.DestNS == "" {
			continue
		}
		v.intent[c.app.DestNS] = append(v.intent[c.app.DestNS], c)
		if c.switched {
			v.merged[c.app.DestNS] = append(v.merged[c.app.DestNS], c)
		}
	}
	return v, nil
}

// unlabelLosers takes the label off the namespace of an Application that is about to be put back, when no other
// Application that asks for protection targets it.
func (a *Agent) unlabelLosers(ctx context.Context, classes []appClass, c appClass) error {
	ns := c.app.DestNS
	if ns == "" {
		return nil
	}
	for _, o := range classes {
		if o.protectedIntent() && o.app.DestNS == ns {
			return nil
		}
	}
	return a.unlabel(ctx, ns)
}

// unlabel takes the agent's own label off a namespace: a namespace an operator labelled (no marker) stays labelled.
func (a *Agent) unlabel(ctx context.Context, ns string) error {
	err := a.kube.SetNamespaceProtected(ctx, ns, false)
	switch {
	case err == nil:
		a.log.Info("namespace unlabelled (no Application that asks for protection targets it)", "namespace", ns)
		return nil
	case errors.Is(err, ErrNotOurs), errors.Is(err, ErrNotFound):
		return nil
	}
	return fmt.Errorf("removing the protected label of %s: %w", ns, err)
}

// unlabelStale removes the agent's label from every namespace that no Application asking for protection targets, before
// the grants are reconciled (which removes their merged grants). It acts only once the core holds the current pairs,
// and only on a namespace that carries the agent's marker.
func (a *Agent) unlabelStale(ctx context.Context, v *optView) error {
	if !a.reportedMatches(v.classes) {
		return nil
	}
	nss, err := a.kube.ProtectedNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("listing the protected namespaces: %w", err)
	}
	names := make([]string, 0, len(nss))
	for ns, l := range nss {
		if l[LabelProtectedBy] == ProtectedByOptIn && len(v.intent[ns]) == 0 {
			names = append(names, ns)
		}
	}
	sort.Strings(names)
	var errs []error
	for _, ns := range names {
		if err := a.unlabel(ctx, ns); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// labelProtected labels each namespace a switched Application targets once its merged grant is in the cluster: the
// grant exists, is the active one, is valid and has not expired. A namespace already labelled is not written.
func (a *Agent) labelProtected(ctx context.Context, v *optView) error {
	if len(v.merged) == 0 {
		return nil
	}
	nss, err := a.kube.ProtectedNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("listing the protected namespaces: %w", err)
	}
	grants, err := a.kube.ListGrants(ctx)
	if err != nil {
		return fmt.Errorf("listing the grants: %w", err)
	}
	ready := map[string]bool{}
	for _, g := range grants {
		if g.Name == MergedGrantName && g.Active() && g.Valid != nil && *g.Valid && expiryAfter(g.Spec.ExpiresAt, a.now()) {
			ready[g.Namespace] = true
		}
	}
	names := make([]string, 0, len(v.merged))
	for ns := range v.merged {
		names = append(names, ns)
	}
	sort.Strings(names)
	var errs []error
	for _, ns := range names {
		if !ready[ns] || nss[ns][LabelProtected] == "true" {
			continue
		}
		switch err := a.kube.SetNamespaceProtected(ctx, ns, true); {
		case err == nil:
			a.log.Info("namespace labelled protected (its merged grant is active and valid)", "namespace", ns)
		case errors.Is(err, ErrNotFound): // Argo CD creates the namespace on a first sync: the next pass
		default:
			errs = append(errs, fmt.Errorf("labelling %s protected: %w", ns, err))
		}
	}
	return errors.Join(errs...)
}

// reconcileMerged is fetchAndApply's tail when the opt-in is on: the per-change grants the feed calls for, with the
// namespaces of switched Applications replaced by their merged grants, in this order:
//
//  1. the namespaces no Application asks to protect any more are unlabelled (when the core holds the pairs that say
//     so), so that no grant is removed from a namespace that is still labelled;
//  2. the grants are reconciled (new ones first, the active label moved, the unwanted ones removed);
//  3. the namespaces whose merged grant is now active and valid are labelled.
//
// Any failure before step 2 leaves the grants as they are.
func (a *Agent) reconcileMerged(ctx context.Context, v *verified, want, have []Grant) error {
	view, err := a.optInView(ctx)
	if err != nil {
		return fmt.Errorf("listing the Applications (the grants stay as they are): %w", err)
	}
	if err := a.unlabelStale(ctx, view); err != nil {
		return fmt.Errorf("%w (the grants stay as they are)", err)
	}
	labelled, err := a.kube.ProtectedNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("listing the protected namespaces (the grants stay as they are): %w", err)
	}
	merged, problems := a.applyMerged(want, have, view, v.claims, labelled)
	var errs []error
	if err := a.reconcile(ctx, merged, have); err != nil {
		errs = append(errs, err)
	}
	if err := a.labelProtected(ctx, view); err != nil {
		errs = append(errs, err)
	}
	if err := a.reportMergeProblems(ctx, problems, view); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
