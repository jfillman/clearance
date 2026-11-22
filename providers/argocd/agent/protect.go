package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
// An Application whose environment is ambiguous (blocked) is not in it; one whose environment is unknown makes the
// whole set unknown (reportPairs does not send it).
func pairsOf(classes []appClass) ([]client.ProtectedPair, string) {
	seen := map[client.ProtectedPair]bool{}
	for _, c := range classes {
		// A name the core would refuse (it is not a DNS label) cannot be a pair, and one such name would make the core
		// refuse the whole report: that Application is blocked in switchApp and left out here.
		if c.protectedIntent() && c.envErr == nil && c.blockedWhy == "" && dnsLabel.MatchString(c.gateApp) && dnsLabel.MatchString(c.env) {
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
// one, when an opt-out has not been explained to it (an opt-out of one of two Applications of a pair changes no set and
// is still a record), or when the last report is older than ReportEvery. It says whether the core holds the current
// set; a pass that removes anything (a label, an Application's switch) goes on only when it does.
//
// A pure addition is sent at once. A report that removes a pair, or explains an opt-out, is debounced: changes within one
// minute of the last one are coalesced into the next, so one tenant flipping its annotation does not make a report each
// time. A report that both adds and removes is split: the additions go first on their own, so a removal that is refused
// or waiting never holds up another team's pair.
//
// Each report carries a number that only goes up and is kept in the state, so an old or replayed report cannot replace
// a newer one; after a state loss the agent starts from the core's last number. The pairs the core last took are kept
// in the state too, so that a pair that has no Application any more (deleted) is reported removed with that reason.
func (a *Agent) reportPairs(ctx context.Context, classes []appClass) bool {
	for _, c := range classes {
		if (c.protectedIntent() || c.pendingRestore()) && c.envErr != nil {
			a.warnOnce("core/protection", "the protected pairs are not reported this pass: "+c.envErr.Error())
			return false
		}
	}
	pairs, digest := pairsOf(classes)
	cur := make([]Pair, len(pairs))
	for i, p := range pairs {
		cur[i] = Pair{p.App, p.Env}
	}
	a.mu.Lock()
	prev, seq := a.st.Reported, a.st.ReportSeq
	a.mu.Unlock()
	var removed, added []Pair
	for _, p := range prev {
		if !slices.Contains(cur, p) {
			removed = append(removed, p)
		}
	}
	for _, p := range cur {
		if !slices.Contains(prev, p) {
			added = append(added, p)
		}
	}
	a.repMu.Lock()
	var unexplained []appClass
	for _, c := range classes {
		if c.pendingRestore() && !a.explained[c.key()] {
			unexplained = append(unexplained, c)
		}
	}
	fresh := a.rep.digest == digest && a.now().Sub(a.rep.at) < a.cfg.OptIn.ReportEvery && len(unexplained) == 0 && len(removed) == 0
	lastSend := a.lastSend
	a.repMu.Unlock()
	if fresh {
		return true
	}
	if seq == 0 && len(cur) == 0 && len(prev) == 0 && len(unexplained) == 0 {
		return true // nothing has ever been protected here: there is nothing to tell the core
	}
	if seq == 0 { // a state that was lost: start from the core's last number
		held, err := a.core.ProtectionSeq(ctx, a.cfg.Cluster)
		if err != nil {
			a.warnOnce("core/protection", "the core's last report number could not be read (removals wait): "+truncate(err.Error(), 200))
			return false
		}
		seq = held
	}
	toPairs := func(l []Pair) []client.ProtectedPair {
		out := make([]client.ProtectedPair, len(l))
		for i, p := range l {
			out[i] = client.ProtectedPair{App: p.App, Env: p.Env}
		}
		return out
	}
	reason := optOutReason(classes, removed, cur, unexplained)
	if (len(removed) > 0 || reason != "") && len(added) > 0 { // the additions first, on their own (also beside an opt-out's explanation)
		union := append(append([]Pair(nil), prev...), added...)
		sort.Slice(union, func(i, j int) bool {
			if union[i].App != union[j].App {
				return union[i].App < union[j].App
			}
			return union[i].Env < union[j].Env
		})
		next, ok := a.sendReport(ctx, toPairs(union), union, "", seq+1, false)
		if !ok {
			return false
		}
		prev, seq = union, next
		a.repMu.Lock()
		lastSend = a.lastSend
		a.repMu.Unlock()
	}
	if (len(removed) > 0 || reason != "") && !lastSend.IsZero() && a.now().Sub(lastSend) < reportDebounce {
		return false // coalesced into the next report
	}
	nextSeq := seq + 1
	if seq > 0 && reason == "" && slices.Equal(prev, cur) {
		nextSeq = seq // the same set again (the heartbeat): the same number, so nothing changes at the core or in the state
	}
	req := &client.ProtectionRequest{Pairs: pairs, Reason: reason, Seq: nextSeq, Exempted: exemptedPairs(classes, removed)}
	if _, ok := a.send(ctx, req, cur); !ok {
		return false
	}
	a.repMu.Lock()
	a.rep = report{digest: digest, at: a.now()}
	if a.explained == nil {
		a.explained = map[string]bool{}
	}
	for _, c := range unexplained {
		a.explained[c.key()] = true
	}
	a.repMu.Unlock()
	return true
}

// reportDebounce is how long a set change that removes something waits after the last report, to be coalesced.
const reportDebounce = time.Minute

// refusedFor is how long the core may refuse the agent's reports before the agent says so in its status and posts an exception.
const refusedFor = 10 * time.Minute

// sendReport sends one report and, when the core takes it, keeps the number and the pairs in the state. It returns the
// number the core now holds. A report the core refuses (4xx) is remembered: after refusedFor the status says so and
// one exception is posted.
func (a *Agent) sendReport(ctx context.Context, pairs []client.ProtectedPair, cur []Pair, reason string, seq int64, final bool) (int64, bool) {
	return a.send(ctx, &client.ProtectionRequest{Pairs: pairs, Reason: reason, Seq: seq}, cur)
}

// exemptedPairs are the removed pairs whose Application an exemption released, and that no other Application keeps.
func exemptedPairs(classes []appClass, removed []Pair) []client.ProtectedPair {
	var out []client.ProtectedPair
	for _, p := range removed {
		for _, c := range classes {
			if c.exempted && !c.protectedIntent() && c.gateApp == p.App && c.env == p.Env {
				out = append(out, client.ProtectedPair{App: p.App, Env: p.Env})
				break
			}
		}
	}
	return out
}

func (a *Agent) send(ctx context.Context, req *client.ProtectionRequest, cur []Pair) (int64, bool) {
	res, err := a.core.ReportProtection(ctx, a.cfg.Cluster, req)
	if err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) {
			if ae.Status == 409 && strings.HasPrefix(ae.Message, "refused: ") && len(req.Exempted) > 0 {
				// The core refuses to drop a pair for an exemption (its CLEARANCE_PROTECTED_ENVIRONMENTS protects it): the
				// exemptions behind it are refused, and the Applications stay gated.
				a.refuseExempted(req.Exempted, strings.TrimPrefix(ae.Message, "refused: "))
			} else if ae.Status == 409 { // the core holds a newer number than ours: read it again
				a.mu.Lock()
				a.st.ReportSeq = 0
				_ = a.saveLocked(ctx)
				a.mu.Unlock()
			}
			a.noteRefused(ctx, err)
		}
		a.warnOnce("core/protection", "the protected pairs could not be reported to the core (removals wait; the core keeps the last set): "+truncate(err.Error(), 200))
		return 0, false
	}
	a.opt().status["core/protection"] = ""
	a.repMu.Lock()
	a.refusedSince = time.Time{}
	a.lastSend = a.now()
	a.repMu.Unlock()
	a.forgetOnce(ctx, "report-refused")
	delete(a.opt().warned, "core/protection")
	a.mu.Lock()
	newSeq := max(req.Seq, res.HeldSeq)
	if newSeq != a.st.ReportSeq || !slices.Equal(a.st.Reported, cur) {
		a.st.ReportSeq = newSeq
		a.st.Reported = cur
		if serr := a.saveLocked(ctx); serr != nil {
			a.log.Warn("the report's number could not be saved", "err", serr)
		}
	}
	a.mu.Unlock()
	if res.Changed {
		var rseq int64 = -1
		if res.Seq != nil {
			rseq = *res.Seq
		}
		a.log.Info("protected pairs reported", "pairs", len(req.Pairs), "added", len(res.Added), "removed", len(res.Removed), "seq", rseq)
	}
	for _, p := range res.StaticRemoved {
		a.log.Warn("a pair left the report and the core's CLEARANCE_PROTECTED_ENVIRONMENTS still protects it", "app", p.App, "env", p.Env)
	}
	return newSeq, true
}

// noteRefused records that the core refused a report; after refusedFor it says so in the status and posts one exception.
func (a *Agent) noteRefused(ctx context.Context, err error) {
	a.repMu.Lock()
	if a.refusedSince.IsZero() {
		a.refusedSince = a.now()
	}
	since := a.refusedSince
	a.repMu.Unlock()
	if a.now().Sub(since) < refusedFor {
		return
	}
	why := fmt.Sprintf("the core has refused the agent's protected-pair reports since %s: %s", since.UTC().Format(time.RFC3339), truncate(err.Error(), 200))
	a.opt().status["core/protection"] = why
	if rerr := a.reportOnce(ctx, "report-refused", "protected-pair reports refused", why,
		[]map[string]any{{"apiVersion": "clearance.hangar.io/v1", "kind": "ClearanceGrant", "name": "protected-pairs"}}); rerr != nil {
		a.log.Warn("the refusal could not be reported", "err", rerr)
	}
}

// optOutReason says why the pairs changed, for the core's record: the Applications that no longer ask for protection
// (or may not have it) and have not been explained yet, and the pairs that left the report with no Application that
// opted out (the Application was deleted, or no longer asks and never had the plugin). It is claimed text.
func optOutReason(classes []appClass, removed, cur []Pair, unexplained []appClass) string {
	var parts []string
	covered := map[Pair]bool{}
	for _, c := range unexplained {
		p := Pair{c.gateApp, c.env}
		covered[p] = true
		how := "opted out"
		switch {
		case c.denied:
			how = "denied"
		case c.left:
			how = "left the agent's projects"
		case c.exempted && c.exempt != nil:
			how = fmt.Sprintf("exempted from rule %s by %q until %s", c.ruleName, c.exempt.Application, c.exempt.At.Format("2006-01-02"))
		case c.wasRuled && c.ruleName == "":
			how = "the rule no longer matches"
		}
		note := ""
		if slices.Contains(cur, p) {
			note = ", the pair stays protected by another Application"
		}
		parts = append(parts, fmt.Sprintf("%s %s (%s/%s%s)", c.key(), how, c.gateApp, c.env, note))
	}
	for _, p := range removed {
		if covered[p] {
			continue
		}
		var who []string
		for _, c := range classes {
			if c.gateApp == p.App && c.env == p.Env && !c.protectedIntent() {
				who = append(who, c.key())
			}
		}
		if len(who) > 0 {
			parts = append(parts, fmt.Sprintf("%s no longer asks (%s/%s)", strings.Join(who, ", "), p.App, p.Env))
		} else {
			parts = append(parts, fmt.Sprintf("application deleted (%s/%s)", p.App, p.Env))
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
	skip    map[string]bool       // namespaces left as they are this pass (an Application there has an unknown environment)
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
	case !a.configured(ns) && isForbidden(err):
		// A namespace the agent is not configured for is one it can never have labelled: the refusal is no reason to hold
		// an opt-out. For a configured namespace a refusal is an error and the opt-out waits.
		return nil
	}
	return fmt.Errorf("removing the protected label of %s: %w", ns, err)
}

// unlabelStale removes the agent's label from every namespace that no Application asking for protection targets, before
// the grants are reconciled (which removes their merged grants). It acts only once the core holds the current pairs,
// and only on a namespace that carries the agent's marker. nss is the pass's one listing of the protected namespaces;
// it says which namespaces it unlabelled.
func (a *Agent) unlabelStale(ctx context.Context, v *optView, nss map[string]map[string]string) (done []string, err error) {
	if !a.reportedMatches(v.classes) {
		return nil, nil
	}
	var names []string
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
			continue
		}
		done = append(done, ns)
	}
	return done, errors.Join(errs...)
}

// labelProtected labels each namespace a switched Application targets once its merged grant is in the cluster: the
// grant exists, is the active one, is valid and has not expired. A namespace already labelled is not written. nss is
// the pass's listing of the protected namespaces.
func (a *Agent) labelProtected(ctx context.Context, v *optView, nss map[string]map[string]string) error {
	if len(v.merged) == 0 {
		return nil
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
		if !ready[ns] || nss[ns][LabelProtected] == "true" || !a.configured(ns) {
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
	// With a rule configured and no good copy of it, a rule-gated Application would read as ungated, and its namespace's
	// label and grant would be removed: nothing is changed until there is one.
	if _, err := a.loadRule(ctx); err != nil {
		return fmt.Errorf("%w (the grants stay as they are)", err)
	}
	view, err := a.optInView(ctx)
	if err != nil {
		return fmt.Errorf("listing the Applications (the grants stay as they are): %w", err)
	}
	// An Application whose destination namespace cannot be read has an unknown environment: its clearances cannot be matched,
	// and dropping them would drop its grant. Only ITS namespace is left as it is this pass; every other namespace's grant
	// is reconciled, so a revocation elsewhere does not wait.
	var envErrs []error
	for _, c := range view.classes {
		if c.protectedIntent() && c.envErr != nil {
			if view.skip == nil {
				view.skip = map[string]bool{}
			}
			view.skip[c.app.DestNS] = true
			envErrs = append(envErrs, fmt.Errorf("the environment of %s is unknown (%v): the grant of namespace %s stays as it is this pass", c.key(), c.envErr, c.app.DestNS))
		}
	}
	labelled, err := a.kube.ProtectedNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("listing the protected namespaces (the grants stay as they are): %w", err)
	}
	done, err := a.unlabelStale(ctx, view, labelled)
	if err != nil {
		return fmt.Errorf("%w (the grants stay as they are)", err)
	}
	after := make(map[string]map[string]string, len(labelled))
	for ns, l := range labelled {
		after[ns] = l
	}
	for _, ns := range done {
		delete(after, ns)
	}
	merged, problems := a.applyMerged(want, have, view, v.claims, after)
	errs := append([]error(nil), envErrs...)
	if err := a.reconcile(ctx, merged, have); err != nil {
		errs = append(errs, err)
	}
	if err := a.labelProtected(ctx, view, after); err != nil {
		errs = append(errs, err)
	}
	if err := a.reportMergeProblems(ctx, problems, view); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func isForbidden(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == 403
}
