package agent_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/token"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// Second-round review fixes for G-ARGO-10c (pull request 175).

func (w *optWorld) setExpiry(id string, at time.Time) {
	for i := range w.feeds.claims {
		if w.feeds.claims[i].Subject == id {
			w.feeds.claims[i].Expires = at.Unix()
		}
	}
}

// -- 1. one expiry per object ---------------------------------------------------------------------------------------

func TestEachObjectRunsOutAtItsOwnClearancesExpiryWhileTheFeedIsUnreadable(t *testing.T) {
	w := newOptWorld(t)
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	feedObjs(w, "api", "app-a", ch2, t0, deploy("api", hex("c")))
	w.setExpiry(ch1, t0.Add(10*time.Minute))
	w.setExpiry(ch2, t0.Add(50*time.Minute))
	w.publishSync()
	g, _ := w.merged("app-a")
	if g.Spec.Objects["apps/Deployment/web"].ExpiresAt != t0.Add(10*time.Minute).UTC().Format(time.RFC3339) ||
		g.Spec.Objects["apps/Deployment/api"].ExpiresAt != t0.Add(50*time.Minute).UTC().Format(time.RFC3339) {
		t.Fatalf("each object carries its own clearance's expiry: %+v", g.Spec.Objects)
	}
	// The feed (or the core) goes away; time passes beyond web's clearance and not api's.
	w.feeds.down = true
	w.clock.add(15 * time.Minute)
	if err := w.sync(); err == nil {
		t.Fatal("the feed is unreadable: expected the error")
	}
	if got := w.mergedObjects("app-a"); got != "apps/Deployment/api=c" {
		t.Fatalf("web's object must go at its own expiry, api's stay: %s", got)
	}
	if !w.labelled("app-a") {
		t.Fatal("unlabelled")
	}
}

// -- 2. an older CRD -----------------------------------------------------------------------------------------------

func TestAnOlderCRDStopsTheOptInAndIsReportedOnce(t *testing.T) {
	w := newOptWorld(t)
	w.kube.schemaMissing = []string{"objects.app", "objects.expiresAt"}
	w.kube.pruning = true
	w.addApp("web-prod", "app-a", protect())
	before := w.writes()
	w.mustReconcile()
	w.clock.add(6 * time.Minute) // it must have failed for five minutes before it is reported
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0.Add(6*time.Minute), deploy("web", hex("a")))
	w.feeds.claims[0].Expires = w.clock.now().Add(time.Hour).Unix()
	w.publishSync()
	w.noNewWrites(before, "an opt-in against a CRD that lacks its fields", "put", "create", "update", "valid") // the per-change grants go on
	if w.isSwitched("web-prod") || len(w.core.reports) != 0 {
		t.Fatal("the opt-in ran")
	}
	for k := range w.kube.grants {
		if strings.Contains(k, agent.MergedGrantName) {
			t.Fatalf("a merged grant was written to a CRD that prunes its fields: %s", k)
		}
	}
	if g := w.grant("app-a", ch1); !g.Active() {
		t.Fatal("per-change behaviour continues")
	}
	ex := w.core.of("deploy.exception")
	if len(ex) != 1 || !strings.Contains(fmt.Sprint(ex[0].Record.Exception["detail"]), "objects.app") {
		t.Fatalf("one exception naming the missing fields: %+v", ex)
	}
	// A repeat pass: no writes, no second report.
	before = w.writes()
	w.clock.add(time.Minute)
	w.mustReconcile()
	w.publishSync()
	w.noNewWrites(before, "a repeat pass", "put", "create", "update", "valid")
	if len(w.core.of("deploy.exception")) != 1 {
		t.Fatal("reported twice")
	}
	// The CRD is applied: the opt-in starts after the recheck.
	w.kube.schemaMissing, w.kube.pruning = nil, false
	w.clock.add(10 * time.Minute)
	w.mustReconcile()
	if !w.isSwitched("web-prod") {
		t.Fatal("not started once the CRD has the fields")
	}
}

func TestAMergedGrantThatLooksPrunedIsRecheckedAndStopsTheOptIn(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync()
	if _, ok := w.merged("app-a"); !ok {
		t.Fatal("setup")
	}
	// The CRD is replaced by an older one: what the agent writes next is pruned.
	w.kube.schemaMissing, w.kube.pruning = []string{"objects.app"}, true
	w.clock.add(time.Minute)
	feedObjs(w, "web", "app-a", ch2, w.clock.now(), deploy("web", hex("b")))
	w.feeds.claims[0].Expires = w.clock.now().Add(time.Hour).Unix()
	w.publishSync()              // writes the new grant: pruned
	w.publishSync()              // sees a held grant with no owners: reads the CRD again
	w.clock.add(6 * time.Minute) // it must have failed for five minutes before it is reported
	w.mustReconcile()
	w.feeds.claims[0].Expires = w.clock.now().Add(time.Hour).Unix()
	w.feeds.claims[0].IssuedAt = w.clock.now().Add(-time.Second).Unix()
	w.feeds.claims[1].Expires = w.clock.now().Add(time.Hour).Unix()
	w.feeds.claims[1].IssuedAt = w.clock.now().Add(-time.Second).Unix()
	w.publishSync()
	if len(w.core.of("deploy.exception")) != 1 {
		t.Fatalf("one exception: %v", exceptions(w))
	}
}

// -- 3. a flipping tenant cannot delay another team's pair ----------------------------------------------------------------

func pairNames(r client.ProtectionRequest) string {
	var out []string
	for _, p := range r.Pairs {
		out = append(out, p.App+"/"+p.Env)
	}
	return strings.Join(out, ",")
}

func TestAPureAdditionIsSentAtOnceAndARemovalIsDebounced(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.addApp("api-prod", "app-b", protect())
	w.mustReconcile()
	w.clock.add(70 * time.Second)
	n := len(w.core.reports)
	// A removal, then at once an addition by another team: the addition is not held by the removal's debounce.
	w.setAnn("web-prod", agent.AnnProtect, nil)
	w.mustReconcile()
	w.addApp("db-prod", "app-c", protect())
	w.mustReconcile()
	var got []string
	for _, r := range w.core.reports[n:] {
		got = append(got, pairNames(r))
	}
	if len(got) == 0 || !strings.Contains(got[len(got)-1], "db/prod") {
		t.Fatalf("the addition was delayed: %v", got)
	}
	if !w.isSwitched("db-prod") {
		t.Fatal("the new Application is switched once the core took its pair")
	}
}

func TestAMixedChangeSendsTheAdditionsFirstOnTheirOwn(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	w.clock.add(70 * time.Second)
	n := len(w.core.reports)
	w.setAnn("web-prod", agent.AnnProtect, nil)
	w.addApp("db-prod", "app-c", protect())
	w.mustReconcile()
	first := pairNames(w.core.reports[n])
	if first != "db/prod,web/prod" {
		t.Fatalf("the first report only adds (the old pair stays): %s", first)
	}
	if !w.isSwitched("db-prod") {
		t.Fatal("db is switched at once")
	}
	if !w.isSwitched("web-prod") {
		t.Fatal("the removal waits out the debounce")
	}
	w.clock.add(70 * time.Second)
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("the removal goes after the debounce")
	}
}

func TestAReportRefusedForTenMinutesIsInTheStatusAndAnExceptionOnce(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	w.clock.add(70 * time.Second)
	w.core.refuse = func(*client.ProtectionRequest) error {
		return &client.APIError{Op: "reportProtection", Status: 429, Message: "at most 30 removals or explained reports are recorded per hour"}
	}
	w.setAnn("web-prod", agent.AnnProtect, nil)
	for i := 0; i < 14; i++ {
		_ = w.reconcile()
		w.clock.add(time.Minute)
	}
	var st map[string]string
	if err := jsonUnmarshal(w.kube.data["clearance-system/clearance-argocd-agent-state"]["optin.json"], &st); err != nil || !strings.Contains(st["core/protection"], "refused the agent's protected-pair reports since") {
		t.Fatalf("status: %v %v", st, err)
	}
	if ex := w.core.of("deploy.exception"); len(ex) != 1 {
		t.Fatalf("one exception, once: %d", len(ex))
	}
	if !w.isSwitched("web-prod") {
		t.Fatal("an opt-out the core has not taken waits")
	}
	w.core.refuse = nil
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("not restored once the core took it")
	}
}

// -- 4. an unlabelled configured namespace has the agent's environment -----------------------------------------------

func TestAnUnlabelledNamespaceIsTheAgentsEnvironmentAndADifferentLabelIsBlocked(t *testing.T) {
	w := newOptWorld(t)
	w.kube.ns["app-a"] = map[string]string{} // exists, no environment label
	a := w.addApp("web-prod", "app-a", protect())
	a.Labels[agent.LabelAppEnv] = "dev"
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("an Application labelled dev was switched into a namespace the agent treats as prod")
	}
	w.addApp("api-prod", "app-a", protect()) // its own label prod = the agent's environment
	w.mustReconcile()
	if !w.isSwitched("api-prod") {
		t.Fatal("an agreeing label")
	}
}

// -- 5. an opt-out that cannot be undone changes nothing ------------------------------------------------------------------

func TestAnOptOutWhoseOriginalCannotBeReadBackLeavesEverythingProtected(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync()
	// The plugin's sources parameter is damaged.
	for i := range w.kube.apps {
		w.kube.apps[i].Source = []byte(strings.Replace(string(w.kube.apps[i].Source), `\"repoURL\"`, `\"repo`, 1))
		w.kube.apps[i].Source = []byte(strings.Replace(string(w.kube.apps[i].Source), `"string":"[{`, `"string":"[not json {`, 1))
	}
	w.setAnn("web-prod", agent.AnnProtect, nil)
	w.clock.add(70 * time.Second)
	n := len(w.core.reports)
	before := w.writes()
	w.mustReconcile()
	w.mustReconcile()
	if len(w.core.reports) != n && len(w.core.reports[len(w.core.reports)-1].Pairs) == 0 {
		t.Fatal("the pair was reported removed before the restore was known to be possible")
	}
	if !w.labelled("app-a") || !w.isSwitched("web-prod") {
		t.Fatal("unlabelled or restored")
	}
	w.noNewWrites(before, "an opt-out that cannot be undone", "put")
	if ex := w.core.of("deploy.exception"); len(ex) != 1 {
		t.Fatalf("reported once: %d", len(ex))
	}
}

// -- 6. one unreadable namespace does not hold the others -----------------------------------------------------------------

func TestAnUnreadableNamespaceHoldsOnlyItself(t *testing.T) {
	w := newOptWorld(t)
	w.kube.ns["app-a"] = map[string]string{agent.LabelEnvironment: "prod"}
	w.kube.ns["app-b"] = map[string]string{agent.LabelEnvironment: "prod"}
	w.addApp("web-prod", "app-a", protect())
	w.addApp("api-prod", "app-b", protect())
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	feedObjs(w, "api", "app-b", ch2, t0, deploy("api", hex("c")))
	w.publishSync()
	w.kube.nsReadErr["app-a"] = errBoom                // only web's namespace cannot be read
	w.kube.liveExempt = map[string]bool{"app-a": true} // and its grant is left as it was, so the feed check does not apply there
	w.dropClaims(ch1, ch2)                             // both clearances are revoked
	w.feeds.publish()
	if err := w.sync(); err == nil {
		t.Fatal("the unreadable namespace is reported as an error")
	}
	if w.mergedObjects("app-b") != "(no grant)" && len(mustGrant(t, w, "app-b").Spec.Objects) != 0 {
		t.Fatalf("app-b's revocation waited for app-a: %s", w.mergedObjects("app-b"))
	}
	if got := w.mergedObjects("app-a"); got != "apps/Deployment/web=a" {
		t.Fatalf("app-a is left exactly as it was: %s", got)
	}
}

func mustGrant(t *testing.T, w *optWorld, ns string) agent.Grant {
	g, ok := w.merged(ns)
	if !ok {
		t.Fatalf("no merged grant in %s", ns)
	}
	return g
}

// -- 7. live means the owner's clearance --------------------------------------------------------------------------------

func TestAnotherApplicationsClearanceDoesNotKeepARevokedObjectAlive(t *testing.T) {
	w := newOptWorld(t)
	w.a = mustAgent(t, w, func(c *agent.Config) { c.OptIn.MaxGrantBytes = 1500 })
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync()
	// api's clearance happens to list web's Deployment at the very hash web holds, and is too big to merge (a refusal that
	// keeps the held grant).
	var objs []token.Object
	for i := 0; i < 40; i++ {
		objs = append(objs, deploy(fmt.Sprintf("api-%02d", i), hex("c")))
	}
	objs = append(objs, deploy("web", hex("a")))
	w.clock.add(time.Minute)
	feedObjs(w, "api", "app-a", ch2, w.clock.now(), objs...)
	w.publishSync()
	w.dropClaims(ch1) // web's clearance is revoked
	w.publishSync()
	g, _ := w.merged("app-a")
	if _, ok := g.Spec.Objects["apps/Deployment/web"]; ok {
		t.Fatalf("web's revoked object was kept alive by api's clearance: %+v", g.Spec.Objects)
	}
}

// -- 9. leaving the projects ----------------------------------------------------------------------------------------------

func TestAnApplicationThatLeavesTheProjectsIsPutBackLikeAnOptOut(t *testing.T) {
	w := newOptWorld(t)
	orig := w.addApp("web-prod", "app-a", protect())
	want := orig.Source
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync()
	w.clock.add(70 * time.Second)
	for i := range w.kube.apps {
		w.kube.apps[i].Project = "elsewhere"
	}
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("it stays on the plugin")
	}
	sameRaw(t, string(w.app("web-prod").Source), string(want))
	r := w.core.reports[len(w.core.reports)-1]
	if len(r.Pairs) != 0 || !strings.Contains(r.Reason, "left the agent's projects (web/prod)") {
		t.Fatalf("%+v", r)
	}
	w.publishSync()
	if w.labelled("app-a") {
		t.Fatal("still labelled")
	}
}
