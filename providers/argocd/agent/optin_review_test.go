package agent_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/token"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// Review fixes for G-ARGO-10c (pull request 175). Each test names the finding it pins.

func (w *optWorld) dropClaims(ids ...string) {
	var keep []token.Claims
	for _, c := range w.feeds.claims {
		drop := false
		for _, id := range ids {
			if c.Subject == id {
				drop = true
			}
		}
		if !drop {
			keep = append(keep, c)
		}
	}
	w.feeds.claims = keep
}

func (w *optWorld) mergedObjects(ns string) string {
	g, ok := w.merged(ns)
	if !ok {
		return "(no grant)"
	}
	return objKeys(g)
}

// -- 1. revoked hashes stay admissible ----------------------------------------------------------------------------

func TestARevokedSoleClearanceLeavesTheGrantEmptyAndTheNamespaceProtected(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	d, dHash := stamped(t, "Deployment", "web", "app-a", "web-prod", ch1, hex("c"))
	feedObjs(w, "web", "app-a", ch1, t0, token.Object{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Rendered: dHash})
	w.publishSync()
	if w.mergedObjects("app-a") != "apps/Deployment/web="+dHash[:1] || !w.labelled("app-a") {
		t.Fatalf("setup: %s %v", w.mergedObjects("app-a"), w.kube.log)
	}
	// The core revokes the change: the feed no longer lists it. (The fake fails the test if an active merged grant ever
	// holds a hash the published feed does not list.)
	w.dropClaims(ch1)
	w.publishSync()
	g, ok := w.merged("app-a")
	if !ok || !g.Active() || g.Valid == nil || !*g.Valid || len(g.Spec.Objects) != 0 || len(g.Spec.Carried) != 0 {
		t.Fatalf("the grant is empty, active and valid: %v %+v", ok, g)
	}
	if !w.labelled("app-a") {
		t.Fatal("the label came off: the namespace is open")
	}
	// What still runs at the revoked hash is an exception.
	w.kube.ns["app-a"][agent.LabelEnvironment] = "prod"
	w.kube.objs["app-a"] = []agent.ObjectDetail{d}
	if err := w.a.ScanExceptions(bg); err != nil {
		t.Fatal(err)
	}
	ex := w.core.of("deploy.exception")
	if len(ex) != 1 || *ex[0].Record.Result != agent.ReasonNotListd {
		t.Fatalf("an object running at a revoked hash is out-of-band: %+v", ex)
	}
	// Stable: the next pass writes nothing.
	ops := len(w.kube.log)
	w.publishSync()
	if len(w.kube.log) != ops {
		t.Errorf("the empty grant is rewritten: %v", w.kube.log[ops:])
	}
}

func TestAChangeThatLeavesTheFeedForAnyReasonLeavesTheGrant(t *testing.T) {
	for _, why := range []string{"revoked", "expired", "moved to exception"} {
		t.Run(why, func(t *testing.T) {
			w := newOptWorld(t)
			opt2(w)
			feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")), cmap("cfg", hex("b")))
			feedObjs(w, "api", "app-a", ch2, t0, deploy("api", hex("c")))
			feedObjs(w, "web", "app-a", ch3, t0.Add(-time.Minute), deploy("web", hex("d"))) // an older web clearance, carried
			w.publishSync()
			g, _ := w.merged("app-a")
			if len(g.Spec.Carried) != 1 {
				t.Fatalf("setup: %+v", g.Spec)
			}
			if why == "expired" { // the feed keeps only what is not expired
				w.clock.add(2 * time.Hour)
				for i := range w.feeds.claims {
					w.feeds.claims[i].Expires = w.clock.now().Add(time.Hour).Unix()
					w.feeds.claims[i].IssuedAt = w.clock.now().Add(-time.Minute).Unix()
				}
				w.dropClaims(ch1, ch3)
			} else {
				w.dropClaims(ch1, ch3)
			}
			w.publishSync()
			g, _ = w.merged("app-a")
			if got := objKeys(g); got != "apps/Deployment/api=c" || len(g.Spec.Carried) != 0 {
				t.Fatalf("web's objects and its carried tree must leave: %s %+v", got, g.Spec.Carried)
			}
			if !w.labelled("app-a") {
				t.Fatal("unlabelled")
			}
		})
	}
}

func TestARevokeDuringAConflictLeavesOnlyWhatIsLive(t *testing.T) {
	w := newOptWorld(t)
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")), deploy("shared", hex("1")))
	feedObjs(w, "api", "app-a", ch2, t0, deploy("api", hex("c")))
	w.publishSync()
	w.clock.add(time.Minute)
	feedObjs(w, "api", "app-a", ch3, w.clock.now(), deploy("api", hex("d")), deploy("web", hex("e"))) // a conflict on web
	w.publishSync()
	if len(exceptions(w)) != 1 {
		t.Fatalf("the conflict is reported: %v", exceptions(w))
	}
	w.dropClaims(ch1, ch2) // web's and api's old clearances are revoked; ch3 stays
	w.publishSync()
	// Only what is live now: api's ch3 (api=d, and web=e, which nobody else claims any more).
	if got := w.mergedObjects("app-a"); got != "apps/Deployment/api=d,apps/Deployment/web=e" {
		t.Fatalf("after the revoke: %s", got)
	}
	w.dropClaims(ch3)
	w.publishSync()
	g, _ := w.merged("app-a")
	if len(g.Spec.Objects) != 0 || !w.labelled("app-a") || !g.Active() {
		t.Fatalf("nothing live: the grant is empty and the label stays: %+v", g.Spec.Objects)
	}
}

func TestARevokeDuringASizeRefusalLeavesOnlyWhatIsLive(t *testing.T) {
	w := newOptWorld(t)
	w.a = mustAgent(t, w, func(c *agent.Config) { c.OptIn.MaxGrantBytes = 1500 })
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync()
	var objs []token.Object
	for i := 0; i < 40; i++ {
		objs = append(objs, deploy(fmt.Sprintf("api-%02d", i), hex("c")))
	}
	w.clock.add(time.Minute)
	feedObjs(w, "api", "app-a", ch2, w.clock.now(), objs...)
	w.publishSync()
	if len(exceptions(w)) != 1 || w.mergedObjects("app-a") != "apps/Deployment/web=a" {
		t.Fatalf("the refusal keeps the held grant: %v %s", exceptions(w), w.mergedObjects("app-a"))
	}
	w.dropClaims(ch1) // web's clearance is revoked while the refusal lasts
	w.publishSync()
	g, _ := w.merged("app-a")
	if len(g.Spec.Objects) != 0 || !w.labelled("app-a") {
		t.Fatalf("held intersected with live: nothing; none of api's refused objects: %+v", g.Spec.Objects)
	}
}

// -- 2. a conflict does not freeze the namespace --------------------------------------------------------------------

func TestAConflictOnOneKeyDoesNotStopAnyOtherKeyAndTheIncumbentKeepsIt(t *testing.T) {
	w := newOptWorld(t)
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	feedObjs(w, "api", "app-a", ch2, t0, deploy("api", hex("c")))
	w.publishSync()
	// api (the newcomer) claims web's key: a hostile claim.
	w.clock.add(time.Minute)
	feedObjs(w, "api", "app-a", ch3, w.clock.now(), deploy("api", hex("d")), deploy("web", hex("e")))
	w.publishSync()
	g, _ := w.merged("app-a")
	if g.Spec.Objects["apps/Deployment/web"].App != "argocd-apps/web-prod" || g.Spec.Objects["apps/Deployment/web"].Rendered != hex("a") {
		t.Fatalf("the incumbent keeps its key: %+v", g.Spec.Objects)
	}
	if g.Spec.Objects["apps/Deployment/api"].Rendered != hex("d") {
		t.Fatalf("api's other key merges (its deploys go on): %+v", g.Spec.Objects)
	}
	// The hostile newcomer cannot stop the incumbent's NEXT deploy.
	w.clock.add(time.Minute)
	feedObjs(w, "web", "app-a", ch4, w.clock.now(), deploy("web", hex("f")))
	w.publishSync()
	g, _ = w.merged("app-a")
	if g.Spec.Objects["apps/Deployment/web"].Rendered != hex("f") || g.Spec.Objects["apps/Deployment/web"].App != "argocd-apps/web-prod" {
		t.Fatalf("the incumbent's next deploy is admitted at its new hash: %+v", g.Spec.Objects)
	}
	ex := exceptions(w)
	if len(ex) != 1 || !strings.Contains(ex[0], "apps/Deployment/web: argocd-apps/web-prod keeps it, argocd-apps/api-prod is left out") {
		t.Fatalf("one exception naming the key and both Applications: %v", ex)
	}
}

func TestWithNoIncumbentAClashedKeyIsLeftOutForBothAndTheRestMerges(t *testing.T) {
	w := newOptWorld(t)
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("shared", hex("a")), deploy("web", hex("b")))
	feedObjs(w, "api", "app-a", ch2, t0, deploy("shared", hex("c")), deploy("api", hex("d")))
	w.publishSync()
	if got := w.mergedObjects("app-a"); got != "apps/Deployment/api=d,apps/Deployment/web=b" {
		t.Fatalf("%s", got)
	}
	if ex := exceptions(w); len(ex) != 1 || !strings.Contains(ex[0], "no incumbent") {
		t.Fatalf("%v", ex)
	}
}

func TestAConflictIsReportedAtTheStartEvery24HoursAndWhenItClears(t *testing.T) {
	w := newOptWorld(t)
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	feedObjs(w, "api", "app-a", ch2, t0, deploy("api", hex("c")))
	w.publishSync()
	w.clock.add(time.Minute)
	feedObjs(w, "api", "app-a", ch3, w.clock.now(), deploy("web", hex("e")))
	w.publishSync()
	w.publishSync()
	if n := len(exceptions(w)); n != 1 {
		t.Fatalf("once when it starts: %d", n)
	}
	refresh := func() { // keep every clearance alive and published at the later time
		for i := range w.feeds.claims {
			w.feeds.claims[i].Expires = w.clock.now().Add(time.Hour).Unix()
			w.feeds.claims[i].IssuedAt = w.clock.now().Add(-time.Second).Unix()
		}
	}
	w.clock.add(23 * time.Hour)
	refresh()
	w.publishSync()
	if n := len(exceptions(w)); n != 1 {
		t.Fatalf("not before 24 hours: %d", n)
	}
	// A restart in between does not forget it or report it again: since and last are in the state.
	w.a = w.restart()
	w.clock.add(2 * time.Hour)
	refresh()
	w.publishSync()
	ex := exceptions(w)
	if len(ex) != 2 || !strings.Contains(ex[1], "still unresolved, 25h0m0s") || !strings.Contains(ex[1], "has lasted 25h0m0s") {
		t.Fatalf("again after 24 hours, with how long it has lasted: %v", ex)
	}
	w.publishSync()
	if len(exceptions(w)) != 2 {
		t.Fatal("reported again at once")
	}
	// It clears: api's claim on web goes. One record says so.
	w.dropClaims(ch3)
	w.publishSync()
	ex = exceptions(w)
	if len(ex) != 3 || !strings.Contains(ex[2], "cleared after 25h0m0s") {
		t.Fatalf("once when it clears: %v", ex)
	}
	w.publishSync()
	if len(exceptions(w)) != 3 {
		t.Fatal("cleared twice")
	}
}

// -- 3. opt-out and namespaces the agent is not configured for ------------------------------------------------------

func TestAnApplicationWhoseNamespaceTheAgentIsNotConfiguredForIsNotSwitched(t *testing.T) {
	w := newOptWorld(t)
	w.a = mustAgent(t, w, func(c *agent.Config) { c.OptIn.Namespaces = []string{"app-a"} })
	w.addApp("web-prod", "app-a", protect())
	w.addApp("other-prod", "app-z", protect())
	w.mustReconcile()
	if !w.isSwitched("web-prod") || w.isSwitched("other-prod") {
		t.Fatalf("switched web %v other %v", w.isSwitched("web-prod"), w.isSwitched("other-prod"))
	}
	var st map[string]string
	_ = json.Unmarshal([]byte(w.kube.data["clearance-system/clearance-argocd-agent-state"]["optin.json"]), &st)
	if !strings.Contains(st["argocd-apps/other-prod"], "not one the agent is configured for") {
		t.Errorf("reported: %v", st)
	}
}

func TestAnOptOutIsNotHeldByARefusedUnlabelOfANamespaceTheAgentCannotHaveLabelled(t *testing.T) {
	forbidden := &agent.StatusError{Code: 403, Body: "namespaces is forbidden"}
	build := func(configured ...string) *optWorld {
		w := newOptWorld(t)
		w.a = mustAgent(t, w, func(c *agent.Config) { c.OptIn.Namespaces = []string{"app-a", "app-z"} })
		w.addApp("web-prod", "app-z", protect())
		w.mustReconcile()
		if !w.isSwitched("web-prod") {
			t.Fatal("setup")
		}
		w.kube.ns["app-z"] = map[string]string{agent.LabelProtected: "true", agent.LabelProtectedBy: agent.ProtectedByOptIn}
		w.kube.failNS["app-z"] = forbidden
		w.setAnn("web-prod", agent.AnnProtect, nil)
		w.a = mustAgent(t, w, func(c *agent.Config) { c.OptIn.Namespaces = configured })
		return w
	}
	// The namespace left the agent's configuration: it can never have labelled it now, so the 403 is no reason to hold the opt-out.
	w := build("app-a")
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("the opt-out hangs on a refused unlabel of a namespace the agent is not configured for")
	}
	// A configured namespace keeps the fail-closed behaviour: the opt-out waits.
	w = build("app-a", "app-z")
	_ = w.reconcile()
	if !w.isSwitched("web-prod") {
		t.Fatal("the Application was put back although the label could not come off")
	}
}

// -- 4. the environment the namespace says --------------------------------------------------------------------------

func TestTheNamespacesEnvironmentLabelDecidesAndADisagreeingApplicationIsBlocked(t *testing.T) {
	w := newOptWorld(t)
	w.kube.ns["app-a"] = map[string]string{agent.LabelEnvironment: "prod"}
	a := w.addApp("web-prod", "app-a", protect())
	a.Labels[agent.LabelAppEnv] = "dev" // someone labelled their Application with a laxer environment
	w.addApp("api-prod", "app-a", protect())
	for i := range w.kube.apps { // api has no env label of its own: the namespace's wins
		if w.kube.apps[i].Name == "api-prod" {
			delete(w.kube.apps[i].Labels, agent.LabelAppEnv)
		}
	}
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("an Application whose env label disagrees with its namespace's was switched")
	}
	if !w.isSwitched("api-prod") {
		t.Fatal("not switched")
	}
	if _, p := w.plugin("api-prod"); p["env"] != "prod" {
		t.Errorf("the namespace's environment: %v", p)
	}
	if fmt.Sprint(lastReport(w)) != "[api/prod]" {
		t.Errorf("no (web, dev) pair: %v", lastReport(w))
	}
	var st map[string]string
	_ = json.Unmarshal([]byte(w.kube.data["clearance-system/clearance-argocd-agent-state"]["optin.json"]), &st)
	if !strings.Contains(st["argocd-apps/web-prod"], "disagrees with its namespace") {
		t.Errorf("reported: %v", st)
	}
}

func TestANamespaceThatCannotBeReadMakesTheEnvironmentUnknownNotTheDefault(t *testing.T) {
	w := newOptWorld(t)
	w.kube.ns["app-a"] = map[string]string{agent.LabelEnvironment: "prod"}
	w.addApp("web-prod", "app-a", protect())
	for i := range w.kube.apps {
		delete(w.kube.apps[i].Labels, agent.LabelAppEnv)
	}
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync()
	_, p := w.plugin("web-prod")
	grants := w.kube.verbs["update"] + w.kube.verbs["create"]
	apps, reports := w.kube.verbs["app"], len(w.core.reports)
	w.kube.nsReadErr["app-a"] = errBoom
	w.clock.add(10 * time.Minute) // a heartbeat is due
	_ = w.reconcile()
	if w.kube.verbs["app"] != apps || len(w.core.reports) != reports {
		t.Fatalf("an Application with an unknown environment was rewritten or its pair reported: %d %d", w.kube.verbs["app"]-apps, len(w.core.reports)-reports)
	}
	if got := fmt.Sprint(lastReport(w)); got != "[web/prod]" {
		t.Fatalf("the pair stays: %s", got)
	}
	w.feeds.claims[0].Expires = w.clock.now().Add(time.Hour).Unix()
	w.feeds.claims[0].IssuedAt = w.clock.now().Add(-time.Second).Unix()
	w.feeds.publish()
	if err := w.sync(); err == nil {
		t.Fatal("expected the grant pass to refuse")
	}
	if w.kube.verbs["update"]+w.kube.verbs["create"] != grants || w.mergedObjects("app-a") != "apps/Deployment/web=a" {
		t.Fatalf("the grant changed (claims dropped) while the environment was unknown: %s", w.mergedObjects("app-a"))
	}
	_, p2 := w.plugin("web-prod")
	if p2["env"] != p["env"] || p2["env"] != "prod" {
		t.Fatalf("the parameter was rewritten with the default: %v", p2)
	}
}

func TestWithTheOptInOffTheEnvironmentLabelIsReadAsBefore(t *testing.T) {
	w := newWorld(t) // opt-in off
	w.kube.protect("app-a", map[string]string{agent.LabelEnvironment: "staging"})
	app := agent.Application{Namespace: "argocd-apps", Name: "web", Project: "tenants", DestNS: "app-a",
		Labels: map[string]string{agent.LabelAppEnv: "dev"}}
	rec, err := w.a.OutcomeRecord(bg, withOp(app))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Record.Destination["environment"] != "dev" {
		t.Fatalf("outcomes keep the Application's own label: %v", rec.Record.Destination)
	}
}

func withOp(a agent.Application) agent.Application {
	a.Op = succeeded("2026-11-07T12:00:05Z")
	return a
}

// -- 5. marker forging, projects, destination -------------------------------------------------------------------------

func TestAnnotatingAForeignPluginApplicationDoesNotGetItRestored(t *testing.T) {
	w := newOptWorld(t)
	// Someone put this Application on the plugin by hand (the Airframe-chart parameters of G-ARGO-4).
	foreign := `{"repoURL":"https://git.example.test/o/r.git","path":".","plugin":{"name":"clearance","parameters":[{"name":"app","string":"web"}]}}`
	w.addApp("web-prod", "app-a", map[string]string{agent.AnnSwitched: "source"}, foreign) // and an annotate-only user adds the marker
	before := w.writes()
	w.mustReconcile()
	w.mustReconcile()
	w.noNewWrites(before, "a forged marker", "put")
	if !w.isSwitched("web-prod") {
		t.Fatal("the foreign Application was restored off the plugin: a protection bypass")
	}
	var st map[string]string
	_ = json.Unmarshal([]byte(w.kube.data["clearance-system/clearance-argocd-agent-state"]["optin.json"]), &st)
	if !strings.Contains(st["argocd-apps/web-prod"], "left alone") {
		t.Errorf("reported once: %v", st)
	}
	// And with the agent's parameter present but disagreeing with the annotation, still not the agent's.
	w2 := newOptWorld(t)
	w2.addApp("web-prod", "app-a", map[string]string{agent.AnnSwitched: "sources"},
		`{"repoURL":"https://git.example.test/o/r.git","plugin":{"name":"clearance","parameters":[{"name":"switched","string":"source"}]}}`)
	w2.mustReconcile()
	if !w2.isSwitched("web-prod") {
		t.Fatal("restored on disagreeing halves")
	}
}

func TestAnApplicationOutsideTheAgentsProjectsIsNeverTouched(t *testing.T) {
	w := newOptWorld(t)
	a := w.addApp("web-prod", "app-a", protect())
	a.Project = "someone-elses"
	before := w.writes()
	w.mustReconcile()
	w.noNewWrites(before, "another project", "put")
	if w.isSwitched("web-prod") || len(lastReport(w)) != 0 {
		t.Fatal("an Application outside the agent's projects was switched or reported")
	}
}

func TestAnApplicationForAnotherClusterIsNeverSwitched(t *testing.T) {
	for name, edit := range map[string]func(*agent.Application){
		"another server":  func(a *agent.Application) { a.DestServer = "https://other.example.test" },
		"a named cluster": func(a *agent.Application) { a.DestServer, a.DestName = "", "prod-2" },
		"no destination":  func(a *agent.Application) { a.DestServer = "" },
	} {
		w := newOptWorld(t)
		a := w.addApp("web-prod", "app-a", protect())
		edit(a)
		w.mustReconcile()
		if w.isSwitched("web-prod") {
			t.Errorf("%s: switched", name)
		}
	}
	w := newOptWorld(t)
	a := w.addApp("web-prod", "app-a", protect())
	a.DestServer, a.DestName = "", "in-cluster"
	w.mustReconcile()
	if !w.isSwitched("web-prod") {
		t.Error("the in-cluster name is this cluster")
	}
}

// -- 6. parent cycle, throttle across a restart -----------------------------------------------------------------------

func TestAParentTheChildItselfCreatedIsNotAnAppOfApps(t *testing.T) {
	w := newOptWorld(t)
	// The child names a dummy parent that has everything the check wants, and the dummy is tracked to the child.
	p := w.addApp("dummy", "argocd-apps", nil)
	p.IgnoreDifferences, p.SyncOptions = []agent.IgnoreDifference{ignoreBoth}, respect
	p.Annotations = map[string]string{agent.AnnTracking: "web:argoproj.io/Application:argocd-apps/dummy"}
	child(w, "web", "dummy")
	w.mustReconcile()
	if w.isSwitched("web") {
		t.Fatal("a self-made parent passed the check")
	}
	// An owner reference is preferred to the labels: the real parent is the one that fails.
	w2 := newOptWorld(t)
	parentApp(w2, "real", respect) // no ignoreDifferences
	parentApp(w2, "dummy", respect, ignoreBoth)
	c := w2.addApp("web", "app-web", protect())
	c.Annotations[agent.AnnTracking] = "dummy:argoproj.io/Application:argocd-apps/web"
	c.Owners = []agent.OwnerRef{{Kind: "Application", Name: "real"}}
	w2.mustReconcile()
	if w2.isSwitched("web") {
		t.Fatal("the label's parent was preferred to the owner reference")
	}
}

func TestTheWriteBoundSurvivesARestart(t *testing.T) {
	w := newOptWorld(t)
	orig := w.addApp("web-prod", "app-a", protect())
	src := orig.Source
	revert := func() {
		for i := range w.kube.apps {
			if w.kube.apps[i].Name == "web-prod" {
				w.kube.apps[i].Source = src
				w.kube.apps[i].ResourceVersion += "0"
			}
		}
	}
	// A crash loop: the agent restarts before every pass, so nothing in memory could bound it.
	for i := 0; i < 10; i++ {
		w.a = w.restart()
		w.mustReconcile()
		revert()
		w.clock.add(time.Minute)
	}
	if n := w.kube.verbs["app"]; n != 3 {
		t.Fatalf("%d writes in 10 minutes of a crash loop: the bound is 3 per 10 minutes whatever the restarts", n)
	}
}

// -- 7. windows and records -----------------------------------------------------------------------------------------

func TestSwitchingAnOperatorLabelledNamespaceActivatesTheMergedGrantBeforeTheOldOneGoes(t *testing.T) {
	w := newOptWorld(t)
	w.kube.protect("app-a", nil)
	w.addApp("web-prod", "app-a", protect())
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync() // a per-change grant is active first (the namespace is labelled by an operator, the Application not switched yet)
	if !w.grant("app-a", ch1).Active() {
		t.Fatal("setup")
	}
	w.kube.log = nil
	w.mustReconcile() // the Application is switched
	w.publishSync()   // now the merged grant takes over: the fake fails the test if there is ever no active grant
	m, o := indexOf(w.kube.log, "update app-a/"+agent.MergedGrantName+" active=true"), indexOf(w.kube.log, "update app-a/"+ch1+" active=false")
	if m < 0 || o < 0 || m > o {
		t.Fatalf("the merged grant is activated before the per-change one is deactivated: %v", w.kube.log)
	}
}

func TestDeletingAnAnnotatedApplicationIsAnOptOutOnTheCoresRecord(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	w.kube.apps = nil // the Application is deleted
	w.mustReconcile()
	r := w.core.reports[len(w.core.reports)-1]
	if len(r.Pairs) != 0 || !strings.Contains(r.Reason, "application deleted (web/prod)") {
		t.Fatalf("%+v", r)
	}
	// It survives a restart: the pairs the core took are in the state.
	w2 := newOptWorld(t)
	w2.addApp("api-prod", "app-a", protect())
	w2.mustReconcile()
	w2.kube.apps = nil
	w2.a = w2.restart()
	w2.mustReconcile()
	if r := w2.core.reports[len(w2.core.reports)-1]; !strings.Contains(r.Reason, "application deleted (api/prod)") {
		t.Fatalf("after a restart: %+v", r)
	}
}

func TestOptingOutOneOfTwoApplicationsOfAPairIsRecorded(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	b := w.addApp("web-copy", "app-b", protect())
	b.Labels[agent.LabelAppName] = "web"
	w.mustReconcile()
	n := len(w.core.reports)
	w.setAnn("web-copy", agent.AnnProtect, nil)
	w.mustReconcile()
	if len(w.core.reports) != n+1 {
		t.Fatalf("an opt-out that changes no set is still reported: %d", len(w.core.reports)-n)
	}
	r := w.core.reports[n]
	if len(r.Pairs) != 1 || !strings.Contains(r.Reason, "web-copy opted out (web/prod, the pair stays protected by another Application)") {
		t.Fatalf("%+v", r)
	}
	w.mustReconcile()
	if len(w.core.reports) != n+1 {
		t.Fatal("reported again")
	}
}

// -- 8. report numbers ----------------------------------------------------------------------------------------------

func TestReportNumbersOnlyGoUpAndSurviveARestart(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	w.clock.add(6 * time.Minute)
	w.mustReconcile() // a heartbeat: the same set, the same number
	w.a = w.restart()
	w.clock.add(6 * time.Minute)
	w.mustReconcile()
	w.addApp("api-prod", "app-b", protect())
	w.mustReconcile() // a change
	var seqs []int64
	for _, r := range w.core.reports {
		seqs = append(seqs, r.Seq)
	}
	if fmt.Sprint(seqs) != "[1 1 1 2]" {
		t.Fatalf("numbers %v: a heartbeat repeats the number, a change goes up, a restart continues", seqs)
	}
	// The state is lost: the agent starts from the core's last number.
	w.core.heldSeq = 41
	w.kube.data = map[string]map[string]string{}
	w.a = w.restart()
	w.setAnn("api-prod", agent.AnnProtect, nil)
	w.mustReconcile()
	if last := w.core.reports[len(w.core.reports)-1]; last.Seq != 42 {
		t.Fatalf("after a state loss: %d, want 42", last.Seq)
	}
}

// -- 9. one namespace listing per pass --------------------------------------------------------------------------------

func TestTheProtectedNamespacesAreListedOncePerGrantPass(t *testing.T) {
	w := newOptWorld(t)
	for i := 0; i < 6; i++ {
		w.addApp(fmt.Sprintf("app%d-prod", i), "app-a", protect())
	}
	w.mustReconcile()
	feedObjs(w, "app0", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync()
	n := w.kube.nsLists
	w.publishSync()
	if got := w.kube.nsLists - n; got != 1 {
		t.Fatalf("%d listings in one pass with six Applications", got)
	}
}
