package agent_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// -- the deny list --------------------------------------------------------------------------------------------------

func TestDeniedApplicationsAreNeverSwitched(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("clearance-api", "clearance-system", protect())
	w.addApp("clearance", "clearance-system", protect())
	w.addApp("prod-clearance", "clearance-system", protect())
	w.addApp("web-prod", "app-web-prod", protect())
	w.mustReconcile()
	for _, n := range []string{"clearance-api", "clearance", "prod-clearance"} {
		if w.isSwitched(n) {
			t.Errorf("%s is on the deny list and was switched", n)
		}
	}
	if !w.isSwitched("web-prod") {
		t.Error("an Application the list does not name is switched")
	}
	if fmt.Sprint(lastReport(w)) != "[web/prod]" {
		t.Errorf("a denied Application is not a protected pair: %v", lastReport(w))
	}
	var st map[string]string
	if err := json.Unmarshal([]byte(w.kube.data["clearance-system/clearance-argocd-agent-state"]["optin.json"]), &st); err != nil ||
		!strings.HasPrefix(st["argocd-apps/clearance-api"], "denied") || st["argocd-apps/web-prod"] != "switched" {
		t.Errorf("the status ConfigMap: %v %v", st, err)
	}
}

func TestADeniedApplicationThatWasSwitchedIsPutBack(t *testing.T) {
	w := newOptWorld(t)
	orig := w.addApp("tools-prod", "app-tools-prod", protect())
	want := orig.Source
	w.mustReconcile()
	if !w.isSwitched("tools-prod") {
		t.Fatal("not switched")
	}
	// The deny list grows (a new agent setting) and names it.
	a := w.restart()
	_ = a
	cfgDeny := func() {
		ag, err := newAgentDeny(w, "tools-*")
		if err != nil {
			t.Fatal(err)
		}
		w.a = ag
	}
	cfgDeny()
	w.mustReconcile()
	if w.isSwitched("tools-prod") {
		t.Fatal("a denied Application stays on the plugin")
	}
	sameRaw(t, string(w.app("tools-prod").Source), string(want))
	if !strings.Contains(w.core.reports[len(w.core.reports)-1].Reason, "denied (tools/prod)") || len(lastReport(w)) != 0 {
		t.Errorf("the removal is on the core's record: %+v", w.core.reports)
	}
}

// -- parents --------------------------------------------------------------------------------------------------------

func parentApp(w *optWorld, name string, opts []string, ign ...agent.IgnoreDifference) {
	p := w.addApp(name, "argocd-apps", nil)
	p.IgnoreDifferences, p.SyncOptions = ign, opts
}

func child(w *optWorld, name string, parent string) {
	c := w.addApp(name, "app-"+name, protect())
	c.Annotations[agent.AnnTracking] = parent + ":argoproj.io/Application:argocd-apps/" + name
}

var respect = []string{"CreateNamespace=true", "RespectIgnoreDifferences=true"}
var ignoreBoth = agent.IgnoreDifference{Group: "argoproj.io", Kind: "Application", JSONPointers: []string{"/spec/source", "/spec/sources"}}

func TestTheParentMustIgnoreTheSources(t *testing.T) {
	type tc struct {
		name    string
		opts    []string
		ign     []agent.IgnoreDifference
		switch_ bool
		why     string
	}
	for _, c := range []tc{
		{"complete", respect, []agent.IgnoreDifference{ignoreBoth}, true, ""},
		{"jq form", respect, []agent.IgnoreDifference{{Group: "argoproj.io", Kind: "Application", JQPathExpressions: []string{".spec.source", ".spec.sources"}}}, true, ""},
		{"the whole spec", respect, []agent.IgnoreDifference{{Group: "argoproj.io", Kind: "Application", JSONPointers: []string{"/spec"}}}, true, ""},
		{"split over two entries", respect, []agent.IgnoreDifference{
			{Group: "argoproj.io", Kind: "Application", JSONPointers: []string{"/spec/source"}},
			{Group: "argoproj.io", Kind: "Application", JSONPointers: []string{"/spec/sources"}}}, true, ""},
		{"for this child by name", respect, []agent.IgnoreDifference{{Group: "argoproj.io", Kind: "Application", Name: "web", JSONPointers: []string{"/spec/source", "/spec/sources"}}}, true, ""},
		{"no entry", respect, nil, false, "no spec.ignoreDifferences entry"},
		{"only source", respect, []agent.IgnoreDifference{{Group: "argoproj.io", Kind: "Application", JSONPointers: []string{"/spec/source"}}}, false, "no spec.ignoreDifferences entry"},
		{"another kind", respect, []agent.IgnoreDifference{{Group: "apps", Kind: "Deployment", JSONPointers: []string{"/spec/source", "/spec/sources"}}}, false, "no spec.ignoreDifferences entry"},
		{"another Application by name", respect, []agent.IgnoreDifference{{Group: "argoproj.io", Kind: "Application", Name: "other", JSONPointers: []string{"/spec/source", "/spec/sources"}}}, false, "no spec.ignoreDifferences entry"},
		{"no RespectIgnoreDifferences", []string{"CreateNamespace=true"}, []agent.IgnoreDifference{ignoreBoth}, false, "RespectIgnoreDifferences=true"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newOptWorld(t)
			parentApp(w, "root", c.opts, c.ign...)
			child(w, "web", "root")
			before := w.writes()
			w.mustReconcile()
			if w.isSwitched("web") != c.switch_ {
				t.Fatalf("switched %v, want %v", w.isSwitched("web"), c.switch_)
			}
			if c.switch_ {
				return
			}
			w.noNewWrites(before, "an Application whose parent would fight", "put")
			var st map[string]string
			_ = json.Unmarshal([]byte(w.kube.data["clearance-system/clearance-argocd-agent-state"]["optin.json"]), &st)
			if !strings.Contains(st["argocd-apps/web"], "blocked") || !strings.Contains(st["argocd-apps/web"], c.why) || !strings.Contains(st["argocd-apps/web"], "root") {
				t.Errorf("the check reports what is missing and where: %q", st["argocd-apps/web"])
			}
			// The pair is still protected at the core: protection is not withheld because the switch was.
			if fmt.Sprint(lastReport(w)) != "[web/prod]" {
				t.Errorf("report: %v", lastReport(w))
			}
		})
	}
}

func TestTheParentIsFoundByLabelTrackingToo(t *testing.T) {
	w := newOptWorld(t)
	parentApp(w, "root", respect)
	c := w.addApp("web", "app-web", protect())
	c.Labels["app.kubernetes.io/instance"] = "root"
	w.mustReconcile()
	if w.isSwitched("web") {
		t.Fatal("the label names a parent with no ignoreDifferences")
	}
}

func TestAParentTheAgentCannotSeeBlocks(t *testing.T) {
	w := newOptWorld(t)
	child(w, "web", "elsewhere")
	w.mustReconcile()
	if w.isSwitched("web") {
		t.Fatal("switched with an unreadable parent")
	}
}

func TestAnApplicationSetOwnerMustIgnoreTheSources(t *testing.T) {
	w := newOptWorld(t)
	c := w.addApp("web", "app-web", protect())
	c.Owners = []agent.OwnerRef{{Kind: "ApplicationSet", Name: "tenants"}}
	w.mustReconcile()
	if w.isSwitched("web") {
		t.Fatal("switched with the owning ApplicationSet unreadable")
	}
	w.kube.appsets["tenants"] = agent.AppSet{Name: "tenants"}
	w.mustReconcile()
	if w.isSwitched("web") {
		t.Fatal("switched though the ApplicationSet ignores nothing")
	}
	w.kube.appsets["tenants"] = agent.AppSet{Name: "tenants", IgnoreApplicationDifferences: []agent.IgnoreDifference{{JSONPointers: []string{"/spec/source", "/spec/sources"}}}}
	w.mustReconcile()
	if !w.isSwitched("web") {
		t.Fatal("not switched though the ApplicationSet ignores both")
	}
}

func TestTheAgentNeverWritesAParent(t *testing.T) {
	w := newOptWorld(t)
	parentApp(w, "root", respect) // missing the entry
	child(w, "web", "root")
	w.mustReconcile()
	w.mustReconcile()
	for _, l := range w.kube.log {
		if strings.Contains(l, "app argocd-apps/root") {
			t.Fatalf("the parent was written: %v", w.kube.log)
		}
	}
}

// -- sources the plugin cannot carry --------------------------------------------------------------------------------

func TestWhatTheAgentWillNotSwitch(t *testing.T) {
	chart := `{"repoURL":"https://charts.example.test","chart":"web","targetRevision":"1.2.3"}`
	plug := `{"repoURL":"https://git.example.test/org/gitops.git","path":".","plugin":{"name":"something-else"}}`
	cases := map[string]func(w *optWorld){
		"a chart from an HTTP repository only": func(w *optWorld) { w.addApp("a-prod", "ns", protect(), chart) },
		"a source that already uses a plugin":  func(w *optWorld) { w.addApp("a-prod", "ns", protect(), plug) },
		"no destination namespace":             func(w *optWorld) { w.addApp("a-prod", "", protect()) },
		"an app name that is not a DNS label": func(w *optWorld) {
			a := w.addApp("a-prod", "ns", protect())
			a.Labels[agent.LabelAppName] = "Not_A_Label"
		},
		"the plugin without the agent's marker": func(w *optWorld) {
			w.addApp("a-prod", "ns", protect(), `{"repoURL":"https://git.example.test/o/r.git","path":".","plugin":{"name":"clearance","parameters":[{"name":"app","string":"a"}]}}`)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			w := newOptWorld(t)
			setup(w)
			before := w.writes()
			w.mustReconcile()
			w.noNewWrites(before, name, "put")
			if w.app("a-prod").Annotations[agent.AnnSwitched] != "" {
				t.Error("marked as switched")
			}
		})
	}
}

func TestAChartPlusAGitSourceIsCarriedByTheGitOne(t *testing.T) {
	chart := `{"repoURL":"https://charts.example.test","chart":"web","targetRevision":"1.2.3","helm":{"valueFiles":["$vals/v.yaml"]}}`
	w := newOptWorld(t)
	w.addApp("web-prod", "ns", protect(), chart, origVals)
	w.mustReconcile()
	v, p := w.plugin("web-prod")
	if v.RepoURL != "https://git.example.test/org/gitops.git" || p["sources"] != "["+chart+","+origVals+"]" && !strings.Contains(p["sources"], `"chart":"web"`) {
		t.Errorf("%+v %v", v, p)
	}
	if w.app("web-prod").Annotations[agent.AnnSwitched] != "sources" || len(w.app("web-prod").Sources) != 1 {
		t.Errorf("a sources Application keeps its shape: %v", w.app("web-prod").Sources)
	}
}

// -- discovery ------------------------------------------------------------------------------------------------------

func TestNothingIsSwitchedUntilTheClusterScopesAreRead(t *testing.T) {
	w := newOptWorld(t)
	w.kube.scopeErr = errors.New("discovery down")
	w.addApp("web-prod", "app-web-prod", protect())
	before := w.writes()
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("switched without the cluster's scopes: the plugin could stamp a namespace on a cluster-scoped object")
	}
	delete(before, "scopes")
	w.kube.scopeErr = nil
	w.clock.add(time.Minute)
	w.mustReconcile()
	if !w.isSwitched("web-prod") {
		t.Fatal("not switched once discovery answers")
	}
	// Discovery failing later keeps the last answer: no rewrite.
	w.kube.scopeErr = errors.New("discovery down")
	w.clock.add(time.Hour)
	before = w.writes()
	w.mustReconcile()
	w.noNewWrites(before, "a discovery failure after a good answer")
	// A change in the cluster (a new CRD) changes the parameter once.
	w.kube.scopeErr = nil
	w.kube.scopes["Provider"] = true
	w.clock.add(time.Hour)
	w.mustReconcile()
	if _, p := w.plugin("web-prod"); p["clusterScopedKinds"] != "!Cluster,Composition,Provider" {
		t.Errorf("clusterScopedKinds: %q", p["clusterScopedKinds"])
	}
}

// -- not fighting ---------------------------------------------------------------------------------------------------

func TestAFailedWriteIsRetriedWithBackoffAndAConflictIsRead(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-web-prod", protect())
	w.kube.failApp["web-prod"] = errors.New("apiserver unavailable")
	if err := w.reconcile(); err == nil {
		t.Fatal("a failed write is an error")
	}
	n := w.kube.verbs["app"]
	for i := 0; i < 5; i++ { // the loop wakes again at once (a watch event): no write before the backoff is over
		_ = w.reconcile()
	}
	if w.kube.verbs["app"] != n {
		t.Errorf("retried at once: %d writes", w.kube.verbs["app"])
	}
	delete(w.kube.failApp, "web-prod")
	w.clock.add(31 * time.Second)
	_ = w.reconcile()
	if w.kube.verbs["app"] != n+1 || !w.isSwitched("web-prod") {
		t.Errorf("after the backoff: %d writes, switched %v", w.kube.verbs["app"], w.isSwitched("web-prod"))
	}
}

func TestAConflictingWriteIsNotForced(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-web-prod", protect())
	w.kube.failApp["web-prod"] = fmt.Errorf("%w: someone else wrote", agent.ErrConflict)
	if err := w.reconcile(); !errors.Is(err, agent.ErrConflict) {
		t.Fatalf("%v", err)
	}
	if w.isSwitched("web-prod") {
		t.Fatal("a conflict was overwritten")
	}
}

func TestTheAgentDoesNotFightSomethingThatPutsTheOriginalBack(t *testing.T) {
	w := newOptWorld(t)
	orig := w.addApp("web-prod", "app-web-prod", protect())
	src := orig.Source
	revert := func() { // the parent, or a person, puts the original back
		for i := range w.kube.apps {
			if w.kube.apps[i].Name == "web-prod" {
				w.kube.apps[i].Source = src
				w.kube.apps[i].ResourceVersion += "0"
			}
		}
	}
	for i := 0; i < 10; i++ {
		w.mustReconcile()
		revert()
		w.clock.add(time.Minute)
	}
	if n := w.kube.verbs["app"]; n != 3 {
		t.Fatalf("%d writes in 10 minutes against something that reverts every one: the bound is 3", n)
	}
	w.clock.add(11 * time.Minute) // the window has passed
	w.mustReconcile()
	if w.kube.verbs["app"] != 4 {
		t.Errorf("the agent writes again once the window has passed: %d", w.kube.verbs["app"])
	}
}

func TestAnAnnotationEditByAPersonIsPickedUpAtOnce(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	w.setAnn("web-prod", agent.AnnProtect, str("true"))
	w.mustReconcile()
	if !w.isSwitched("web-prod") {
		t.Fatal("not switched")
	}
}

// -- the core is down -----------------------------------------------------------------------------------------------

func TestAnOptOutAndANewSwitchBothWaitForTheCore(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-web-prod", protect())
	w.mustReconcile()
	feedClaims(w, "web", "app-web-prod", ch1, hex("a"))
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	if w.kube.ns["app-web-prod"][agent.LabelProtected] != "true" {
		t.Fatal("not labelled")
	}
	w.core.reportDown = true
	w.setAnn("web-prod", agent.AnnProtect, nil)
	w.clock.add(70 * time.Second) // past the report debounce
	w.addApp("api-prod", "app-api-prod", protect())
	_ = w.reconcile()
	if !w.isSwitched("web-prod") || w.kube.ns["app-web-prod"][agent.LabelProtected] != "true" {
		t.Fatal("an opt-out the core has not recorded was acted on: protection dropped silently")
	}
	if w.isSwitched("api-prod") {
		t.Fatal("a new opt-in was switched before the core took its pair")
	}
	if err := w.sync(); err != nil { // the grant loop does not unlabel either
		t.Fatal(err)
	}
	if w.kube.ns["app-web-prod"][agent.LabelProtected] != "true" || len(w.kube.grants) == 0 {
		t.Fatalf("the grant loop removed protection while the core could not record it: %v", w.kube.log)
	}
	w.core.reportDown = false
	w.mustReconcile() // the addition goes first, on its own; the removal is coalesced into the next report
	w.clock.add(70 * time.Second)
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("not restored once the core took the removal")
	}
	w.mustReconcile()
	if !w.isSwitched("api-prod") {
		t.Fatal("not switched once the core took its pair")
	}
}

func TestAnAgentThatCannotReadTheApplicationsReportsAndChangesNothing(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-web-prod", protect())
	w.mustReconcile()
	reports := len(w.core.reports)
	w.kube.listAppErr = errors.New("forbidden")
	before := w.writes()
	if err := w.reconcile(); err == nil {
		t.Fatal("expected the error")
	}
	w.clock.add(time.Hour)
	_ = w.reconcile()
	w.noNewWrites(before, "an unreadable Application list")
	if len(w.core.reports) != reports {
		t.Errorf("a report (an empty one would remove every pair) was sent from a list that failed")
	}
}

func TestARemovedPairThatTheCoreStillProtectsIsLoggedAndRestored(t *testing.T) {
	w := newOptWorld(t)
	w.core.static["web/prod"] = true
	w.addApp("web-prod", "app-web-prod", protect())
	w.mustReconcile()
	w.setAnn("web-prod", agent.AnnProtect, nil)
	w.clock.add(70 * time.Second) // past the report debounce
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("restored when the core says the pair is still protected: the removal is recorded, the Application returns to its original")
	}
}

func TestARestartContinuesWhereItStopped(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-web-prod", protect())
	w.mustReconcile()
	w.a = w.restart()
	before := w.writes()
	w.mustReconcile()
	w.noNewWrites(before, "a restart")
	if len(w.core.reports) != 2 {
		t.Errorf("a restart reports the set again (the core de-duplicates): %d", len(w.core.reports))
	}
}
