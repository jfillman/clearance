package agent_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/token"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// G-ARGO-10c: the annotation opt-in, against the fakes (fakes_test.go, optin_fakes_test.go).

const origHelm = `{"repoURL":"https://git.example.test/org/gitops.git","path":"charts/web","targetRevision":"main","helm":{"valueFiles":["values.yaml"],"parameters":[{"name":"image.tag","value":"1.2.3"}]}}`
const origVals = `{"repoURL":"https://git.example.test/org/gitops.git","targetRevision":"main","ref":"vals"}`

type optWorld struct {
	*world
}

func newOptWorld(t *testing.T) *optWorld {
	w := newWorld(t)
	ow := &optWorld{w}
	ow.a = ow.restart()
	ow.kube.scopes = map[string]bool{"Namespace": true, "Deployment": false, "Composition": true, "Cluster": false}
	ow.core.static = map[string]bool{}
	return ow
}

// restart is a new agent process over the same cluster, with the opt-in on.
func (w *optWorld) restart() *agent.Agent {
	a, err := agent.New(agent.Config{Cluster: "hangar-prod", Environment: "prod", Version: "0.0.0-test", Wait: agent.TestWaitPin,
		ArgoNamespace: "argocd-apps", Projects: []string{"tenants"}, StateNS: "clearance-system",
		OptIn: agent.OptIn{Enabled: true, DenyApps: agent.DefaultDenyApps}},
		w.kube, w.feeds, w.core, w.clock.now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		w.t.Fatal(err)
	}
	if err := a.Load(bg); err != nil {
		w.t.Fatal(err)
	}
	return a
}

func (w *optWorld) reconcile() error { return w.a.ReconcileOptIn(bg) }

// mustReconcile fails the test on an error.
func (w *optWorld) mustReconcile() {
	w.t.Helper()
	if err := w.reconcile(); err != nil {
		w.t.Fatal(err)
	}
}

// addApp puts an Application (the tenants project, argocd-apps) in the cluster.
func (w *optWorld) addApp(name, destNS string, ann map[string]string, srcs ...string) *agent.Application {
	a := agent.Application{Namespace: "argocd-apps", Name: name, Project: "tenants", DestNS: destNS, ResourceVersion: "1",
		Labels:      map[string]string{agent.LabelAppName: strings.TrimSuffix(name, "-prod"), agent.LabelAppEnv: "prod"},
		Annotations: ann}
	if len(srcs) == 0 {
		srcs = []string{origHelm}
	}
	if len(srcs) == 1 {
		a.Source = json.RawMessage(srcs[0])
	} else {
		for _, s := range srcs {
			a.Sources = append(a.Sources, json.RawMessage(s))
		}
	}
	w.kube.apps = append(w.kube.apps, a)
	return &w.kube.apps[len(w.kube.apps)-1]
}

func (w *optWorld) app(name string) agent.Application {
	for _, a := range w.kube.apps {
		if a.Name == name {
			return a
		}
	}
	w.t.Fatalf("no Application %s", name)
	return agent.Application{}
}

// setAnn sets (v != nil) or removes an annotation of an Application, as a person or the parent would.
func (w *optWorld) setAnn(name, key string, v *string) {
	for i := range w.kube.apps {
		if w.kube.apps[i].Name == name {
			m := map[string]string{}
			for a, b := range w.kube.apps[i].Annotations {
				m[a] = b
			}
			if v == nil {
				delete(m, key)
			} else {
				m[key] = *v
			}
			w.kube.apps[i].Annotations = m
			return
		}
	}
	w.t.Fatalf("no Application %s", name)
}

func str(s string) *string { return &s }

func protect() map[string]string { return map[string]string{agent.AnnProtect: "true"} }

type pluginView struct {
	Plugin struct {
		Name       string `json:"name"`
		Parameters []struct {
			Name   string `json:"name"`
			String string `json:"string"`
		} `json:"parameters"`
	} `json:"plugin"`
	RepoURL        string `json:"repoURL"`
	Path           string `json:"path"`
	TargetRevision string `json:"targetRevision"`
}

// plugin reads the plugin source of a switched Application and its parameters.
func (w *optWorld) plugin(name string) (pluginView, map[string]string) {
	w.t.Helper()
	a := w.app(name)
	raw := a.Source
	if len(raw) == 0 && len(a.Sources) > 0 {
		raw = a.Sources[0]
	}
	var v pluginView
	if err := json.Unmarshal(raw, &v); err != nil || v.Plugin.Name == "" {
		w.t.Fatalf("%s is not on the plugin: %s", name, raw)
	}
	p := map[string]string{}
	for _, x := range v.Plugin.Parameters {
		p[x.Name] = x.String
	}
	return v, p
}

func (w *optWorld) isSwitched(name string) bool {
	a := w.app(name)
	raw := a.Source
	if len(raw) == 0 && len(a.Sources) > 0 {
		raw = a.Sources[0]
	}
	var v pluginView
	return json.Unmarshal(raw, &v) == nil && v.Plugin.Name != ""
}

func sameRaw(t *testing.T, got, want string) {
	t.Helper()
	var x, y any
	if err := json.Unmarshal([]byte(got), &x); err != nil {
		t.Fatalf("got %q: %v", got, err)
	}
	_ = json.Unmarshal([]byte(want), &y)
	if !reflect.DeepEqual(x, y) {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}

// writes is every write the agent made to the cluster (not the core).
func (w *optWorld) writes() map[string]int {
	out := map[string]int{}
	for k, v := range w.kube.verbs {
		out[k] = v
	}
	return out
}

// noNewWrites fails if the agent wrote anything to the cluster since before; ignore names verbs that are allowed (the
// status ConfigMap a blocked Application is reported in is one write, once).
func (w *optWorld) noNewWrites(before map[string]int, what string, ignore ...string) {
	w.t.Helper()
	after := w.writes()
	for _, k := range append(ignore, "scopes") {
		delete(before, k)
		delete(after, k)
	}
	if !reflect.DeepEqual(before, after) {
		w.t.Errorf("%s made writes: before %v after %v", what, before, after)
	}
}

func lastReport(w *optWorld) []string {
	if len(w.core.reports) == 0 {
		return nil
	}
	var out []string
	for _, p := range w.core.reports[len(w.core.reports)-1].Pairs {
		out = append(out, p.App+"/"+p.Env)
	}
	return out
}

// -- off by default -------------------------------------------------------------------------------------------------

func TestOptInIsOffByDefault(t *testing.T) {
	w := newWorld(t) // the default agent: no OptIn
	ow := &optWorld{w}
	ow.addApp("web-prod", "app-web-prod", protect())
	ow.kube.protect("app-web-prod", nil)
	if err := w.a.ReconcileOptIn(bg); err != nil {
		t.Fatal(err)
	}
	w.feeds.claims = []token.Claims{claim(w.feeds, ch1, "app-web-prod", t0, deploy("web", hex("a")))}
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	if v := w.kube.verbs; v["app"] != 0 || v["ns"] != 0 || v["scopes"] != 0 || len(w.core.reports) != 0 {
		t.Errorf("an agent without the opt-in wrote %v and reported %v", v, w.core.reports)
	}
	// The grants are the per-change ones, exactly as before.
	if g := w.grant("app-web-prod", ch1); !g.Active() {
		t.Errorf("the per-change grant is the active one: %v", g.Labels)
	}
	for k := range w.kube.grants {
		if strings.Contains(k, agent.MergedGrantName) {
			t.Errorf("a merged grant without the opt-in: %s", k)
		}
	}
	if len(ow.app("web-prod").Annotations) != 1 || ow.isSwitched("web-prod") {
		t.Error("the Application was changed")
	}
}

// -- annotate, restore ----------------------------------------------------------------------------------------------

func TestAnnotatedApplicationIsSwitchedAndItsOriginalHandedOver(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-web-prod", protect())
	w.mustReconcile()
	v, p := w.plugin("web-prod")
	if v.Plugin.Name != "clearance" || v.RepoURL != "https://git.example.test/org/gitops.git" || v.Path != "charts/web" || v.TargetRevision != "main" {
		t.Errorf("the plugin source takes the first git source: %+v", v)
	}
	sameRaw(t, p["sources"], "["+origHelm+"]") // the original, unchanged, is the plugin's `sources`
	if p["app"] != "web" || p["env"] != "prod" || p["cluster"] != "hangar-prod" {
		t.Errorf("identity parameters: %v", p)
	}
	// The cluster's discovery says Composition is cluster-scoped and Cluster is namespaced: the 10b renderer's rules differ.
	if p["clusterScopedKinds"] != "!Cluster,Composition" {
		t.Errorf("clusterScopedKinds: %q", p["clusterScopedKinds"])
	}
	if got := w.app("web-prod").Annotations[agent.AnnSwitched]; got != "source" {
		t.Errorf("the original shape is recorded: %q", got)
	}
	if got := w.app("web-prod").Annotations[agent.AnnProtect]; got != "true" {
		t.Errorf("the annotation is not the agent's to touch: %q", got)
	}
	if fmt.Sprint(lastReport(w)) != "[web/prod]" {
		t.Errorf("the pair is reported: %v", w.core.reports)
	}
}

func TestDeAnnotatingRestoresTheOriginalExactly(t *testing.T) {
	for name, srcs := range map[string][]string{"source": {origHelm}, "sources": {origHelm, origVals}} {
		t.Run(name, func(t *testing.T) {
			w := newOptWorld(t)
			orig := w.addApp("web-prod", "app-web-prod", protect(), srcs...)
			wantSource, wantSources := orig.Source, orig.Sources
			w.mustReconcile()
			if !w.isSwitched("web-prod") {
				t.Fatal("not switched")
			}
			w.setAnn("web-prod", agent.AnnProtect, nil)
			w.mustReconcile()
			got := w.app("web-prod")
			if w.isSwitched("web-prod") || got.Annotations[agent.AnnSwitched] != "" {
				t.Fatalf("not restored: %v %s", got.Annotations, got.Source)
			}
			if name == "source" {
				sameRaw(t, string(got.Source), string(wantSource))
				if len(got.Sources) != 0 {
					t.Errorf("sources appeared: %v", got.Sources)
				}
			} else {
				if len(got.Source) != 0 || len(got.Sources) != len(wantSources) {
					t.Fatalf("shape lost: %s %v", got.Source, got.Sources)
				}
				for i := range wantSources {
					sameRaw(t, string(got.Sources[i]), string(wantSources[i]))
				}
			}
			// The pair left the report, with the opt-out named in its reason.
			if len(lastReport(w)) != 0 || !strings.Contains(w.core.reports[len(w.core.reports)-1].Reason, "argocd-apps/web-prod opted out (web/prod)") {
				t.Errorf("the opt-out report: %+v", w.core.reports)
			}
		})
	}
}

func TestOnlyTheValueTrueOptsIn(t *testing.T) {
	for _, v := range []string{"True", "TRUE", "yes", "1", "", " true", "true ", "false", "enabled"} {
		w := newOptWorld(t)
		w.addApp("web-prod", "app-web-prod", map[string]string{agent.AnnProtect: v})
		before := w.writes()
		w.mustReconcile()
		if w.isSwitched("web-prod") || len(w.core.reports) > 0 && len(w.core.reports[0].Pairs) > 0 {
			t.Errorf("value %q opted in", v)
		}
		w.noNewWrites(before, fmt.Sprintf("value %q", v))
	}
}

func TestUnannotatedApplicationsAreNeverWritten(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-web-prod", nil)
	w.addApp("api-prod", "app-api-prod", map[string]string{"team": "x"})
	before := w.writes()
	w.mustReconcile()
	w.mustReconcile()
	w.noNewWrites(before, "Applications that never asked")
	if w.kube.verbs["put"] != 0 || w.kube.verbs["scopes"] != 0 {
		t.Errorf("state or discovery was touched for nothing: %v", w.kube.verbs)
	}
	for _, n := range []string{"web-prod", "api-prod"} {
		if w.isSwitched(n) || w.app(n).Annotations[agent.AnnSwitched] != "" {
			t.Errorf("%s was changed", n)
		}
	}
	if len(lastReport(w)) != 0 {
		t.Errorf("a pair for an Application that never asked: %v", lastReport(w))
	}
}

func TestASecondReconcileMakesNoWrites(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-web-prod", protect())
	w.addApp("api-prod", "app-web-prod", protect())
	w.mustReconcile()
	w.feeds.claims = []token.Claims{claim(w.feeds, ch1, "app-web-prod", t0, deploy("web", hex("a")))}
	w.feeds.claims[0].Target.App = "web"
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	if w.kube.ns["app-web-prod"][agent.LabelProtected] != "true" {
		t.Fatalf("the namespace is labelled once its merged grant is active: %v", w.kube.log)
	}
	before, reports, records := w.writes(), len(w.core.reports), len(w.core.records)
	w.mustReconcile()
	w.mustReconcile()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	w.noNewWrites(before, "a second reconcile and grant sync")
	if len(w.core.reports) != reports || len(w.core.records) != records {
		t.Errorf("the core was written to again: %d reports, %d records", len(w.core.reports)-reports, len(w.core.records)-records)
	}
	// After ReportEvery the same set is reported again: the core's sign that the agent is alive. No cluster write.
	w.clock.add(6 * time.Minute)
	w.feeds.claims[0].Expires = w.clock.now().Add(time.Hour).Unix()
	w.feeds.publish()
	before = w.writes()
	w.mustReconcile()
	if len(w.core.reports) != reports+1 {
		t.Errorf("the heartbeat: %d reports", len(w.core.reports)-reports)
	}
	w.noNewWrites(before, "a heartbeat")
}
