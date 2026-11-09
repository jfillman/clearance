package agent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
	"github.com/jfillman/clearance/internal/token"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// stamped is a live object as Argo CD's client-side apply leaves it: the rendered content plus the tracking id and
// the CMP's stamps, with the last-applied configuration. rendered is the hash of the content as the gate hashes it.
func stamped(t *testing.T, kind, name, ns, app, change, tree string) (agent.ObjectDetail, string) {
	t.Helper()
	apiVersion := "apps/v1"
	if kind == "ConfigMap" {
		apiVersion = "v1"
	}
	content := map[string]any{"apiVersion": apiVersion, "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": ns}, "spec": map[string]any{"replicas": 2}}
	raw, _ := json.Marshal(content)
	rendered, err := agent.ContentHash(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	ann := map[string]any{agent.AnnTracking: fmt.Sprintf("%s:%s/%s:%s/%s", app, strings.TrimSuffix(apiVersion, "/v1"), kind, ns, name),
		agent.AnnRendered: rendered, agent.AnnGrant: change, agent.AnnTree: "sha256:" + tree}
	content["metadata"].(map[string]any)["annotations"] = ann
	la, _ := json.Marshal(content)
	return agent.ObjectDetail{Object: agent.Object{APIVersion: apiVersion, Kind: kind, Namespace: ns, Name: name, UID: "uid-" + name,
		Annotations: map[string]string{agent.AnnTracking: ann[agent.AnnTracking].(string), agent.AnnRendered: rendered,
			agent.AnnGrant: change, agent.AnnTree: "sha256:" + tree, agent.AnnRelease: "chain-1:hangar-prod/prod"},
		Manager: "argocd-application-controller"}, LastApplied: string(la)}, rendered
}

func webApp(op *agent.Operation) agent.Application {
	return agent.Application{Namespace: "argocd-apps", Name: "web", UID: "uid-app", Project: "tenants", DestNS: "app-a",
		SyncState: "Synced", Health: "Healthy", Revisions: []string{"abc123"}, Op: op}
}

func succeeded(start string) *agent.Operation {
	return &agent.Operation{Phase: "Succeeded", StartedAt: start, FinishedAt: start, Revisions: []string{"abc123"}}
}

func TestOutcomes(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", map[string]string{agent.LabelEnvironment: "prod"})
	tree := hex("c")
	d, _ := stamped(t, "Deployment", "web", "app-a", "web", ch2, tree)
	c, _ := stamped(t, "ConfigMap", "cfg", "app-a", "web", ch2, tree)
	w.kube.objs["app-a"] = []agent.ObjectDetail{d, c}

	app := webApp(succeeded("2026-11-07T12:00:00Z"))
	if err := w.a.HandleApplication(bg, app); err != nil {
		t.Fatal(err)
	}
	recs := w.core.of("deploy.outcome")
	if len(recs) != 1 {
		t.Fatalf("%d outcomes", len(recs))
	}
	r := recs[0].Record
	out := r.Outcome
	if *r.App != "web" || *r.Result != "applied" || out["applied"] != true || out["observed_revision"] != "abc123" ||
		out["health"] != "Healthy" || out["phase"] != "Succeeded" || out["digests"].(map[string]any)["sha256"] != tree ||
		r.Change["id"] != ch2 || r.Change["tree"] != "sha256:"+tree ||
		r.Release["id"] != "chain-1:hangar-prod/prod" || r.Change["release"] != nil ||
		r.Destination["cluster"] != "hangar-prod" || r.Destination["environment"] != "prod" ||
		r.Source["provider"] != "argocd-agent/0.0.0-test" || r.Source["operation"] != "uid-app@2026-11-07T12:00:00Z" {
		t.Errorf("record: %+v %+v", r, out)
	}
	// The same operation, seen again (a relist, a watch event, a restart), posts nothing more.
	for _, a := range []*agent.Agent{w.a, w.agent()} {
		if err := a.HandleApplication(bg, app); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(w.core.of("deploy.outcome")); n != 1 {
		t.Errorf("%d outcomes after seeing it again", n)
	}
	// The next operation is its own outcome; a running one, and another project's, are not.
	if err := w.a.HandleApplication(bg, webApp(succeeded("2026-11-07T12:30:00Z"))); err != nil {
		t.Fatal(err)
	}
	running := webApp(&agent.Operation{Phase: "Running", StartedAt: "2026-11-07T13:00:00Z"})
	other := webApp(succeeded("2026-11-07T13:00:00Z"))
	other.Project = "platform"
	_ = w.a.HandleApplication(bg, running)
	_ = w.a.HandleApplication(bg, other)
	if n := len(w.core.of("deploy.outcome")); n != 2 {
		t.Errorf("%d outcomes", n)
	}
	// The core is down: nothing is marked done, and the next pass posts it.
	w.core.down = true
	next := webApp(succeeded("2026-11-07T14:00:00Z"))
	if err := w.a.HandleApplication(bg, next); err == nil {
		t.Fatal("a post that failed is an error")
	}
	w.core.down = false
	if err := w.a.HandleApplication(bg, next); err != nil || len(w.core.of("deploy.outcome")) != 3 {
		t.Errorf("retry: %v %d", err, len(w.core.of("deploy.outcome")))
	}
}

func TestMixedStampsAreSaid(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", nil)
	d, _ := stamped(t, "Deployment", "web", "app-a", "web", ch2, hex("c"))
	c, _ := stamped(t, "ConfigMap", "cfg", "app-a", "web", ch1, hex("d"))
	w.kube.objs["app-a"] = []agent.ObjectDetail{d, c}
	if err := w.a.HandleApplication(bg, webApp(succeeded("2026-11-07T12:00:00Z"))); err != nil {
		t.Fatal(err)
	}
	r := w.core.of("deploy.outcome")[0].Record
	if r.Outcome["mixed_stamps"] != true || r.Outcome["digests"] != nil || r.Change["id"] != nil {
		t.Errorf("objects of two clearances are not one change: %+v", r)
	}
}

func TestARefusedSync(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", nil)
	msg := `admission webhook: deployments.apps "web" is forbidden: ValidatingAdmissionPolicy 'clearance-grant' with binding 'clearance-grant' denied request: grant does not list apps/Deployment/web`
	app := webApp(&agent.Operation{Phase: "Failed", StartedAt: "2026-11-07T12:00:00Z", Message: "one or more objects failed to apply",
		Resources: []agent.SyncResource{{Group: "apps", Version: "v1", Kind: "Deployment", Namespace: "app-a", Name: "web", Status: "SyncFailed", Message: msg},
			{Kind: "ConfigMap", Namespace: "app-a", Name: "cfg", Status: "Synced", Message: "configmap/cfg configured"}}})
	for i := 0; i < 2; i++ {
		if err := w.a.HandleApplication(bg, app); err != nil {
			t.Fatal(err)
		}
	}
	if o := w.core.of("deploy.outcome"); len(o) != 1 || *o[0].Record.Result != "failed" || o[0].Record.Outcome["applied"] != false {
		t.Errorf("outcome: %+v", o)
	}
	ex := w.core.of("deploy.exception")
	if len(ex) != 1 {
		t.Fatalf("%d exceptions", len(ex))
	}
	x := ex[0].Record
	objs := x.Exception["objects"].([]map[string]any)
	if *x.Result != agent.ReasonRefused || x.Exception["kind"] != "out-of-band" || len(objs) != 1 || objs[0]["name"] != "web" || objs[0]["apiVersion"] != "apps/v1" ||
		!strings.Contains(x.Exception["detail"].(string), "ValidatingAdmissionPolicy") {
		t.Errorf("exception: %+v", x)
	}
	// A failed sync for another reason is not the policy's.
	w.core.records = nil
	plain := webApp(&agent.Operation{Phase: "Failed", StartedAt: "2026-11-07T13:00:00Z", Message: "ImagePullBackOff"})
	if err := w.a.HandleApplication(bg, plain); err != nil || len(w.core.of("deploy.exception")) != 0 {
		t.Errorf("a plain failure is no exception: %v", err)
	}
}

// TestConformanceAgainstFakeArgo is the card's done bar, end to end on fakes: a cleared change becomes a grant in one
// sync; Argo CD (the fake) applies the stamped objects; the outcome carries the cleared tree's digest; a kubectl apply
// into the namespace is an exception on the next scan, naming the break-glass window when one is open; the agent
// identity is on every record; and with the core gone nothing running is touched.
func TestConformanceAgainstFakeArgo(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", map[string]string{agent.LabelEnvironment: "prod", agent.LabelApp: "web"})
	tree := hex("c")
	d, dHash := stamped(t, "Deployment", "web", "app-a", "web", ch2, tree)
	c, cHash := stamped(t, "ConfigMap", "cfg", "app-a", "web", ch2, tree)

	// 1. A change clears; the grant is in the cluster within one sync of the feed carrying it.
	cl := claim(w.feeds, ch2, "app-a", t0, deploy("web", dHash), cmap("cfg", cHash))
	cl.Subjects.TreeRoot = tree
	w.feeds.claims = []token.Claims{cl}
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	g := w.grant("app-a", ch2)
	if !g.Active() || g.Spec.Objects["apps/Deployment/web"].Rendered != dHash {
		t.Fatalf("grant: %+v", g)
	}

	// 2. Argo CD syncs the stamped tree; its operation finishes; the agent posts the outcome.
	w.kube.objs["app-a"] = []agent.ObjectDetail{d, c}
	if err := w.a.HandleApplication(bg, webApp(succeeded("2026-11-07T12:00:05Z"))); err != nil {
		t.Fatal(err)
	}
	o := w.core.of("deploy.outcome")
	if len(o) != 1 || o[0].Record.Outcome["digests"].(map[string]any)["sha256"] != tree || o[0].Record.Change["id"] != ch2 {
		t.Fatalf("outcome: %+v", o)
	}

	// 3. A clean namespace is no exception.
	if err := w.a.ScanExceptions(bg); err != nil || len(w.core.of("deploy.exception")) != 0 {
		t.Fatalf("a clean scan: %v %+v", err, w.core.of("deploy.exception"))
	}

	// 4. kubectl apply into the protected namespace: an exception within one scan, once.
	w.core.windows = nil
	w.kube.objs["app-a"] = append(w.kube.objs["app-a"], agent.ObjectDetail{Object: agent.Object{APIVersion: "v1", Kind: "ConfigMap",
		Namespace: "app-a", Name: "by-hand", UID: "uid-hand", Manager: "kubectl-client-side-apply"}})
	for i := 0; i < 3; i++ {
		if err := w.a.ScanExceptions(bg); err != nil {
			t.Fatal(err)
		}
	}
	ex := w.core.of("deploy.exception")
	if len(ex) != 1 {
		t.Fatalf("%d exceptions", len(ex))
	}
	x := ex[0].Record
	objs := x.Exception["objects"].([]map[string]any)
	if *x.Result != agent.ReasonNoStamp || x.Exception["kind"] != "out-of-band" || len(objs) != 1 || objs[0]["name"] != "by-hand" ||
		objs[0]["namespace"] != "app-a" || !strings.Contains(*x.Principal, "kubectl-client-side-apply") || *x.App != "web" ||
		x.Destination["cluster"] != "hangar-prod" || x.Destination["environment"] != "prod" {
		t.Errorf("exception: %+v", x)
	}
	for _, r := range w.core.records {
		if r.Record.Source["provider"] != "argocd-agent/0.0.0-test" {
			t.Errorf("provider identity: %v", r.Record.Source)
		}
	}

	// 5. With the core gone nothing running is touched and nothing is lost.
	w.feeds.down, w.core.down = true, true
	w.clock.add(time.Minute)
	if err := w.sync(); err == nil {
		t.Error("an unreachable feed is an error")
	}
	if w.kube.workOps != 0 || len(w.kube.objs["app-a"]) != 3 {
		t.Error("something running was touched")
	}
}

func TestExceptionKinds(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", map[string]string{agent.LabelEnvironment: "prod"})
	d, dHash := stamped(t, "Deployment", "web", "app-a", "web", ch2, hex("c"))
	c, cHash := stamped(t, "ConfigMap", "cfg", "app-a", "web", ch2, hex("c"))
	w.feeds.claims = []token.Claims{claim(w.feeds, ch2, "app-a", t0, deploy("web", dHash), cmap("cfg", cHash))}
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	// cfg's stamp is listed but its last-applied content is not what the stamp says: a stamp copied onto other content.
	c.LastApplied = strings.Replace(c.LastApplied, `"replicas":2`, `"replicas":9`, 1)
	unlisted, _ := stamped(t, "Deployment", "other", "app-a", "web", ch2, hex("c")) // stamped, but no grant lists it
	byHand := agent.ObjectDetail{Object: agent.Object{APIVersion: "v1", Kind: "ConfigMap", Namespace: "app-a", Name: "by-hand", Manager: "kubectl"}}
	owned := agent.ObjectDetail{Object: agent.Object{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "app-a", Name: "rs", Owned: true}}
	root := agent.ObjectDetail{Object: agent.Object{APIVersion: "v1", Kind: "ConfigMap", Namespace: "app-a", Name: "kube-root-ca.crt"}}
	w.kube.objs["app-a"] = []agent.ObjectDetail{d, c, unlisted, byHand, owned, root}
	w.core.windows = nil
	if err := w.a.ScanExceptions(bg); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range w.core.of("deploy.exception") {
		for _, o := range r.Record.Exception["objects"].([]map[string]any) {
			got[fmt.Sprint(o["name"])] = *r.Record.Result
		}
	}
	want := map[string]string{"by-hand": agent.ReasonNoStamp, "other": agent.ReasonNotListd, "cfg": agent.ReasonContent}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("findings %v, want %v", got, want)
	}
	// What is fixed is forgotten and reported again if it comes back; a scan that could not read everything forgets nothing.
	n := len(w.core.records)
	w.kube.failList = true
	if err := w.a.ScanExceptions(bg); err == nil {
		t.Error("a scan that cannot list is an error")
	}
	w.kube.failList = false
	w.kube.objs["app-a"] = []agent.ObjectDetail{d, unlisted, byHand}
	_ = w.a.ScanExceptions(bg)
	if len(w.core.records) != n {
		t.Errorf("reported again: %d", len(w.core.records)-n)
	}
	w.kube.objs["app-a"] = []agent.ObjectDetail{d}
	_ = w.a.ScanExceptions(bg)
	w.kube.objs["app-a"] = []agent.ObjectDetail{d, byHand}
	bg1 := "bg-0000000000000001"
	w.core.windows = []agent.Window{{ID: bg1, Cluster: "hangar-prod", Env: "prod"}}
	_ = w.a.ScanExceptions(bg)
	if len(w.core.records) != n+1 {
		t.Fatalf("a finding that came back is reported: %d", len(w.core.records)-n)
	}
	last := w.core.records[len(w.core.records)-1].Record
	if !strings.Contains(last.Exception["detail"].(string), bg1) {
		t.Errorf("the break-glass window is named: %v", last.Exception["detail"])
	}
}

// The gate's own wait Job is not an exception, and neither the name nor the label alone earns that.
func TestScanSkipsOnlyTheRealWaitJob(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", map[string]string{agent.LabelEnvironment: "prod"})
	job := func(ns string, spec []byte) agent.ObjectDetail {
		return agent.ObjectDetail{Object: agent.Object{APIVersion: "batch/v1", Kind: "Job", Namespace: ns, Name: agent.WaitJobName, UID: "u-" + string(rune('a'+len(spec)%26)),
			Manager: "argocd-controller", Labels: map[string]string{"clearance.hangar.io/injected": "wait"},
			Annotations: map[string]string{"argocd.argoproj.io/hook": "PreSync"}}, Spec: spec}
	}
	w.kube.objs["app-a"] = []agent.ObjectDetail{job("app-a", agent.LiveWaitSpec)}
	w.core.windows = nil
	if err := w.a.ScanExceptions(bg); err != nil {
		t.Fatal(err)
	}
	if got := w.core.of("deploy.exception"); len(got) != 0 {
		t.Fatalf("the injected Job was reported: %d exceptions", len(got))
	}
	forged := strings.Replace(string(agent.LiveWaitSpec), `"http://clearance.hangar-dev.local"}`, `"http://evil.example"}`, 1)
	if forged == string(agent.LiveWaitSpec) {
		t.Fatal("the fixture did not change")
	}
	w.kube.objs["app-a"] = []agent.ObjectDetail{job("app-a", []byte(forged))}
	if err := w.a.ScanExceptions(bg); err != nil {
		t.Fatal(err)
	}
	if got := w.core.of("deploy.exception"); len(got) != 1 {
		t.Fatalf("a Job that copies the name and label must be reported: %d exceptions", len(got))
	}
}

func TestContentHashIgnoresArgosAndTheStamps(t *testing.T) {
	plain := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a","namespace":"n"},"data":{"k":"v"}}`
	annotated := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a","namespace":"n","annotations":{"argocd.argoproj.io/tracking-id":"x","clearance.hangar.io/rendered":"y","clearance.hangar.io/tree":"z","keep":"me"}},"data":{"k":"v"}}`
	h1, err := agent.ContentHash(plain)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := agent.ContentHash(annotated)
	h3, _ := agent.ContentHash(strings.Replace(annotated, `,"keep":"me"`, "", 1))
	if h1 != h3 || h1 == h2 || len(h1) != 64 {
		t.Errorf("hashes %s %s %s", h1, h2, h3)
	}
}

func TestUnreadableLastAppliedIsAFinding(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", nil)
	d, dHash := stamped(t, "Deployment", "web", "app-a", "web", ch2, hex("c"))
	w.feeds.claims = []token.Claims{claim(w.feeds, ch2, "app-a", t0, deploy("web", dHash))}
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	d.LastApplied = "{not json"
	w.kube.objs["app-a"] = []agent.ObjectDetail{d}
	if err := w.a.ScanExceptions(bg); err != nil || len(w.core.of("deploy.exception")) != 1 {
		t.Fatalf("%v %v", err, w.core.of("deploy.exception"))
	}
}

func TestMixedReleaseIsNotReportedAsOne(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", nil)
	d, _ := stamped(t, "Deployment", "web", "app-a", "web", ch2, hex("c"))
	c, _ := stamped(t, "ConfigMap", "cfg", "app-a", "web", ch2, hex("c"))
	c.Annotations[agent.AnnRelease] = "chain-2:hangar-prod/prod"
	w.kube.objs["app-a"] = []agent.ObjectDetail{d, c}
	if err := w.a.HandleApplication(bg, webApp(succeeded("2026-11-07T12:00:00Z"))); err != nil {
		t.Fatal(err)
	}
	r := w.core.of("deploy.outcome")[0].Record
	if r.Release != nil || r.Change["release"] != nil || r.Outcome["mixed_stamps"] != true {
		t.Errorf("%+v", r)
	}
}

// G-ARGO-6: the CMP's stamp on every object is read first, so an app with no Rollout still names its release; the
// outcome carries it as release {id}, not under change.
func TestTheReleaseStampIsReadBeforeTheChartsAnnotation(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", nil)
	c, _ := stamped(t, "ConfigMap", "cfg", "app-a", "web", ch2, hex("c"))
	delete(c.Annotations, agent.AnnRelease) // no Rollout: only the CMP's stamp
	c.Annotations[agent.AnnStampRelease] = "chain-9:hangar-prod/prod"
	w.kube.objs["app-a"] = []agent.ObjectDetail{c}
	if err := w.a.HandleApplication(bg, webApp(succeeded("2026-11-07T12:00:00Z"))); err != nil {
		t.Fatal(err)
	}
	r := w.core.of("deploy.outcome")[0].Record
	if r.Release["id"] != "chain-9:hangar-prod/prod" || r.Change["release"] != nil {
		t.Errorf("%+v", r)
	}
}

// G-ARGO-6: the outcome of a realistic tenant-onboarded Application (named <app>-<env>, labelled hangar.io/app and
// hangar.io/env) is for the change clearance-gate registered under the Glidepath app name, so the core attaches it.
func TestAnOutcomeOfATenantOnboardedApplicationAttachesToItsChange(t *testing.T) {
	ctx := context.Background()
	tree := strings.Repeat("c", 64)
	st := memory.New()
	svc := gate.NewService(gate.Config{Verifiers: []string{"app-*-cicd/pipeline-runner"}}, st, func() time.Time { return t0 })
	// the change as clearance-gate registers it: the Glidepath app name, the environment name, the cluster
	body := map[string]any{"app": "gate-api", "env": "prod", "cluster": "hangar-prod", "repo": "jfillman/gitops-gate-api",
		"pr": json.Number("7"), "head": strings.Repeat("a", 40), "base": strings.Repeat("b", 40), "proposer": "user:dana",
		"proposerKind": "person", "owner": "group:default/team-gate", "protected": true, "treeDigest": tree,
		"paths": []any{"hangar-prod/prod/release.yaml"}, "linesChanged": json.Number("4"), "objects": []any{},
		"checks": map[string]any{"ci": "pass", "provenance": "not-agent", "render": "ok", "admission": "pass"}}
	c, err := svc.Register(ctx, authn.Principal{ID: "app-gate-api-cicd/pipeline-runner"}, body)
	if err != nil || c.State != "cleared" {
		t.Fatalf("%+v %v", c, err)
	}

	w := newWorld(t)
	w.kube.protect("app-gate-api-prod", map[string]string{agent.LabelEnvironment: "prod"})
	d, _ := stamped(t, "Deployment", "gate-api", "app-gate-api-prod", "gate-api-prod", c.ID, tree)
	w.kube.objs["app-gate-api-prod"] = []agent.ObjectDetail{d}
	app := agent.Application{Namespace: "argocd-apps", Name: "gate-api-prod", UID: "uid-1", Project: "tenants",
		Labels: map[string]string{agent.LabelAppName: "gate-api", agent.LabelAppEnv: "prod"}, DestNS: "app-gate-api-prod",
		SyncState: "Synced", Health: "Healthy", Revisions: []string{"abc123"}, Op: succeeded("2026-11-07T12:00:00Z")}
	req, err := w.a.OutcomeRecord(ctx, app)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(req.Record)
	ev := store.Event{"ts": "2026-11-07T12:00:01Z", "tool": "deploy.outcome", "boundary": "deployment", "principal": "p",
		"decision": nil, "tier": nil, "task_id": nil, "session": nil, "parent": nil, "agent": nil, "rule": nil, "args_sha256": nil}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for k, v := range fields {
		ev[k] = v
	}
	if ev["app"] != "gate-api" {
		t.Fatalf("the outcome names the Application, not the app: %v", ev["app"])
	}
	rec, err := svc.RecordOutcome(ctx, ev, evidence.Writer{Provider: evidence.Provider{Name: "argocd-agent", Version: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if rec["unattached"] != nil {
		t.Fatalf("not attached: %v", rec["unattached"])
	}
	row, _ := st.Change(ctx, c.ID)
	var got gate.Change
	_ = json.Unmarshal(row.Record, &got)
	if got.Outcome == nil || !got.Outcome.Matched || got.Outcome.Release != "chain-1:hangar-prod/prod" {
		t.Fatalf("outcome: %+v", got.Outcome)
	}
}

// A protected project can hold an environment the gate does not protect. The agent has no read in that namespace and
// must not try: on hangar-prod gate-api-staging produced a 403 on every list.
func TestAnApplicationOutsideAProtectedNamespaceIsSkipped(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", map[string]string{agent.LabelEnvironment: "prod"})
	d, _ := stamped(t, "Deployment", "web", "app-a", "web", ch2, hex("c"))
	w.kube.objs["app-a"] = []agent.ObjectDetail{d}
	w.kube.objs["app-staging"] = []agent.ObjectDetail{d}

	staging := webApp(succeeded("2026-11-07T12:00:00Z"))
	staging.Name, staging.UID, staging.DestNS = "web-staging", "uid-staging", "app-staging"
	if err := w.a.HandleApplication(bg, staging); err != nil {
		t.Fatalf("an unprotected namespace is not an error: %v", err)
	}
	if n := len(w.core.of("deploy.outcome")); n != 0 {
		t.Fatalf("%d outcomes for an unprotected namespace", n)
	}
	lists := w.kube.nsLists
	if err := w.a.HandleApplication(bg, staging); err != nil {
		t.Fatal(err)
	}
	if lists == 0 || w.kube.nsLists != lists {
		t.Fatalf("a second status change inside the window listed the namespaces again: %d then %d", lists, w.kube.nsLists)
	}
	if err := w.a.HandleApplication(bg, webApp(succeeded("2026-11-07T12:00:00Z"))); err != nil {
		t.Fatal(err)
	}
	if n := len(w.core.of("deploy.outcome")); n != 1 {
		t.Fatalf("%d outcomes for the protected namespace, want 1", n)
	}
}
