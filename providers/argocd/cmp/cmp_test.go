package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/definitions/deftest"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/gate/render"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store/memory"
	"github.com/jfillman/clearance/internal/vocab"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
)

const (
	parity   = "testdata/parity-gate-api"
	mergeSHA = "0123456789abcdef0123456789abcdef01234567"
	chartSHA = "c7e846a1111111111111111111111111111111aa"
)

func read(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parity, p))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tektonDigests is what Glidepath's clearance-gate task computes for a render (tekton_digest.py is its code,
// verbatim; the JSON is its output for the recorded render).
type tektonDigests struct {
	Tree    string            `json:"tree"`
	Objects map[string]string `json:"objects"`
}

func tekton(t *testing.T, p string) tektonDigests {
	t.Helper()
	var d tektonDigests
	if err := json.Unmarshal(read(t, p), &d); err != nil || d.Tree == "" || len(d.Objects) == 0 {
		t.Fatal(err, d)
	}
	return d
}

func gateAPIConfig() Config {
	return Config{AppName: "gate-api-prod", Destination: "app-gate-api-prod", Revision: mergeSHA,
		SourceRepo: "https://github.com/jfillman/gitops-gate-api.git", SourcePath: ".",
		App: "gate-api", Env: "prod", Cluster: "hangar-prod",
		ChartRepo: "https://github.com/jfillman/airframe.git", ChartRev: "v0.3.168", ChartPath: "charts/airframe-application",
		ValueFiles: []string{"hangar-prod/base.yaml", "hangar-prod/prod/values.yaml", "hangar-prod/prod/release.yaml"},
		CoreURL:    "http://clearance.test", CacheTTL: 2 * time.Minute, WaitImage: "ghcr.io/jfillman/clearance-wait:test",
		WaitTimeout: time.Hour}
}

// fakeExec answers git and helm the way the real tools would for the recorded render, and records every call.
type fakeExec struct {
	calls  [][]string
	render []byte
	fail   map[string]error
}

func (f *fakeExec) run(_ context.Context, dir, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	switch name {
	case "git":
		if args[0] == "rev-parse" {
			return []byte(chartSHA + "\n"), nil
		}
		return nil, nil
	case "helm":
		return f.render, nil
	case "kustomize":
		return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: extra\ndata:\n  a: b\n"), nil
	}
	return nil, errors.New("unexpected " + name)
}

type fakeCore struct {
	answer *client.Change
	err    error
	reqs   []*client.ChangeRequest
}

func (c *fakeCore) RegisterChange(_ context.Context, r *client.ChangeRequest) (*client.Change, error) {
	c.reqs = append(c.reqs, r)
	return c.answer, c.err
}

type env struct {
	cfg  Config
	exec *fakeExec
	core *fakeCore
	d    Deps
	src  string
	now  time.Time
	err  bytes.Buffer
}

func newEnv(t *testing.T) *env {
	e := &env{cfg: gateAPIConfig(), exec: &fakeExec{render: read(t, "head.yaml")}, core: &fakeCore{}, src: t.TempDir(), now: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	e.cfg.ValuesJSON = string(read(t, "injected.json"))
	e.d = Deps{Exec: e.exec.run, Core: e.core, Cache: Cache{Dir: t.TempDir()}, Now: func() time.Time { return e.now }, Stderr: &e.err}
	return e
}

func (e *env) generate(t *testing.T) (Outcome, []map[string]any, error) {
	t.Helper()
	var out bytes.Buffer
	o, err := Generate(context.Background(), e.d, e.cfg, e.src, &out)
	var objs []map[string]any
	for _, doc := range strings.Split(out.String(), "---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("output is not a JSON stream: %v\n%s", err, doc)
		}
		objs = append(objs, m)
	}
	return o, objs, err
}

func ann(o map[string]any) map[string]any {
	a, _ := o["metadata"].(map[string]any)["annotations"].(map[string]any)
	return a
}

// -- the parity test --------------------------------------------------------------------------------------------

// The plugin's tree and every object's hash equal what the Tekton clearance-gate check computes for the same render
// (gate-api, hangar-prod/prod, Application gate-api-prod).
func TestParityWithTheTektonGateRender(t *testing.T) {
	want := tekton(t, "tekton.json")
	tree, err := Canonicalize(read(t, "head.yaml"), "app-gate-api-prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Root != want.Tree {
		t.Fatalf("tree %s, Tekton %s", tree.Root, want.Tree)
	}
	if len(tree.Hashes) != len(want.Objects) {
		t.Fatalf("%d objects, Tekton %d", len(tree.Hashes), len(want.Objects))
	}
	for k, h := range tree.Hashes {
		id := strings.Join(k[:], "/")
		if want.Objects[id] != h {
			t.Errorf("%s: %s, Tekton %s", id, h, want.Objects[id])
		}
	}
}

// The same, through generate: a cleared change's output carries Tekton's per-object hash and tree on every object.
func TestGenerateStampsWhatTektonHashes(t *testing.T) {
	want := tekton(t, "tekton.json")
	e := newEnv(t)
	e.core.answer = &client.Change{ID: "ch-abc", State: "cleared", Tier: 1, Outage: "allow-and-record", ExpiresAt: e.now.Add(time.Hour).Format(time.RFC3339Nano)}
	o, objs, err := e.generate(t)
	if err != nil || o != Cleared {
		t.Fatal(o, err)
	}
	if len(objs) != len(want.Objects) {
		t.Fatalf("%d objects emitted, want %d", len(objs), len(want.Objects))
	}
	for _, obj := range objs {
		k := keyOf(obj)
		a := ann(obj)
		if a[AnnRendered] != want.Objects[strings.Join(k[:], "/")] || a[AnnTree] != want.Tree || a[AnnGrant] != "ch-abc" {
			t.Errorf("%v: stamps %v, Tekton %s", k, a, want.Objects[strings.Join(k[:], "/")])
		}
	}
	// What was sent: the pushed commit Argo syncs, the release name and namespace as Argo gives them.
	r := e.core.reqs[0]
	if r.TreeDigest != want.Tree || r.PR != 0 || r.Head != mergeSHA || r.Repo != "jfillman/gitops-gate-api" || r.App != "gate-api" {
		t.Fatalf("%+v", r)
	}
	helm := e.exec.calls[2]
	if helm[0] != "helm" || helm[1] != "template" || helm[2] != "gate-api-prod" || helm[4] != "--namespace" || helm[5] != "app-gate-api-prod" {
		t.Fatalf("helm was run as %v", helm)
	}
}

// Documents a known difference, G-ARGO-8's to close: the Tekton task renders with the app name as the release
// (`helm template gate-api`), while Argo CD, and so the plugin, uses the Application's name (`gate-api-prod`), and
// the chart stamps app.kubernetes.io/instance from it. Until the task renders with <app>-<env>, the two trees differ
// and a PR's clearance is not found by tree at sync time.
func TestTheTektonTaskTodayRendersADifferentTree(t *testing.T) {
	today, mine := tekton(t, "tekton-today.json"), tekton(t, "tekton.json")
	if today.Tree == mine.Tree {
		t.Fatal("the release name no longer changes the tree: the discrepancy is closed, delete this test")
	}
	// the plugin is faithful to whichever render it is handed
	tree, err := Canonicalize(read(t, "head-tekton-today.yaml"), "app-gate-api-prod", nil)
	if err != nil || tree.Root != today.Tree {
		t.Fatal(err, tree.Root, today.Tree)
	}
}

// -- the three outcomes ------------------------------------------------------------------------------------------

func TestHeldForPeopleEmitsTheManifestsAndAPreSyncWaitJob(t *testing.T) {
	e := newEnv(t)
	e.core.answer = &client.Change{ID: "ch-held", State: "holding", Tier: 2}
	o, objs, err := e.generate(t)
	if err != nil || o != Held {
		t.Fatal(o, err)
	}
	if len(objs) != 7 {
		t.Fatalf("%d objects: the 6 of the tree and the Job", len(objs))
	}
	for _, obj := range objs[:6] {
		if a := ann(obj); a[AnnRendered] == nil || a[AnnGrant] != nil {
			t.Errorf("%v: a held object is stamped rendered, and has no grant: %v", keyOf(obj), a)
		}
	}
	job := objs[6]
	md := job["metadata"].(map[string]any)
	a := md["annotations"].(map[string]any)
	if job["kind"] != "Job" || md["name"] != WaitJobName || md["namespace"] != "app-gate-api-prod" ||
		a["argocd.argoproj.io/hook"] != "PreSync" || a["clearance.hangar.io/change"] != "ch-held" {
		t.Fatalf("%v", job)
	}
	c := job["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	args, _ := json.Marshal(c["args"])
	if c["image"] != "ghcr.io/jfillman/clearance-wait:test" || string(args) != `["--change","ch-held","--timeout","1h0m0s"]` {
		t.Fatalf("%v", c)
	}
	pod := job["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	if _, set := pod["serviceAccountName"]; set || pod["automountServiceAccountToken"] != false {
		t.Fatalf("the wait Job sets no serviceAccountName (the admission allowlist refuses one) and mounts no default token: %v", pod)
	}
	if md["labels"].(map[string]any)["clearance.hangar.io/injected"] != "wait" {
		t.Fatal("the injected Job is labelled so admission can tell it from tenant objects")
	}
}

func TestADeniedChangeFailsTheRenderSoNothingSyncs(t *testing.T) {
	for _, state := range []string{"denied", "expired", "superseded", "exception", "degraded"} {
		e := newEnv(t)
		reason := "DG-POLICY: clearance.yaml loosens the baseline"
		e.core.answer = &client.Change{ID: "ch-x", State: state, Tier: 3, DenyReason: &reason}
		o, objs, err := e.generate(t)
		if err == nil || o != "" || len(objs) != 0 || !strings.Contains(err.Error(), state) || !strings.Contains(err.Error(), "nothing syncs") {
			t.Errorf("%s: %q %v %v", state, o, objs, err)
		}
	}
}

func TestACoreRefusalFailsClosed(t *testing.T) {
	e := newEnv(t)
	e.core.err = &client.APIError{Op: "registerChange", Status: 403, Message: "hangar-prod/argocd-apps/argocd-apps-repo-server is not a verifier"}
	if _, objs, err := e.generate(t); err == nil || len(objs) != 0 || !strings.Contains(err.Error(), "not a verifier") {
		t.Fatal(err)
	}
}

// -- the outage policy and the cache -------------------------------------------------------------------------------

func TestAClearedTreeIsNotAskedAgainWithinTheTTL(t *testing.T) {
	e := newEnv(t)
	e.core.answer = &client.Change{ID: "ch-c", State: "cleared", Tier: 1, Outage: "allow-and-record", ExpiresAt: e.now.Add(48 * time.Hour).Format(time.RFC3339Nano)}
	if _, _, err := e.generate(t); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Minute)
	if o, objs, err := e.generate(t); err != nil || o != Cleared || len(e.core.reqs) != 1 || ann(objs[0])[AnnGrant] != "ch-c" {
		t.Fatal(o, err, len(e.core.reqs))
	}
	e.now = e.now.Add(3 * time.Minute) // past the TTL: asked again
	if _, _, err := e.generate(t); err != nil || len(e.core.reqs) != 2 {
		t.Fatal(err, len(e.core.reqs))
	}
}

func TestAnOutageServesAClearedAllowAndRecordTreeAndHoldsTheRest(t *testing.T) {
	down := &client.UnavailableError{Op: "registerChange", Reason: "timeout"}
	// cleared before, tier 1 (allow-and-record): served from the cache while the core is down
	e := newEnv(t)
	e.core.answer = &client.Change{ID: "ch-c", State: "cleared", Tier: 1, Outage: "allow-and-record", ExpiresAt: e.now.Add(48 * time.Hour).Format(time.RFC3339Nano)}
	if _, _, err := e.generate(t); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Hour)
	e.core.err = down
	if o, objs, err := e.generate(t); err != nil || o != Cleared || ann(objs[0])[AnnGrant] != "ch-c" {
		t.Fatal(o, err)
	}
	// a tier-2 tree cleared by people has outage hold: never served stale
	e = newEnv(t)
	e.core.answer = &client.Change{ID: "ch-p", State: "cleared", Tier: 2, Outage: "hold", ExpiresAt: e.now.Add(48 * time.Hour).Format(time.RFC3339Nano)}
	if _, _, err := e.generate(t); err != nil {
		t.Fatal(err)
	}
	e.now, e.core.err = e.now.Add(time.Hour), down
	if _, objs, err := e.generate(t); err == nil || len(objs) != 0 || !strings.Contains(err.Error(), "outage hold") {
		t.Fatal(err)
	}
	// a tree the core never answered for: an unknown tier is never allowed
	e = newEnv(t)
	e.core.err = down
	if _, objs, err := e.generate(t); err == nil || len(objs) != 0 || !strings.Contains(err.Error(), "outage hold") {
		t.Fatal(err)
	}
	// a cached clearance past its own expiry is not served
	e = newEnv(t)
	e.core.answer = &client.Change{ID: "ch-c", State: "cleared", Tier: 1, Outage: "allow-and-record", ExpiresAt: e.now.Add(time.Hour).Format(time.RFC3339Nano)}
	if _, _, err := e.generate(t); err != nil {
		t.Fatal(err)
	}
	e.now, e.core.err = e.now.Add(2*time.Hour), down
	if _, _, err := e.generate(t); err == nil {
		t.Fatal("served a lapsed clearance")
	}
}

func TestARenderThatFailsOrIsEmptyFailsTheComparison(t *testing.T) {
	e := newEnv(t)
	e.exec.fail = map[string]error{"helm": errors.New("helm template: boom")}
	if _, _, err := e.generate(t); err == nil || len(e.core.reqs) != 0 {
		t.Fatal(err)
	}
	e = newEnv(t)
	e.exec.render = []byte("# nothing\n")
	if _, _, err := e.generate(t); err == nil || !strings.Contains(err.Error(), "no objects") || len(e.core.reqs) != 0 {
		t.Fatal(err)
	}
	e = newEnv(t)
	e.cfg.Revision = "main"
	e.core.answer = &client.Change{ID: "x", State: "cleared"}
	if _, _, err := e.generate(t); err == nil || !strings.Contains(err.Error(), "not a commit") {
		t.Fatal(err)
	}
	e = newEnv(t)
	e.cfg.WaitImage = ""
	e.core.answer = &client.Change{ID: "ch-held", State: "holding"}
	if _, objs, err := e.generate(t); err == nil || len(objs) != 0 || !strings.Contains(err.Error(), "CLEARANCE_WAIT_IMAGE") {
		t.Fatal(err)
	}
}

// -- the render ---------------------------------------------------------------------------------------------------

func TestTheChartIsFetchedAtItsTagAndTheCommitIsPeeled(t *testing.T) {
	e := newEnv(t)
	e.core.answer = &client.Change{ID: "ch-c", State: "cleared", Tier: 1, ExpiresAt: e.now.Add(time.Hour).Format(time.RFC3339Nano)}
	if err := os.MkdirAll(filepath.Join(e.src, "hangar-prod", "prod"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"hangar-prod/prod/values.yaml", "hangar-prod/prod/release.yaml"} { // base.yaml stays missing
		if err := os.WriteFile(filepath.Join(e.src, f), []byte("a: b\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := e.generate(t); err != nil {
		t.Fatal(err)
	}
	clone := e.exec.calls[0]
	if strings.Join(clone[:7], " ") != "git clone --quiet --depth 1 --branch v0.3.168" || clone[7] != "--" || clone[8] != "https://github.com/jfillman/airframe.git" {
		t.Fatalf("%v", clone)
	}
	if !strings.Contains(e.err.String(), "(c7e846a11111)") {
		t.Fatalf("the peeled commit is recorded: %s", e.err.String())
	}
	helm := e.exec.calls[2]
	var files []string
	for i, a := range helm {
		if a == "-f" {
			files = append(files, filepath.Base(helm[i+1]))
		}
	}
	// base.yaml is missing and skipped; the platform's injected values come last
	if strings.Join(files, " ") != "values.yaml release.yaml injected.json" {
		t.Fatalf("value files %v", files)
	}
	if !strings.HasSuffix(helm[3], "charts/airframe-application") {
		t.Fatalf("chart %s", helm[3])
	}
}

func TestKustomizeRendersBesideTheChartAndIsStampedToo(t *testing.T) {
	e := newEnv(t)
	e.cfg.KustomizeDir = "hangar-prod/prod/configmap"
	if err := os.MkdirAll(filepath.Join(e.src, "hangar-prod/prod/configmap"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.core.answer = &client.Change{ID: "ch-c", State: "cleared", Tier: 1, ExpiresAt: e.now.Add(time.Hour).Format(time.RFC3339Nano)}
	_, objs, err := e.generate(t)
	if err != nil || len(objs) != 7 {
		t.Fatal(err, len(objs))
	}
	var cm map[string]any
	for _, o := range objs {
		if o["kind"] == "ConfigMap" && o["metadata"].(map[string]any)["name"] == "extra" {
			cm = o
		}
	}
	if cm == nil || ann(cm)[AnnRendered] == nil || cm["metadata"].(map[string]any)["namespace"] != "app-gate-api-prod" {
		t.Fatalf("%v", cm)
	}
}

// -- canonicalisation ------------------------------------------------------------------------------------------------

func TestTheDestinationNamespaceIsSetBeforeHashing(t *testing.T) {
	const doc = `
apiVersion: v1
kind: ConfigMap
metadata: {name: a}
data: {k: v}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: a, namespace: dest}
data: {k: v}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: r}
---
apiVersion: v1
kind: Namespace
metadata: {name: dest}
`
	// a document without a namespace and one with it are the same object once the destination is set
	if _, err := Canonicalize([]byte(doc), "dest", nil); err == nil || !strings.Contains(err.Error(), "one identity") {
		t.Fatal("two objects collapse to one identity", err)
	}
	tree, err := Canonicalize([]byte(strings.Replace(doc, "metadata: {name: a, namespace: dest}", "metadata: {name: b, namespace: dest}", 1)), "dest", nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, k := range tree.Keys {
		got = append(got, strings.Join(k[:], "/"))
	}
	want := "rbac.authorization.k8s.io/v1/ClusterRole//r v1/ConfigMap/dest/a v1/ConfigMap/dest/b v1/Namespace//dest"
	if strings.Join(got, " ") != want {
		t.Fatalf("%v", got)
	}
	// the emitted object carries the namespace too, so what Argo applies is what was hashed
	for i, o := range tree.Emitted {
		if k := tree.Keys[i]; k[1] == "ConfigMap" && o["metadata"].(map[string]any)["namespace"] != "dest" {
			t.Fatalf("%v", o)
		}
	}
}

// Two YAML readers read a few scalars differently (PyYAML, which the hash follows: `yes` is true; Argo CD's, which
// applies the object: `yes` is a string). A stamp on such an object would be the hash of a different object.
func TestAnObjectTheTwoYAMLReadersReadDifferentlyIsRefused(t *testing.T) {
	for name, scalar := range map[string]string{"yes": "yes", "sexagesimal": "1:30", "date": "2001-01-01"} {
		doc := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {k: " + scalar + "}\n"
		if _, err := Canonicalize([]byte(doc), "dest", nil); err == nil || !strings.Contains(err.Error(), "reads differently") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the same value written the same way by both is fine, and so is a number written 1.0
	ok := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {k: 'yes', n: \"1:30\"}\nx: [1.0, 0.5, 3, true, null]\n"
	if _, err := Canonicalize([]byte(ok), "dest", nil); err != nil {
		t.Fatal(err)
	}
}

func TestAListIsFlattenedAndStampsAreRefreshedNotStacked(t *testing.T) {
	tree, err := Canonicalize([]byte(`
apiVersion: v1
kind: List
items:
  - {apiVersion: v1, kind: ConfigMap, metadata: {name: a, annotations: {clearance.hangar.io/grant: forged}}}
  - {apiVersion: v1, kind: ConfigMap, metadata: {name: b}}
`), "dest", nil)
	if err != nil || len(tree.Keys) != 2 {
		t.Fatal(err, tree)
	}
	tree.Stamp("") // held: a tenant-written grant annotation is removed, never trusted
	if a := ann(tree.Emitted[0]); a[AnnGrant] != nil || a[AnnRendered] == nil {
		t.Fatalf("%v", a)
	}
}

// -- the registration has the object shape the Tekton task posts ----------------------------------------------------

func TestTheRegistrationIsAValidChangeRequestAndAnUncoveredTreeHolds(t *testing.T) {
	vocab.Set(vocabtest.Lab())
	tree, err := Canonicalize(read(t, "head.yaml"), "app-gate-api-prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := registration(gateAPIConfig(), tree)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(req)
	body, err := pycompat.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := gate.ParseRequest(body)
	if err != nil {
		t.Fatalf("the core refuses the plugin's registration: %v\n%s", err, raw)
	}
	if parsed.PR != 0 || len(parsed.Objects) != 6 || parsed.Objects[0].Digest == "" || parsed.TreeDigest != tree.Root {
		t.Fatalf("%+v", parsed)
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(raw, &keys)
	for _, k := range []string{"app", "env", "cluster", "repo", "pr", "head", "proposer", "proposerKind", "protected", "treeDigest", "paths", "linesChanged", "objects", "checks"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("the Tekton task's change.json has %q; the plugin's registration does not", k)
		}
	}
}

// inProcess is the real gate service behind the Core interface: the registration goes through ParseRequest,
// classification and the store, and what comes back is the change's JSON.
type inProcess struct {
	svc *gate.Service
	who authn.Principal
}

func (p inProcess) RegisterChange(ctx context.Context, r *client.ChangeRequest) (*client.Change, error) {
	raw, _ := json.Marshal(r)
	body, _ := pycompat.Decode(bytes.NewReader(raw))
	ch, err := p.svc.Register(ctx, p.who, body)
	if err != nil {
		return nil, err
	}
	out, _ := json.Marshal(ch)
	var c client.Change
	return &c, json.Unmarshal(out, &c)
}

// The whole flow against the real gate: the Tekton task registers the PR (here: the same tree, a tier-1 image bump),
// Argo CD syncs the merge commit, and the plugin finds the clearance by tree; a tree nobody cleared is held.
func TestAMergeCommitIsCoveredByThePRsClearanceAndAnUncoveredTreeHolds(t *testing.T) {
	vocab.Set(vocabtest.Lab())
	e := newEnv(t)
	st := memory.New()
	svc := gate.NewService(gate.Config{Verifiers: []string{"app-*-cicd/pipeline-runner", "hangar-prod/argocd-apps/argocd-apps-repo-server"}}, st,
		func() time.Time { return e.now })
	svc.Tools = deftest.Tools()
	e.d.Core = inProcess{svc, authn.Principal{ID: "hangar-prod/argocd-apps/argocd-apps-repo-server", Kind: authn.KindForeignWorkload}}

	tree, err := Canonicalize(read(t, "head.yaml"), "app-gate-api-prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Before anything clears the tree: the plugin registers it, as a new change, and it holds (every object is "added").
	o, objs, err := e.generate(t)
	if err != nil || o != Held || objs[len(objs)-1]["kind"] != "Job" {
		t.Fatal(o, err)
	}
	// The Tekton task's registration of the PR: the same tree, an image bump, checks green: cleared by policy.
	ci := authn.Principal{ID: "app-gate-api-cicd/pipeline-runner", Kind: authn.KindServiceAccount}
	pr := map[string]any{"app": "gate-api", "env": "prod", "cluster": "hangar-prod", "repo": "jfillman/gitops-gate-api", "pr": json.Number("7"),
		"head": strings.Repeat("a", 40), "base": strings.Repeat("b", 40), "proposer": "user:dana", "proposerKind": "person", "protected": true,
		"treeDigest": tree.Root, "paths": []any{"hangar-prod/prod/release.yaml"}, "linesChanged": json.Number("4"),
		"objects": []any{map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Rollout", "namespace": "app-gate-api-prod", "name": "gate-api", "op": "changed",
			"fields": []any{"/spec/template/spec/containers/0/image"}, "images": []any{"ghcr.io/jfillman/gate-api@sha256:" + strings.Repeat("e", 64)}, "digest": strings.Repeat("d", 64)}},
		"checks": map[string]any{"ci": "pass", "provenance": "not-agent", "render": "ok", "admission": "pass"}}
	b, _ := json.Marshal(pr)
	body, _ := pycompat.Decode(bytes.NewReader(b))
	cleared, err := svc.Register(context.Background(), ci, body)
	if err != nil || cleared.State != "cleared" {
		t.Fatal(err, cleared)
	}
	e.now = e.now.Add(5 * time.Minute)
	o, objs, err = e.generate(t)
	if err != nil || o != Cleared {
		t.Fatal(o, err)
	}
	for _, obj := range objs {
		if ann(obj)[AnnGrant] != cleared.ID {
			t.Fatalf("%v is stamped with %v, want the PR's clearance %s", keyOf(obj), ann(obj), cleared.ID)
		}
	}
	// A change to the tree (one more object) is not covered by that clearance.
	e.exec.render = append(append([]byte{}, e.exec.render...), []byte("\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: extra\n  namespace: app-gate-api-prod\n")...)
	e.now = e.now.Add(5 * time.Minute)
	e.cfg.Revision = strings.Repeat("c", 40)
	if o, _, err := e.generate(t); err != nil || o != Held {
		t.Fatal(o, err)
	}
}

// -- configuration ---------------------------------------------------------------------------------------------------

func TestParseConfig(t *testing.T) {
	good := map[string]string{"ARGOCD_APP_NAME": "gate-api-prod", "ARGOCD_APP_NAMESPACE": "app-gate-api-prod", "ARGOCD_APP_REVISION": mergeSHA,
		"ARGOCD_APP_SOURCE_REPO_URL": "git@github.com:Jfillman/gitops-gate-api.git", "PARAM_APP": "gate-api", "PARAM_ENV": "prod", "PARAM_CLUSTER": "hangar-prod",
		"PARAM_CHARTREPO": "https://github.com/jfillman/airframe.git", "PARAM_CHARTREVISION": "v0.3.168", "PARAM_CHARTPATH": "charts/airframe-application",
		"PARAM_VALUEFILES": "a.yaml, b/c.yaml,", "CLEARANCE_URL": "http://clearance.test"}
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := ParseConfig(get(good))
	if err != nil || strings.Join(c.ValueFiles, "|") != "a.yaml|b/c.yaml" || c.TokenFile != "/var/run/secrets/tokens/clearance" {
		t.Fatal(c, err)
	}
	if r, err := c.RepoName(); err != nil || r != "jfillman/gitops-gate-api" {
		t.Fatal(r, err)
	}
	for name, mut := range map[string]map[string]string{
		"no core":           {"CLEARANCE_URL": ""},
		"no app":            {"PARAM_APP": ""},
		"chart without tag": {"PARAM_CHARTREVISION": ""},
		"option as repo":    {"PARAM_CHARTREPO": "--upload-pack=x"},
		"path escapes":      {"PARAM_VALUEFILES": "../../etc/passwd"},
		"absolute path":     {"PARAM_CHARTPATH": "/etc"},
		"bad alias":         {"CLEARANCE_WAIT_HOST_ALIAS": "nope"},
		"bad duration":      {"CLEARANCE_WAIT_TIMEOUT": "soon"},
		"bad app name":      {"PARAM_ENV": "Prod_1"},
	} {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		for k, v := range mut {
			m[k] = v
		}
		if _, err := ParseConfig(get(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The agent (G-ARGO-3) checks a live object by hashing its last-applied configuration: Argo CD's tracking id and the
// gate's three annotations removed (an empty annotations map deleted), then render.ObjectDigest. That must equal the
// stamp, for objects with and without annotations of their own, and even when a chart wrote a gate annotation.
func TestTheStampIsWhatTheAgentRecomputesFromLastApplied(t *testing.T) {
	doc := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: plain}\ndata: {a: b}\n---\n" +
		"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: own, annotations: {team: x, clearance.hangar.io/grant: forged}}\ndata: {a: b}\n---\n" +
		"apiVersion: v1\nkind: Secret\nmetadata: {name: s, annotations: {clearance.hangar.io/rendered: forged}}\n"
	tree, err := Canonicalize([]byte(doc), "dest", nil)
	if err != nil {
		t.Fatal(err)
	}
	tree.Stamp("ch-1")
	for _, o := range tree.Emitted {
		raw, _ := json.Marshal(o) // what Argo CD records as last-applied, plus its tracking id
		var live map[string]any
		_ = json.Unmarshal(raw, &live)
		md := live["metadata"].(map[string]any)
		md["annotations"].(map[string]any)["argocd.argoproj.io/tracking-id"] = "app:v1/ConfigMap:dest/x"
		got := agentContentHash(t, live)
		if got != ann(o)[AnnRendered] {
			t.Errorf("%v: the agent computes %s, the stamp is %v", keyOf(o), got, ann(o)[AnnRendered])
		}
	}
}

// agentContentHash is providers/argocd/agent.ContentHash (G-ARGO-3), reproduced: that package is on another branch.
func agentContentHash(t *testing.T, o map[string]any) string {
	t.Helper()
	md := o["metadata"].(map[string]any)
	if a, ok := md["annotations"].(map[string]any); ok {
		for _, k := range []string{"argocd.argoproj.io/tracking-id", AnnRendered, AnnGrant, AnnTree, AnnRelease} {
			delete(a, k)
		}
		if len(a) == 0 {
			delete(md, "annotations")
		}
	}
	raw, _ := json.Marshal(o)
	set := render.Set{}
	if err := render.Add(set, raw); err != nil || len(set) != 1 {
		t.Fatal(err, len(set))
	}
	for _, d := range set {
		return render.ObjectDigest(d)
	}
	return ""
}

// The Helm source the plugin replaces had ignoreMissingValueFiles: an app with no base.yaml or release.yaml yet
// still renders. The plugin skips every absent value file (the injected values stay), and the ApplicationSet lists
// all three paths for it (apron tests/run.sh, "gate on: ... skips").
func TestAppWithNoValueFilesYetStillRenders(t *testing.T) {
	e := newEnv(t) // e.src is empty: none of the three files exists
	e.core.answer = &client.Change{ID: "ch-c", State: "cleared", Tier: 1, ExpiresAt: e.now.Add(time.Hour).Format(time.RFC3339Nano)}
	if _, _, err := e.generate(t); err != nil {
		t.Fatal(err)
	}
	for _, a := range e.exec.calls[2] {
		if strings.HasSuffix(a, "base.yaml") || strings.HasSuffix(a, "release.yaml") || strings.HasSuffix(a, "values.yaml") {
			t.Fatalf("an absent value file was passed to helm: %v", e.exec.calls[2])
		}
	}
	if last := e.exec.calls[2][len(e.exec.calls[2])-1]; !strings.HasSuffix(last, "injected.json") {
		t.Fatalf("the injected values are still passed: %v", e.exec.calls[2])
	}
}

// G-ARGO-6: the release id rides on every object as a gate annotation, from the chart's own hangar.io/release-id (the
// Rollout), else the values' releaseTracking.releaseId; two releases in one tree are none; a tenant-written stamp is
// never trusted; and the stamp never changes what the agent recomputes.
func TestTheReleaseIdIsStampedOnEveryObject(t *testing.T) {
	doc := "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata: {name: r, annotations: {hangar.io/release-id: 'c1:hangar-prod/prod'}}\n---\n" +
		"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: plain, annotations: {clearance.hangar.io/release: forged}}\ndata: {a: b}\n"
	tree, err := Canonicalize([]byte(doc), "dest", nil)
	if err != nil {
		t.Fatal(err)
	}
	tree.SetRelease("values:hangar-prod/prod") // the chart's own id wins over the values
	tree.Stamp("ch-1")
	for _, o := range tree.Emitted {
		if got := ann(o)[AnnRelease]; got != "c1:hangar-prod/prod" {
			t.Errorf("%v: release stamp %v", keyOf(o), got)
		}
		raw, _ := json.Marshal(o)
		var live map[string]any
		_ = json.Unmarshal(raw, &live)
		if got := agentContentHash(t, live); got != ann(o)[AnnRendered] {
			t.Errorf("%v: the release stamp changed what the agent recomputes", keyOf(o))
		}
	}
	// no Rollout: the values' id
	tree, _ = Canonicalize([]byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n"), "dest", nil)
	tree.SetRelease("c2:hangar-prod/prod")
	tree.Stamp("")
	if got := ann(tree.Emitted[0])[AnnRelease]; got != "c2:hangar-prod/prod" {
		t.Errorf("values fallback: %v", got)
	}
	// two releases in one tree: none (and a forged stamp is removed, not kept)
	two := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, annotations: {hangar.io/release-id: x, clearance.hangar.io/release: forged}}\n---\n" +
		"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: b, annotations: {hangar.io/release-id: y}}\n"
	tree, _ = Canonicalize([]byte(two), "dest", nil)
	tree.SetRelease("values")
	tree.Stamp("")
	for _, o := range tree.Emitted {
		if v, ok := ann(o)[AnnRelease]; ok {
			t.Errorf("%v: stamped %v although the objects name two releases", keyOf(o), v)
		}
	}
}

func TestTheReleaseIdIsReadFromTheValuesFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("base.yaml", "replicas: 2\n")
	write("prod/release.yaml", "releaseTracking:\n  releaseId: \"c9:hangar-prod/prod\"\n  cluster: hangar-prod\n")
	cfg := Config{ValueFiles: []string{"base.yaml", "missing.yaml", "prod/release.yaml"}}
	if got := releaseFromValues(cfg, dir); got != "c9:hangar-prod/prod" {
		t.Errorf("%q", got)
	}
	if got := releaseFromValues(Config{ValueFiles: []string{"base.yaml"}}, dir); got != "" {
		t.Errorf("%q", got)
	}
}
