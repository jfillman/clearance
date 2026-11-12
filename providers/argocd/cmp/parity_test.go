package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/jfillman/clearance/internal/argosrc"
)

// gateAPIApp is gate-api's Application as the generic tests describe it (see genericConfig): the airframe chart
// with a `$gitops` ref source.
func gateAPIApp(t *testing.T) Application {
	t.Helper()
	cfg := genericConfig(t)
	app := Application{}
	app.Metadata.Name, app.Metadata.Namespace = "gate-api-prod", "argocd"
	app.Spec.Destination.Namespace = "app-gate-api-prod"
	if err := json.Unmarshal([]byte(cfg.Sources), &app.Spec.Sources); err != nil {
		t.Fatal(err)
	}
	return app
}

type stubArgo struct {
	out  []byte
	err  error
	prov []argosrc.Provenance
}

func (s *stubArgo) Manifests(_ context.Context, _ string, prov []argosrc.Provenance) ([]byte, error) {
	s.prov = prov
	return s.out, s.err
}

// withTracking is Argo CD's `app manifests` output: the same objects, each carrying the tracking annotation the
// repo-server adds.
func withTracking(t *testing.T, manifests []byte) []byte {
	t.Helper()
	var out strings.Builder
	for _, doc := range strings.Split(string(manifests), "\n---") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var m map[string]any
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil || m == nil {
			t.Fatal(err, doc)
		}
		md := m["metadata"].(map[string]any)
		ann, _ := md["annotations"].(map[string]any)
		if ann == nil {
			ann = map[string]any{}
			md["annotations"] = ann
		}
		ann["argocd.argoproj.io/tracking-id"] = "gate-api-prod:/Service:app-gate-api-prod/x"
		b, _ := json.Marshal(m)
		out.WriteString("---\n" + string(b) + "\n")
	}
	return []byte(out.String())
}

func runParityOnce(t *testing.T, argo Argo, scopes map[string]bool, apps ...Application) *Report {
	t.Helper()
	g := &genericRun{t: t, repoOf: map[string]string{}, render: read(t, "head.yaml")}
	return RunParity(context.Background(), ParityOpts{Run: g.run, Argo: argo, Cluster: ClusterInfo{ServerVersion: "v1.34.2"}, Scopes: scopes, Instance: "test/argocd", Parallel: 2, Timeout: time.Minute}, apps)
}

func TestParityIdenticalDespiteTheTrackingAnnotation(t *testing.T) {
	want := tekton(t, "tekton.json")
	argo := &stubArgo{out: withTracking(t, read(t, "head.yaml"))}
	rep := runParityOnce(t, argo, nil, gateAPIApp(t))
	r := rep.Results[0]
	if r.Status != StatusIdentical || r.Objects != len(want.Objects) || r.PluginTree != want.Tree || r.ArgoTree != want.Tree || rep.Counts[StatusIdentical] != 1 {
		t.Fatalf("%+v", r)
	}
	// Argo CD is asked for the commits the plugin side resolved, by source position (a ref source included).
	if len(argo.prov) != 2 || argo.prov[0].Resolved != shaAirframe || argo.prov[1].Resolved != shaGitops || argo.prov[1].Type != "Ref" {
		t.Fatalf("%+v", argo.prov)
	}
}

// A comparison that cannot fail proves nothing: change one leaf, drop one object, add one, and each is found.
func TestParityFindsADifferenceObjectByObject(t *testing.T) {
	base := read(t, "head.yaml")
	cases := map[string]struct {
		mut  func(string) string
		want string
	}{
		"a leaf": {func(s string) string {
			return strings.Replace(s, "ghcr.io/jfillman/gate-api", "ghcr.io/jfillman/other", 1)
		}, "differs at /"},
		"an extra object in Argo CD": {func(s string) string {
			return s + "\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: extra\n  namespace: app-gate-api-prod\n"
		}, "only Argo CD renders app-gate-api-prod/ConfigMap/extra"},
	}
	for name, c := range cases {
		argo := &stubArgo{out: withTracking(t, []byte(c.mut(string(base))))}
		r := runParityOnce(t, argo, nil, gateAPIApp(t)).Results[0]
		if r.Status != StatusDiffers || !strings.Contains(r.Detail, c.want) || r.PluginTree == r.ArgoTree {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// An object only the plugin renders: Argo CD's output lacks one.
	docs := strings.Split(string(base), "\n---")
	argo := &stubArgo{out: withTracking(t, []byte(strings.Join(docs[:len(docs)-1], "\n---")))}
	r := runParityOnce(t, argo, nil, gateAPIApp(t)).Results[0]
	if r.Status != StatusDiffers || !strings.Contains(r.Detail, "only the plugin renders") {
		t.Fatalf("%+v", r)
	}
}

func TestParityStatuses(t *testing.T) {
	good := withTracking(t, read(t, "head.yaml"))
	plugin := gateAPIApp(t)
	plugin.Spec.Sources = []json.RawMessage{[]byte(`{"repoURL":"https://github.com/jfillman/x.git","plugin":{"name":"clearance"}}`)}
	jsonnet := gateAPIApp(t)
	jsonnet.Spec.Sources[0] = []byte(`{"repoURL":"https://github.com/jfillman/airframe.git","path":"charts/airframe-application","targetRevision":"main","kustomize":{"patches":[{"patch":"x"}]}}`)
	single := gateAPIApp(t)
	single.Spec.Sources = nil
	raw := json.RawMessage(`{"repoURL":"https://github.com/jfillman/airframe.git","path":"charts/airframe-application","targetRevision":"v0.3.168","plugin":{"name":"other"}}`)
	single.Spec.Source = &raw

	rep := runParityOnce(t, &stubArgo{out: good}, nil, plugin, jsonnet, single)
	got := []string{rep.Results[0].Status, rep.Results[1].Status, rep.Results[2].Status}
	if strings.Join(got, ",") != "not-comparable,unsupported,not-comparable" || !strings.Contains(rep.Results[1].Detail, "kustomize.patches") {
		t.Fatalf("%v %+v", got, rep.Results)
	}
	r := runParityOnce(t, &stubArgo{err: errors.New("ComparisonError: boom")}, nil, gateAPIApp(t)).Results[0]
	if r.Status != StatusError || !strings.Contains(r.Detail, "argo render") || !strings.Contains(r.Detail, "boom") {
		t.Fatalf("%+v", r)
	}
	// Both sides holding nothing stampable is the same answer, not a failure.
	empty := gateAPIApp(t)
	g := &genericRun{t: t, repoOf: map[string]string{}, render: nil}
	r = RunParity(context.Background(), ParityOpts{Run: g.run, Argo: &stubArgo{out: []byte("")}, Instance: "i", Parallel: 1, Timeout: time.Minute}, []Application{empty}).Results[0]
	if r.Status != StatusIdentical || !strings.Contains(r.Detail, "no objects") {
		t.Fatalf("%+v", r)
	}
}

func TestParityScopeAudit(t *testing.T) {
	// The cluster says a kind the plugin's list treats as namespaced is cluster-scoped (and the reverse).
	truth := map[string]bool{"Service": true, "ServiceAccount": false, "Rollout": false}
	r := runParityOnce(t, &stubArgo{out: withTracking(t, read(t, "head.yaml"))}, truth, gateAPIApp(t)).Results[0]
	if r.Status != StatusIdentical || strings.Join(r.ScopeMismatch, ",") != "Service" {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains((&Report{Results: []AppResult{r}, Counts: map[string]int{StatusIdentical: 1}}).Text(), "scope test/argocd/gate-api-prod") {
		t.Fatal("the scope finding is in the text report")
	}
}

func TestReadApplicationsAndTheSourcesParameter(t *testing.T) {
	list := `{"items":[{"metadata":{"name":"a"},"spec":{"project":"p","destination":{"namespace":"n"},"source":{"repoURL":"r","path":"p"}}},
	{"metadata":{"name":"b"},"spec":{"destination":{"namespace":"n"},"sources":[{"repoURL":"r1","chart":"c"},{"repoURL":"r2","ref":"x"}]}}]}`
	apps, err := ReadApplications([]byte(list))
	if err != nil || len(apps) != 2 {
		t.Fatal(apps, err)
	}
	if apps[0].SourcesJSON() != `[{"repoURL":"r","path":"p"}]` || apps[1].SourcesJSON() != `[{"repoURL":"r1","chart":"c"},{"repoURL":"r2","ref":"x"}]` {
		t.Fatal(apps[0].SourcesJSON(), apps[1].SourcesJSON())
	}
	// The parameter the plugin receives is exactly what the Application held: it parses back to the same sources.
	for _, a := range apps {
		if _, err := argosrc.ParseSources(a.SourcesJSON()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReadApplications([]byte(`{"foo":1}`)); err == nil {
		t.Fatal("accepted")
	}
}

func TestCLIArgoPinsEverySourceToTheRevisionTheRenderResolved(t *testing.T) {
	var got [][]string
	dir := t.TempDir()
	c := cliArgo{bin: "argocd", save: dir, run: func(_ context.Context, _ []string, name string, args ...string) ([]byte, error) {
		got = append(got, append([]string{name}, args...))
		return []byte("---\nkind: X\n"), nil
	}}
	prov := []argosrc.Provenance{{Position: 1, Repo: "r", Requested: "v1", Resolved: shaAirframe}, {Position: 2, Type: "Ref", Repo: "g", Requested: "main", Resolved: shaGitops},
		{Position: 3, Repo: "h", Chart: "c", Requested: "1.2.3", Resolved: "sha256:abc"}}
	if _, err := c.Manifests(context.Background(), "app", prov); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Manifests(context.Background(), "solo", prov[:1]); err != nil {
		t.Fatal(err)
	}
	// One source is asked with --revision (not left to the CLI's default, which prints the controller's target
	// objects: hooks removed, cluster-scoped namespaces cleared), a chart at its version.
	if _, err := c.Manifests(context.Background(), "chart", prov[2:]); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got[2], " ") != "argocd --core app manifests chart --source git --revision 1.2.3" {
		t.Fatalf("%v", got[2])
	}
	want := "argocd --core app manifests app --source git --revisions " + shaAirframe + " --source-positions 1 --revisions " + shaGitops +
		" --source-positions 2 --revisions 1.2.3 --source-positions 3"
	if strings.Join(got[0], " ") != want || strings.Join(got[1], " ") != "argocd --core app manifests solo --source git --revision "+shaAirframe {
		t.Fatalf("%v", got)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "app.yaml")); err != nil || len(b) == 0 {
		t.Fatal("the raw manifests are kept", err)
	}
}

func TestParityMarkdownAndText(t *testing.T) {
	rep := &Report{Counts: map[string]int{StatusIdentical: 1, StatusDiffers: 1, StatusUnsupported: 1}, Results: []AppResult{
		{Instance: "i/a", Name: "x", Status: StatusIdentical, Objects: 3},
		{Instance: "i/a", Name: "y", Status: StatusDiffers, Detail: "ns/Kind/n differs at /spec"},
		{Instance: "i/b", Name: "z", Status: StatusUnsupported, Detail: "unsupported (source 1): jsonnet | pipe"}}}
	md := rep.Markdown()
	for _, w := range []string{"3 Applications: identical 1, differs 1, unsupported 1", "| i/a | 2 | 1 | 1 |", "| i/a/y | differs |", `jsonnet \| pipe`} {
		if !strings.Contains(md, w) {
			t.Fatalf("missing %q in\n%s", w, md)
		}
	}
	if !strings.Contains(rep.Text(), "differs i/a/y: ns/Kind/n differs at /spec") {
		t.Fatal(rep.Text())
	}
}

func TestStripTrackingLeavesTheRestAlone(t *testing.T) {
	in := "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  annotations:\n    argocd.argoproj.io/tracking-id: x\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n  annotations:\n    argocd.argoproj.io/tracking-id: x\n    keep: me\n"
	out := string(stripTracking([]byte(in)))
	if strings.Contains(out, "tracking-id") || !strings.Contains(out, `"keep":"me"`) || strings.Contains(out, `"annotations":{}`) {
		t.Fatal(out)
	}
}

func TestHideSecretDataIsWhatArgoCDShows(t *testing.T) {
	in := "apiVersion: v1\nkind: Secret\nmetadata: {name: a}\ndata: {k: dg==}\nstringData: {s: plain}\n---\napiVersion: v1\nkind: Secret\nmetadata: {name: b}\ndata: {}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\ndata: {k: v}\n"
	out, err := hideSecretData([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"data":{"k":"++++++++","s":"++++++++"}`) || strings.Contains(s, "plain") || strings.Contains(s, "stringData") ||
		!strings.Contains(s, `"data":null`) || !strings.Contains(s, `"data":{"k":"v"}`) {
		t.Fatal(s)
	}
	// Nothing to hide: the render is returned as it was, byte for byte.
	same := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"
	if o, _ := hideSecretData([]byte(same)); string(o) != same {
		t.Fatal("a render with no Secret was rewritten")
	}
}

func TestParityNamesAChartThatRendersNullAnnotationsAndOneThatIsNotDeterministic(t *testing.T) {
	cm := func(name, extra string) string {
		return "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + name + "\n  namespace: app-gate-api-prod\n" + extra + "data: {a: b}\n"
	}
	// The plugin's render has `annotations:` (null); Argo CD's, after its tracking is stripped, has none.
	g := &genericRun{t: t, repoOf: map[string]string{}, render: []byte(cm("n", "  annotations:\n"))}
	r := RunParity(context.Background(), ParityOpts{Run: g.run, Argo: &stubArgo{out: withTracking(t, []byte(cm("n", "")))}, Instance: "i", Parallel: 1, Timeout: time.Minute},
		[]Application{gateAPIApp(t)}).Results[0]
	if r.Status != StatusDiffers || !strings.Contains(r.Detail, "annotations: null") {
		t.Fatalf("%+v", r)
	}
	// A render that changes between two runs is the chart's: said so.
	g = &genericRun{t: t, repoOf: map[string]string{}, each: func(n int) []byte { return []byte(cm("t", "  annotations:\n    at: \"t"+string(rune('0'+n))+"\"\n")) }}
	r = RunParity(context.Background(), ParityOpts{Run: g.run, Argo: &stubArgo{out: withTracking(t, []byte(cm("t", "  annotations:\n    at: \"other\"\n")))}, Instance: "i", Parallel: 1, Timeout: time.Minute},
		[]Application{gateAPIApp(t)}).Results[0]
	if r.Status != StatusDiffers || !strings.Contains(r.Detail, "non-deterministic render") {
		t.Fatalf("%+v", r)
	}
}
