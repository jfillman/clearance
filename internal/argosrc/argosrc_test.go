package argosrc

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// execRun is Runner on the real machine, recording every call.
type recorder struct {
	mu    sync.Mutex
	calls [][]string
	fake  func(dir, name string, args []string) ([]byte, bool, error)
}

func (r *recorder) run(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	r.calls = append(r.calls, append([]string{name}, args...))
	r.mu.Unlock()
	if r.fake != nil {
		if out, handled, err := r.fake(dir, name, args); handled {
			return out, err
		}
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var out, eb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &eb
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=file:https",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test"}, env...)
	if err := cmd.Run(); err != nil {
		return nil, errors.New(name + " " + strings.Join(args, " ") + ": " + err.Error() + ": " + eb.String())
	}
	return out.Bytes(), nil
}

func (r *recorder) find(name, first string) []string {
	for _, c := range r.calls {
		if c[0] == name && len(c) > 1 && c[1] == first {
			return c
		}
	}
	return nil
}

func need(t *testing.T, bin string) {
	t.Helper()
	if _, err := exec.LookPath(bin); err != nil {
		t.Skipf("%s is not installed", bin)
	}
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// gitRepo makes a local repository with the files committed on branch main and returns its path.
func gitRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	need(t, "git")
	dir := t.TempDir()
	for k, v := range files {
		write(t, dir, k, v)
	}
	r := &recorder{}
	for _, a := range [][]string{{"init", "-q", "-b", "main"}, {"add", "-A"}, {"commit", "-q", "-m", "x"}} {
		if _, err := r.run(context.Background(), dir, nil, "git", a...); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const chartYAML = "apiVersion: v2\nname: demo\nversion: 1.2.3\n"

// A chart that shows what Helm was told: the release, the namespace, the values, the cluster's version and APIs.
const cmTemplate = `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-cm
data:
  release: {{ .Release.Name | quote }}
  namespace: {{ .Release.Namespace | quote }}
  kube: {{ .Capabilities.KubeVersion.Version | quote }}
  hasFoo: {{ .Capabilities.APIVersions.Has "example.test/v1/Foo" | quote }}
  color: {{ .Values.color | quote }}
  size: {{ .Values.size | quote }}
  extra: {{ .Values.extra | default "none" | quote }}
  list: {{ join "," (.Values.list | default list) | quote }}
`

func demoChart() map[string]string {
	return map[string]string{
		"chart/Chart.yaml":             chartYAML,
		"chart/values.yaml":            "color: red\nsize: s\n",
		"chart/templates/cm.yaml":      cmTemplate,
		"chart/crds/crd.yaml":          "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: foos.example.test\nspec:\n  group: example.test\n",
		"env/dev.yaml":                 "color: blue\n",
		"env/dev2.yaml":                "size: l\nextra: from-dev2\n",
		"chart/templates/NOTES.txt":    "notes\n",
		"chart/templates/_helpers.tpl": "",
	}
}

func opts(t *testing.T, r *recorder) Options {
	return Options{Run: r.run, Work: t.TempDir(), AllowLocalRepos: true}
}

func render(t *testing.T, r *recorder, req Request) (*Result, error) {
	t.Helper()
	need(t, "helm")
	return Render(context.Background(), opts(t, r), req)
}

func mustRender(t *testing.T, r *recorder, req Request) *Result {
	t.Helper()
	res, err := render(t, r, req)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return res
}

func has(t *testing.T, res *Result, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(string(res.Manifests), s) {
			t.Fatalf("the render has no %q:\n%s", s, res.Manifests)
		}
	}
}

func TestHelmFromGitPath(t *testing.T) {
	repo := gitRepo(t, demoChart())
	r := &recorder{}
	res := mustRender(t, r, Request{AppName: "demo-dev", Namespace: "ns-dev", KubeVersion: "v1.34.2+k3s1", APIVersions: []string{"v1", "example.test/v1/Foo"},
		Sources: []Source{{RepoURL: repo, Path: "chart", TargetRevision: "main", Helm: &Helm{
			ValueFiles: []string{"/env/dev.yaml", "../env/dev2.yaml"},
			Values:     "color: ignored\n", ValuesObject: []byte(`{"color":"green","list":["a","b"]}`),
			Parameters: []HelmParameter{{Name: "size", Value: "xl"}, {Name: "extra", Value: "a,b"}},
		}}}})
	// The release is the Application's name, the namespace its destination, valuesObject wins over values and
	// comes after the files, parameters win over everything, the cluster's facts reach the chart.
	has(t, res, `name: demo-dev-cm`, `release: "demo-dev"`, `namespace: "ns-dev"`, `kube: "v1.34.2"`, `hasFoo: "true"`,
		`color: "green"`, `size: "xl"`, `extra: "a,b"`, `list: "a,b"`, "kind: CustomResourceDefinition")
	if len(res.Sources) != 1 || res.Sources[0].Type != "Helm" || len(res.Sources[0].Resolved) != 40 {
		t.Fatalf("provenance %+v", res.Sources)
	}
	h := r.find("helm", "template")
	want := []string{"template", ".", "--name-template", "demo-dev", "--namespace", "ns-dev", "--kube-version", "1.34.2"}
	for i, w := range want {
		if h[1+i] != w {
			t.Fatalf("helm was run as %v, want it to start %v", h, want)
		}
	}
	if !contains(h, "--include-crds") || !contains(h, "--api-versions") {
		t.Fatalf("helm was run as %v", h)
	}
	// The value files come in the listed order, then the inline values file.
	var vals []string
	for i, a := range h {
		if a == "--values" {
			vals = append(vals, filepath.Base(h[i+1]))
		}
	}
	if len(vals) != 3 || vals[0] != "dev.yaml" || vals[1] != "dev2.yaml" || !strings.HasPrefix(vals[2], "values-") {
		t.Fatalf("values files %v", vals)
	}
	if len(res.ValueDocs) != 3 {
		t.Fatalf("value docs %d", len(res.ValueDocs))
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestHelmReleaseNameNamespaceAndSkipCrds(t *testing.T) {
	repo := gitRepo(t, demoChart())
	res := mustRender(t, &recorder{}, Request{AppName: "ns_demo", Namespace: "dest",
		Sources: []Source{{RepoURL: repo, Path: "chart", Helm: &Helm{ReleaseName: "", Namespace: "other", SkipCrds: true}}}})
	// "namespace_name" is an Application in another namespace: the release is the name part. helm.namespace wins.
	has(t, res, `release: "demo"`, `namespace: "other"`)
	if strings.Contains(string(res.Manifests), "CustomResourceDefinition") {
		t.Fatal("skipCrds still rendered the CRD")
	}
	res = mustRender(t, &recorder{}, Request{AppName: "app", Namespace: "dest",
		Sources: []Source{{RepoURL: repo, Path: "chart", Helm: &Helm{ReleaseName: "custom"}}}})
	has(t, res, `release: "custom"`, `namespace: "dest"`)
	// No helm section at all: the chart is found by its Chart.yaml.
	res = mustRender(t, &recorder{}, Request{AppName: "app", Namespace: "dest", Sources: []Source{{RepoURL: repo, Path: "chart"}}})
	has(t, res, `release: "app"`)
}

func TestMultiSourceRefValueFiles(t *testing.T) {
	chart := gitRepo(t, demoChart())
	values := gitRepo(t, map[string]string{"apps/base.yaml": "color: violet\n", "apps/dev.yaml": "size: m\n"})
	r := &recorder{}
	res := mustRender(t, r, Request{AppName: "multi", Namespace: "ns", Sources: []Source{
		{RepoURL: chart, Path: "chart", Helm: &Helm{ValueFiles: []string{"$vals/apps/base.yaml", "$vals/apps/dev.yaml", "$vals/apps/absent.yaml"}, IgnoreMissingValueFiles: true}},
		{RepoURL: values, Ref: "vals", Directory: &Directory{Exclude: "*"}},
	}})
	has(t, res, `color: "violet"`, `size: "m"`)
	if len(res.Sources) != 2 || res.Sources[1].Type != "Ref" {
		t.Fatalf("provenance %+v", res.Sources)
	}
	// Without ignoreMissingValueFiles an absent file is passed on and Helm refuses it, as under Argo CD.
	_, err := render(t, &recorder{}, Request{AppName: "multi", Namespace: "ns", Sources: []Source{
		{RepoURL: chart, Path: "chart", Helm: &Helm{ValueFiles: []string{"$vals/apps/absent.yaml"}}},
		{RepoURL: values, Ref: "vals"},
	}})
	if err == nil || !strings.Contains(err.Error(), "absent.yaml") {
		t.Fatalf("err %v", err)
	}
	// An unknown $ref is an error; so is a ref that escapes its repository.
	for _, vf := range []string{"$nope/apps/base.yaml", "$vals/../../etc/passwd"} {
		_, err = render(t, &recorder{}, Request{AppName: "m", Namespace: "ns", Sources: []Source{
			{RepoURL: chart, Path: "chart", Helm: &Helm{ValueFiles: []string{vf}}}, {RepoURL: values, Ref: "vals"}}})
		if err == nil {
			t.Fatalf("%s was accepted", vf)
		}
	}
}

func TestValueFileGlobsKeepExplicitPositions(t *testing.T) {
	repo := gitRepo(t, map[string]string{
		"chart/Chart.yaml": chartYAML, "chart/templates/cm.yaml": cmTemplate,
		"vals/a.yaml": "color: a\n", "vals/b.yaml": "color: b\n", "vals/c.yaml": "color: c\n",
	})
	r := &recorder{}
	res := mustRender(t, r, Request{AppName: "g", Namespace: "ns", Sources: []Source{{RepoURL: repo, Path: "chart",
		Helm: &Helm{ValueFiles: []string{"../vals/*.yaml", "../vals/a.yaml"}}}}})
	// b, c (glob order) then a (its explicit position): a wins.
	has(t, res, `color: "a"`)
	h := r.find("helm", "template")
	var order []string
	for i, a := range h {
		if a == "--values" {
			order = append(order, filepath.Base(h[i+1]))
		}
	}
	if strings.Join(order, ",") != "b.yaml,c.yaml,a.yaml" {
		t.Fatalf("order %v", order)
	}
}

func TestEnvsubstInParametersAndValueFiles(t *testing.T) {
	repo := gitRepo(t, demoChart())
	res := mustRender(t, &recorder{}, Request{AppName: "envy", Namespace: "ns", Project: "proj", Sources: []Source{{RepoURL: repo, Path: "chart", TargetRevision: "main",
		Helm: &Helm{ValueFiles: []string{"/env/${ARGOCD_APP_NAME}x.yaml", "/env/dev.yaml"}, IgnoreMissingValueFiles: true,
			Parameters: []HelmParameter{{Name: "extra", Value: "$ARGOCD_APP_PROJECT_NAME-$ARGOCD_APP_SOURCE_TARGET_REVISION-$$-$UNKNOWN"}}}}}})
	has(t, res, `extra: "proj-main-$-"`, `color: "blue"`)
}

func TestHelmFromHTTPRepository(t *testing.T) {
	need(t, "helm")
	dir := t.TempDir()
	write(t, dir, "src/demo/Chart.yaml", chartYAML)
	write(t, dir, "src/demo/values.yaml", "color: red\nsize: s\n")
	write(t, dir, "src/demo/templates/cm.yaml", cmTemplate)
	r := &recorder{}
	if _, err := r.run(context.Background(), filepath.Join(dir, "src"), nil, "helm", "package", "demo", "--destination", filepath.Join(dir, "repo")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.run(context.Background(), filepath.Join(dir, "repo"), nil, "helm", "repo", "index", "."); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(dir, "repo"))))
	defer srv.Close()
	// helm resolves the chart URL in index.yaml against the repository URL it was given.
	r = &recorder{}
	res := mustRender(t, r, Request{AppName: "web", Namespace: "ns", Sources: []Source{{RepoURL: srv.URL, Chart: "demo", TargetRevision: "1.2.3",
		Helm: &Helm{ValuesObject: []byte(`{"color":"teal"}`)}}}})
	has(t, res, `release: "web"`, `color: "teal"`, `size: "s"`)
	if res.Sources[0].Type != "Helm" || !strings.HasPrefix(res.Sources[0].Resolved, "sha256:") || res.Sources[0].Chart != "demo" {
		t.Fatalf("provenance %+v", res.Sources)
	}
	pull := r.find("helm", "pull")
	if !contains(pull, "--repo") || !contains(pull, "--version") || !contains(pull, "demo") {
		t.Fatalf("pull %v", pull)
	}
	// A version constraint is not an exact version: refused.
	_, err := render(t, &recorder{}, Request{AppName: "web", Namespace: "ns", Sources: []Source{{RepoURL: srv.URL, Chart: "demo", TargetRevision: "1.*"}}})
	if !IsUnsupported(err) {
		t.Fatalf("err %v", err)
	}
}

// chartTgz is a packaged chart for the OCI test's fake `helm pull`.
func chartTgz(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range map[string]string{"demo/Chart.yaml": chartYAML, "demo/values.yaml": "color: red\nsize: s\n", "demo/templates/cm.yaml": cmTemplate} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestHelmFromOCIRegistry(t *testing.T) {
	tgz := chartTgz(t)
	r := &recorder{fake: func(dir, name string, args []string) ([]byte, bool, error) {
		if name == "helm" && args[0] == "pull" {
			dest := args[indexOf(args, "--destination")+1]
			return nil, true, os.WriteFile(filepath.Join(dest, "demo-1.2.3.tgz"), tgz, 0o644)
		}
		return nil, false, nil
	}}
	res := mustRender(t, r, Request{AppName: "oci-app", Namespace: "ns", Sources: []Source{{RepoURL: "registry.example.test/org/charts", Chart: "demo", TargetRevision: "1.2.3"}}})
	has(t, res, `release: "oci-app"`, `color: "red"`)
	pull := r.find("helm", "pull")
	if pull[2] != "--destination" || !contains(pull, "oci://registry.example.test/org/charts/demo") || pull[indexOf(pull, "--version")+1] != "1.2.3" {
		t.Fatalf("pull %v", pull)
	}
	for _, rev := range []string{"", "^1.0.0", "1.x"} {
		_, err := render(t, r, Request{AppName: "o", Namespace: "ns", Sources: []Source{{RepoURL: "registry.example.test/org/charts", Chart: "demo", TargetRevision: rev}}})
		if !IsUnsupported(err) {
			t.Fatalf("revision %q: %v", rev, err)
		}
	}
}

func indexOf(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

func TestUntarRefusesEscapes(t *testing.T) {
	for _, h := range []tar.Header{
		{Name: "../evil", Typeflag: tar.TypeReg, Size: 1},
		{Name: "/abs", Typeflag: tar.TypeReg, Size: 1},
		{Name: "d/link", Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"},
		{Name: "dev", Typeflag: tar.TypeChar},
	} {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(zw)
		h.Mode = 0o644
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte("x"))
		}
		tw.Close()
		zw.Close()
		if err := untar(buf.Bytes(), t.TempDir()); err == nil {
			t.Fatalf("%q was unpacked", h.Name)
		}
	}
}

func TestKustomize(t *testing.T) {
	need(t, "kustomize")
	repo := gitRepo(t, map[string]string{
		"app/kustomization.yaml": "resources:\n- deploy.yaml\n",
		"app/deploy.yaml":        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 1\n  selector:\n    matchLabels: {app: web}\n  template:\n    metadata:\n      labels: {app: web}\n    spec:\n      containers:\n      - name: web\n        image: nginx:1.0\n",
	})
	r := &recorder{}
	res := mustRender(t, r, Request{AppName: "k", Namespace: "ns", Sources: []Source{{RepoURL: repo, Path: "app", Kustomize: &Kustomize{
		NamePrefix: "dev-", NameSuffix: "-x", Images: []string{"nginx=registry.example.test/nginx:$ARGOCD_APP_NAME"},
		CommonLabels: map[string]string{"env": "dev"}, CommonAnnotations: map[string]string{"note": "$ARGOCD_APP_NAME"},
		Namespace: "kns", Replicas: []KustomizeRep{{Name: "dev-web-x", Count: []byte(`"3"`)}},
	}}}})
	has(t, res, "name: dev-web-x", "image: registry.example.test/nginx:k", "env: dev", "namespace: kns", "replicas: 3", "note: $ARGOCD_APP_NAME")
	// The type is also found from a kustomization file with no kustomize section.
	res = mustRender(t, &recorder{}, Request{AppName: "k", Namespace: "ns", Sources: []Source{{RepoURL: repo, Path: "app"}}})
	has(t, res, "kind: Deployment")
	// Build options other than helm ones pass through; helm inflation is refused.
	_, err := render(t, &recorder{}, Request{AppName: "k", Namespace: "ns", KustomizeBuildOptions: "--enable-helm", Sources: []Source{{RepoURL: repo, Path: "app"}}})
	if !IsUnsupported(err) {
		t.Fatalf("err %v", err)
	}
}

func TestDirectory(t *testing.T) {
	cm := func(n string) string { return "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + n + "\n" }
	repo := gitRepo(t, map[string]string{
		"d/a.yaml": cm("a"), "d/b.yml": cm("b"), "d/c.json": `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"c"}}`,
		"d/skip.yaml": "# +argocd:skip-file-rendering\n" + cm("skipped"), "d/notes.txt": "kind: nope",
		"d/values.yaml": "replicas: 2\n", "d/sub/e.yaml": cm("e"), "d/sub/deep/f.yaml": cm("f"),
		"d/multi.yaml": cm("m1") + "---\n" + cm("m2"),
	})
	names := func(res *Result) string {
		var out []string
		for _, n := range []string{"a", "b", "c", "e", "f", "m1", "m2", "skipped"} {
			if strings.Contains(string(res.Manifests), "name: "+n+"\n") || strings.Contains(string(res.Manifests), `"name":"`+n+`"`) {
				out = append(out, n)
			}
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		d    *Directory
		want string
	}{
		{nil, "a,b,c,m1,m2"},
		{&Directory{Recurse: true}, "a,b,c,e,f,m1,m2"},
		{&Directory{Recurse: true, Exclude: "sub/*"}, "a,b,c,m1,m2"},
		{&Directory{Recurse: true, Include: "{a.yaml,sub/*.yaml}"}, "a,e,f"},
		{&Directory{Recurse: true, Include: "*.yaml", Exclude: "sub/deep/*"}, "a,e,m1,m2"},
		{&Directory{Exclude: "*"}, ""},
	} {
		res := mustRender(t, &recorder{}, Request{AppName: "d", Namespace: "ns", Sources: []Source{{RepoURL: repo, Path: "d", Directory: c.d}}})
		if got := names(res); got != c.want {
			t.Fatalf("%+v: rendered %q, want %q", c.d, got, c.want)
		}
	}
}

func TestDirectoryBrokenManifests(t *testing.T) {
	cm := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"
	bad := gitRepo(t, map[string]string{"x/a.yaml": cm, "x/broken.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: [\n"})
	if _, err := render(t, &recorder{}, Request{AppName: "d", Namespace: "ns", Sources: []Source{{RepoURL: bad, Path: "x"}}}); err == nil {
		t.Fatal("a broken manifest was ignored")
	}
	// A YAML file that does not parse and does not look like a manifest is left alone, as Argo CD leaves it.
	ok := gitRepo(t, map[string]string{"x/a.yaml": cm, "x/junk.yaml": "foo: [\n"})
	mustRender(t, &recorder{}, Request{AppName: "d", Namespace: "ns", Sources: []Source{{RepoURL: ok, Path: "x"}}})
	two := gitRepo(t, map[string]string{"x/a.json": `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a"}} {"kind":"X"}`})
	if _, err := render(t, &recorder{}, Request{AppName: "d", Namespace: "ns", Sources: []Source{{RepoURL: two, Path: "x"}}}); err == nil {
		t.Fatal("two objects in a JSON file were accepted")
	}
}

func TestFailsClosed(t *testing.T) {
	repo := gitRepo(t, map[string]string{
		"chart/Chart.yaml": chartYAML, "chart/templates/cm.yaml": cmTemplate,
		"jsonnet/a.jsonnet": "{}", "ovr/Chart.yaml": chartYAML, "ovr/.argocd-source.yaml": "helm:\n  parameters: []\n",
		"k/kustomization.yaml": "resources: []\n", "d/a.yaml": "x: 1\n",
	})
	sub := gitRepo(t, map[string]string{"a.txt": "x", ".gitmodules": "[submodule \"x\"]\n"})
	cases := []struct {
		name string
		src  Source
		raw  string
		want string
	}{
		{"plugin", Source{RepoURL: repo, Path: "chart", Plugin: &Plugin{Name: "other"}}, "", "another config management plugin"},
		{"oci artifact", Source{RepoURL: "oci://registry.example.test/x", Path: "."}, "", "oci:// artifact"},
		{"tag prefix", Source{RepoURL: repo, Path: "chart", TagPrefix: "v"}, "", "tagPrefix"},
		{"jsonnet", Source{RepoURL: repo, Path: "jsonnet", Directory: &Directory{}}, "", "jsonnet"},
		{"patches", Source{RepoURL: repo, Path: "k", Kustomize: &Kustomize{Patches: []json.RawMessage{[]byte(`{"patch":"x"}`)}}}, "", "kustomize.patches"},
		{"kustomize version", Source{RepoURL: repo, Path: "k", Kustomize: &Kustomize{Version: "v4"}}, "", "kustomize.version"},
		{"argocd-source", Source{RepoURL: repo, Path: "ovr"}, "", ".argocd-source.yaml"},
		{"url value file", Source{RepoURL: repo, Path: "chart", Helm: &Helm{ValueFiles: []string{"https://example.test/v.yaml"}}}, "", "remote value file"},
		{"helm 2", Source{RepoURL: repo, Path: "chart", Helm: &Helm{Version: "v2"}}, "", "helm.version"},
		{"submodules", Source{RepoURL: sub, Path: "."}, "", "submodules"},
		{"unknown field", Source{}, `[{"repoURL":"x","somethingNew":true}]`, "does not know"},
	}
	for _, c := range cases {
		var err error
		if c.raw != "" {
			_, err = ParseSources(c.raw)
		} else {
			_, err = render(t, &recorder{}, Request{AppName: "f", Namespace: "ns", Sources: []Source{c.src}})
		}
		if !IsUnsupported(err) || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	// Not repositories the sidecar may read.
	for _, u := range []string{"file:///etc", "ext::sh -c id", "/etc", "-oProxyCommand=x"} {
		_, err := Render(context.Background(), Options{Run: (&recorder{}).run, Work: t.TempDir()}, Request{AppName: "f", Namespace: "ns", Sources: []Source{{RepoURL: u, Path: "."}}})
		if err == nil || !strings.Contains(err.Error(), "repository URL") {
			t.Fatalf("%s: %v", u, err)
		}
	}
}

func TestDuplicateObjectsAreRefused(t *testing.T) {
	cm := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: same\n"
	a := gitRepo(t, map[string]string{"x/a.yaml": cm})
	_, err := render(t, &recorder{}, Request{AppName: "d", Namespace: "ns", Sources: []Source{{RepoURL: a, Path: "x"}, {RepoURL: a, Path: "x"}}})
	if err == nil || !strings.Contains(err.Error(), "ConfigMap/same") {
		t.Fatalf("err %v", err)
	}
}

func TestRefOnlySourceRendersNothingAndSingleSourceRefIsLiteral(t *testing.T) {
	repo := gitRepo(t, map[string]string{"r/a.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"})
	// Two sources, the second only a ref: it renders nothing even without an exclude.
	res := mustRender(t, &recorder{}, Request{AppName: "d", Namespace: "ns", Sources: []Source{{RepoURL: repo, Path: "r"}, {RepoURL: repo, Ref: "x"}}})
	if strings.Count(string(res.Manifests), "kind: ConfigMap") != 1 {
		t.Fatalf("%s", res.Manifests)
	}
}

func TestParseKubeVersionAndReleaseName(t *testing.T) {
	for in, want := range map[string]string{"": "", "v1.34.2": "1.34.2", "1.30": "1.30", "v1.30.2+k3s1": "1.30.2", "v1.31.0-eks-abc": "1.31.0"} {
		if got, err := ParseKubeVersion(in); err != nil || got != want {
			t.Fatalf("%q: %q %v", in, got, err)
		}
	}
	if _, err := ParseKubeVersion("latest"); err == nil {
		t.Fatal("accepted")
	}
	if ReleaseName("ns_app", nil) != "app" || ReleaseName("app", &Helm{ReleaseName: "r"}) != "r" || ReleaseName("a_b_c", nil) != "a_b_c" {
		t.Fatal("release names")
	}
	if cleanSetParameter("a,b") != `a\,b` || cleanSetParameter(`a\,b`) != `a\,b` || cleanSetParameter("{a,b}") != "{a,b}" {
		t.Fatal("set parameters")
	}
}

func TestReleaseIDFromValues(t *testing.T) {
	got := ReleaseIDFromValues([][]byte{[]byte("releaseTracking:\n  releaseId: r1\n"), []byte("other: 1\n"), []byte("releaseTracking:\n  releaseId: r2\n")})
	if got != "r2" {
		t.Fatal(got)
	}
}

func TestDuplicateKeysAreNotArgosrcsToRefuse(t *testing.T) {
	// A mapping that repeats a key renders under Argo CD (the last one wins). The renderer passes it through; the
	// plugin's stamping reader (Canonicalize) is what refuses it, and the parity run reports that as a refusal.
	dup := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  k: 1\n  k: 2\n"
	repo := gitRepo(t, map[string]string{"x/a.yaml": dup})
	res := mustRender(t, &recorder{}, Request{AppName: "d", Namespace: "ns", Sources: []Source{{RepoURL: repo, Path: "x"}}})
	has(t, res, "name: a")
}

func TestAnApplicationWithoutADestinationNamespaceRenders(t *testing.T) {
	repo := gitRepo(t, demoChart())
	r := &recorder{}
	mustRender(t, r, Request{AppName: "cluster-scoped-app", Sources: []Source{{RepoURL: repo, Path: "chart"}}})
	if h := r.find("helm", "template"); contains(h, "--namespace") {
		t.Fatalf("helm was run as %v: with no destination namespace Argo CD passes no --namespace", h)
	}
}

func TestPluginSourceKeepsItsParameters(t *testing.T) {
	srcs, err := ParseSources(`[{"repoURL":"r","plugin":{"name":"clearance","env":[{"name":"a","value":"b"}],"parameters":[{"name":"app","string":"x"}]}}]`)
	if err != nil || srcs[0].Plugin == nil || srcs[0].Plugin.Name != "clearance" {
		t.Fatal(srcs, err)
	}
}
