package main

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Fuzz targets for the plugin's path and parameter handling (W-34 F7). Every path a tenant writes into the
// Application's plugin parameters (chartPath, kustomizeDir, valueFiles) and every parameter the plugin reads from its
// environment goes through these functions before anything reads the disk or runs a tool. The properties: nothing
// panics, an absolute path or a ".." segment is refused, and whatever is accepted stays inside the repository it names.
// The seeds below are the corpus; CI runs each target for 30 s (the cmp-fuzz job, tools/fuzz-all.sh).

// within is whether p is root or under it (both already clean and absolute).
func within(p, root string) bool {
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

var pathSeeds = []string{
	"", ".", "..", "a", "a/b.yaml", "env/dev/values.yaml", "../x", "a/../../x", "a/..", "./a", "a/./b", "a//b",
	"/etc/passwd", "//etc/passwd", "/", `..\x`, `a\..\..\x`, "C:/x", "-x", "--set=a", "~/x", "....//x", "%2e%2e/x",
	"a\x00b", "a\nb", "a/b/", " a", "link.yaml", "linkdir/values.yaml", "chart/../../outside",
}

// FuzzSafeRel is the check every plugin path parameter passes in ParseConfig: relative, no ".." segment, no NUL.
func FuzzSafeRel(f *testing.F) {
	for _, s := range pathSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if !safeRel(p) {
			return
		}
		if path.IsAbs(p) || filepath.IsAbs(p) || strings.ContainsRune(p, 0) {
			t.Fatalf("safeRel accepted %q", p)
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." {
				t.Fatalf("safeRel accepted %q, which has a .. segment", p)
			}
		}
		root := filepath.FromSlash("/repo/root")
		if j := filepath.Join(root, filepath.FromSlash(p)); !within(j, root) {
			t.Fatalf("safeRel accepted %q, which joins to %q outside %q", p, j, root)
		}
	})
}

// FuzzParseConfig feeds the plugin parameters (PARAM_*) and the Argo CD variables a tenant influences through
// ParseConfig, then Canonical, the cache keys and the generic mode's source parsing: what main does before any render.
func FuzzParseConfig(f *testing.F) {
	f.Add("app", "dev", "c1", "https://git.example.test/platform/charts.git", "v1.0.0", "charts/app", "base.yaml,dev/values.yaml", "configmap", ".", `{"a":1}`, "", "")
	f.Add("app", "dev", "c1", "https://GIT.example.test/platform/charts", "v1.0.0", "../charts", "/etc/passwd", "a/../../b", "..", "", "", "")
	f.Add("app", "dev", "c1", "--upload-pack=touch", "-x", "charts/app", "a,,b, ,../c", "", "", "", "", "")
	f.Add("app", "dev", "c1", "file:///etc", "v1", "", "", "", "", "", "", "")
	f.Add("app", "dev", "c1", "git@git.example.test:platform/charts.git", "main", "x", "y", "z", ".", "", "", "")
	f.Add("app", "dev", "c1", "", "", "", "", "", "", "", `[{"repoURL":"https://git.example.test/platform/charts.git","path":"../x","targetRevision":"v1"}]`, "--load-restrictor LoadRestrictionsNone")
	f.Add("App", "d-", "", "https://evil.example.test/x.git", "v1", "", "", "", "", "", "[]", "--enable-exec")
	f.Fuzz(func(t *testing.T, app, env, cluster, chartRepo, chartRev, chartPath, valueFiles, kustomizeDir, sourcePath, valuesJSON, sources, buildOpts string) {
		vars := map[string]string{
			"ARGOCD_APP_NAME": "app-dev", "ARGOCD_APP_NAMESPACE": "app-dev", "ARGOCD_APP_REVISION": strings.Repeat("a", 40),
			"ARGOCD_APP_SOURCE_REPO_URL": "https://git.example.test/acme/gitops.git", "ARGOCD_APP_SOURCE_PATH": sourcePath,
			"CLEARANCE_URL": "https://clearance.example.test", "CLEARANCE_CHART_REPOS": "https://git.example.test/platform/charts.git",
			"CLEARANCE_TOKEN_FILE": "/var/run/secrets/tokens/clearance", "CLEARANCE_CMP_CACHE_DIR": "/tmp/clearance-cmp-cache",
			"PARAM_APP": app, "PARAM_ENV": env, "PARAM_CLUSTER": cluster, "PARAM_CHARTREPO": chartRepo,
			"PARAM_CHARTREVISION": chartRev, "PARAM_CHARTPATH": chartPath, "PARAM_VALUEFILES": valueFiles,
			"PARAM_KUSTOMIZEDIR": kustomizeDir, "PARAM_VALUESJSON": valuesJSON, "PARAM_SOURCES": sources,
			"PARAM_KUSTOMIZEBUILDOPTIONS": buildOpts,
		}
		cfg, err := ParseConfig(func(k string) string { return vars[k] })
		if err != nil {
			return
		}
		root := filepath.FromSlash("/repo/root")
		for _, p := range append([]string{cfg.ChartPath, cfg.KustomizeDir}, cfg.ValueFiles...) {
			if p == "" {
				continue
			}
			if !safeRel(p) {
				t.Fatalf("ParseConfig accepted the path %q", p)
			}
			if j := filepath.Join(root, filepath.FromSlash(p)); !within(j, root) {
				t.Fatalf("ParseConfig accepted %q, which leaves the repository (%q)", p, j)
			}
		}
		for _, v := range []string{cfg.App, cfg.Env, cfg.Cluster} {
			if !nameRx.MatchString(v) {
				t.Fatalf("ParseConfig accepted the name %q", v)
			}
		}
		if cfg.ChartRepo != "" && (strings.HasPrefix(cfg.ChartRepo, "-") || !revRx.MatchString(cfg.ChartRev)) {
			t.Fatalf("ParseConfig accepted the chart %q at %q", cfg.ChartRepo, cfg.ChartRev)
		}
		canon, err := cfg.Canonical()
		if err == nil && canon.Sources == "" && canon.ChartRepo != "" && canon.ChartRepo != vars["CLEARANCE_CHART_REPOS"] && canon.ChartRepo != vars["ARGOCD_APP_SOURCE_REPO_URL"] {
			t.Fatalf("Canonical let the chart come from %q, which the platform did not write", canon.ChartRepo)
		}
		if err == nil && canon.Sources != "" {
			_, _ = SourcesRequest(canon)
		}
		canon.RenderCacheTTL, canon.chartCommit = 1, strings.Repeat("b", 40)
		_, _ = renderKey(canon), lkgKey(canon)
	})
}

// FuzzRenderPaths runs Render (the chart-parameter mode) on a real checkout with a value file, a kustomize directory, a
// chart, an in-repository symlink and two symlinks that leave the repository, for every path parameter ParseConfig
// accepts. The tools are fakes that record their arguments: whatever helm or kustomize would be given must resolve
// inside the checkout (the injected values file, written by the plugin into its own scratch, aside).
func FuzzRenderPaths(f *testing.F) {
	src, outside := renderFixture(f)
	for _, s := range pathSeeds {
		f.Add(s, "chart", "k")
		f.Add("values.yaml", s, "k")
		f.Add("values.yaml", "chart", s)
	}
	f.Add("out.yaml", "outdir", "outdir")
	f.Add("inlink.yaml", "chart", "")
	f.Fuzz(func(t *testing.T, valueFile, chartPath, kustomizeDir string) {
		cfg := Config{AppName: "app-dev", Destination: "app-dev", App: "app", Env: "dev", Cluster: "c1", CoreURL: "https://clearance.example.test",
			TokenFile: "/var/run/secrets/tokens/clearance", FSSandbox: NetnsOff, ChartPath: chartPath, KustomizeDir: kustomizeDir, ValuesJSON: `{"a":1}`}
		for _, v := range strings.Split(valueFile, ",") {
			if v = strings.TrimSpace(v); v != "" {
				cfg.ValueFiles = append(cfg.ValueFiles, v)
			}
		}
		if cfg.validate() != nil {
			return
		}
		var mu sync.Mutex
		var seen [][]string
		run := func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
			mu.Lock()
			seen = append(seen, append([]string{name}, args...))
			mu.Unlock()
			if name == "kustomize" {
				return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: k}\n"), nil
			}
			return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: h}\n"), nil
		}
		if _, err := Render(context.Background(), run, cfg, src); err != nil {
			return
		}
		realSrc, _ := filepath.EvalSymlinks(src)
		inside := func(p string) {
			t.Helper()
			r, err := filepath.EvalSymlinks(p)
			if err != nil {
				r = filepath.Clean(p) // a path that does not exist reads nothing; it must still name a place inside
				if !within(r, filepath.Clean(src)) {
					t.Fatalf("a tool was given %q, outside the checkout (value file %q, chart %q, kustomize %q)", p, valueFile, chartPath, kustomizeDir)
				}
				return
			}
			if !within(r, realSrc) || strings.HasPrefix(r, outside) {
				t.Fatalf("a tool was given %q, which resolves to %q outside the checkout (value file %q, chart %q, kustomize %q)", p, r, valueFile, chartPath, kustomizeDir)
			}
		}
		for _, c := range seen {
			switch c[0] {
			case "helm":
				inside(c[3]) // helm template <name> <chart> ...
				for i := 0; i+1 < len(c); i++ {
					if c[i] == "-f" && filepath.Base(c[i+1]) != "injected.json" {
						inside(c[i+1])
					}
				}
			case "kustomize":
				inside(c[len(c)-1])
			}
		}
	})
}

// renderFixture is a checkout for FuzzRenderPaths: values.yaml, chart/, k/ (a kustomization), inlink.yaml (a link to
// values.yaml), and out.yaml and outdir (links to a file and a directory outside the checkout).
func renderFixture(f *testing.F) (src, outside string) {
	f.Helper()
	src, outside = f.TempDir(), f.TempDir()
	if r, err := filepath.EvalSymlinks(outside); err == nil {
		outside = r
	}
	for name, body := range map[string]string{
		"values.yaml": "a: 1\n", "sub/values.yaml": "b: 2\n", "chart/Chart.yaml": "apiVersion: v2\nname: c\nversion: 0.1.0\n",
		"chart/templates/cm.yaml": "kind: ConfigMap\n", "k/kustomization.yaml": "resources: []\n",
	} {
		p := filepath.Join(src, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			f.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			f.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("token: s3cr3t\n"), 0o644); err != nil {
		f.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "chart", "templates"), 0o755); err != nil {
		f.Fatal(err)
	}
	for link, target := range map[string]string{"inlink.yaml": "values.yaml", "out.yaml": filepath.Join(outside, "secret"), "outdir": outside} {
		if err := os.Symlink(target, filepath.Join(src, link)); err != nil {
			f.Fatal(err)
		}
	}
	return src, outside
}

// FuzzNormalizeRepo is the allow list's comparison: nothing panics, and an accepted URL has an allowed scheme, a host
// and no ".", ".." or empty path segment.
func FuzzNormalizeRepo(f *testing.F) {
	for _, s := range []string{
		"https://git.example.test/platform/charts.git", "HTTPS://Git.Example.Test:443/platform/charts/", "git@git.example.test:o/r.git",
		"ssh://git@git.example.test:22/o/r", "git://127.0.0.1:9418/chart.git", "http://[fd00::1]:8080/o/r", "oci://registry.example.test/charts",
		"registry.example.test/charts", "file:///etc", "ext::sh -c touch% /tmp/x", "-uhttps://x", "https://h/a/../b", "https://h/a%2f..%2fb",
		"https://h/%2e%2e/b", "https://u:p@h/o/r", "https://h/o/r?x=1", "https://h", "/local/path", "../relative", "https://h//o",
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, raw string, oci bool) {
		n, err := NormalizeRepo(raw, oci)
		if err != nil {
			return
		}
		scheme, rest, ok := strings.Cut(n, "://")
		if !ok {
			t.Fatalf("NormalizeRepo(%q) = %q, which has no scheme", raw, n)
		}
		switch scheme {
		case "https", "http", "ssh", "git", "oci":
		default:
			t.Fatalf("NormalizeRepo(%q) = %q: scheme %q", raw, n, scheme)
		}
		host, p, _ := strings.Cut(rest, "/")
		if host == "" {
			t.Fatalf("NormalizeRepo(%q) = %q has no host", raw, n)
		}
		if p != "" {
			for _, seg := range strings.Split(p, "/") {
				if seg == "" || seg == "." || seg == ".." {
					t.Fatalf("NormalizeRepo(%q) = %q has a %q path segment", raw, n, seg)
				}
			}
		}
	})
}
