package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
)

// The plugin's hot paths, for the regression check in CI (the cmp-bench job in .github/workflows/cmp.yaml; docs/gate.md,
// "Benchmarks"). They use the parity fixtures and the fakes the tests use: no network, no helm, git or kustomize
// process, so what they time is the plugin's own work (parsing, hashing, the cache files, the manifest stamping) and
// not the tools it runs. Run one by hand with: go test -run '^$' -bench . -benchmem ./providers/argocd/cmp

func benchParams() map[string]string {
	return map[string]string{
		"ARGOCD_APP_NAME": "gate-api-prod", "ARGOCD_APP_NAMESPACE": "app-gate-api-prod", "ARGOCD_APP_REVISION": mergeSHA,
		"ARGOCD_APP_SOURCE_REPO_URL": "https://github.com/jfillman/gitops-gate-api.git", "ARGOCD_APP_SOURCE_PATH": ".",
		"CLEARANCE_URL": "http://clearance.test", "CLEARANCE_CHART_REPOS": "https://github.com/jfillman/airframe.git",
		"PARAM_APP": "gate-api", "PARAM_ENV": "prod", "PARAM_CLUSTER": "hangar-prod",
		"PARAM_CHARTREPO": "https://github.com/jfillman/airframe.git", "PARAM_CHARTREVISION": "v0.3.168",
		"PARAM_CHARTPATH": "charts/airframe-application", "PARAM_VALUEFILES": "hangar-prod/base.yaml,hangar-prod/prod/values.yaml",
	}
}

// BenchmarkParseConfig is the plugin's parameters and Argo CD's variables read into a Config.
func BenchmarkParseConfig(b *testing.B) {
	vars := benchParams()
	get := func(k string) string { return vars[k] }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseConfig(get); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCanonical is the repository check that runs before anything is fetched.
func BenchmarkCanonical(b *testing.B) {
	cfg := gateAPIConfig()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := cfg.Canonical(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCanonicalize is the recorded render read, namespaced, hashed per object and into the tree digest.
func BenchmarkCanonicalize(b *testing.B) {
	rendered := read(b, "head.yaml")
	b.SetBytes(int64(len(rendered)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Canonicalize(rendered, "app-gate-api-prod", nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkClearedTreeCacheLookup is Cache.Get on an entry that is there and still within its clearance, the lookup
// every run makes before it asks the core.
func BenchmarkClearedTreeCacheLookup(b *testing.B) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	c := Cache{Dir: b.TempDir()}
	tree := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	c.Put("gate-api", "prod", "hangar-prod", CacheEntry{ID: "ch-abc", Tier: 1, Outage: "allow-and-record", Tree: tree, CachedAt: now, ExpiresAt: now.Add(time.Hour)})
	if _, ok := c.Get("gate-api", "prod", "hangar-prod", tree, now); !ok {
		b.Fatal("the entry is not there")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.Get("gate-api", "prod", "hangar-prod", tree, now); !ok {
			b.Fatal("miss")
		}
	}
}

// benchEnv is cachedEnv with the clock fixed and the stderr log discarded.
func benchEnv(b *testing.B) *env {
	e := cachedEnv(b)
	e.d.Stderr = io.Discard
	return e
}

func generateOnce(b *testing.B, e *env) {
	b.Helper()
	var out bytes.Buffer
	if o, err := Generate(context.Background(), e.d, e.cfg, e.src, &out); err != nil || o != Cleared {
		b.Fatal(o, err)
	}
}

// BenchmarkGenerateWarm is a whole run answered by the pre-render cache: Canonical, the tag lookup, the cache key, the
// cached entry read and the stamped stream written. Nothing is rendered and the core is not asked.
func BenchmarkGenerateWarm(b *testing.B) {
	e := benchEnv(b)
	generateOnce(b, e) // the cold run fills the cache
	if e.exec.count("helm", "") != 1 {
		b.Fatal("the first run did not render")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generateOnce(b, e)
	}
	b.StopTimer()
	if n := e.exec.count("helm", ""); n != 1 {
		b.Fatalf("%d renders: the pre-render cache did not answer", n)
	}
}

// BenchmarkGenerateCold is a whole run that renders: a chart the fake git clone writes (a local fixture, no network),
// the recorded helm output, canonicalisation, the core's answer and the stamped stream. Every iteration starts with
// empty caches, which is set up outside the timer.
func BenchmarkGenerateCold(b *testing.B) {
	e := benchEnv(b)
	root := b.TempDir()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dir := filepath.Join(root, "run")
		os.RemoveAll(dir)
		e.d.Cache = Cache{Dir: filepath.Join(dir, "cache")}
		e.cfg.ChartCache.Dir = filepath.Join(dir, "charts")
		b.StartTimer()
		generateOnce(b, e)
	}
}

// BenchmarkRenderChartParameters is Render alone: the chart from a cold chart cache (the fake clone), the symlink
// check, the value files and helm's output.
func BenchmarkRenderChartParameters(b *testing.B) {
	e := benchEnv(b)
	root := b.TempDir()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		e.cfg.ChartCache.Dir = filepath.Join(root, "charts", time.Now().Format("150405.000000000"))
		b.StartTimer()
		if _, err := Render(context.Background(), e.exec.run, e.cfg, e.src); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRenderSourcesHelm is the generic mode's source resolution for gate-api's two sources: a Helm chart from a
// git path with value files from a $ref source, both fetched by the fake (no network) and rendered by the recorded helm
// output.
func BenchmarkRenderSourcesHelm(b *testing.B) {
	g := &genericRun{t: b, repoOf: map[string]string{}, render: read(b, "head.yaml")}
	cfg := genericConfig(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := RenderSources(context.Background(), g.run, cfg); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGenerateGeneric is the generic mode's whole run through the stamping, with the core's answer cached in
// the cleared-tree cache (the generic mode has no pre-render cache: it renders, then finds the clearance).
func BenchmarkGenerateGeneric(b *testing.B) {
	g := &genericRun{t: b, repoOf: map[string]string{}, render: read(b, "head.yaml")}
	e := newEnv(b)
	e.d.Stderr = io.Discard
	e.d.Run = g.run
	e.cfg = genericConfig(b)
	e.core.answer = &client.Change{ID: "ch-gen", State: "cleared", Tier: 1, Outage: "allow-and-record", ExpiresAt: e.now.Add(time.Hour).Format(time.RFC3339Nano)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		generateOnce(b, e)
	}
}

// BenchmarkRenderKustomizeDir is Render with a kustomize directory beside the chart: the symlink check of the
// directory, then the fake kustomize's output appended to helm's.
func BenchmarkRenderKustomizeDir(b *testing.B) {
	e := benchEnv(b)
	if err := os.MkdirAll(filepath.Join(e.src, "extras"), 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.src, "extras", "kustomization.yaml"), []byte("resources: []\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	e.cfg.KustomizeDir = "extras"
	root := b.TempDir()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		e.cfg.ChartCache.Dir = filepath.Join(root, "charts", time.Now().Format("150405.000000000"))
		b.StartTimer()
		r, err := Render(context.Background(), e.exec.run, e.cfg, e.src)
		if err != nil || !bytes.Contains(r.Manifests, []byte("name: extra")) {
			b.Fatal(err)
		}
	}
}
