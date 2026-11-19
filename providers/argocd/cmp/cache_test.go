package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
)

const chartSHA2 = "d8f957b2222222222222222222222222222222bb"

// cachedEnv is newEnv with both caches on and a fake clone that writes a chart.
func cachedEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.cfg.ChartCache = ChartCache{Dir: filepath.Join(t.TempDir(), "charts"), MaxBytes: 1 << 30, MaxEntries: 8, Now: func() time.Time { return e.now }}
	e.cfg.RenderCacheTTL = 15 * time.Minute
	e.exec.tree = map[string]string{"charts/airframe-application/Chart.yaml": "name: airframe-application\nversion: 1.0.0\n",
		"charts/airframe-application/templates/a.yaml": "kind: ConfigMap\n"}
	e.core.answer = &client.Change{ID: "ch-abc", State: "cleared", Tier: 1, Outage: "allow-and-record", ExpiresAt: e.now.Add(time.Hour).Format(time.RFC3339Nano)}
	return e
}

func (f *fakeExec) count(name, sub string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c[0] == name && (sub == "" || (len(c) > 1 && c[1] == sub)) {
			n++
		}
	}
	return n
}

func renderOnce(t *testing.T, e *env) *Rendered {
	t.Helper()
	r, err := Render(context.Background(), e.exec.run, e.cfg, e.src)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestChartCacheHitAndMiss(t *testing.T) {
	e := cachedEnv(t)
	for i := 1; i <= 3; i++ {
		if r := renderOnce(t, e); r.ChartMerge != chartSHA {
			t.Fatalf("render %d: commit %s", i, r.ChartMerge)
		}
	}
	// Every render asks the remote what the tag is now; only the first fetches.
	if n := e.exec.count("git", "clone"); n != 1 {
		t.Fatalf("%d clones for 3 renders", n)
	}
	if n := e.exec.count("git", "ls-remote"); n != 3 {
		t.Fatalf("%d ls-remote calls for 3 renders", n)
	}
	// Helm read the chart from the render's own copy, with the .git directory not in it.
	for _, c := range e.exec.calls {
		if c[0] == "helm" && !strings.HasSuffix(c[3], filepath.Join("chart", "charts", "airframe-application")) {
			t.Fatalf("helm chart path %s", c[3])
		}
	}
	ents, _ := os.ReadDir(e.cfg.ChartCache.Dir)
	var dirs []string
	for _, x := range ents {
		if x.IsDir() {
			dirs = append(dirs, x.Name())
		}
		if strings.HasPrefix(x.Name(), ".tmp-") {
			t.Fatalf("a temporary directory is left: %s", x.Name())
		}
	}
	if len(dirs) != 1 {
		t.Fatalf("entries %v", dirs)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.ChartCache.Dir, dirs[0], "tree", ".git")); err == nil {
		t.Fatal("the entry keeps .git")
	}
}

func TestChartCacheIsOffWithoutADirectory(t *testing.T) {
	e := cachedEnv(t)
	e.cfg.ChartCache = ChartCache{}
	renderOnce(t, e)
	renderOnce(t, e)
	if e.exec.count("git", "clone") != 2 || e.exec.count("git", "ls-remote") != 0 {
		t.Fatalf("%v", e.exec.calls)
	}
}

func TestAMovedTagIsRefetched(t *testing.T) {
	e := cachedEnv(t)
	renderOnce(t, e)
	e.exec.head = chartSHA2 // the tag now points at another commit
	if r := renderOnce(t, e); r.ChartMerge != chartSHA2 {
		t.Fatalf("the moved tag was served as %s", r.ChartMerge)
	}
	if n := e.exec.count("git", "clone"); n != 2 {
		t.Fatalf("%d clones", n)
	}
	// Both commits are cached, each under its own key; the old one is a hit again if the tag goes back.
	e.exec.head = chartSHA
	if r := renderOnce(t, e); r.ChartMerge != chartSHA || e.exec.count("git", "clone") != 2 {
		t.Fatalf("%s, %d clones", r.ChartMerge, e.exec.count("git", "clone"))
	}
}

func TestATagThatMovesBetweenTheLookupAndTheCloneIsKeyedByWhatWasCloned(t *testing.T) {
	e := cachedEnv(t)
	e.cfg.chartCommit = chartSHA2 // what the lookup said; the clone below is at chartSHA
	if r := renderOnce(t, e); r.ChartMerge != chartSHA2 {
		// the fake's clone and rev-parse answer head (chartSHA): the recorded commit is the clone's, not the hint
		if r.ChartMerge != chartSHA {
			t.Fatal(r.ChartMerge)
		}
	}
	e.cfg.chartCommit = ""
	if r := renderOnce(t, e); r.ChartMerge != chartSHA || e.exec.count("git", "clone") != 1 {
		t.Fatalf("%s, %d clones", r.ChartMerge, e.exec.count("git", "clone"))
	}
}

func TestConcurrentRendersFetchTheChartOnce(t *testing.T) {
	e := cachedEnv(t)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := Render(context.Background(), e.exec.run, e.cfg, e.src); err != nil || r.ChartMerge != chartSHA {
				t.Errorf("%v %v", r, err)
			}
		}()
	}
	wg.Wait()
	if n := e.exec.count("git", "clone"); n != 1 {
		t.Fatalf("%d clones for 12 concurrent renders", n)
	}
}

func TestACorruptedEntryIsDiscardedAndRefetched(t *testing.T) {
	for name, damage := range map[string]func(dir string){
		"a changed file": func(dir string) {
			os.WriteFile(filepath.Join(dir, "tree", "charts", "airframe-application", "Chart.yaml"), []byte("name: evil\n"), 0o644)
		},
		"an added file": func(dir string) { os.WriteFile(filepath.Join(dir, "tree", "extra.yaml"), []byte("x"), 0o644) },
		"a removed file": func(dir string) {
			os.Remove(filepath.Join(dir, "tree", "charts", "airframe-application", "Chart.yaml"))
		},
		"an added link": func(dir string) { os.Symlink("/etc/passwd", filepath.Join(dir, "tree", "link")) },
		"a broken meta": func(dir string) { os.WriteFile(filepath.Join(dir, "meta.json"), []byte("{"), 0o600) },
		"another commit": func(dir string) {
			os.WriteFile(filepath.Join(dir, "meta.json"), []byte(`{"version":1,"repo":"x","commit":"y","digest":"z"}`), 0o600)
		},
		"a missing tree": func(dir string) { os.RemoveAll(filepath.Join(dir, "tree")) },
	} {
		t.Run(name, func(t *testing.T) {
			e := cachedEnv(t)
			renderOnce(t, e)
			dir := filepath.Join(e.cfg.ChartCache.Dir, e.cfg.ChartCache.key(e.cfg.ChartRepo, chartSHA))
			damage(dir)
			r := renderOnce(t, e)
			if n := e.exec.count("git", "clone"); n != 2 {
				t.Fatalf("%d clones: the damaged entry was trusted", n)
			}
			if r.ChartMerge != chartSHA {
				t.Fatal(r.ChartMerge)
			}
			renderOnce(t, e) // and the refetched entry is good: a hit
			if n := e.exec.count("git", "clone"); n != 2 {
				t.Fatalf("%d clones after the refetch", n)
			}
		})
	}
}

func TestEvictionKeepsTheCacheWithinItsBounds(t *testing.T) {
	e := cachedEnv(t)
	tick := e.now
	e.cfg.ChartCache.Now = func() time.Time { tick = tick.Add(time.Minute); return tick }
	e.cfg.ChartCache.MaxEntries = 2
	shas := []string{"a" + chartSHA[1:], "b" + chartSHA[1:], "c" + chartSHA[1:]}
	for _, s := range shas {
		e.exec.head = s
		renderOnce(t, e)
	}
	exists := func(sha string) bool {
		_, err := os.Stat(filepath.Join(e.cfg.ChartCache.Dir, e.cfg.ChartCache.key(e.cfg.ChartRepo, sha)))
		return err == nil
	}
	if exists(shas[0]) || !exists(shas[1]) || !exists(shas[2]) {
		t.Fatalf("the oldest entry should be the one evicted: %v %v %v", exists(shas[0]), exists(shas[1]), exists(shas[2]))
	}
	// Using b makes c the oldest: the next fetch evicts c, not b.
	e.exec.head = shas[1]
	renderOnce(t, e)
	e.exec.head = shas[0]
	renderOnce(t, e)
	if !exists(shas[1]) || !exists(shas[0]) || exists(shas[2]) {
		t.Fatalf("least recently used order: %v %v %v", exists(shas[0]), exists(shas[1]), exists(shas[2]))
	}
	// A byte bound too: one entry is far more than 10 bytes, so only the entry just fetched stays.
	e.cfg.ChartCache.MaxEntries, e.cfg.ChartCache.MaxBytes = 0, 10
	e.exec.head = shas[2]
	renderOnce(t, e)
	if exists(shas[0]) || exists(shas[1]) || !exists(shas[2]) {
		t.Fatalf("byte bound: %v %v %v", exists(shas[0]), exists(shas[1]), exists(shas[2]))
	}
}

func TestTheSymlinkCheckRunsOnACachedChartToo(t *testing.T) {
	e := cachedEnv(t)
	e.exec.links = map[string]string{"charts/airframe-application/templates/leak.yaml": "/etc/passwd"}
	for i := 0; i < 2; i++ { // the fetch, then the cache hit
		_, err := Render(context.Background(), e.exec.run, e.cfg, e.src)
		if err == nil || !strings.Contains(err.Error(), "refused: the chart") {
			t.Fatalf("render %d: %v", i, err)
		}
	}
	if e.exec.count("helm", "") != 0 {
		t.Fatal("helm ran on a chart with a link out of the repository")
	}
}

// -- the pre-render cache ----------------------------------------------------------------------------------------

func (e *env) gen(t *testing.T) string {
	t.Helper()
	var out bytes.Buffer
	if _, err := Generate(context.Background(), e.d, e.cfg, e.src, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestAnUnchangedAppSkipsGitHelmAndTheCore(t *testing.T) {
	e := cachedEnv(t)
	first := e.gen(t)
	before := len(e.exec.calls)
	second := e.gen(t)
	if second != first || second == "" {
		t.Fatal("the cached stream differs from the rendered one")
	}
	// The one thing a hit does is ask the remote what the tag is.
	got := e.exec.calls[before:]
	if len(got) != 1 || got[0][0] != "git" || got[0][1] != "ls-remote" {
		t.Fatalf("a hit ran %v", got)
	}
	if len(e.core.reqs) != 1 {
		t.Fatalf("%d calls to the core", len(e.core.reqs))
	}
	if !strings.Contains(e.err.String(), "serving the cleared render ch-abc from the cache") {
		t.Fatal(e.err.String())
	}
	if !strings.Contains(second, `"clearance.hangar.io/grant":"ch-abc"`) {
		t.Fatal("the stream is not stamped with the grant")
	}
}

func TestAChangedInputMissesThePreRenderCache(t *testing.T) {
	for name, change := range map[string]func(e *env){
		"the gitops revision": func(e *env) { e.cfg.Revision = "1123456789abcdef0123456789abcdef01234567" },
		"a parameter":         func(e *env) { e.cfg.ValuesJSON = `{"x":1}` },
		"a value file":        func(e *env) { e.cfg.ValueFiles = append(e.cfg.ValueFiles, "more.yaml") },
		"the chart path":      func(e *env) { e.cfg.ChartPath = "charts/other" },
		"the chart commit":    func(e *env) { e.exec.head = chartSHA2 },
		"the environment":     func(e *env) { e.cfg.Env = "stage" },
		"the destination":     func(e *env) { e.cfg.Destination = "elsewhere" },
		"the kube version":    func(e *env) { e.cfg.KubeVersion = "1.99.0" },
		"the api versions":    func(e *env) { e.cfg.APIVersions = []string{"v1", "apps/v1"} },
		"the cluster":         func(e *env) { e.cfg.Cluster = "other-cluster" },
	} {
		t.Run(name, func(t *testing.T) {
			e := cachedEnv(t)
			e.gen(t)
			change(e)
			e.gen(t)
			if n := e.exec.count("helm", ""); n != 2 {
				t.Fatalf("a change of %s was served from the pre-render cache (%d renders)", name, n)
			}
		})
	}
}

func TestAPreRenderEntryExpiresWithTheClearanceAndTheCacheLifetime(t *testing.T) {
	e := cachedEnv(t)
	e.gen(t)
	e.now = e.now.Add(14 * time.Minute) // inside both
	e.gen(t)
	if len(e.core.reqs) != 1 {
		t.Fatal("a hit within the lifetime went to the core")
	}
	e.now = e.now.Add(2 * time.Minute) // 16 minutes: past the cache lifetime, not the clearance
	e.gen(t)
	if len(e.core.reqs) != 2 {
		t.Fatal("served past the cache lifetime")
	}
	// The clearance's own expiry bounds it, whatever the lifetime.
	e = cachedEnv(t)
	e.cfg.RenderCacheTTL = 24 * time.Hour
	e.core.answer.ExpiresAt = e.now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	e.gen(t)
	e.now = e.now.Add(6 * time.Minute)
	e.gen(t)
	if len(e.core.reqs) != 2 {
		t.Fatal("served after the clearance expired")
	}
}

func TestAHoldOrADenialIsNeverCachedAndDropsAnEarlierEntry(t *testing.T) {
	for _, state := range []string{"holding", "denied"} {
		t.Run(state, func(t *testing.T) {
			e := cachedEnv(t)
			reason := "no"
			e.core.answer = &client.Change{ID: "ch-x", State: state, Tier: 2, DenyReason: &reason}
			for i := 0; i < 3; i++ {
				var out bytes.Buffer
				Generate(context.Background(), e.d, e.cfg, e.src, &out)
			}
			if len(e.core.reqs) != 3 {
				t.Fatalf("%d calls to the core for 3 renders: a %s was served from the cache", len(e.core.reqs), state)
			}
			if ents, _ := os.ReadDir(filepath.Join(e.d.Cache.Dir, "renders")); len(ents) != 0 {
				t.Fatalf("%s left %d entries", state, len(ents))
			}
			// An entry from an earlier clearance of the same inputs does not outlive a hold the core then reports.
			e.core.answer = &client.Change{ID: "ch-abc", State: "cleared", Tier: 1, ExpiresAt: e.now.Add(time.Hour).Format(time.RFC3339Nano)}
			e.gen(t)
			e.core.answer = &client.Change{ID: "ch-y", State: state, Tier: 2, DenyReason: &reason}
			var out bytes.Buffer
			e.cfg.RenderCacheTTL = time.Minute
			e.now = e.now.Add(2 * time.Minute) // the entry's lifetime is over, so the core is asked and says no
			Generate(context.Background(), e.d, e.cfg, e.src, &out)
			e.now = e.now.Add(-2 * time.Minute)
			n := len(e.core.reqs)
			Generate(context.Background(), e.d, e.cfg, e.src, &out)
			if len(e.core.reqs) != n+1 {
				t.Fatal("a cleared entry was served after the core said " + state)
			}
		})
	}
}

func TestGenericModeAndANonCommitRevisionAreNotPreRenderCached(t *testing.T) {
	e := cachedEnv(t)
	e.cfg.Revision = "main"
	e.cfg.ChartRepo = "https://github.com/jfillman/airframe.git"
	e.core.answer.ID = "ch-abc"
	var out bytes.Buffer
	// registration refuses a non-commit revision, which is enough: nothing may have been stored.
	Generate(context.Background(), e.d, e.cfg, e.src, &out)
	if ents, _ := os.ReadDir(filepath.Join(e.d.Cache.Dir, "renders")); len(ents) != 0 {
		t.Fatal("a branch name was a cache key")
	}
	cfg := e.cfg
	cfg.Revision, cfg.Sources = mergeSHA, "[]"
	if renderKey(cfg) != "" {
		t.Fatal("generic mode has a key")
	}
	cfg.Sources, cfg.chartCommit = "", ""
	if renderKey(cfg) != "" {
		t.Fatal("an unresolved chart tag has a key")
	}
}

func TestACorruptPreRenderEntryIsDiscarded(t *testing.T) {
	e := cachedEnv(t)
	e.gen(t)
	cfg := e.cfg
	cfg.chartCommit = chartSHA
	p := e.d.Cache.renderPath(renderKey(cfg))
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var ent renderEntry
	if err := json.Unmarshal(b, &ent); err != nil {
		t.Fatal(err)
	}
	ent.Stream = bytes.Replace(ent.Stream, []byte("ch-abc"), []byte("ch-evl"), -1) // the stream changes, its recorded sum does not
	b, _ = json.Marshal(ent)
	os.WriteFile(p, b, 0o600)
	e.gen(t)
	if e.exec.count("helm", "") != 2 {
		t.Fatal("a tampered entry was served")
	}
}

func BenchmarkRender(b *testing.B) {
	for _, mode := range []string{"cold", "chart-cached", "unchanged"} {
		b.Run(mode, func(b *testing.B) {
			dir := b.TempDir()
			now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
			ex := &fakeExec{render: mustRead(b, "head.yaml"), tree: map[string]string{"charts/airframe-application/Chart.yaml": strings.Repeat("name: x\n", 2000)}}
			core := &fakeCore{answer: &client.Change{ID: "ch-abc", State: "cleared", Tier: 1, ExpiresAt: now.Add(1000 * time.Hour).Format(time.RFC3339Nano)}}
			cfg := gateAPIConfig()
			cfg.ValuesJSON = string(mustRead(b, "injected.json"))
			cfg.ChartCache = ChartCache{Dir: filepath.Join(dir, "charts"), MaxBytes: 1 << 30, MaxEntries: 8}
			cfg.RenderCacheTTL = 1000 * time.Hour
			cfg.CacheTTL = 0 // the tree cache is not what is measured
			d := Deps{Exec: ex.run, Core: core, Cache: Cache{Dir: dir}, Now: func() time.Time { return now }, Stderr: new(bytes.Buffer)}
			src := b.TempDir()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				switch mode {
				case "cold":
					os.RemoveAll(dir)
				case "chart-cached":
					os.RemoveAll(filepath.Join(dir, "renders"))
				}
				if _, err := Generate(context.Background(), d, cfg, src, new(bytes.Buffer)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func mustRead(b *testing.B, p string) []byte {
	b.Helper()
	v, err := os.ReadFile(filepath.Join(parity, p))
	if err != nil {
		b.Fatal(err)
	}
	return v
}

func TestCacheSettings(t *testing.T) {
	vars := map[string]string{"ARGOCD_APP_NAME": "a", "ARGOCD_APP_NAMESPACE": "n", "PARAM_APP": "a", "PARAM_ENV": "e", "PARAM_CLUSTER": "c", "CLEARANCE_URL": "http://x.test"}
	parse := func(extra map[string]string) (Config, error) {
		return ParseConfig(func(k string) string {
			if v, ok := extra[k]; ok {
				return v
			}
			return vars[k]
		})
	}
	c, err := parse(nil)
	if err != nil || c.RenderCacheTTL != 15*time.Minute || c.ChartCache.MaxBytes != 512<<20 || c.ChartCache.MaxEntries != 32 ||
		c.ChartCache.Dir != "/tmp/clearance-cmp-cache/charts" {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	if c, err = parse(map[string]string{"CLEARANCE_CMP_CHART_CACHE_MAX_BYTES": "0"}); err != nil || c.ChartCache.enabled() {
		t.Fatalf("0 turns the chart cache off: %+v %v", c.ChartCache, err)
	}
	for _, bad := range []map[string]string{{"CLEARANCE_CMP_CHART_CACHE_MAX_ENTRIES": "-1"}, {"CLEARANCE_CMP_CHART_CACHE_MAX_BYTES": "lots"}, {"CLEARANCE_CMP_RENDER_CACHE_TTL": "0s"}} {
		if _, err := parse(bad); err == nil {
			t.Fatalf("%v was accepted", bad)
		}
	}
}
