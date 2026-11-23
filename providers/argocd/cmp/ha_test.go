package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
)

// Repo-server high availability (W-34 F9; docs/install-argocd-plugin.md, "More than one repo-server"). Every cache the
// plugin keeps lives on its own pod's volume: a second replica, or a replica after its pod was replaced, starts cold.
// These tests hold that a cold replica emits exactly what a warm one does and only does more work to get there, that a
// replica's leftovers from a crash are not a problem, and that renders sharing one cache directory at once (the
// cmp-server starts one process per request) are safe under the caches' locks.

// replicaEnv is cachedEnv laid out as the sidecar lays out its volume: every cache under one CLEARANCE_CMP_CACHE_DIR.
func replicaEnv(t *testing.T) *env {
	t.Helper()
	e := cachedEnv(t)
	dir := t.TempDir()
	e.cfg.CacheDir = dir
	e.d.Cache = Cache{Dir: dir}
	e.cfg.ChartCache.Dir = filepath.Join(dir, "charts")
	return e
}

func TestASecondReplicaWithAColdCacheEmitsTheSameManifests(t *testing.T) {
	a, b := replicaEnv(t), replicaEnv(t)
	first := a.gen(t)
	if a.gen(t) != first {
		t.Fatal("replica a: the warm render differs from the cold one")
	}
	if n := a.exec.count("git", "clone"); n != 1 {
		t.Fatalf("replica a cloned %d times for one chart commit", n)
	}
	if n := a.exec.count("helm", ""); n != 1 {
		t.Fatalf("replica a ran helm %d times: its second render should be a pre-render hit", n)
	}

	// Replica b has never seen this Application: the same bytes, after its own clone, render and call to the core.
	if got := b.gen(t); got != first {
		t.Fatalf("a cold replica emitted something else:\n%s\nwant\n%s", got, first)
	}
	if b.exec.count("git", "clone") != 1 || b.exec.count("helm", "") != 1 || len(b.core.reqs) != 1 {
		t.Fatalf("replica b: %d clones, %d helm runs, %d core calls; a cold replica does the whole render once",
			b.exec.count("git", "clone"), b.exec.count("helm", ""), len(b.core.reqs))
	}
	if !strings.Contains(b.err.String(), "chart-cache=miss") {
		t.Fatalf("replica b did not report a chart cache miss: %s", b.err.String())
	}
	if b.gen(t) != first || b.exec.count("helm", "") != 1 {
		t.Fatal("replica b's own cache did not answer its second render")
	}

	// Replica a's pod is replaced: its emptyDir is gone, and it starts as cold as b did.
	if err := os.RemoveAll(a.cfg.CacheDir); err != nil {
		t.Fatal(err)
	}
	if got := a.gen(t); got != first {
		t.Fatal("replica a after a restart emitted something else")
	}
	if n := a.exec.count("git", "clone"); n != 2 {
		t.Fatalf("replica a after a restart: %d clones in all, want 2", n)
	}
}

func TestAReplicaRestartedMidWriteEmitsTheSameManifests(t *testing.T) {
	a := replicaEnv(t)
	first := a.gen(t)
	// What a container killed mid-write could leave on the emptyDir, which outlives the container (not the pod):
	// temporary files of every cache, a stale lock file, and torn copies of the entries themselves.
	old := time.Now().Add(-2 * time.Hour)
	for _, p := range []string{
		filepath.Join(a.cfg.CacheDir, ".entry-1"), filepath.Join(a.cfg.CacheDir, "renders", ".entry-2"),
		filepath.Join(a.cfg.ChartCache.Dir, ".tmp-3", "tree", "Chart.yaml"), filepath.Join(a.cfg.CacheDir, "slots", "slot-0"),
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(`{"half`), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(p, old, old)
		os.Chtimes(filepath.Dir(p), old, old)
	}
	tornAll := func(dir string) {
		ents, _ := os.ReadDir(dir)
		for _, x := range ents {
			if strings.HasSuffix(x.Name(), ".json") {
				p := filepath.Join(dir, x.Name())
				b, _ := os.ReadFile(p)
				os.WriteFile(p, b[:len(b)/2], 0o600)
			}
		}
	}
	tornAll(a.cfg.CacheDir)
	tornAll(filepath.Join(a.cfg.CacheDir, "renders"))
	ents, _ := os.ReadDir(a.cfg.ChartCache.Dir)
	for _, x := range ents {
		if len(x.Name()) == 64 { // an entry: change one file of its tree, as a torn copy would
			filepath.Walk(filepath.Join(a.cfg.ChartCache.Dir, x.Name(), "tree"), func(p string, info os.FileInfo, err error) error {
				if err == nil && info.Name() == "Chart.yaml" {
					os.WriteFile(p, []byte("name: tampered\n"), 0o644)
				}
				return nil
			})
		}
	}
	if got := a.gen(t); got != first {
		t.Fatalf("after a crash the replica emitted something else:\n%s", got)
	}
	if n := a.exec.count("git", "clone"); n != 2 {
		t.Fatalf("%d clones: the torn chart entry must be discarded and fetched again", n)
	}
	if a.gen(t) != first {
		t.Fatal("the cache rebuilt after the crash does not answer")
	}
}

// lockedCore is fakeCore for concurrent renders.
type lockedCore struct {
	mu sync.Mutex
	c  *fakeCore
}

func (l *lockedCore) RegisterChange(ctx context.Context, r *client.ChangeRequest) (*client.Change, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.c.RegisterChange(ctx, r)
}

func TestConcurrentRendersSharingOneCacheDirectoryAreSafe(t *testing.T) {
	variants := []string{`{"v":1}`, `{"v":2}`, `{"v":3}`}
	// What each variant renders to on its own, sequentially, with nothing cached.
	want := map[string]string{}
	for _, v := range variants {
		ref := replicaEnv(t)
		ref.cfg.ValuesJSON = v
		want[v] = ref.gen(t)
	}
	shared := replicaEnv(t)
	core := &lockedCore{c: shared.core}
	run := func(wave int) {
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				cfg := shared.cfg
				cfg.ValuesJSON = variants[i%len(variants)]
				var stderr, out bytes.Buffer
				d := shared.d
				d.Core, d.Stderr = core, &stderr
				if _, err := Generate(context.Background(), d, cfg, shared.src, &out); err != nil {
					t.Errorf("wave %d render %d: %v\n%s", wave, i, err, stderr.String())
					return
				}
				if out.String() != want[cfg.ValuesJSON] {
					t.Errorf("wave %d render %d (%s) emitted something else than the same render alone", wave, i, cfg.ValuesJSON)
				}
			}(i)
		}
		wg.Wait()
	}
	run(1)
	if n := shared.exec.count("git", "clone"); n != 1 {
		t.Fatalf("%d clones of one chart commit by 24 concurrent renders: the chart cache's lock lets one fetch it", n)
	}
	helm := shared.exec.count("helm", "")
	run(2) // everything is cached now: no render runs helm again
	if n := shared.exec.count("helm", ""); n != helm {
		t.Fatalf("the second wave ran helm %d more times: its renders should all be pre-render hits", n-helm)
	}
	for _, dir := range []string{shared.cfg.CacheDir, filepath.Join(shared.cfg.CacheDir, "renders"), shared.cfg.ChartCache.Dir} {
		ents, _ := os.ReadDir(dir)
		for _, x := range ents {
			if strings.HasPrefix(x.Name(), ".entry-") || strings.HasPrefix(x.Name(), ".tmp-") || strings.HasPrefix(x.Name(), ".trash-") {
				t.Errorf("a temporary file was left behind: %s", filepath.Join(dir, x.Name()))
			}
		}
	}
	if ents, _ := os.ReadDir(filepath.Join(shared.cfg.CacheDir, "renders")); countJSON(ents) != len(variants) {
		t.Fatalf("%d pre-render entries for %d distinct renders", countJSON(ents), len(variants))
	}
}

func countJSON(ents []os.DirEntry) int {
	n := 0
	for _, x := range ents {
		if strings.HasSuffix(x.Name(), ".json") {
			n++
		}
	}
	return n
}

func TestTheTreeCacheIsBounded(t *testing.T) {
	c := Cache{Dir: t.TempDir()}
	base := time.Now().Add(-time.Hour)
	var paths []string
	for i := 0; i < 8; i++ {
		tree := fmt.Sprintf("%064x", i)
		c.Put("app", "dev", "c1", CacheEntry{ID: "ch", Tree: tree, ExpiresAt: time.Now().Add(time.Hour)})
		p := c.path("app", "dev", "c1", tree)
		at := base.Add(time.Duration(i) * time.Minute)
		os.Chtimes(p, at, at)
		paths = append(paths, p)
	}
	// Another cache's directory and files beside the entries are not the tree cache's to prune.
	os.MkdirAll(filepath.Join(c.Dir, "renders"), 0o700)
	os.WriteFile(filepath.Join(c.Dir, "renders", "x.json"), []byte("{}"), 0o600)
	stale, fresh := filepath.Join(c.Dir, ".entry-stale"), filepath.Join(c.Dir, ".entry-fresh")
	os.WriteFile(stale, nil, 0o600)
	os.WriteFile(fresh, nil, 0o600)
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(stale, old, old)

	c.pruneTrees(5)
	for i, p := range paths {
		_, err := os.Stat(p)
		if kept := err == nil; kept != (i >= 3) {
			t.Errorf("entry %d (age rank %d): kept=%v, want the five newest kept", i, len(paths)-i, kept)
		}
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "renders", "x.json")); err != nil {
		t.Error("pruning the tree cache touched the pre-render cache")
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("an interrupted Put's temporary file older than an hour was left")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a temporary file of a Put that may still be running was removed")
	}
}

func TestPutPrunesTheTreeCacheAtItsBound(t *testing.T) {
	c := Cache{Dir: t.TempDir()}
	// A full cache, written directly: treeCacheMaxEntries entries, the first the oldest.
	base := time.Now().Add(-2 * time.Hour)
	oldest := ""
	for i := 0; i < treeCacheMaxEntries; i++ {
		p := c.path("app", "dev", "c1", fmt.Sprintf("%064x", i))
		if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		at := base.Add(time.Duration(i) * time.Millisecond)
		os.Chtimes(p, at, at)
		if i == 0 {
			oldest = p
		}
	}
	tree := fmt.Sprintf("%064x", treeCacheMaxEntries+1)
	c.Put("app", "dev", "c1", CacheEntry{ID: "ch", Tree: tree, ExpiresAt: time.Now().Add(time.Hour)})
	ents, _ := os.ReadDir(c.Dir)
	if n := countJSON(ents); n != treeCacheMaxEntries {
		t.Fatalf("%d tree entries after a Put into a full cache, want %d", n, treeCacheMaxEntries)
	}
	if _, err := os.Stat(oldest); err == nil {
		t.Fatal("the oldest entry was kept")
	}
	if _, ok := c.Get("app", "dev", "c1", tree, time.Now()); !ok {
		t.Fatal("the new entry was not kept")
	}
}

func TestAKilledRunsScratchIsSweptByTheNextRender(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	old := time.Now().Add(-time.Hour)
	mk := func(name string, stale bool) string {
		p := filepath.Join(tmp, name)
		if err := os.MkdirAll(filepath.Join(p, "chart"), 0o700); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(p, "chart", "Chart.yaml"), []byte("name: x\n"), 0o600)
		if stale {
			os.Chtimes(p, old, old)
		}
		return p
	}
	// What a run killed with SIGKILL leaves: its scratch, never removed. The volume outlives the container.
	killedRender, killedLookup := mk("clearance-render-111", true), mk("clearance-lookup-222", true)
	live, other := mk("clearance-render-333", false), mk("someone-else", true)
	cfg := Config{CacheDir: t.TempDir()}
	var stderr bytes.Buffer
	if _, err := renderBounded(context.Background(), cfg, t.TempDir(), &stderr, func(ctx context.Context) (*Rendered, error) {
		return &Rendered{Manifests: []byte("{}")}, nil
	}); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{killedRender: false, killedLookup: false, live: true, other: true} {
		if _, err := os.Stat(p); (err == nil) != want {
			t.Errorf("%s: present=%v, want %v", filepath.Base(p), err == nil, want)
		}
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 2 {
		t.Errorf("the render's own scratch was not removed: %v", ents)
	}
}
