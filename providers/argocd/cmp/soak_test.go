package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSoakGenerateInProcess is the in-process half of the soak (W-34 F7; the cmp-soak CI job): CLEARANCE_CMP_SOAK=N
// runs Generate N times in one process over a fixed set of inputs (three chart commits, four sets of injected values),
// against a two-entry chart cache. A plugin run is its own process, so a leak there dies with it; this catches what one
// run leaks into the process (goroutines, open files) and what every run leaves on the volume (scratch directories,
// cache entries past their bounds), which a short unit test cannot see. Without CLEARANCE_CMP_SOAK it is skipped.
func TestSoakGenerateInProcess(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("CLEARANCE_CMP_SOAK"))
	if n <= 0 {
		t.Skip("CLEARANCE_CMP_SOAK is not set (the cmp-soak CI job sets it)")
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp) // every scratch directory a render makes goes here, and must be gone after it
	e := replicaEnv(t)
	e.cfg.ChartCache.MaxEntries = 2
	heads := []string{"a" + chartSHA[1:], "b" + chartSHA[1:], "c" + chartSHA[1:]}
	want := map[string]string{}
	baseG, baseFD := -1, -1
	var midSize int64
	for i := 0; i < n; i++ {
		e.exec.mu.Lock()
		e.exec.head = heads[i%len(heads)]
		e.exec.mu.Unlock()
		e.cfg.ValuesJSON = fmt.Sprintf(`{"soak":%d}`, i%4)
		key := e.exec.head + e.cfg.ValuesJSON
		e.err.Reset()
		out := e.gen(t)
		if w, ok := want[key]; !ok {
			want[key] = out
		} else if out != w {
			t.Fatalf("run %d: the same inputs emitted something else than before", i)
		}
		if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
			t.Fatalf("run %d left %d entries in TMPDIR, the first %s", i, len(ents), ents[0].Name())
		}
		if i == 2*len(want) && baseG < 0 { // every input seen at least once: the steady state
			runtime.GC()
			baseG, baseFD = runtime.NumGoroutine(), openFDs()
		}
		if i == n/2 {
			midSize = dirBytes(t, e.cfg.CacheDir)
		}
	}
	if baseG < 0 {
		t.Fatalf("CLEARANCE_CMP_SOAK=%d is too few runs to reach a steady state", n)
	}
	time.Sleep(50 * time.Millisecond) // let a goroutine that is finishing finish
	runtime.GC()
	if g := runtime.NumGoroutine(); g > baseG+2 {
		t.Errorf("goroutines grew from %d to %d over %d runs", baseG, g, n)
	}
	if fd := openFDs(); baseFD >= 0 && fd > baseFD+2 {
		t.Errorf("open files grew from %d to %d over %d runs", baseFD, fd, n)
	}
	if ents, _ := os.ReadDir(e.cfg.ChartCache.Dir); countEntries(ents) > e.cfg.ChartCache.MaxEntries {
		t.Errorf("%d chart cache entries, bound %d", countEntries(ents), e.cfg.ChartCache.MaxEntries)
	}
	if ents, _ := os.ReadDir(filepath.Join(e.cfg.CacheDir, "renders")); countJSON(ents) > len(want) {
		t.Errorf("%d pre-render entries for %d distinct renders", countJSON(ents), len(want))
	}
	if end := dirBytes(t, e.cfg.CacheDir); end > midSize+16<<10 {
		t.Errorf("the cache directory grew from %d to %d bytes in the second half, over inputs it had all seen", midSize, end)
	}
	t.Logf("%d runs, %d distinct renders, %d goroutines, %d open files, cache %d bytes", n, len(want), runtime.NumGoroutine(), openFDs(), dirBytes(t, e.cfg.CacheDir))
}

// openFDs is the number of this process's open file descriptors, or -1 where /proc is not there.
func openFDs() int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(ents)
}

func countEntries(ents []os.DirEntry) int {
	n := 0
	for _, x := range ents {
		if x.IsDir() && len(x.Name()) == 64 {
			n++
		}
	}
	return n
}

func dirBytes(t *testing.T, dir string) int64 {
	t.Helper()
	var n int64
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && !strings.HasPrefix(info.Name(), "lock-") {
			n += info.Size()
		}
		return nil
	})
	return n
}
