package api

// A memory harness for the coverage read, not a regression test: it runs only with CLEARANCE_MEM_HARNESS=1
// (go test ./internal/api -run TestCoverageMemoryHarness -v). It drives the handler in a loop against the in-memory
// store with records sized like a real chain's, under a 400 MiB soft limit, with a share of requests cancelled
// part-way, and prints the Go runtime's own memory counters. It says nothing about pgx or Postgres.

import (
	"context"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/observe"
)

func covMemWorld(scopes, obs, health, assess, stateBytes int) world {
	c := &rawChain{}
	blob := strings.Repeat("x", stateBytes)
	for s := 0; s < scopes; s++ {
		scope := fmt.Sprintf("aws:%03d", s)
		for i := 0; i < health; i++ {
			c.health(covNow.Add(-time.Duration(i+1)*20*time.Second), scope, []string{"cloudtrail", "config"}[i%2], "fake-trail", "healthy", false)
		}
		for i := 0; i < obs; i++ {
			c.add(covNow.Add(-time.Duration(i+1)*3*time.Minute), "observation", scope, map[string]any{
				"source": map[string]any{"name": "cloudtrail", "event_id": fmt.Sprint(s, "-", i)}, "provider": map[string]any{"name": "fake-trail"},
				"action":       map[string]any{"verb": "create", "api": "RunInstances", "succeeded": true},
				"integrity":    map[string]any{"sourceVerified": true},
				"state_change": map[string]any{"before": nil, "after": map[string]any{"blob": blob}}})
		}
		for i := 0; i < assess; i++ {
			c.add(covNow.Add(-time.Duration(i+1)*time.Minute), "assessment", scope, map[string]any{
				"about": map[string]any{"seq": 1}, "coverage": "authorized-and-verified", "tier": 1})
		}
	}
	return world{raw: c.rows}
}

func TestCoverageMemoryHarness(t *testing.T) {
	if os.Getenv("CLEARANCE_MEM_HARNESS") != "1" {
		t.Skip("set CLEARANCE_MEM_HARNESS=1")
	}
	cancelPct := 0
	fmt.Sscan(os.Getenv("CLEARANCE_MEM_CANCEL_PCT"), &cancelPct)
	total := 3000
	fmt.Sscan(os.Getenv("CLEARANCE_MEM_REQUESTS"), &total)
	total = max(total, 1)
	every := max(total/4, 1)
	debug.SetMemoryLimit(400 << 20)
	h, _ := covSpied(t, covMemWorld(3, 450, 3000, 1500, 3000), nil, func(o *Options) { o.CoverageConcurrency = 2; o.CoverageWait = 3 * time.Second })
	paths := []string{"/v1/coverage?scope=aws:000", "/v1/coverage?scope=aws:001", "/v1/coverage?scope=aws:002", "/v1/coverage", "/v1/coverage?names=only"}
	var mu sync.Mutex
	done, codes := 0, map[int]int{}
	report := func(tag string) {
		runtime.GC() // live heap after a collection: the leak signal
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		fmt.Printf("%-6s req=%5d HeapAlloc(after GC)=%3dMiB HeapInuse=%3dMiB HeapIdle=%3dMiB HeapReleased=%3dMiB Sys=%3dMiB NumGC=%4d goroutines=%d\n",
			tag, done, m.HeapAlloc>>20, m.HeapInuse>>20, m.HeapIdle>>20, m.HeapReleased>>20, m.Sys>>20, m.NumGC, runtime.NumGoroutine())
	}
	report("start")
	var wg sync.WaitGroup
	next := make(chan int, total)
	for i := 0; i < total; i++ {
		next <- i
	}
	close(next)
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(w)))
			for range next {
				ctx, cancel := context.WithCancel(bg)
				if rng.Intn(100) < cancelPct {
					time.AfterFunc(time.Duration(rng.Intn(4000))*time.Microsecond, cancel)
				}
				req := httptest.NewRequest("GET", paths[rng.Intn(len(paths))], nil).WithContext(ctx)
				req.Header.Set("Authorization", "Bearer audit")
				rec := httptest.NewRecorder()
				h.srv.Handler().ServeHTTP(rec, req)
				cancel()
				mu.Lock()
				done++
				codes[rec.Code]++
				d := done
				mu.Unlock()
				if d%every == 0 {
					mu.Lock()
					report("mid")
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	report("end")
	fmt.Println("status codes:", codes)
}

// What a slim stored record costs once parsed (records()/parseStored: canon.Parse into map[string]any): the live bytes
// per record of about 535 bytes of JSON, which a statement holds up to MaxCoverageRecords (10000) of per kind.
func TestCoverageParsedRecordCost(t *testing.T) {
	if os.Getenv("CLEARANCE_MEM_HARNESS") != "1" {
		t.Skip("set CLEARANCE_MEM_HARNESS=1")
	}
	text := `{"seq":123456,"hash":"` + strings.Repeat("a", 64) + `","prev_hash":"` + strings.Repeat("b", 64) + `","ts":"2026-11-16T08:00:00.123456Z","tool":"observation","scope":"aws:000",` +
		`"source":{"name":"cloudtrail","event_id":"` + strings.Repeat("e", 36) + `"},"provider":{"name":"observe-aws","version":"0.1.0"},` +
		`"resource":{"kind":"Instance","id":"i-0abc123"},"actor":{"subject":"arn:aws:sts::000000000000:assumed-role/deployer/run-1"},` +
		`"action":{"verb":"create","api":"RunInstances","succeeded":true},"integrity":{"sourceVerified":true,"completenessClaimed":true},"times":{"observed":"2026-11-16T08:00:00Z"}}`
	t.Logf("record JSON bytes: %d", len(text))
	runtime.GC()
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	keep := make([]Record, 0, 10000)
	for i := 0; i < 10000; i++ {
		r, err := parseStored(text, "recorded-not-checkpointed")
		if err != nil {
			t.Fatal(err)
		}
		keep = append(keep, r)
	}
	runtime.GC()
	runtime.ReadMemStats(&b)
	fmt.Printf("parsed %d records of %d JSON bytes: live %.1f MiB (%d bytes each, %.1fx the text)\n", len(keep), len(text),
		float64(b.HeapAlloc-a.HeapAlloc)/(1<<20), (b.HeapAlloc-a.HeapAlloc)/uint64(len(keep)), float64((b.HeapAlloc-a.HeapAlloc)/uint64(len(keep)))/float64(len(text)))
	runtime.KeepAlive(keep)
}

// coverageBuildRecords is what a coverage statement holds before observe.Build runs: n parsed records of each of the
// six kinds, as collect keeps them (state_change and correlation are already gone: the store drops them). project says
// whether collect slimmed each one (observe.Project) as it arrived.
func coverageBuildRecords(n int, project bool) [][]Record {
	pre := `{"seq":123456,"hash":"` + strings.Repeat("a", 64) + `","prev_hash":"` + strings.Repeat("b", 64) + `","ts":"2026-11-16T08:00:00.123456Z","scope":"aws:000",` +
		`"provider":{"name":"observe-aws","version":"0.1.0"},"actor":{"subject":"arn:aws:sts::000000000000:assumed-role/deployer/run-1"},`
	about := `"about":{"seq":1,"hash":"` + strings.Repeat("c", 64) + `"},"rule_set":{"name":"default","version":"2026-11-01"}`
	texts := []string{
		pre + `"tool":"observation","source":{"name":"cloudtrail","event_id":"` + strings.Repeat("e", 36) + `"},` +
			`"resource":{"kind":"Instance","id":"i-0abc123"},"action":{"verb":"create","api":"RunInstances","succeeded":true},` +
			`"integrity":{"sourceVerified":true,"completenessClaimed":true},"times":{"observed":"2026-11-16T08:00:00Z"},"tier":3}`,
		pre + `"tool":"observation.assessment",` + about + `,"coverage":"authorized-and-verified","tier":1,"attribution":{"signal":"role-session","matched":"run-1"}}`,
		pre + `"tool":"observation.resolution",` + about + `,"resolution":{"state":"accepted","cause":"known","by":"alice"}}`,
		pre + `"tool":"observation.verification",` + about + `,"source":{"name":"cloudtrail"},"verification":{"method":"digest","ok":true}}`,
		pre + `"tool":"observation.health","source":{"name":"cloudtrail"},"health":{"state":"healthy","interval_seconds":300,` +
			`"checks":[{"name":"trail-enabled","ok":true,"detail":"ok"},{"name":"config-recorder","ok":true,"detail":"ok"}]}}`,
		pre + `"tool":"observation.audit-gap","source":{"name":"cloudtrail"},"gap":{"state":"open","reason":"lost","detail":"digest missing"}}`,
	}
	kinds := make([][]Record, 0, len(texts))
	for _, text := range texts {
		rs := make([]Record, 0, n)
		for i := 0; i < n; i++ {
			r, err := parseStored(text, "recorded-not-checkpointed")
			if err != nil {
				panic(err)
			}
			if project {
				r = observe.Project(r)
			}
			rs = append(rs, r)
		}
		kinds = append(kinds, rs)
	}
	return kinds
}

func heapAfterGC() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// The live heap a statement holds at its peak, before and after collect projects each record (the numbers in the PR for
// I-27): 6 kinds of MaxCoverageRecords each.
func TestCoverageBuildHeldHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates tens of MiB")
	}
	measure := func(project bool) uint64 {
		base := heapAfterGC()
		keep := coverageBuildRecords(MaxCoverageRecords, project)
		held := heapAfterGC() - base
		runtime.KeepAlive(keep)
		return held
	}
	full, slim := measure(false), measure(true)
	t.Logf("held by one statement (6 kinds x %d records): full parse %.1f MiB, projected %.1f MiB (%.1fx smaller)",
		MaxCoverageRecords, float64(full)/(1<<20), float64(slim)/(1<<20), float64(full)/float64(slim))
	if slim >= full {
		t.Errorf("projection should shrink what a statement holds: full %d, projected %d", full, slim)
	}
}

func benchBuild(b *testing.B, project bool) {
	b.ReportAllocs()
	var peak uint64
	for i := 0; i < b.N; i++ {
		base := heapAfterGC()
		keep := coverageBuildRecords(MaxCoverageRecords, project)
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		if m.HeapAlloc-base > peak {
			peak = m.HeapAlloc - base
		}
		runtime.KeepAlive(keep)
	}
	b.ReportMetric(float64(peak)/(1<<20), "heap-before-gc-MiB")
}

func BenchmarkCoverageBuildFullParse(b *testing.B) { benchBuild(b, false) }
func BenchmarkCoverageBuildProjected(b *testing.B) { benchBuild(b, true) }
