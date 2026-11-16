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
