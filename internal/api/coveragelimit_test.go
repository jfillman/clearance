package api

// The coverage read's resource bounds: records read without the objects a statement never uses, work that ends when
// the request does, a bound on computations in flight that refuses rather than queues, and an opt-in short cache.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/observe"
)

var covNow = t0.Add(72 * time.Hour)

// covWorld is nScopes scopes, each with perScope observations in the last day, every one carrying a state_change
// of stateBytes, and a healthy feed.
func covWorld(nScopes, perScope, stateBytes int) world {
	c := &rawChain{}
	blob := strings.Repeat("x", stateBytes)
	for s := 0; s < nScopes; s++ {
		scope := fmt.Sprintf("aws:%03d", s)
		c.health(covNow.Add(-23*time.Hour), scope, "cloudtrail", "fake-trail", "healthy", false)
		for i := 0; i < perScope; i++ {
			c.add(covNow.Add(-time.Duration(i+1)*time.Minute), "observation", scope, map[string]any{
				"source": map[string]any{"name": "cloudtrail", "event_id": fmt.Sprint(s, "-", i)}, "provider": map[string]any{"name": "fake-trail"},
				"action":       map[string]any{"verb": "create", "api": "RunInstances", "succeeded": true},
				"integrity":    map[string]any{"sourceVerified": true},
				"state_change": map[string]any{"before": nil, "after": map[string]any{"blob": blob}},
				"correlation":  map[string]any{"ids": []any{blob[:stateBytes/4]}}})
		}
		c.health(covNow.Add(-time.Minute), scope, "cloudtrail", "fake-trail", "healthy", false)
	}
	return world{raw: c.rows}
}

func atCovNow(o *Options) { o.Clock = func() time.Time { return covNow } }

// covSpy counts evidence reads, sums the size of what they return, and can hold them.
type covSpy struct {
	Store
	calls, inflight, peak atomic.Int64
	bytes                 atomic.Int64
	release               chan struct{} // non-nil: Evidence waits for it (or its context)
	started               chan struct{} // non-nil: one send per Evidence call that starts
	afterCall             func(n int64) // runs after call n returns
}

func (s *covSpy) Evidence(ctx context.Context, f EvidenceFilter, v *Viewer, limit int, after *int64) ([]Record, error) {
	n := s.calls.Add(1)
	cur := s.inflight.Add(1)
	defer s.inflight.Add(-1)
	for {
		p := s.peak.Load()
		if cur <= p || s.peak.CompareAndSwap(p, cur) {
			break
		}
	}
	if s.started != nil {
		select {
		case s.started <- struct{}{}:
		default:
		}
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	rs, err := s.Store.Evidence(ctx, f, v, limit, after)
	b, _ := json.Marshal(rs)
	s.bytes.Add(int64(len(b)))
	if s.afterCall != nil {
		s.afterCall(n)
	}
	return rs, err
}

func spied(t *testing.T, w world, mod func(*covSpy), opts ...option) (*harness, *covSpy) {
	t.Helper()
	var sp *covSpy
	b := backend{"spy", func(t *testing.T, w world) (Store, string) {
		st, dsn := backends[0].build(t, w)
		sp = &covSpy{Store: st}
		if mod != nil {
			mod(sp)
		}
		return sp, dsn
	}}
	return newHarness(t, b, w, append([]option{atCovNow}, opts...)...), sp
}

// Proved: the statement reads records without state_change and correlation, builds the identical statement, and
// reads a small fraction of the bytes. Before the change every record came whole (the Slim flag off).
func TestCoverageStatementReadsRecordsWithoutTheObjectsItNeverUses(t *testing.T) {
	h, sp := spied(t, covWorld(1, 300, 8<<10), nil)
	from, to := covNow.Add(-24*time.Hour), covNow
	aud := &Viewer{Role: RoleAuditor}
	got, err := h.srv.statement(bg, aud, "aws:000", from, to, covNow)
	if err != nil {
		t.Fatal(err)
	}
	slimBytes := sp.bytes.Swap(0)
	// the pre-change read: the same records whole
	full := observe.Input{Scope: "aws:000", Window: observe.Window{From: from, To: to}}
	f, tt := evidence.ISO(from), evidence.ISO(to)
	base := EvidenceFilter{Scope: "aws:000", Outcomes: OutcomesInclude}
	rd := func(kind, since, until string) []Record {
		ff := base
		ff.Tools, ff.Since, ff.Until = []string{kind}, since, until
		rs, _, err := h.srv.collect(bg, ff, aud, MaxCoverageRecords)
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}
	full.Observations = rd(evidence.KindObservation, f, tt)
	full.Assessments, full.Resolutions, full.Verifications = rd(evidence.KindAssessment, f, ""), rd(evidence.KindResolution, f, ""), rd(evidence.KindVerification, f, "")
	full.Health, full.Gaps = rd(evidence.KindHealth, f, tt), rd(evidence.KindAuditGap, f, tt)
	before, _ := h.srv.opt.Store.HealthBefore(bg, aud, "aws:000", f)
	full.Health = append(before, full.Health...)
	fullBytes := sp.bytes.Load()
	want := observe.Build(full, covNow)
	gj, _ := json.Marshal(got)
	wj, _ := json.Marshal(want)
	if string(gj) != string(wj) {
		t.Fatalf("slim statement differs from the whole-record one:\n%s\n%s", gj, wj)
	}
	t.Logf("bytes of records read for one scope of 300 observations: slim %d, whole %d (%.0fx)", slimBytes, fullBytes, float64(fullBytes)/float64(slimBytes))
	if slimBytes*20 > fullBytes {
		t.Errorf("slim read %d bytes, whole %d: expected at least 20x less", slimBytes, fullBytes)
	}
}

// Proved: a cancelled request stops reading: the next page, the next record kind and the next scope are not read.
func TestCancelledCoverageReadStopsReading(t *testing.T) {
	ctx, cancel := context.WithCancel(bg)
	h, sp := spied(t, covWorld(5, 3, 10), func(sp *covSpy) {
		sp.afterCall = func(n int64) {
			if n == 1 {
				cancel() // the client goes away during the first read
			}
		}
	})
	req := httptest.NewRequest("GET", "/v1/coverage", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer audit")
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Fatalf("status %d, want 503", rec.Code)
	}
	if n := sp.calls.Load(); n != 1 {
		t.Errorf("%d evidence reads after the client left, want 1 (the one in flight)", n)
	}
	// uncancelled, the same request reads 6 kinds x 5 scopes
	h2, sp2 := spied(t, covWorld(5, 3, 10), nil)
	if r := h2.get("/v1/coverage", "audit"); r.status != 200 {
		t.Fatal(r.status, string(r.body))
	}
	if n := sp2.calls.Load(); n != 30 {
		t.Errorf("uncancelled: %d reads, want 30", n)
	}
}

// Proved: with one slot, a second coverage read is refused at once (503, Retry-After), not queued; other endpoints
// answer; the slot is free again afterwards.
func TestCoverageComputationsAreBoundedAndTheRestAreRefused(t *testing.T) {
	h, sp := spied(t, covWorld(1, 2, 10), func(sp *covSpy) { sp.release = make(chan struct{}); sp.started = make(chan struct{}, 8) },
		func(o *Options) { o.CoverageConcurrency = 1 })
	var wg sync.WaitGroup
	first := make(chan resp, 1)
	wg.Add(1)
	go func() { defer wg.Done(); first <- h.get("/v1/coverage?scope=aws:000", "audit") }()
	select {
	case <-sp.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first read never started")
	}
	t0 := time.Now()
	req := httptest.NewRequest("GET", "/v1/coverage?scope=aws:000", nil)
	req.Header.Set("Authorization", "Bearer audit")
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "retry") {
		t.Errorf("second read: %d, Retry-After %q, %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}
	if d := time.Since(t0); d > time.Second {
		t.Errorf("the refusal took %s", d)
	}
	if r := h.get("/v1/evidence/counts?by=provider", "audit"); r.status != 200 {
		t.Errorf("another endpoint answered %d", r.status)
	}
	close(sp.release)
	wg.Wait()
	if r := <-first; r.status != 200 {
		t.Errorf("first read: %d %s", r.status, r.body)
	}
	if p := sp.peak.Load(); p != 1 {
		t.Errorf("peak %d evidence reads at once, want 1", p)
	}
	if r := h.get("/v1/coverage?scope=aws:000", "audit"); r.status != 200 {
		t.Errorf("after the slot freed: %d", r.status)
	}
}

// Proved: the default allows more than one at a time, and a refused read never took a slot it does not release.
func TestCoverageDefaultConcurrencyIsTwo(t *testing.T) {
	h, sp := spied(t, covWorld(1, 2, 10), func(sp *covSpy) { sp.release = make(chan struct{}); sp.started = make(chan struct{}, 8) })
	var wg sync.WaitGroup
	codes := make([]int, 3)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); codes[i] = h.get("/v1/coverage?scope=aws:000", "audit").status }(i)
	}
	for i := 0; i < 2; i++ {
		<-sp.started
	}
	codes[2] = h.get("/v1/coverage?scope=aws:000", "audit").status
	close(sp.release)
	wg.Wait()
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 503 {
		t.Errorf("codes %v, want 200 200 503", codes)
	}
}

// Proved: with a TTL, a repeat inside it reads nothing and says how old it is; after it the answer is recomputed.
// Without one (the default) nothing is cached and no Age is sent.
func TestCoverageCacheIsOptInAndSaysHowOldItIs(t *testing.T) {
	clock := covNow
	get := func(h *harness, path string) (*httptest.ResponseRecorder, map[string]any) {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer audit")
		rec := httptest.NewRecorder()
		h.srv.Handler().ServeHTTP(rec, req)
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec, m
	}
	h, sp := spied(t, covWorld(2, 2, 10), nil, func(o *Options) { o.CoverageCacheTTL = 30 * time.Second; o.Clock = func() time.Time { return clock } })
	r1, m1 := get(h, "/v1/coverage")
	n := sp.calls.Load()
	if r1.Code != 200 || n == 0 || r1.Header().Get("Age") != "0" {
		t.Fatalf("first: %d, %d reads, Age %q", r1.Code, n, r1.Header().Get("Age"))
	}
	clock = clock.Add(20 * time.Second)
	r2, m2 := get(h, "/v1/coverage")
	if sp.calls.Load() != n || r2.Header().Get("Age") != "20" || r2.Header().Get("Cache-Control") != "private, max-age=10" {
		t.Errorf("repeat inside the TTL: %d new reads, Age %q, Cache-Control %q", sp.calls.Load()-n, r2.Header().Get("Age"), r2.Header().Get("Cache-Control"))
	}
	if m2["to"] != m1["to"] || r2.Body.String() != r1.Body.String() {
		t.Errorf("the cached body is not the computed one (to %v, was %v)", m2["to"], m1["to"])
	}
	if _, m := get(h, "/v1/coverage?scope=aws:000"); m["scope"] != "aws:000" { // another key is not answered from it
		t.Errorf("scoped read: %v", m)
	}
	clock = clock.Add(11 * time.Second)
	r3, m3 := get(h, "/v1/coverage")
	if sp.calls.Load() == n || r3.Header().Get("Age") != "0" || m3["to"] == m1["to"] {
		t.Errorf("past the TTL: not recomputed (Age %q, to %v)", r3.Header().Get("Age"), m3["to"])
	}
	// a refusal is not cached: a 400 is not stored (validation precedes the cache)
	if r, _ := get(h, "/v1/coverage?from=nonsense"); r.Code != 400 {
		t.Errorf("bad from: %d", r.Code)
	}

	h0, sp0 := spied(t, covWorld(1, 2, 10), nil)
	get(h0, "/v1/coverage?scope=aws:000")
	k := sp0.calls.Load()
	r, _ := get(h0, "/v1/coverage?scope=aws:000")
	if sp0.calls.Load() != 2*k || r.Header().Get("Age") != "" || r.Header().Get("Cache-Control") != "" {
		t.Errorf("default: %d reads for two requests of %d, Age %q", sp0.calls.Load(), k, r.Header().Get("Age"))
	}
}

func TestCoverageSettingsFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		base := map[string]string{"CLEARANCE_API_DSN": "postgres://x"}
		for k, v := range m {
			base[k] = v
		}
		return func(k string) string { return base[k] }
	}
	c, err := FromEnv(env(nil))
	if err != nil || c.CoverageConcurrency != DefaultCoverageConcurrency || c.CoverageCacheTTL != 0 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	c, err = FromEnv(env(map[string]string{"CLEARANCE_API_COVERAGE_CONCURRENCY": "4", "CLEARANCE_API_COVERAGE_CACHE_SECONDS": "30"}))
	if err != nil || c.CoverageConcurrency != 4 || c.CoverageCacheTTL != 30*time.Second {
		t.Fatalf("set: %+v %v", c, err)
	}
	for _, kv := range [][2]string{{"CLEARANCE_API_COVERAGE_CONCURRENCY", "0"}, {"CLEARANCE_API_COVERAGE_CONCURRENCY", "x"},
		{"CLEARANCE_API_COVERAGE_CACHE_SECONDS", "-1"}, {"CLEARANCE_API_COVERAGE_CACHE_SECONDS", "301"}} {
		if _, err := FromEnv(env(map[string]string{kv[0]: kv[1]})); err == nil {
			t.Errorf("%s=%s accepted", kv[0], kv[1])
		}
	}
}
