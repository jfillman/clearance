package grc_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/grc"
	"github.com/jfillman/clearance/internal/grc/grctest"
)

// clearedThen is a change that was cleared ago ago and has since moved to state (superseded, exception) at now-since.
func clearedThen(id, state string, ago, since time.Duration) gate.Change {
	c := change(id, "prod", gate.StateCleared, 2, ago)
	c.State = state
	later := gate.PyTime{Time: now.Add(-since)}
	c.DecidedAt, c.UpdatedAt = &later, later // the move overwrites decided_at with the later time
	return c
}

func neverCleared(id, state string, ago time.Duration) gate.Change {
	c := change(id, "prod", state, 2, ago)
	c.ClearedBy, c.Approvals = nil, nil
	return c
}

func reasonOf(t *testing.T, r *rig, kind string) string {
	t.Helper()
	recs := r.core.kinds(kind)
	if len(recs) == 0 {
		t.Fatalf("no %s record", kind)
	}
	rec := recs[len(recs)-1]["record"].(map[string]any)
	if rec["result"] != "failed" {
		t.Fatalf("last %s record is not a failure: %v", kind, rec)
	}
	s, _ := rec["reason"].(string)
	return s
}

// 1. A change that was cleared stays in the set after it is superseded or flagged as an exception: the hub holds the
// window, not the latest change per app.
func TestAClearedChangeStaysInTheSetAfterItIsSupersededOrAnException(t *testing.T) {
	r := newRig(t)
	a := clearedThen("a", gate.StateSuperseded, 48*time.Hour, time.Hour)
	x := clearedThen("x", gate.StateException, 30*time.Hour, 2*time.Hour)
	b := change("b", "prod", gate.StateCleared, 2, time.Hour)
	never := neverCleared("never", gate.StateSuperseded, 5*time.Hour)
	exNever := neverCleared("exnever", gate.StateException, 5*time.Hour)
	r.api.Set(a, x, b, never, exNever)
	if err := r.service(t).PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.hub.Items(evRes) != 3 {
		t.Fatalf("%d items, want a, x and b", r.hub.Items(evRes))
	}
	for _, id := range []string{"a", "x", "b"} {
		if _, ok := r.hub.Item(evRes, "clearance-change-"+id); !ok {
			t.Errorf("%s was dropped", id)
		}
	}
	for _, id := range []string{"never", "exnever"} {
		if _, ok := r.hub.Item(evRes, "clearance-change-"+id); ok {
			t.Errorf("%s was never cleared and is evidence of nothing", id)
		}
	}
	it, _ := r.hub.Item(evRes, "clearance-change-a")
	p := it["customProperties"].(map[string]any)
	if p["state"] != "superseded" || p["cleared_at"] != now.Add(-48*time.Hour).Format(time.RFC3339) {
		t.Fatalf("state and the time it was cleared (not superseded): %v", p)
	}
	// The window is by when it was cleared: cleared long ago, superseded recently, is out.
	old := clearedThen("old", gate.StateSuperseded, 100*24*time.Hour, time.Hour)
	r.api.Set(a, x, b, old)
	if err := r.service(t).PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.hub.Item(evRes, "clearance-change-old"); ok {
		t.Error("a change cleared outside the window is in the set")
	}
}

// 2. The hub deletes what a push leaves out, so a set that cannot be vouched for is never sent.
func TestEmptyAndShrinkGuards(t *testing.T) {
	ten := func() []gate.Change {
		var cs []gate.Change
		for i := 0; i < 10; i++ {
			cs = append(cs, change(fmt.Sprintf("c%d", i), "prod", gate.StateCleared, 1, time.Duration(i+1)*time.Hour))
		}
		return cs
	}
	refused := func(t *testing.T, r *rig, s *grc.Service, reason string, puts int) {
		t.Helper()
		err := s.PushOnce(context.Background())
		var rf *grc.Refusal
		if !errors.As(err, &rf) {
			t.Fatalf("got %v, want a refusal", err)
		}
		if rf.Reason != reason {
			t.Fatalf("reason %q (%v), want %q", rf.Reason, err, reason)
		}
		if r.hub.Puts != puts {
			t.Fatalf("the hub was sent a set (%d puts, was %d)", r.hub.Puts, puts)
		}
		if got := reasonOf(t, r, "grc.push"); got != reason {
			t.Fatalf("the ledger says %q, want %q", got, reason)
		}
	}
	t.Run("empty page", func(t *testing.T) {
		r := newRig(t)
		refused(t, r, r.service(t), "shrink-refused", 0)
	})
	for name, body := range map[string]string{"empty object": `{}`, "null": `null`, "no items": `{"next":null}`, "items null": `{"items":null}`, "a string": `"ok"`} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.api.Override = body
			refused(t, r, r.service(t), "source", 0)
		})
	}
	t.Run("wrong env filter", func(t *testing.T) {
		r := newRig(t)
		r.api.Set(ten()...)
		r.cfg.Envs = []string{"prd"}
		refused(t, r, r.service(t), "shrink-refused", 0)
	})
	t.Run("a record that does not parse", func(t *testing.T) {
		r := newRig(t)
		r.api.Set(ten()...)
		r.api.Extra = append(r.api.Extra, []byte(`{"id": 7}`), []byte(`"junk"`))
		refused(t, r, r.service(t), "unreadable-source", 0)
		if !strings.Contains(r.logs.String(), "did not parse") {
			t.Error("the count is not logged")
		}
	})
	t.Run("a big shrink", func(t *testing.T) {
		r := newRig(t)
		r.api.Set(ten()...)
		s := r.service(t)
		if err := s.PushOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.api.Set(ten()[:5]...)
		refused(t, r, s, "shrink-refused", 1)
		if r.hub.Items(evRes) != 10 {
			t.Fatal("the hub lost items")
		}
		if !strings.Contains(r.logs.String(), "5 items against 10") {
			t.Errorf("the sizes are not logged: %s", r.logs.String())
		}
		// A small shrink (the window ageing items out) is fine: 9 of 10 is above the floor.
		r.api.Set(ten()[:9]...)
		if err := s.PushOnce(context.Background()); err != nil || r.hub.Items(evRes) != 9 {
			t.Fatalf("a small shrink: %v", err)
		}
		// The record says how many left the set.
		var left any
		for _, rec := range r.core.kinds("grc.push") {
			if d, ok := rec["record"].(map[string]any)["destination"].(map[string]any); ok && d["left"] != nil {
				left = d["left"]
			}
		}
		if left != float64(1) {
			t.Fatalf("items that left the set: %v", left)
		}
	})
	t.Run("an allowed shrink", func(t *testing.T) {
		r := newRig(t)
		r.api.Set(ten()...)
		r.cfg.AllowShrink = true
		s := r.service(t)
		if err := s.PushOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.api.Set(ten()[:2]...)
		if err := s.PushOnce(context.Background()); err != nil || r.hub.Items(evRes) != 2 {
			t.Fatalf("shrink was allowed but: %v (%d items)", err, r.hub.Items(evRes))
		}
		r.api.Set()
		if err := s.PushOnce(context.Background()); err != nil || r.hub.Items(evRes) != 0 {
			t.Fatalf("an empty set was allowed but: %v", err)
		}
	})
	t.Run("after a restart only empty is refused", func(t *testing.T) {
		r := newRig(t)
		r.api.Set(ten()...)
		if err := r.service(t).PushOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.api.Set(ten()[:3]...)
		if err := r.service(t).PushOnce(context.Background()); err != nil { // the floor is unknown after a restart
			t.Fatalf("%v", err)
		}
		r.api.Set()
		refused(t, r, r.service(t), "shrink-refused", 2)
	})
	t.Run("the report is guarded the same way", func(t *testing.T) {
		r := newRig(t)
		err := r.service(t).ReportOnce(context.Background())
		var rf *grc.Refusal
		if !errors.As(err, &rf) || r.hub.Puts != 0 || reasonOf(t, r, "grc.report") != "shrink-refused" {
			t.Fatalf("an empty report: %v", err)
		}
	})
}

// 4. More pages than the read took is an incomplete set, never pushed as complete.
func TestAnIncompleteReadIsRefusedAndRecorded(t *testing.T) {
	r := newRig(t)
	r.api.PageSize = 2
	for i := 0; i < 7; i++ {
		r.api.Changes = append(r.api.Changes, change(fmt.Sprintf("c%d", i), "prod", gate.StateCleared, 1, time.Duration(i+1)*time.Hour))
	}
	r.cfg.MaxItems = 4
	if err := r.service(t).PushOnce(context.Background()); err == nil || r.hub.Puts != 0 || reasonOf(t, r, "grc.push") != "truncated" {
		t.Fatalf("a truncated read: %v puts %d", err, r.hub.Puts)
	}
	if err := r.service(t).ReportOnce(context.Background()); err == nil || r.hub.Puts != 0 || reasonOf(t, r, "grc.report") != "truncated" {
		t.Fatalf("a truncated report read: %v", err)
	}
	// Over the cap after merging three states is a truncation too.
	r2 := newRig(t)
	for i := 0; i < 3; i++ {
		r2.api.Changes = append(r2.api.Changes, change(fmt.Sprintf("c%d", i), "prod", gate.StateCleared, 1, time.Duration(i+1)*time.Hour),
			clearedThen(fmt.Sprintf("s%d", i), gate.StateSuperseded, time.Duration(i+5)*time.Hour, time.Hour))
	}
	r2.cfg.MaxItems = 5
	if err := r2.service(t).PushOnce(context.Background()); err == nil || r2.hub.Puts != 0 || reasonOf(t, r2, "grc.push") != "truncated" {
		t.Fatalf("a set over the cap: %v", err)
	}
}

// 5. The coverage report: whole days, a change since superseded still counts as cleared, no state falls through.
func TestCoverageReportCountsEveryStateAndWholeDays(t *testing.T) {
	r := newRig(t)
	day := func(d int, h int) time.Duration { // an age that lands on a UTC day d days before today at hour h
		return now.Sub(time.Date(2026, 11, 14-d, h, 0, 0, 0, time.UTC))
	}
	r.cfg.Window = 24*time.Hour*3 + 6*time.Hour // starts at 06:00 three days back: the day's report is still whole
	cs := []gate.Change{
		change("cleared", "prod", gate.StateCleared, 1, day(0, 1)),
		clearedThen("sup", gate.StateSuperseded, day(0, 2), time.Hour),
		clearedThen("exc", gate.StateException, day(0, 3), time.Hour),
		change("denied", "prod", gate.StateDenied, 2, day(0, 4)),
		change("degraded", "prod", gate.StateDegraded, 2, day(0, 5)),
		change("expired", "prod", gate.StateExpired, 2, day(0, 6)),
		neverCleared("supnever", gate.StateSuperseded, day(0, 7)),
		neverCleared("excnever", gate.StateException, day(0, 8)),
		change("edge", "prod", gate.StateCleared, 3, day(3, 2)), // 02:00 of the first day: before the window's start time, in its first day
		change("before", "prod", gate.StateCleared, 3, day(4, 2)),
	}
	r.api.Set(cs...)
	if err := r.service(t).ReportOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	it, _ := r.hub.Item(repRes, "clearance-coverage-prod-2026-11-14")
	p := it["customProperties"].(map[string]any)
	want := map[string]float64{"changes_total": 8, "changes_cleared": 3, "changes_denied": 1, "changes_degraded": 1, "changes_exception": 1, "changes_other": 2}
	for k, v := range want {
		if p[k] != v {
			t.Errorf("%s = %v, want %v (%v)", k, p[k], v, p)
		}
	}
	if edge, ok := r.hub.Item(repRes, "clearance-coverage-prod-2026-11-11"); !ok || edge["customProperties"].(map[string]any)["changes_cleared"] != float64(1) {
		t.Errorf("the first day of the window is partial or missing: %v", edge)
	}
	if _, ok := r.hub.Item(repRes, "clearance-coverage-prod-2026-11-10"); ok {
		t.Error("a day before the window is in the report")
	}
}

// 7. A persistent failure is one record an hour per class; a record the core refuses for one item skips that item.
func TestFailureRecordsAreOnePerHourPerClass(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	for i := 0; i < 100; i++ {
		r.hub.Fail = append(r.hub.Fail, grctest.Failure{Status: 503})
	}
	clock := now
	s := r.service(t)
	s.Now = func() time.Time { return clock }
	for i := 0; i < 4; i++ {
		_ = s.PushOnce(context.Background())
		clock = clock.Add(5 * time.Minute)
	}
	if n := len(r.core.kinds("grc.push")); n != 1 {
		t.Fatalf("%d failure records in an hour, want 1", n)
	}
	clock = clock.Add(time.Hour)
	_ = s.PushOnce(context.Background())
	if n := len(r.core.kinds("grc.push")); n != 2 {
		t.Fatalf("%d records after the hour turned, want 2", n)
	}
	// A different class is its own record.
	r.hub.Fail = []grctest.Failure{{Status: 400}}
	_ = s.PushOnce(context.Background())
	if n := len(r.core.kinds("grc.push")); n != 3 {
		t.Fatalf("%d records with a second class, want 3", n)
	}
}

func TestTheCoreRefusingOneItemSkipsItAndTheRestAreRecorded(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("a", "prod", gate.StateCleared, 1, time.Hour), change("b", "prod", gate.StateCleared, 1, 2*time.Hour), change("c", "prod", gate.StateCleared, 1, 3*time.Hour))
	r.core.Status = func(id string) int {
		if id == "b" {
			return 400
		}
		return 0
	}
	s := r.service(t)
	if err := s.PushOnce(context.Background()); err != nil {
		t.Fatalf("a refused item stopped the cycle: %v", err)
	}
	if n := len(r.core.items()); n != 2 {
		t.Fatalf("%d item records, want a and c", n)
	}
	if !strings.Contains(r.logs.String(), "refused a push record") {
		t.Error("the skip is not logged")
	}
	// A 5xx stops the loop (and the next cycle retries it).
	r2 := newRig(t)
	r2.api.Set(change("a", "prod", gate.StateCleared, 1, time.Hour), change("b", "prod", gate.StateCleared, 1, 2*time.Hour))
	r2.core.Status = func(id string) int {
		if id == "a" {
			return 503
		}
		return 0
	}
	if err := r2.service(t).PushOnce(context.Background()); err == nil || len(r2.core.items()) != 0 {
		t.Fatalf("a 5xx must stop the loop: %v", err)
	}
}

// 8. A Retry-After longer than the backoff cap ends the cycle: no early retry.
func TestARetryAfterBeyondTheCapEndsTheCycle(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	r.hub.Fail = []grctest.Failure{{Status: 429, RetryAfter: "3600"}}
	err := r.service(t).PushOnce(context.Background())
	var e *grc.Error
	if !errors.As(err, &e) || e.Class != "rate-limited" {
		t.Fatalf("%v", err)
	}
	if r.hub.Puts != 1 || len(r.sleeps) != 0 {
		t.Fatalf("puts %d sleeps %v: retried before the hub said", r.hub.Puts, r.sleeps)
	}
	if reasonOf(t, r, "grc.push") != "rate-limited" {
		t.Fatal("not recorded")
	}
}

// 10. Config hardening.
func TestConfigHardening(t *testing.T) {
	r := newRig(t)
	base := map[string]string{
		"CLEARANCE_GRC_TARGET": "vanta", "CLEARANCE_GRC_VANTA_BASE_URL": "https://api.vanta.com", "CLEARANCE_GRC_VANTA_CLIENT_ID": "c",
		"CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE": "/x", "CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID": "r", "CLEARANCE_API_URL": "http://clearance-api.ns.svc:8080",
		"CLEARANCE_URL": "http://clearance-core:8080", "CLEARANCE_GRC_LINK_BASE": linkBase}
	with := func(over map[string]string, opts ...grc.ConfigOption) error {
		_, err := grc.ConfigFromEnv(func(k string) string {
			if v, ok := over[k]; ok {
				return v
			}
			return base[k]
		}, opts...)
		return err
	}
	if err := with(nil); err != nil {
		t.Fatalf("the base config is valid: %v", err)
	}
	if err := with(map[string]string{"CLEARANCE_API_URL": "http://api.ns.svc.cluster.local:8080"}); err != nil {
		t.Errorf("an in-cluster service host: %v", err)
	}
	for name, over := range map[string]map[string]string{
		"loopback hub from the environment": {"CLEARANCE_GRC_VANTA_BASE_URL": "http://127.0.0.1:9"},
		"api over plain http to the world":  {"CLEARANCE_API_URL": "http://api.example.com"},
		"core over plain http to the world": {"CLEARANCE_URL": "http://203.0.113.7:8080"},
		"api with credentials":              {"CLEARANCE_API_URL": "https://u:p@api.example.com"},
		"api without a host":                {"CLEARANCE_API_URL": "https://"},
		"loopback api from the environment": {"CLEARANCE_API_URL": "http://127.0.0.1:8080"},
		"a plaintext secret and no file":    {"CLEARANCE_GRC_VANTA_CLIENT_SECRET": "hunter2", "CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE": ""},
		"a bad ratio":                       {"CLEARANCE_GRC_MIN_SET_RATIO": "1.5"},
	} {
		if err := with(over); err == nil {
			t.Errorf("%s was accepted", name)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the secret is in the error", name)
		}
	}
	if err := with(map[string]string{"CLEARANCE_GRC_VANTA_BASE_URL": "http://127.0.0.1:9"}, grc.ConfigLoopbackForTest()); err != nil {
		t.Errorf("the test option: %v", err)
	}
	// The constructor refuses a loopback hub unless the test option is passed; a setting cannot pass it.
	if _, err := grc.NewVanta("http://127.0.0.1:9", "c", "/x", "r", ""); err == nil {
		t.Error("NewVanta took a loopback http hub with no option")
	}
	if _, err := grc.NewVanta("http://127.0.0.1:9", "c", "/x", "r", "", grc.InsecureLoopbackForTest()); err != nil {
		t.Error(err)
	}
	// No proxy unless asked.
	if tr := grc.NewHTTPClient(false).Transport.(*http.Transport); tr.Proxy != nil {
		t.Error("the default client uses the environment's proxy")
	}
	if tr := grc.NewHTTPClient(true).Transport.(*http.Transport); tr.Proxy == nil {
		t.Error("the proxy setting does nothing")
	}
	_ = r
}

// 11. Readiness fails after a sustained failure, liveness never does; a slow report does not hold up the evidence.
func TestReadinessAndLivenessAreSeparate(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	clock := now
	s := r.service(t)
	s.Now = func() time.Time { return clock }
	get := func(path string) int {
		rec := httptest.NewRecorder()
		s.Mux().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code
	}
	if get("/healthz") != 200 || get("/readyz") != 200 {
		t.Fatal("not ready at start")
	}
	r.hub.ClientSecret = "bad"
	_ = s.PushOnce(context.Background())
	if get("/readyz") != 200 {
		t.Fatal("one failed cycle is not yet unready")
	}
	clock = clock.Add(r.cfg.UnreadyAfter + time.Minute)
	_ = s.PushOnce(context.Background())
	if get("/readyz") != 503 {
		t.Fatal("a sustained failure leaves the pod ready")
	}
	if get("/healthz") != 200 {
		t.Fatal("a vendor outage must not fail liveness (the pod would restart-loop)")
	}
	r.hub.ClientSecret = secret
	if err := s.PushOnce(context.Background()); err != nil || get("/readyz") != 200 {
		t.Fatalf("recovery: %v", err)
	}
	// The two loops fail and recover on their own: the report failing does not mark the evidence loop failed.
	if !s.Healthy() {
		t.Fatal("evidence loop unhealthy after success")
	}
}

func TestAStalledReportDoesNotDelayTheEvidencePush(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	s := r.service(t)
	waiting, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.Sleep = func(ctx context.Context, d time.Duration) error { // the report's retry wait blocks until released
		once.Do(func() { close(waiting) })
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}
	r.hub.Fail = []grctest.Failure{{Status: 503}} // the first PUT (the report's) fails and waits
	done := make(chan error, 1)
	go func() { done <- s.ReportOnce(context.Background()) }()
	<-waiting
	if err := s.PushOnce(context.Background()); err != nil {
		t.Fatalf("the evidence push waited on the report: %v", err)
	}
	if r.hub.Items(evRes) != 1 {
		t.Fatal("no evidence while the report waits")
	}
	close(release)
	<-done
}

// 12. A resend restores what the hub lost; a report on two days with the same figures is two records.
func TestAnUnchangedSetIsSentAgainAfterTheResendInterval(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	clock := now
	s := r.service(t)
	s.Now = func() time.Time { return clock }
	if err := s.PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.hub.Sets = map[string]map[string]map[string]any{} // the hub lost it
	clock = clock.Add(time.Hour)
	_ = s.PushOnce(context.Background())
	if r.hub.Items(evRes) != 0 || r.hub.Puts != 1 {
		t.Fatal("an unchanged set inside the interval was re-sent")
	}
	clock = clock.Add(r.cfg.ResendEvery)
	if err := s.PushOnce(context.Background()); err != nil || r.hub.Items(evRes) != 1 {
		t.Fatalf("the set was not restored: %v", err)
	}
}

func TestTheReportRecordNamesTheDay(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	clock := now
	s := r.service(t)
	s.Now = func() time.Time { return clock }
	if err := s.ReportOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(24 * time.Hour) // the same change, the same counts, tomorrow
	if err := s.ReportOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(r.core.kinds("grc.report")); n != 2 {
		t.Fatalf("%d report records for two days, want 2", n)
	}
}

func TestEveryFailureClassIsOneTheCoreAccepts(t *testing.T) {
	for _, c := range []string{"auth", "rate-limited", "unavailable", "rejected", "bad-response", "network", "config"} {
		found := false
		for _, r := range grc.Reasons {
			found = found || r == c
		}
		if !found {
			t.Errorf("%s is not in grc.Reasons", c)
		}
	}
}
