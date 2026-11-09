package api

// O-1: a fake observed provider posts its four kinds to a real core, clearance-api reads the chain, and the coverage
// route says blind for a scope whose health record has gone stale.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/server"
)

const obsScope = "aws:123456789012"

type fakeObserved struct {
	t    *testing.T
	dsn  string
	core *core.Core
	srv  *httptest.Server
}

// onBoth runs fn on a core over memory and, where CLEARANCE_TEST_DSN names a Postgres, on one over a scratch database.
func onBoth(t *testing.T, fn func(t *testing.T, f *fakeObserved)) {
	t.Run("memory", func(t *testing.T) { fn(t, newFakeObserved(t, "")) })
	t.Run("postgres", func(t *testing.T) { fn(t, newFakeObserved(t, newDB(t))) })
}

func newFakeObserved(t *testing.T, dsn string) *fakeObserved {
	t.Helper()
	ps, err := server.ParseProviders(`[{"name": "fake-trail", "version": "0.1.0", "principals": ["observed-system/fake-trail"],
	  "kinds": ["observation", "assessment", "resolution", "observation.health", "observation.verification"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	cfg := core.Config{Memory: dsn == "", DSN: dsn, Version: "test", Providers: ps, Auth: core.DevAuthenticator(), MaxClockSkew: -1}
	c, err := core.Build(bg, cfg, nil, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	srv := httptest.NewServer(c.Server.Handler())
	t.Cleanup(srv.Close)
	return &fakeObserved{t: t, dsn: dsn, core: c, srv: srv}
}

func (f *fakeObserved) post(kind string, rec map[string]any) map[string]any {
	f.t.Helper()
	raw, _ := json.Marshal(map[string]any{"provider": "fake-trail", "kind": kind, "record": rec})
	req, _ := http.NewRequest("POST", f.srv.URL+"/v1/records", strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer observed-system/fake-trail")
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 {
		f.t.Fatalf("POST %s: %d %v", kind, resp.StatusCode, out)
	}
	return out
}

func obsEvent(id, api string, ok bool) map[string]any {
	return map[string]any{"scope": obsScope, "source": map[string]any{"name": "cloudtrail", "event_id": id},
		"resource":  map[string]any{"kind": "Instance", "id": "i-0abc"},
		"actor":     map[string]any{"subject": "arn:aws:sts::123456789012:assumed-role/deployer/run-1"},
		"action":    map[string]any{"verb": "create", "api": api, "succeeded": ok},
		"integrity": map[string]any{"sourceVerified": true, "completenessClaimed": true},
		"times":     map[string]any{"observed": "2026-11-09T10:00:05Z"}}
}

func obsHealth(state string, failed ...string) map[string]any {
	ok := len(failed) == 0
	checks := []any{map[string]any{"name": "trail-enabled", "ok": true}, map[string]any{"name": "digests-validating", "ok": ok}}
	return map[string]any{"scope": obsScope, "source": map[string]any{"name": "cloudtrail"},
		"health": map[string]any{"state": state, "checks": checks, "interval_seconds": 300}}
}

// firstTS is when the core recorded the first record: a window that starts there has no unseen stretch before it.
func (f *fakeObserved) firstTS() time.Time {
	rs, err := f.core.Store.Records(bg, 0, 1)
	if err != nil || len(rs) == 0 {
		f.t.Fatal(err)
	}
	ts, err := time.Parse(time.RFC3339, rs[0]["ts"].(string))
	if err != nil {
		f.t.Fatal(err)
	}
	return ts
}

func (f *fakeObserved) harness(t *testing.T, at time.Time) *harness {
	build := func(t *testing.T, _ world) (Store, string) {
		if f.dsn != "" {
			return openReader(t, f.dsn), f.dsn
		}
		st, err := fromReader(bg, f.core.Store)
		if err != nil {
			t.Fatal(err)
		}
		return st, ""
	}
	return newHarness(t, backend{"observed", build}, world{},
		func(o *Options) { o.Clock = func() time.Time { return at } })
}

var _ = context.Background

func TestCoverageIsBlindForAScopeWhoseHealthRecordIsStale(t *testing.T) {
	onBoth(t, checkCoverageIsBlindForAScopeWhoseHealthRecordIsStale)
}

func checkCoverageIsBlindForAScopeWhoseHealthRecordIsStale(t *testing.T, f *fakeObserved) {
	start := time.Now().UTC().Truncate(time.Second)
	f.post("observation.health", obsHealth("healthy"))
	seen := f.post("observation", obsEvent("e-1", "RunInstances", true))
	cleared := f.post("observation", obsEvent("e-2", "RunInstances", true))
	f.post("observation", obsEvent("e-3", "RunInstances", false))
	f.post("assessment", map[string]any{"scope": obsScope, "about": map[string]any{"seq": cleared["seq"]},
		"coverage": "authorized-and-verified", "tier": 1, "rule_set": map[string]any{"version": "1"},
		"attribution": map[string]any{"signal": "grant-match"}})
	f.post("assessment", map[string]any{"scope": obsScope, "about": map[string]any{"seq": seen["seq"]},
		"coverage": "out-of-band-detected", "tier": 3, "rule_set": map[string]any{"version": "1"},
		"attribution": map[string]any{"signal": "no-grant"}})
	f.post("resolution", map[string]any{"scope": obsScope, "about": map[string]any{"seq": seen["seq"]},
		"resolution": map[string]any{"state": "reverted", "cause": "agent-caused"}})

	from := evidence.ISO(f.firstTS())
	url := "/v1/coverage?scope=" + obsScope + "&from=" + from

	// a minute later the feed is fresh: healthy, three observations (one cleared, one out of band and reverted, one
	// unassessed), and so not clean
	h := f.harness(t, start.Add(time.Minute))
	st := h.ok(url, "audit")
	if st["state"] != "healthy" || st["clean"] != false {
		t.Fatalf("%v", st)
	}
	cl, sn := st["cleared_and_verified"].(map[string]any), st["seen_not_cleared"].(map[string]any)
	if cl["count"] != json.Number("1") || sn["count"] != json.Number("2") {
		t.Fatalf("cleared %v, seen %v", cl, sn)
	}
	by := sn["by_coverage"].(map[string]any)
	if by["out-of-band-detected"] != json.Number("1") || by["unassessed"] != json.Number("1") {
		t.Fatal(by)
	}
	var reverted bool
	for _, it := range sn["items"].([]any) {
		if m := it.(map[string]any); m["resolution"] == "reverted" && m["cause"] == "agent-caused" {
			reverted = true
		}
	}
	if !reverted {
		t.Fatal(sn)
	}

	// an hour later no health record has come: the window is blind, whatever was seen, and never clean
	h = f.harness(t, start.Add(time.Hour))
	st = h.ok(url, "audit")
	if st["state"] != "blind" || st["clean"] != false {
		t.Fatalf("a stale feed is blind: %v", st)
	}
	src := st["health"].(map[string]any)["sources"].([]any)[0].(map[string]any)
	if src["source"] != "cloudtrail" || src["now"] != "blind" || src["stale"] != true {
		t.Fatal(src)
	}
	seg := st["could_not_see"].(map[string]any)["segments"].([]any)
	if len(seg) == 0 || seg[len(seg)-1].(map[string]any)["reason"] != "stale" {
		t.Fatal(seg)
	}
	if !strings.Contains(st["text"].(string), "blind") {
		t.Fatal(st["text"])
	}

	// no observation at all and no health record: blind, not clean (a clean list needs a healthy health record)
	h = f.harness(t, start.Add(time.Minute))
	empty := h.ok("/v1/coverage?scope=aws:999999999999&from="+from, "audit")
	if empty["state"] != "blind" || empty["clean"] != false {
		t.Fatal(empty)
	}
}

func TestCoverageIsCleanOnlyForAHealthyWindowWithNothingUncleared(t *testing.T) {
	onBoth(t, checkCoverageIsCleanOnlyForAHealthyWindowWithNothingUncleared)
}

func checkCoverageIsCleanOnlyForAHealthyWindowWithNothingUncleared(t *testing.T, f *fakeObserved) {
	start := time.Now().UTC().Truncate(time.Second)
	f.post("observation.health", obsHealth("healthy"))
	o := f.post("observation", obsEvent("e-1", "RunInstances", true))
	f.post("assessment", map[string]any{"scope": obsScope, "about": map[string]any{"seq": o["seq"]},
		"coverage": "authorized-and-verified", "tier": 1, "rule_set": map[string]any{"version": "1"},
		"attribution": map[string]any{"signal": "grant-match"}})
	h := f.harness(t, start.Add(time.Minute))
	url := "/v1/coverage?scope=" + obsScope + "&from=" + evidence.ISO(f.firstTS())
	if st := h.ok(url, "audit"); st["clean"] != true || st["state"] != "healthy" {
		t.Fatalf("%v", st)
	}
	// the feed degrades: the same window is no longer clean, and says why
	f.post("observation.health", obsHealth("degraded", "digests-validating"))
	h = f.harness(t, start.Add(time.Minute))
	st := h.ok(url, "audit")
	if st["clean"] != false || st["state"] != "degraded" {
		t.Fatalf("%v", st)
	}
	if src := st["health"].(map[string]any)["sources"].([]any)[0].(map[string]any); src["failed_checks"].([]any)[0] != "digests-validating" {
		t.Fatal(src)
	}
	if gaps := st["could_not_see"].(map[string]any)["audit_gaps"].([]any); len(gaps) != 1 {
		t.Fatal(gaps)
	}
}

func TestTheObservationAndHealthListsAreByScopeAndForAuditors(t *testing.T) {
	onBoth(t, checkTheObservationAndHealthListsAreByScopeAndForAuditors)
}

func checkTheObservationAndHealthListsAreByScopeAndForAuditors(t *testing.T, f *fakeObserved) {
	start := time.Now().UTC().Truncate(time.Second)
	f.post("observation.health", obsHealth("healthy"))
	f.post("observation", obsEvent("e-1", "RunInstances", true))
	other := obsEvent("e-2", "RunInstances", true)
	other["scope"] = "aws:210987654321"
	f.post("observation", other)
	f.post("observation.health", obsHealth("blind", "digests-validating"))
	h := f.harness(t, start.Add(time.Minute))
	eqSeqs(t, "observations", seqs(h.ok("/v1/observations?scope="+obsScope, "audit")), 1)
	eqSeqs(t, "other scope", seqs(h.ok("/v1/observations?scope=aws:210987654321", "audit")), 2)
	eqSeqs(t, "source", seqs(h.ok("/v1/observations?scope="+obsScope+"&source=audit-webhook", "audit")))
	eqSeqs(t, "health", seqs(h.ok("/v1/observations/health?scope="+obsScope, "audit")), 4, 3, 0)
	h.status(t, 400, "GET", "/v1/observations", "audit", "")
	h.status(t, 400, "GET", "/v1/observations?scope="+obsScope+"&kind=health", "audit", "")
	h.status(t, 400, "GET", "/v1/coverage?scope="+obsScope+"&from=yesterday", "audit", "")
	h.status(t, 400, "GET", "/v1/coverage?scope="+obsScope+"&from=2026-11-09T10:00:00Z&to=2026-11-09T09:00:00Z", "audit", "")
	h.status(t, 403, "GET", "/v1/observations?scope="+obsScope, "carol", "")
	h.status(t, 403, "GET", "/v1/coverage?scope="+obsScope, "carol", "")
	h.status(t, 401, "GET", "/v1/coverage?scope="+obsScope, "", "")
}

// O-5: the coverage statement counts the observations the trail verified after the fact, and lists the verification
// records; a verification does not add an observation.
func TestCoverageCountsWhatTheTrailVerifiedLater(t *testing.T) {
	onBoth(t, checkCoverageCountsWhatTheTrailVerifiedLater)
}

func checkCoverageCountsWhatTheTrailVerifiedLater(t *testing.T, f *fakeObserved) {
	start := time.Now().UTC().Truncate(time.Second)
	f.post("observation.health", obsHealth("healthy"))
	a := obsEvent("e-1", "RunInstances", true)
	a["integrity"] = map[string]any{"sourceVerified": false, "completenessClaimed": true, "method": "eventbridge-delivery"}
	later := f.post("observation", a)
	b := obsEvent("e-2", "RunInstances", true)
	b["integrity"] = map[string]any{"sourceVerified": false, "completenessClaimed": true, "method": "eventbridge-delivery"}
	f.post("observation", b)                                     // never verified
	f.post("observation", obsEvent("e-3", "RunInstances", true)) // verified by its own delivery
	f.post("observation.verification", map[string]any{"scope": obsScope, "source": map[string]any{"name": "cloudtrail", "event_id": "e-1/verification"},
		"about": map[string]any{"seq": later["seq"]}, "verification": map[string]any{"method": "cloudtrail-digest-chain", "verified": true}})
	h := f.harness(t, start.Add(time.Minute))
	st := h.ok("/v1/coverage?scope="+obsScope+"&from="+evidence.ISO(f.firstTS()), "audit")
	si := st["source_integrity"].(map[string]any)
	if si["observations"] != json.Number("3") || si["verified"] != json.Number("2") || si["verified_later"] != json.Number("1") ||
		si["verified_by_record"] != json.Number("1") || si["unverified"] != json.Number("1") {
		t.Fatalf("source integrity %v", si)
	}
	var how []string
	for _, it := range st["seen_not_cleared"].(map[string]any)["items"].([]any) {
		m := it.(map[string]any)
		by, _ := m["verified_by"].(string)
		how = append(how, by)
		if (by != "") != (m["source_verified"] == true) {
			t.Fatalf("source_verified and verified_by disagree: %v", m)
		}
	}
	if strings.Join(how, ",") != "later,,self" {
		t.Fatalf("how each observation was verified (in seq order): %v", how)
	}
	if st["seen_not_cleared"].(map[string]any)["count"] != json.Number("3") {
		t.Fatalf("a verification adds no observation: %v", st["seen_not_cleared"])
	}
	if got := seqs(h.ok("/v1/observations?scope="+obsScope+"&kind=observation.verification", "audit")); len(got) != 1 {
		t.Fatalf("verification records: %v", got)
	}
	if !strings.Contains(st["text"].(string), "Source verified: 2 of 3 observations") {
		t.Fatal(st["text"])
	}
}
