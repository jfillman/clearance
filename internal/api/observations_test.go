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
	h.status(t, 401, "GET", "/v1/coverage?scope="+obsScope, "", "")
}

// O-5 (owner decision 2026-11-12): any signed-in person reads the observation routes, a delegate acting for one does,
// and the read is of the whole scope (not the per-person evidence scope, which would show a person none of it). An
// unauthenticated caller, a token the authenticator refuses (a non-allowlisted OIDC user is refused there) and a
// machine principal are still refused. The resolution write is not touched here.
func TestAnySignedInPersonReadsObservationsAndCoverage(t *testing.T) {
	onBoth(t, checkAnySignedInPersonReadsObservationsAndCoverage)
}

func checkAnySignedInPersonReadsObservationsAndCoverage(t *testing.T, f *fakeObserved) {
	start := time.Now().UTC().Truncate(time.Second)
	f.post("observation.health", obsHealth("healthy"))
	ev := obsEvent("e-1", "RunInstances", true)
	ev["state_change"] = map[string]any{"before": map[string]any{},
		"after": map[string]any{"instanceType": "t3.micro", "MasterUserPassword": "hunter2-plain",
			"containers": []any{map[string]any{"name": "DB_PASSWORD", "value": "hunter3-plain"}, map[string]any{"name": "REGION", "value": "ca-central-1"}}}}
	f.post("observation", ev)
	h := f.harness(t, start.Add(time.Minute))
	paths := []string{"/v1/observations?scope=" + obsScope, "/v1/observations/health?scope=" + obsScope, "/v1/coverage?scope=" + obsScope}
	for _, who := range []string{"carol", "alice", "bob", "audit"} { // alice owns nothing and is in no group: still a person
		for _, p := range paths {
			h.status(t, 200, "GET", p, who, "")
		}
	}
	for _, p := range paths {
		h.status(t, 200, "GET", p, "tower", "user:alice") // Tower's proxy: the delegate naming a person
		h.status(t, 403, "GET", p, "tower", "")           // the delegate for nobody is not a person
		h.status(t, 403, "GET", p, "svc", "")             // a machine principal
		h.status(t, 401, "GET", p, "", "")                // no token
		h.status(t, 401, "GET", p, "mallory", "")         // a token the authenticator refuses (not on CLEARANCE_OIDC_ALLOWED_USERS)
	}
	eqSeqs(t, "person sees the scope", seqs(h.ok(paths[0], "alice")), 1)
	if st := h.ok(paths[2], "alice"); st["state"] == nil || st["scope"] != obsScope {
		t.Fatalf("statement %v", st)
	}
	// An auditor reads the record as stored; a person reads it with secret-bearing values redacted.
	raw := string(h.get(paths[0], "audit").body)
	if !strings.Contains(raw, "hunter2-plain") || !strings.Contains(raw, "hunter3-plain") {
		t.Fatalf("the auditor's read is as stored: %s", raw)
	}
	bodies := map[string]string{"alice": string(h.get(paths[0], "alice").body), "carol": string(h.get(paths[0], "carol").body),
		"tower for alice": string(h.do("GET", paths[0], "tower", "user:alice").body)}
	for who, body := range bodies {
		if strings.Contains(body, "hunter") {
			t.Fatalf("%s read a secret value: %s", who, body)
		}
		for _, keep := range []string{"t3.micro", "ca-central-1", "state_change_redacted"} {
			if !strings.Contains(body, keep) {
				t.Fatalf("%s: %q was redacted or missing: %s", who, keep, body)
			}
		}
	}
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

// The live W5 gate: StopLogging succeeded and the core flipped the scope blind; the collector's next routine record said
// degraded. Coverage stays blind until the collector reports healthy.
func TestCoverageStaysBlindAfterAMonitoringFlipUntilTheCollectorIsHealthy(t *testing.T) {
	onBoth(t, checkCoverageStaysBlindAfterAMonitoringFlipUntilTheCollectorIsHealthy)
}

func checkCoverageStaysBlindAfterAMonitoringFlipUntilTheCollectorIsHealthy(t *testing.T, f *fakeObserved) {
	start := time.Now().UTC().Truncate(time.Second)
	f.post("observation.health", obsHealth("healthy"))
	stop := obsEvent("e-stop", "StopLogging", true)
	stop["action"].(map[string]any)["protects_monitoring"] = true
	f.post("observation", stop)
	f.post("observation.health", obsHealth("degraded", "digests-validating")) // routine: the trail is still stopped
	h := f.harness(t, start.Add(time.Minute))
	url := "/v1/coverage?scope=" + obsScope + "&from=" + evidence.ISO(f.firstTS())
	st := h.ok(url, "audit")
	if st["state"] != "blind" {
		t.Fatalf("a degraded record does not end a monitoring flip: %v", st["state"])
	}
	for _, sg := range st["could_not_see"].(map[string]any)["segments"].([]any) {
		if sg.(map[string]any)["state"] == "degraded" {
			t.Fatalf("no stretch of the window is merely degraded: %v", sg)
		}
	}
	f.post("observation.health", obsHealth("healthy"))
	h = f.harness(t, start.Add(2*time.Minute))
	st = h.ok(url, "audit")
	if src := st["health"].(map[string]any)["sources"].([]any)[0].(map[string]any); src["state"] == nil || src["now"] != "healthy" {
		t.Fatalf("the collector's healthy record ends the flip: %v", src)
	}
}
