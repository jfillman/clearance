package server_test

// O-1: the observation kinds through the whole core over HTTP, written by a fake observed provider: its four kinds, the
// de-duplication of its events, the Secret guard, the operation on monitoring that flips a scope's health, and one
// chain of v1 and v1.1 records that verifies and validates against the published schema.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
	"github.com/jfillman/clearance/schemas"
)

const (
	observer = "observed-system/fake-trail"
	scope    = "aws:123456789012"
)

func observedFixture(t *testing.T) *fixture {
	t.Helper()
	v := vocabtest.Lab()
	v.MonitoringProtectionOps = []string{"StopLogging", "cloudtrail:DeleteTrail"}
	vocabtest.Use(t, v)
	ps, err := server.ParseProviders(`[{"name": "autopilot-gateway", "version": "0.3.27", "principals": ["autopilot-system/clearance"]},
	  {"name": "fake-trail", "version": "0.1.0", "principals": ["observed-system/fake-trail"],
	   "kinds": ["observation", "assessment", "resolution", "observation.health"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, "")
	cfg.Providers = ps
	return newFixture(t, cfg)
}

func observation(id, api string, ok bool) map[string]any {
	rec := map[string]any{"scope": scope, "source": map[string]any{"name": "cloudtrail", "event_id": id},
		"resource": map[string]any{"kind": "Trail", "name": "org-trail", "region": "us-east-1"},
		"actor": map[string]any{"subject": "arn:aws:sts::123456789012:assumed-role/deployer/run-1",
			"chain":  []any{"arn:aws:iam::123456789012:role/ci", "arn:aws:iam::123456789012:role/deployer"},
			"issuer": "token.actions.githubusercontent.com", "client": "aws-cli/2.17", "attributes": map[string]any{"mfa": false}},
		"action":    map[string]any{"verb": "update", "api": api, "succeeded": ok},
		"integrity": map[string]any{"sourceVerified": true, "completenessClaimed": true, "method": "digest-chain"},
		"times": map[string]any{"requested": "2026-11-09T10:00:00Z", "observed": "2026-11-09T10:00:05Z",
			"delivered": "2026-11-09T10:04:00Z"},
		"state_change": map[string]any{"before": map[string]any{"enabled": true}, "after": map[string]any{"enabled": false}},
		"correlation":  map[string]any{"grant": "ch-0123456789abcdef", "task_id": "t-1", "run_id": "r-1", "operation_id": "op-1"}}
	if !ok {
		rec["action"].(map[string]any)["refused_reason"] = "AccessDenied"
	}
	return rec
}

func health(state string, failed ...string) map[string]any {
	checks := []any{}
	for _, n := range []string{"trail-enabled", "regions-covered", "digests-validating"} {
		checks = append(checks, map[string]any{"name": n, "ok": !contains(failed, n)})
	}
	return map[string]any{"scope": scope, "source": map[string]any{"name": "cloudtrail"},
		"health": map[string]any{"state": state, "checks": checks, "interval_seconds": 300}}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (f *fixture) post(kind string, rec map[string]any) answer {
	return f.do("POST", "/v1/records", observer, map[string]any{"provider": "fake-trail", "kind": kind, "record": rec})
}

func tools(recs []store.Record) []string {
	var out []string
	for _, r := range recs {
		out = append(out, r["tool"].(string))
	}
	return out
}

func TestAFakeObservedProviderPostsAllFourKinds(t *testing.T) {
	f := observedFixture(t)
	f.post("observation.health", health("healthy")).want(t, 200, "")
	o := f.post("observation", observation("e-1", "PutEventSelectors2", true)).want(t, 200, "")
	seq := int64(o.body["seq"].(float64))
	f.post("assessment", map[string]any{"scope": scope, "about": map[string]any{"seq": seq}, "coverage": "authorized-and-verified",
		"tier": 1, "rule_set": map[string]any{"version": "2026-11-01"},
		"attribution": map[string]any{"signal": "grant-match", "grant": "ch-0123456789abcdef"}}).want(t, 200, "")
	f.post("resolution", map[string]any{"scope": scope, "about": map[string]any{"seq": seq},
		"resolution": map[string]any{"state": "ratified", "by": "user:dana"}}).want(t, 200, "")

	recs := f.records()
	if got := strings.Join(tools(recs), " "); got != "observation.health observation assessment resolution" {
		t.Fatal(got)
	}
	for _, r := range recs {
		if r["schema"] != evidence.SchemaV1_1 {
			t.Fatalf("%v is not v1.1: %v", r["tool"], r["schema"])
		}
		if r["provider"].(map[string]any)["name"] != "fake-trail" {
			t.Fatal(r["provider"])
		}
	}
	ob := recs[1]
	if ob["coverage"] != "observed-not-attributed" {
		t.Fatalf("an observation is not cleared by being seen: %v", ob["coverage"])
	}
	if ob["completeness_supported"] != true || !has(ob["verified"], "completeness_supported") || has(ob["verified"], "actor") {
		t.Fatalf("the health record supported the completeness claim, and only that is verified: %v", ob)
	}
	if recs[2]["coverage"] != "authorized-and-verified" || recs[2]["tier"] != json.Number("1") {
		t.Fatal(recs[2])
	}
	validate(t, recs)
}

func has(v any, s string) bool {
	l, _ := v.([]any)
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// validate holds the whole chain to the published schema and verifies it.
func validate(t *testing.T, recs []store.Record) {
	t.Helper()
	if ok, bad := evidence.Verify(recs); !ok {
		t.Fatalf("chain broken at %d", bad)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemas.EvidenceV1))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	const url = "https://clearance.hangarplatform.dev/schemas/evidence/v1.json"
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		raw, _ := json.Marshal(r)
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := sch.Validate(inst); err != nil {
			t.Errorf("seq %v (%v) does not validate: %v", r["seq"], r["tool"], err)
		}
	}
}

func TestTheProvidersEventsAreDeDuplicated(t *testing.T) {
	f := observedFixture(t)
	first := f.post("observation", observation("e-7", "RunInstances", true)).want(t, 200, "")
	again := f.post("observation", observation("e-7", "RunInstances", true)).want(t, 200, "")
	if again.body["duplicate"] != true || again.body["seq"] != first.body["seq"] || again.body["hash"] != first.body["hash"] ||
		first.body["duplicate"] != nil {
		t.Fatalf("%v then %v", first.body, again.body)
	}
	if n := len(f.records()); n != 1 {
		t.Fatalf("a repeat wrote %d records", n)
	}
	// another event id, another source and another kind are not repeats
	f.post("observation", observation("e-8", "RunInstances", true)).want(t, 200, "")
	other := observation("e-7", "RunInstances", true)
	other["source"] = map[string]any{"name": "audit-webhook", "event_id": "e-7"}
	if r := f.post("observation", other).want(t, 200, ""); r.body["duplicate"] != nil {
		t.Fatal("the same event id from another source was a duplicate")
	}
	// the key is the provider's too: the gateway's records with the same ids do not collide with the observer's
	f.do("POST", "/v1/records", gw, map[string]any{"provider": "autopilot-gateway", "kind": "run.launch", "record": map[string]any{
		"session": "s-1", "principal": "autopilot-runs/x", "agent": "a", "result": "ok",
		"source": map[string]any{"name": "cloudtrail", "event_id": "e-7"}}}).want(t, 200, "")
	// and it holds for the kinds that already existed: the R-9 line, a repeat of a provider's own event
	rec := map[string]any{"session": "s-2", "principal": "autopilot-runs/x", "agent": "a", "result": "ok",
		"source": map[string]any{"event_id": "launch-2"}}
	a := f.do("POST", "/v1/records", gw, map[string]any{"provider": "autopilot-gateway", "kind": "run.launch", "record": rec}).want(t, 200, "")
	b := f.do("POST", "/v1/records", gw, map[string]any{"provider": "autopilot-gateway", "kind": "run.launch", "record": rec}).want(t, 200, "")
	if b.body["duplicate"] != true || a.body["seq"] != b.body["seq"] {
		t.Fatalf("%v then %v", a.body, b.body)
	}
	if n := len(f.records()); n != 5 {
		t.Fatalf("%d records", n)
	}
}

func TestAnObservationCarriesNoSecretBody(t *testing.T) {
	f := observedFixture(t)
	secret := func(mod func(rec map[string]any)) map[string]any {
		rec := observation("s-1", "get", true)
		rec["resource"] = map[string]any{"kind": "Secret", "name": "db", "namespace": "prod"}
		delete(rec, "state_change")
		rec["source"] = map[string]any{"name": "kube-audit", "event_id": "s-1", "level": "Metadata"}
		mod(rec)
		return rec
	}
	f.post("observation", secret(func(map[string]any) {})).want(t, 200, "") // Metadata: fine
	for name, mod := range map[string]func(map[string]any){
		"not at Metadata": func(r map[string]any) { r["source"].(map[string]any)["level"] = "RequestResponse" },
		"no level":        func(r map[string]any) { delete(r["source"].(map[string]any), "level") },
		"a state change":  func(r map[string]any) { r["state_change"] = map[string]any{"after": map[string]any{"x": 1}} },
		"a body in attributes": func(r map[string]any) {
			r["actor"].(map[string]any)["attributes"] = map[string]any{"kind": "Secret", "data": map[string]any{"p": "c2VjcmV0"}}
		},
		"stringData in a nested": func(r map[string]any) {
			r["correlation"] = map[string]any{"grant": "x"}
			r["action"].(map[string]any)["stringData"] = "x"
		},
	} {
		rec := secret(mod)
		rec["source"].(map[string]any)["event_id"] = "s-" + name
		f.post("observation", rec).want(t, 400, "")
	}
	// a Secret body hidden in the state change of an observation of something else
	cm := observation("s-cm", "update", true)
	cm["state_change"] = map[string]any{"after": map[string]any{"kind": "Secret", "apiVersion": "v1", "data": map[string]any{"p": "c2VjcmV0"}}}
	f.post("observation", cm).want(t, 400, "Secret")
	for _, r := range f.records() {
		if strings.Contains(fmt.Sprint(r), "c2VjcmV0") {
			t.Fatal("a Secret body reached the chain")
		}
	}
}

func TestAnOperationOnMonitoringIsTier3AndFlipsTheScopesHealth(t *testing.T) {
	f := observedFixture(t)
	f.post("observation.health", health("healthy")).want(t, 200, "")
	// refused: nothing changed, but monitoring was touched: tier 3, degraded
	f.post("observation", observation("m-1", "StopLogging", false)).want(t, 200, "")
	recs := f.records()
	if got := strings.Join(tools(recs), " "); got != "observation.health observation observation.health observation.audit-gap" {
		t.Fatal(got)
	}
	if recs[1]["tier"] != json.Number("3") || !has(recs[1]["verified"], "tier") {
		t.Fatalf("an operation on monitoring is a verified tier 3: %v", recs[1])
	}
	flip, gap := recs[2], recs[3]
	if flip["health"].(map[string]any)["state"] != "degraded" || flip["provider"].(map[string]any)["name"] != "clearance" {
		t.Fatal(flip)
	}
	if gap["coverage"] != "coverage-unavailable" || gap["gap"].(map[string]any)["state"] != "degraded" ||
		gap["gap"].(map[string]any)["reason"] != "monitoring-protection" {
		t.Fatal(gap)
	}
	// succeeded: blind, and no second gap while the first is open
	f.post("observation", observation("m-2", "StopLogging", true)).want(t, 200, "")
	recs = f.records()
	if got := strings.Join(tools(recs[4:]), " "); got != "observation observation.health" {
		t.Fatal(got)
	}
	if recs[5]["health"].(map[string]any)["state"] != "blind" || recs[4]["completeness_supported"] != false {
		t.Fatal(recs[4:])
	}
	// the platform's name in configuration, by source too, and the provider's own mark; an ordinary call is neither
	ob := observation("m-3", "CreateTrail", true)
	f.post("observation", ob).want(t, 200, "")
	if r := f.records(); r[len(r)-1]["tier"] != nil {
		t.Fatal(r[len(r)-1])
	}
	own := observation("m-4", "SomethingElse", true)
	own["action"].(map[string]any)["protects_monitoring"] = true
	f.post("observation", own).want(t, 200, "")
	if r := f.records(); r[len(r)-1]["tier"] != json.Number("3") {
		t.Fatal(r[len(r)-1])
	}
	// a feed that recovers says so itself
	f.post("observation.health", health("healthy")).want(t, 200, "")
	validate(t, f.records())
}

func TestAHealthRecordThatDropsAFeedWritesAnAuditGap(t *testing.T) {
	f := observedFixture(t)
	f.post("observation.health", health("healthy")).want(t, 200, "")
	f.post("observation.health", health("blind", "trail-enabled", "digests-validating")).want(t, 200, "")
	f.post("observation.health", health("blind", "trail-enabled")).want(t, 200, "") // already down: no second gap
	got := tools(f.records())
	if strings.Join(got, " ") != "observation.health observation.health observation.audit-gap observation.health" {
		t.Fatal(got)
	}
	if g := f.records()[2]["gap"].(map[string]any); g["reason"] != "health-reported" || g["since"] == nil {
		t.Fatal(g)
	}
}

func TestObservedRecordsAreRefusedWhenTheyAreNotWellFormed(t *testing.T) {
	f := observedFixture(t)
	f.post("observation", observation("w-0", "RunInstances", true)).want(t, 200, "")
	bad := map[string]func(map[string]any){
		"no event id":                func(r map[string]any) { delete(r["source"].(map[string]any), "event_id") },
		"coverage set":               func(r map[string]any) { r["coverage"] = "authorized-and-verified" },
		"no actor subject":           func(r map[string]any) { delete(r["actor"].(map[string]any), "subject") },
		"succeeded missing":          func(r map[string]any) { delete(r["action"].(map[string]any), "succeeded") },
		"reason on a success":        func(r map[string]any) { r["action"].(map[string]any)["refused_reason"] = "x" },
		"no observed time":           func(r map[string]any) { delete(r["times"].(map[string]any), "observed") },
		"integrity incomplete":       func(r map[string]any) { delete(r["integrity"].(map[string]any), "completenessClaimed") },
		"scope with a space":         func(r map[string]any) { r["scope"] = "aws account" },
		"unknown correlation":        func(r map[string]any) { r["correlation"] = map[string]any{"colour": "red"} },
		"a resolution's field":       func(r map[string]any) { r["resolution"] = map[string]any{"state": "ratified"} },
		"a health on an observation": func(r map[string]any) { r["health"] = map[string]any{"state": "healthy"} },
	}
	n := 0
	for name, mod := range bad {
		rec := observation(fmt.Sprintf("w-%d", n+1), "RunInstances", true)
		n++
		mod(rec)
		f.post("observation", rec).want(t, 400, "")
		_ = name
	}
	// health: a healthy state with a failed check, a degraded one with none, an empty list
	hc := health("healthy", "trail-enabled")
	f.post("observation.health", hc).want(t, 400, "failed")
	f.post("observation.health", health("degraded")).want(t, 400, "no check failed")
	empty := health("healthy")
	empty["health"].(map[string]any)["checks"] = []any{}
	f.post("observation.health", empty).want(t, 400, "checks")
	// an assessment or resolution is about a record that exists, of the right kind, in the same scope
	f.post("assessment", map[string]any{"scope": scope, "about": map[string]any{"seq": 99}, "coverage": "break-glass", "tier": 2,
		"rule_set": map[string]any{"version": "1"}, "attribution": map[string]any{"signal": "window"}}).want(t, 400, "not a record")
	f.post("assessment", map[string]any{"scope": "aws:other", "about": map[string]any{"seq": 0}, "coverage": "break-glass", "tier": 2,
		"rule_set": map[string]any{"version": "1"}, "attribution": map[string]any{"signal": "window"}}).want(t, 400, "scope")
	f.post("assessment", map[string]any{"scope": scope, "about": map[string]any{"seq": 0}, "coverage": "sideways", "tier": 2,
		"rule_set": map[string]any{"version": "1"}, "attribution": map[string]any{"signal": "window"}}).want(t, 400, "")
	// a reverted resolution names its cause, and only it does
	res := func(r map[string]any) answer {
		return f.post("resolution", map[string]any{"scope": scope, "about": map[string]any{"seq": 0}, "resolution": r})
	}
	res(map[string]any{"state": "reverted"}).want(t, 400, "cause")
	res(map[string]any{"state": "reverted", "cause": "someone"}).want(t, 400, "cause")
	res(map[string]any{"state": "ratified", "cause": "agent-caused"}).want(t, 400, "cause")
	for _, c := range []string{"agent-caused", "policy-triggered", "human-initiated", "automated-remediation",
		"requirement-changed", "external-dependency", "unattributed"} {
		res(map[string]any{"state": "reverted", "cause": c}).want(t, 200, "")
	}
	for _, st := range []string{"declared-break-glass", "still-live"} {
		res(map[string]any{"state": st}).want(t, 200, "")
	}
	// a resolution is not about a resolution
	f.post("resolution", map[string]any{"scope": scope, "about": map[string]any{"seq": 1}, "resolution": map[string]any{"state": "still-live"}}).want(t, 400, "resolution record")
}

func TestOnlyAProviderRegisteredForTheObservationKindsMayWriteThem(t *testing.T) {
	f := observedFixture(t)
	// the gateway lists no kinds (all but the observation kinds); the observer lists them
	f.do("POST", "/v1/records", gw, map[string]any{"provider": "autopilot-gateway", "kind": "observation",
		"record": observation("x-1", "RunInstances", true)}).want(t, 403, "may not write")
	// and the observer does not write what it did not list
	f.do("POST", "/v1/records", observer, map[string]any{"provider": "fake-trail", "kind": "deploy.outcome",
		"record": map[string]any{"app": "a", "target": "t", "outcome": map[string]any{"applied": true}}}).want(t, 403, "may not write")
	// observation.audit-gap is the core's
	f.post("observation.audit-gap", map[string]any{"scope": scope}).want(t, 400, "")
	// the observation fields belong to the observation kinds
	f.do("POST", "/v1/records", gw, map[string]any{"provider": "autopilot-gateway", "kind": "run.launch", "record": map[string]any{
		"session": "s-1", "principal": "p", "agent": "a", "result": "ok", "scope": scope}}).want(t, 400, "observation kinds")
	_ = time.Now
}
