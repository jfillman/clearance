package server_test

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Gate exemptions (W-42; docs/gate.md, "The gate rule and exemptions"): a deploy.exception of kind gate-exemption, decided
// by the core. protectionFixture's CLEARANCE_PROTECTED_ENVIRONMENTS is hangar-prod/prod.

func exemption(env, state string, expires time.Time, extra map[string]any) map[string]any {
	x := map[string]any{"state": state, "application": "argocd/web-" + env, "entry": "argocd/web-*", "rule": "tenants",
		"rule_digest": strings.Repeat("ab", 32), "reason": "a migration to the new chart", "expires": expires.UTC().Format(time.RFC3339)}
	for k, v := range extra {
		x[k] = v
	}
	return map[string]any{"provider": "agent-prod", "kind": "deploy.exception", "record": map[string]any{
		"principal": "argocd-agent (gate rule)", "target": "argocd/web-" + env, "result": "gate exemption " + state, "app": "web",
		"destination": map[string]any{"cluster": "hangar-prod", "environment": env},
		"exception":   map[string]any{"kind": "gate-exemption", "exemption": x}}}
}

func TestAGateExemptionIsRecordedWithItsCoverage(t *testing.T) {
	f := protectionFixture(t, "")
	in := time.Now().Add(30 * 24 * time.Hour)
	f.do("POST", "/v1/records", agentProd, exemption("staging", "requested", in, map[string]any{"ref": "PR-1"})).want(t, 200, "")
	var got map[string]any
	for _, r := range f.records() {
		if r["tool"] == "deploy.exception" {
			got = r
		}
	}
	if got == nil || got["coverage"] != "coverage-unavailable" {
		t.Fatalf("the exemption is recorded as the gap it is: %v", got)
	}
	x := got["exception"].(map[string]any)["exemption"].(map[string]any)
	if x["state"] != "requested" || x["ref"] != "PR-1" || x["approvedBy"] != nil {
		t.Fatalf("recorded as posted, with no approver field: %v", x)
	}
}

func TestTheCoreRefusesAnExemptionOnAStaticEnvironment(t *testing.T) {
	f := protectionFixture(t, "")
	in := time.Now().Add(30 * 24 * time.Hour)
	n := len(f.records())
	for _, st := range []string{"requested", "active", "expiring"} {
		f.do("POST", "/v1/records", agentProd, exemption("prod", st, in, nil)).want(t, 409, "refused: static")
	}
	if len(f.records()) != n {
		t.Fatal("a refused exemption writes nothing")
	}
	// Closing or explaining one is always taken.
	for _, st := range []string{"expired", "refused"} {
		f.do("POST", "/v1/records", agentProd, exemption("prod", st, in, map[string]any{"why": "static"})).want(t, 200, "")
	}
	// Asking again with the same event id is decided again, not answered from the earlier record.
	rec := exemption("staging", "requested", in, nil)
	rec["record"].(map[string]any)["source"] = map[string]any{"name": "argocd-agent", "event_id": "gx-1"}
	f.do("POST", "/v1/records", agentProd, rec).want(t, 200, "")
	again := f.do("POST", "/v1/records", agentProd, rec).want(t, 200, "")
	if again.body["duplicate"] != true {
		t.Fatalf("the same request is one record: %v", again.body)
	}
}

func TestAGateExemptionIsHeldToItsShape(t *testing.T) {
	f := protectionFixture(t, "")
	in := time.Now().Add(30 * 24 * time.Hour)
	for name, c := range map[string]struct {
		body map[string]any
		want string
	}{
		"too long":       {exemption("staging", "requested", time.Now().Add(91*24*time.Hour), nil), "refused: too-long"},
		"short reason":   {exemption("staging", "requested", in, map[string]any{"reason": "short"}), "reason"},
		"no expiry":      {exemption("staging", "requested", in, map[string]any{"expires": "next week"}), "expires"},
		"a state":        {exemption("staging", "approved", in, nil), "state"},
		"an approver":    {exemption("staging", "requested", in, map[string]any{"approvedBy": "someone"}), "unknown field"},
		"bad digest":     {exemption("staging", "requested", in, map[string]any{"rule_digest": "abc"}), "rule_digest"},
		"bad app key":    {exemption("staging", "requested", in, map[string]any{"application": "web"}), "application"},
		"names a change": {withChange(exemption("staging", "requested", in, nil)), "names no change"},
		"other kind":     {outOfBandWithExemption(), "only by one"},
	} {
		t.Run(name, func(t *testing.T) {
			code := 400
			if strings.HasPrefix(c.want, "refused") {
				code = 409
			}
			f.do("POST", "/v1/records", agentProd, c.body).want(t, code, c.want)
		})
	}
}

func withChange(b map[string]any) map[string]any {
	b["record"].(map[string]any)["change"] = map[string]any{"id": "ch-0123456789abcdef"}
	return b
}

func outOfBandWithExemption() map[string]any {
	b := exemption("staging", "requested", time.Now().Add(time.Hour), nil)
	b["record"].(map[string]any)["exception"].(map[string]any)["kind"] = "out-of-band"
	return b
}

func TestAReportCannotRemoveAStaticPairForAnExemption(t *testing.T) {
	f := protectionFixture(t, "")
	f.do("PUT", "/v1/protection/hangar-prod", agentProd, pairs("web/prod", "web/staging")).want(t, 200, "")
	body := pairs("web/staging")
	body["exempted"] = []any{map[string]any{"app": "web", "env": "prod"}}
	f.do("PUT", "/v1/protection/hangar-prod", agentProd, body).want(t, 409, "refused: static")
	body = pairs("web/prod")
	body["exempted"] = []any{map[string]any{"app": "web", "env": "prod"}}
	f.do("PUT", "/v1/protection/hangar-prod", agentProd, body).want(t, 400, "still in pairs")
	body = pairs("web/prod")
	body["exempted"] = []any{map[string]any{"app": "web", "env": "staging"}}
	f.do("PUT", "/v1/protection/hangar-prod", agentProd, body).want(t, 200, "")
	recs := protectionRecords(f)
	if res := fmt.Sprint(recs[len(recs)-1]["result"]); !strings.Contains(res, "removed for a gate exemption web/staging") {
		t.Fatalf("the record names the exemption: %s", res)
	}
}
