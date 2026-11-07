package gate_test

// C-6: the clearance state machine (every transition, and the token consistent with every state), protected
// environments, the outage block, provider exception and degraded-mode reports, and break-glass.

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
)

var argoWriter = evidence.Writer{Provider: evidence.Provider{Name: "argo-gate", Version: "0.1.0"},
	Verified: map[string]bool{"provider": true, "ts": true}}

// report is a provider record as the core builds it from POST /v1/records (server.ProviderEvent.event).
func report(f *fixture, tool string, fields map[string]any) store.Event {
	ev := store.Event{"ts": evidence.ISO(f.clock.now()), "tool": tool, "boundary": "deployment",
		"principal": "hangar-prod/argocd/clearance-sync", "target": "gate-api-prod", "result": "reported",
		"app": "gate-api", "destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"}}
	for k, v := range fields {
		if v == nil {
			delete(ev, k)
		} else {
			ev[k] = v
		}
	}
	return ev
}

func exceptionOf(f *fixture, kind, changeID string) store.Event {
	x := map[string]any{"kind": kind}
	switch kind {
	case "out-of-band":
		x["objects"] = []any{map[string]any{"kind": "Deployment", "namespace": "app-gate-api-prod", "name": "gate-api"}}
	case "drift":
		x["addresses"] = []any{"aws_security_group.web"}
	case "untraced-apply":
		x["actor"] = "arn:aws:iam::123456789012:user/someone"
	case "digest-mismatch":
		x["expected"], x["observed"] = "sha256:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("9", 64)
	}
	fields := map[string]any{"exception": x}
	if changeID != "" {
		fields["change"] = map[string]any{"id": changeID}
	}
	return report(f, gate.KindException, fields)
}

func degradedOf(f *fixture, decision string, tier any, changeID string) store.Event {
	from := f.clock.now().Add(-30 * time.Minute)
	fields := map[string]any{"decision": decision, "coverage": "coverage-unavailable",
		"outage": map[string]any{"from": evidence.ISO(from), "to": evidence.ISO(f.clock.now())}}
	if tier != nil {
		fields["tier"] = json.Number(fmt.Sprint(tier))
	}
	if changeID != "" {
		fields["change"] = map[string]any{"id": changeID}
	}
	return report(f, gate.KindDegraded, fields)
}

func (f *fixture) report(t *testing.T, ev store.Event) store.Record {
	t.Helper()
	rec, err := f.svc.Report(f.ctx, ev, argoWriter)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// tokenLive says whether the change has an unrevoked token.
func (f *fixture) tokenLive(t *testing.T, id string) bool {
	t.Helper()
	tk, err := f.st.Token(f.ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return tk.RevokedAt == nil
}

// consistent is the token invariant: a change has a live token exactly while it is cleared.
func (f *fixture) consistent(t *testing.T, id string) {
	t.Helper()
	c := f.get(t, id)
	if live := f.tokenLive(t, id); live != (c.State == gate.StateCleared) {
		t.Fatalf("%s is %s but its token live=%v", id, c.State, live)
	}
}

var pending = map[string]any{"ci": "pending", "provenance": "not-agent", "render": "ok"}

func headN(n int) string { return strings.Repeat(fmt.Sprint(n), 40) }

// transitionCases drive each edge of gate.Transitions on a fresh gate with tokens, and say which change moved.
var transitionCases = map[[2]string]func(t *testing.T, f *fixture) string{
	{"", gate.StateHolding}: func(t *testing.T, f *fixture) string {
		return f.register(t, "ci", change(map[string]any{"objects": replicas})).ID
	},
	{"", gate.StateCleared}: func(t *testing.T, f *fixture) string {
		return f.register(t, "ci", change(map[string]any{"objects": imageBump})).ID
	},
	{"", gate.StateDenied}: func(t *testing.T, f *fixture) string {
		return f.register(t, "ci", change(map[string]any{"objects": imageBump, "proposerKind": "unknown"})).ID
	},
	{gate.StateHolding, gate.StateCleared}: func(t *testing.T, f *fixture) string {
		// by people ...
		c := f.register(t, "ci", change(map[string]any{"objects": replicas}))
		if _, err := f.svc.Clear(f.ctx, principals["erin"], c.ID, ""); err != nil {
			t.Fatal(err)
		}
		f.consistent(t, c.ID)
		// ... and by a re-registration with green checks
		d := f.register(t, "ci", change(map[string]any{"objects": imageBump, "checks": pending, "head": headN(4), "pr": json.Number("8")}))
		if d.State != gate.StateHolding {
			t.Fatal(d.State)
		}
		if got := f.register(t, "ci", change(map[string]any{"objects": imageBump, "head": headN(4), "pr": json.Number("8")})); got.State != gate.StateCleared {
			t.Fatal(got.State)
		}
		f.consistent(t, d.ID)
		return c.ID
	},
	{gate.StateHolding, gate.StateDenied}: func(t *testing.T, f *fixture) string {
		c := f.register(t, "ci", change(map[string]any{"objects": replicas}))
		if _, err := f.svc.Deny(f.ctx, principals["erin"], c.ID, "not now", ""); err != nil {
			t.Fatal(err)
		}
		// a re-registration that is denied by policy (the PR now looks like an unattributed agent's)
		d := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": headN(5), "pr": json.Number("9")}))
		if got := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": headN(5), "pr": json.Number("9"),
			"proposerKind": "unknown"})); got.State != gate.StateDenied {
			t.Fatal(got.State)
		}
		f.consistent(t, d.ID)
		return c.ID
	},
	{gate.StateHolding, gate.StateExpired}: func(t *testing.T, f *fixture) string {
		c := f.register(t, "ci", change(map[string]any{"objects": replicas}))
		f.clock.advance(8 * 24 * time.Hour)
		if _, err := f.svc.Expire(f.ctx); err != nil {
			t.Fatal(err)
		}
		return c.ID
	},
	{gate.StateHolding, gate.StateSuperseded}: func(t *testing.T, f *fixture) string {
		c := f.register(t, "ci", change(map[string]any{"objects": replicas}))
		f.register(t, "ci", change(map[string]any{"objects": replicas, "head": headN(2)}))
		return c.ID
	},
	{gate.StateHolding, gate.StateDegraded}: func(t *testing.T, f *fixture) string {
		c := f.register(t, "ci", change(map[string]any{"objects": replicas}))
		f.report(t, degradedOf(f, "allow", nil, c.ID))
		return c.ID
	},
	{gate.StateHolding, gate.StateException}: func(t *testing.T, f *fixture) string {
		c := f.register(t, "ci", change(map[string]any{"objects": replicas}))
		f.report(t, exceptionOf(f, "out-of-band", c.ID))
		return c.ID
	},
	{gate.StateCleared, gate.StateSuperseded}: func(t *testing.T, f *fixture) string {
		c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
		f.consistent(t, c.ID)
		f.register(t, "ci", change(map[string]any{"objects": imageBump, "head": headN(2)}))
		return c.ID
	},
	{gate.StateCleared, gate.StateException}: func(t *testing.T, f *fixture) string {
		c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
		f.consistent(t, c.ID)
		f.report(t, exceptionOf(f, "digest-mismatch", c.ID))
		return c.ID
	},
}

func TestEveryTransitionOfTheStateMachine(t *testing.T) {
	if len(transitionCases) != len(gate.Transitions) {
		t.Fatalf("%d cases for %d transitions", len(transitionCases), len(gate.Transitions))
	}
	for _, tr := range gate.Transitions {
		run, ok := transitionCases[[2]string{tr.From, tr.To}]
		if !ok {
			t.Fatalf("no case for %q -> %q", tr.From, tr.To)
		}
		t.Run(tr.From+"->"+tr.To, func(t *testing.T) {
			f, _ := withTokens(t)
			id := run(t, f)
			c := f.get(t, id)
			if c.State != tr.To {
				t.Fatalf("state %s, want %s", c.State, tr.To)
			}
			f.consistent(t, id)
			if tr.From == gate.StateCleared {
				revs := f.records(t, "deploy.revoke")
				if len(revs) == 0 || revs[len(revs)-1]["change"].(map[string]any)["id"] != id {
					t.Fatalf("leaving cleared wrote no deploy.revoke: %v", revs)
				}
			}
			if tr.To == gate.StateDegraded || tr.To == gate.StateException {
				if c.Ended == nil || c.Ended.Seq == 0 {
					t.Fatalf("no ended record: %+v", c.Ended)
				}
			}
			if _, err := memory_load(f); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func memory_load(f *fixture) (int, error) {
	recs, err := f.st.Records(f.ctx, 0, 100000)
	if err != nil {
		return 0, err
	}
	ok, bad := evidence.Verify(recs)
	if !ok {
		return 0, fmt.Errorf("the chain breaks at %d", bad)
	}
	return len(recs), nil
}

func TestTheStateMachineHasNoOtherEdges(t *testing.T) {
	all := append([]string{""}, gate.States...)
	edges := 0
	for _, from := range all {
		for _, to := range gate.States {
			if gate.CanMove(from, to) {
				edges++
				if slices.Contains(gate.FinalStates, from) {
					t.Errorf("a final state moves: %s -> %s", from, to)
				}
			}
		}
	}
	if edges != len(gate.Transitions) {
		t.Fatalf("%d edges, %d transitions", edges, len(gate.Transitions))
	}
	for _, s := range gate.States {
		if gate.CanMove(s, s) || gate.CanMove(s, "") {
			t.Errorf("%s has a self or backwards edge", s)
		}
	}
	// the main path's states are the first five, the C-6 side states the last two
	if !slices.Equal(gate.States[5:], []string{gate.StateDegraded, gate.StateException}) {
		t.Fatal(gate.States)
	}
}

func TestFinalStatesIgnoreReportsAndPeople(t *testing.T) {
	f, _ := withTokens(t)
	c := f.register(t, "ci", change(map[string]any{"objects": replicas}))
	f.report(t, exceptionOf(f, "out-of-band", c.ID))
	// a second report names it: recorded, the state stays
	before := len(f.records(t, ""))
	f.report(t, degradedOf(f, "allow", 2, c.ID))
	if got := f.get(t, c.ID); got.State != gate.StateException || len(f.records(t, "")) != before+1 {
		t.Fatal(got.State)
	}
	if _, err := f.svc.Clear(f.ctx, principals["erin"], c.ID, ""); func() string { r, _ := ruleOf(err); return r }() != "DG-STATE" {
		t.Fatal(err)
	}
	// re-registering the same head returns it as it stands
	if got := f.register(t, "ci", change(map[string]any{"objects": replicas})); got.State != gate.StateException {
		t.Fatal(got.State)
	}
	// a held change the provider held during the outage (decision deny) stays holding: "held" is holding
	d := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": headN(6), "pr": json.Number("11")}))
	f.report(t, degradedOf(f, "deny", nil, d.ID))
	if got := f.get(t, d.ID); got.State != gate.StateHolding {
		t.Fatal(got.State)
	}
	// a cleared change the provider let through during an outage stays cleared (it was cleared)
	e := f.register(t, "ci", change(map[string]any{"objects": imageBump, "head": headN(7), "pr": json.Number("12")}))
	f.report(t, degradedOf(f, "allow", nil, e.ID))
	if got := f.get(t, e.ID); got.State != gate.StateCleared {
		t.Fatal(got.State)
	}
	f.consistent(t, e.ID)
}

func TestAPushSupersedesOnlyItsOwnAppEnvAndCluster(t *testing.T) {
	f, _ := withTokens(t)
	a := f.register(t, "ci", change(map[string]any{"objects": replicas, "pr": json.Number("0"), "head": headN(1)}))
	b := f.register(t, "ci", change(map[string]any{"objects": replicas, "pr": json.Number("0"), "head": headN(2), "app": "other-app"}))
	if f.get(t, a.ID).State != gate.StateHolding || f.get(t, b.ID).State != gate.StateHolding {
		t.Fatal("a push for another app superseded a holding change")
	}
	f.register(t, "ci", change(map[string]any{"objects": replicas, "pr": json.Number("0"), "head": headN(3)}))
	if f.get(t, a.ID).State != gate.StateSuperseded || f.get(t, b.ID).State != gate.StateHolding {
		t.Fatal(f.get(t, a.ID).State, f.get(t, b.ID).State)
	}
}

func TestASupersededClearedChangeIsRejectedForDeployment(t *testing.T) {
	f, _ := withTokens(t)
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	f.register(t, "ci", change(map[string]any{"objects": replicas, "head": headN(2)}))
	out, err := f.svc.DeploymentRequested(f.ctx, "1", "jfillman/gitops-gate-api", head, "prod", 1, "https://cb")
	if err != nil || out.Answer == nil || *out.Answer != "rejected" || out.Rule == nil || *out.Rule != "DG-UNREGISTERED" {
		t.Fatal(out, err)
	}
	if _, live, _ := f.svc.Clearance(f.ctx, c.ID); live != nil {
		t.Fatal("a superseded change still serves a token")
	}
}

// -- protected environments --------------------------------------------------------------------------------------

func TestOnlyConfiguredEnvironmentsAreProtected(t *testing.T) {
	f, _ := withTokens(t)
	f.svc.Config.Protected = []string{"hangar-prod/*", "*/prod"}
	// protected: the gate tiers it as before
	c := f.register(t, "ci", change(map[string]any{"objects": secret}))
	if c.State != gate.StateHolding || !c.Protected || c.Tier != 3 {
		t.Fatal(c.State, c.Protected, c.Tier)
	}
	// not on the list: tier 0, reason unprotected, cleared, recorded, with a token
	u := f.register(t, "ci", change(map[string]any{"objects": secret, "cluster": "hangar-dev", "env": "dev", "head": headN(2), "pr": json.Number("3")}))
	if u.State != gate.StateCleared || u.Protected || u.Tier != 0 || len(u.Reasons) != 1 || u.Reasons[0].Rule != "unprotected" ||
		u.Reasons[0].Subject != "hangar-dev/dev" || *u.ClearedBy != "policy" {
		t.Fatalf("%+v", u)
	}
	f.consistent(t, u.ID)
	clr := f.records(t, "deploy.clear")
	if !strings.Contains(clr[len(clr)-1]["result"].(string), "hangar-dev/dev is not a protected environment") {
		t.Fatal(clr[len(clr)-1]["result"])
	}
	// the caller's protected: true decides nothing; protected: false is refused
	_, err := f.svc.Register(f.ctx, principals["ci"], change(map[string]any{"protected": false, "head": headN(3)}))
	if r, s := ruleOf(err); r != "DG-PROTECTED" || s != 400 {
		t.Fatal(err)
	}
	// an empty list protects every environment (fail closed)
	f.svc.Config.Protected = nil
	if !f.svc.Protects("anything", "dev") {
		t.Fatal("an unconfigured deployment protects nothing")
	}
	e := f.register(t, "ci", change(map[string]any{"objects": secret, "cluster": "hangar-dev", "env": "dev", "head": headN(4), "pr": json.Number("4")}))
	if e.State != gate.StateHolding || !e.Protected {
		t.Fatal(e.State)
	}
	if _, err := gate.ParseProtected([]string{"prod"}); err == nil {
		t.Fatal("an entry without cluster/env is accepted")
	}
	if _, err := gate.ParseProtected([]string{"a/b/c"}); err == nil {
		t.Fatal("an entry with two slashes is accepted")
	}
}

func TestTheTrustedRegistryRuleFiresWhenConfigured(t *testing.T) {
	f, _ := withTokens(t)
	f.svc = gate.NewService(gate.Config{Verifiers: f.svc.Config.Verifiers, TrustedRegistries: []string{"ghcr.io/riley-roooo/"}},
		f.st, f.clock.now)
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	if c.Tier != 2 || !has(ruleList(gate.Classification{Reasons: c.Reasons}), "image:not-trusted-registry") {
		t.Fatal(c.Tier, c.Reasons)
	}
	trusted := objs(obj("Rollout", "gate-api", "changed", []string{"/spec/template/spec/containers/0/image"},
		[]string{"ghcr.io/riley-roooo/gate-api@sha256:" + strings.Repeat("e", 64)}, "argoproj.io/v1alpha1"))
	if c := f.register(t, "ci", change(map[string]any{"objects": trusted, "head": headN(2), "pr": json.Number("2")})); c.Tier != 1 {
		t.Fatal(c.Tier, c.Reasons)
	}
}

// -- the outage policy -----------------------------------------------------------------------------------------------

func TestTheOutageBlockTightensOnly(t *testing.T) {
	v := baseline.View().Outage
	if v["0"] != gate.OutageAllow || v["1"] != gate.OutageAllow || v["2"] != gate.OutageHold || v["3"] != gate.OutageHold {
		t.Fatal(v)
	}
	p, err := baseline.Tightened(map[string]any{"outage": map[string]any{"1": "hold"}})
	if err != nil || p.OutageFor(1) != gate.OutageHold || p.OutageFor(0) != gate.OutageAllow {
		t.Fatal(err, p.Outage)
	}
	for _, bad := range []map[string]any{{"2": "allow-and-record"}, {"3": "allow-and-record"}, {"4": "hold"}, {"1": "maybe"}} {
		if _, err := baseline.Tightened(map[string]any{"outage": bad}); func() string { r, _ := ruleOf(err); return r }() != "DG-POLICY" {
			t.Fatal(bad, err)
		}
	}
	if baseline.OutageFor(-1) != gate.OutageHold || baseline.OutageFor(7) != gate.OutageHold {
		t.Fatal("an unknown tier is not held")
	}
	f := newGate(t)
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	if c.Outage != gate.OutageAllow {
		t.Fatal(c.Outage)
	}
	h := f.register(t, "ci", change(map[string]any{"objects": imageBump, "head": headN(2), "pr": json.Number("2"),
		"policy": map[string]any{"outage": map[string]any{"1": "hold"}}}))
	if h.Tier != 1 || h.Outage != gate.OutageHold {
		t.Fatal(h.Tier, h.Outage)
	}
}

func TestADegradedReportIsHeldToTheOutagePolicy(t *testing.T) {
	f := newGate(t)
	tier1 := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	cases := []struct {
		ev       store.Event
		action   string
		source   string
		conforms bool
	}{
		{degradedOf(f, "allow", nil, tier1.ID), gate.OutageAllow, "change", true},
		{degradedOf(f, "allow", 1, ""), gate.OutageAllow, "baseline", true},
		{degradedOf(f, "allow", 2, ""), gate.OutageHold, "baseline", false},
		{degradedOf(f, "allow", nil, ""), gate.OutageHold, "unknown-tier", false},
		{degradedOf(f, "deny", 3, ""), gate.OutageHold, "baseline", true},
	}
	for i, c := range cases {
		rec := f.report(t, c.ev)
		op := rec["outage_policy"].(map[string]any)
		if op["action"] != c.action || op["source"] != c.source || op["conforms"] != c.conforms {
			t.Fatalf("case %d: %v", i, op)
		}
		if rec["coverage"] != "coverage-unavailable" || rec["boundary"] != "deployment" ||
			!slices.Contains(anyStrs(rec["verified"]), "outage_policy") || !slices.Contains(anyStrs(rec["claimed"]), "decision") {
			t.Fatalf("case %d: %v", i, rec)
		}
	}
	// shape refusals
	for _, edit := range []func(store.Event){
		func(e store.Event) { e["coverage"] = "authorized-and-verified" },
		func(e store.Event) { delete(e, "outage") },
		func(e store.Event) {
			e["outage"] = map[string]any{"from": "2026-09-26T12:00:00Z", "to": "2026-09-26T11:00:00Z"}
		},
		func(e store.Event) {
			e["outage"] = map[string]any{"from": "2026-09-26T11:00:00Z", "to": "2030-01-01T00:00:00Z"}
		},
		func(e store.Event) { e["decision"] = "maybe" },
		func(e store.Event) { e["rule"] = "R001" },
		func(e store.Event) { delete(e, "destination") },
		func(e store.Event) { e["change"] = map[string]any{"id": "nope"} },
	} {
		e := degradedOf(f, "allow", 1, "")
		edit(e)
		var br *gate.BadReport
		if _, err := f.svc.Report(f.ctx, e, argoWriter); !errors.As(err, &br) {
			t.Fatalf("%v accepted: %v", e, err)
		}
	}
}

func anyStrs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestEveryExceptionKindHasItsShapeAndCoverage(t *testing.T) {
	f := newGate(t)
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	for _, kind := range gate.ExceptionKinds {
		id := ""
		if kind == "digest-mismatch" {
			id = c.ID
		}
		rec := f.report(t, exceptionOf(f, kind, id))
		if rec["coverage"] != gate.ExceptionCoverage[kind] || rec["exception"].(map[string]any)["kind"] != kind {
			t.Fatalf("%s: %v", kind, rec)
		}
	}
	for kind, x := range map[string]map[string]any{
		"out-of-band":     {"kind": "out-of-band"},
		"drift":           {"kind": "drift"},
		"untraced-apply":  {"kind": "untraced-apply"},
		"digest-mismatch": {"kind": "digest-mismatch", "expected": "a", "observed": "b"}, // no change.id
		"unknown kind":    {"kind": "sideways"},
		"unknown field":   {"kind": "drift", "addresses": []any{"x"}, "colour": "red"},
		"bad object":      {"kind": "out-of-band", "objects": []any{map[string]any{"kind": "Deployment"}}},
	} {
		e := exceptionOf(f, "drift", "")
		e["exception"] = x
		var br *gate.BadReport
		if _, err := f.svc.Report(f.ctx, e, argoWriter); !errors.As(err, &br) {
			t.Fatalf("%s accepted: %v", kind, err)
		}
	}
	e := exceptionOf(f, "drift", "")
	e["coverage"] = "authorized-and-verified"
	if _, err := f.svc.Report(f.ctx, e, argoWriter); err == nil {
		t.Fatal("an exception claiming full coverage was accepted")
	}
}

// -- break-glass ---------------------------------------------------------------------------------------------------

var glass = gate.BreakglassRequest{Reason: "prod is down; rolling back by hand", TTL: "1h", Cluster: "hangar-prod", Env: "prod"}

func TestBreakGlassIsForAdminsWithABoundedTTL(t *testing.T) {
	f := newGate(t)
	f.svc.Config.Protected = []string{"hangar-prod/prod"}
	rule := func(err error) string { r, _ := ruleOf(err); return r }
	if _, err := f.svc.OpenBreakglass(f.ctx, principals["dana"], glass, ""); rule(err) != "DG-BREAKGLASS" {
		t.Fatal(err)
	}
	if _, err := f.svc.OpenBreakglass(f.ctx, principals["tower"], glass, "user:dana"); rule(err) != "DG-BREAKGLASS" {
		t.Fatal("a delegate naming a non-admin broke glass", err)
	}
	if _, err := f.svc.OpenBreakglass(f.ctx, principals["ci"], glass, ""); rule(err) != "DG-PERSON" {
		t.Fatal("a workload broke glass", err)
	}
	if _, err := f.svc.OpenBreakglass(f.ctx, principals["other"], glass, "user:root"); rule(err) != "DG-DELEGATE" {
		t.Fatal("a non-delegate named an admin", err)
	}
	for _, ttl := range []string{"5h", "4h1s", "30s", "soon", "-1h"} {
		g := glass
		g.TTL = ttl
		if _, err := f.svc.OpenBreakglass(f.ctx, principals["root"], g, ""); rule(err) != "DG-BREAKGLASS-TTL" {
			t.Fatal(ttl, err)
		}
	}
	f.svc.Config.BreakglassMaxTTL = 30 * time.Minute
	if _, err := f.svc.OpenBreakglass(f.ctx, principals["root"], glass, ""); rule(err) != "DG-BREAKGLASS-TTL" {
		t.Fatal("the deployment's cap is not applied", err)
	}
	f.svc.Config.BreakglassMaxTTL = 0
	g := glass
	g.Reason = " "
	if _, err := f.svc.OpenBreakglass(f.ctx, principals["root"], g, ""); rule(err) != "DG-REASON" {
		t.Fatal(err)
	}
	g = glass
	g.Env = "dev"
	if _, err := f.svc.OpenBreakglass(f.ctx, principals["root"], g, ""); rule(err) != "DG-BREAKGLASS-SCOPE" {
		t.Fatal("glass broken on an unprotected environment", err)
	}
	if len(f.records(t, "")) != 0 {
		t.Fatal("a refused break-glass was recorded")
	}
	b, err := f.svc.OpenBreakglass(f.ctx, principals["tower"], glass, "user:root")
	if err != nil || b.Person != "user:root" || *b.Via != tower || b.TTLSeconds != 3600 || b.State != "open" {
		t.Fatal(b, err)
	}
	if _, err := f.svc.OpenBreakglass(f.ctx, principals["root"], glass, ""); rule(err) != "DG-BREAKGLASS-OPEN" {
		t.Fatal("two windows on one environment", err)
	}
	opened := f.records(t, gate.ToolBreakglassOpen)
	if len(opened) != 1 || opened[0]["principal"] != "user:root" || opened[0]["result"] != "break-glass opened on hangar-prod/prod for 1h0m0s via "+tower ||
		opened[0]["reason"] != glass.Reason || slices.Contains(anyStrs(opened[0]["verified"]), "initiator") {
		t.Fatal(opened)
	}
}

func TestBreakGlassIsRecordedBeforeTheChangeAndReconciledAtItsTTL(t *testing.T) {
	f, _ := withTokens(t)
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	b, err := f.svc.OpenBreakglass(f.ctx, principals["root"], glass, "")
	if err != nil {
		t.Fatal(err)
	}
	opened := f.records(t, gate.ToolBreakglassOpen)
	if len(opened) != 1 || opened[0]["seq"] == nil {
		t.Fatal(opened)
	}
	openSeq, _ := gate.SeqInt(opened[0]["seq"])
	if openSeq != b.OpenSeq || !slices.Contains(anyStrs(opened[0]["verified"]), "initiator") {
		t.Fatal(b.OpenSeq, opened[0])
	}
	// the change the glass covers: a hand-made rollback the Argo agent sees as out of band
	f.clock.advance(10 * time.Minute)
	ex := f.report(t, exceptionOf(f, "out-of-band", ""))
	exSeq, _ := gate.SeqInt(ex["seq"])
	if exSeq <= openSeq || ex["breakglass"] != b.ID || !slices.Contains(anyStrs(ex["verified"]), "breakglass") {
		t.Fatalf("the exception does not follow the window or name it: %v", ex)
	}
	// it clears nothing: a cleared change the exception names still leaves cleared
	f.report(t, exceptionOf(f, "digest-mismatch", c.ID))
	if f.get(t, c.ID).State != gate.StateException {
		t.Fatal(f.get(t, c.ID).State)
	}
	// another environment's exception is not the window's
	other := exceptionOf(f, "drift", "")
	other["destination"] = map[string]any{"cluster": "hangar-dev", "environment": "dev"}
	if r := f.report(t, other); r["breakglass"] != nil {
		t.Fatal(r)
	}
	if ws, _ := f.svc.OpenBreakglassWindows(f.ctx, "hangar-prod"); len(ws) != 1 || ws[0].ID != b.ID {
		t.Fatal(ws)
	}
	if ws, _ := f.svc.OpenBreakglassWindows(f.ctx, "hangar-dev"); len(ws) != 0 {
		t.Fatal(ws)
	}
	// before the TTL nothing closes
	if ids, err := f.svc.ReconcileBreakglass(f.ctx); err != nil || len(ids) != 0 {
		t.Fatal(ids, err)
	}
	f.clock.advance(time.Hour)
	ids, err := f.svc.ReconcileBreakglass(f.ctx)
	if err != nil || !slices.Equal(ids, []string{b.ID}) {
		t.Fatal(ids, err)
	}
	closed := f.records(t, gate.ToolBreakglassClose)
	if len(closed) != 1 {
		t.Fatal(closed)
	}
	cl := closed[0]
	listed := cl["changes"].([]any)
	if cl["principal"] != "policy" || cl["reported"] != json.Number("2") || len(listed) != 2 ||
		listed[0].(map[string]any)["seq"] != ex["seq"] || listed[0].(map[string]any)["kind"] != "out-of-band" ||
		cl["limitations"] != gate.BreakglassLimitation || cl["truncated"] != false {
		t.Fatalf("%v", cl)
	}
	w := cl["window"].(map[string]any)
	if w["from"] != evidence.ISO(b.OpenedAt) || w["to"] != evidence.ISO(b.ExpiresAt) {
		t.Fatal(w)
	}
	if !strings.HasPrefix(cl["result"].(string), "break-glass "+b.ID+" closed (ttl): 2 records in the window, 2 of them exceptions") {
		t.Fatal(cl["result"])
	}
	row, err := f.st.Breakglass(f.ctx, b.ID)
	if err != nil || row.State != "closed" {
		t.Fatal(row, err)
	}
	if ws, _ := f.svc.OpenBreakglassWindows(f.ctx, ""); len(ws) != 0 {
		t.Fatal(ws)
	}
	// after it closed, a new exception is not tagged, and a closed window cannot close again
	if r := f.report(t, exceptionOf(f, "out-of-band", "")); r["breakglass"] != nil {
		t.Fatal(r)
	}
	if _, err := f.svc.CloseBreakglass(f.ctx, principals["root"], b.ID, ""); func() string { r, _ := ruleOf(err); return r }() != "DG-STATE" {
		t.Fatal(err)
	}
	if _, err := memory_load(f); err != nil {
		t.Fatal(err)
	}
}

func TestAnAdminClosesBreakGlassEarly(t *testing.T) {
	f := newGate(t)
	b, err := f.svc.OpenBreakglass(f.ctx, principals["root"], glass, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CloseBreakglass(f.ctx, principals["dana"], b.ID, ""); func() string { r, _ := ruleOf(err); return r }() != "DG-BREAKGLASS" {
		t.Fatal(err)
	}
	if _, err := f.svc.CloseBreakglass(f.ctx, principals["root"], "bg-0000000000000000", ""); func() string { r, _ := ruleOf(err); return r }() != "DG-UNKNOWN" {
		t.Fatal(err)
	}
	f.clock.advance(5 * time.Minute)
	out, err := f.svc.CloseBreakglass(f.ctx, principals["root"], b.ID, "")
	if err != nil || out.State != "closed" || *out.ClosedBy != "user:root" || *out.Reported != 0 || !out.ClosedAt.Equal(f.clock.now()) {
		t.Fatal(out, err)
	}
	cl := f.records(t, gate.ToolBreakglassClose)
	if len(cl) != 1 || cl[0]["principal"] != "user:root" || len(cl[0]["changes"].([]any)) != 0 {
		t.Fatal(cl)
	}
	// a window can be opened again once closed
	if _, err := f.svc.OpenBreakglass(f.ctx, principals["root"], glass, ""); err != nil {
		t.Fatal(err)
	}
}

func TestBreakGlassHTTP(t *testing.T) {
	f := newGate(t)
	mux := serve(f)
	body := map[string]any{"reason": glass.Reason, "ttl": "30m", "cluster": "hangar-prod", "env": "prod"}
	if code, _ := call(mux, "POST", "/v1/breakglass", "", body, nil); code != 401 {
		t.Fatal(code)
	}
	if code, out := call(mux, "POST", "/v1/breakglass", "dana", body, nil); code != 403 || out["rule"] != "DG-BREAKGLASS" {
		t.Fatal(code, out)
	}
	if code, _ := call(mux, "POST", "/v1/breakglass", "root", map[string]any{"reason": "x", "ttl": "1h", "cluster": "a",
		"env": "b", "user": "user:someone"}, nil); code != 400 {
		t.Fatal("an unknown field (a free-text user) was accepted", code)
	}
	code, out := call(mux, "POST", "/v1/breakglass", "root", body, nil)
	if code != 200 || out["state"] != "open" || out["person"] != "user:root" {
		t.Fatal(code, out)
	}
	if code, out := call(mux, "POST", "/v1/breakglass", "root", body, nil); code != 409 || out["rule"] != "DG-BREAKGLASS-OPEN" {
		t.Fatal(code, out)
	}
	code, out = call(mux, "POST", "/v1/breakglass/"+out["id"].(string)+"/close", "root", nil, nil)
	if code != 200 || out["state"] != "closed" {
		t.Fatal(code, out)
	}
}

func TestAnAppWindowTagsOnlyThatAppsReports(t *testing.T) {
	f := newGate(t)
	g := glass
	app := "gate-api"
	g.App = &app
	b, err := f.svc.OpenBreakglass(f.ctx, principals["root"], g, "")
	if err != nil {
		t.Fatal(err)
	}
	if r := f.report(t, exceptionOf(f, "out-of-band", "")); r["breakglass"] != b.ID {
		t.Fatal("the window's own app is not tagged", r)
	}
	other := exceptionOf(f, "out-of-band", "")
	other["app"] = "flight-api"
	if r := f.report(t, other); r["breakglass"] != nil {
		t.Fatal("another app's report was tagged", r)
	}
	// a window per environment, whatever its app
	if _, err := f.svc.OpenBreakglass(f.ctx, principals["root"], glass, ""); func() string { r, _ := ruleOf(err); return r }() != "DG-BREAKGLASS-OPEN" {
		t.Fatal(err)
	}
}

func TestAPreC6ChangeIsHeldToTheBaseline(t *testing.T) {
	f := newGate(t)
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	row, _ := f.st.Change(f.ctx, c.ID)
	var m map[string]any
	_ = json.Unmarshal(row.Record, &m)
	delete(m, "outage")
	raw, _ := json.Marshal(m)
	row.Record = raw
	if err := f.st.Atomic(f.ctx, func(tx store.Tx) error { return tx.PutChange(f.ctx, row) }); err != nil {
		t.Fatal(err)
	}
	op := f.report(t, degradedOf(f, "allow", nil, c.ID))["outage_policy"].(map[string]any)
	if op["source"] != "baseline" || op["action"] != gate.OutageAllow {
		t.Fatal(op)
	}
}

// A Terraform plan has no cluster: a report about one names destination.workspace {backend, key, name} (G-TF-5).
func TestReportLocatedByWorkspace(t *testing.T) {
	f := newGate(t)
	ws := func() map[string]any {
		return map[string]any{"workspace": map[string]any{"backend": "s3", "key": "prod/network.tfstate", "name": "default"}}
	}
	plan := func(dest map[string]any) store.Event {
		ev := exceptionOf(f, "drift", "")
		ev["destination"] = dest
		return ev
	}
	rec := f.report(t, plan(ws()))
	if rec["coverage"] != "observed-not-attributed" {
		t.Fatal(rec["coverage"])
	}
	// the gitops path is unchanged: cluster and environment are still required
	for _, d := range []map[string]any{
		{"cluster": "hangar-prod"}, {"environment": "prod"}, {},
		{"workspace": map[string]any{"backend": "s3", "key": "k"}},                                  // no name
		{"workspace": map[string]any{"backend": "s3", "key": "k", "name": "default", "extra": "x"}}, // unknown field
		{"workspace": map[string]any{"backend": "S3", "key": "k", "name": "default"}},               // bad backend
		{"workspace": ws()["workspace"], "cluster": "hangar-prod", "environment": "prod"},           // both
	} {
		var br *gate.BadReport
		if _, err := f.svc.Report(f.ctx, plan(d), argoWriter); !errors.As(err, &br) {
			t.Fatalf("%v: %v", d, err)
		}
	}
	f.report(t, exceptionOf(f, "drift", "")) // cluster + environment, as before
}
