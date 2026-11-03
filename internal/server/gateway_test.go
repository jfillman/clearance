package server_test

// What the Autopilot gateway needs of the core before the hangar-dev cutover (R-3e): the record kinds it holds in
// its outbox, a person's run opened through a delegate, a handler's refusal on an outcome, and its cluster-pinned
// agent definitions published to the core.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
)

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (f *fixture) last() map[string]any {
	f.t.Helper()
	recs := f.records()
	if len(recs) == 0 {
		f.t.Fatal("no records")
	}
	return recs[len(recs)-1]
}

// -- POST /v1/records: the kinds the gateway held --------------------------------------------------------------------

// Each kind's fields are what the Python gateway recorded for it at clearance v0.26.1 (dispatch.py finish_run,
// _backstop_outcomes, end_session, release_triggers via _control_record, and the outage read), less what the core
// sets (ts, tool, the envelope).
func gatewayKinds() map[string]map[string]any {
	digest := strings.Repeat("b", 64)
	return map[string]map[string]any{
		"run.finish": {"task_id": "t-1", "session": "s-1", "parent": "s-0", "principal": "autopilot-runs/x",
			"agent": "x", "decision": "allow", "args_sha256": digest, "result": "succeeded"},
		"session.end": {"task_id": "t-1", "session": "s-1", "principal": "user:jfillman", "agent": "x",
			"decision": "allow", "target": "s-1", "args_sha256": digest, "result": "ended: runaway via tower/backstage"},
		"trigger.release": {"principal": "user:jfillman", "agent": "x", "decision": "allow", "target": "x",
			"args_sha256": digest, "result": "released (held by user:jfillman since 2026-11-01T00:00:00Z: noisy)"},
		server.OutageKind: {"task_id": "t-1", "session": "s-1", "principal": "user:alice", "agent": "coding-agent",
			"tool": "catalog.read", "tier": 0, "decision": "allow", "target": nil, "args_sha256": digest,
			"result": "ok", "coverage": server.CoverageUnavailable,
			"reason": "the core was unreachable at 2026-11-03T10:00:00Z; allowed as an unscoped T0 read"},
	}
}

func recordBody(kind string, rec map[string]any) map[string]any {
	clean := map[string]any{}
	for k, v := range rec {
		if v != nil {
			clean[k] = v
		}
	}
	return map[string]any{"provider": "autopilot-gateway", "kind": kind, "record": clean}
}

func TestTheGatewaysHeldKindsAreRecorded(t *testing.T) {
	f := memFixture(t)
	for kind, rec := range gatewayKinds() {
		a := f.do("POST", "/v1/records", gw, recordBody(kind, rec)).want(t, 200, "")
		r := f.last()
		if r["hash"] != a.body["hash"] || r["boundary"] != "runtime" || r["provider"].(map[string]any)["name"] != "autopilot-gateway" {
			t.Fatalf("%s: %v", kind, r)
		}
		if v := anyStrings(r["verified"]); !slices.Equal(v, []string{"provider", "ts"}) {
			t.Errorf("%s: verified %v: everything but provider and ts is the provider's claim", kind, v)
		}
		for k, want := range rec {
			if k == "tier" {
				if fmt.Sprint(r[k]) != fmt.Sprint(want) {
					t.Errorf("%s: tier %v", kind, r[k])
				}
				continue
			}
			if r[k] != want && !(want == nil && r[k] == nil) {
				t.Errorf("%s: %s = %v, sent %v", kind, k, r[k], want)
			}
		}
		if kind == server.OutageKind {
			sub := r["subject"].(map[string]any)
			if r["tool"] != "catalog.read" || r["coverage"] != server.CoverageUnavailable || sub["kind"] != "tool-call" ||
				sub["name"] != "catalog.read" || sub["digests"].(map[string]any)["sha256"] != rec["args_sha256"] ||
				!slices.Contains(anyStrings(r["claimed"]), "subject") {
				t.Errorf("an outage read: %v", r)
			}
		} else if r["tool"] != kind || r["coverage"] != "authorized-and-verified" {
			t.Errorf("%s: tool %v coverage %v", kind, r["tool"], r["coverage"])
		}
	}
	verifyChainLen(t, f, 4)
}

func verifyChainLen(t *testing.T, f *fixture, n int) {
	t.Helper()
	recs := f.records()
	if len(recs) != n {
		t.Fatalf("%d records, want %d", len(recs), n)
	}
	if ok, bad := evidence.Verify(recs); !ok {
		t.Fatalf("the chain breaks at %d", bad)
	}
}

func TestTheGatewaysHeldKindsAreRefusedWithoutWhatTheyCarry(t *testing.T) {
	f := memFixture(t)
	required := map[string][]string{
		"run.finish":      {"session", "task_id", "principal", "agent", "args_sha256", "result"},
		"session.end":     {"session", "principal", "agent", "target", "result"},
		"trigger.release": {"principal", "agent", "target", "result"},
		server.OutageKind: {"session", "task_id", "principal", "agent", "tool", "tier", "args_sha256", "result", "coverage"},
	}
	for kind, fields := range required {
		for _, k := range fields {
			rec := gatewayKinds()[kind]
			delete(rec, k)
			f.do("POST", "/v1/records", gw, recordBody(kind, rec)).want(t, 400, "carries "+k)
		}
	}
	outage := func(edit func(map[string]any)) map[string]any {
		rec := gatewayKinds()[server.OutageKind]
		edit(rec)
		return recordBody(server.OutageKind, rec)
	}
	for _, c := range []struct {
		edit func(map[string]any)
		says string
	}{
		{func(r map[string]any) { r["coverage"] = "authorized-and-verified" }, "coverage is coverage-unavailable"},
		{func(r map[string]any) { r["coverage"] = "observed-not-attributed" }, "coverage is coverage-unavailable"},
		{func(r map[string]any) { r["tool"] = "repo.pr.open"; r["tier"] = 1 }, "only a T0 read"},
		{func(r map[string]any) { r["tool"] = "k8s.exec" }, "not a tool the core knows"},
		{func(r map[string]any) { r["tier"] = 1 }, "tier is 0"},
		{func(r map[string]any) { r["decision"] = "deny" }, "decision is allow"},
		{func(r map[string]any) { r["rule"] = "R014" }, "carries no rule"},
		{func(r map[string]any) {
			r["subject"] = map[string]any{"kind": "tool-call", "digests": map[string]any{"sha256": strings.Repeat("c", 64)}}
		}, "subject is the core's"},
		{func(r map[string]any) { r["effect"] = map[string]any{"repo": "a/b"} }, "is a read"},
		{func(r map[string]any) { r["outcome"] = map[string]any{"applied": true} }, "is a read"},
	} {
		f.do("POST", "/v1/records", gw, outage(c.edit)).want(t, 400, c.says)
	}
	// tool names the called tool on a tool.call record only.
	rec := gatewayKinds()["run.finish"]
	rec["tool"] = "catalog.read"
	f.do("POST", "/v1/records", gw, recordBody("run.finish", rec)).want(t, 400, "tool is set on a tool.call record only")
	// The definition.* kinds are the core's own (PUT /v1/definitions): a provider does not post them.
	for _, k := range []string{"definition.load", "definition.unload", "definition.reject"} {
		f.do("POST", "/v1/records", gw, recordBody(k, map[string]any{"principal": "p", "agent": "a", "result": "r"})).
			want(t, 400, "is not one of")
	}
	// A provider narrowed by kinds may not write them.
	f.do("POST", "/v1/records", argo, map[string]any{"provider": "argo-gate", "kind": "run.finish",
		"record": gatewayKinds()["run.finish"]}).want(t, 403, "may not write run.finish")
	if n := len(f.records()); n != 0 {
		t.Fatalf("a refused record was written: %d", n)
	}
}

// -- session.open: a person's run, through a delegate --------------------------------------------------------------

const openAllowed = 3 // session.open coding-agent by user:alice, allowed (no packs)

func TestAPersonsRunRecordsTheDelegateAsPythonDid(t *testing.T) {
	f := memFixture(t)
	run := func(props map[string]any) map[string]any {
		f.evaluate(openAllowed, func(m map[string]any) { m["action"].(map[string]any)["properties"] = props })
		return f.last()
	}
	// Gateway.run_agent at v0.26.1: args_sha256({"via": via}), result "opened to run" + " via <delegate>".
	r := run(map[string]any{"run": true, "via": "tower/backstage"})
	if r["result"] != "opened to run via tower/backstage" || r["args_sha256"] != sha(`{"via":"tower/backstage"}`) ||
		r["tool"] != "session.open" || r["decision"] != "allow" || r["principal"] != "user:alice" {
		t.Fatal(r)
	}
	r = run(map[string]any{"run": true})
	if r["result"] != "opened to run" || r["args_sha256"] != sha(`{"via":null}`) {
		t.Fatal(r)
	}
	// An MCP open is unchanged: args {"limits": {}}, "opened".
	r = run(map[string]any{})
	if r["result"] != "opened" || r["args_sha256"] != sha(`{"limits":{}}`) {
		t.Fatal(r)
	}
	n := len(f.records())
	for _, c := range []struct {
		props map[string]any
		says  string
	}{
		{map[string]any{"via": "tower/backstage"}, "it needs run"},
		{map[string]any{"run": true, "trigger": "cron"}, "not a triggered open"},
		{map[string]any{"run": true, "limits": map[string]any{"tool_calls": 5}}, "asks for no limits"},
		{map[string]any{"run": true, "via": strings.Repeat("x", 257)}, "via is a principal id"},
		{map[string]any{"run": true, "via": "tower/\nbackstage"}, "via is a principal id"},
		{map[string]any{"run": "yes"}, "bad request"},
	} {
		f.do("POST", "/access/v1/evaluation", gw, request(t, openAllowed, func(m map[string]any) {
			m["action"].(map[string]any)["properties"] = c.props
		})).want(t, 400, c.says)
	}
	f.do("POST", "/access/v1/evaluation", gw, request(t, prOpenAllowed, func(m map[string]any) {
		m["action"].(map[string]any)["properties"].(map[string]any)["run"] = true
	})).want(t, 400, "session.open properties")
	if len(f.records()) != n {
		t.Fatal("a refused evaluation was recorded")
	}
}

// -- an outcome's refusal ------------------------------------------------------------------------------------------

func TestAnOutcomeCarriesAHandlersRefusal(t *testing.T) {
	f := memFixture(t)
	id := decisionID(t, f.evaluate(prOpenAllowed, nil))
	bad := []struct {
		body map[string]any
		says string
	}{
		{map[string]any{"result": "refused", "refusal": map[string]any{"rule": "hr-003", "message": "m"}}, "refusal.rule"},
		{map[string]any{"result": "refused", "refusal": map[string]any{"rule": "HR-003", "message": ""}}, "refusal.message"},
		{map[string]any{"result": "refused", "refusal": map[string]any{"rule": "HR-003"}}, "refusal.message"},
		{map[string]any{"result": "refused", "refusal": map[string]any{"rule": "HR-003", "message": "m", "x": 1}}, "unknown field"},
		{map[string]any{"result": "refused", "refusal": map[string]any{"rule": "HR-003", "message": "m"},
			"effect": map[string]any{"repo": "a/b"}}, "do not go together"},
	}
	for _, c := range bad {
		f.do("POST", "/v1/decisions/"+id+"/outcome", gw, c.body).want(t, 400, c.says)
	}
	f.do("POST", "/v1/decisions/"+id+"/outcome", gw, map[string]any{"result": "refused R004: no live session",
		"refusal": map[string]any{"rule": "R004", "message": "no live session"}}).want(t, 200, "")
	r := f.last()
	ref := r["refusal"].(map[string]any)
	if ref["rule"] != "R004" || ref["message"] != "no live session" || r["decision"] != "allow" || r["rule"] != nil {
		t.Fatal(r)
	}
	if !slices.Contains(anyStrings(r["claimed"]), "refusal") || !slices.Contains(anyStrings(r["verified"]), "decision") {
		t.Fatalf("verified %v claimed %v", r["verified"], r["claimed"])
	}
	verifyChainLen(t, f, 2)
}

// -- PUT /v1/definitions -------------------------------------------------------------------------------------------

const pinCommit = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"

// codingAgent is tests/fixtures/agents/coding-agent.yaml with an owner: the agent corpus line prOpenAllowed's
// session runs.
func codingAgent(owner string) map[string]any {
	return map[string]any{
		"name": "coding-agent", "owner": owner,
		"description": "Makes a change in an app's repository and opens it as a pull request for a person to merge.",
		"kind":        "task", "identity": map[string]any{"type": "delegated"},
		"profile": map[string]any{"tierCeiling": "T1",
			"tools": []any{"catalog.read", "metrics.query", "logs.query", "argo.app.get", "repo.pr.open", "xr.request",
				"argo.sync.lower", "glidepath.run.rerun", "glidepath.run.cancel", "run.spawn", "run.close",
				"human.request", "repo.pr.open_upper"},
			"repos": map[string]any{"allow": []any{"jfillman/*"}}, "models": []any{"claude-sonnet-5"},
			"network": "clearance+model", "compute": "small",
			"limits": map[string]any{"ttlMinutes": 30, "toolCalls": 200, "githubCalls": 300, "openPrs": 3,
				"modelTokens": 500000, "children": 2}},
		"runtime": map[string]any{"image": "ghcr.io/jfillman/agent-coding@sha256:" + strings.Repeat("e3", 32),
			"framework": "claude-agent-sdk", "sandbox": "standard"},
		"triggers": []any{map[string]any{"type": "manual"}},
	}
}

func pinSource(xr string) map[string]any {
	return map[string]any{"repo": "jfillman/gate-api", "path": "agents/" + xr + ".yaml", "commit": pinCommit,
		"namespace": "app-gate-api-cicd", "xr": xr, "loaded_at": "2026-11-03T10:00:00Z"}
}

func publish(pins []any, rejected []any) map[string]any {
	b := map[string]any{"provider": "autopilot-gateway", "pins": pins}
	if rejected != nil {
		b["rejected"] = rejected
	}
	return b
}

func scopeStatus(t *testing.T, f *fixture) string {
	t.Helper()
	pv := f.do("POST", "/v1/provenance", ci, map[string]any{"repo": "jfillman/gate-api", "pr": 32, "head": headSHA,
		"paths": []string{"app.js"}, "author": vocabtest.AgentLogin}).want(t, 200, "")
	return fmt.Sprint(pv.body["scope"].(map[string]any)["status"], " ", pv.body["scope"].(map[string]any)["rule"])
}

func TestPublishedDefinitionsAreRecordedOnceAndProvenanceReadsThem(t *testing.T) {
	f := memFixture(t)
	id := decisionID(t, f.evaluate(prOpenAllowed, nil))
	f.do("POST", "/v1/decisions/"+id+"/outcome", gw, effectBody()).want(t, 200, "")
	if s := scopeStatus(t, f); !strings.Contains(s, "AS004") {
		t.Fatalf("before the publish provenance should find no definition: %s", s)
	}
	team := "group:default/team-gate"
	pin := map[string]any{"source": pinSource("coding-agent"), "owner": team, "doc": codingAgent(team)}
	a := f.do("PUT", "/v1/definitions", gw, publish([]any{pin}, nil)).want(t, 200, "")
	if fmt.Sprint(a.body["added"]) != "[coding-agent]" || a.body["cluster"] != float64(1) {
		t.Fatal(a.body)
	}
	r := f.last()
	if r["tool"] != "definition.load" || r["agent"] != "coding-agent" || r["principal"] != "pin:app-gate-api-cicd/coding-agent" ||
		r["target"] != "jfillman/gate-api@1a2b3c4 agents/coding-agent.yaml" || r["result"] != "loaded jfillman/gate-api@1a2b3c4 agents/coding-agent.yaml" ||
		r["decision"] != "allow" || r["provider"].(map[string]any)["name"] != evidence.CoreProviderName {
		t.Fatal(r)
	}
	if c := r["caller"].(map[string]any); c["provider"] != "autopilot-gateway" || c["principal"] != gw {
		t.Fatal(c)
	}
	ver, cl := anyStrings(r["verified"]), anyStrings(r["claimed"])
	for _, k := range []string{"provider", "ts", "caller", "tool", "decision"} {
		if !slices.Contains(ver, k) {
			t.Errorf("%s is not verified: %v", k, ver)
		}
	}
	for _, k := range []string{"principal", "agent", "target", "args_sha256", "result", "subject"} {
		if !slices.Contains(cl, k) {
			t.Errorf("%s is not claimed: %v", k, cl)
		}
	}
	if sub := r["subject"].(map[string]any); sub["kind"] != "definition" {
		t.Fatal(sub)
	}
	if s := scopeStatus(t, f); !strings.Contains(s, "in-scope") {
		t.Fatalf("provenance does not see the published definition: %s", s)
	}
	n := len(f.records())

	// The same set again: nothing changes, nothing is recorded (once per change, never once per poll).
	a = f.do("PUT", "/v1/definitions", gw, publish([]any{pin}, nil)).want(t, 200, "")
	if fmt.Sprint(a.body["added"], a.body["changed"], a.body["removed"]) != "[] [] []" || len(f.records()) != n {
		t.Fatal(a.body)
	}

	// A pin the core refuses (the file's owner is not the XR's), and one the provider could not load.
	other := map[string]any{"source": pinSource("coding-agent"), "owner": "group:default/team-other", "doc": codingAgent(team)}
	broken := map[string]any{"name": "half-pin", "source": map[string]any{"repo": "", "path": "", "commit": "", "xr": "half-pin"},
		"reason": "the XR has no complete spec.source (repo, path, commit)"}
	a = f.do("PUT", "/v1/definitions", gw, publish([]any{other}, []any{broken})).want(t, 200, "")
	if fmt.Sprint(a.body["removed"]) != "[coding-agent]" || len(a.body["rejected"].([]any)) != 2 || a.body["cluster"] != float64(0) {
		t.Fatal(a.body)
	}
	recs := f.records()[n:]
	var tools []string
	for _, r := range recs {
		tools = append(tools, fmt.Sprint(r["tool"], " ", r["agent"], " ", r["rule"]))
	}
	if fmt.Sprint(tools) != "[definition.unload coding-agent <nil> definition.reject coding-agent DF-PIN definition.reject half-pin DF-PIN]" {
		t.Fatal(tools)
	}
	if !strings.Contains(fmt.Sprint(recs[1]["result"]), "the pin's owner is 'group:default/team-other'") {
		t.Fatalf("the core's own reason: %v", recs[1]["result"])
	}
	if s := scopeStatus(t, f); !strings.Contains(s, "AS004") {
		t.Fatalf("an unpinned definition is gone for provenance: %s", s)
	}
	// An empty set unpins everything; the rejections clear without a record.
	m := len(f.records())
	a = f.do("PUT", "/v1/definitions", gw, publish([]any{}, nil)).want(t, 200, "")
	if len(a.body["cleared"].([]any)) != 2 || len(f.records()) != m {
		t.Fatal(a.body)
	}
	verifyChainLen(t, f, len(f.records()))
}

func TestPublishingDefinitionsIsRefused(t *testing.T) {
	team := "group:default/team-gate"
	good := func() map[string]any {
		return publish([]any{map[string]any{"source": pinSource("coding-agent"), "owner": team, "doc": codingAgent(team)}}, nil)
	}
	with := func(edit func(m map[string]any)) map[string]any { m := good(); edit(m); return m }
	pin0 := func(m map[string]any) map[string]any { return m["pins"].([]any)[0].(map[string]any) }
	f := memFixture(t)
	f.do("PUT", "/v1/definitions", argo, with(func(m map[string]any) { m["provider"] = "argo-gate" })).
		want(t, 403, "may not publish definitions")
	f.do("PUT", "/v1/definitions", gw, with(func(m map[string]any) { m["provider"] = "argo-gate" })).
		want(t, 403, "not the registered provider")
	f.do("PUT", "/v1/definitions", "someone/else", good()).want(t, 403, "not a registered provider")
	f.do("PUT", "/v1/definitions", "", good()).want(t, 401, "")
	f.do("PUT", "/v1/definitions", gw, with(func(m map[string]any) { m["extra"] = 1 })).want(t, 400, "unknown field")
	f.do("PUT", "/v1/definitions", gw, with(func(m map[string]any) { delete(m, "pins") })).want(t, 400, "pins is required")
	f.do("PUT", "/v1/definitions", gw, with(func(m map[string]any) { pin0(m)["extra"] = 1 })).want(t, 400, "unknown field")
	f.do("PUT", "/v1/definitions", gw, with(func(m map[string]any) { delete(pin0(m), "doc") })).want(t, 400, "doc is")
	for k, v := range map[string]any{"commit": "main", "repo": "gate-api", "xr": "Coding_Agent", "namespace": "", "path": ""} {
		f.do("PUT", "/v1/definitions", gw, with(func(m map[string]any) { pin0(m)["source"].(map[string]any)[k] = v })).
			want(t, 400, k)
	}
	f.do("PUT", "/v1/definitions", gw, with(func(m map[string]any) { delete(pin0(m)["source"].(map[string]any), "commit") })).
		want(t, 400, "commit is required")
	f.do("PUT", "/v1/definitions", gw, with(func(m map[string]any) { pin0(m)["source"].(map[string]any)["kind"] = "bundled" })).
		want(t, 400, "unknown field")
	f.do("PUT", "/v1/definitions", gw, with(func(m map[string]any) {
		m["rejected"] = []any{map[string]any{"name": "x", "source": map[string]any{}, "reason": ""}}
	})).want(t, 400, "reason")
	f.do("PUT", "/v1/definitions", gw, with(func(m map[string]any) {
		pins := make([]any, server.MaxPins+1)
		for i := range pins {
			pins[i] = pin0(good())
		}
		m["pins"] = pins
	})).want(t, 400, "at most")
	if n := len(f.records()); n != 0 {
		t.Fatalf("a refused publish was recorded: %d", n)
	}
}

// A schema-invalid document is the core's rejection (profile), not the provider's word.
func TestAPublishedPinIsValidatedByTheCoresSchema(t *testing.T) {
	f := memFixture(t)
	team := "group:default/team-gate"
	doc := codingAgent(team)
	doc["profile"].(map[string]any)["tierCeiling"] = "T9"
	a := f.do("PUT", "/v1/definitions", gw, publish([]any{map[string]any{"source": pinSource("coding-agent"),
		"owner": team, "doc": doc}}, nil)).want(t, 200, "")
	rej := a.body["rejected"].([]any)
	if len(rej) != 1 || !strings.HasPrefix(fmt.Sprint(rej[0].(map[string]any)["reason"]), "schema: ") || a.body["cluster"] != float64(0) {
		t.Fatal(a.body)
	}
	if r := f.last(); r["tool"] != "definition.reject" || r["rule"] != "DF-PIN" {
		t.Fatal(r)
	}
}

// -- the dev chain read ---------------------------------------------------------------------------------------------

func TestTheDevRecordsReadIsOnlyServedWhenAskedFor(t *testing.T) {
	f := memFixture(t)
	f.evaluate(prOpenAllowed, nil)
	f.do("GET", server.DevRecordsPath, gw, nil).want(t, 404, "")
	cfg := config(t, "")
	cfg.DevRecords = true
	g := newFixture(t, cfg)
	g.evaluate(prOpenAllowed, nil)
	g.evaluate(prOpenDenied, nil)
	resp, err := g.srv.Client().Get(g.srv.URL + server.DevRecordsPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("an unauthenticated read: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", g.srv.URL+server.DevRecordsPath+"?from=1&limit=5", nil)
	req.Header.Set("Authorization", "Bearer "+gw)
	resp, err = g.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	err = json.NewDecoder(resp.Body).Decode(&recs)
	resp.Body.Close()
	if err != nil || len(recs) != 1 || recs[0]["seq"] != float64(1) || recs[0]["decision"] != "deny" {
		t.Fatalf("%v %v", recs, err)
	}
	g.do("GET", server.DevRecordsPath+"?from=x", gw, nil).want(t, 400, "from")
	g.do("GET", server.DevRecordsPath+"?limit=0", gw, nil).want(t, 400, "limit")
	cfg.Memory, cfg.DSN = false, "postgres://unused"
	if _, err := core.Build(t.Context(), cfg, nil, quiet); err == nil || !strings.Contains(err.Error(), "in-memory") {
		t.Fatalf("a dev read on a kept store: %v", err)
	}
}

// The published set is kept with the chain: a restarted core reads it back (its provenance sees the pins at once),
// and the gateway's first publish after the restart, the same set, records nothing.
func TestPublishedDefinitionsSurviveARestart(t *testing.T) {
	dsn := pgDSN(t)
	f := newFixture(t, config(t, dsn))
	id := decisionID(t, f.evaluate(prOpenAllowed, nil))
	f.do("POST", "/v1/decisions/"+id+"/outcome", gw, effectBody()).want(t, 200, "")
	team := "group:default/team-gate"
	body := publish([]any{map[string]any{"source": pinSource("coding-agent"), "owner": team, "doc": codingAgent(team)}}, nil)
	f.do("PUT", "/v1/definitions", gw, body).want(t, 200, "")
	n := len(f.records())
	f.core.Close()
	g := newFixture(t, config(t, dsn))
	if s := scopeStatus(t, g); !strings.Contains(s, "in-scope") {
		t.Fatalf("after a restart provenance does not see the stored pin: %s", s)
	}
	m := len(g.records())
	a := g.do("PUT", "/v1/definitions", gw, body).want(t, 200, "")
	if fmt.Sprint(a.body["added"], a.body["changed"]) != "[] []" || len(g.records()) != m || m != n+1 {
		t.Fatalf("%v: %d records, then %d", a.body, m, len(g.records()))
	}
}
