package server_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/profile"
	"github.com/jfillman/clearance/internal/server"
)

// A-4 (AP-C1, AP-C2): a model call's outcome carries the model that answered and its usage; a run's records carry
// the pinned model version and the Preflight result of its definition; run.finish carries the run's cost.

func usageBody() map[string]any {
	return map[string]any{"result": "ok", "model_version": "claude-sonnet-5-5-20261015",
		"usage": map[string]any{"input_tokens": 1200, "output_tokens": 300, "cache_creation_input_tokens": 4000,
			"cache_read_input_tokens": 20000, "charged_tokens": 8500}}
}

func TestAModelCallOutcomeCarriesUsageAndModelVersion(t *testing.T) {
	f := memFixture(t)
	id := decisionID(t, f.evaluate(modelAllowed, nil))
	f.do("POST", "/v1/decisions/"+id+"/outcome", gw, usageBody()).want(t, 200, "")
	recs := f.records()
	out := recs[len(recs)-1]
	if out["tool"] != "model.call" || out["model_version"] != "claude-sonnet-5-5-20261015" {
		t.Fatalf("outcome %v", out)
	}
	u := out["usage"].(map[string]any)
	want := map[string]string{"input_tokens": "1200", "output_tokens": "300", "cache_creation_input_tokens": "4000",
		"cache_read_input_tokens": "20000", "charged_tokens": "8500"}
	for k, v := range want {
		if fmt.Sprint(u[k]) != v {
			t.Errorf("usage.%s = %v, want %s", k, u[k], v)
		}
	}
	// Claimed: the core saw neither the provider's answer nor its meter.
	cl, v := anyStrings(out["claimed"]), anyStrings(out["verified"])
	for _, k := range []string{"usage", "model_version"} {
		if !slices.Contains(cl, k) || slices.Contains(v, k) {
			t.Fatalf("%s: verified %v claimed %v", k, v, cl)
		}
	}
	// The kinds a provider leaves out are recorded as 0, so a reader sums without a missing key.
	id2 := decisionID(t, f.evaluate(modelAllowed, nil))
	f.do("POST", "/v1/decisions/"+id2+"/outcome", gw, map[string]any{"result": "ok",
		"usage": map[string]any{"charged_tokens": 0}}).want(t, 200, "")
	recs = f.records()
	if u := recs[len(recs)-1]["usage"].(map[string]any); fmt.Sprint(u["input_tokens"]) != "0" || len(u) != 5 {
		t.Fatalf("usage %v", u)
	}
	if ok, bad := evidence.Verify(recs); !ok {
		t.Fatalf("chain breaks at %d", bad)
	}
}

func TestUsageRefusals(t *testing.T) {
	f := memFixture(t)
	tool := decisionID(t, f.evaluate(prOpenAllowed, nil))
	model := decisionID(t, f.evaluate(modelAllowed, nil))
	path := func(id string) string { return "/v1/decisions/" + id + "/outcome" }
	f.do("POST", path(tool), gw, usageBody()).want(t, 400, "not a model call")
	f.do("POST", path(tool), gw, map[string]any{"result": "ok", "model_version": "m"}).want(t, 400, "not a model call")
	with := func(edit func(m map[string]any)) map[string]any { m := usageBody(); edit(m); return m }
	f.do("POST", path(model), gw, with(func(m map[string]any) { m["usage"].(map[string]any)["charged_tokens"] = -1 })).
		want(t, 400, "usage.charged_tokens")
	f.do("POST", path(model), gw, with(func(m map[string]any) { m["usage"].(map[string]any)["output_tokens"] = int64(1) << 41 })).
		want(t, 400, "usage.output_tokens")
	f.do("POST", path(model), gw, with(func(m map[string]any) { m["usage"].(map[string]any)["input_tokens"] = 1.5 })).
		want(t, 400, "")
	f.do("POST", path(model), gw, with(func(m map[string]any) { delete(m["usage"].(map[string]any), "charged_tokens") })).
		want(t, 400, "")
	f.do("POST", path(model), gw, with(func(m map[string]any) { m["usage"].(map[string]any)["thinking"] = 1 })).
		want(t, 400, "unknown field")
	f.do("POST", path(model), gw, with(func(m map[string]any) { m["model_version"] = "bad version" })).
		want(t, 400, "model_version")
	f.do("POST", path(model), gw, with(func(m map[string]any) { m["model_version"] = strings.Repeat("m", 201) })).
		want(t, 400, "model_version")
	if n := len(f.records()); n != 2 {
		t.Fatalf("a refused outcome was written: %d records", n)
	}
	f.do("POST", path(model), gw, usageBody()).want(t, 200, "")
}

func runRecord(kind string, extra map[string]any) map[string]any {
	rec := map[string]any{"session": "s-1", "task_id": "t-1", "principal": "autopilot-runs/x", "agent": "researcher",
		"result": "created", "args_sha256": strings.Repeat("a", 64)}
	for k, v := range extra {
		rec[k] = v
	}
	return map[string]any{"provider": "autopilot-gateway", "kind": kind, "record": rec}
}

func TestARunsRecordsCarryModelVersionPreflightAndCost(t *testing.T) {
	f := memFixture(t)
	pf := map[string]any{"result": "not-run", "definition": "researcher"}
	for _, kind := range []string{"session.open", "run.launch", "run.delete"} {
		f.do("POST", "/v1/records", gw, runRecord(kind, map[string]any{"model_version": "claude-sonnet-5-5",
			"preflight": pf})).want(t, 200, "")
		recs := f.records()
		r := recs[len(recs)-1]
		if r["model_version"] != "claude-sonnet-5-5" || r["preflight"].(map[string]any)["result"] != "not-run" {
			t.Fatalf("%s: %v", kind, r)
		}
	}
	cost := map[string]any{"charged_tokens": 8500, "input_tokens": 1200, "output_tokens": 300, "model_calls": 2,
		"tool_calls": 7, "wall_seconds": 95, "compute": "small"}
	f.do("POST", "/v1/records", gw, runRecord("run.finish", map[string]any{"model_version": "claude-sonnet-5-5",
		"preflight": map[string]any{"result": "pass", "definition": "researcher", "cases": 6}, "cost": cost})).
		want(t, 200, "")
	recs := f.records()
	r := recs[len(recs)-1]
	c := r["cost"].(map[string]any)
	if fmt.Sprint(c["charged_tokens"]) != "8500" || fmt.Sprint(c["wall_seconds"]) != "95" || c["compute"] != "small" ||
		fmt.Sprint(c["cache_read_input_tokens"]) != "0" {
		t.Fatalf("cost %v", c)
	}
	if p := r["preflight"].(map[string]any); fmt.Sprint(p["cases"]) != "6" || p["result"] != "pass" {
		t.Fatalf("preflight %v", p)
	}
	cl := anyStrings(r["claimed"])
	for _, k := range []string{"cost", "preflight", "model_version"} {
		if !slices.Contains(cl, k) {
			t.Fatalf("%s is not claimed: %v", k, cl)
		}
	}
	if ok, bad := evidence.Verify(recs); !ok {
		t.Fatalf("chain breaks at %d", bad)
	}
}

func TestRunRecordFieldRefusals(t *testing.T) {
	f := memFixture(t)
	human := map[string]any{"provider": "autopilot-gateway", "kind": "human.answer", "record": map[string]any{
		"principal": "user:jfillman", "target": "h-01", "result": "answered", "model_version": "m"}}
	f.do("POST", "/v1/records", gw, human).want(t, 400, "run's records only")
	f.do("POST", "/v1/records", gw, runRecord("run.launch", map[string]any{"cost": map[string]any{"charged_tokens": 1}})).
		want(t, 400, "cost is set on [run.finish]")
	f.do("POST", "/v1/records", gw, runRecord("run.launch", map[string]any{"preflight": map[string]any{"result": "maybe"}})).
		want(t, 400, "preflight.result")
	f.do("POST", "/v1/records", gw, runRecord("run.launch", map[string]any{"preflight": map[string]any{}})).
		want(t, 400, "")
	f.do("POST", "/v1/records", gw, runRecord("run.launch", map[string]any{"preflight": map[string]any{"result": "pass",
		"definition": "Not A Name"}})).want(t, 400, "preflight.definition")
	f.do("POST", "/v1/records", gw, runRecord("run.launch", map[string]any{"preflight": map[string]any{"result": "pass",
		"cases": -1}})).want(t, 400, "preflight.cases")
	f.do("POST", "/v1/records", gw, runRecord("run.finish", map[string]any{"cost": map[string]any{"charged_tokens": 1,
		"wall_seconds": -5}})).want(t, 400, "cost.wall_seconds")
	f.do("POST", "/v1/records", gw, runRecord("run.finish", map[string]any{"cost": map[string]any{"charged_tokens": 1,
		"compute": "Huge!"}})).want(t, 400, "cost.compute")
	// Only the compute classes a definition may name: a well-formed but unknown class is refused too.
	f.do("POST", "/v1/records", gw, runRecord("run.finish", map[string]any{"cost": map[string]any{"charged_tokens": 1,
		"compute": "tiny"}})).want(t, 400, "cost.compute")
	f.do("POST", "/v1/records", gw, runRecord("run.finish", map[string]any{"cost": map[string]any{"charged_tokens": 1,
		"dollars": 3}})).want(t, 400, "unknown field")
	f.do("POST", "/v1/records", gw, runRecord("run.launch", map[string]any{"model_version": ""})).
		want(t, 400, "model_version")
	if n := len(f.records()); n != 0 {
		t.Fatalf("a refused record was written: %d", n)
	}
}

// The compute classes a cost may name are the ones a definition may (internal/profile), so the two cannot drift.
func TestCostComputeClassesAreTheProfiles(t *testing.T) {
	for _, c := range server.ComputeClasses {
		if _, err := profile.ParseComputeClass(c); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	if _, err := profile.ParseComputeClass("tiny"); err == nil {
		t.Fatal("profile takes a class the cost refuses")
	}
	f := memFixture(t)
	for _, c := range server.ComputeClasses {
		f.do("POST", "/v1/records", gw, runRecord("run.finish", map[string]any{"cost": map[string]any{
			"charged_tokens": 1, "compute": c}})).want(t, 200, "")
	}
}
