package decide_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/decide/decidetest"
)

func engine(t testing.TB) *decide.Engine {
	return decidetest.Engine(t)
}

func TestLoadFailsOnABadRule(t *testing.T) {
	for _, c := range []struct{ name, expr, want string }{
		{"syntax", "ctx.known &&", "does not compile"},
		{"undeclared", "ctx.no_such_key", "does not compile"},
		{"type error", "tool.tier > 'x'", "does not compile"},
		{"not bool", "tool.tier", "not bool"},
		{"too costly", "effective.tools.all(a, effective.tools.all(b, effective.tools.exists(c, a + b + c == tool.name)))", "cost"},
	} {
		t.Run(c.name, func(t *testing.T) {
			core, _ := decide.Core()
			core.Rules = append(core.Rules, decide.Rule{ID: "R900", Name: "x", Expr: c.expr, Message: "m", Hint: "h", Order: 900})
			_, err := decide.NewFromData(core, decide.Options{})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
	core, _ := decide.Core()
	core.Rules = append(core.Rules, core.Rules[0])
	if _, err := decide.NewFromData(core, decide.Options{}); err == nil {
		t.Error("a rule id registered twice must fail the load")
	}
	core, _ = decide.Core()
	core.Tools = append(core.Tools, decide.ToolSpec{Name: "k8s.exec", Target: "none"})
	if _, err := decide.NewFromData(core, decide.Options{}); err == nil {
		t.Error("a tripwire registered as a tool must fail the load")
	}
	hb := decidetest.Bundle(t)
	if _, err := decide.New(decide.Options{Bundles: []*decide.Bundle{hb, hb}}); err == nil {
		t.Error("a bundle loaded twice must fail the load")
	}
}

const base = `{"subject":{"type":"principal","id":"user:alice","properties":{"kind":"user","tier_ceiling":1}},
 "action":{"name":"tool.call","properties":{"args":%s}},
 "resource":{"type":"tool","id":"%s"},
 "context":{"now":"2026-09-26T12:00:00Z","session_id":"s-1","session":{"id":"s-1","principal":"user:alice",
  "agent":"coding-agent","task_id":"t-1","parent_id":null,"depth":0,
  "limits":{"tier_ceiling":"T2","ttl_minutes":30,"tool_calls":10,"github_calls":10,"open_prs":1,"model_tokens":0,
   "children":0,"tools":["repo.pr.open_upper","catalog.read"],"models":[],"network":"clearance","compute":"small"},
  "used":{"tool_calls":0,"github_calls":0,"open_prs":0,"model_tokens":0,"children":0},
  "reserved":{"tool_calls":0,"github_calls":0,"open_prs":0,"model_tokens":0,"children":0},
  "expires_at":"2026-09-26T12:30:00Z","closed":false,"tripped":false,"denials":0},
  "scope":{"agent_kind":"task","deny_paths":[],"repos_allow":["jfillman/*"],"api_allow":[],
   "field_deny":["/release"],"field_allow":[]}}}`

func decideJSON(t *testing.T, e *decide.Engine, tool, args string) *decide.EvaluationResponse {
	t.Helper()
	req, err := decide.DecodeEvaluation(strings.NewReader(sprintf(base, args, tool)))
	if err != nil {
		t.Fatal(err)
	}
	return e.Decide(context.Background(), req)
}

func sprintf(f, args, tool string) string {
	return strings.Replace(strings.Replace(f, "%s", args, 1), "%s", tool, 1)
}

// A date PyYAML refuses with ValueError (not a YAMLError) is an uncaught exception in the Python gateway; the
// Go engine fails closed on it.
func TestNonYAMLErrorFailsClosed(t *testing.T) {
	e := engine(t)
	r := decideJSON(t, e, "repo.pr.open_upper", `{"repo":"jfillman/gitops-x","branch":"b","title":"t",
	  "files":[{"path":"values.yaml","before":"a: 2024-02-30\n","content":"a: 1\n"}]}`)
	if r.Decision || r.Context.Rule != "R000" || r.Context.Message != "the policy could not be evaluated: ValueError" {
		t.Fatalf("got %+v", r.Context)
	}
	if !r.Context.Spend.Denial {
		t.Error("an R000 is a denied call")
	}
	ok := decideJSON(t, e, "repo.pr.open_upper", `{"repo":"jfillman/gitops-x","branch":"b","title":"t",
	  "files":[{"path":"values.yaml","before":"a: 2024-02-28\n","content":"a: 1\n"}]}`)
	if !ok.Decision {
		t.Fatalf("a valid date: got %+v", ok.Context)
	}
}

func TestInvalidRequestFailsClosed(t *testing.T) {
	e := engine(t)
	r := e.Decide(context.Background(), &decide.EvaluationRequest{})
	if r.Decision || r.Context.Rule != "R000" {
		t.Fatalf("an empty request: %+v", r.Context)
	}
	if got := e.RecordFields(&decide.EvaluationRequest{}, r); got == nil || got["decision"] != "deny" || got["rule"] != "R000" {
		t.Fatalf("record for an invalid request: %v", got)
	}
}

func TestDecodeIsStrict(t *testing.T) {
	good := sprintf(base, `{"query":"x"}`, "catalog.read")
	if _, err := decide.DecodeEvaluation(strings.NewReader(good)); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown field":   strings.Replace(good, `"closed":false`, `"closed":false,"extra":1`, 1),
		"trailing data":   good + " {}",
		"args not object": sprintf(base, `[1]`, "catalog.read"),
		"float budget":    strings.Replace(good, `"tool_calls":10`, `"tool_calls":10.5`, 1),
		"bad tier":        strings.Replace(good, `"tier_ceiling":"T2"`, `"tier_ceiling":"T9"`, 1),
		"wrong resource":  strings.Replace(good, `"type":"tool"`, `"type":"model"`, 1),
		"no now":          strings.Replace(good, `"now":"2026-09-26T12:00:00Z",`, ``, 1),
	} {
		if _, err := decide.DecodeEvaluation(strings.NewReader(body)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	huge := bytes.Repeat([]byte(" "), decide.MaxRequestBytes+1)
	if _, err := decide.DecodeEvaluation(bytes.NewReader(huge)); err != decide.ErrTooLarge {
		t.Errorf("an over-size body: %v", err)
	}
}

// The response's JSON shape is the contract R-1d serves.
func TestResponseShape(t *testing.T) {
	e := engine(t)
	r := decideJSON(t, e, "k8s.exec", `{}`)
	b, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	c := m["context"].(map[string]any)
	if m["decision"] != false || c["rule"] != "R002" || c["spend"].(map[string]any)["trip_tree"] != "tripwire: k8s.exec" ||
		c["policy"].(map[string]any)["bundle"] != "clearance-core+hangar" {
		t.Fatalf("shape: %s", b)
	}
	ev := e.RecordFields(mustDecode(t, sprintf(base, `{}`, "k8s.exec")), r)
	if ev["rule"] != "R002" || ev["result"] != "this capability is never exposed to any agent" || ev["args_sha256"] == "" {
		t.Fatalf("record: %v", ev)
	}
}

func mustDecode(t *testing.T, s string) *decide.EvaluationRequest {
	r, err := decide.DecodeEvaluation(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func FuzzDecodeEvaluation(f *testing.F) {
	f.Add([]byte(sprintf(base, `{"query":"x"}`, "catalog.read")))
	f.Add([]byte(sprintf(base, `{"repo":"jfillman/x","branch":"b","title":"t","files":[{"path":"cicd.yaml","before":"a: 1","content":"b: [1, {c: on}]"}]}`, "repo.pr.open")))
	f.Add([]byte(sprintf(base, `{"agent":"x","limits":{"tool_calls":1}}`, "run.spawn")))
	f.Add([]byte(`{"subject":{"type":"principal","id":"u","properties":{"kind":"user","tier_ceiling":1}},"action":{"name":"model.call","properties":{"est_tokens":5}},"resource":{"type":"model","id":"m"},"context":{"now":"2026-01-01T00:00:00Z","models":{"routes":["m"]}}}`))
	f.Add([]byte(`{"subject":{"type":"principal","id":"u","properties":{"kind":"user","tier_ceiling":1}},"action":{"name":"session.open","properties":{"limits":{"network":"clearance-model"}}},"resource":{"type":"agent","id":"a"},"context":{"now":"2026-01-01T00:00:00Z","new_session_id":"s-1"}}`))
	f.Add([]byte(sprintf(base, `{"app":"gate-api","documents":[{"path":"a.yaml","content":"k: v"}],"patch":{"a":1}}`, "airframe.validate")))
	f.Add([]byte(sprintf(base, `{"app":"gate-api","env":"prod","cluster":"c","sourceEnv":"dev","sourceCluster":"c"}`, "glidepath.promote")))
	e := engine(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := decide.DecodeEvaluation(bytes.NewReader(data))
		if err != nil {
			return
		}
		resp := e.Decide(context.Background(), req)
		_ = e.RecordFields(req, resp)
		if resp.Decision && resp.Context.Rule != "" {
			t.Fatalf("an allow with a rule: %+v", resp.Context)
		}
	})
}

// FuzzBundleSource: a source document is read over the network at start; whatever it holds, the load either fails
// or yields a bundle whose engine builds and decides.
func FuzzBundleSource(f *testing.F) {
	bundle, err := os.ReadFile(decidetest.FixtureBundle())
	if err != nil {
		f.Fatal(err)
	}
	good, err := os.ReadFile(decidetest.FixtureSource())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"contractVersion":1,"scope":{"rules":[{"pattern":"/**","agentScope":"open"}]}}`))
	f.Add([]byte(`{"contractVersion":1.5,"scope":{"rules":[]}}`))
	f.Add([]byte(`{"contractVersion":1,"scope":{"rules":[{"pattern":"/a","agentScope":"tighten","order":"int","default":1e400}]}}`))
	req := sprintf(base, `{"repo":"jfillman/x","branch":"b","title":"t","files":[{"path":"cicd.yaml","before":"a: 1","content":"a: 2"}]}`, "repo.pr.open")
	f.Fuzz(func(t *testing.T, doc []byte) {
		b, err := decide.LoadBundle(bundle, func(string, decide.SourceSpec) ([]byte, string, error) { return doc, "fuzz", nil })
		if err != nil {
			return
		}
		e, err := decide.New(decide.Options{Bundles: []*decide.Bundle{b}})
		if err != nil {
			return
		}
		r, err := decide.DecodeEvaluation(strings.NewReader(req))
		if err != nil {
			t.Fatal(err)
		}
		_ = e.Decide(context.Background(), r)
	})
}

// A policy bundle is checked like the core rules: its context expressions compile and type-check at load, its
// rules name documents it has, and its sources are the versions it was written for.
func TestABadPolicyBundleFailsTheLoad(t *testing.T) {
	fixture, err := os.ReadFile(decidetest.FixtureBundle())
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(fixture, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	src := decidetest.FileFetch(decidetest.FixtureSource())
	for name, c := range map[string]struct {
		data []byte
		want string
	}{
		"var does not compile": {edit(func(m map[string]any) { m["vars"].([]any)[0].(map[string]any)["expr"] = "args['app'] &&" }), "does not compile"},
		"var is not its type":  {edit(func(m map[string]any) { m["vars"].([]any)[0].(map[string]any)["expr"] = "1" }), "not bool"},
		"arg check reads nothing declared": {edit(func(m map[string]any) {
			m["arg_checks"].([]any)[0].(map[string]any)["checks"] = []any{"nope.x"}
		}), "does not compile"},
		"app is not a string": {edit(func(m map[string]any) { m["app"] = "1" }), "not string"},
		"problems from no document": {edit(func(m map[string]any) {
			for _, r := range m["rules"].([]any) {
				if r.(map[string]any)["id"] == "R021" {
					r.(map[string]any)["problems"] = "nope"
				}
			}
		}), "not one of its documents"},
		"incompatible source": {edit(func(m map[string]any) {
			m["sources"].([]any)[0].(map[string]any)["compatible"] = []any{7}
		}), "this bundle is written for [7]"},
		"unknown field": {edit(func(m map[string]any) { m["surprise"] = true }), "unknown field"},
		"wrong format":  {edit(func(m map[string]any) { m["apiVersion"] = "v0" }), "apiVersion"},
		"no such source": {edit(func(m map[string]any) {
			m["documents"].([]any)[0].(map[string]any)["rules"] = map[string]any{"source": "x"}
		}), "unknown source"},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := decide.LoadBundle(c.data, src)
			if err == nil {
				_, err = decide.New(decide.Options{Bundles: []*decide.Bundle{b}})
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

// The core names no deployment's tools: without a bundle, a bundle's tool is unknown (R003).
func TestTheCoreAloneKnowsNoBundleTool(t *testing.T) {
	e, err := decide.New(decide.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if e.Tool("glidepath.runs.list") != nil || len(e.PRTools()) != 2 || len(e.ProfileSections()) != 0 {
		t.Fatal(e.PRTools(), e.ProfileSections())
	}
	resp := decideJSON(t, e, "glidepath.runs.list", `{"app":"x"}`)
	if resp.Context.Rule != "R003" {
		t.Fatal(resp.Context)
	}
}
