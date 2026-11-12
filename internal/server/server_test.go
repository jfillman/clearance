package server_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/githubapp"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
)

const (
	gw      = "autopilot-system/clearance"
	argo    = "hangar-prod/argocd/clearance-sync"
	ci      = "app-gate-api-cicd/pipeline-runner"
	tower   = "hangar-prod/app-backstage-prod/backstage"
	owner   = "group:default/team-gate"
	headSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var providersJSON = `[{"name": "autopilot-gateway", "version": "0.3.27", "principals": ["autopilot-system/clearance"],
  "definitions": true},
 {"name": "argo-gate", "version": "0.1.0", "principals": ["hangar-prod/argocd/*"],
  "kinds": ["deploy.outcome", "deploy.exception", "deploy.degraded"]}]`

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type groups map[string][]string

func (g groups) Groups(_ context.Context, p string) []string { return g[p] }

// fixture is a whole core (internal/core.Build) on a store, served by httptest.
type fixture struct {
	t    testing.TB
	core *core.Core
	srv  *httptest.Server
}

func config(t testing.TB, dsn string) core.Config {
	ps, err := server.ParseProviders(providersJSON)
	if err != nil {
		t.Fatal(err)
	}
	cfg := core.Config{Memory: dsn == "", DSN: dsn, Version: "test", Providers: ps, Auth: core.DevAuthenticator(),
		MaxClockSkew: -1, AgentLogins: []string{vocabtest.AgentLogin}}
	cfg.Gate.Verifiers = []string{"app-*-cicd/pipeline-runner"}
	cfg.Gate.Delegates = []string{tower}
	cfg.Gate.Admins = []string{"user:admin"}
	return cfg
}

func newFixture(t testing.TB, cfg core.Config) *fixture {
	t.Helper()
	c, err := core.Build(context.Background(), cfg, nil, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	c.Gate.Directory = groups{"user:dana": {owner}, "user:erin": {owner}}
	srv := httptest.NewServer(c.Server.Handler())
	t.Cleanup(srv.Close)
	return &fixture{t: t, core: c, srv: srv}
}

func memFixture(t *testing.T) *fixture { return newFixture(t, config(t, "")) }

type answer struct {
	status int
	body   map[string]any
	ctype  string
}

func (f *fixture) do(method, path, token string, body any) answer {
	f.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			f.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return f.send(req)
}

func (f *fixture) send(req *http.Request) answer {
	f.t.Helper()
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	a := answer{status: resp.StatusCode, ctype: resp.Header.Get("Content-Type")}
	_ = json.Unmarshal(raw, &a.body)
	return a
}

func (a answer) want(t testing.TB, status int, errContains string) answer {
	t.Helper()
	if a.status != status {
		t.Fatalf("status %d, want %d: %v", a.status, status, a.body)
	}
	if errContains != "" && !strings.Contains(fmt.Sprint(a.body["error"]), errContains) {
		t.Fatalf("error %q does not say %q", a.body["error"], errContains)
	}
	return a
}

func (f *fixture) records() []store.Record {
	f.t.Helper()
	recs, err := f.core.Store.Records(context.Background(), 0, 10000)
	if err != nil {
		f.t.Fatal(err)
	}
	return recs
}

// corpus lines (testdata/golden/corpus.jsonl): requests the Python engine decided, by line number.
var corpus = func() map[int]json.RawMessage {
	out := map[int]json.RawMessage{}
	fh, err := os.Open("../../testdata/golden/corpus.jsonl")
	if err != nil {
		return out
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(nil, 64<<20)
	for n := 0; sc.Scan(); n++ {
		var l struct {
			Request json.RawMessage `json:"request"`
		}
		if json.Unmarshal(sc.Bytes(), &l) == nil && l.Request != nil {
			out[n] = l.Request
		}
	}
	return out
}()

const (
	prOpenAllowed = 210 // tests/test_policy.py::test_baseline_pr_is_allowed (no packs)
	prOpenDenied  = 218 // repo.pr.open denied R008 (no packs)
	modelAllowed  = 190 // model.call allowed, with routes
)

func request(t testing.TB, line int, edit func(map[string]any)) []byte {
	t.Helper()
	raw, ok := corpus[line]
	if !ok {
		t.Fatalf("corpus line %d missing", line)
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(m)
	}
	out, _ := json.Marshal(m)
	return out
}

func (f *fixture) evaluate(line int, edit func(map[string]any)) answer {
	f.t.Helper()
	return f.do("POST", "/access/v1/evaluation", gw, request(f.t, line, edit)).want(f.t, 200, "")
}

func decisionID(t *testing.T, a answer) string {
	t.Helper()
	id, ok := a.body["decision_id"].(string)
	if !ok {
		t.Fatalf("no decision_id: %v", a.body)
	}
	return id
}

// -- operational ----------------------------------------------------------------------------------------------

func TestHealthAndReadiness(t *testing.T) {
	f := memFixture(t)
	f.do("GET", "/healthz", "", nil).want(t, 200, "")
	r := f.do("GET", "/readyz", "", nil).want(t, 200, "")
	if r.body["head"] != float64(-1) || r.body["policy"].(map[string]any)["bundle"] != "clearance-core" {
		t.Fatal(r.body)
	}
	f.core.Store.Close()
	f.do("GET", "/readyz", "", nil).want(t, 503, "store unreachable")
	f.do("POST", "/healthz", "user:x", nil).want(t, 405, "")
}

func TestEveryRouteIsServedAndAnswersJSON(t *testing.T) {
	f := memFixture(t)
	for _, rt := range server.Routes() {
		path := strings.NewReplacer("{id}", "0", "{change_id}", "ch-0").Replace(rt.Path)
		a := f.do(rt.Method, path, "user:nobody", "{}")
		if a.status == 404 && a.body == nil || a.status == 405 {
			t.Errorf("%s %s: not routed (%d)", rt.Method, rt.Path, a.status)
		}
		if !strings.HasPrefix(a.ctype, "application/json") {
			t.Errorf("%s %s: content type %q", rt.Method, rt.Path, a.ctype)
		}
	}
	f.do("GET", "/v1/nothing", "user:nobody", nil).want(t, 404, "")
}

func TestAuthenticationIsRequiredExceptWhereSigned(t *testing.T) {
	f := memFixture(t)
	for _, rt := range server.Routes() {
		path := strings.NewReplacer("{id}", "0", "{change_id}", "ch-0").Replace(rt.Path)
		a := f.do(rt.Method, path, "", "{}")
		switch rt.Auth {
		case server.AuthBearer, server.AuthProvider:
			a.want(t, 401, "a bearer token is required")
		default:
			if a.status == 401 {
				t.Errorf("%s %s asked for a bearer token", rt.Method, rt.Path)
			}
		}
	}
	f.do("POST", "/access/v1/evaluation", "two words", "{}").want(t, 401, "token not accepted")
}

// -- POST /access/v1/evaluation ---------------------------------------------------------------------------------

func TestAnEvaluationIsDecidedAndRecordedAsTheCore(t *testing.T) {
	f := memFixture(t)
	allow := f.evaluate(prOpenAllowed, nil)
	if allow.body["decision"] != true || decisionID(t, allow) != "0" {
		t.Fatal(allow.body)
	}
	deny := f.evaluate(prOpenDenied, nil)
	if deny.body["decision"] != false || deny.body["context"].(map[string]any)["rule"] != "R008" || decisionID(t, deny) != "1" {
		t.Fatal(deny.body)
	}
	recs := f.records()
	if len(recs) != 2 {
		t.Fatal(len(recs))
	}
	r := recs[0]
	prov := r["provider"].(map[string]any)
	if prov["name"] != "clearance" || prov["version"] != "test" || r["tool"] != "repo.pr.open" || r["decision"] != "allow" {
		t.Fatal(r)
	}
	if c := r["caller"].(map[string]any); c["provider"] != "autopilot-gateway" || c["principal"] != gw {
		t.Fatal(c)
	}
	if !slices.Contains(anyStrings(r["verified"]), "caller") || !slices.Contains(anyStrings(r["verified"]), "principal") ||
		!slices.Contains(anyStrings(r["verified"]), "policy") {
		t.Fatal(r["verified"])
	}
	// The decision names the policy that decided it: the core alone here, the digest, the evaluator.
	pol := allow.body["context"].(map[string]any)["policy"].(map[string]any)
	if p := r["policy"].(map[string]any); p["ref"] != "clearance-core" || p["engine"] != "cel-go" || p["version"] != pol["version"] {
		t.Fatal(p, pol)
	}
	if allow.body["record"].(map[string]any)["hash"] != r["hash"] {
		t.Fatal("the answer's record is not the stored one")
	}
	if recs[1]["decision"] != "deny" || recs[1]["rule"] != "R008" {
		t.Fatal(recs[1])
	}
}

func TestAnUnrecordedDecisionHasNoID(t *testing.T) {
	f := memFixture(t)
	a := f.evaluate(modelAllowed, func(m map[string]any) { delete(m["context"].(map[string]any), "models") })
	if a.body["decision_id"] != nil || a.body["decision"] != false {
		t.Fatal(a.body)
	}
	if n := len(f.records()); n != 0 {
		t.Fatal(n)
	}
}

func TestEvaluationRefusals(t *testing.T) {
	f := memFixture(t)
	body := request(t, prOpenAllowed, nil)
	f.do("POST", "/access/v1/evaluation", "someone/else", body).want(t, 403, "not a registered provider")
	f.do("POST", "/access/v1/evaluation", "user:alice", body).want(t, 403, "not a registered provider")
	f.do("POST", "/access/v1/evaluation", gw, request(t, prOpenAllowed, func(m map[string]any) { m["extra"] = 1 })).
		want(t, 400, "")
	f.do("POST", "/access/v1/evaluation", gw, request(t, prOpenAllowed, func(m map[string]any) {
		m["subject"].(map[string]any)["nickname"] = "x"
	})).want(t, 400, "")
	f.do("POST", "/access/v1/evaluation", gw, string(body)+"{}").want(t, 400, "")
	f.do("POST", "/access/v1/evaluation", gw, "not json").want(t, 400, "")
	big := bytes.Repeat([]byte(" "), server.MaxEvaluationBody+1)
	f.do("POST", "/access/v1/evaluation", gw, big).want(t, 413, "too large")
	// The same without a Content-Length: the body reader stops it.
	req, _ := http.NewRequest("POST", f.srv.URL+"/access/v1/evaluation", io.MultiReader(bytes.NewReader(big)))
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+gw)
	f.send(req).want(t, 413, "too large")
	if n := len(f.records()); n != 0 {
		t.Fatalf("a refused request was recorded: %d", n)
	}
}

func TestEvaluationClockSkewIsRefused(t *testing.T) {
	cfg := config(t, "")
	cfg.MaxClockSkew = time.Minute
	f := newFixture(t, cfg)
	f.do("POST", "/access/v1/evaluation", gw, request(t, prOpenAllowed, nil)).want(t, 400, "core's clock")
	now := time.Now().UTC().Format(time.RFC3339)
	a := f.do("POST", "/access/v1/evaluation", gw, request(t, prOpenAllowed, func(m map[string]any) {
		m["context"].(map[string]any)["now"] = now
	})).want(t, 200, "")
	if a.body["decision_id"] == nil {
		t.Fatal(a.body)
	}
}

// -- POST /v1/decisions/{id}/outcome ------------------------------------------------------------------------------

func effectBody() map[string]any {
	return map[string]any{"result": "ok", "effect": map[string]any{"repo": "Jfillman/Gate-API", "pr": 32,
		"commit": headSHA, "branch": "agent/fix", "paths": []string{"app.js", "./app.js", "lib/x.js"}},
		"receipt": map[string]any{"id": "pr-32", "url": "https://github.com/jfillman/gate-api/pull/32"}}
}

func TestAnOutcomeIsRecordedOnceForTheProviderThatAsked(t *testing.T) {
	f := memFixture(t)
	id := decisionID(t, f.evaluate(prOpenAllowed, nil))
	a := f.do("POST", "/v1/decisions/"+id+"/outcome", gw, effectBody()).want(t, 200, "")
	recs := f.records()
	out, dec := recs[len(recs)-1], recs[0]
	if a.body["seq"] != float64(1) || out["hash"] != a.body["hash"] {
		t.Fatal(a.body)
	}
	for _, k := range []string{"tool", "task_id", "session", "principal", "agent", "args_sha256", "decision"} {
		if fmt.Sprint(out[k]) != fmt.Sprint(dec[k]) {
			t.Errorf("%s: %v, decision has %v", k, out[k], dec[k])
		}
	}
	eff := out["effect"].(map[string]any)
	if eff["repo"] != "jfillman/gate-api" || fmt.Sprint(eff["paths"]) != "[app.js lib/x.js]" || fmt.Sprint(eff["pr"]) != "32" {
		t.Fatal(eff)
	}
	if of := out["outcome_of"].(map[string]any); fmt.Sprint(of["seq"]) != "0" || of["hash"] != dec["hash"] {
		t.Fatal(of)
	}
	if p := out["provider"].(map[string]any); p["name"] != "autopilot-gateway" || p["version"] != "0.3.27" {
		t.Fatal(p)
	}
	ver, cl := anyStrings(out["verified"]), anyStrings(out["claimed"])
	for _, k := range []string{"provider", "task_id", "tool", "outcome_of", "ts"} {
		if !slices.Contains(ver, k) {
			t.Errorf("%s is not verified: %v", k, ver)
		}
	}
	for _, k := range []string{"effect", "result", "receipt"} {
		if !slices.Contains(cl, k) {
			t.Errorf("%s is not claimed: %v", k, cl)
		}
	}
	f.do("POST", "/v1/decisions/"+id+"/outcome", gw, effectBody()).want(t, 409, "already has an outcome")

	// Provenance finds the receipt the outcome recorded.
	pv := f.do("POST", "/v1/provenance", ci, map[string]any{"repo": "jfillman/gate-api", "pr": 32, "head": headSHA,
		"paths": []string{"app.js"}, "author": vocabtest.AgentLogin}).want(t, 200, "")
	if pv.body["record"] == nil || pv.body["agent_pr"] != true {
		t.Fatal(pv.body)
	}
	f.do("POST", "/v1/provenance", "user:alice", map[string]any{"repo": "a/b", "pr": 1, "head": headSHA, "paths": []string{}}).
		want(t, 403, "not a provenance verifier")
}

func TestOutcomeRefusals(t *testing.T) {
	f := memFixture(t)
	allowed := decisionID(t, f.evaluate(prOpenAllowed, nil))
	denied := decisionID(t, f.evaluate(prOpenDenied, nil))
	model := decisionID(t, f.evaluate(modelAllowed, nil))
	rec := f.do("POST", "/v1/records", gw, map[string]any{"provider": "autopilot-gateway", "kind": "run.launch",
		"record": map[string]any{"session": "s-1", "principal": "autopilot-runs/x", "agent": "x", "result": "created"}}).
		want(t, 200, "")
	recSeq := fmt.Sprint(rec.body["seq"])
	path := func(id string) string { return "/v1/decisions/" + id + "/outcome" }
	ok := map[string]any{"result": "ok"}

	f.do("POST", path(allowed), argo, ok).want(t, 403, "another provider")
	f.do("POST", path(allowed), "someone/else", ok).want(t, 403, "not a registered provider")
	f.do("POST", path(denied), gw, ok).want(t, 409, "was a deny")
	f.do("POST", path("999"), gw, ok).want(t, 404, "no such decision")
	f.do("POST", path("-1"), gw, ok).want(t, 404, "no such decision")
	f.do("POST", path("01"), gw, ok).want(t, 404, "no such decision")
	f.do("POST", path("abc"), gw, ok).want(t, 404, "no such decision")
	f.do("POST", path(recSeq), gw, ok).want(t, 404, "no such decision")
	f.do("POST", path(allowed), gw, map[string]any{"result": "ok", "extra": 1}).want(t, 400, "unknown field")
	f.do("POST", path(allowed), gw, map[string]any{"result": ""}).want(t, 400, "result")
	f.do("POST", path(allowed), gw, map[string]any{"result": "ok", "effect": map[string]any{"pr": 3}}).want(t, 400, "effect.pr")
	f.do("POST", path(allowed), gw, map[string]any{"result": "ok", "effect": map[string]any{"repo": "a/b", "paths": []string{"../x"}}}).
		want(t, 400, "effect.paths")
	f.do("POST", path(allowed), gw, map[string]any{"result": "ok", "receipt": map[string]any{"x": []int{1}}}).want(t, 400, "receipt.x")
	f.do("POST", path(model), gw, effectBody()).want(t, 400, "has no receipt")
	f.do("POST", path(allowed), gw, bytes.Repeat([]byte("x"), server.MaxOutcomeBody+1)).want(t, 413, "too large")
	// None of that was recorded; the allowed decision still takes its outcome.
	f.do("POST", path(allowed), gw, ok).want(t, 200, "")
	f.do("POST", path(model), gw, map[string]any{"result": "ok", "receipt": map[string]any{"tokens": 1200}}).want(t, 200, "")
}

func TestTheOutcomeIndexSurvivesARestart(t *testing.T) {
	f := memFixture(t)
	id := decisionID(t, f.evaluate(prOpenAllowed, nil))
	f.do("POST", "/v1/decisions/"+id+"/outcome", gw, map[string]any{"result": "ok"}).want(t, 200, "")
	// A new server on the same store reads the index from the chain.
	srv, err := server.New(context.Background(), server.Options{Store: f.core.Store, Engine: f.core.Engine,
		Auth: core.DevAuthenticator(), Providers: f.core.Config.Providers, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(srv.Handler())
	defer h.Close()
	g := &fixture{t: t, core: f.core, srv: h}
	g.do("POST", "/v1/decisions/"+id+"/outcome", gw, map[string]any{"result": "ok"}).want(t, 409, "already")
}

// -- POST /v1/records -----------------------------------------------------------------------------------------------

func TestEveryProviderRecordKind(t *testing.T) {
	f := memFixture(t)
	s := func(v string) any { return v }
	cases := []struct {
		who, prov, kind string
		rec             map[string]any
		boundary        string
	}{
		{gw, "autopilot-gateway", "session.open", map[string]any{"session": s("s-1"), "task_id": s("t-1"),
			"principal": s("autopilot-runs/x"), "agent": s("x"), "result": s("opened"), "decision": s("allow")}, "runtime"},
		{gw, "autopilot-gateway", "run.launch", map[string]any{"session": s("s-1"), "principal": s("autopilot-runs/x"),
			"agent": s("x"), "result": s("created"), "args_sha256": s(strings.Repeat("a", 64))}, "runtime"},
		{gw, "autopilot-gateway", "run.delete", map[string]any{"session": s("s-1"), "principal": s("autopilot-runs/x"),
			"agent": s("x"), "result": s("deleted")}, "runtime"},
		{gw, "autopilot-gateway", "human.answer", map[string]any{"principal": s("user:jfillman"), "target": s("h-01"),
			"result": s("answered via tower"), "intent": s("because the PR is right")}, "runtime"},
		{gw, "autopilot-gateway", "session.freeze", map[string]any{"principal": s("user:jfillman"), "session": s("s-1"),
			"agent": s("x"), "result": s("frozen: runaway")}, "runtime"},
		{gw, "autopilot-gateway", "trigger.hold", map[string]any{"principal": s("user:jfillman"), "agent": s("x"),
			"target": s("x"), "result": s("held until ...")}, "runtime"},
		{argo, "argo-gate", "deploy.outcome", map[string]any{"app": s("gate-api"), "target": s("gate-api-prod"),
			"outcome":     map[string]any{"applied": true, "observed_revision": headSHA, "health": "Healthy"},
			"destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"}}, "deployment"},
		{argo, "argo-gate", "deploy.exception", map[string]any{"principal": s("kubernetes-admin"),
			"target": s("apps/v1/Deployment/app-gate-api-prod/gate-api"), "result": s("applied without a grant"),
			"coverage": s("out-of-band-detected"),
			"exception": map[string]any{"kind": "out-of-band", "objects": []any{map[string]any{
				"apiVersion": "apps/v1", "kind": "Deployment", "namespace": "app-gate-api-prod", "name": "gate-api"}}},
			"destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"}}, "deployment"},
		{argo, "argo-gate", "deploy.degraded", map[string]any{"principal": s("hangar-prod/argocd/clearance-sync"),
			"target": s("gate-api-prod"), "app": s("gate-api"), "result": s("synced on the outage policy"),
			"decision": s("allow"), "tier": func() *int { t := 1; return &t }(), "coverage": s("coverage-unavailable"),
			"outage":      map[string]any{"from": "2026-09-26T11:00:00Z", "to": "2026-09-26T11:30:00Z"},
			"destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"}}, "deployment"},
	}
	for _, c := range cases {
		a := f.do("POST", "/v1/records", c.who, map[string]any{"provider": c.prov, "kind": c.kind, "record": c.rec}).
			want(t, 200, "")
		recs := f.records()
		r := recs[len(recs)-1]
		if r["hash"] != a.body["hash"] || r["tool"] != c.kind || r["boundary"] != c.boundary ||
			r["provider"].(map[string]any)["name"] != c.prov {
			t.Fatalf("%s: %v", c.kind, r)
		}
		v, cl := anyStrings(r["verified"]), anyStrings(r["claimed"])
		if !slices.Contains(v, "provider") || !slices.Contains(v, "ts") || slices.Contains(v, "principal") ||
			!slices.Contains(cl, "target") && c.rec["target"] != nil {
			t.Fatalf("%s verified %v claimed %v", c.kind, v, cl)
		}
		if c.kind == "human.answer" {
			if it := r["intent"].(map[string]any); it["capture"] != "redacted" || it["text"] != nil {
				t.Fatal(it)
			}
		}
	}
}

func TestRecordRefusals(t *testing.T) {
	f := memFixture(t)
	good := func() map[string]any {
		return map[string]any{"provider": "autopilot-gateway", "kind": "run.launch", "record": map[string]any{
			"session": "s-1", "principal": "autopilot-runs/x", "agent": "x", "result": "created"}}
	}
	with := func(edit func(m map[string]any)) map[string]any { m := good(); edit(m); return m }
	f.do("POST", "/v1/records", gw, with(func(m map[string]any) { m["kind"] = "run.anything" })).want(t, 400, "is not one of")
	f.do("POST", "/v1/records", gw, with(func(m map[string]any) { m["provider"] = "argo-gate" })).want(t, 403, "not the registered provider")
	f.do("POST", "/v1/records", gw, with(func(m map[string]any) { m["provider"] = "nobody" })).want(t, 403, "not the registered provider")
	f.do("POST", "/v1/records", argo, with(func(m map[string]any) { m["provider"] = "argo-gate" })).want(t, 403, "may not write run.launch")
	f.do("POST", "/v1/records", "someone/else", good()).want(t, 403, "not a registered provider")
	f.do("POST", "/v1/records", gw, with(func(m map[string]any) { m["extra"] = true })).want(t, 400, "unknown field")
	f.do("POST", "/v1/records", gw, with(func(m map[string]any) { m["record"].(map[string]any)["provider"] = "x" })).
		want(t, 400, "unknown field")
	f.do("POST", "/v1/records", gw, with(func(m map[string]any) { m["record"].(map[string]any)["seq"] = 5 })).
		want(t, 400, "unknown field")
	f.do("POST", "/v1/records", gw, with(func(m map[string]any) { delete(m["record"].(map[string]any), "session") })).
		want(t, 400, "carries session")
	f.do("POST", "/v1/records", gw, with(func(m map[string]any) { m["record"].(map[string]any)["tier"] = 9 })).want(t, 400, "tier")
	f.do("POST", "/v1/records", gw, with(func(m map[string]any) { m["record"].(map[string]any)["coverage"] = "maybe" })).
		want(t, 400, "")
	f.do("POST", "/v1/records", gw, with(func(m map[string]any) { m["record"].(map[string]any)["outcome"] = map[string]any{"x": 1.5e300} })).
		want(t, 400, "")
	f.do("POST", "/v1/records", gw, bytes.Repeat([]byte("x"), server.MaxRecordBody+1)).want(t, 413, "too large")
	if n := len(f.records()); n != 0 {
		t.Fatalf("a refused record was written: %d", n)
	}
	f.do("POST", "/v1/records", gw, good()).want(t, 200, "")
}

// -- the R-1c routes, mounted --------------------------------------------------------------------------------------

func change(ci string) map[string]any {
	return map[string]any{"app": "gate-api", "env": "prod", "cluster": "hangar-prod", "repo": "jfillman/gitops-gate-api",
		"pr": 7, "head": headSHA, "base": strings.Repeat("b", 40), "proposer": "user:dana", "proposerKind": "person",
		"owner": owner, "protected": true, "treeDigest": strings.Repeat("c", 64),
		"paths": []string{"hangar-prod/prod/release.yaml"}, "linesChanged": 4, "objects": []any{map[string]any{
			"apiVersion": "argoproj.io/v1alpha1", "kind": "Rollout", "namespace": "app-gate-api-prod", "name": "gate-api",
			"op": "changed", "fields": []string{"/spec/template/spec/containers/0/image"},
			"images": []string{"ghcr.io/jfillman/flight/gate-api@sha256:" + strings.Repeat("e", 64)},
			"digest": strings.Repeat("d", 64)}},
		"checks": map[string]any{"ci": ci, "provenance": "not-agent", "render": "ok", "admission": "pass"}}
}

func TestGateRoutes(t *testing.T) {
	f := memFixture(t)
	f.do("POST", "/v1/clearances", "user:dana", change("pending")).want(t, 403, "")
	f.do("POST", "/v1/clearances", ci, map[string]any{"app": "x"}).want(t, 400, "")
	f.do("POST", "/v1/clearances", ci, bytes.Repeat([]byte("x"), 4<<20+1)).want(t, 413, "too large")
	reg := f.do("POST", "/v1/clearances", ci, change("pending")).want(t, 200, "")
	id := reg.body["id"].(string)
	if reg.body["state"] != "holding" {
		t.Fatal(reg.body)
	}
	f.do("POST", "/v1/clearances/"+id+"/clear", "user:sam", nil).want(t, 403, "")
	f.do("POST", "/v1/clearances/"+id+"/clear", "user:dana", nil).want(t, 403, "") // the proposer
	f.do("POST", "/v1/clearances/"+id+"/deny", "user:admin", map[string]any{"reason": "no", "extra": 1}).want(t, 400, "unknown field")
	cl := f.do("POST", "/v1/clearances/"+id+"/clear", "user:erin", nil).want(t, 200, "")
	if cl.body["state"] != "cleared" || cl.body["audit_seq"] == nil {
		t.Fatal(cl.body)
	}
	f.do("POST", "/v1/clearances/"+id+"/deny", "user:admin", map[string]any{"reason": "too late"}).want(t, 409, "")
	// A second change on a new head, denied by an admin.
	c2 := change("pending")
	c2["head"] = strings.Repeat("e", 40)
	id2 := f.do("POST", "/v1/clearances", ci, c2).want(t, 200, "").body["id"].(string)
	d := f.do("POST", "/v1/clearances/"+id2+"/deny", "user:admin", map[string]any{"reason": "wrong replica count"}).want(t, 200, "")
	if d.body["state"] != "denied" {
		t.Fatal(d.body)
	}
	for _, r := range f.records() {
		if p := r["provider"].(map[string]any); p["name"] != "clearance" || p["version"] != "test" {
			t.Fatalf("a gate record sealed as %v", p)
		}
	}
}

func TestReviewRoute(t *testing.T) {
	f := memFixture(t)
	a := f.do("POST", "/v1/definitions/review", "user:alice", map[string]any{"doc": map[string]any{"name": "x"}}).want(t, 200, "")
	if a.body["ok"] != false || len(a.body["problems"].([]any)) == 0 {
		t.Fatal(a.body)
	}
	f.do("POST", "/v1/definitions/review", "some/workload", map[string]any{"doc": map[string]any{}}).want(t, 403, "")
	f.do("POST", "/v1/definitions/review", "user:alice", map[string]any{"doc": map[string]any{}, "nope": 1}).want(t, 400, "unknown field")
	f.do("POST", "/v1/definitions/review", "user:alice", bytes.Repeat([]byte("x"), 64<<10+1)).want(t, 413, "too large")
}

// G-TF-6: the run task route takes no bearer token (its HMAC signature is its authentication) and is off (404) until
// an installation is configured; a configured one answers an unsigned request 401, never a bearer challenge.
func TestRunTaskRouteIsOffUntilConfigured(t *testing.T) {
	f := memFixture(t)
	f.do("POST", "/v1/terraform/run-task", "", "{}").want(t, 404, "runs no HCP Terraform run task")
}

func TestWebhookIsAuthenticatedBySignatureOnly(t *testing.T) {
	f := memFixture(t)
	f.do("POST", "/v1/github/webhook", "", "{}").want(t, 404, "runs no GitHub App")

	dir := t.TempDir()
	key, secret := filepath.Join(dir, "key.pem"), filepath.Join(dir, "secret")
	if err := os.WriteFile(key, []byte("unused"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config(t, "")
	app, err := githubapp.ReadConfig("1", key, secret, "off", "http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	cfg.GitHubApp = app
	g := newFixture(t, cfg)
	body := []byte(`{"zen": "hello"}`)
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	req := func(sig string) *http.Request {
		r, _ := http.NewRequest("POST", g.srv.URL+"/v1/github/webhook", bytes.NewReader(body))
		r.Header.Set("X-GitHub-Event", "ping")
		r.Header.Set("X-Hub-Signature-256", sig)
		return r
	}
	g.send(req("sha256="+strings.Repeat("0", 64))).want(t, 401, "")
	if a := g.send(req("sha256="+hex.EncodeToString(mac.Sum(nil)))).want(t, 200, ""); a.body["result"] != "ignored" {
		t.Fatal(a.body)
	}
}

// -- the chain --------------------------------------------------------------------------------------------------

func TestTheChainVerifiesAfterEveryKindOfCall(t *testing.T) {
	f := memFixture(t)
	runSequence(t, f)
	verifyChain(t, f)
}

func runSequence(t *testing.T, f *fixture) {
	t.Helper()
	id := decisionID(t, f.evaluate(prOpenAllowed, nil))
	f.evaluate(prOpenDenied, nil)
	mid := decisionID(t, f.evaluate(modelAllowed, nil))
	f.do("POST", "/v1/decisions/"+id+"/outcome", gw, effectBody()).want(t, 200, "")
	f.do("POST", "/v1/decisions/"+mid+"/outcome", gw, map[string]any{"result": "ok"}).want(t, 200, "")
	f.do("POST", "/v1/records", gw, map[string]any{"provider": "autopilot-gateway", "kind": "session.open",
		"record": map[string]any{"session": "s-2", "task_id": "t-2", "principal": "p", "agent": "a", "result": "opened"}}).
		want(t, 200, "")
	f.do("POST", "/v1/records", argo, map[string]any{"provider": "argo-gate", "kind": "deploy.outcome",
		"record": map[string]any{"app": "gate-api", "target": "prod", "outcome": map[string]any{"applied": true}}}).want(t, 200, "")
	f.do("POST", "/v1/clearances", ci, change("pass")).want(t, 200, "")
	f.do("POST", "/v1/provenance", ci, map[string]any{"repo": "jfillman/gate-api", "pr": 32, "head": headSHA,
		"paths": []string{"app.js"}, "author": vocabtest.AgentLogin}).want(t, 200, "")
}

func verifyChain(t *testing.T, f *fixture) {
	t.Helper()
	recs := f.records()
	if len(recs) < 9 {
		t.Fatalf("only %d records", len(recs))
	}
	if ok, bad := evidence.Verify(recs); !ok {
		t.Fatalf("the chain breaks at %d", bad)
	}
	for _, r := range recs {
		if r["schema"] != evidence.Schema {
			t.Fatalf("seq %v is %v", r["seq"], r["schema"])
		}
	}
}

// -- Postgres end to end --------------------------------------------------------------------------------------------

var dbN atomic.Int64

// pgDSN is a scratch database on CLEARANCE_TEST_DSN's server (one per test: the writer lock is per database).
func pgDSN(t testing.TB) string {
	t.Helper()
	admin := os.Getenv("CLEARANCE_TEST_DSN")
	if admin == "" {
		t.Skip("CLEARANCE_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("clr_server_%d_%d", os.Getpid(), dbN.Add(1))
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		conn.Close(ctx)
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

func TestEndToEndOnPostgres(t *testing.T) {
	dsn := pgDSN(t)
	f := newFixture(t, config(t, dsn))
	runSequence(t, f)
	verifyChain(t, f)
	id := "0"
	f.core.Close()
	// Reopened (verified from genesis), the index still refuses a second outcome.
	g := newFixture(t, config(t, dsn))
	g.do("POST", "/v1/decisions/"+id+"/outcome", gw, map[string]any{"result": "ok"}).want(t, 409, "already")
	g.do("GET", "/readyz", "", nil).want(t, 200, "")
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// cancelingStore cancels the request's context once the decision's write is under way: the gateway's 250 ms timeout
// firing while a slow append is in flight.
type cancelingStore struct {
	store.Store
	cancel func()
}

func (c *cancelingStore) Atomic(ctx context.Context, fn func(tx store.Tx) error) error {
	return c.Store.Atomic(ctx, func(tx store.Tx) error {
		c.cancel()
		return fn(tx)
	})
}

func TestADecisionIsRecordedWhenTheClientCancelsMidWrite(t *testing.T) {
	f := memFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ps, err := server.ParseProviders(providersJSON)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(context.Background(), server.Options{Store: &cancelingStore{Store: f.core.Store, cancel: cancel},
		Engine: f.core.Engine, Auth: core.DevAuthenticator(), Providers: ps, Version: "test", MaxClockSkew: -1})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "/access/v1/evaluation", bytes.NewReader(request(t, modelAllowed, nil)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+gw)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if n := len(f.records()); n != 1 {
		t.Fatalf("the decision was made, so it is recorded even though the client has gone: %d records (%d %s)", n, rec.Code, rec.Body)
	}
}
