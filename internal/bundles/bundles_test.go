package bundles_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/bundles"
	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/decide/decidetest"
)

func contract(t *testing.T, version int) []byte {
	t.Helper()
	raw, err := os.ReadFile(decidetest.FixtureSource())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["contractVersion"] = version
	out, _ := json.Marshal(doc)
	return out
}

// serve is a contract endpoint (GET /v1/contract) that answers 503 for the first `down` requests.
func serve(t *testing.T, body []byte, down int32) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	var hits atomic.Int32
	var auth atomic.Value
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		auth.Store(r.Header.Get("Authorization"))
		if r.URL.Path != "/v1/contract" || n <= down {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s, &hits, &auth
}

func cfg(t *testing.T, url string, wait time.Duration) bundles.Config {
	t.Helper()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("projected-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src, _ := json.Marshal(map[string]any{"glidepath": map[string]string{"url": url, "tokenFile": tok}})
	c, err := bundles.FromEnv(func(k string) string {
		return map[string]string{"CLEARANCE_BUNDLES": decidetest.FixtureBundle(), "CLEARANCE_BUNDLE_SOURCES": string(src),
			"CLEARANCE_BUNDLE_SOURCE_WAIT": wait.String(), "CLEARANCE_ENV_LOWER_PREFIXES": "pr-,agent-"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTheBundleReadsItsSourceLiveWithAToken(t *testing.T) {
	s, _, auth := serve(t, contract(t, 1), 0)
	c := cfg(t, s.URL+"/v1/contract", time.Second)
	if strings.Join(c.Environments.LowerPrefixes, ",") != "pr-,agent-" || len(c.Environments.LowerNames) != 4 {
		t.Fatalf("environments %+v", c.Environments)
	}
	e, err := bundles.Engine(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Load() != "Bearer projected-token" {
		t.Fatalf("Authorization %v", auth.Load())
	}
	pol := e.Policy()
	if pol.Bundle != "clearance-core+hangar" || len(pol.Bundles) != 1 || pol.Bundles[0].Version != "1.0.0" ||
		len(pol.Bundles[0].Sources) != 1 || pol.Bundles[0].Sources[0].Version != 1 {
		t.Fatalf("%+v", pol)
	}
	// A different contract is a different policy version: a Glidepath scope change shows in every decision.
	s2, _, _ := serve(t, append(contract(t, 1)[:len(contract(t, 1))-1], []byte(`,"extra":1}`)...), 0)
	e2, err := bundles.Engine(context.Background(), cfg(t, s2.URL+"/v1/contract", time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if e2.Policy().Version == pol.Version {
		t.Fatal("a changed source document left the policy version unchanged")
	}
}

func TestAnIncompatibleContractVersionFailsTheLoad(t *testing.T) {
	s, _, _ := serve(t, contract(t, 2), 0)
	_, err := bundles.Engine(context.Background(), cfg(t, s.URL+"/v1/contract", time.Second), nil)
	if err == nil || !strings.Contains(err.Error(), "is version 2; this bundle is written for [1]") {
		t.Fatal(err)
	}
}

func TestASourceThatComesUpWithinTheWaitLoads(t *testing.T) {
	s, hits, _ := serve(t, contract(t, 1), 1)
	if _, err := bundles.Engine(context.Background(), cfg(t, s.URL+"/v1/contract", 10*time.Second), nil); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("%d requests", hits.Load())
	}
}

func TestAMissingSourceEntryFailsTheStart(t *testing.T) {
	c := cfg(t, "http://unused", 0)
	c.Sources = map[string]bundles.Source{}
	if _, err := bundles.Engine(context.Background(), c, nil); err == nil || !strings.Contains(err.Error(), "no CLEARANCE_BUNDLE_SOURCES entry") {
		t.Fatal(err)
	}
}

const decideReq = `{"subject":{"type":"principal","id":"user:alice","properties":{"kind":"user","tier_ceiling":2}},
 "action":{"name":"tool.call","properties":{"args":%s}},"resource":{"type":"tool","id":"%s"},
 "context":{"now":"2026-09-26T12:00:00Z","session_id":"s-1","session":{"id":"s-1","principal":"user:alice",
  "agent":"a","task_id":"t-1","parent_id":null,"depth":0,
  "limits":{"tier_ceiling":"T2","ttl_minutes":30,"tool_calls":10,"github_calls":10,"open_prs":1,"model_tokens":0,
   "children":0,"tools":["glidepath.runs.list","repo.pr.open","catalog.read"],"models":[],"network":"clearance","compute":"small"},
  "used":{"tool_calls":0,"github_calls":0,"open_prs":0,"model_tokens":0,"children":0},
  "reserved":{"tool_calls":0,"github_calls":0,"open_prs":0,"model_tokens":0,"children":0},
  "expires_at":"2026-09-26T12:30:00Z","closed":false,"tripped":false,"denials":0},
  "scope":{"agent_kind":"task","deny_paths":[],"repos_allow":["jfillman/*"],"api_allow":[],"field_deny":[],"field_allow":[],
   "profile":{"glidepath":{"apps":["gate-api"]}}}}}`

func decideOn(t *testing.T, e *decide.Engine, tool, args string) *decide.EvaluationResponse {
	t.Helper()
	req, err := decide.DecodeEvaluation(strings.NewReader(fmt.Sprintf(decideReq, args, tool)))
	if err != nil {
		t.Fatal(err)
	}
	return e.Decide(context.Background(), req)
}

const (
	cicdLoosened = `{"repo":"jfillman/gate-api","branch":"b","title":"t","files":[{"path":"cicd.yaml",` +
		`"before":"governance: {sast: true}","content":"governance: {sast: false}"}]}`
	otherFile = `{"repo":"jfillman/gate-api","branch":"b","title":"t","files":[{"path":"charts/values.yaml","content":"x: 1"}]}`
)

// Down at start, then up: the core starts with the bundle degraded (its tools and the checks needing the source
// refused, R000, nothing charged; everything else decides as before), and Watch loads it whole once the source
// answers, after which decisions use it and name it.
func TestASourceDownAtStartDegradesTheBundleUntilItAnswers(t *testing.T) {
	defer bundles.SetRetryInterval(20 * time.Millisecond)()
	s, hits, _ := serve(t, contract(t, 1), 3) // three 503s: the start's attempt, then two of Watch's
	e, err := bundles.Engine(context.Background(), cfg(t, s.URL+"/v1/contract", 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	pol := e.Policy()
	if len(pol.Bundles) != 1 || pol.Bundles[0].Status != "unavailable" || len(pol.Bundles[0].Unavailable) != 1 ||
		!strings.Contains(pol.Bundles[0].Unavailable[0].Error, "HTTP 503") || len(e.Degraded()) != 1 {
		t.Fatalf("%+v", pol)
	}
	// The bundle's own tool: refused, the bundle named, no denial spent.
	d := decideOn(t, e, "glidepath.runs.list", `{"app":"gate-api"}`)
	c := d.Context
	if d.Decision || c.Rule != "R000" || !strings.Contains(c.Message, "policy bundle hangar is unavailable: its source glidepath could not be read") ||
		c.Spend.Denial || c.Tier == nil || *c.Tier != 0 {
		t.Fatalf("%+v", c)
	}
	// A file the bundle's document checks with the missing rules: refused. Any other file, and core tools: decided.
	if d := decideOn(t, e, "repo.pr.open", cicdLoosened); d.Decision || d.Context.Rule != "R000" {
		t.Fatalf("%+v", d.Context)
	}
	if d := decideOn(t, e, "repo.pr.open", otherFile); !d.Decision {
		t.Fatalf("%+v", d.Context)
	}
	if d := decideOn(t, e, "catalog.read", `{"query":"x"}`); !d.Decision {
		t.Fatalf("%+v", d.Context)
	}
	degradedVersion := pol.Version

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { bundles.Watch(ctx, cfg(t, s.URL+"/v1/contract", 0), e, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Watch did not load the bundle")
	}
	if hits.Load() < 4 {
		t.Fatalf("%d fetches", hits.Load())
	}
	pol = e.Policy()
	if pol.Bundles[0].Status != "loaded" || len(pol.Bundles[0].Sources) != 1 || pol.Version == degradedVersion || len(e.Degraded()) != 0 {
		t.Fatalf("%+v", pol)
	}
	// Decisions now use the bundle: its tool decides, and the cicd.yaml change gets its GP-SCOPE finding.
	if d := decideOn(t, e, "glidepath.runs.list", `{"app":"gate-api"}`); !d.Decision || d.Context.Policy.Bundles[0].Status != "loaded" {
		t.Fatalf("%+v", d.Context)
	}
	if d := decideOn(t, e, "repo.pr.open", cicdLoosened); d.Decision || d.Context.Rule != "GP-SCOPE-002" || len(d.Context.Problems) != 1 {
		t.Fatalf("%+v", d.Context)
	}
}

// A version the bundle does not list is configuration, not an outage: at start it is refused; found later by
// Watch, it is logged and the bundle stays degraded.
func TestAnIncompatibleVersionAfterTheStartKeepsTheBundleDegraded(t *testing.T) {
	defer bundles.SetRetryInterval(10 * time.Millisecond)()
	s, hits, _ := serve(t, contract(t, 2), 1)
	e, err := bundles.Engine(context.Background(), cfg(t, s.URL+"/v1/contract", 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	bundles.Watch(ctx, cfg(t, s.URL+"/v1/contract", 0), e, nil)
	if hits.Load() < 2 || len(e.Degraded()) != 1 {
		t.Fatalf("hits %d degraded %d", hits.Load(), len(e.Degraded()))
	}
}

func TestAFileSource(t *testing.T) {
	c := cfg(t, "http://unused", 0)
	c.Sources = map[string]bundles.Source{"glidepath": {File: decidetest.FixtureSource()}}
	e, err := bundles.Engine(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Policy().Bundles[0].Sources[0].Version != 1 {
		t.Fatal(e.Policy())
	}
}

func TestNoBundlesIsTheCoreAlone(t *testing.T) {
	c, err := bundles.FromEnv(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	e, err := bundles.Engine(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Policy().Bundle != "clearance-core" || e.Tool("glidepath.runs.list") != nil {
		t.Fatal(e.Policy())
	}
}
