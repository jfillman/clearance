package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/bundles"
	"github.com/jfillman/clearance/internal/decide/decidetest"
	"github.com/jfillman/clearance/internal/server"
)

const evalBody = `{"subject":{"type":"principal","id":"user:alice","properties":{"kind":"user","tier_ceiling":2}},
 "action":{"name":"tool.call","properties":{"args":%s}},"resource":{"type":"tool","id":"%s"},
 "context":{"now":"%s","session_id":"s-1","session":{"id":"s-1","principal":"user:alice",
  "agent":"a","task_id":"t-1","parent_id":null,"depth":0,
  "limits":{"tier_ceiling":"T2","ttl_minutes":30,"tool_calls":10,"github_calls":10,"open_prs":1,"model_tokens":0,
   "children":0,"tools":["glidepath.runs.list","repo.pr.open"],"models":[],"network":"clearance","compute":"small"},
  "used":{"tool_calls":0,"github_calls":0,"open_prs":0,"model_tokens":0,"children":0},
  "reserved":{"tool_calls":0,"github_calls":0,"open_prs":0,"model_tokens":0,"children":0},
  "expires_at":"2099-01-01T00:00:00Z","closed":false,"tripped":false,"denials":0},
  "scope":{"agent_kind":"task","deny_paths":[],"repos_allow":["jfillman/*"],"api_allow":[],"field_deny":[],"field_allow":[],
   "profile":{"glidepath":{"apps":["gate-api"]}}}}}`

// glidepath-api is down when the core starts: the core serves (ready, the bundle named degraded), records the
// bundle's refused calls, keeps the gate up, and decides with the bundle once the source answers.
func TestACoreStartsWithADegradedBundleAndLoadsItWhenTheSourceAnswers(t *testing.T) {
	defer func(d time.Duration) { bundles.RetryInterval = d }(bundles.RetryInterval)
	bundles.RetryInterval = 20 * time.Millisecond
	contract, err := os.ReadFile(decidetest.FixtureSource())
	if err != nil {
		t.Fatal(err)
	}
	var up atomic.Bool
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !up.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Write(contract)
	}))
	defer src.Close()
	cfg := Config{Memory: true, Listen: "127.0.0.1:0", Auth: DevAuthenticator(), ExpireEvery: time.Hour, Version: "t",
		Providers: []server.Provider{{Name: "gw", Version: "1", Principals: []string{"gw/gw"}}}, MaxClockSkew: -1}
	cfg.Policy, err = bundles.FromEnv(func(k string) string {
		return map[string]string{"CLEARANCE_BUNDLES": decidetest.FixtureBundle(), "CLEARANCE_BUNDLE_SOURCE_WAIT": "0s",
			"CLEARANCE_BUNDLE_SOURCES": fmt.Sprintf(`{"glidepath":{"url":%q}}`, src.URL)}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, done := make(chan string, 1), make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func(a string) { addr <- a })
	}()
	var base string
	select {
	case a := <-addr:
		base = "http://" + a
	case err := <-done:
		t.Fatal("the core did not start with its bundle's source down: ", err)
	}
	ready := func() server.Ready {
		resp, err := http.Get(base + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("readyz %d", resp.StatusCode)
		}
		var r server.Ready
		_ = json.NewDecoder(resp.Body).Decode(&r)
		return r
	}
	evaluate := func(tool, args string) map[string]any {
		body := fmt.Sprintf(evalBody, args, tool, time.Now().UTC().Format(time.RFC3339))
		req, _ := http.NewRequest("POST", base+"/access/v1/evaluation", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer gw/gw")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != 200 {
			t.Fatalf("evaluation %d %v", resp.StatusCode, out)
		}
		return out
	}
	if r := ready(); !r.OK || strings.Join(r.Degraded, ",") != "hangar" || r.Policy.Bundles[0].Status != "unavailable" {
		t.Fatalf("%+v", r)
	}
	out := evaluate("glidepath.runs.list", `{"app":"gate-api"}`)
	c := out["context"].(map[string]any)
	if out["decision"] != false || c["rule"] != "R000" || !strings.Contains(c["message"].(string), "policy bundle hangar is unavailable") ||
		out["decision_id"] == nil {
		t.Fatalf("a degraded bundle's call is refused and recorded: %v", out)
	}
	// The gate is up: an unknown change is the gate's own answer, not an outage.
	req, _ := http.NewRequest("POST", base+"/v1/clearances/ch-nope/clear", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer user:alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		t.Fatalf("gate %d", resp.StatusCode)
	}

	up.Store(true)
	deadline := time.Now().Add(10 * time.Second)
	for len(ready().Degraded) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("the bundle did not load once its source answered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	out = evaluate("repo.pr.open", `{"repo":"jfillman/gate-api","branch":"b","title":"t","files":[{"path":"cicd.yaml",`+
		`"before":"governance: {sast: true}","content":"governance: {sast: false}"}]}`)
	c = out["context"].(map[string]any)
	pol := c["policy"].(map[string]any)["bundles"].([]any)[0].(map[string]any)
	if out["decision"] != false || c["rule"] != "GP-SCOPE-002" || pol["status"] != "loaded" {
		t.Fatalf("decisions use the loaded bundle: %v", out)
	}
	if out := evaluate("glidepath.runs.list", `{"app":"gate-api"}`); out["decision"] != true {
		t.Fatalf("%v", out)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
