package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestAPanicIsA500WithoutItsStack(t *testing.T) {
	var logs bytes.Buffer
	s := &Server{log: slog.New(slog.NewTextHandler(&logs, nil))}
	h := s.recoverer(s.accessLog(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("secret detail in a panic")
	})))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	if w.Code != 500 || strings.Contains(w.Body.String(), "secret detail") || strings.Contains(w.Body.String(), "goroutine") {
		t.Fatal(w.Code, w.Body.String())
	}
	var body map[string]any
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || body["error"] != "internal error" {
		t.Fatal(w.Body.String())
	}
}

func TestTheAccessLogHasNoBodyHeaderOrToken(t *testing.T) {
	var logs bytes.Buffer
	s := &Server{log: slog.New(slog.NewTextHandler(&logs, nil))}
	h := s.accessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(201)
	}))
	req := httptest.NewRequest("POST", "/v1/records?token=leak-q", strings.NewReader(`{"secret":"leak-b"}`))
	req.Header.Set("Authorization", "Bearer leak-h")
	h.ServeHTTP(httptest.NewRecorder(), req)
	line := logs.String()
	if !strings.Contains(line, "status=201") || !strings.Contains(line, "path=/v1/records") {
		t.Fatal(line)
	}
	for _, leak := range []string{"leak-q", "leak-b", "leak-h"} {
		if strings.Contains(line, leak) {
			t.Fatalf("the access log carries %s: %s", leak, line)
		}
	}
}

func TestProvidersConfig(t *testing.T) {
	good := `[{"name":"autopilot-gateway","version":"0.3.27","principals":["autopilot-system/clearance"]}]`
	ps, err := ParseProviders(good)
	if err != nil || len(ps) != 1 || !ps[0].matches("autopilot-system/clearance") || ps[0].matches("autopilot-system/other") {
		t.Fatal(ps, err)
	}
	two := `[{"name":"x","version":"1","principals":["a/b"],"definitions":true,"kinds":["tool.call","run.finish"]},` +
		`{"name":"y","version":"1","principals":["c/d"]}]`
	if ps, err := ParseProviders(two); err != nil || !ps[0].Definitions || ps[1].Definitions || !ps[0].mayWrite("tool.call") {
		t.Fatal(ps, err)
	}
	// kinds absent is every non-observation kind; kinds [] is none (and survives a re-marshal); [] needs a grant.
	none := `[{"name":"x","version":"1","principals":["a/b"],"kinds":[],"targets":["s"]},` +
		`{"name":"y","version":"1","principals":["c/d"],"targets":["s"]},` +
		`{"name":"z","version":"1","principals":["e/f"],"kinds":[],"definitions":true}]`
	ps, err = ParseProviders(none)
	if err != nil || ps[0].mayWrite("tool.call") || ps[0].mayWrite("observation") ||
		!ps[1].mayWrite("tool.call") || ps[1].mayWrite("observation") || ps[2].mayWrite("tool.call") {
		t.Fatal(ps, err)
	}
	if raw, _ := json.Marshal(ps[0]); !strings.Contains(string(raw), `"kinds":[]`) {
		t.Fatal(string(raw))
	}
	if _, err := ParseProviders(`[{"name":"x","version":"1","principals":["a/b"],"kinds":[]}]`); err == nil ||
		!strings.Contains(err.Error(), "could do nothing") {
		t.Fatal(err)
	}
	if ps, err := ParseProviders(""); err != nil || ps != nil {
		t.Fatal(ps, err)
	}
	for _, bad := range []string{
		`{}`, `[{"name":"x","version":"1","principals":["a/b"],"extra":1}]`,
		`[{"name":"Bad Name","version":"1","principals":["a/b"]}]`,
		`[{"name":"clearance","version":"1","principals":["a/b"]}]`,
		`[{"name":"x","version":"","principals":["a/b"]}]`,
		`[{"name":"x","version":"1","principals":[]}]`,
		`[{"name":"x","version":"1","principals":[""]}]`,
		`[{"name":"x","version":"1","principals":["a/b"],"kinds":["model.call"]}]`,
		`[{"name":"x","version":"1","principals":["a/b"],"kinds":["definition.load"]}]`,
		`[{"name":"x","version":"1","principals":["a/b"],"definitions":"yes"}]`,
		`[{"name":"x","version":"1","principals":["a/b"],"definitions":true},` +
			`{"name":"y","version":"1","principals":["c/d"],"definitions":true}]`,
		`[{"name":"x","version":"1","principals":["a/b"],"intent_capture":"some"}]`,
		`[{"name":"x","version":"1","principals":["a/b"]},{"name":"x","version":"2","principals":["c/d"]}]`,
		good + ` []`,
	} {
		if _, err := ParseProviders(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestRoutePatternsAndCaps(t *testing.T) {
	seen := map[string]bool{}
	for _, rt := range Routes() {
		if seen[rt.Pattern()] || rt.OperationID == "" || rt.MaxBody <= 0 || len(rt.Responses) == 0 {
			t.Fatalf("bad route %+v", rt)
		}
		seen[rt.Pattern()] = true
	}
	for path, want := range map[string]int64{"/access/v1/evaluation": MaxEvaluationBody, "/v1/decisions/7/outcome": MaxOutcomeBody,
		"/v1/clearances/ch-1/deny": 64 << 10, "/v1/github/webhook": 25 << 20, "/v1/terraform/run-task": 64 << 10, "/v1/decisions//outcome": DefaultMaxBody} {
		if got, _ := capFor(httptest.NewRequest("POST", path, nil)); got != want {
			t.Errorf("%s: cap %d, want %d", path, got, want)
		}
	}
}

// TestContractIsCurrent regenerates the contract and fails when the committed file differs: run
// `go generate ./internal/server` after changing a route or a request or response type.
func TestContractIsCurrent(t *testing.T) {
	got, err := Contract()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../" + ContractPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: run go generate ./internal/server", ContractPath)
	}
	var doc map[string]any
	if err := json.Unmarshal(got, &doc); err != nil || doc["openapi"] != "3.1.0" {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	for _, rt := range Routes() {
		if _, ok := paths[rt.Path].(map[string]any)[strings.ToLower(rt.Method)]; !ok {
			t.Errorf("%s is not in the contract", rt.Pattern())
		}
	}
	// Strict request bodies say so.
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	for _, n := range []string{"OutcomeRequest", "RecordRequest", "ProviderEvent", "DecideEvaluationRequest"} {
		if schemas[n].(map[string]any)["additionalProperties"] != false {
			t.Errorf("%s is not strict in the contract", n)
		}
	}
}
