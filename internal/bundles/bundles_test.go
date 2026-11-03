package bundles_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/bundles"
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

func TestAnUnreachableSourceFailsClosed(t *testing.T) {
	s, _, _ := serve(t, contract(t, 1), 1000)
	_, err := bundles.Engine(context.Background(), cfg(t, s.URL+"/v1/contract", 0), nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatal(err)
	}
	c := cfg(t, s.URL, 0)
	c.Sources = map[string]bundles.Source{}
	if _, err := bundles.Engine(context.Background(), c, nil); err == nil || !strings.Contains(err.Error(), "no CLEARANCE_BUNDLE_SOURCES entry") {
		t.Fatal(err)
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
