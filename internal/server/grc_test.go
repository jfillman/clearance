package server_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/grc"
	"github.com/jfillman/clearance/internal/grc/grctest"
	"github.com/jfillman/clearance/internal/server"
)

const grcPrincipal = "clearance/grc"

// grcFixture is a real core with clearance-grc registered as a provider of its own two kinds, a fake Vanta and a fake
// clearance-api serving the core's own changes.
func grcFixture(t *testing.T) (*fixture, *grctest.Vanta, *grctest.API, func() *grc.Service) {
	t.Helper()
	var base []map[string]any
	if err := json.Unmarshal([]byte(providersJSON), &base); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(append(base, map[string]any{"name": "clearance-grc", "version": "test", "principals": []string{grcPrincipal},
		"kinds": []string{"grc.push", "grc.report"}}))
	ps, err := server.ParseProviders(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, "")
	cfg.Providers = ps
	f := newFixture(t, cfg)
	hub, api := grctest.NewVanta("client-1", "gate-test-client-secret"), grctest.NewAPI()
	t.Cleanup(func() { hub.Close(); api.Close() })
	dir := t.TempDir()
	sec, tok := filepath.Join(dir, "secret"), filepath.Join(dir, "token")
	os.WriteFile(sec, []byte("gate-test-client-secret"), 0o600)
	os.WriteFile(tok, []byte(grcPrincipal), 0o600) // the dev authenticator reads the principal from the bearer
	env := map[string]string{"CLEARANCE_GRC_TARGET": "vanta", "CLEARANCE_GRC_VANTA_BASE_URL": hub.URL, "CLEARANCE_GRC_VANTA_CLIENT_ID": "client-1",
		"CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE": sec, "CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID": "res-ev", "CLEARANCE_GRC_VANTA_REPORT_RESOURCE_ID": "res-rep",
		"CLEARANCE_API_URL": api.URL, "CLEARANCE_URL": f.srv.URL, "CLEARANCE_GRC_SA_TOKEN_FILE": tok,
		"CLEARANCE_GRC_LINK_BASE": "https://clearance.example.com", "CLEARANCE_GRC_BACKOFF_BASE": "1ms", "CLEARANCE_GRC_BACKOFF_MAX": "2ms",
		"CLEARANCE_GRC_MAX_ATTEMPTS": "3"}
	gcfg, err := grc.ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	mk := func() *grc.Service {
		v, err := grc.NewVanta(gcfg.VantaBaseURL, gcfg.VantaClientID, gcfg.VantaSecretFile, "", gcfg.VantaEvidenceResource, gcfg.VantaReportResource)
		if err != nil {
			t.Fatal(err)
		}
		return grc.NewService(gcfg, v, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	return f, hub, api, mk
}

// clearedChange registers a change at the real core, clears it as a person, and returns the change as it is served.
func (f *fixture) clearedChange(t *testing.T, head string) gate.Change {
	t.Helper()
	c := change("pending")
	c["head"] = head
	id := f.do("POST", "/v1/clearances", ci, c).want(t, 200, "").body["id"].(string)
	// The clear answer is the change as clearance-api serves it (gate.Change's own JSON).
	b, _ := json.Marshal(f.do("POST", "/v1/clearances/"+id+"/clear", "user:erin", nil).want(t, 200, "").body)
	ch, err := gate.FromRecord(b)
	if err != nil || ch.State != "cleared" || ch.DecidedAt == nil {
		t.Fatalf("%v %+v", err, ch)
	}
	return *ch
}

// TestP4GRCPush is the P-4 gate against fakes (one command: `go test ./internal/server -run TestP4GRCPush`): a
// real change cleared at a real core appears as an evidence item at a fake Vanta, with a working link back, a
// grc.push record in the chain, a coverage report on its own resource, and nothing but the documented fields sent.
// The real-sandbox run is the owner's (docs/grc-push.md, "Run it against a Vanta sandbox").
func TestP4GRCPush(t *testing.T) {
	f, hub, api, mk := grcFixture(t)
	ctx := context.Background()
	ch := f.clearedChange(t, strings.Repeat("a", 40))
	api.Set(ch)

	// Registration: only the provider that names the kind may write it; the default-kinds providers may not.
	rec := map[string]any{"provider": "targets-dev", "kind": "grc.push", "record": map[string]any{"target": "vanta", "result": "pushed"}}
	f.do("POST", "/v1/records", "hangar-dev/gitops/targets", rec).want(t, 403, "may not write")
	rec["provider"] = "clearance-grc"
	f.do("POST", "/v1/records", "hangar-dev/gitops/targets", rec).want(t, 403, "")
	f.do("POST", "/v1/records", grcPrincipal, map[string]any{"provider": "clearance-grc", "kind": "grc.push", "record": map[string]any{"result": "pushed"}}).want(t, 400, "target")
	f.do("POST", "/v1/records", grcPrincipal, map[string]any{"provider": "clearance-grc", "kind": "deploy.outcome", "record": map[string]any{"app": "a", "target": "t", "outcome": map[string]any{}}}).want(t, 403, "may not write")

	svc := mk()
	if err := svc.PushOnce(ctx); err != nil {
		t.Fatal(err)
	}
	item, ok := hub.Item("res-ev", "clearance-change-"+ch.ID)
	if !ok {
		t.Fatal("the change is not an evidence item at the hub")
	}
	if item["externalUrl"] != "https://clearance.example.com/changes/"+ch.ID {
		t.Fatalf("link back: %v", item["externalUrl"])
	}
	props := item["customProperties"].(map[string]any)
	if props["origin"] != "person" || props["tier"] == nil || props["approver_kind"] != "person" || props["change_digest"] != strings.Repeat("c", 64) {
		t.Fatalf("%v", props)
	}
	pushes := f.toolRecords(server.KindGRCPush)
	if len(pushes) != 1 {
		t.Fatalf("%d grc.push records in the chain", len(pushes))
	}
	if p := pushes[0]["provider"].(map[string]any); p["name"] != "clearance-grc" {
		t.Fatalf("%v", p)
	}
	if pushes[0]["result"] != "pushed" || pushes[0]["target"] != "vanta" || pushes[0]["args_sha256"] == nil {
		t.Fatalf("%v", pushes[0])
	}

	// A restart and a retry: still one item and one record.
	if err := mk().PushOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if hub.Items("res-ev") != 1 || len(f.toolRecords(server.KindGRCPush)) != 1 {
		t.Fatalf("a restart duplicated: items %d records %d", hub.Items("res-ev"), len(f.toolRecords(server.KindGRCPush)))
	}

	// The report lands on its own resource and is a record.
	if err := svc.ReportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if hub.Items("res-rep") != 1 || len(f.toolRecords(server.KindGRCReport)) != 1 {
		t.Fatalf("report: items %d records %d", hub.Items("res-rep"), len(f.toolRecords(server.KindGRCReport)))
	}

	// The hub is down: the push fails, is bounded, and is a record; the core's decision path is not touched.
	ch2 := f.clearedChange(t, strings.Repeat("b", 40))
	api.Set(ch, ch2)
	for i := 0; i < 10; i++ {
		hub.Fail = append(hub.Fail, grctest.Failure{Status: 503})
	}
	puts := hub.Puts
	if err := svc.PushOnce(ctx); err == nil {
		t.Fatal("a failed push is an error")
	}
	if hub.Puts-puts != 3 {
		t.Fatalf("%d attempts, want 3", hub.Puts-puts)
	}
	var failed int
	for _, r := range f.toolRecords(server.KindGRCPush) {
		if r["result"] == "failed" {
			failed++
			if r["reason"] != "unavailable" {
				t.Fatalf("%v", r)
			}
		}
	}
	if failed != 1 {
		t.Fatalf("%d failed records", failed)
	}
	ch3 := f.clearedChange(t, strings.Repeat("d", 40)) // the core still decides while the hub is down
	if ch3.State != "cleared" {
		t.Fatal("the decision path was affected")
	}
	hub.Fail = nil
	api.Set(ch, ch2, ch3)
	if err := svc.PushOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if hub.Items("res-ev") != 3 {
		t.Fatalf("%d items after recovery", hub.Items("res-ev"))
	}

	// No credential or token in the chain, and none in anything sent to the hub beyond the token exchange itself.
	chain, _ := json.Marshal(f.records())
	for _, needle := range []string{"gate-test-client-secret", "secret-access-token", "Bearer"} {
		if strings.Contains(string(chain), needle) {
			t.Errorf("%q is in the chain", needle)
		}
	}
	for _, b := range hub.Bodies {
		for _, bad := range []string{"jfillman", "user:dana", "user:erin", "release.yaml", "hangar-prod"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("a body sent to the hub carries %q", bad)
			}
		}
	}
	_ = time.Second
}
