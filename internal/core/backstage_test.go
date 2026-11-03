package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBackstage is Tower's catalog: people's memberOf groups and Components' owners, switchable to down.
type fakeBackstage struct {
	mu     sync.Mutex
	groups map[string][]string // login -> group refs
	owners map[string]string   // app -> spec.owner
	down   bool
	asked  int
}

func (f *fakeBackstage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked++
	if f.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("Authorization") != "Bearer backstage-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/api/catalog/entities/by-name/")
	if login, ok := strings.CutPrefix(p, "user/default/"); ok {
		if gs, ok := f.groups[login]; ok {
			rels := []any{}
			for _, g := range gs {
				rels = append(rels, map[string]any{"type": "memberOf", "targetRef": g})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"relations": rels})
			return
		}
	}
	if app, ok := strings.CutPrefix(p, "component/default/"); ok {
		if o, ok := f.owners[app]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"spec": map[string]any{"owner": o}})
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func (f *fakeBackstage) set(fn func(*fakeBackstage)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

type gateFixture struct {
	t     *testing.T
	core  *httptest.Server
	now   time.Time
	mu    sync.Mutex
	stage *fakeBackstage
}

func (g *gateFixture) clock() time.Time { g.mu.Lock(); defer g.mu.Unlock(); return g.now }
func (g *gateFixture) advance(d time.Duration) {
	g.mu.Lock()
	g.now = g.now.Add(d)
	g.mu.Unlock()
}

// newGateFixture builds the core with core.Build from a Config read by FromEnv (BACKSTAGE_URL and
// BACKSTAGE_TOKEN_FILE), and serves its handler.
func newGateFixture(t *testing.T, stage *fakeBackstage, backstageURL string) *gateFixture {
	t.Helper()
	tok := filepath.Join(t.TempDir(), "backstage-token")
	if err := os.WriteFile(tok, []byte("backstage-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := FromEnv(env(map[string]string{"BACKSTAGE_URL": backstageURL, "BACKSTAGE_TOKEN_FILE": tok,
		"CLEARANCE_VERIFIERS": "glidepath-system/verifier"}))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Memory, cfg.Auth = true, DevAuthenticator()
	g := &gateFixture{t: t, now: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC), stage: stage}
	c, err := Build(context.Background(), cfg, g.clock, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	g.core = httptest.NewServer(c.Server.Handler())
	t.Cleanup(g.core.Close)
	return g
}

func (g *gateFixture) post(who, path string, body any) (int, map[string]any) {
	g.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", g.core.URL+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+who)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// register registers a tier-2 change (a Deployment's replicas) for app web, naming no owner: the gate asks Owners.
func (g *gateFixture) register(pr int) string {
	g.t.Helper()
	body := map[string]any{"app": "web", "env": "prod", "cluster": "hangar-prod", "repo": "jfillman/web",
		"pr": pr, "head": strings.Repeat("a", 39) + string(rune('0'+pr)), "proposer": "user:dana",
		"proposerKind": "person", "protected": true, "treeDigest": "sha256:" + strings.Repeat("b", 64),
		"checks": map[string]string{"ci": "pass", "provenance": "not-agent", "render": "ok"},
		"paths":  []string{"values-prod.yaml"}, "linesChanged": 1,
		"objects": []any{map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "namespace": "web",
			"name": "web", "op": "changed", "fields": []string{"/spec/replicas"}}}}
	status, out := g.post("glidepath-system/verifier", "/v1/clearances", body)
	if status != 200 && status != 201 {
		g.t.Fatalf("register: %d %v", status, out)
	}
	if out["tier"] != float64(2) || out["state"] != "holding" {
		g.t.Fatalf("not a held tier-2 change: %v", out)
	}
	id, _ := out["id"].(string)
	if id == "" {
		g.t.Fatalf("no id: %v", out)
	}
	return id
}

// A member of the app's owner group (both read from Backstage) clears a tier-2 change through the HTTP API; someone
// in no group is DG-FORBIDDEN.
func TestGateClearsByBackstageOwnerGroup(t *testing.T) {
	stage := &fakeBackstage{groups: map[string][]string{"alice": {"group:default/team-web"}, "bob": {"group:default/other"}},
		owners: map[string]string{"web": "team-web"}}
	bs := httptest.NewServer(stage)
	defer bs.Close()
	g := newGateFixture(t, stage, bs.URL)

	id := g.register(1)
	status, out := g.post("user:bob", "/v1/clearances/"+id+"/clear", map[string]any{})
	if status != 403 || out["rule"] != "DG-FORBIDDEN" {
		t.Fatalf("bob: %d %v", status, out)
	}
	status, out = g.post("user:alice", "/v1/clearances/"+id+"/clear", map[string]any{})
	if status != 200 || out["state"] != "cleared" {
		t.Fatalf("alice: %d %v", status, out)
	}
	if out["owner"] != "group:default/team-web" {
		t.Fatalf("owner group not from Backstage: %v", out["owner"])
	}
}

// Backstage down: nobody is in any group, so a would-be member cannot clear; it never allows.
func TestGateBackstageDownCannotClear(t *testing.T) {
	stage := &fakeBackstage{groups: map[string][]string{"alice": {"group:default/team-web", "group:default/admins"}},
		owners: map[string]string{"web": "team-web"}}
	bs := httptest.NewServer(stage)
	defer bs.Close()
	g := newGateFixture(t, stage, bs.URL)
	id := g.register(2) // the owner is read while Backstage is up
	stage.set(func(f *fakeBackstage) { f.down = true })
	status, out := g.post("user:alice", "/v1/clearances/"+id+"/clear", map[string]any{})
	if status != 403 || out["rule"] != "DG-FORBIDDEN" {
		t.Fatalf("cleared with Backstage down: %d %v", status, out)
	}

	// Unreachable altogether, and the owner unknown at registration: the outside group stands in as owner, and
	// still nobody is in it.
	bs.Close()
	g2 := newGateFixture(t, stage, bs.URL)
	id2 := g2.register(3)
	status, out = g2.post("user:alice", "/v1/clearances/"+id2+"/clear", map[string]any{})
	if status != 403 || out["rule"] != "DG-FORBIDDEN" {
		t.Fatalf("cleared with Backstage unreachable: %d %v", status, out)
	}
}

// Group membership is cached for 60 s: a person added to the owner group can clear once the cache expires.
func TestGateDirectoryCacheExpires(t *testing.T) {
	stage := &fakeBackstage{groups: map[string][]string{"carol": {}}, owners: map[string]string{"web": "group:default/team-web"}}
	bs := httptest.NewServer(stage)
	defer bs.Close()
	g := newGateFixture(t, stage, bs.URL)
	id := g.register(4)
	if status, out := g.post("user:carol", "/v1/clearances/"+id+"/clear", map[string]any{}); status != 403 {
		t.Fatalf("carol before: %d %v", status, out)
	}
	stage.set(func(f *fakeBackstage) { f.groups["carol"] = []string{"group:default/team-web"} })
	g.advance(30 * time.Second)
	if status, out := g.post("user:carol", "/v1/clearances/"+id+"/clear", map[string]any{}); status != 403 {
		t.Fatalf("carol inside the TTL: %d %v (not cached)", status, out)
	}
	g.advance(31 * time.Second)
	if status, out := g.post("user:carol", "/v1/clearances/"+id+"/clear", map[string]any{}); status != 200 ||
		out["state"] != "cleared" {
		t.Fatalf("carol after the TTL: %d %v", status, out)
	}
}

// No BACKSTAGE_URL: neither is wired (serve.py), and the startup says people cannot clear.
func TestGateWithoutBackstage(t *testing.T) {
	var logs bytes.Buffer
	c, err := Build(context.Background(), Config{Memory: true, Auth: DevAuthenticator()}, nil,
		slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Gate.Directory != nil || c.Gate.Owners != nil {
		t.Fatal("wired a directory without BACKSTAGE_URL")
	}
	if !strings.Contains(logs.String(), "no person can clear a tier-2 or tier-3 change") {
		t.Fatal(logs.String())
	}
}

func TestBackstageEnv(t *testing.T) {
	cfg, err := FromEnv(env(map[string]string{"BACKSTAGE_URL": "http://backstage.tower:7007"}))
	if err != nil || cfg.BackstageURL != "http://backstage.tower:7007" || cfg.BackstageTokenFile != "/var/run/clearance/backstage-token" {
		t.Fatal(cfg.BackstageURL, cfg.BackstageTokenFile, err)
	}
	if cfg, _ := FromEnv(env(nil)); cfg.BackstageURL != "" {
		t.Fatal(cfg.BackstageURL)
	}
	for _, bad := range []string{"backstage:7007", "ftp://x", "http://", "http://u:p@x", "http://x/?q=1", "::"} {
		if _, err := FromEnv(env(map[string]string{"BACKSTAGE_URL": bad})); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
