package core

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestConfigFromEnv(t *testing.T) {
	cfg, err := FromEnv(env(map[string]string{
		"CLEARANCE_DSN": "postgres://x", "CLEARANCE_PACKS": "hangar", "CLEARANCE_VERIFIERS": "a/*, b/c ,",
		"CLEARANCE_PROVIDERS":      `[{"name":"autopilot-gateway","version":"1","principals":["autopilot-system/clearance"]}]`,
		"CLEARANCE_EXPIRE_SECONDS": "15", "MODEL_ROUTES": "claude-sonnet-5=claude-sonnet-5-5,x=y",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" || cfg.ExpireEvery != 15*time.Second || len(cfg.Providers) != 1 || cfg.Auth == nil ||
		strings.Join(cfg.Gate.Verifiers, "|") != "a/*|b/c" || strings.Join(cfg.Gate.Models, "|") != "claude-sonnet-5|x" ||
		cfg.AgentLogins[0] != DefaultAgentLogin || cfg.GitHubApp != nil || cfg.Gate.Admins == nil {
		t.Fatalf("%+v", cfg)
	}
	for _, bad := range []map[string]string{
		{"CLEARANCE_PACKS": "nope"},
		{"CLEARANCE_PROVIDERS": "[{]"},
		{"CLEARANCE_EXPIRE_SECONDS": "-1"},
		{"CLEARANCE_EXPIRE_SECONDS": "x"},
		{"MODEL_ROUTES": "alias"},
		{"CLEARANCE_GITHUB_APP_ID": "1"},
		{"CLEARANCE_GITHUB_APP_COMMENTS": "all"},
		{"CLEARANCE_OIDC_ISSUER": "https://dex"},
	} {
		if _, err := FromEnv(env(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestBuildNeedsAStoreAndAnAuthenticator(t *testing.T) {
	if _, err := Build(context.Background(), Config{Memory: true}, nil, nil); err == nil {
		t.Fatal("built without an authenticator")
	}
	if _, err := Build(context.Background(), Config{Auth: DevAuthenticator()}, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "CLEARANCE_DSN") {
		t.Fatal(err)
	}
}

func TestDevAuthenticator(t *testing.T) {
	a := DevAuthenticator()
	p, err := a.Authenticate(context.Background(), "user:alice")
	if err != nil || p.ID != "user:alice" || !p.IsPerson() {
		t.Fatal(p, err)
	}
	p, err = a.Authenticate(context.Background(), "autopilot-system/clearance")
	if err != nil || p.IsPerson() {
		t.Fatal(p, err)
	}
	if _, err := a.Authenticate(context.Background(), "two words"); err == nil {
		t.Fatal("accepted a token with a space")
	}
}

// TestRunServesAndShutsDownOnCancel is `clearance core --memory`: it serves, and a cancelled context (SIGTERM in
// main) shuts it down cleanly.
func TestRunServesAndShutsDownOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	addr := make(chan string, 1)
	done := make(chan error, 1)
	cfg := Config{Memory: true, Listen: "127.0.0.1:0", Auth: DevAuthenticator(), ExpireEvery: 10 * time.Millisecond}
	go func() {
		done <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func(a string) { addr <- a })
	}()
	var a string
	select {
	case a = <-addr:
	case err := <-done:
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + a + "/readyz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(resp, err)
	}
	resp.Body.Close()
	time.Sleep(30 * time.Millisecond) // a few expiry ticks
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
