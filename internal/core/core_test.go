package core

import (
	"context"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
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
		"CLEARANCE_DSN": "postgres://x", "CLEARANCE_BUNDLES": "/b/hangar.json", "CLEARANCE_VERIFIERS": "a/*, b/c ,",
		"AGENT_LOGINS": vocabtest.AgentLogin, "CLEARANCE_TRAILER_PREFIX": "Hangar-",
		"CLEARANCE_PROVIDERS":      `[{"name":"autopilot-gateway","version":"1","principals":["autopilot-system/clearance"]}]`,
		"CLEARANCE_EXPIRE_SECONDS": "15", "MODEL_ROUTES": "claude-sonnet-5=claude-sonnet-5-5,x=y",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" || cfg.ExpireEvery != 15*time.Second || len(cfg.Providers) != 1 || cfg.Auth == nil ||
		strings.Join(cfg.Gate.Verifiers, "|") != "a/*|b/c" || strings.Join(cfg.Gate.Models, "|") != "claude-sonnet-5|x" ||
		cfg.AgentLogins[0] != vocabtest.AgentLogin || cfg.GitHubApp != nil || cfg.Gate.Admins == nil ||
		strings.Join(cfg.Policy.Files, "|") != "/b/hangar.json" || cfg.Vocabulary.TrailerPrefix != "Hangar-" ||
		cfg.Vocabulary.OnBehalfOfHeader != "X-Clearance-On-Behalf-Of" {
		t.Fatalf("%+v", cfg)
	}
	for _, bad := range []map[string]string{
		{"CLEARANCE_PACKS": "hangar"},
		{"CLEARANCE_FLIGHT_REGISTRIES": "ghcr.io/x/"},
		{"CLEARANCE_BUNDLE_SOURCES": `{"x": {}}`},
		{"CLEARANCE_BUNDLE_SOURCES": `{"x": {"url": "ftp://h/x"}}`},
		{"CLEARANCE_BUNDLE_SOURCE_WAIT": "soon"},
		{"CLEARANCE_TRAILER_PREFIX": "a b"},
		{"CLEARANCE_V0_PROVIDER": "noversion"},
		{"CLEARANCE_PROVIDERS": "[{]"},
		{"CLEARANCE_EXPIRE_SECONDS": "-1"},
		{"CLEARANCE_EXPIRE_SECONDS": "x"},
		{"MODEL_ROUTES": "alias"},
		{"CLEARANCE_GITHUB_APP_ID": "1"},
		{"CLEARANCE_GITHUB_APP_COMMENTS": "all"},
		{"CLEARANCE_OIDC_ISSUER": "https://dex"},
		{"CLEARANCE_TRUSTED_REGISTRIES": "ghcr.io/acme"},
		{"CLEARANCE_TRUSTED_REGISTRIES": "ghcr.io/a b/"},
		{"CLEARANCE_GATE_UNBOUND_TREE": "warn"},
	} {
		if _, err := FromEnv(env(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestTheClockSkewSetting(t *testing.T) {
	for v, want := range map[string]time.Duration{"": 0, "0": -1, "0s": -1, "30s": 30 * time.Second, "10m": 10 * time.Minute,
		"24h": 24 * time.Hour} {
		got, err := ParseMaxClockSkew(v)
		if err != nil || got != want {
			t.Errorf("%q: %v %v, want %v", v, got, err, want)
		}
	}
	for _, bad := range []string{"5", "-1m", "25h", "soon"} {
		if _, err := ParseMaxClockSkew(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	cfg, err := FromEnv(env(map[string]string{"CLEARANCE_MAX_CLOCK_SKEW": "90s"}))
	if err != nil || cfg.MaxClockSkew != 90*time.Second || cfg.CheckMaxClockSkew() != nil {
		t.Fatal(cfg.MaxClockSkew, err)
	}
	if _, err := FromEnv(env(map[string]string{"CLEARANCE_MAX_CLOCK_SKEW": "-5m"})); err == nil {
		t.Fatal("a negative skew")
	}
	cfg, _ = FromEnv(env(map[string]string{"CLEARANCE_MAX_CLOCK_SKEW": "0"}))
	if cfg.MaxClockSkew >= 0 || cfg.CheckMaxClockSkew() != ErrSkewOffNeedsMemory {
		t.Fatal("off on a durable store")
	}
	cfg.Memory = true
	if cfg.CheckMaxClockSkew() != nil {
		t.Fatal("off is allowed with --memory")
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

// Hangar's Flight registry (decided 2026-11-03): an image bump from it stays tier 1, anything else is tier 2. Unset
// keeps the product default, any registry.
func TestTrustedRegistriesFromEnv(t *testing.T) {
	cfg, err := FromEnv(env(map[string]string{"CLEARANCE_DSN": "postgres://x",
		"CLEARANCE_TRUSTED_REGISTRIES": "ghcr.io/riley-roooo/, registry.example/flight/"}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.Gate.TrustedRegistries, "|") != "ghcr.io/riley-roooo/|registry.example/flight/" {
		t.Fatalf("%q", cfg.Gate.TrustedRegistries)
	}
	cfg, err = FromEnv(env(map[string]string{"CLEARANCE_DSN": "postgres://x"}))
	if err != nil || len(cfg.Gate.TrustedRegistries) != 0 {
		t.Fatalf("default: %q %v", cfg.Gate.TrustedRegistries, err)
	}
}

// A placeholder tree digest is flagged unless the deployment refuses it (flag is the default for one release; G-TF-1).
func TestTheUnboundTreeSetting(t *testing.T) {
	for v, want := range map[string]string{"": "flag", "flag": "flag", "refuse": "refuse"} {
		cfg, err := FromEnv(env(map[string]string{"CLEARANCE_DSN": "postgres://x", "CLEARANCE_GATE_UNBOUND_TREE": v}))
		if err != nil || cfg.Gate.UnboundTree != want {
			t.Errorf("%q: %q %v", v, cfg.Gate.UnboundTree, err)
		}
	}
}
