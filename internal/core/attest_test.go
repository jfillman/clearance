package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/attest"
)

// readyzOf runs a memory core with cfg and returns /readyz's attestation block.
func readyzOf(t *testing.T, cfg Config) map[string]any {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addr := make(chan string, 1)
	done := make(chan error, 1)
	cfg.Memory, cfg.Listen, cfg.Auth, cfg.ExpireEvery = true, "127.0.0.1:0", DevAuthenticator(), 10*time.Millisecond
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
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	att, _ := body["attestation"].(map[string]any)
	return att
}

func TestReadyzSaysAttestationsAreOffWhenNoBackendIsConfigured(t *testing.T) {
	cfg, err := FromEnv(env(nil))
	if err != nil || cfg.Attest != nil {
		t.Fatal(cfg.Attest, err)
	}
	att := readyzOf(t, Config{})
	if att["enabled"] != false || !strings.HasPrefix(att["detail"].(string), "off:") ||
		!strings.Contains(att["detail"].(string), attest.EnvFulcio) {
		t.Fatalf("%v", att)
	}
}

func TestReadyzNamesTheConfiguredAttestationBackend(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	p := filepath.Join(t.TempDir(), "attest.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := FromEnv(env(map[string]string{attest.EnvKeyFile: p}))
	if err != nil || cfg.Attest == nil {
		t.Fatal(cfg.Attest, err)
	}
	att := readyzOf(t, Config{Attest: cfg.Attest})
	if att["enabled"] != true || att["backend"] != "static" {
		t.Fatalf("%v", att)
	}
	// A half-configured keyless backend stops the start instead of running without attestations.
	if _, err := FromEnv(env(map[string]string{attest.EnvFulcio: "https://fulcio.example"})); err == nil {
		t.Fatal("Fulcio without Rekor was accepted")
	}
}
