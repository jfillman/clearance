package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/grc"
	"github.com/jfillman/clearance/internal/grc/grctest"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"version"}, env(nil), &out, &bytes.Buffer{}); code != 0 || !strings.HasPrefix(out.String(), "clearance-grc ") {
		t.Fatalf("%d %q", code, out.String())
	}
}

// Off unless configured: no target, nothing is sent, exit 0 (not a crash loop).
func TestOffUnlessConfigured(t *testing.T) {
	var errb bytes.Buffer
	if code := run(context.Background(), nil, env(nil), &bytes.Buffer{}, &errb); code != 0 || !strings.Contains(errb.String(), "off") {
		t.Fatalf("%d %q", code, errb.String())
	}
}

func TestARefusedConfigurationExitsTwoAndNamesNoValue(t *testing.T) {
	var errb bytes.Buffer
	code := run(context.Background(), nil, env(map[string]string{"CLEARANCE_GRC_TARGET": "vanta", "CLEARANCE_GRC_VANTA_CLIENT_SECRET": "hunter2"}), &bytes.Buffer{}, &errb)
	if code != 2 || strings.Contains(errb.String(), "hunter2") || !strings.Contains(errb.String(), "CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE") {
		t.Fatalf("%d %q", code, errb.String())
	}
	// A loopback hub is not reachable from the environment.
	code = run(context.Background(), nil, env(map[string]string{"CLEARANCE_GRC_TARGET": "vanta", "CLEARANCE_GRC_VANTA_BASE_URL": "http://127.0.0.1:1",
		"CLEARANCE_GRC_VANTA_CLIENT_ID": "c", "CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE": "/x", "CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID": "r",
		"CLEARANCE_API_URL": "https://a.example", "CLEARANCE_URL": "https://c.example", "CLEARANCE_GRC_LINK_BASE": "https://ui.example"}), &bytes.Buffer{}, &bytes.Buffer{})
	if code != 2 {
		t.Fatalf("a loopback http hub from the environment: exit %d", code)
	}
}

// A configured service runs, serves /healthz and /readyz, pushes, and stops cleanly when told to.
func TestRunsServesHealthAndStops(t *testing.T) {
	hub, api := grctest.NewVanta("c", "unique-secret-value-xyz"), grctest.NewAPI()
	defer hub.Close()
	defer api.Close()
	dir := t.TempDir()
	sec, tok := filepath.Join(dir, "secret"), filepath.Join(dir, "token")
	os.WriteFile(sec, []byte("unique-secret-value-xyz"), 0o600)
	os.WriteFile(tok, []byte("p"), 0o600)
	ln := httptest.NewUnstartedServer(nil)
	addr := ln.Listener.Addr().String() // a free port, closed before the service takes it
	ln.Listener.Close()
	m := map[string]string{"CLEARANCE_GRC_TARGET": "vanta", "CLEARANCE_GRC_VANTA_BASE_URL": hub.URL, "CLEARANCE_GRC_VANTA_CLIENT_ID": "c",
		"CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE": sec, "CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID": "r", "CLEARANCE_API_URL": api.URL,
		"CLEARANCE_URL": api.URL, "CLEARANCE_GRC_SA_TOKEN_FILE": tok, "CLEARANCE_GRC_LINK_BASE": "https://ui.example", "CLEARANCE_GRC_LISTEN": addr}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var errb bytes.Buffer
	go func() { done <- run(ctx, nil, env(m), &bytes.Buffer{}, &errb, grc.ConfigLoopbackForTest()) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the health listener never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, p := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get("http://" + addr + p)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", p, err, resp)
		}
		resp.Body.Close()
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("did not stop")
	}
	if strings.Contains(errb.String(), "unique-secret-value-xyz") {
		t.Fatal("the secret is in the log")
	}
}
