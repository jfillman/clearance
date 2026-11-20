package client

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A TLS server whose certificate httptest signs with its own private CA: the client trusts it only with that CA's file.
func TestClientVerifiesAnHTTPSCoreAgainstTheCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pemOf(srv.Certificate().Raw)
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	opt := Options{BaseURL: srv.URL, Timeout: 2 * time.Second, Retries: -1, BreakerThreshold: -1}
	bare, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bare.Healthz(context.Background()); err == nil {
		t.Fatal("without the CA file the private server must be refused")
	}
	opt.CAFile = caFile
	withCA, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withCA.Healthz(context.Background()); err != nil {
		t.Fatalf("with the CA file: %v", err)
	}
	opt.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := New(opt); err == nil {
		t.Fatal("an unreadable CA file must fail New")
	}
	hc, err := NewHTTPClient(caFile, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := hc.Get(srv.URL); err != nil {
		t.Fatalf("NewHTTPClient with the CA: %v", err)
	} else {
		resp.Body.Close()
	}
	plain, _ := NewHTTPClient("", 2*time.Second)
	if _, err := plain.Get(srv.URL); err == nil {
		t.Fatal("NewHTTPClient without the CA must refuse")
	}
}

func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// The feed readers keep the environment's proxy policy (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) and still refuse redirects.
func TestNewHTTPClientKeepsTheProxyPolicyAndRefusesRedirects(t *testing.T) {
	hc, err := NewHTTPClient("", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatalf("the transport dropped the proxy policy: %#v", hc.Transport)
	}
	if hc.CheckRedirect == nil || hc.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("a redirect would be followed")
	}
}
