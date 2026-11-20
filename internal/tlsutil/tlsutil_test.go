package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pki writes a private CA and a leaf for 127.0.0.1 into dir and returns the file paths.
func pki(t *testing.T, dir, name string) (caFile, certFile, keyFile string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca " + name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf " + name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	write := func(f, typ string, der []byte) string {
		p := filepath.Join(dir, f)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return write("ca-"+name+".pem", "CERTIFICATE", caDER), write("tls-"+name+".crt", "CERTIFICATE", leafDER), write("tls-"+name+".key", "EC PRIVATE KEY", keyDER)
}

func serve(t *testing.T, l Listener) string {
	t.Helper()
	ln, err := l.Listen()
	if err != nil || ln == nil {
		t.Fatalf("Listen: %v %v", ln, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }),
		ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func get(addr string, cfg *tls.Config) (string, error) {
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := hc.Get("https://" + addr + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func TestPrivateCAIsAcceptedWithTheCAFileAndRefusedWithout(t *testing.T) {
	dir := t.TempDir()
	ca, crt, key := pki(t, dir, "a")
	addr := serve(t, Listener{Addr: "127.0.0.1:0", CertFile: crt, KeyFile: key})
	cc, err := ClientConfig(ca)
	if err != nil || cc == nil {
		t.Fatal(err)
	}
	if body, err := get(addr, cc); err != nil || body != "ok" {
		t.Fatalf("with the CA file: %q %v", body, err)
	}
	if _, err := get(addr, nil); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("without the CA file the server must be refused, got %v", err)
	}
	// A different CA must not vouch for it either.
	other, _, _ := pki(t, dir, "b")
	oc, _ := ClientConfig(other)
	if _, err := get(addr, oc); err == nil {
		t.Fatal("another CA's file must be refused")
	}
}

func TestClientConfigWithNoFileKeepsTheSystemRoots(t *testing.T) {
	if c, err := ClientConfig(""); c != nil || err != nil {
		t.Fatalf("%v %v", c, err)
	}
	if _, err := ClientConfig(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing CA file must be an error")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not a certificate"), 0o600)
	if _, err := ClientConfig(bad); err == nil {
		t.Fatal("a file with no certificate must be an error")
	}
}

func TestTheServingCertificateIsReloadedWhenTheFilesChange(t *testing.T) {
	dir := t.TempDir()
	ca1, crt, key := pki(t, dir, "a")
	s, err := NewServer(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.now = func() time.Time { return now }
	first, _ := s.GetCertificate(nil)
	// cert-manager renews: new files at the same paths (a later mtime).
	_, crt2, key2 := pki(t, dir, "b")
	for _, m := range [][2]string{{crt2, crt}, {key2, key}} {
		b, _ := os.ReadFile(m[0])
		if err := os.WriteFile(m[1], b, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(m[1], now.Add(time.Minute), now.Add(time.Minute))
	}
	if c, _ := s.GetCertificate(nil); c != first {
		t.Fatal("inside the check interval the cached certificate is kept")
	}
	now = now.Add(time.Minute)
	if c, _ := s.GetCertificate(nil); c == first {
		t.Fatal("after the interval the changed files must be loaded")
	}
	// A half-written pair keeps the last good certificate.
	good, _ := s.GetCertificate(nil)
	_ = os.WriteFile(key, []byte("garbage"), 0o600)
	_ = os.Chtimes(key, now.Add(time.Hour), now.Add(time.Hour))
	now = now.Add(time.Minute)
	if c, _ := s.GetCertificate(nil); c != good {
		t.Fatal("a bad reload must keep serving the last good certificate")
	}
	_ = ca1
}

func TestListenerFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	ok := map[string]string{"CLEARANCE_TLS_LISTEN": ":8443", "CLEARANCE_TLS_CERT_FILE": "/c", "CLEARANCE_TLS_KEY_FILE": "/k"}
	l, err := ListenerFromEnv(env(ok), ":8080")
	if err != nil || l.Addr != ":8443" || l.CertFile != "/c" || l.KeyFile != "/k" {
		t.Fatalf("%+v %v", l, err)
	}
	if l, err := ListenerFromEnv(env(nil), ":8080"); err != nil || l.Addr != "" {
		t.Fatalf("off by default: %+v %v", l, err)
	}
	if _, err := ListenerFromEnv(env(ok), Off); err != nil {
		t.Fatalf("plain off with TLS on is allowed: %v", err)
	}
	for name, c := range map[string]struct {
		m     map[string]string
		plain string
	}{
		"no key":          {map[string]string{"CLEARANCE_TLS_LISTEN": ":8443", "CLEARANCE_TLS_CERT_FILE": "/c"}, ":8080"},
		"files, no addr":  {map[string]string{"CLEARANCE_TLS_CERT_FILE": "/c", "CLEARANCE_TLS_KEY_FILE": "/k"}, ":8080"},
		"bad address":     {map[string]string{"CLEARANCE_TLS_LISTEN": "8443", "CLEARANCE_TLS_CERT_FILE": "/c", "CLEARANCE_TLS_KEY_FILE": "/k"}, ":8080"},
		"same address":    {ok, ":8443"},
		"nothing serving": {nil, Off},
	} {
		if _, err := ListenerFromEnv(env(c.m), c.plain); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestListenRefusesAnUnreadableCertificate(t *testing.T) {
	if _, err := (Listener{Addr: "127.0.0.1:0", CertFile: "/nope.crt", KeyFile: "/nope.key"}).Listen(); err == nil {
		t.Fatal("a missing certificate must stop the start")
	}
}
