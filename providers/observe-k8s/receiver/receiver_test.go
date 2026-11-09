package receiver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type pki struct {
	caPEM  []byte
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	serial int64
}

func newPKI(t *testing.T, name string) *pki {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &pki{ca: ca, caKey: k, serial: 1}
}

func (p *pki) pool() *x509.CertPool { c := x509.NewCertPool(); c.AddCert(p.ca); return c }

func (p *pki) issue(t *testing.T, cn string, server bool) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.serial++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if server {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &k.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

type memSink struct {
	mu      sync.Mutex
	items   [][]byte
	err     error
	entered chan struct{}
	release chan struct{}
}

func (m *memSink) Append(p ...[]byte) error {
	if m.entered != nil {
		m.entered <- struct{}{}
		<-m.release
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.items = append(m.items, p...)
	return nil
}

func (m *memSink) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.items) }

type env struct {
	srv  *httptest.Server
	apis *pki
	rcv  *Receiver
	sink *memSink
	ca   *pki
}

func setup(t *testing.T, sink *memSink) *env {
	t.Helper()
	serverCA, clientCA := newPKI(t, "server-ca"), newPKI(t, "client-ca")
	r, err := New(Config{Sink: sink, AllowedClients: []string{"kube-apiserver"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(r)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCA.issue(t, "collector", true)}, ClientCAs: clientCA.pool(),
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &env{srv: srv, apis: clientCA, rcv: r, sink: sink, ca: serverCA}
}

func (e *env) client(cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: e.ca.pool(), MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func list(items ...string) string {
	return `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[` + strings.Join(items, ",") + `]}`
}

func ev(id, resource, extra string) string {
	return fmt.Sprintf(`{"auditID":%q,"level":"Metadata","stage":"ResponseComplete","verb":"update","user":{"username":"dana"},"objectRef":{"resource":%q,"namespace":"shop","name":"x"}%s}`, id, resource, extra)
}

func post(t *testing.T, c *http.Client, url, body string) (*http.Response, error) {
	t.Helper()
	return c.Post(url+"/audit", "application/json", strings.NewReader(body))
}

func TestOnlyTheAPIServerMayPost(t *testing.T) {
	e := setup(t, &memSink{})
	good := e.apis.issue(t, "kube-apiserver", false)
	other := e.apis.issue(t, "someone-else", false)
	rogueCA := newPKI(t, "rogue")
	rogue := rogueCA.issue(t, "kube-apiserver", false)

	// No client certificate: refused at the handshake.
	if resp, err := post(t, e.client(nil), e.srv.URL, list(ev("a", "configmaps", ""))); err == nil {
		resp.Body.Close()
		t.Fatalf("a client with no certificate got %d", resp.StatusCode)
	}
	// A certificate from another CA, even with the right name: refused at the handshake.
	if resp, err := post(t, e.client(&rogue), e.srv.URL, list(ev("a", "configmaps", ""))); err == nil {
		resp.Body.Close()
		t.Fatalf("a certificate from another CA got %d", resp.StatusCode)
	}
	// Our CA, the wrong identity: 403.
	resp, err := post(t, e.client(&other), e.srv.URL, list(ev("a", "configmaps", "")))
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong identity: %v %v", resp, err)
	}
	resp.Body.Close()
	if e.sink.count() != 0 {
		t.Fatal("something was queued for a client that is not the API server")
	}
	// The API server.
	resp, err = post(t, e.client(&good), e.srv.URL, list(ev("a", "configmaps", ""), ev("b", "configmaps", "")))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("api server: %v %v", resp, err)
	}
	resp.Body.Close()
	if e.sink.count() != 2 {
		t.Fatalf("queued %d, want 2", e.sink.count())
	}
	if st := e.rcv.Status(); st.Batches != 1 || st.Events != 2 || st.Rejected < 1 || st.LastClient != "kube-apiserver" || st.LastBatch.IsZero() {
		t.Fatalf("status %+v", st)
	}
}

func TestDirectCallWithoutTLSIsRefused(t *testing.T) {
	r, _ := New(Config{Sink: &memSink{}, AllowedClients: []string{"kube-apiserver"}})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("POST", "/audit", strings.NewReader(list())))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401: a handler not behind verified mTLS must not accept events", rec.Code)
	}
	if _, err := New(Config{Sink: &memSink{}}); err == nil {
		t.Fatal("a receiver with no allowed client must not build")
	}
}

// 200 is sent only after Append has returned; a sink that fails gets 503, never 200.
func TestAcknowledgedOnlyAfterTheBatchIsDurable(t *testing.T) {
	sink := &memSink{entered: make(chan struct{}), release: make(chan struct{})}
	e := setup(t, sink)
	cert := e.apis.issue(t, "kube-apiserver", false)
	done := make(chan *http.Response, 1)
	go func() {
		resp, err := post(t, e.client(&cert), e.srv.URL, list(ev("a", "configmaps", "")))
		if err != nil {
			t.Error(err)
		}
		done <- resp
	}()
	<-sink.entered
	select {
	case <-done:
		t.Fatal("the API server was answered before the append returned")
	case <-time.After(150 * time.Millisecond):
	}
	close(sink.release)
	resp := <-done
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("after the append: %v", resp)
	}
	resp.Body.Close()

	failing := &memSink{err: errors.New("disk full")}
	e2 := setup(t, failing)
	cert2 := e2.apis.issue(t, "kube-apiserver", false)
	resp, err := post(t, e2.client(&cert2), e2.srv.URL, list(ev("a", "configmaps", "")))
	if err != nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a failed append: %v %v; want 503 so the API server retries", resp, err)
	}
	resp.Body.Close()
	if st := e2.rcv.Status(); st.Batches != 0 {
		t.Fatalf("a batch that was not made durable was counted: %+v", st)
	}
}

// A Secret body never reaches the queue: not from a policy that records it, not nested in another object's body.
func TestSecretBodiesAreCutOffBeforeTheQueue(t *testing.T) {
	const marker = "c3VwZXItc2VjcmV0LXZhbHVl" // base64 of a secret value
	secretBody := `{"kind":"Secret","apiVersion":"v1","metadata":{"name":"x","namespace":"shop"},"data":{"password":"` + marker + `"}}`
	sink := &memSink{}
	e := setup(t, sink)
	cert := e.apis.issue(t, "kube-apiserver", false)
	batch := list(
		strings.Replace(ev("s1", "secrets", `,"requestObject":`+secretBody+`,"responseObject":`+secretBody), `"Metadata"`, `"RequestResponse"`, 1),
		ev("s2", "configmaps", `,"requestObject":`+secretBody), // a Secret body under another resource
		ev("s3", "serviceaccounts", `,"responseObject":{"kind":"TokenRequest","status":{"token":"`+marker+`"}}`),
		ev("ok", "configmaps", `,"requestObject":{"kind":"ConfigMap","data":{"k":"v"}}`),
	)
	resp, err := post(t, e.client(&cert), e.srv.URL, batch)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	resp.Body.Close()
	if sink.count() != 4 {
		t.Fatalf("queued %d, want 4", sink.count())
	}
	for i, it := range sink.items {
		if bytes.Contains(it, []byte(marker)) || bytes.Contains(it, []byte(`"password"`)) || bytes.Contains(it, []byte("TokenRequest")) {
			t.Fatalf("event %d queued with a secret in it: %s", i, it)
		}
	}
	var s1 map[string]any
	json.Unmarshal(sink.items[0], &s1)
	if s1["annotations"].(map[string]any)[AnnStripped] != "true" {
		t.Fatalf("the stripped event is not marked: %v", s1["annotations"])
	}
	if !bytes.Contains(sink.items[3], []byte(`"k":"v"`)) {
		t.Fatalf("a ConfigMap body was dropped: %s", sink.items[3])
	}
	if st := e.rcv.Status(); st.Stripped != 3 {
		t.Fatalf("stripped %d, want 3", st.Stripped)
	}
}

// A Secret event already at Metadata has no body and is not marked: the policy is doing its job.
func TestMetadataSecretEventIsLeftAlone(t *testing.T) {
	items, stripped, err := Sanitize([]byte(list(ev("m", "secrets", ""))))
	if err != nil || stripped != 0 || len(items) != 1 || bytes.Contains(items[0], []byte(AnnStripped)) {
		t.Fatalf("%v %d %s", err, stripped, items)
	}
}

func TestMalformedBatchesAreRefusedWholesale(t *testing.T) {
	for name, b := range map[string]string{"not json": "{", "wrong kind": `{"kind":"Pod","apiVersion":"v1","items":[]}`,
		"no audit id": list(`{"verb":"get"}`)} {
		if _, _, err := Sanitize([]byte(b)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestOversizedEventLosesItsBodies(t *testing.T) {
	big := strings.Repeat("a", MaxItem+10)
	items, _, err := Sanitize([]byte(list(ev("big", "configmaps", `,"requestObject":{"data":{"k":"`+big+`"}}`))))
	if err != nil || len(items) != 1 || len(items[0]) > 4096 || !bytes.Contains(items[0], []byte(AnnOversized)) {
		t.Fatalf("%v %d", err, len(items))
	}
}

func FuzzSanitize(f *testing.F) {
	f.Add([]byte(list(ev("a", "secrets", `,"requestObject":{"kind":"Secret","data":{"a":"b"}}`))))
	f.Add([]byte(`{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[{}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		items, _, err := Sanitize(b)
		if err != nil {
			return
		}
		for _, it := range items {
			var m map[string]any
			if json.Unmarshal(it, &m) != nil {
				t.Fatalf("an item is not JSON: %s", it)
			}
			if aboutCredential(m) && (m["requestObject"] != nil || m["responseObject"] != nil) {
				t.Fatalf("a credential body survived: %s", it)
			}
		}
	})
}
