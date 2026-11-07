// Package attesttest is test support for the attestation signer: a fake Fulcio (a throwaway CA that issues
// short-lived certificates against an OIDC token's subject) and a fake Rekor (a log that signs entry timestamps with
// a throwaway key). No real key, no network beyond loopback. Never use it outside tests.
package attesttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/token"
)

// Issuer is the OIDC issuer the fake Fulcio records in its certificates.
const Issuer = "https://issuer.test"

// Fulcio is a fake Fulcio.
type Fulcio struct {
	Server  *httptest.Server
	Root    *x509.Certificate
	RootPEM []byte
	key     *ecdsa.PrivateKey
	// Issued counts the certificates issued.
	mu     sync.Mutex
	Issued int
}

// NewFulcio starts a fake Fulcio, closed with the test.
func NewFulcio(t *testing.T) *Fulcio {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Fulcio Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(der)
	f := &Fulcio{Root: root, key: k, RootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	return f
}

// URL is the Fulcio's base URL.
func (f *Fulcio) URL() string { return f.Server.URL }

func (f *Fulcio) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v2/signingCert" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Credentials struct {
			OIDCIdentityToken string `json:"oidcIdentityToken"`
		} `json:"credentials"`
		PublicKeyRequest struct {
			PublicKey struct {
				Algorithm string `json:"algorithm"`
				Content   string `json:"content"`
			} `json:"publicKey"`
			ProofOfPossession string `json:"proofOfPossession"`
		} `json:"publicKeyRequest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	iss, sub := tokenClaims(req.Credentials.OIDCIdentityToken)
	blk, _ := pem.Decode([]byte(req.PublicKeyRequest.PublicKey.Content))
	if blk == nil || sub == "" {
		http.Error(w, "bad key or token", 400)
		return
	}
	pubAny, err := x509.ParsePKIXPublicKey(blk.Bytes)
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if err != nil || !ok {
		http.Error(w, "bad key", 400)
		return
	}
	pop, _ := base64.StdEncoding.DecodeString(req.PublicKeyRequest.ProofOfPossession)
	h := sha256.Sum256([]byte(sub))
	if !ecdsa.VerifyASN1(pub, h[:], pop) {
		http.Error(w, "proof of possession failed", 401)
		return
	}
	u, _ := url.Parse(sub)
	issuerExt, _ := asn1.Marshal(iss)
	f.mu.Lock()
	f.Issued++
	serial := int64(1000 + f.Issued)
	f.mu.Unlock()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:            []*url.URL{u},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: issuerExt}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.Root, pub, f.key)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	var resp struct {
		Embedded struct {
			Chain struct {
				Certificates []string `json:"certificates"`
			} `json:"chain"`
		} `json:"signedCertificateEmbeddedSct"`
	}
	resp.Embedded.Chain.Certificates = []string{leaf, string(f.RootPEM)}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func tokenClaims(tok string) (iss, sub string) {
	var parts [3]string
	n := 0
	start := 0
	for i := 0; i <= len(tok) && n < 3; i++ {
		if i == len(tok) || tok[i] == '.' {
			parts[n] = tok[start:i]
			n++
			start = i + 1
		}
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var c struct{ Iss, Sub string }
	_ = json.Unmarshal(b, &c)
	return c.Iss, c.Sub
}

// WriteToken writes an unsigned test OIDC token (iss, sub) to a file and returns its path. Fulcio's fake does not
// check the token's signature; the real one does.
func WriteToken(t *testing.T, iss, sub string) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	tok := enc(map[string]string{"alg": "none"}) + "." + enc(map[string]string{"iss": iss, "sub": sub}) + ".x"
	p := filepath.Join(t.TempDir(), "oidc-token")
	if err := os.WriteFile(p, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Rekor is a fake Rekor v1 log.
type Rekor struct {
	Server *httptest.Server
	Key    *ecdsa.PrivateKey
	// KeyPEM is the log's public key.
	KeyPEM []byte
	mu     sync.Mutex
	// Entries are the DSSE envelopes logged, in order.
	Entries []json.RawMessage
}

// NewRekor starts a fake Rekor, closed with the test.
func NewRekor(t *testing.T) *Rekor {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	r := &Rekor{Key: k, KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
	r.Server = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.Server.Close)
	return r
}

// URL is the Rekor's base URL.
func (r *Rekor) URL() string { return r.Server.URL }

// Logged is how many entries the log holds.
func (r *Rekor) Logged() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Entries)
}

func (r *Rekor) serve(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/api/v1/log/entries" || req.Method != http.MethodPost {
		http.NotFound(w, req)
		return
	}
	var in struct {
		Kind string `json:"kind"`
		Spec struct {
			ProposedContent struct {
				Envelope  string   `json:"envelope"`
				Verifiers []string `json:"verifiers"`
			} `json:"proposedContent"`
		} `json:"spec"`
	}
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil || in.Kind != "dsse" || len(in.Spec.ProposedContent.Verifiers) != 1 {
		http.Error(w, "bad entry", 400)
		return
	}
	var env token.Envelope
	if err := json.Unmarshal([]byte(in.Spec.ProposedContent.Envelope), &env); err != nil || len(env.Signatures) != 1 {
		http.Error(w, "bad envelope", 400)
		return
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	sig, _ := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	vpem, _ := base64.StdEncoding.DecodeString(in.Spec.ProposedContent.Verifiers[0])
	blk, _ := pem.Decode(vpem)
	if blk == nil {
		http.Error(w, "bad verifier", 400)
		return
	}
	var pub *ecdsa.PublicKey
	if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
		pub, _ = c.PublicKey.(*ecdsa.PublicKey)
	} else if k, err := x509.ParsePKIXPublicKey(blk.Bytes); err == nil {
		pub, _ = k.(*ecdsa.PublicKey)
	}
	d := sha256.Sum256(token.PAE(env.PayloadType, payload))
	if pub == nil || !ecdsa.VerifyASN1(pub, d[:], sig) {
		http.Error(w, "the verifier does not verify the envelope", 400)
		return
	}
	ph := sha256.Sum256(payload)
	eh := sha256.Sum256([]byte(in.Spec.ProposedContent.Envelope))
	body, _ := json.Marshal(map[string]any{"apiVersion": "0.0.1", "kind": "dsse", "spec": map[string]any{
		"envelopeHash": map[string]string{"algorithm": "sha256", "value": hex.EncodeToString(eh[:])},
		"payloadHash":  map[string]string{"algorithm": "sha256", "value": hex.EncodeToString(ph[:])},
		"signatures":   []map[string]string{{"signature": env.Signatures[0].Sig, "verifier": in.Spec.ProposedContent.Verifiers[0]}}}})
	r.mu.Lock()
	idx := int64(len(r.Entries))
	r.Entries = append(r.Entries, json.RawMessage(in.Spec.ProposedContent.Envelope))
	r.mu.Unlock()
	at := time.Now().Unix()
	logID := sha256.Sum256(r.KeyPEM)
	set, _ := json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{base64.StdEncoding.EncodeToString(body), at, hex.EncodeToString(logID[:]), idx})
	sd := sha256.Sum256(set)
	sigSET, _ := ecdsa.SignASN1(rand.Reader, r.Key, sd[:])
	uuid := hex.EncodeToString(logID[:]) + strconv.FormatInt(idx, 16)
	resp := map[string]any{uuid: map[string]any{"body": base64.StdEncoding.EncodeToString(body), "integratedTime": at,
		"logID": hex.EncodeToString(logID[:]), "logIndex": idx,
		"verification": map[string]any{"signedEntryTimestamp": base64.StdEncoding.EncodeToString(sigSET)}}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}
