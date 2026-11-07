package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/token"
)

func runAttest(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := cli.Main(context.Background(), append([]string{"attest", "verify"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

func TestAttestVerifyChecksABundleOffline(t *testing.T) {
	const tree = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// A throwaway key, signing a statement through the static backend.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sg, _ := token.NewKeySigner(k)
	st := attest.Statement{Type: attest.StatementType, PredicateType: attest.PredicateType,
		Subject:   []attest.Subject{{Name: "manifest-tree:o/r/a/prod", Digest: map[string]string{"sha256": tree}}},
		Predicate: attest.Predicate{Clearance: token.Clearance{ID: "chg-1"}, Limitations: []string{"x"}}}
	payload, _ := json.Marshal(st)
	signed, err := (&attest.Static{Signer: sg}).Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	bundle, _ := json.Marshal(signed.Bundle)
	der, _ := x509.MarshalPKIXPublicKey(sg.Public())
	pub := write("pub.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	code, out, errs := runAttest("--file", write("good.json", bundle), "--key", pub, "--subject", "sha256:"+tree)
	if code != 0 || !strings.Contains(out, "ok: static attestation of change chg-1") || !strings.Contains(out, attest.EnvelopeDigest(signed.Bundle.DSSEEnvelope)) {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	// A tampered statement, a wrong subject and a wrong key all exit 1.
	bad := signed.Bundle
	st.Predicate.Clearance.ID = "chg-evil"
	tp, _ := json.Marshal(st)
	bad.DSSEEnvelope.Payload = base64.StdEncoding.EncodeToString(tp)
	badRaw, _ := json.Marshal(bad)
	if code, _, errs := runAttest("--file", write("bad.json", badRaw), "--key", pub); code != 1 || !strings.Contains(errs, "FAILED") {
		t.Fatalf("tampered: %d %q", code, errs)
	}
	if code, _, errs := runAttest("--file", write("good.json", bundle), "--key", pub, "--subject", "sha256:"+strings.Repeat("f", 64)); code != 1 ||
		!strings.Contains(errs, "does not name subject") {
		t.Fatalf("wrong subject: %d %q", code, errs)
	}
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der2, _ := x509.MarshalPKIXPublicKey(&k2.PublicKey)
	other := write("other.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der2}))
	if code, _, _ := runAttest("--file", write("good.json", bundle), "--key", other); code != 1 {
		t.Fatalf("wrong key: %d", code)
	}
	// Usage: neither a key nor a trust root, and an unreadable file.
	if code, _, _ := runAttest("--file", write("good.json", bundle)); code != 2 {
		t.Fatalf("usage: %d", code)
	}
	if code, _, _ := runAttest("--file", filepath.Join(dir, "none"), "--key", pub); code != 1 {
		t.Fatalf("missing file: %d", code)
	}
}
