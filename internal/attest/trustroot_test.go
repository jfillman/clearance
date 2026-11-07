package attest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/attest/attesttest"
)

func signBundle(t *testing.T, k keyless) []byte {
	t.Helper()
	s, err := k.b.Sign(context.Background(), payload(t, testStatement()))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s.Bundle)
	return raw
}

func trustOpts(tr []byte, t *testing.T) attest.VerifyOptions {
	t.Helper()
	root, err := attest.ParseTrustedRoot(tr)
	if err != nil {
		t.Fatal(err)
	}
	return attest.VerifyOptions{Trust: root, Identity: identity, Issuer: attesttest.Issuer,
		Subjects: []string{"sha256:" + treeRoot}}
}

func TestATrustedRootVerifiesAKeylessBundleAndNeedsNoRekorKeyFlag(t *testing.T) {
	k := newKeyless(t)
	raw := signBundle(t, k)
	tr, err := attest.BuildTrustedRoot(
		[]attest.BuildCA{{URI: "http://fulcio", PEM: k.fulcio.RootPEM}},
		[]attest.BuildLog{{BaseURL: "http://rekor", PEM: k.rekor.KeyPEM}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := attest.Verify(raw, trustOpts(tr, t))
	if err != nil || !res.LogVerified || res.Identity != identity {
		t.Fatalf("%v %+v", err, res)
	}
}

// The cutover case: an old bundle (legacy root and Rekor key, windows closed at the cutover) and a new one both verify
// against one trusted root, and each is refused when the root lists only the other generation.
func TestLegacyAndNewGenerationsBothVerifyUntilTheirWindowsClose(t *testing.T) {
	oldK, newK := newKeyless(t), newKeyless(t)
	oldRaw, newRaw := signBundle(t, oldK), signBundle(t, newK)
	now := time.Now()
	cutover := now.Add(time.Hour) // signed before the cutover: inside the legacy window
	tr, err := attest.BuildTrustedRoot(
		[]attest.BuildCA{
			{URI: "http://fulcio", PEM: oldK.fulcio.RootPEM, Window: attest.Window{End: cutover}},
			{URI: "http://fulcio", PEM: newK.fulcio.RootPEM, Window: attest.Window{Start: now.Add(-time.Minute)}}},
		[]attest.BuildLog{
			{BaseURL: "http://rekor", PEM: oldK.rekor.KeyPEM, Window: attest.Window{End: cutover}},
			{BaseURL: "http://rekor", PEM: newK.rekor.KeyPEM, Window: attest.Window{Start: now.Add(-time.Minute)}}})
	if err != nil {
		t.Fatal(err)
	}
	o := trustOpts(tr, t)
	for name, raw := range map[string][]byte{"old": oldRaw, "new": newRaw} {
		if _, err := attest.Verify(raw, o); err != nil {
			t.Fatalf("%s bundle: %v", name, err)
		}
	}
	// Only the new generation listed: the old bundle is refused (unknown log id).
	only, _ := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: newK.fulcio.RootPEM}}, []attest.BuildLog{{PEM: newK.rekor.KeyPEM}})
	if _, err := attest.Verify(oldRaw, trustOpts(only, t)); err == nil {
		t.Fatal("an old bundle verified against only the new generation")
	}
	// Rekor's key window closed before the entry was signed: refused.
	closed, _ := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: oldK.fulcio.RootPEM}},
		[]attest.BuildLog{{PEM: oldK.rekor.KeyPEM, Window: attest.Window{End: now.Add(-time.Hour)}}})
	if _, err := attest.Verify(oldRaw, trustOpts(closed, t)); err == nil || !strings.Contains(err.Error(), "window") {
		t.Fatalf("a closed key window: %v", err)
	}
	// The Fulcio chain's window closed before the entry: refused.
	caClosed, _ := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: oldK.fulcio.RootPEM, Window: attest.Window{End: now.Add(-time.Hour)}}},
		[]attest.BuildLog{{PEM: oldK.rekor.KeyPEM}})
	if _, err := attest.Verify(oldRaw, trustOpts(caClosed, t)); err == nil {
		t.Fatal("a closed CA window verified")
	}
}

func TestATrustedRootStillPinsIdentityAndIssuer(t *testing.T) {
	k := newKeyless(t)
	raw := signBundle(t, k)
	tr, _ := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: k.fulcio.RootPEM}}, []attest.BuildLog{{PEM: k.rekor.KeyPEM}})
	for name, mod := range map[string]func(*attest.VerifyOptions){
		"identity": func(o *attest.VerifyOptions) { o.Identity += "-x" },
		"issuer":   func(o *attest.VerifyOptions) { o.Issuer = "https://evil.test" },
		"none":     func(o *attest.VerifyOptions) { o.Identity = "" },
	} {
		o := trustOpts(tr, t)
		mod(&o)
		if _, err := attest.Verify(raw, o); err == nil {
			t.Fatalf("%s: verified", name)
		}
	}
}

func throwawayCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, path int) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		MaxPathLen: path, MaxPathLenZero: path == 0, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func pemOf(cs ...*x509.Certificate) []byte {
	var b []byte
	for _, c := range cs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return b
}

func TestBuildOrdersAChainAndRefusesWhatIsNotOne(t *testing.T) {
	root, rk := throwawayCA(t, "Throwaway Root", nil, nil, 1)
	inter, _ := throwawayCA(t, "Throwaway Intermediate", root, rk, 0)
	other, _ := throwawayCA(t, "Another Root", nil, nil, 1)
	root2, rk2 := throwawayCA(t, "Absent Root", nil, nil, 1)
	inter2, _ := throwawayCA(t, "Orphan Intermediate", root2, rk2, 0)
	r := attesttest.NewRekor(t)
	logs := []attest.BuildLog{{BaseURL: "http://rekor", PEM: r.KeyPEM}}

	// Root first, then intermediate: ordered intermediate-first in the document.
	raw, err := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: pemOf(root, inter)}}, logs)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := attest.ParseTrustedRoot(raw)
	if err != nil || len(tr.CAs[0].Chain) != 2 || tr.CAs[0].Chain[0].Subject.CommonName != "Throwaway Intermediate" {
		t.Fatalf("%v %+v", err, tr)
	}
	again, _ := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: pemOf(inter, root)}}, logs)
	if string(again) != string(raw) {
		t.Fatal("the same inputs in another order gave other bytes")
	}
	for name, in := range map[string][]byte{
		"an intermediate with no root":                          pemOf(inter),
		"two unrelated roots":                                   pemOf(root, other),
		"two self-signed roots":                                 pemOf(other, root, inter),
		"a real gap (an intermediate of a root not in the set)": pemOf(root, inter2),
		"not PEM": []byte("nope"),
		"empty":   nil,
	} {
		if _, err := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: in}}, logs); err == nil {
			t.Errorf("%s: built", name)
		}
	}
	// A window that ends before it starts is refused at build time, for a chain and for a key, and a chain's default
	// start is the root's, so an end before the root existed is refused too.
	later, earlier := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)
	if _, err := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: pemOf(root), Window: attest.Window{Start: later, End: earlier}}}, logs); err == nil {
		t.Error("an inverted chain window: built")
	}
	if _, err := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: pemOf(root), Window: attest.Window{End: root.NotBefore.Add(-time.Hour)}}}, logs); err == nil {
		t.Error("a chain window ending before the root exists: built")
	}
	if _, err := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: pemOf(root)}}, []attest.BuildLog{{PEM: r.KeyPEM, Window: attest.Window{Start: later, End: earlier}}}); err == nil {
		t.Error("an inverted key window: built")
	}
	if _, err := attest.BuildTrustedRoot(nil, logs); err == nil {
		t.Error("no chain: built")
	}
	if _, err := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: pemOf(root)}}, nil); err == nil {
		t.Error("no rekor key: built")
	}
	if _, err := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: pemOf(root)}}, []attest.BuildLog{{PEM: pemOf(root)}}); err == nil {
		t.Error("a certificate as a Rekor key: built")
	}
}

func TestParseTrustedRootRefusesWhatIsWrong(t *testing.T) {
	for name, in := range map[string]string{
		"not json":   "nope",
		"wrong type": `{"mediaType":"application/x"}`,
		"no CAs":     `{"mediaType":"` + attest.TrustedRootMediaType + `"}`,
	} {
		if _, err := attest.ParseTrustedRoot([]byte(in)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestCheckURLAcceptsHTTPOnlyForLoopbackAndInClusterServices(t *testing.T) {
	for _, ok := range []string{"https://fulcio.example.com", "http://127.0.0.1:5555", "http://localhost:8080",
		"http://fulcio-server.fulcio-system.svc", "http://rekor-server.rekor-system.svc:80", "http://a.b.svc.cluster.local/x"} {
		if _, err := attest.CheckURL("u", ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://fulcio.example.com", "http://evil.svc.example.com", "http://svc", "http://.svc",
		"http://a.b.c.svc", "http://fulcio.svc", "http://u:p@a.b.svc", "ftp://a.b.svc", "http://10.0.0.1"} {
		if _, err := attest.CheckURL("u", bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

// A certificate whose subject equals its issuer is not a root unless it really signed itself: a forged "self-issued"
// copy of the genuine root's name and key, signed by another key, must not become a trust anchor.
func TestAForgedSelfIssuedCertIsNotATrustAnchor(t *testing.T) {
	k := newKeyless(t)
	raw := signBundle(t, k)
	good, err := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: k.fulcio.RootPEM}}, []attest.BuildLog{{PEM: k.rekor.KeyPEM}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attest.Verify(raw, trustOpts(good, t)); err != nil {
		t.Fatal(err)
	}
	real := k.fulcio.Root
	other, otherKey := throwawayCA(t, "x", nil, nil, 1)
	_ = other
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: real.Subject, NotBefore: real.NotBefore, NotAfter: real.NotAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	parent := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: real.Subject, NotBefore: real.NotBefore, NotAfter: real.NotAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, real.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := x509.ParseCertificate(der)
	if string(forged.RawSubject) != string(forged.RawIssuer) || forged.CheckSignatureFrom(forged) == nil {
		t.Fatal("the forgery is not a bad self-issued certificate")
	}
	var doc map[string]any
	_ = json.Unmarshal(good, &doc)
	cas := doc["certificateAuthorities"].([]any)
	certs := cas[0].(map[string]any)["certChain"].(map[string]any)["certificates"].([]any)
	certs[0].(map[string]any)["rawBytes"] = base64.StdEncoding.EncodeToString(forged.Raw)
	bad, _ := json.Marshal(doc)
	if _, err := attest.Verify(raw, trustOpts(bad, t)); err == nil {
		t.Fatal("a forged self-issued certificate was accepted as a root")
	}
}

func TestTheCASubjectNamesTheRootNotTheIntermediate(t *testing.T) {
	root, rk := throwawayCA(t, "Throwaway Root", nil, nil, 1)
	inter, _ := throwawayCA(t, "Throwaway Intermediate", root, rk, 0)
	r := attesttest.NewRekor(t)
	raw, err := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: pemOf(inter, root)}}, []attest.BuildLog{{PEM: r.KeyPEM}})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		CertificateAuthorities []struct{ Subject map[string]string }
	}
	_ = json.Unmarshal(raw, &doc)
	if got := doc.CertificateAuthorities[0].Subject["commonName"]; got != "Throwaway Root" {
		t.Fatalf("subject %q", got)
	}
}

func TestParseAcceptsAnEd25519CAChainButNeedsAnECDSARekorKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "legacy-root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	r := attesttest.NewRekor(t)
	raw, err := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: pemOf(c)}}, []attest.BuildLog{{PEM: r.KeyPEM}})
	if err != nil {
		t.Fatal(err)
	}
	if tr, err := attest.ParseTrustedRoot(raw); err != nil || len(tr.CAs) != 1 {
		t.Fatalf("an Ed25519 chain: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	doc["tlogs"] = []any{}
	noLogs, _ := json.Marshal(doc)
	if _, err := attest.ParseTrustedRoot(noLogs); err == nil || !strings.Contains(err.Error(), "Rekor key") {
		t.Fatalf("no Rekor key: %v", err)
	}
	// A log whose key is Ed25519 is skipped, so a document with only that is refused too.
	edDER, _ := x509.MarshalPKIXPublicKey(pub)
	doc["tlogs"] = []any{map[string]any{"baseUrl": "http://r", "hashAlgorithm": "SHA2_256",
		"publicKey": map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(edDER), "keyDetails": "PKIX_ED25519"},
		"logId":     map[string]any{"keyId": "AAAA"}}}
	edOnly, _ := json.Marshal(doc)
	if _, err := attest.ParseTrustedRoot(edOnly); err == nil {
		t.Fatal("an Ed25519-only Rekor key list was accepted")
	}
}
