package attest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
		"an intermediate with no root": pemOf(inter),
		"two unrelated roots":          pemOf(root, other),
		"a gap":                        pemOf(root, other, inter),
		"not PEM":                      []byte("nope"),
		"empty":                        nil,
	} {
		if _, err := attest.BuildTrustedRoot([]attest.BuildCA{{PEM: in}}, logs); err == nil {
			t.Errorf("%s: built", name)
		}
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
