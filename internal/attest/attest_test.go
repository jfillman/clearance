package attest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/attest/attesttest"
	"github.com/jfillman/clearance/internal/token"
)

const (
	treeRoot = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	commit   = "1111111111111111111111111111111111111111"
	imageHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	identity = "https://kubernetes.io/namespaces/autopilot-system/serviceaccounts/clearance-recorder"
)

func testStatement() *attest.Statement {
	return &attest.Statement{Type: attest.StatementType, PredicateType: attest.PredicateType,
		Subject: []attest.Subject{
			{Name: "manifest-tree:o/r/app/prod", Digest: map[string]string{"sha256": treeRoot}},
			{Name: "commit:o/r", Digest: map[string]string{"gitCommit": commit}},
			{Name: "ghcr.io/o/app", Digest: map[string]string{"sha256": imageHex}}},
		Predicate: attest.Predicate{Clearance: token.Clearance{ID: "chg-1", ClearedBy: "policy", DecidedAt: "2026-11-07T00:00:00Z"},
			Approvals: []token.Approval{}, Provenance: token.Provenance{Level: "unknown", Proposer: "p", ProposerKind: "person"},
			Cleared: token.Subjects{Kind: "manifest-tree", Repo: "o/r", PR: 1, Commit: commit, TreeRoot: "sha256:" + treeRoot, Images: []string{}},
			Tier:    1, Coverage: "authorized-and-verified", Limitations: []string{"x"},
			Outcome: attest.Outcome{Seq: 7, Provider: "argocd-agent", Applied: true, At: "2026-11-07T00:01:00Z"}}}
}

func payload(t *testing.T, st *attest.Statement) []byte {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type keyless struct {
	b      *attest.Keyless
	fulcio *attesttest.Fulcio
	rekor  *attesttest.Rekor
	opts   attest.VerifyOptions
}

func newKeyless(t *testing.T) keyless {
	t.Helper()
	f, r := attesttest.NewFulcio(t), attesttest.NewRekor(t)
	rk, err := attest.NewRekor(r.URL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	roots, _ := attest.ParseRoots(f.RootPEM)
	rkey, err := attest.ParseRekorKey(r.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return keyless{b: &attest.Keyless{Fulcio: f.URL(), Rekor: rk, TokenFile: attesttest.WriteToken(t, attesttest.Issuer, identity)},
		fulcio: f, rekor: r,
		opts: attest.VerifyOptions{Roots: roots, Identity: identity, Issuer: attesttest.Issuer, RekorKey: rkey,
			Subjects: []string{"sha256:" + treeRoot, "gitCommit:" + commit}}}
}

func TestKeylessSignsLogsAndVerifiesOffline(t *testing.T) {
	k := newKeyless(t)
	s, err := k.b.Sign(context.Background(), payload(t, testStatement()))
	if err != nil {
		t.Fatal(err)
	}
	if s.Backend != "keyless" || s.RekorLogIndex == nil || *s.RekorLogIndex != 0 || k.rekor.Logged() != 1 || k.fulcio.Issued != 1 {
		t.Fatalf("%+v logged %d issued %d", s, k.rekor.Logged(), k.fulcio.Issued)
	}
	raw, _ := json.Marshal(s.Bundle)
	res, err := attest.Verify(raw, k.opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "keyless" || res.Identity != identity || !res.LogVerified || *res.LogIndex != 0 ||
		res.Digest != attest.EnvelopeDigest(s.Bundle.DSSEEnvelope) || res.Statement.Predicate.Clearance.ID != "chg-1" {
		t.Fatalf("%+v", res)
	}
	// Two attestations use two ephemeral keys and two certificates.
	if _, err := k.b.Sign(context.Background(), payload(t, testStatement())); err != nil || k.fulcio.Issued != 2 {
		t.Fatal(err, k.fulcio.Issued)
	}
}

func TestKeylessVerifyRefusesWhatIsWrong(t *testing.T) {
	k := newKeyless(t)
	s, err := k.b.Sign(context.Background(), payload(t, testStatement()))
	if err != nil {
		t.Fatal(err)
	}
	good, _ := json.Marshal(s.Bundle)
	other := attesttest.NewFulcio(t)
	otherRoots, _ := attest.ParseRoots(other.RootPEM)
	otherRekor := attesttest.NewRekor(t)
	otherKey, _ := attest.ParseRekorKey(otherRekor.KeyPEM)

	tampered := s.Bundle
	st := testStatement()
	st.Predicate.Tier = 0 // a different statement, the same signature
	tampered.DSSEEnvelope.Payload = base64.StdEncoding.EncodeToString(payload(t, st))
	tb, _ := json.Marshal(tampered)

	cases := map[string]struct {
		raw []byte
		mod func(o *attest.VerifyOptions)
	}{
		"tampered statement": {tb, nil},
		"wrong subject":      {good, func(o *attest.VerifyOptions) { o.Subjects = []string{"sha256:" + strings.Repeat("c", 64)} }},
		"wrong commit":       {good, func(o *attest.VerifyOptions) { o.Subjects = []string{"gitCommit:" + strings.Repeat("2", 40)} }},
		"wrong identity":     {good, func(o *attest.VerifyOptions) { o.Identity = identity + "-other" }},
		"wrong issuer":       {good, func(o *attest.VerifyOptions) { o.Issuer = "https://evil.test" }},
		"untrusted root":     {good, func(o *attest.VerifyOptions) { o.Roots = otherRoots }},
		"another rekor":      {good, func(o *attest.VerifyOptions) { o.RekorKey = otherKey }},
		"no rekor key":       {good, func(o *attest.VerifyOptions) { o.RekorKey = nil }},
		"no identity pinned": {good, func(o *attest.VerifyOptions) { o.Identity = "" }},
		"not json":           {[]byte("nope"), nil},
		"neither bundle":     {[]byte(`{"a":1}`), nil},
	}
	for name, c := range cases {
		o := k.opts
		if c.mod != nil {
			c.mod(&o)
		}
		if _, err := attest.Verify(c.raw, o); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// Dropping the Rekor entry from a keyless bundle is refused.
	nolog := s.Bundle
	nolog.VerificationMaterial.TlogEntries = nil
	nb, _ := json.Marshal(nolog)
	if _, err := attest.Verify(nb, k.opts); err == nil {
		t.Error("a keyless bundle with no Rekor entry verified")
	}
	if _, err := attest.Verify(good, k.opts); err != nil {
		t.Fatal("the good bundle stopped verifying:", err)
	}
}

func staticKey(t *testing.T) (token.Signer, token.KeySet) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.NewKeySigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return s, token.KeySet{s.KeyID(): s.Public()}
}

func TestStaticSignsAndVerifies(t *testing.T) {
	sg, ks := staticKey(t)
	rekor := attesttest.NewRekor(t)
	rk, _ := attest.NewRekor(rekor.URL(), nil)
	rkey, _ := attest.ParseRekorKey(rekor.KeyPEM)
	for name, b := range map[string]*attest.Static{"unlogged": {Signer: sg}, "logged": {Signer: sg, Rekor: rk}} {
		s, err := b.Sign(context.Background(), payload(t, testStatement()))
		if err != nil {
			t.Fatal(name, err)
		}
		raw, _ := json.Marshal(s.Bundle)
		res, err := attest.Verify(raw, attest.VerifyOptions{Keys: ks, RekorKey: rkey, Subjects: []string{"sha256:" + treeRoot}})
		if err != nil || res.Mode != "static" || res.KeyID != sg.KeyID() || res.LogVerified != (name == "logged") {
			t.Fatalf("%s: %+v %v", name, res, err)
		}
		// A bare envelope verifies too.
		env, _ := json.Marshal(s.Bundle.DSSEEnvelope)
		if _, err := attest.Verify(env, attest.VerifyOptions{Keys: ks}); err != nil {
			t.Fatal(name, "bare envelope:", err)
		}
		// Tampering, a wrong subject and a wrong key all fail.
		bad := s.Bundle
		st := testStatement()
		st.Subject[0].Digest["sha256"] = strings.Repeat("d", 64)
		bad.DSSEEnvelope.Payload = base64.StdEncoding.EncodeToString(payload(t, st))
		bb, _ := json.Marshal(bad)
		if _, err := attest.Verify(bb, attest.VerifyOptions{Keys: ks}); !errors.Is(err, token.ErrSignature) {
			t.Fatal(name, "tampered:", err)
		}
		if _, err := attest.Verify(raw, attest.VerifyOptions{Keys: ks, Subjects: []string{"sha256:" + strings.Repeat("e", 64)}}); err == nil {
			t.Fatal(name, "wrong subject verified")
		}
		_, other := staticKey(t)
		if _, err := attest.Verify(raw, attest.VerifyOptions{Keys: other}); !errors.Is(err, token.ErrUnknownKey) {
			t.Fatal(name, "wrong key:", err)
		}
		if _, err := attest.Verify(raw, attest.VerifyOptions{}); err == nil {
			t.Fatal(name, "verified with no key")
		}
	}
}

func TestVerifyRefusesAMalformedStatement(t *testing.T) {
	sg, ks := staticKey(t)
	b := &attest.Static{Signer: sg}
	for name, mod := range map[string]func(*attest.Statement){
		"no subject":     func(s *attest.Statement) { s.Subject = nil },
		"wrong type":     func(s *attest.Statement) { s.PredicateType = "https://example.test/other" },
		"no limitations": func(s *attest.Statement) { s.Predicate.Limitations = nil },
	} {
		st := testStatement()
		mod(st)
		s, err := b.Sign(context.Background(), payload(t, st))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(s.Bundle)
		if _, err := attest.Verify(raw, attest.VerifyOptions{Keys: ks}); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// An unknown field in the predicate is refused (the schema is closed).
	s, _ := b.Sign(context.Background(), []byte(`{"_type":"`+attest.StatementType+`","subject":[{"name":"a","digest":{"sha256":"aa"}}],"predicateType":"`+attest.PredicateType+`","predicate":{"extra":1}}`))
	raw, _ := json.Marshal(s.Bundle)
	if _, err := attest.Verify(raw, attest.VerifyOptions{Keys: ks}); err == nil {
		t.Error("an unknown predicate field verified")
	}
}

func TestFulcioAndRekorFailuresAreErrors(t *testing.T) {
	k := newKeyless(t)
	k.fulcio.Server.Close()
	if _, err := k.b.Sign(context.Background(), payload(t, testStatement())); err == nil {
		t.Fatal("signed with Fulcio down")
	}
	k = newKeyless(t)
	k.rekor.Server.Close()
	if _, err := k.b.Sign(context.Background(), payload(t, testStatement())); err == nil {
		t.Fatal("signed with Rekor down")
	}
	k = newKeyless(t)
	k.b.TokenFile = filepath.Join(t.TempDir(), "missing")
	if _, err := k.b.Sign(context.Background(), payload(t, testStatement())); err == nil {
		t.Fatal("signed without an identity token")
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if b, err := attest.FromEnv(env(nil)); b != nil || err != nil {
		t.Fatalf("nothing set: %v %v", b, err)
	}
	for name, m := range map[string]map[string]string{
		"both":                {attest.EnvKeyFile: "/k", attest.EnvFulcio: "https://f"},
		"rekor alone":         {attest.EnvRekor: "https://r"},
		"fulcio, no rekor":    {attest.EnvFulcio: "https://f"},
		"http fulcio":         {attest.EnvFulcio: "http://f.example", attest.EnvRekor: "https://r"},
		"credentials in url":  {attest.EnvFulcio: "https://u:p@f", attest.EnvRekor: "https://r"},
		"key, missing file":   {attest.EnvKeyFile: filepath.Join(t.TempDir(), "none")},
		"token file with key": {attest.EnvKeyFile: "/k", attest.EnvTokenFile: "/t"},
	} {
		if b, err := attest.FromEnv(env(m)); err == nil {
			t.Errorf("%s: accepted (%v)", name, b)
		}
	}
	b, err := attest.FromEnv(env(map[string]string{attest.EnvFulcio: "https://fulcio.example", attest.EnvRekor: "http://127.0.0.1:3000"}))
	if err != nil || b.Name() != "keyless" {
		t.Fatalf("%v %v", b, err)
	}
	// A static key file: written here, a throwaway.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := marshalEC(k)
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, der, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err = attest.FromEnv(env(map[string]string{attest.EnvKeyFile: p}))
	if err != nil || b.Name() != "static" {
		t.Fatalf("%v %v", b, err)
	}
}
