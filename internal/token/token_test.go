package token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/token"
)

var bg = context.Background()

// The test keys are generated here, per run; no key is committed.
func newSigner(t testing.TB) *token.KeySigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.NewKeySigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func keys(t testing.TB, ss ...*token.KeySigner) token.KeySet {
	t.Helper()
	set := token.JWKS{}
	for _, s := range ss {
		j, err := token.PublicJWK(s.Public())
		if err != nil {
			t.Fatal(err)
		}
		set.Keys = append(set.Keys, j)
	}
	raw, _ := json.Marshal(set)
	ks, err := token.ParseJWKS(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func claims() token.Claims {
	return token.Claims{
		Type: token.Type, Issuer: "clearance", Subject: "ch-0123456789abcdef", IssuedAt: t0.Unix(),
		Expires: t0.Add(15 * time.Minute).Unix(), Nonce: "n0nce",
		Clearance: token.Clearance{ID: "ch-0123456789abcdef", ClearedBy: "people", DecidedAt: "2026-11-03T12:00:00+00:00"},
		Subjects: token.Subjects{Kind: "manifest-tree", Repo: "acme/gitops", PR: 7, Commit: strings.Repeat("a", 40),
			TreeRoot: strings.Repeat("c", 64), Images: []string{"ghcr.io/acme/app@sha256:" + strings.Repeat("d", 64)}},
		Objects: []token.Object{{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "app", Name: "web",
			Rendered: strings.Repeat("e", 64), Changed: true, Op: "changed"}},
		Target: token.Target{Cluster: "prod-1", Env: "prod", App: "web"}, Tier: 2,
		Policy: token.Policy{Ref: "clearance.yaml@" + strings.Repeat("9", 40), Version: "baseline-2026-10-31", Engine: "kyverno/1.19.0", Verdict: "pass",
			Bundle: "https://github.com/acme/gitops-prod-1.git//30-policy@" + strings.Repeat("4", 40)},
		Provenance: token.Provenance{Level: "confirmed-human", Check: "not-agent", Proposer: "user:dana", ProposerKind: "person"},
		Approvals: []token.Approval{{Sub: "CgVhbGljZRIGZ2l0aHVi", Iss: "https://dex.example", Person: "user:alice",
			Role: "owner", At: "2026-11-03T12:00:00+00:00"}},
	}
}

func opts(now time.Time) token.Options {
	return token.Options{Issuer: "clearance", Now: func() time.Time { return now }}
}

func envJSON(t testing.TB, tok token.Token) []byte {
	t.Helper()
	b, err := json.Marshal(tok.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIssueAndVerify(t *testing.T) {
	s := newSigner(t)
	tok, err := token.Issue(bg, s, claims())
	if err != nil {
		t.Fatal(err)
	}
	if tok.Envelope.PayloadType != token.PayloadType || len(tok.Envelope.Signatures) != 1 ||
		tok.Envelope.Signatures[0].KeyID != s.KeyID() || tok.KeyID != s.KeyID() {
		t.Fatalf("envelope %+v", tok.Envelope)
	}
	ks := keys(t, s)
	got, err := token.Verify(bg, envJSON(t, tok), ks, opts(t0.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "ch-0123456789abcdef" || got.Approvals[0].Iss != "https://dex.example" || got.Objects[0].Rendered != strings.Repeat("e", 64) {
		t.Fatalf("claims %+v", got)
	}
	jc, err := token.VerifyJWT(bg, tok.JWT, ks, opts(t0.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(jc)
	if string(a) != string(b) {
		t.Fatalf("the JWT projection carries other claims:\n%s\n%s", a, b)
	}
	// The DSSE signature is plain ECDSA over sha256(PAE): what any DSSE verifier (sigstore-go's included) checks.
	payload, _ := base64.StdEncoding.DecodeString(tok.Envelope.Payload)
	sig, _ := base64.StdEncoding.DecodeString(tok.Envelope.Signatures[0].Sig)
	d := sha256.Sum256(token.PAE(token.PayloadType, payload))
	if !ecdsa.VerifyASN1(s.Public(), d[:], sig) {
		t.Fatal("the DSSE signature does not verify over the PAE")
	}
}

func TestPAE(t *testing.T) {
	// The DSSE specification's example.
	if got := string(token.PAE("http://example.com/HelloWorld", []byte("hello world"))); got != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Fatal(got)
	}
}

func TestExpiry(t *testing.T) {
	s := newSigner(t)
	tok, _ := token.Issue(bg, s, claims())
	ks := keys(t, s)
	exp := time.Unix(claims().Expires, 0)
	if _, err := token.Verify(bg, envJSON(t, tok), ks, opts(exp.Add(token.DefaultLeeway-time.Second))); err != nil {
		t.Fatalf("within the leeway: %v", err)
	}
	for _, now := range []time.Time{exp.Add(token.DefaultLeeway), exp.Add(time.Hour)} {
		if _, err := token.Verify(bg, envJSON(t, tok), ks, opts(now)); !errors.Is(err, token.ErrExpired) {
			t.Fatalf("at %s: %v", now, err)
		}
		if _, err := token.VerifyJWT(bg, tok.JWT, ks, opts(now)); !errors.Is(err, token.ErrExpired) {
			t.Fatalf("jwt at %s: %v", now, err)
		}
	}
	if _, err := token.Verify(bg, envJSON(t, tok), ks, opts(t0.Add(-time.Hour))); !errors.Is(err, token.ErrNotYetValid) {
		t.Fatal(err)
	}
	o := opts(exp.Add(time.Second))
	o.Leeway = -1
	if _, err := token.Verify(bg, envJSON(t, tok), ks, o); !errors.Is(err, token.ErrExpired) {
		t.Fatal(err)
	}
	// A token may not claim a long life, whoever signed it.
	c := claims()
	c.Expires = c.IssuedAt + int64(token.MaxLifetime/time.Second) + 1
	if _, err := token.Issue(bg, s, c); !errors.Is(err, token.ErrMalformed) {
		t.Fatal(err)
	}
}

// liveNonce is the core's check in miniature: the nonce the clearance holds now.
type liveNonce map[string]string

func (l liveNonce) CheckNonce(_ context.Context, c *token.Claims) error {
	if l[c.Subject] != c.Nonce {
		return token.ErrReplay
	}
	return nil
}

func TestReplay(t *testing.T) {
	s := newSigner(t)
	ks := keys(t, s)
	tok, _ := token.Issue(bg, s, claims())
	raw := envJSON(t, tok)

	// One-shot consumer: the same token twice is a replay, and so is a refresh of it (same clearance, same nonce).
	cache := &token.NonceCache{Now: func() time.Time { return t0 }}
	o := opts(t0)
	o.Nonces = cache
	if _, err := token.Verify(bg, raw, ks, o); err != nil {
		t.Fatal(err)
	}
	if _, err := token.Verify(bg, raw, ks, o); !errors.Is(err, token.ErrReplay) {
		t.Fatalf("second use: %v", err)
	}
	c := claims()
	c.IssuedAt, c.Expires = t0.Add(5*time.Minute).Unix(), t0.Add(20*time.Minute).Unix()
	refreshed, _ := token.Issue(bg, s, c)
	later := o
	later.Now = func() time.Time { return t0.Add(6 * time.Minute) }
	if _, err := token.VerifyJWT(bg, refreshed.JWT, ks, later); !errors.Is(err, token.ErrReplay) {
		t.Fatalf("a refresh of a used token: %v", err)
	}
	// Full cache fails closed.
	small := &token.NonceCache{Max: 1, Now: func() time.Time { return t0 }}
	o.Nonces = small
	if _, err := token.Verify(bg, raw, ks, o); err != nil {
		t.Fatal(err)
	}
	c2 := claims()
	c2.Nonce = "other"
	other, _ := token.Issue(bg, s, c2)
	if _, err := token.Verify(bg, envJSON(t, other), ks, o); !errors.Is(err, token.ErrCacheFull) || !errors.Is(err, token.ErrReplay) {
		t.Fatal(err)
	}

	// The core's check: a token whose nonce is no longer the clearance's (a new head revoked it, or it was cleared
	// again) is refused, though its signature and expiry are fine.
	live := liveNonce{"ch-0123456789abcdef": "n0nce"}
	o.Nonces = live
	if _, err := token.Verify(bg, raw, ks, o); err != nil {
		t.Fatal(err)
	}
	live["ch-0123456789abcdef"] = "rotated"
	if _, err := token.Verify(bg, raw, ks, o); !errors.Is(err, token.ErrReplay) {
		t.Fatal(err)
	}
	delete(live, "ch-0123456789abcdef")
	if _, err := token.VerifyJWT(bg, tok.JWT, ks, o); !errors.Is(err, token.ErrReplay) {
		t.Fatal(err)
	}
}

func TestChangedDigest(t *testing.T) {
	s := newSigner(t)
	ks := keys(t, s)
	tok, _ := token.Issue(bg, s, claims())
	raw := envJSON(t, tok)
	for name, e := range map[string]token.Expect{
		"tree root": {TreeRoot: strings.Repeat("f", 64)},
		"commit":    {Commit: strings.Repeat("b", 40)},
		"clearance": {ClearanceID: "ch-ffffffffffffffff"},
		"cluster":   {Cluster: "prod-2"},
		"plan":      {PlanDigest: "sha256:" + strings.Repeat("1", 64)},
	} {
		o := opts(t0)
		o.Expect = e
		if _, err := token.Verify(bg, raw, ks, o); !errors.Is(err, token.ErrDigestMismatch) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := token.VerifyJWT(bg, tok.JWT, ks, o); !errors.Is(err, token.ErrDigestMismatch) {
			t.Errorf("jwt %s: %v", name, err)
		}
	}
	o := opts(t0)
	o.Expect = token.Expect{TreeRoot: strings.Repeat("c", 64), Commit: strings.Repeat("a", 40), Cluster: "prod-1"}
	got, err := token.Verify(bg, raw, ks, o)
	if err != nil {
		t.Fatal(err)
	}
	// Per object: the listed hash covers it, another hash does not, an unlisted object is not covered.
	if err := got.Covers("apps/v1", "Deployment", "app", "web", strings.Repeat("e", 64)); err != nil {
		t.Fatal(err)
	}
	if err := got.Covers("apps/v1", "Deployment", "app", "web", strings.Repeat("9", 64)); !errors.Is(err, token.ErrDigestMismatch) {
		t.Fatal(err)
	}
	if err := got.Covers("v1", "Secret", "app", "web", strings.Repeat("e", 64)); !errors.Is(err, token.ErrNotCovered) {
		t.Fatal(err)
	}

	// A payload edited after signing (the tree root swapped) fails the signature, in both encodings.
	payload, _ := base64.StdEncoding.DecodeString(tok.Envelope.Payload)
	edited := strings.Replace(string(payload), strings.Repeat("c", 64), strings.Repeat("f", 64), 1)
	env := tok.Envelope
	env.Payload = base64.StdEncoding.EncodeToString([]byte(edited))
	b, _ := json.Marshal(env)
	if _, err := token.Verify(bg, b, ks, opts(t0)); !errors.Is(err, token.ErrSignature) {
		t.Fatal(err)
	}
	parts := strings.Split(tok.JWT, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(edited))
	if _, err := token.VerifyJWT(bg, strings.Join(parts, "."), ks, opts(t0)); !errors.Is(err, token.ErrSignature) {
		t.Fatal(err)
	}
}

func TestKeysAndRefusals(t *testing.T) {
	s, other := newSigner(t), newSigner(t)
	tok, _ := token.Issue(bg, s, claims())
	raw := envJSON(t, tok)
	if _, err := token.Verify(bg, raw, keys(t, other), opts(t0)); !errors.Is(err, token.ErrUnknownKey) {
		t.Fatal(err)
	}
	if _, err := token.VerifyJWT(bg, tok.JWT, keys(t, other), opts(t0)); !errors.Is(err, token.ErrUnknownKey) {
		t.Fatal(err)
	}
	// Another key under this key's id.
	forged := token.KeySet{s.KeyID(): other.Public()}
	if _, err := token.Verify(bg, raw, forged, opts(t0)); !errors.Is(err, token.ErrSignature) {
		t.Fatal(err)
	}
	if _, err := token.VerifyJWT(bg, tok.JWT, forged, opts(t0)); !errors.Is(err, token.ErrSignature) {
		t.Fatal(err)
	}
	ks := keys(t, s, other)
	o := opts(t0)
	o.Issuer = "someone-else"
	if _, err := token.Verify(bg, raw, ks, o); !errors.Is(err, token.ErrIssuer) {
		t.Fatal(err)
	}
	o.Issuer = ""
	if _, err := token.Verify(bg, raw, ks, o); !errors.Is(err, token.ErrIssuer) {
		t.Fatal("an empty issuer must not accept any")
	}
	// A JWKS whose kid is not the key's thumbprint is refused.
	j, _ := token.PublicJWK(s.Public())
	j.Kid = "alias"
	b, _ := json.Marshal(token.JWKS{Keys: []token.JWK{j}})
	if _, err := token.ParseJWKS(b); !errors.Is(err, token.ErrMalformed) {
		t.Fatal(err)
	}
	// alg none, a wrong typ, a truncated signature, unknown claim fields, another payload type.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"` + s.KeyID() + `","typ":"` + token.JWTType + `"}`))
	parts := strings.Split(tok.JWT, ".")
	for _, bad := range []string{hdr + "." + parts[1] + ".", parts[0] + "." + parts[1] + "." + parts[2][:10], "a.b", ""} {
		if _, err := token.VerifyJWT(bg, bad, ks, opts(t0)); !errors.Is(err, token.ErrMalformed) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	env := tok.Envelope
	env.PayloadType = "application/vnd.in-toto+json"
	b, _ = json.Marshal(env)
	if _, err := token.Verify(bg, b, ks, opts(t0)); !errors.Is(err, token.ErrMalformed) {
		t.Fatal(err)
	}
	if _, err := token.Verify(bg, []byte(`{"payloadType":"`+token.PayloadType+`","payload":"","signatures":[],"x":1}`), ks, opts(t0)); !errors.Is(err, token.ErrMalformed) {
		t.Fatal(err)
	}
	// Signed claims with an extra field are refused (strict decoding of what was signed).
	payload, _ := base64.StdEncoding.DecodeString(tok.Envelope.Payload)
	extra := strings.Replace(string(payload), `{"_type"`, `{"admin":true,"_type"`, 1)
	d := sha256.Sum256(token.PAE(token.PayloadType, []byte(extra)))
	sig, _ := s.Sign(bg, d[:])
	b, _ = json.Marshal(token.Envelope{PayloadType: token.PayloadType, Payload: base64.StdEncoding.EncodeToString([]byte(extra)),
		Signatures: []token.Signature{{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)}}})
	if _, err := token.Verify(bg, b, ks, opts(t0)); !errors.Is(err, token.ErrMalformed) {
		t.Fatal(err)
	}
}

func TestKeyFile(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(k)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(k)
	dir := t.TempDir()
	for name, b := range map[string]*pem.Block{"sec1.pem": {Type: "EC PRIVATE KEY", Bytes: sec1}, "pkcs8.pem": {Type: "PRIVATE KEY", Bytes: pkcs8}} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(b), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := token.LoadKeyFile(p)
		if err != nil {
			t.Fatal(name, err)
		}
		want, _ := token.KeyID(&k.PublicKey)
		if s.KeyID() != want {
			t.Fatal(name)
		}
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	b384, _ := x509.MarshalECPrivateKey(p384)
	for name, raw := range map[string][]byte{
		"p384":    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b384}),
		"not pem": []byte("nope"),
		"cert":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
	} {
		_, err := token.ParseKeyPEM(raw)
		if err == nil {
			t.Fatalf("%s accepted", name)
		}
		if strings.Contains(err.Error(), string(raw)) {
			t.Fatalf("%s: the error quotes the key", name)
		}
	}
	if _, err := token.LoadKeyFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing file")
	}
}

func FuzzVerifyEnvelope(f *testing.F) {
	s := newSigner(f)
	tok, _ := token.Issue(bg, s, claims())
	raw, _ := json.Marshal(tok.Envelope)
	f.Add(raw)
	f.Add([]byte(`{"payloadType":"` + token.PayloadType + `","payload":"e30=","signatures":[{"keyid":"","sig":"MEUCIQ=="}]}`))
	f.Add([]byte(`[]`))
	ks := keys(f, s)
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := token.Verify(bg, b, ks, opts(t0))
		if err == nil && c.Subject == "" {
			t.Fatal("verified claims without a subject")
		}
	})
}

func FuzzVerifyJWT(f *testing.F) {
	s := newSigner(f)
	tok, _ := token.Issue(bg, s, claims())
	f.Add(tok.JWT)
	f.Add("e30.e30.")
	f.Add("..")
	ks := keys(f, s)
	f.Fuzz(func(t *testing.T, jwt string) {
		c, err := token.VerifyJWT(bg, jwt, ks, opts(t0))
		if err == nil && c.Subject == "" {
			t.Fatal("verified claims without a subject")
		}
	})
}

func FuzzParseJWKS(f *testing.F) {
	j, _ := token.PublicJWK(newSigner(f).Public())
	b, _ := json.Marshal(token.JWKS{Keys: []token.JWK{j}})
	f.Add(b)
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"","y":""}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		ks, err := token.ParseJWKS(raw)
		if err != nil {
			return
		}
		for kid, pub := range ks {
			if got, _ := token.KeyID(pub); got != kid {
				t.Fatal(fmt.Sprintf("kid %q is not its key's thumbprint", kid))
			}
		}
	})
}
