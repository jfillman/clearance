package authn

// Ported from tests/test_auth.py (one Go test per Python test, names mirrored) and the GitHub Actions authenticator
// tests of tests/test_register.py, plus negative tests the Python suite does not have.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	iss = "https://dex.example/dex"
	aud = "clearance"
)

var (
	keyOnce           sync.Once
	testKey, otherKey *rsa.PrivateKey
)

func keys(t testing.TB) (*rsa.PrivateKey, *rsa.PrivateKey) {
	keyOnce.Do(func() {
		var err error
		if testKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if otherKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return testKey, otherKey
}

func enc(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// sign makes a compact JWS. signer is an *rsa.PrivateKey (RS256), *ecdsa.PrivateKey (ES256), []byte (HS256) or nil
// (none).
func sign(t testing.TB, claims map[string]any, signer any, header map[string]any) string {
	h := map[string]any{"typ": "JWT"}
	switch signer.(type) {
	case *rsa.PrivateKey:
		h["alg"] = "RS256"
	case *ecdsa.PrivateKey:
		h["alg"] = "ES256"
	case []byte:
		h["alg"] = "HS256"
	default:
		h["alg"] = "none"
	}
	for k, v := range header {
		h[k] = v
	}
	in := enc(h) + "." + enc(claims)
	d := sha256.Sum256([]byte(in))
	var sig []byte
	switch k := signer.(type) {
	case *rsa.PrivateKey:
		s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = s
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case []byte:
		m := hmac.New(sha256.New, k)
		m.Write([]byte(in))
		sig = m.Sum(nil)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwkOf(pub crypto.PublicKey, kid string) map[string]any {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return map[string]any{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(p.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.E)).Bytes())}
	case *ecdsa.PublicKey:
		b, _ := p.Bytes()
		return map[string]any{"kty": "EC", "kid": kid, "use": "sig", "alg": "ES256", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(b[1:33]), "y": base64.RawURLEncoding.EncodeToString(b[33:])}
	}
	panic("key type")
}

func jwksDoc(ks ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"keys": ks})
	return b
}

// claimsWith is test_auth.py's id_token claims with overrides; a nil value drops the claim.
func claimsWith(over map[string]any) map[string]any {
	now := time.Now().Unix()
	c := map[string]any{"iss": iss, "aud": aud, "sub": "CiQx", "email": "alice@example.com", "email_verified": true,
		"iat": now, "exp": now + 300}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func idToken(t testing.TB, signer any, kid string, over map[string]any) string {
	return sign(t, claimsWith(over), signer, map[string]any{"kid": kid})
}

type fetchLog struct {
	mu sync.Mutex
	n  int
}

func (f *fetchLog) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.n }

func staticJWKS(f *fetchLog, doc []byte) *JWKS {
	return &JWKS{URL: iss + "/keys", MinRefresh: time.Minute, Fetch: func(context.Context, string) ([]byte, error) {
		if f != nil {
			f.mu.Lock()
			f.n++
			f.mu.Unlock()
		}
		return doc, nil
	}}
}

func oidcFixture(t *testing.T) (*OIDCAuthenticator, *fetchLog) {
	k, _ := keys(t)
	f := &fetchLog{}
	return NewOIDCAuthenticator(iss, aud, staticJWKS(f, jwksDoc(jwkOf(&k.PublicKey, "k1"))), []string{"alice@example.com"}), f
}

func mustRefuse(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted, want a refusal")
	}
	if !IsRefusal(err) {
		t.Fatalf("error %v is not an *Error", err)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("refusal %q does not say %q", err, contains)
	}
}

var bg = context.Background()

func TestAValidIDTokenIsAUser(t *testing.T) {
	a, _ := oidcFixture(t)
	k, _ := keys(t)
	p, err := a.Authenticate(bg, idToken(t, k, "k1", nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "user:alice@example.com" || p.Kind != KindPerson || !p.IsPerson() {
		t.Fatalf("got %+v", p)
	}
	// The person at their identity provider, for an approval's sub and iss (C-1).
	if p.Claims["iss"] != iss || p.Claims["sub"] == nil || p.Claims["sub"] == "" {
		t.Fatalf("claims %v", p.Claims)
	}
}

func TestAValidTokenForSomeoneNotAllowedIsRefused(t *testing.T) {
	a, _ := oidcFixture(t)
	k, _ := keys(t)
	mallory := idToken(t, k, "k1", map[string]any{"email": "mallory@example.com"})
	_, err := a.Authenticate(bg, mallory)
	mustRefuse(t, err, "not allowed")
	a.Allowed = []string{"*@example.com"}
	if p, err := a.Authenticate(bg, mallory); err != nil || p.ID != "user:mallory@example.com" {
		t.Fatalf("got %+v, %v", p, err)
	}
	a.Allowed = nil
	_, err = a.Authenticate(bg, idToken(t, k, "k1", nil))
	mustRefuse(t, err, "not allowed")
}

func TestAWrongClaimIsRefused(t *testing.T) {
	k, _ := keys(t)
	for name, bad := range map[string]map[string]any{
		"aud":            {"aud": "someone-else"},
		"iss":            {"iss": "https://evil.example"},
		"exp":            {"exp": time.Now().Unix() - 3600},
		"email":          {"email": nil},
		"email_verified": {"email_verified": false},
		"sub":            {"sub": nil},
	} {
		t.Run(name, func(t *testing.T) {
			a, _ := oidcFixture(t)
			_, err := a.Authenticate(bg, idToken(t, k, "k1", bad))
			mustRefuse(t, err, "")
		})
	}
}

func TestATokenSignedByAnotherKeyIsRefused(t *testing.T) {
	a, _ := oidcFixture(t)
	_, o := keys(t)
	_, err := a.Authenticate(bg, idToken(t, o, "k1", nil))
	mustRefuse(t, err, "")
}

func TestHmacAndNoneAreNeverAccepted(t *testing.T) {
	a, _ := oidcFixture(t)
	now := time.Now().Unix()
	c := map[string]any{"iss": iss, "aud": aud, "sub": "x", "email": "a@b", "iat": now, "exp": now + 60}
	a.Allowed = []string{"*"}
	for _, tok := range []string{
		sign(t, c, []byte(strings.Repeat("s", 32)), map[string]any{"kid": "k1"}),
		sign(t, c, nil, map[string]any{"kid": "k1"}),
	} {
		_, err := a.Authenticate(bg, tok)
		mustRefuse(t, err, "")
	}
}

func TestAnUnknownKidRefetchesAtMostOnceAMinute(t *testing.T) {
	a, f := oidcFixture(t)
	k, _ := keys(t)
	if _, err := a.Authenticate(bg, idToken(t, k, "k1", nil)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, err := a.Authenticate(bg, idToken(t, k, "nope", nil))
		mustRefuse(t, err, "unknown signing key")
	}
	if f.count() != 1 {
		t.Fatalf("%d fetches; the first fetch happened under a minute ago", f.count())
	}
	// A minute on, an unknown kid fetches again.
	later := time.Now().Add(61 * time.Second)
	a.Keys.Now = func() time.Time { return later }
	_, _ = a.Authenticate(bg, idToken(t, k, "nope", nil))
	if f.count() != 2 {
		t.Fatalf("%d fetches after a minute, want 2", f.count())
	}
}

// opener is test_auth.py's Opener: it records each TokenReview and answers with status (or fails).
type opener struct {
	status any
	fail   error
	code   int
	calls  []openerCall
}

type openerCall struct {
	url   string
	body  map[string]any
	authz string
}

func (o *opener) do(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	o.calls = append(o.calls, openerCall{r.URL.String(), body, r.Header.Get("Authorization")})
	if o.fail != nil {
		return nil, o.fail
	}
	code := o.code
	if code == 0 {
		code = 201
	}
	out, _ := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "status": o.status})
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(string(out))), Header: http.Header{}}, nil
}

func workload(t *testing.T, o *opener) *WorkloadAuthenticator {
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("clearance-own-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWorkloadAuthenticator("clearance")
	a.TokenFile, a.Do = tok, o.do
	return a
}

func TestAReviewedServiceAccountTokenIsAWorkload(t *testing.T) {
	o := &opener{status: map[string]any{"authenticated": true, "audiences": []string{"clearance"},
		"user": map[string]any{"username": "system:serviceaccount:holmesgpt:holmes"}}}
	p, err := workload(t, o).Authenticate(bg, "caller-token")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "holmesgpt/holmes" || p.Kind != KindServiceAccount {
		t.Fatalf("got %+v", p)
	}
	c := o.calls[0]
	if !strings.HasSuffix(c.url, "/apis/authentication.k8s.io/v1/tokenreviews") {
		t.Fatal(c.url)
	}
	spec, _ := json.Marshal(c.body["spec"])
	if string(spec) != `{"audiences":["clearance"],"token":"caller-token"}` {
		t.Fatal(string(spec))
	}
	if c.authz != "Bearer clearance-own-token" {
		t.Fatalf("Clearance reviews with its own identity, re-read from the file: %q", c.authz)
	}
}

func TestAnUnreviewedOrForeignTokenIsRefused(t *testing.T) {
	for i, status := range []map[string]any{
		{"authenticated": false},
		{"authenticated": true, "audiences": []string{"https://kubernetes.default.svc"}, "user": map[string]any{"username": "system:serviceaccount:a:b"}},
		{"authenticated": true, "audiences": []string{"clearance"}, "user": map[string]any{"username": "alice"}},
		{"authenticated": true, "audiences": []string{"clearance"}, "user": map[string]any{"username": "system:serviceaccount:a:b:c"}},
	} {
		_, err := workload(t, &opener{status: status}).Authenticate(bg, "t")
		if err == nil {
			t.Fatalf("case %d accepted", i)
		}
		mustRefuse(t, err, "")
	}
}

func TestTheAPIServerUnreachableIsARefusal(t *testing.T) {
	_, err := workload(t, &opener{fail: errors.New("down")}).Authenticate(bg, "t")
	mustRefuse(t, err, "token review failed")
	// A non-2xx answer (Python's HTTPError) too.
	ok := map[string]any{"authenticated": true, "audiences": []string{"clearance"}, "user": map[string]any{"username": "system:serviceaccount:a:b"}}
	_, err = workload(t, &opener{status: ok, code: 403}).Authenticate(bg, "t")
	mustRefuse(t, err, "token review failed")
}

// count is test_auth.py's Count: an authenticator that counts its calls and answers p (or refuses when p is nil).
type count struct {
	mu sync.Mutex
	p  *Principal
	n  int
}

func (c *count) Authenticate(context.Context, string) (Principal, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	if c.p == nil {
		return Principal{}, refuse("no")
	}
	return *c.p, nil
}

func TestRoutingByIssuerAndTheVerifierStillChecksEverything(t *testing.T) {
	oidc, _ := oidcFixture(t)
	k, o := keys(t)
	wl := &count{p: &Principal{ID: "ns/sa", Kind: KindServiceAccount}}
	r := &RoutingAuthenticator{ByIssuer: map[string]Authenticator{iss: oidc}, Workload: wl}
	if p, err := r.Authenticate(bg, idToken(t, k, "k1", nil)); err != nil || p.Kind != KindPerson || wl.n != 0 {
		t.Fatalf("got %+v %v n=%d", p, err, wl.n)
	}
	sa := sign(t, map[string]any{"iss": "https://kubernetes.default.svc", "exp": time.Now().Unix() + 60}, []byte(strings.Repeat("x", 32)), nil)
	if p, err := r.Authenticate(bg, sa); err != nil || p.ID != "ns/sa" || wl.n != 1 {
		t.Fatalf("got %+v %v n=%d", p, err, wl.n)
	}
	// Claims Dex's issuer, fails Dex's verification; never falls through.
	_, err := r.Authenticate(bg, idToken(t, o, "k1", nil))
	mustRefuse(t, err, "")
	if wl.n != 1 {
		t.Fatal("fell through to the workload verifier")
	}
	_, err = r.Authenticate(bg, "not-a-jwt")
	mustRefuse(t, err, "not a JWT")
	_, err = (&RoutingAuthenticator{}).Authenticate(bg, sa)
	mustRefuse(t, err, "no verifier")
}

func TestCacheHoldsASuccessUntilTTLOrExpAndNeverAFailure(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	inner := &count{p: &Principal{ID: "u", Kind: KindPerson}}
	c := NewCachingAuthenticator(inner)
	c.Now = clock
	tok := sign(t, map[string]any{"exp": 1030}, []byte(strings.Repeat("x", 32)), nil)
	for i := 0; i < 2; i++ {
		if _, err := c.Authenticate(bg, tok); err != nil {
			t.Fatal(err)
		}
	}
	if inner.n != 1 {
		t.Fatalf("inner called %d times", inner.n)
	}
	now = time.Unix(1031, 0) // past exp, though inside the ttl
	_, _ = c.Authenticate(bg, tok)
	if inner.n != 2 {
		t.Fatalf("inner called %d times past exp", inner.n)
	}
	// And the ttl itself: a far exp is held for 60 s only.
	far := sign(t, map[string]any{"exp": 99999}, []byte(strings.Repeat("x", 32)), nil)
	_, _ = c.Authenticate(bg, far)
	now = now.Add(59 * time.Second)
	_, _ = c.Authenticate(bg, far)
	if inner.n != 3 {
		t.Fatalf("inner called %d times inside the ttl", inner.n)
	}
	now = now.Add(2 * time.Second)
	_, _ = c.Authenticate(bg, far)
	if inner.n != 4 {
		t.Fatalf("inner called %d times past the ttl", inner.n)
	}
	bad := &count{}
	bc := NewCachingAuthenticator(bad)
	bc.Now = clock
	for i := 0; i < 2; i++ {
		_, err := bc.Authenticate(bg, tok)
		mustRefuse(t, err, "")
	}
	if bad.n != 2 {
		t.Fatalf("a failure was cached: inner called %d times", bad.n)
	}
}

func TestACacheIsBounded(t *testing.T) {
	inner := &count{p: &Principal{ID: "u"}}
	c := NewCachingAuthenticator(inner)
	c.MaxEntries = 8
	for i := 0; i < 20; i++ {
		tok := sign(t, map[string]any{"exp": time.Now().Unix() + 100 + int64(i)}, []byte("k"), nil)
		if _, err := c.Authenticate(bg, tok); err != nil {
			t.Fatal(err)
		}
		if len(c.cache) > 8 {
			t.Fatalf("%d entries", len(c.cache))
		}
	}
}

func TestAForeignClustersServiceAccountIsANamedWorkloadAndOnlyIfAllowed(t *testing.T) {
	k, o := keys(t)
	prod := "https://hangarplatform.dev/oidc/hangar-prod"
	a := NewForeignWorkloadAuthenticator("hangar-prod", prod, "clearance", staticJWKS(nil, jwksDoc(jwkOf(&k.PublicKey, "k1"))),
		[]string{"app-backstage-prod/backstage"})
	sa := func(sub string, signer any, over map[string]any) string {
		m := map[string]any{"iss": prod, "sub": sub, "email": nil, "email_verified": nil}
		for kk, v := range over {
			m[kk] = v
		}
		return idToken(t, signer, "k1", m)
	}
	p, err := a.Authenticate(bg, sa("system:serviceaccount:app-backstage-prod:backstage", k, nil))
	if err != nil || p.ID != "hangar-prod/app-backstage-prod/backstage" || p.Kind != KindForeignWorkload {
		t.Fatalf("got %+v %v", p, err)
	}
	for _, c := range []struct{ tok, why string }{
		{sa("system:serviceaccount:default:default", k, nil), "may not call"},
		{sa("user-xyz", k, nil), "service-account"},
		{sa("system:serviceaccount:app-backstage-prod:backstage", k, map[string]any{"aud": "other"}), "rejected"},
		{idToken(t, k, "k1", map[string]any{"sub": "system:serviceaccount:app-backstage-prod:backstage"}), "rejected"},
		{sa("system:serviceaccount:app-backstage-prod:backstage", o, nil), "rejected"},
	} {
		_, err := a.Authenticate(bg, c.tok)
		mustRefuse(t, err, c.why)
	}
}

// -- tests/test_register.py: the GitHub Actions authenticator -------------------------------------------------------

const (
	head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	repo = "jfillman/clearance-deploy-scratch"
)

func ghToken(t testing.TB, signer any, over map[string]any) string {
	now := time.Now().Unix()
	c := map[string]any{"iss": GitHubActionsIssuer, "aud": "clearance", "iat": now, "exp": now + 300,
		"sub": "repo:" + repo + ":environment:prod", "repository": "jfillman/Clearance-Deploy-Scratch",
		"environment": "prod", "ref": "refs/heads/main", "sha": head}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return sign(t, c, signer, map[string]any{"kid": "k1"})
}

func ghAuth(t testing.TB, allowed []string) (*GitHubActionsAuthenticator, *fetchLog) {
	k, _ := keys(t)
	f := &fetchLog{}
	return NewGitHubActionsAuthenticator("clearance", staticJWKS(f, jwksDoc(jwkOf(&k.PublicKey, "k1"))), allowed), f
}

func TestAWorkflowTokenIsAGithubPrincipalWithItsRepository(t *testing.T) {
	a, f := ghAuth(t, nil)
	k, _ := keys(t)
	p, err := a.Authenticate(bg, ghToken(t, k, nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "github:repo:"+repo+":environment:prod" || p.Kind != KindGitHubActions {
		t.Fatalf("got %+v", p)
	}
	if p.Claims["repository"] != repo || p.Claims["environment"] != "prod" {
		t.Fatalf("claims %v", p.Claims)
	}
	if _, err := a.Authenticate(bg, ghToken(t, k, nil)); err != nil {
		t.Fatal(err)
	}
	if f.count() != 1 {
		t.Fatal("the JWKS is cached")
	}
}

func TestWrongAudienceExpiredForeignOrNotARepoTokenIsRefused(t *testing.T) {
	k, _ := keys(t)
	for name, over := range map[string]map[string]any{
		"aud":        {"aud": "someone-else"},
		"exp":        {"exp": time.Now().Unix() - 600},
		"iss":        {"iss": "https://evil.example"},
		"sub":        {"sub": "system:serviceaccount:a:b"},
		"repository": {"repository": nil},
	} {
		t.Run(name, func(t *testing.T) {
			a, _ := ghAuth(t, nil)
			_, err := a.Authenticate(bg, ghToken(t, k, over))
			mustRefuse(t, err, "")
		})
	}
}

func TestAnotherKeyAndAnHmacTokenAreRefused(t *testing.T) {
	a, _ := ghAuth(t, nil)
	_, o := keys(t)
	_, err := a.Authenticate(bg, ghToken(t, o, nil))
	mustRefuse(t, err, "")
	now := time.Now().Unix()
	forged := sign(t, map[string]any{"iss": GitHubActionsIssuer, "aud": "clearance", "sub": "repo:" + repo + ":ref:x",
		"repository": repo, "iat": now, "exp": now + 60}, []byte(strings.Repeat("s", 32)), map[string]any{"kid": "k1"})
	_, err = a.Authenticate(bg, forged)
	mustRefuse(t, err, "")
}

func TestAllowedNarrowsWhichWorkflowsGetIn(t *testing.T) {
	a, _ := ghAuth(t, []string{"repo:jfillman/other:*"})
	k, _ := keys(t)
	_, err := a.Authenticate(bg, ghToken(t, k, nil))
	mustRefuse(t, err, "may not call")
	none, _ := ghAuth(t, []string{})
	_, err = none.Authenticate(bg, ghToken(t, k, nil))
	mustRefuse(t, err, "may not call")
}

func TestTheImmutableIDSubjectMatchesByName(t *testing.T) {
	k, _ := keys(t)
	raw := "repo:jfillman@7268337/clearance-deploy-scratch@1441488947:ref:refs/heads/main"
	a, _ := ghAuth(t, []string{"repo:jfillman/clearance-deploy-scratch:*"})
	p, err := a.Authenticate(bg, ghToken(t, k, map[string]any{"sub": raw, "repository_id": "1441488947", "repository_owner_id": "7268337"}))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "github:repo:jfillman/clearance-deploy-scratch:ref:refs/heads/main" {
		t.Fatal(p.ID)
	}
	if p.Claims["sub"] != raw || p.Claims["repository_id"] != "1441488947" {
		t.Fatalf("claims %v", p.Claims)
	}
	for in, want := range map[string]string{
		"repo:acme/shop:environment:prod": "repo:acme/shop:environment:prod",
		"repo:acme@1/shop@2":              "repo:acme/shop",
		"repo:acme@x/shop":                "repo:acme@x/shop",
		"repo:a/b:x\n":                    "repo:a/b:x", // Python's $ matches before a final newline
	} {
		if got := CanonicalSub(in); got != want {
			t.Errorf("CanonicalSub(%q) = %q, want %q", in, got, want)
		}
	}
	other, _ := ghAuth(t, []string{"repo:jfillman/other:*"})
	_, err = other.Authenticate(bg, ghToken(t, k, map[string]any{"sub": raw}))
	mustRefuse(t, err, "")
}

// -- negative tests beyond the Python suite -------------------------------------------------------------------------

func TestNegativeTokens(t *testing.T) {
	k, _ := keys(t)
	pubDER, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	now := time.Now().Unix()
	base := claimsWith(nil)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, tok := range map[string]string{
		"alg none, empty signature":     strings.TrimSuffix(sign(t, base, nil, map[string]any{"kid": "k1"}), "."),
		"alg none":                      sign(t, base, nil, map[string]any{"kid": "k1"}),
		"HS256 with the RSA public key": sign(t, base, pubPEM, map[string]any{"kid": "k1"}),
		"HS256 with the JWK n":          sign(t, base, k.PublicKey.N.Bytes(), map[string]any{"kid": "k1"}),
		"RS256 header, ES256 key":       sign(t, base, ec, map[string]any{"kid": "k1", "alg": "RS256"}),
		"ES256 header on an RSA key":    sign(t, base, k, map[string]any{"kid": "k1", "alg": "ES256"}),
		"PS256":                         sign(t, base, k, map[string]any{"kid": "k1", "alg": "PS256"}),
		"wrong aud":                     idToken(t, k, "k1", map[string]any{"aud": "other"}),
		"aud list without us":           idToken(t, k, "k1", map[string]any{"aud": []string{"a", "b"}}),
		"aud empty list":                idToken(t, k, "k1", map[string]any{"aud": []string{}}),
		"expired":                       idToken(t, k, "k1", map[string]any{"exp": now - 31}),
		"exp a string":                  idToken(t, k, "k1", map[string]any{"exp": "99999999999"}),
		"iat in the future":             idToken(t, k, "k1", map[string]any{"iat": now + 120}),
		"nbf in the future":             idToken(t, k, "k1", map[string]any{"nbf": now + 120}),
		"no iat":                        idToken(t, k, "k1", map[string]any{"iat": nil}),
		"sub not a string":              idToken(t, k, "k1", map[string]any{"sub": 7}),
		"wrong issuer":                  idToken(t, k, "k1", map[string]any{"iss": iss + "/"}),
		"kid not found":                 idToken(t, k, "k2", nil),
		"no kid":                        sign(t, base, k, nil),
		"kid not a string":              sign(t, base, k, map[string]any{"kid": 1}),
		"crit header":                   sign(t, base, k, map[string]any{"kid": "k1", "crit": []string{"exp"}}),
		"a person not in allowed":       idToken(t, k, "k1", map[string]any{"email": "eve@example.com"}),
		"email not verified":            idToken(t, k, "k1", map[string]any{"email_verified": false}),
		"truncated":                     idToken(t, k, "k1", nil)[:100],
		"four segments":                 idToken(t, k, "k1", nil) + ".x",
		"tampered payload": func() string {
			p := strings.Split(idToken(t, k, "k1", nil), ".")
			p[1] = enc(claimsWith(map[string]any{"email": "alice@example.com", "exp": now + 99999}))
			return strings.Join(p, ".")
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			a, _ := oidcFixture(t)
			_, err := a.Authenticate(bg, tok)
			mustRefuse(t, err, "")
		})
	}
	// Inside the leeway an expired token still passes, as PyJWT's leeway=30.
	a, _ := oidcFixture(t)
	if _, err := a.Authenticate(bg, idToken(t, k, "k1", map[string]any{"exp": now - 10})); err != nil {
		t.Fatalf("inside the leeway: %v", err)
	}
	if _, err := a.Authenticate(bg, idToken(t, k, "k1", map[string]any{"aud": []string{"x", aud}})); err != nil {
		t.Fatalf("aud list naming us: %v", err)
	}
}

func TestES256IsAccepted(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a := NewOIDCAuthenticator(iss, aud, staticJWKS(nil, jwksDoc(jwkOf(&ec.PublicKey, "e1"))), []string{"alice@*"})
	p, err := a.Authenticate(bg, idToken(t, ec, "e1", nil))
	if err != nil || p.ID != "user:alice@example.com" {
		t.Fatalf("%+v %v", p, err)
	}
	// GitHub Actions is RS256 only.
	g := NewGitHubActionsAuthenticator("clearance", staticJWKS(nil, jwksDoc(jwkOf(&ec.PublicKey, "k1"))), nil)
	_, err = g.Authenticate(bg, ghToken(t, ec, nil))
	mustRefuse(t, err, "")
}

func TestJWKSSkipsUnusableKeysAndFailsClosed(t *testing.T) {
	k, _ := keys(t)
	doc := jwksDoc(map[string]any{"kty": "OKP", "kid": "o", "crv": "Ed25519", "x": "AA"},
		map[string]any{"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"},
		jwkOf(&k.PublicKey, "k1"))
	j := staticJWKS(nil, doc)
	if _, err := j.Key(bg, "k1"); err != nil {
		t.Fatal(err)
	}
	for _, kid := range []string{"o", "enc"} {
		if _, err := j.Key(bg, kid); err == nil {
			t.Fatalf("kid %s usable", kid)
		}
	}
	down := &JWKS{URL: "x", MinRefresh: time.Minute, Fetch: func(context.Context, string) ([]byte, error) { return nil, errors.New("down") }}
	_, err := down.Key(bg, "k1")
	mustRefuse(t, err, "unavailable")
	garbage := staticJWKS(nil, []byte("<html>"))
	_, err = garbage.Key(bg, "k1")
	mustRefuse(t, err, "unavailable")
}
