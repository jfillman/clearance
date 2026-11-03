package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMiddleware(t *testing.T) {
	a := AuthenticatorFunc(func(_ context.Context, tok string) (Principal, error) {
		if tok == "good" {
			return Principal{ID: "user:alice", Kind: KindPerson}, nil
		}
		return Principal{}, refuse("no")
	})
	skip := func(r *http.Request) bool {
		return r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/v1/github/webhook"
	}
	h := Middleware(a, skip)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := From(r.Context())
		if ok {
			_, _ = w.Write([]byte(p.ID))
		} else {
			_, _ = w.Write([]byte("anonymous"))
		}
	}))
	for _, c := range []struct {
		path, authz string
		code        int
		body        string
	}{
		{"/v1/x", "Bearer good", 200, "user:alice"},
		{"/v1/x", "bearer   good  ", 200, "user:alice"},
		{"/v1/x", "BEARER good", 200, "user:alice"},
		{"/v1/x", "", 401, `{"error":"a bearer token is required"}`},
		{"/v1/x", "Bearer ", 401, `{"error":"a bearer token is required"}`},
		{"/v1/x", "Bearer    ", 401, `{"error":"a bearer token is required"}`},
		{"/v1/x", "Basic Z29vZA==", 401, `{"error":"a bearer token is required"}`},
		{"/v1/x", "Bearer bad", 401, `{"error":"token not accepted"}`},
		{"/healthz", "", 200, "anonymous"},
		{"/readyz", "Bearer bad", 200, "anonymous"},
		{"/v1/github/webhook", "", 200, "anonymous"},
	} {
		r := httptest.NewRequest("GET", c.path, nil)
		if c.authz != "" {
			r.Header.Set("Authorization", c.authz)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.code || strings.TrimSpace(w.Body.String()) != c.body {
			t.Errorf("%s %q: %d %s, want %d %s", c.path, c.authz, w.Code, w.Body, c.code, c.body)
		}
		if c.code == 401 && w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("401 content type %q", w.Header().Get("Content-Type"))
		}
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestFromEnv(t *testing.T) {
	a, err := FromEnv(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	c := a.(*CachingAuthenticator)
	r := c.Inner.(*RoutingAuthenticator)
	if len(r.ByIssuer) != 0 || r.Workload.(*WorkloadAuthenticator).Audience != "clearance" {
		t.Fatalf("bare env: %+v", r)
	}
	if c.TTL.Seconds() != 60 || c.MaxEntries != 4096 {
		t.Fatalf("cache %v %d", c.TTL, c.MaxEntries)
	}

	a, err = FromEnv(env(map[string]string{
		"CLEARANCE_AUDIENCE":    "core",
		"CLEARANCE_OIDC_ISSUER": "https://dex.example/dex/", "CLEARANCE_OIDC_AUDIENCE": "clearance-people",
		"CLEARANCE_OIDC_ALLOWED_USERS": " alice@example.com, ,*@corp.example ", "CLEARANCE_OIDC_USER_CLAIM": "preferred_username",
		"CLEARANCE_FOREIGN_ISSUER": "https://hangarplatform.dev/oidc/hangar-prod/", "CLEARANCE_FOREIGN_CLUSTER": "hangar-prod",
		"CLEARANCE_FOREIGN_SERVICE_ACCOUNTS": "app-backstage-prod/backstage",
		"CLEARANCE_GITHUB_OIDC_AUDIENCE":     "clearance-gh", "CLEARANCE_GITHUB_OIDC_ALLOWED": "repo:jfillman/*",
	}))
	if err != nil {
		t.Fatal(err)
	}
	r = a.(*CachingAuthenticator).Inner.(*RoutingAuthenticator)
	o := r.ByIssuer["https://dex.example/dex"].(*OIDCAuthenticator)
	if o.Audience != "clearance-people" || o.Keys.URL != "https://dex.example/dex/keys" || o.UserClaim != "preferred_username" ||
		strings.Join(o.Allowed, "|") != "alice@example.com|*@corp.example" {
		t.Fatalf("oidc %+v", o)
	}
	f := r.ByIssuer["https://hangarplatform.dev/oidc/hangar-prod"].(*ForeignWorkloadAuthenticator)
	if f.Name != "hangar-prod" || f.Audience != "core" || f.Keys.URL != "https://hangarplatform.dev/oidc/hangar-prod/jwks.json" {
		t.Fatalf("tower %+v", f)
	}
	g := r.ByIssuer[GitHubActionsIssuer].(*GitHubActionsAuthenticator)
	if g.Audience != "clearance-gh" || strings.Join(g.Allowed, "|") != "repo:jfillman/*" || g.Keys.URL != GitHubActionsJWKS {
		t.Fatalf("github %+v", g)
	}
	if r.Workload.(*WorkloadAuthenticator).Audience != "core" {
		t.Fatal("workload audience")
	}

	a, _ = FromEnv(env(map[string]string{"CLEARANCE_GITHUB_OIDC_AUDIENCE": "x", "CLEARANCE_OIDC_ISSUER": "https://i", "CLEARANCE_OIDC_AUDIENCE": "a",
		"CLEARANCE_OIDC_ALLOWED_USERS": "*", "CLEARANCE_OIDC_JWKS_URL": "https://i/jwks"}))
	r = a.(*CachingAuthenticator).Inner.(*RoutingAuthenticator)
	if strings.Join(r.ByIssuer[GitHubActionsIssuer].(*GitHubActionsAuthenticator).Allowed, "|") != "repo:*" {
		t.Fatal("github allowed default")
	}
	if r.ByIssuer["https://i"].(*OIDCAuthenticator).Keys.URL != "https://i/jwks" {
		t.Fatal("jwks url override")
	}

	for name, bad := range map[string]map[string]string{
		"issuer without audience": {"CLEARANCE_OIDC_ISSUER": "https://i", "CLEARANCE_OIDC_ALLOWED_USERS": "*"},
		"audience without issuer": {"CLEARANCE_OIDC_AUDIENCE": "a"},
		"issuer without allowed":  {"CLEARANCE_OIDC_ISSUER": "https://i", "CLEARANCE_OIDC_AUDIENCE": "a"},
		"blank allowed":           {"CLEARANCE_OIDC_ISSUER": "https://i", "CLEARANCE_OIDC_AUDIENCE": "a", "CLEARANCE_OIDC_ALLOWED_USERS": " , "},
		"tower without cluster":   {"CLEARANCE_FOREIGN_ISSUER": "https://t", "CLEARANCE_FOREIGN_SERVICE_ACCOUNTS": "a/b"},
		"tower without sas":       {"CLEARANCE_FOREIGN_ISSUER": "https://t", "CLEARANCE_FOREIGN_CLUSTER": "c"},
	} {
		if _, err := FromEnv(env(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// FuzzParseJWT: arbitrary tokens through the parser and the routing and verifying path never panic, and nothing
// that is not a well-formed JWS gets through.
func FuzzParseJWT(f *testing.F) {
	k, _ := keys(f)
	f.Add(idToken(f, k, "k1", nil))
	f.Add(sign(f, claimsWith(nil), nil, nil))
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJub25lIn0.eyJpc3MiOiJ4In0.")
	f.Add("....")
	f.Add("")
	oidc := NewOIDCAuthenticator(iss, aud, staticJWKS(nil, jwksDoc(jwkOf(&k.PublicKey, "k1"))), []string{"*"})
	r := &RoutingAuthenticator{ByIssuer: map[string]Authenticator{iss: oidc}}
	f.Fuzz(func(t *testing.T, tok string) {
		j, err := ParseJWT(tok)
		if err == nil && (j.Header == nil || j.Claims == nil || strings.Count(tok, ".") != 2) {
			t.Fatalf("parsed %q into %+v", tok, j)
		}
		p, err := r.Authenticate(context.Background(), tok)
		if err == nil && p.ID == "" {
			t.Fatal("empty principal accepted")
		}
	})
}
