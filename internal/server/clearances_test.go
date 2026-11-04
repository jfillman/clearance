package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/token"
)

// signer is a throwaway key, per test.
func signer(t testing.TB) *token.KeySigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := token.NewKeySigner(k)
	return s
}

func tokenFixture(t *testing.T) (*fixture, *token.KeySigner) {
	cfg := config(t, "")
	s := signer(t)
	cfg.Signer, cfg.TokenIssuer, cfg.TokenTTL = s, "clearance", 15*time.Minute
	return newFixture(t, cfg), s
}

func (f *fixture) keySet(t *testing.T) token.KeySet {
	t.Helper()
	res, err := http.Get(f.srv.URL + "/v1/keys") // no token: the key set is public
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || res.Header.Get("Cache-Control") == "" {
		t.Fatalf("GET /v1/keys: %d %s", res.StatusCode, raw)
	}
	ks, err := token.ParseJWKS(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestTheCoreServesAClearanceAndItsToken(t *testing.T) {
	f, s := tokenFixture(t)
	id := f.do("POST", "/v1/clearances", ci, change("pass")).want(t, 200, "").body["id"].(string) // tier 1, cleared by policy
	ks := f.keySet(t)
	if _, ok := ks[s.KeyID()]; !ok || len(ks) != 1 {
		t.Fatalf("keys %v", ks)
	}
	for _, who := range []string{ci, argo, gw} { // the registering verifier, and registered providers
		a := f.do("GET", "/v1/clearances/"+id, who, nil).want(t, 200, "")
		if a.body["state"] != "cleared" || a.body["cluster"] != "hangar-prod" || a.body["token"] == nil {
			t.Fatalf("%s: %v", who, a.body)
		}
		tok := a.body["token"].(map[string]any)
		env, _ := json.Marshal(tok["dsse"])
		o := token.Options{Issuer: "clearance", Expect: token.Expect{ClearanceID: id, TreeRoot: strings.Repeat("c", 64),
			Cluster: "hangar-prod"}, Nonces: f.core.Gate}
		c, err := token.Verify(context.Background(), env, ks, o)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := token.VerifyJWT(context.Background(), tok["jwt"].(string), ks, o); err != nil {
			t.Fatal(err)
		}
		if c.Nonce != tok["nonce"] || tok["key_id"] != s.KeyID() {
			t.Fatalf("%v vs %+v", tok, c)
		}
	}
	f.do("GET", "/v1/clearances/"+id, "user:erin", nil).want(t, 403, "neither a registered provider")
	f.do("GET", "/v1/clearances/"+id, "app-other-cicd/pipeline-runner", nil).want(t, 403, "")
	f.do("GET", "/v1/clearances/ch-nope", ci, nil).want(t, 404, "no such change")
	// A holding change has no token yet.
	held := f.do("POST", "/v1/clearances", ci, func() map[string]any {
		c := change("pending")
		c["head"] = strings.Repeat("e", 40)
		return c
	}()).want(t, 200, "").body["id"].(string)
	a := f.do("GET", "/v1/clearances/"+held, argo, nil).want(t, 200, "")
	if a.body["state"] != "holding" || a.body["token"] != nil {
		t.Fatal(a.body)
	}
	// ... and the new head revoked the first change's token.
	if a := f.do("GET", "/v1/clearances/"+id, argo, nil).want(t, 200, ""); a.body["token"] != nil {
		t.Fatal("a superseded token is still served", a.body)
	}
	if ok, bad := evidence.Verify(f.records()); !ok {
		t.Fatalf("the chain breaks at %d", bad)
	}
}

func TestACoreWithoutAKeyIssuesNoTokens(t *testing.T) {
	f := memFixture(t)
	id := f.do("POST", "/v1/clearances", ci, change("pass")).want(t, 200, "").body["id"].(string)
	if a := f.do("GET", "/v1/clearances/"+id, ci, nil).want(t, 200, ""); a.body["state"] != "cleared" || a.body["token"] != nil {
		t.Fatal(a.body)
	}
	if ks := f.keySet(t); len(ks) != 0 {
		t.Fatal(ks)
	}
}

func TestARestartWithANewKeyPublishesBoth(t *testing.T) {
	dsn := pgDSN(t)
	cfg := config(t, dsn)
	s1 := signer(t)
	cfg.Signer, cfg.TokenTTL = s1, 15*time.Minute
	f := newFixture(t, cfg)
	id := f.do("POST", "/v1/clearances", ci, change("pass")).want(t, 200, "").body["id"].(string)
	f.core.Close()
	s2 := signer(t)
	cfg.Signer = s2
	f2 := newFixture(t, cfg)
	ks := f2.keySet(t)
	if _, ok := ks[s1.KeyID()]; !ok || len(ks) != 2 {
		t.Fatal("the retired key is not published for its tokens' lifetime", ks)
	}
	// The core's read re-signs a token signed by a key it no longer uses.
	tok := f2.do("GET", "/v1/clearances/"+id, ci, nil).want(t, 200, "").body["token"].(map[string]any)
	if tok["key_id"] != s2.KeyID() {
		t.Fatal(tok["key_id"])
	}
}

func TestTheSigningKeyAndTTLConfiguration(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	if _, err := core.FromEnv(env(map[string]string{"CLEARANCE_SIGNING_KMS": "awskms:///alias/clearance"})); err == nil ||
		!strings.Contains(err.Error(), "not built") {
		t.Fatal(err)
	}
	if _, err := core.FromEnv(env(map[string]string{"CLEARANCE_SIGNING_KEY_FILE": "/nonexistent/key.pem"})); err == nil {
		t.Fatal("a missing key file starts")
	}
	for v, ok := range map[string]bool{"": true, "15m": true, "1h": true, "30s": false, "25h": false, "3m": false, "x": false} {
		_, err := core.ParseTokenTTL(v, time.Minute)
		if (err == nil) != ok {
			t.Errorf("%q: %v", v, err)
		}
	}
}

func TestAProvidersConformanceIsStampedOnItsRecords(t *testing.T) {
	ps, err := server.ParseProviders(`[{"name": "argo-gate", "version": "0.1.0", "principals": ["hangar-prod/argocd/*"],
	  "conformance": "clearance-conformance/v1@2026-11-03"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if w := ps[0].Writer(); w.Provider.Conformance != "clearance-conformance/v1@2026-11-03" {
		t.Fatal(w)
	}
	for _, bad := range []string{"v1", "clearance-conformance/1", "clearance-conformance/v1@yesterday", "Clearance/v1"} {
		if _, err := server.ParseProviders(`[{"name": "p", "version": "1", "principals": ["x"], "conformance": "` + bad + `"}]`); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	cfg := config(t, "")
	cfg.Providers = ps
	f := newFixture(t, cfg)
	f.do("POST", "/v1/records", argo, map[string]any{"provider": "argo-gate", "kind": "deploy.outcome",
		"record": map[string]any{"app": "gate-api", "target": "jfillman/gitops-gate-api@aaaaaaa", "outcome": map[string]any{"synced": true}}}).
		want(t, 200, "")
	recs := f.records()
	p := recs[len(recs)-1]["provider"].(map[string]any)
	if p["name"] != "argo-gate" || p["conformance"] != "clearance-conformance/v1@2026-11-03" {
		t.Fatal(p)
	}
	if ok, bad := evidence.Verify(recs); !ok {
		t.Fatalf("the chain breaks at %d", bad)
	}
}
