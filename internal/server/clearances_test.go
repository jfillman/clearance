package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/api"
	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store/pg"
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

// waitCall is GET .../wait from a goroutine: its status and body arrive on the channel.
func (f *fixture) waitCall(path, who string) <-chan answer {
	out := make(chan answer, 1)
	go func() {
		req, _ := http.NewRequest("GET", f.srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+who)
		resp, err := f.srv.Client().Do(req)
		if err != nil {
			out <- answer{status: -1}
			return
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		a := answer{status: resp.StatusCode}
		_ = json.Unmarshal(raw, &a.body)
		out <- a
	}()
	return out
}

func TestTheWaitRouteAnswersOnTheWrite(t *testing.T) {
	f, _ := tokenFixture(t)
	pending := change("pending")
	held := f.do("POST", "/v1/clearances", ci, pending).want(t, 200, "").body["id"].(string)
	// A state other than the one given answers at once.
	a := f.do("GET", "/v1/clearances/"+held+"/wait?state=cleared&timeout=5", argo, nil).want(t, 200, "")
	if a.body["state"] != "holding" || a.body["changed"] != true {
		t.Fatal(a.body)
	}
	// Nothing written: the timeout, changed false.
	t0 := time.Now()
	a = f.do("GET", "/v1/clearances/"+held+"/wait?timeout=1", argo, nil).want(t, 200, "")
	if a.body["state"] != "holding" || a.body["changed"] != false || time.Since(t0) < time.Second {
		t.Fatal(a.body, time.Since(t0))
	}
	// The check passes (the verifier re-registers the same head): the waiter wakes with the token, long before
	// its timeout.
	ch := f.waitCall("/v1/clearances/"+held+"/wait?state=holding&timeout=30", argo)
	deadline := time.Now().Add(5 * time.Second)
	for f.core.Gate.Waiting() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	t1 := time.Now()
	f.do("POST", "/v1/clearances", ci, change("pass")).want(t, 200, "")
	select {
	case a = <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("the waiter did not wake")
	}
	if a.status != 200 || a.body["state"] != "cleared" || a.body["changed"] != true || a.body["token"] == nil ||
		time.Since(t1) > 5*time.Second {
		t.Fatal(a.status, a.body)
	}
	if f.core.Gate.Waiting() != 0 {
		t.Fatal("a watch leaked", f.core.Gate.Waiting())
	}
	// The same callers as getClearance; bad parameters are 400.
	f.do("GET", "/v1/clearances/"+held+"/wait?timeout=1", "user:erin", nil).want(t, 403, "neither a registered provider")
	f.do("GET", "/v1/clearances/ch-nope/wait?timeout=1", ci, nil).want(t, 404, "no such change")
	for _, q := range []string{"timeout=0", "timeout=61", "timeout=x", "other=1", "timeout=1&timeout=2"} {
		f.do("GET", "/v1/clearances/"+held+"/wait?"+q, argo, nil).want(t, 400, "")
	}
}

func TestTheWaitRouteThroughTheRealServer(t *testing.T) {
	// Through the core's own http.Server (HTTPServer, with every timeout set), not only the handler: the route's
	// deadline changes (no read deadline, a write deadline past the wait) are accepted by the connection.
	f, _ := tokenFixture(t)
	held := f.do("POST", "/v1/clearances", ci, change("pending")).want(t, 200, "").body["id"].(string)
	hs := f.core.Server.HTTPServer("127.0.0.1:0")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/v1/clearances/"+held+"/wait?timeout=2", nil)
	req.Header.Set("Authorization", "Bearer "+argo)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != 200 || body["changed"] != false {
		t.Fatal(resp.StatusCode, body)
	}
}

// The seam end to end, on one Postgres: the core signs the grant feed in the clearing transaction, clearance-api (a
// read-only process with no key) serves it, and a reader verifies it with the keys clearance-api publishes.
func TestTheCoreSignsTheGrantFeedAndClearanceAPIServesIt(t *testing.T) {
	dsn := pgDSN(t)
	cfg := config(t, dsn)
	s := signer(t)
	cfg.Signer, cfg.TokenIssuer, cfg.TokenTTL = s, "clearance", 15*time.Minute
	f := newFixture(t, cfg)
	id := f.do("POST", "/v1/clearances", ci, change("pass")).want(t, 200, "").body["id"].(string)

	rd, err := pg.OpenReader(context.Background(), dsn, pg.Options{MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rd.Close)
	auth := authn.AuthenticatorFunc(func(_ context.Context, tok string) (authn.Principal, error) {
		return authn.Principal{ID: tok, Kind: authn.KindForeignWorkload}, nil
	})
	srv, err := api.New(api.Options{Store: &api.PG{R: rd}, Auth: auth, Log: quiet,
		Access: &api.Access{FeedReaders: []api.FeedReader{{Principal: "hangar-prod/clearance-system/*", Cluster: "hangar-prod"}}}})
	if err != nil {
		t.Fatal(err)
	}
	get := func(path, who string) (int, []byte) {
		req := httptest.NewRequest("GET", path, nil)
		if who != "" {
			req.Header.Set("Authorization", "Bearer "+who)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes()
	}
	code, rawKeys := get("/v1/keys", "")
	ks, err := token.ParseJWKS(rawKeys)
	if code != 200 || err != nil {
		t.Fatal(code, err)
	}
	code, raw := get("/v1/grant-feeds/hangar-prod", "hangar-prod/clearance-system/grant-sync")
	if code != 200 {
		t.Fatalf("%d %s", code, raw)
	}
	var feed api.GrantFeed
	if err := json.Unmarshal(raw, &feed); err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(feed.Feed)
	fd, err := token.VerifyFeed(env, ks, token.FeedOptions{Issuer: "clearance", Cluster: "hangar-prod"})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]token.Envelope{}
	for _, tk := range feed.Tokens {
		byID[tk.ChangeID] = tk.DSSE
		tokRaw, _ := json.Marshal(tk.DSSE)
		if _, err := token.Verify(context.Background(), tokRaw, ks, token.Options{Issuer: "clearance",
			Expect: token.Expect{Cluster: "hangar-prod"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := fd.Match(byID); err != nil || len(fd.Entries) != 1 || fd.Entries[0].ChangeID != id || fd.RecordsSeq < 0 {
		t.Fatalf("%+v %v", fd, err)
	}
	// A new head revokes it: the next feed (a higher seq) is empty.
	held := change("pending")
	held["head"] = strings.Repeat("e", 40)
	f.do("POST", "/v1/clearances", ci, held).want(t, 200, "")
	_, raw = get("/v1/grant-feeds/hangar-prod", "hangar-prod/clearance-system/grant-sync")
	_ = json.Unmarshal(raw, &feed)
	env, _ = json.Marshal(feed.Feed)
	if fd2, err := token.VerifyFeed(env, ks, token.FeedOptions{Issuer: "clearance", Cluster: "hangar-prod",
		MinSeq: fd.Seq + 1}); err != nil || len(fd2.Entries) != 0 || len(feed.Tokens) != 0 {
		t.Fatalf("%+v %v", fd2, err)
	}
}

// G-TF-2 on the whole core: a terraform-plan change waits on C-10's wait route like any other, wakes cleared with
// a token bound to the plan digest, and takes one outcome from its registrant.
func TestAPlanWaitsClearsAndReportsItsOutcome(t *testing.T) {
	f, _ := tokenFixture(t)
	digest := strings.Repeat("e6", 32)
	planChange := func(ciCheck string) map[string]any {
		return map[string]any{"app": "network", "env": "lab", "repo": "jfillman/hangar-infra", "pr": 0, "head": headSHA,
			"proposer": "user:dana", "owner": owner, "paths": []string{"network/lab/main.tf"},
			"checks": map[string]any{"ci": ciCheck, "provenance": "not-agent"},
			"subject": map[string]any{"kind": "terraform-plan", "planDigest": digest, "planJsonDigest": strings.Repeat("4f", 32),
				"variableSetDigest": strings.Repeat("1c", 32),
				"workspace":         map[string]any{"backend": "s3", "key": "network/lab/terraform.tfstate", "name": "default"},
				"versions":          map[string]any{"terraform": "1.9.8", "providers": map[string]any{}},
				"summary":           map[string]any{"create": 0, "update": 1, "replace": 0, "destroy": 0, "destroyedAddresses": []any{}},
				"resources": []any{map[string]any{"address": "aws_vpc.lab", "type": "aws_vpc", "actions": []any{"update"},
					"fields": []any{"/tags/Owner"}}}}}
	}
	reg := f.do("POST", "/v1/clearances", ci, planChange("pending")).want(t, 200, "")
	id := reg.body["id"].(string)
	if reg.body["state"] != "holding" {
		t.Fatal(reg.body)
	}
	if exp, _ := time.Parse(time.RFC3339, reg.body["expires_at"].(string)); exp.Sub(time.Now()) > 24*time.Hour {
		t.Fatalf("a plan holds until %v", exp)
	}
	ch := f.waitCall("/v1/clearances/"+id+"/wait?state=holding&timeout=30", ci)
	deadline := time.Now().Add(5 * time.Second)
	for f.core.Gate.Waiting() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// The same plan registered again, its checks green now: the same change, cleared by policy.
	if again := f.do("POST", "/v1/clearances", ci, planChange("pass")).want(t, 200, ""); again.body["id"] != id {
		t.Fatal(again.body["id"], id)
	}
	var a answer
	select {
	case a = <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("the waiter did not wake")
	}
	if a.status != 200 || a.body["state"] != "cleared" || a.body["changed"] != true || a.body["token"] == nil {
		t.Fatal(a.status, a.body)
	}
	tok := a.body["token"].(map[string]any)
	env, _ := json.Marshal(tok["dsse"])
	o := token.Options{Issuer: "clearance", Expect: token.Expect{ClearanceID: id, PlanDigest: digest}}
	claims, err := token.Verify(context.Background(), env, f.keySet(t), o)
	if err != nil || claims.Subjects.Kind != "terraform-plan" || claims.Subjects.PlanDigest != digest {
		t.Fatal(claims, err)
	}
	o.Expect.PlanDigest = strings.Repeat("0a", 32)
	if _, err := token.Verify(context.Background(), env, f.keySet(t), o); err == nil {
		t.Fatal("the token verified for another plan")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	out := map[string]any{"applied": true, "planDigest": "sha256:" + digest, "startedAt": now, "finishedAt": now,
		"changes": []any{map[string]any{"address": "aws_vpc.lab", "action": "update", "status": "complete"}}}
	f.do("POST", "/v1/clearances/"+id+"/outcome", argo, out).want(t, 403, "did not register")
	got := f.do("POST", "/v1/clearances/"+id+"/outcome", ci, out).want(t, 200, "")
	if got.body["matched"] != true || got.body["exception_seq"] != nil {
		t.Fatal(got.body)
	}
	f.do("POST", "/v1/clearances/"+id+"/outcome", ci, out).want(t, 409, "already recorded")
	if ok, bad := evidence.Verify(f.records()); !ok {
		t.Fatalf("the chain breaks at %d", bad)
	}
}
