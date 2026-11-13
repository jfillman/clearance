package client_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/token"
)

const (
	gw      = "autopilot-system/clearance"
	ci      = "app-gate-api-cicd/pipeline-runner"
	owner   = "group:default/team-gate"
	headSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

const providersJSON = `[{"name": "autopilot-gateway", "version": "0.3.27", "principals": ["autopilot-system/clearance"]},
 {"name": "targets-prod", "version": "0.1.0", "principals": ["hangar-prod/gitops/targets"], "targets": ["hangar-prod"]}]`

type groups map[string][]string

func (g groups) Groups(_ context.Context, p string) []string { return g[p] }

// coreServer is a whole core (internal/core.Build, in-memory store, dev auth) behind httptest.
func coreServer(t *testing.T) (*core.Core, *httptest.Server) {
	t.Helper()
	ps, err := server.ParseProviders(providersJSON)
	if err != nil {
		t.Fatal(err)
	}
	cfg := core.Config{Memory: true, Version: "test", Providers: ps, Auth: core.DevAuthenticator(), MaxClockSkew: -1,
		AgentLogins: []string{vocabtest.AgentLogin}}
	cfg.Gate.Verifiers = []string{"app-*-cicd/pipeline-runner"}
	cfg.Gate.Admins = []string{"user:admin"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // a throwaway signing key, this test's only
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Signer, err = token.NewKeySigner(key); err != nil {
		t.Fatal(err)
	}
	c, err := core.Build(context.Background(), cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	c.Gate.Directory = groups{"user:dana": {owner}, "user:erin": {owner}}
	srv := httptest.NewServer(c.Server.Handler())
	t.Cleanup(srv.Close)
	return c, srv
}

func newClient(t *testing.T, base, token string, edit ...func(*client.Options)) *client.Client {
	t.Helper()
	opt := client.Options{BaseURL: base, Provider: "autopilot-gateway"}
	if token != "" {
		opt.Token = client.StaticToken(token)
	}
	for _, e := range edit {
		e(&opt)
	}
	c, err := client.New(opt)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// corpus line n's request (testdata/golden/corpus.jsonl), strictly decoded into the client's type: the client's
// types carry every request the Python engine decided.
func corpusRequest(t *testing.T, n int) *client.EvaluationRequest {
	t.Helper()
	fh, err := os.Open("../testdata/golden/corpus.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(nil, 64<<20)
	for i := 0; sc.Scan(); i++ {
		if i != n {
			continue
		}
		var line struct {
			Request json.RawMessage `json:"request"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(line.Request))
		dec.DisallowUnknownFields()
		var req client.EvaluationRequest
		if err := dec.Decode(&req); err != nil {
			t.Fatalf("corpus line %d does not decode into client.EvaluationRequest: %v", n, err)
		}
		return &req
	}
	t.Fatalf("corpus line %d missing", n)
	return nil
}

const (
	prOpenAllowed = 210 // repo.pr.open allowed
	prOpenDenied  = 218 // repo.pr.open denied R008
)

// -- against the real core ---------------------------------------------------------------------------------------

func TestEvaluateOutcomeAndRecordAgainstTheCore(t *testing.T) {
	cr, srv := coreServer(t)
	c := newClient(t, srv.URL, gw)
	ctx := context.Background()

	allow, err := c.Evaluate(ctx, corpusRequest(t, prOpenAllowed))
	if err != nil || !allow.Decision || allow.DecisionID == nil || *allow.DecisionID != "0" || allow.Record == nil {
		t.Fatalf("%+v %v", allow, err)
	}
	if allow.Context.Spend.GithubCalls != 4 || allow.Context.Policy.Bundle != "clearance-core" {
		t.Fatalf("%+v", allow.Context)
	}
	deny, err := c.Evaluate(ctx, corpusRequest(t, prOpenDenied))
	if err != nil || deny.Decision || deny.Context.Rule != "R008" || deny.Context.Hint == "" {
		t.Fatalf("a deny is a result: %+v %v", deny, err)
	}

	ref, err := c.Outcome(ctx, *allow.DecisionID, &client.OutcomeRequest{Result: "ok",
		Effect:  &client.Effect{Repo: "jfillman/gate-api", PR: 32, Commit: headSHA, Branch: "agent/fix", Paths: []string{"app.js"}},
		Receipt: map[string]any{"id": "pr-32"}})
	if err != nil || ref.Seq != 2 || len(ref.Hash) != 64 {
		t.Fatalf("%+v %v", ref, err)
	}
	var api *client.APIError
	if _, err := c.Outcome(ctx, *allow.DecisionID, &client.OutcomeRequest{Result: "ok"}); !errors.As(err, &api) || api.Status != 409 {
		t.Fatalf("a second outcome: %v", err)
	}
	if _, err := c.Outcome(ctx, *deny.DecisionID, &client.OutcomeRequest{Result: "ok"}); !errors.As(err, &api) || api.Status != 409 {
		t.Fatalf("an outcome of a deny: %v", err)
	}
	if _, err := c.Outcome(ctx, "", &client.OutcomeRequest{Result: "ok"}); err == nil {
		t.Fatal("an empty decision id was sent")
	}

	rec, err := c.Record(ctx, &client.RecordRequest{Kind: "session.open", Record: client.ProviderEvent{
		Session: client.String("s-1"), TaskID: client.String("t-1"), Principal: client.String("user:alice"),
		Agent: client.String("coding-agent"), Result: client.String("opened")}})
	if err != nil || rec.Seq != 3 {
		t.Fatalf("%+v %v", rec, err)
	}
	stored, err := cr.Store.Records(ctx, 3, 1)
	if err != nil || len(stored) != 1 || stored[0]["tool"] != "session.open" ||
		stored[0]["provider"].(map[string]any)["name"] != "autopilot-gateway" {
		t.Fatalf("%v %v", stored, err)
	}
	if _, err := c.Record(ctx, &client.RecordRequest{Kind: "run.anything"}); !errors.As(err, &api) || api.Status != 400 {
		t.Fatalf("a bad kind: %v", err)
	}

	// Provenance finds the outcome's receipt.
	v, err := newClient(t, srv.URL, ci).Provenance(ctx, &client.ProvenanceRequest{Repo: "jfillman/gate-api", PR: 32,
		Head: headSHA, Paths: []string{"app.js"}, Author: vocabtest.AgentLogin})
	if err != nil || !v.AgentPR || v.Record == nil || v.AuditSeq == nil {
		t.Fatalf("%+v %v", v, err)
	}
	if c.BreakerState() != client.BreakerClosed {
		t.Fatal(c.BreakerState())
	}
}

func TestPublishTargetsAgainstTheCore(t *testing.T) {
	_, srv := coreServer(t)
	c := newClient(t, srv.URL, "hangar-prod/gitops/targets")
	ctx := context.Background()
	req := &client.TargetsRequest{Targets: []client.Target{{ID: "gate-api-prod", Name: "gate-api", Kind: "k8s-namespace", Group: "hangar-prod",
		Env: "prod", App: "gate-api", Scope: "hangar-prod", Gates: []client.TargetGate{{Type: "glidepath", Instance: "gate-api-cicd", Mode: "enforce"}}}}}
	a, err := c.PublishTargets(ctx, "hangar-prod", req)
	if err != nil || !a.Changed || a.Targets != 1 || len(a.Digest) != 64 || a.Seq == nil || a.Source != "hangar-prod" {
		t.Fatalf("%+v %v", a, err)
	}
	b, err := c.PublishTargets(ctx, "hangar-prod", req) // nil observers are sent as []
	if err != nil || b.Changed || b.Digest != a.Digest || b.Seq != nil {
		t.Fatalf("the same set changes nothing: %+v %v", b, err)
	}
	if w, err := c.PublishTargets(ctx, "hangar-prod", &client.TargetsRequest{}); err != nil || !w.Changed || w.Targets != 0 {
		t.Fatalf("a nil list withdraws: %+v %v", w, err)
	}
	var apiErr *client.APIError
	if _, err := c.PublishTargets(ctx, "hangar-dev", req); !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("another source is refused: %v", err)
	}
}

func TestRefusalsAreAPIErrors(t *testing.T) {
	_, srv := coreServer(t)
	req := corpusRequest(t, prOpenAllowed)
	cases := []struct {
		token  string
		status int
		says   string
	}{
		{"", 401, "bearer token is required"},
		{"someone/else", 403, "not a registered provider"},
		{"user:alice", 403, "not a registered provider"},
	}
	for _, tc := range cases {
		_, err := newClient(t, srv.URL, tc.token).Evaluate(context.Background(), req)
		var api *client.APIError
		if !errors.As(err, &api) || api.Status != tc.status || !strings.Contains(api.Message, tc.says) ||
			errors.Is(err, client.ErrCoreUnavailable) {
			t.Errorf("token %q: %v", tc.token, err)
		}
	}
}

func TestTheGateThroughTheClient(t *testing.T) {
	_, srv := coreServer(t)
	ctx := context.Background()
	verifier := newClient(t, srv.URL, ci)
	change := &client.ChangeRequest{App: "gate-api", Env: "prod", Cluster: "hangar-prod",
		Repo: "jfillman/gitops-gate-api", PR: 7, Head: headSHA, Base: strings.Repeat("b", 40), Proposer: "user:dana",
		ProposerKind: "person", Owner: owner, Protected: true, TreeDigest: strings.Repeat("c", 64),
		Paths: []string{"hangar-prod/prod/release.yaml"}, LinesChanged: 4, Objects: []client.ObjectChange{{
			APIVersion: "argoproj.io/v1alpha1", Kind: "Rollout", Namespace: "app-gate-api-prod", Name: "gate-api",
			Op: "changed", Fields: []string{"/spec/template/spec/containers/0/image"},
			Images: []string{"ghcr.io/jfillman/flight/gate-api@sha256:" + strings.Repeat("e", 64)},
			Digest: strings.Repeat("d", 64)}},
		Checks: map[string]string{"ci": "pending", "provenance": "not-agent", "render": "ok", "admission": "pass"}}
	ch, err := verifier.RegisterChange(ctx, change)
	if err != nil || ch.State != "holding" || !strings.HasPrefix(ch.ID, "ch-") {
		t.Fatalf("%+v %v", ch, err)
	}
	var api *client.APIError
	if _, err := newClient(t, srv.URL, "user:dana").Clear(ctx, ch.ID, ""); !errors.As(err, &api) || api.Status != 403 {
		t.Fatalf("the proposer cleared: %v", err)
	}
	d, err := newClient(t, srv.URL, "user:erin").Clear(ctx, ch.ID, "")
	if err != nil || d.State != "cleared" || d.AuditSeq == 0 || d.ID != ch.ID {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := newClient(t, srv.URL, "user:admin").Deny(ctx, ch.ID, "too late", ""); !errors.As(err, &api) || api.Status != 409 {
		t.Fatalf("a deny after a clear: %v", err)
	}
	// The cleared change's token, verified offline against the published keys.
	got, err := verifier.Clearance(ctx, ch.ID)
	if err != nil || got.State != "cleared" || got.Token == nil || got.Token.JWT == "" {
		t.Fatalf("%+v %v", got, err)
	}
	// The wait route: a state other than the one known answers at once; the same state waits out the timeout.
	if w, err := verifier.Wait(ctx, ch.ID, "holding", 5*time.Second); err != nil || !w.Changed || w.State != "cleared" ||
		w.Token == nil {
		t.Fatalf("wait %+v %v", w, err)
	}
	if w, err := verifier.Wait(ctx, ch.ID, "", time.Second); err != nil || w.Changed || w.State != "cleared" {
		t.Fatalf("wait timeout %+v %v", w, err)
	}
	if _, err := verifier.Wait(ctx, ch.ID, "", 2*time.Minute); err == nil {
		t.Fatal("a wait past MaxWait was sent")
	}
	jwks, err := newClient(t, srv.URL, "").Keys(ctx)
	if err != nil || len(jwks.Keys) != 1 {
		t.Fatalf("%+v %v", jwks, err)
	}
	rawKeys, _ := json.Marshal(jwks)
	ks, err := token.ParseJWKS(rawKeys)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(got.Token.DSSE)
	cl, err := token.Verify(ctx, env, ks, token.Options{Issuer: "clearance", Expect: token.Expect{ClearanceID: ch.ID}})
	if err != nil || len(cl.Approvals) != 1 || cl.Approvals[0].Person != "user:erin" {
		t.Fatalf("%+v %v", cl, err)
	}
	if _, err := newClient(t, srv.URL, "user:erin").Clearance(ctx, ch.ID); !errors.As(err, &api) || api.Status != 403 {
		t.Fatalf("a person read the core's clearance route: %v", err)
	}
	change.Head = strings.Repeat("e", 40)
	ch2, err := verifier.RegisterChange(ctx, change)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := newClient(t, srv.URL, "user:admin").Deny(ctx, ch2.ID, "wrong replica count", "")
	if err != nil || d2.State != "denied" || d2.DenyReason == nil || *d2.DenyReason != "wrong replica count" {
		t.Fatalf("%+v %v", d2, err)
	}
}

func TestProbes(t *testing.T) {
	cr, srv := coreServer(t)
	c := newClient(t, srv.URL, "")
	if h, err := c.Healthz(context.Background()); err != nil || !h.OK {
		t.Fatal(h, err)
	}
	r, err := c.Readyz(context.Background())
	if err != nil || !r.OK || r.Head != -1 || r.Policy.Bundle != "clearance-core" {
		t.Fatal(r, err)
	}
	cr.Store.Close()
	if _, err := c.Readyz(context.Background()); !errors.Is(err, client.ErrCoreUnavailable) {
		t.Fatalf("a not-ready core: %v", err)
	}
}

// -- every error class, against fakes ----------------------------------------------------------------------------

// fake is a server answering each request with handle, counting them.
type fake struct {
	hits atomic.Int64
	srv  *httptest.Server
}

func newFake(t *testing.T, handle func(w http.ResponseWriter, r *http.Request)) *fake {
	f := &fake{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		// Read the body first: the server notices a client hanging up (r.Context ends) only once it has.
		_, _ = io.Copy(io.Discard, r.Body)
		handle(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func status(code int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

const okEval = `{"decision": true, "context": {"message": "allowed", "tier": 1, "spend": {}, "policy": {"bundle": "b", "version": "v"}}, "decision_id": "0", "record": {"seq": 0, "hash": "h"}}`

func evalReq() *client.EvaluationRequest {
	return &client.EvaluationRequest{Subject: client.Subject{Type: "principal", ID: "user:alice"},
		Action:   client.Action{Name: client.ActionToolCall},
		Resource: client.Resource{Type: client.ResourceTool, ID: "catalog.read"},
		Context:  client.Context{Now: time.Now()}}
}

func unavailable(t *testing.T, err error, reason string, attempts int) {
	t.Helper()
	var u *client.UnavailableError
	if !errors.Is(err, client.ErrCoreUnavailable) || !errors.As(err, &u) || u.Reason != reason || u.Attempts != attempts {
		t.Fatalf("want unavailable %s after %d attempts, got %#v", reason, attempts, err)
	}
}

// closedAddr is an address nothing listens on.
func closedAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "http://" + addr
}

func TestConnectionRefusedIsUnavailableAfterOneRetry(t *testing.T) {
	c := newClient(t, closedAddr(t), gw)
	_, err := c.Evaluate(context.Background(), evalReq())
	unavailable(t, err, client.ReasonConnection, 2)
	// A refused dial sent nothing, so even an outcome is retried.
	_, err = c.Outcome(context.Background(), "0", &client.OutcomeRequest{Result: "ok"})
	unavailable(t, err, client.ReasonConnection, 2)
	_, err = newClient(t, closedAddr(t), gw, func(o *client.Options) { o.Retries = -1 }).Evaluate(context.Background(), evalReq())
	unavailable(t, err, client.ReasonConnection, 1)
}

func TestATimeoutIsUnavailableAndHonoured(t *testing.T) {
	release := make(chan struct{})
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	c := newClient(t, f.srv.URL, gw, func(o *client.Options) { o.Timeout = 50 * time.Millisecond })
	start := time.Now()
	_, err := c.Evaluate(context.Background(), evalReq())
	took := time.Since(start)
	unavailable(t, err, client.ReasonTimeout, 2)
	if took < 100*time.Millisecond || took > time.Second {
		t.Fatalf("two 50 ms attempts took %s", took)
	}
	if f.hits.Load() != 2 {
		t.Fatalf("hits %d", f.hits.Load())
	}
	// An outcome that timed out may have been recorded: not retried.
	_, err = c.Outcome(context.Background(), "0", &client.OutcomeRequest{Result: "ok"})
	unavailable(t, err, client.ReasonTimeout, 1)
	// The default is 250 ms per attempt.
	start = time.Now()
	_, err = newClient(t, f.srv.URL, gw, func(o *client.Options) { o.Retries = -1 }).Evaluate(context.Background(), evalReq())
	unavailable(t, err, client.ReasonTimeout, 1)
	if took := time.Since(start); took < 240*time.Millisecond || took > 2*time.Second {
		t.Fatalf("the default timeout took %s", took)
	}
}

func TestServerErrors(t *testing.T) {
	cases := []struct {
		name     string
		code     int
		outcome  bool // call Outcome (retried only when nothing was acted on) instead of Evaluate
		attempts int
	}{
		{"503 evaluate", 503, false, 2},
		{"502 evaluate", 502, false, 2},
		{"504 evaluate", 504, false, 2},
		{"500 evaluate", 500, false, 1},
		{"503 outcome", 503, true, 2},
		{"502 outcome", 502, true, 1},
		{"504 outcome", 504, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, status(tc.code, `{"error": "the decision could not be recorded"}`))
			c := newClient(t, f.srv.URL, gw)
			var err error
			if tc.outcome {
				_, err = c.Outcome(context.Background(), "0", &client.OutcomeRequest{Result: "ok"})
			} else {
				_, err = c.Evaluate(context.Background(), evalReq())
			}
			unavailable(t, err, client.ReasonServerError, tc.attempts)
			var u *client.UnavailableError
			errors.As(err, &u)
			if u.Status != tc.code || !strings.Contains(err.Error(), "could not be recorded") {
				t.Fatal(err)
			}
			if f.hits.Load() != int64(tc.attempts) {
				t.Fatalf("hits %d", f.hits.Load())
			}
		})
	}
	// A 503 then a 200: the retry succeeds.
	var n atomic.Int64
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			status(503, `{"error": "x"}`)(w, r)
			return
		}
		status(200, okEval)(w, r)
	})
	if res, err := newClient(t, f.srv.URL, gw).Evaluate(context.Background(), evalReq()); err != nil || !res.Decision {
		t.Fatal(res, err)
	}
}

func TestClientErrorsAreNotRetriedAndCarryTheGateRule(t *testing.T) {
	f := newFake(t, status(403, `{"error": "not a verifier", "rule": "DG-ROLE", "hint": "ask"}`))
	_, err := newClient(t, f.srv.URL, gw).Clear(context.Background(), "ch-1", "user:dana")
	var api *client.APIError
	if !errors.As(err, &api) || api.Status != 403 || api.Rule != "DG-ROLE" || api.Hint != "ask" ||
		errors.Is(err, client.ErrCoreUnavailable) || f.hits.Load() != 1 {
		t.Fatalf("%v (hits %d)", err, f.hits.Load())
	}
	// A 4xx with no JSON body still is one.
	f2 := newFake(t, status(404, "nope"))
	if _, err := newClient(t, f2.srv.URL, gw).Evaluate(context.Background(), evalReq()); !errors.As(err, &api) || api.Message != "Not Found" {
		t.Fatal(err)
	}
}

func TestUnreadableAnswers(t *testing.T) {
	cases := map[string]func(http.ResponseWriter, *http.Request){
		"not json":       status(200, "not json"),
		"unknown field":  status(200, strings.Replace(okEval, `"decision": true`, `"decision": true, "extra": 1`, 1)),
		"wrong type":     status(200, strings.Replace(okEval, `"decision": true`, `"decision": "yes"`, 1)),
		"trailing data":  status(200, okEval+"{}"),
		"redirect":       func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://example.com/", 302) },
		"over the limit": status(200, okEval+strings.Repeat(" ", 1<<10)),
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, h)
			c := newClient(t, f.srv.URL, gw, func(o *client.Options) { o.MaxResponseBytes = 1 << 10 })
			_, err := c.Evaluate(context.Background(), evalReq())
			if !errors.Is(err, client.ErrBadResponse) || errors.Is(err, client.ErrCoreUnavailable) || f.hits.Load() != 1 {
				t.Fatalf("%v (hits %d)", err, f.hits.Load())
			}
			if c.BreakerState() != client.BreakerClosed {
				t.Fatal("an answer moved the breaker")
			}
		})
	}
	// AllowUnknownFields lets a newer core's extra field through.
	f := newFake(t, cases["unknown field"])
	if res, err := newClient(t, f.srv.URL, gw, func(o *client.Options) { o.AllowUnknownFields = true }).
		Evaluate(context.Background(), evalReq()); err != nil || !res.Decision {
		t.Fatal(res, err)
	}
}

func TestTheTokenIsReadOnEveryRequest(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		status(200, okEval)(w, r)
	})
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, f.srv.URL, "", func(o *client.Options) { o.Token = client.FileToken(path) })
	if _, err := c.Evaluate(context.Background(), evalReq()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Evaluate(context.Background(), evalReq()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "Bearer first,Bearer second" {
		t.Fatal(seen)
	}
	// A failing or malformed token sends nothing and is ErrToken, not unavailable.
	os.Remove(path)
	for _, tok := range []client.TokenSource{client.FileToken(path), client.StaticToken("two words"), client.StaticToken("")} {
		_, err := newClient(t, f.srv.URL, "", func(o *client.Options) { o.Token = tok }).Evaluate(context.Background(), evalReq())
		if !errors.Is(err, client.ErrToken) || errors.Is(err, client.ErrCoreUnavailable) {
			t.Fatal(err)
		}
	}
	if f.hits.Load() != 2 {
		t.Fatalf("hits %d", f.hits.Load())
	}
}

// fakeClock is the breaker's clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestTheBreakerOpensAfterFiveFailuresAndFailsFast(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			status(503, `{"error": "down"}`)(w, r)
			return
		}
		status(200, okEval)(w, r)
	})
	clock := &fakeClock{t: time.Unix(1e9, 0)}
	c := newClient(t, f.srv.URL, gw, func(o *client.Options) { o.Clock = clock.now })
	for i := 0; i < 4; i++ {
		_, err := c.Evaluate(context.Background(), evalReq())
		unavailable(t, err, client.ReasonServerError, 2)
		if c.BreakerState() != client.BreakerClosed {
			t.Fatalf("open after %d failures", i+1)
		}
	}
	_, err := c.Evaluate(context.Background(), evalReq())
	unavailable(t, err, client.ReasonServerError, 2)
	if c.BreakerState() != client.BreakerOpen {
		t.Fatal("not open after 5 failures")
	}
	hits := f.hits.Load()
	start := time.Now()
	for i := 0; i < 100; i++ {
		_, err := c.Evaluate(context.Background(), evalReq())
		unavailable(t, err, client.ReasonBreakerOpen, 0)
	}
	if f.hits.Load() != hits || time.Since(start) > 100*time.Millisecond {
		t.Fatalf("an open breaker sent requests (%d) or was slow (%s)", f.hits.Load()-hits, time.Since(start))
	}
	// Probes bypass it.
	if _, err := c.Healthz(context.Background()); !errors.Is(err, client.ErrCoreUnavailable) || f.hits.Load() == hits {
		t.Fatal("a probe did not go through", err)
	}
	// After the cooldown one probe goes through; a failed probe opens it again at once.
	clock.add(client.DefaultBreakerCooldown)
	if c.BreakerState() != client.BreakerHalfOpen {
		t.Fatal(c.BreakerState())
	}
	_, err = c.Evaluate(context.Background(), evalReq())
	unavailable(t, err, client.ReasonServerError, 2)
	if c.BreakerState() != client.BreakerOpen {
		t.Fatal("a failed probe did not reopen it")
	}
	// The core recovers: the next probe closes it.
	down.Store(false)
	clock.add(client.DefaultBreakerCooldown)
	if res, err := c.Evaluate(context.Background(), evalReq()); err != nil || !res.Decision {
		t.Fatal(res, err)
	}
	if c.BreakerState() != client.BreakerClosed {
		t.Fatal(c.BreakerState())
	}
}

func TestOnlyOneHalfOpenProbeAtATime(t *testing.T) {
	release := make(chan struct{})
	var block atomic.Bool
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if !block.Load() {
			status(503, `{"error": "down"}`)(w, r)
			return
		}
		<-release
		status(200, okEval)(w, r)
	})
	clock := &fakeClock{t: time.Unix(1e9, 0)}
	c := newClient(t, f.srv.URL, gw, func(o *client.Options) {
		o.Clock, o.BreakerThreshold, o.Retries, o.Timeout = clock.now, 1, -1, 5*time.Second
	})
	_, err := c.Evaluate(context.Background(), evalReq())
	unavailable(t, err, client.ReasonServerError, 1)
	if c.BreakerState() != client.BreakerOpen {
		t.Fatal(c.BreakerState())
	}
	clock.add(client.DefaultBreakerCooldown)
	block.Store(true)
	done := make(chan error, 1)
	go func() {
		_, err := c.Evaluate(context.Background(), evalReq())
		done <- err
	}()
	for deadline := time.Now().Add(2 * time.Second); f.hits.Load() < 2; {
		if time.Now().After(deadline) {
			t.Fatal("the probe never arrived")
		}
		time.Sleep(time.Millisecond)
	}
	// While the probe is out, every other call fails fast.
	_, err = c.Evaluate(context.Background(), evalReq())
	unavailable(t, err, client.ReasonBreakerOpen, 0)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if c.BreakerState() != client.BreakerClosed || f.hits.Load() != 2 {
		t.Fatalf("%s, hits %d", c.BreakerState(), f.hits.Load())
	}
}

func TestTheCallersContextIsNotAnOutage(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	c := newClient(t, f.srv.URL, gw, func(o *client.Options) { o.BreakerThreshold = 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.Evaluate(ctx, evalReq())
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, client.ErrCoreUnavailable) {
		t.Fatal(err)
	}
	if c.BreakerState() != client.BreakerClosed {
		t.Fatal("the caller's deadline opened the breaker")
	}
}

func TestNewRefusesABadBaseURL(t *testing.T) {
	for _, u := range []string{"", "core:8080", "ftp://core", "http://", "http://u:p@core", "http://core?x=1"} {
		if _, err := client.New(client.Options{BaseURL: u}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	c, err := client.New(client.Options{BaseURL: "http://core:8080/prefix/"})
	if err != nil || c == nil {
		t.Fatal(err)
	}
}

func TestABasePathPrefixIsKept(t *testing.T) {
	var path atomic.Value
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.URL.Path)
		status(200, `{"seq": 1, "hash": "h"}`)(w, r)
	})
	c := newClient(t, f.srv.URL+"/api/v1/namespaces/x/services/core:8080/proxy/", gw)
	if _, err := c.Outcome(context.Background(), "12", &client.OutcomeRequest{Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	if path.Load() != "/api/v1/namespaces/x/services/core:8080/proxy/v1/decisions/12/outcome" {
		t.Fatal(path.Load())
	}
}
