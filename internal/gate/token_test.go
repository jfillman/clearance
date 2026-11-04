package gate_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

// withTokens is the gate with a throwaway signing key (generated per test; no key is committed).
func withTokens(t *testing.T) (*fixture, token.KeySet) {
	t.Helper()
	f := newGate(t)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := token.NewKeySigner(k)
	f.svc.Tokens = &gate.Tokens{Signer: s, Issuer: "clearance-test", TTL: 15 * time.Minute}
	return f, token.KeySet{s.KeyID(): s.Public()}
}

func (f *fixture) token(t *testing.T, id string) store.Token {
	t.Helper()
	tk, err := f.st.Token(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func (f *fixture) verify(t *testing.T, ks token.KeySet, tk store.Token, nonces token.NonceChecker) (*token.Claims, error) {
	t.Helper()
	o := token.Options{Issuer: "clearance-test", Now: f.clock.now, Nonces: nonces}
	dsse, err := token.Verify(f.ctx, tk.Envelope, ks, o)
	if err != nil {
		return nil, err
	}
	jwt, err := token.VerifyJWT(f.ctx, tk.JWT, ks, o)
	if err != nil {
		t.Fatalf("the DSSE envelope verifies and its JWT projection does not: %v", err)
	}
	a, _ := json.Marshal(dsse)
	b, _ := json.Marshal(jwt)
	if string(a) != string(b) {
		t.Fatalf("the two encodings differ:\n%s\n%s", a, b)
	}
	return dsse, nil
}

func TestAPolicyClearIssuesABoundToken(t *testing.T) {
	f, ks := withTokens(t)
	body := change(map[string]any{"objects": imageBump, "taskId": "task-42"})
	c := f.register(t, "ci", body)
	if c.State != "cleared" || *c.ClearedBy != "policy" || *c.TaskID != "task-42" {
		t.Fatal(c)
	}
	tk := f.token(t, c.ID)
	if tk.Cluster != "hangar-prod" || tk.RevokedAt != nil || !tk.ExpiresAt.Equal(T0.Add(15*time.Minute)) {
		t.Fatalf("%+v", tk)
	}
	cl, err := f.verify(t, ks, tk, f.svc)
	if err != nil {
		t.Fatal(err)
	}
	img := "ghcr.io/jfillman/flight/gate-api@sha256:" + strings.Repeat("e", 64)
	if cl.Subject != c.ID || cl.Subjects.TreeRoot != tree || cl.Subjects.Commit != head || cl.Subjects.Repo != "jfillman/gitops-gate-api" ||
		cl.Subjects.PR != 7 || len(cl.Subjects.Images) != 1 || cl.Subjects.Images[0] != img ||
		cl.Target != (token.Target{Cluster: "hangar-prod", Env: "prod", App: "gate-api"}) || cl.Tier != 1 ||
		cl.Clearance.ClearedBy != "policy" || cl.Policy != (token.Policy{Ref: "baseline", Version: c.PolicyVersion,
		Engine: "none", Verdict: "not-evaluated"}) || len(cl.Approvals) != 0 || cl.Nonce != tk.Nonce ||
		cl.Provenance != (token.Provenance{Level: "confirmed-human", Check: "not-agent", Proposer: "user:dana",
			ProposerKind: "person", TaskID: "task-42"}) {
		t.Fatalf("claims %+v", cl)
	}
	if len(cl.Objects) != 1 || cl.Objects[0] != (token.Object{APIVersion: "argoproj.io/v1alpha1", Kind: "Rollout",
		Namespace: "app-gate-api-prod", Name: "gate-api", Rendered: strings.Repeat("d", 64), Changed: true, Op: "changed"}) {
		t.Fatalf("objects %+v", cl.Objects)
	}
	// The deploy.clear record names who cleared it (policy, no person) and the token's nonce; the task correlates.
	rec := f.records(t, "deploy.clear")[0]
	if rec["cleared_by"] != "policy" || rec["token"] != tk.Nonce || len(rec["approvals"].([]any)) != 0 || rec["task_id"] != "task-42" {
		t.Fatalf("record %v", rec)
	}
	samePolicy(t, cl.Policy, rec)
}

// samePolicy: a token attests its record, so its policy claim is the record's policy group, field for field.
func samePolicy(t *testing.T, p token.Policy, rec store.Record) {
	t.Helper()
	raw, _ := json.Marshal(p)
	var claim map[string]any
	_ = json.Unmarshal(raw, &claim)
	if group := policyOf(t, rec); !reflect.DeepEqual(claim, group) {
		t.Fatalf("token policy %v, record policy %v", claim, group)
	}
}

func TestTheTokensPolicyIsItsClearRecordsPolicyGroup(t *testing.T) {
	f, ks := withTokens(t)
	commit := strings.Repeat("9", 40)
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump, "policy": map[string]any{"ttlDays": 3}, "policyCommit": commit,
		"admission": kyvernoPass, "checks": map[string]any{"ci": "pass", "provenance": "not-agent", "render": "ok"}}))
	tk, err := f.st.Token(f.ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := f.verify(t, ks, tk, f.svc)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Policy != (token.Policy{Ref: "clearance.yaml@" + commit, Version: "baseline-2026-10-31+sha256:" + *c.RepoPolicyDigest,
		Engine: "kyverno/1.19.0", Verdict: "pass", Bundle: kyvernoPass["bundle"].(string)}) {
		t.Fatalf("%+v", cl.Policy)
	}
	samePolicy(t, cl.Policy, f.records(t, "deploy.clear")[0])
}

func TestPeopleClearingIssuesATokenNamingThePersonAtTheirIdP(t *testing.T) {
	f, ks := withTokens(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": secret})).ID // tier 3: an owner and an outside person
	if _, err := f.st.Token(f.ctx, cid); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a holding change has a token", err)
	}
	// erin signs in herself (her ID token's subject and issuer); root through the portal (a delegate).
	erin := authn.Principal{ID: "user:erin", Kind: authn.KindPerson,
		Claims: map[string]any{"sub": "CgRlcmluEgZnaXRodWI", "iss": "https://dex.example"}}
	if _, err := f.svc.Clear(f.ctx, erin, cid, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Token(f.ctx, cid); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a half-approved change has a token", err)
	}
	f.clock.advance(time.Minute)
	out, err := f.svc.Clear(f.ctx, principals["tower"], cid, "user:root")
	if err != nil || out.State != "cleared" {
		t.Fatal(out, err)
	}
	cl, err := f.verify(t, ks, f.token(t, cid), f.svc)
	if err != nil {
		t.Fatal(err)
	}
	want := []token.Approval{
		{Sub: "CgRlcmluEgZnaXRodWI", Iss: "https://dex.example", Person: "user:erin", Role: "owner", At: "2026-09-26T12:00:00Z"},
		{Sub: "user:root", Iss: "delegate:" + tower, Person: "user:root", Via: tower, Role: "outside", At: "2026-09-26T12:01:00Z"},
	}
	if len(cl.Approvals) != 2 || cl.Approvals[0] != want[0] || cl.Approvals[1] != want[1] {
		t.Fatalf("approvals %+v", cl.Approvals)
	}
	if cl.Clearance.ClearedBy != "people" || cl.Tier != 3 || cl.IssuedAt != T0.Add(time.Minute).Unix() {
		t.Fatalf("claims %+v", cl)
	}
	recs := f.records(t, "deploy.clear")
	first, last := recs[0], recs[len(recs)-1]
	if _, has := first["token"]; has || first["cleared_by"] != nil || len(first["approvals"].([]any)) != 1 {
		t.Fatalf("the first approval's record: %v", first)
	}
	ap := last["approvals"].([]any)
	if last["token"] != cl.Nonce || last["cleared_by"] != "people" || len(ap) != 2 ||
		ap[1].(map[string]any)["iss"] != "delegate:"+tower || ap[1].(map[string]any)["via"] != tower ||
		ap[0].(map[string]any)["sub"] != "CgRlcmluEgZnaXRodWI" {
		t.Fatalf("the clearing record: %v", last)
	}
	samePolicy(t, cl.Policy, last)
}

func TestANewHeadRevokesTheTokenAndTheOldOneIsAReplay(t *testing.T) {
	f, ks := withTokens(t)
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	old := f.token(t, c.ID)
	if _, err := f.verify(t, ks, old, f.svc); err != nil {
		t.Fatal(err)
	}
	// A new head on the same pull request.
	f.clock.advance(time.Minute)
	newHead := strings.Repeat("f", 40)
	n := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": newHead}))
	if n.State != "holding" {
		t.Fatal(n)
	}
	revoked := f.token(t, c.ID)
	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(T0.Add(time.Minute)) {
		t.Fatalf("not revoked: %+v", revoked)
	}
	// The old token still has a good signature and is not expired, so offline it verifies; the core's nonce
	// check refuses it.
	if _, err := f.verify(t, ks, old, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verify(t, ks, old, f.svc); !errors.Is(err, token.ErrReplay) {
		t.Fatal(err)
	}
	if _, live, err := f.svc.Clearance(f.ctx, c.ID); err != nil || live != nil {
		t.Fatal("a revoked token is still served", live, err)
	}
	recs := f.records(t, "deploy.revoke")
	if len(recs) != 1 || recs[0]["token"] != old.Nonce || !strings.Contains(recs[0]["result"].(string), "superseded by ffffff") {
		t.Fatalf("%v", recs)
	}
	// A token for the right clearance but bound elsewhere is refused even with a live nonce.
	o := token.Options{Issuer: "clearance-test", Now: f.clock.now, Expect: token.Expect{TreeRoot: strings.Repeat("9", 64)}}
	if _, err := token.Verify(f.ctx, old.Envelope, ks, o); !errors.Is(err, token.ErrDigestMismatch) {
		t.Fatal(err)
	}
	// A pushed commit (pr 0) revokes only the same app, environment and cluster's tokens.
	a := f.register(t, "ci", change(map[string]any{"objects": imageBump, "pr": json.Number("0"), "head": strings.Repeat("1", 40)}))
	b := f.register(t, "ci", change(map[string]any{"objects": imageBump, "pr": json.Number("0"), "head": strings.Repeat("2", 40),
		"app": "other-app"}))
	if f.token(t, a.ID).RevokedAt != nil || f.token(t, b.ID).RevokedAt != nil {
		t.Fatal("another app's push revoked a token")
	}
	f.register(t, "ci", change(map[string]any{"objects": imageBump, "pr": json.Number("0"), "head": strings.Repeat("3", 40)}))
	if f.token(t, a.ID).RevokedAt == nil || f.token(t, b.ID).RevokedAt != nil {
		t.Fatal("a push for the same app did not revoke its older token (or revoked another's)")
	}
}

func TestTokensRefreshUntilTheHorizonAndThenLapse(t *testing.T) {
	f, ks := withTokens(t)
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	first := f.token(t, c.ID)
	// Not due yet: nothing changes.
	if n, r, err := f.svc.Refresh(f.ctx); err != nil || n != 0 || r != 0 {
		t.Fatal(n, r, err)
	}
	f.clock.advance(8 * time.Minute) // under half the 15m life left
	if n, r, err := f.svc.Refresh(f.ctx); err != nil || n != 1 || r != 0 {
		t.Fatal(n, r, err)
	}
	second := f.token(t, c.ID)
	if second.Nonce != first.Nonce || !second.ExpiresAt.Equal(T0.Add(23*time.Minute)) || second.JWT == first.JWT {
		t.Fatalf("refresh: %+v", second)
	}
	if _, err := f.verify(t, ks, second, f.svc); err != nil {
		t.Fatal(err)
	}
	// Reading through the core never answers a token about to expire.
	f.clock.advance(10 * time.Minute)
	_, live, err := f.svc.Clearance(f.ctx, c.ID)
	if err != nil || live == nil || !live.ExpiresAt.Equal(T0.Add(33*time.Minute)) {
		t.Fatal(live, err)
	}
	// The horizon: as long after the clear as the change could have held (7 days). The last token ends there.
	f.clock.t = T0.Add(7*24*time.Hour - 5*time.Minute)
	if n, _, _ := f.svc.Refresh(f.ctx); n != 1 {
		t.Fatal("not re-issued before the horizon")
	}
	if tk := f.token(t, c.ID); !tk.ExpiresAt.Equal(T0.Add(7 * 24 * time.Hour)) {
		t.Fatalf("exp past the horizon: %s", tk.ExpiresAt)
	}
	f.clock.t = T0.Add(7 * 24 * time.Hour)
	if n, r, err := f.svc.Refresh(f.ctx); err != nil || n != 0 || r != 1 {
		t.Fatal(n, r, err)
	}
	if f.token(t, c.ID).RevokedAt == nil {
		t.Fatal("a lapsed token is not revoked")
	}
	if _, err := f.verify(t, ks, second, nil); !errors.Is(err, token.ErrExpired) {
		t.Fatal(err)
	}
}

func TestARotatedKeyReSignsTheLiveTokens(t *testing.T) {
	f, _ := withTokens(t)
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s2, _ := token.NewKeySigner(k)
	f.svc.Tokens.Signer = s2
	if n, _, err := f.svc.Refresh(f.ctx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err := f.verify(t, token.KeySet{s2.KeyID(): s2.Public()}, f.token(t, c.ID), f.svc); err != nil {
		t.Fatal(err)
	}
}

type failSigner struct{ token.Signer }

func (failSigner) Sign(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("kms unavailable")
}

func TestASigningFailureLeavesTheChangeUncleared(t *testing.T) {
	f, _ := withTokens(t)
	f.svc.Tokens.Signer = failSigner{f.svc.Tokens.Signer}
	if _, err := f.svc.Register(f.ctx, principals["ci"], change(map[string]any{"objects": imageBump})); err == nil ||
		!strings.Contains(err.Error(), "kms unavailable") {
		t.Fatal(err)
	}
	if recs := f.records(t, ""); len(recs) != 0 {
		t.Fatalf("a failed clear wrote %d records", len(recs))
	}
	cid := change(nil)
	req, _ := gate.ParseRequest(cid)
	if _, err := f.st.Change(f.ctx, req.ID()); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the change was kept", err)
	}
}

func TestTheGitHubAppsRecordsNameWhoCleared(t *testing.T) {
	f, _ := withTokens(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas})).ID
	if _, err := f.svc.Clear(f.ctx, principals["tower"], cid, "user:erin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DeploymentRequested(f.ctx, "177375213", "jfillman/gitops-gate-api", head, "prod", 9, "https://cb"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DeploymentDelivered(f.ctx, cid, 9, "prod"); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"deploy.request", "deploy.answer"} {
		recs := f.records(t, tool)
		rec := recs[len(recs)-1]
		ap, _ := rec["approvals"].([]any)
		if rec["principal"] != "app:177375213" || rec["cleared_by"] != "people" || len(ap) != 1 ||
			ap[0].(map[string]any)["person"] != "user:erin" || ap[0].(map[string]any)["via"] != tower {
			t.Fatalf("%s: %v", tool, rec)
		}
	}
	// A policy clear says so.
	p := f.register(t, "ci", change(map[string]any{"objects": imageBump, "head": strings.Repeat("4", 40), "pr": json.Number("8")}))
	if _, err := f.svc.DeploymentRequested(f.ctx, "177375213", "jfillman/gitops-gate-api", p.Head, "prod", 10, "https://cb"); err != nil {
		t.Fatal(err)
	}
	recs := f.records(t, "deploy.request")
	if rec := recs[len(recs)-1]; rec["cleared_by"] != "policy" || len(rec["approvals"].([]any)) != 0 {
		t.Fatalf("%v", rec)
	}
}
