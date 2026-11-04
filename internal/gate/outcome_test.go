package gate_test

// G-TF-2: hold, release and outcome for the terraform-plan subject. The 24-hour hold and its deploy.expire,
// registration idempotent by repository, workspace and plan digest, the change-bound outcome (matched, and a mismatch
// that is a deploy.exception of kind digest-mismatch), and the outcome's state machine: once, only for a cleared plan,
// only from the principal that registered it.

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
)

func yes() *bool { b := true; return &b }

// applied is the outcome of applying the plan with digest d: one resource updated, nine seconds.
func applied(d string) gate.OutcomeRequest {
	return gate.OutcomeRequest{Applied: yes(), PlanDigest: "sha256:" + d,
		Changes:   []gate.AppliedChange{{Address: "aws_vpc.lab", Action: "update", Status: "complete"}},
		StartedAt: T0.Format(time.RFC3339), FinishedAt: T0.Add(9 * time.Second).Format(time.RFC3339)}
}

var tagOnly = plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")) // tier 1: cleared by policy

// heldPlan is a tier-2 plan (a create) with its own digest, cleared by erin (in the owner group, not the proposer).
func heldPlan(t *testing.T, f *fixture, d string) *gate.Change {
	t.Helper()
	c := f.register(t, "ci", tfChange(plan(map[string]any{"planDigest": d}, res("aws_subnet.c", "aws_subnet", create)), nil))
	if c.State != "holding" || c.Tier != 2 {
		t.Fatalf("%s tier %d", c.State, c.Tier)
	}
	return c
}

func TestAMatchedAndAMismatchedOutcome(t *testing.T) {
	f, _ := withTokens(t)
	// Matched: the tag-only plan cleared by policy, applied as cleared.
	a := f.register(t, "ci", tfChange(tagOnly, nil))
	if a.State != "cleared" {
		t.Fatal(a.State)
	}
	out, err := f.svc.Outcome(f.ctx, principals["ci"], a.ID, applied(planDigest))
	if err != nil || !out.Matched || out.ExceptionSeq != nil || out.Change.Outcome == nil || out.Change.Outcome.Seq != out.AuditSeq ||
		!out.Change.Outcome.Applied || out.Change.Outcome.PlanDigest != planDigest || out.Change.State != "cleared" {
		t.Fatalf("%+v %v", out, err)
	}
	if n := len(f.records(t, "deploy.exception")); n != 0 {
		t.Fatalf("a matched outcome wrote %d exceptions", n)
	}
	recs := f.records(t, "deploy.outcome")
	if len(recs) != 1 {
		t.Fatalf("%d deploy.outcome records", len(recs))
	}
	r := recs[0]
	o, _ := r["outcome"].(map[string]any)
	d, _ := o["digests"].(map[string]any)
	ch, _ := r["change"].(map[string]any)
	changes, _ := o["changes"].([]any)
	if r["matched"] != true || o["applied"] != true || d["sha256"] != planDigest || ch["id"] != a.ID || ch["tree"] != planDigest ||
		len(changes) != 1 || r["principal"] != principals["ci"].ID || r["decision"] != nil || r["boundary"] != "deployment" ||
		r["coverage"] != "authorized-and-verified" || r["result"] != "applied (1 update): the cleared plan" {
		t.Fatalf("%v", r)
	}
	// matched is the core's comparison (verified); what the apply did is the reporter's claim.
	if !inList(r["verified"], "matched") || !inList(r["claimed"], "outcome") {
		t.Fatalf("verified %v claimed %v", r["verified"], r["claimed"])
	}
	if seq, _ := gate.SeqInt(r["seq"]); seq != out.AuditSeq {
		t.Fatal(seq, out.AuditSeq)
	}

	// Mismatched: a held plan, cleared by a person, then an apply that reports another plan's digest.
	cleared := canon.SHA256Hex([]byte("the plan erin cleared"))
	other := canon.SHA256Hex([]byte("the plan that was applied"))
	b := heldPlan(t, f, cleared)
	if _, err := f.svc.Clear(f.ctx, principals["erin"], b.ID, ""); err != nil {
		t.Fatal(err)
	}
	out, err = f.svc.Outcome(f.ctx, principals["ci"], b.ID, applied(other))
	if err != nil || out.Matched || out.ExceptionSeq == nil || out.Change.Outcome.Matched || out.Change.Outcome.Exception == nil ||
		*out.Change.Outcome.Exception != *out.ExceptionSeq || *out.ExceptionSeq <= out.AuditSeq {
		t.Fatalf("%+v %v", out, err)
	}
	recs = f.records(t, "deploy.outcome")
	if len(recs) != 2 || recs[1]["matched"] != false {
		t.Fatalf("%v", recs)
	}
	if res, _ := recs[1]["result"].(string); !strings.Contains(res, "is not the cleared sha256:"+cleared[:12]) {
		t.Fatal(res)
	}
	exc := f.records(t, "deploy.exception")
	if len(exc) != 1 {
		t.Fatalf("%d deploy.exception records", len(exc))
	}
	x := exc[0]
	xk, _ := x["exception"].(map[string]any)
	xc, _ := x["change"].(map[string]any)
	dest, _ := x["destination"].(map[string]any)
	if xk["kind"] != "digest-mismatch" || xk["expected"] != "sha256:"+cleared || xk["observed"] != "sha256:"+other ||
		xc["id"] != b.ID || x["coverage"] != "out-of-band-detected" || dest["environment"] != "lab" || x["principal"] != principals["ci"].ID ||
		!strings.Contains(fmt.Sprint(xk["detail"]), fmt.Sprintf("seq %d", out.AuditSeq)) {
		t.Fatalf("%v", x)
	}
	if _, err := time.Parse(time.RFC3339, fmt.Sprint(xk["detected_at"])); err != nil {
		t.Fatal(err)
	}
	if ok, bad := evidence.Verify(f.records(t, "")); !ok {
		t.Fatalf("the chain breaks at %d", bad)
	}
	stored := f.get(t, b.ID)
	if stored.Outcome == nil || stored.Outcome.Matched || stored.Outcome.Exception == nil {
		t.Fatalf("stored %+v", stored.Outcome)
	}
	// The mismatch takes the clearance away (C-6): the change is in exception, ended by that record, and its
	// token is revoked in the same transaction, a deploy.revoke after the exception.
	if stored.State != gate.StateException || out.Change.State != gate.StateException || stored.Ended == nil ||
		stored.Ended.Seq != *out.ExceptionSeq || stored.Ended.Tool != gate.KindException || stored.Ended.Kind != "digest-mismatch" {
		t.Fatalf("%s ended %+v", stored.State, stored.Ended)
	}
	if tk := f.token(t, b.ID); tk.RevokedAt == nil {
		t.Fatal("the mismatched change's token is still live")
	} else {
		var revoked store.Record
		for _, r := range f.records(t, "deploy.revoke") {
			if c, _ := r["change"].(map[string]any); c["id"] == b.ID {
				revoked = r
			}
		}
		rs, _ := gate.SeqInt(revoked["seq"])
		if revoked == nil || revoked["result"] != "token revoked: exception: digest-mismatch" || revoked["token"] != tk.Nonce ||
			rs <= *out.ExceptionSeq {
			t.Fatalf("%v", revoked)
		}
	}
	// The matched change keeps its clearance and its token.
	if got := f.get(t, a.ID); got.State != gate.StateCleared || got.Ended != nil {
		t.Fatalf("%s %+v", got.State, got.Ended)
	}
	if tk := f.token(t, a.ID); tk.RevokedAt != nil {
		t.Fatal("a matched outcome revoked the token")
	}
	if n := len(f.records(t, "deploy.revoke")); n != 1 {
		t.Fatalf("%d deploy.revoke records", n)
	}
	f.consistent(t, a.ID)
	f.consistent(t, b.ID)
	// A second outcome is still DG-STATE.
	if r, s := ruleOf(func() error { _, err := f.svc.Outcome(f.ctx, principals["ci"], b.ID, applied(cleared)); return err }()); r != "DG-STATE" || s != 409 {
		t.Fatal(r, s)
	}
}

// The outcome's state machine: once per change (a second is DG-STATE, matched or not), only for a cleared plan,
// only from its registrant; every refusal records nothing.
func TestTheOutcomeStateMachine(t *testing.T) {
	f := newGate(t)
	a := f.register(t, "ci", tfChange(tagOnly, nil))
	if _, err := f.svc.Outcome(f.ctx, principals["ci"], a.ID, applied(planDigest)); err != nil {
		t.Fatal(err)
	}
	b := heldPlan(t, f, canon.SHA256Hex([]byte("b")))
	if _, err := f.svc.Clear(f.ctx, principals["erin"], b.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Outcome(f.ctx, principals["ci"], b.ID, applied(canon.SHA256Hex([]byte("not b")))); err != nil {
		t.Fatal(err)
	}
	held := heldPlan(t, f, canon.SHA256Hex([]byte("held")))
	denied := heldPlan(t, f, canon.SHA256Hex([]byte("denied")))
	if _, err := f.svc.Deny(f.ctx, principals["erin"], denied.ID, "no", ""); err != nil {
		t.Fatal(err)
	}
	manifest := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	before := len(f.records(t, ""))
	for name, tc := range map[string]struct {
		who, id string
		rule    string
		status  int
	}{
		"a second outcome, matched":    {"ci", a.ID, "DG-STATE", 409},
		"a second outcome, mismatched": {"ci", b.ID, "DG-STATE", 409},
		"a holding plan":               {"ci", held.ID, "DG-STATE", 409},
		"a denied plan":                {"ci", denied.ID, "DG-STATE", 409},
		"not its registrant":           {"other", a.ID, "DG-FORBIDDEN", 403},
		"a person":                     {"erin", held.ID, "DG-FORBIDDEN", 403},
		"a manifest change":            {"ci", manifest.ID, "DG-SUBJECT", 400},
		"no such change":               {"ci", "ch-0000000000000000", "DG-UNKNOWN", 404},
	} {
		_, err := f.svc.Outcome(f.ctx, principals[tc.who], tc.id, applied(planDigest))
		if r, s := ruleOf(err); r != tc.rule || s != tc.status {
			t.Errorf("%s: %v", name, err)
		}
	}
	if after := len(f.records(t, "")); after != before {
		t.Fatalf("refusals wrote %d records", after-before)
	}
	// An expired plan has no outcome either, and the gate off keeps none.
	f.clock.advance(25 * time.Hour)
	if _, err := f.svc.Outcome(f.ctx, principals["ci"], held.ID, applied(planDigest)); err == nil {
		t.Fatal("an outcome for a plan that never cleared")
	}
	off := gate.NewService(gate.Config{Off: true}, f.st, f.clock.now)
	if r, s := ruleOf(func() error { _, err := off.Outcome(f.ctx, principals["ci"], a.ID, applied(planDigest)); return err }()); r != "DG-OFF" || s != 404 {
		t.Fatal(r, s)
	}
}

func TestAMalformedOutcomeIsRefused(t *testing.T) {
	f := newGate(t)
	a := f.register(t, "ci", tfChange(tagOnly, nil))
	with := func(edit func(*gate.OutcomeRequest)) gate.OutcomeRequest {
		o := applied(planDigest)
		edit(&o)
		return o
	}
	for name, o := range map[string]gate.OutcomeRequest{
		"no applied":          with(func(o *gate.OutcomeRequest) { o.Applied = nil }),
		"no digest":           with(func(o *gate.OutcomeRequest) { o.PlanDigest = "" }),
		"a short digest":      with(func(o *gate.OutcomeRequest) { o.PlanDigest = "abc" }),
		"an invented action":  with(func(o *gate.OutcomeRequest) { o.Changes[0].Action = "obliterate" }),
		"an invented status":  with(func(o *gate.OutcomeRequest) { o.Changes[0].Status = "maybe" }),
		"no address":          with(func(o *gate.OutcomeRequest) { o.Changes[0].Address = "" }),
		"a control character": with(func(o *gate.OutcomeRequest) { o.Changes[0].Address = "aws_vpc.lab\n" }),
		"too many changes":    with(func(o *gate.OutcomeRequest) { o.Changes = make([]gate.AppliedChange, gate.MaxResources+1) }),
		"no startedAt":        with(func(o *gate.OutcomeRequest) { o.StartedAt = "" }),
		"not a time":          with(func(o *gate.OutcomeRequest) { o.FinishedAt = "yesterday" }),
		"finished first":      with(func(o *gate.OutcomeRequest) { o.FinishedAt = T0.Add(-time.Second).Format(time.RFC3339) }),
		"in the future":       with(func(o *gate.OutcomeRequest) { o.FinishedAt = T0.Add(time.Hour).Format(time.RFC3339) }),
		"a long error":        with(func(o *gate.OutcomeRequest) { o.Error = strings.Repeat("x", gate.MaxOutcomeError+1) }),
		"a NUL in the error":  with(func(o *gate.OutcomeRequest) { o.Error = "a\x00b" }),
	} {
		var bc *gate.BadChange
		if _, err := f.svc.Outcome(f.ctx, principals["ci"], a.ID, o); !errors.As(err, &bc) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A failed apply is an outcome: not applied, its error recorded.
	failed := with(func(o *gate.OutcomeRequest) {
		no := false
		o.Applied, o.Changes, o.Error = &no, nil, "Error: Saved plan is stale"
	})
	out, err := f.svc.Outcome(f.ctx, principals["ci"], a.ID, failed)
	if err != nil || !out.Matched || out.Change.Outcome.Applied {
		t.Fatal(out, err)
	}
	r := f.records(t, "deploy.outcome")[0]
	if o, _ := r["outcome"].(map[string]any); o["applied"] != false || o["error"] != "Error: Saved plan is stale" ||
		r["result"] != "not applied: the cleared plan: Error: Saved plan is stale" {
		t.Fatalf("%v", r)
	}
}

// A plan holds 24 hours, not the gitops week, and then expires with a deploy.expire record. A clearance.yaml
// ttlDays shortens the gitops TTL and never lengthens the plan's.
func TestAPlanHoldsTwentyFourHoursAndExpires(t *testing.T) {
	f := newGate(t)
	held := heldPlan(t, f, canon.SHA256Hex([]byte("stale soon")))
	if got := held.ExpiresAt.Sub(held.CreatedAt.Time); got != 24*time.Hour {
		t.Fatalf("a plan holds %s", got)
	}
	gitops := f.register(t, "ci", change(map[string]any{"objects": replicas}))
	if gitops.State != "holding" || gitops.ExpiresAt.Sub(gitops.CreatedAt.Time) != 7*24*time.Hour {
		t.Fatalf("%s %s", gitops.State, gitops.ExpiresAt.Sub(gitops.CreatedAt.Time))
	}
	week := f.register(t, "ci", tfChange(plan(map[string]any{"planDigest": canon.SHA256Hex([]byte("ttl 3"))}, res("aws_subnet.d", "aws_subnet", create)),
		map[string]any{"policy": map[string]any{"ttlDays": 3}}))
	if got := week.ExpiresAt.Sub(week.CreatedAt.Time); got != 24*time.Hour {
		t.Fatalf("clearance.yaml ttlDays 3 made a plan hold %s", got)
	}
	if v := f.svc.PolicyView().Terraform.TTLHours; v != 24 {
		t.Fatal(v)
	}
	f.clock.advance(24*time.Hour - time.Second)
	if done, err := f.svc.Expire(f.ctx); err != nil || len(done) != 0 {
		t.Fatal(done, err)
	}
	f.clock.advance(time.Second)
	done, err := f.svc.Expire(f.ctx)
	if err != nil || len(done) != 2 || !slices.Contains(done, held.ID) || !slices.Contains(done, week.ID) {
		t.Fatal(done, err)
	}
	if got := f.get(t, held.ID); got.State != "expired" {
		t.Fatal(got.State)
	}
	if got := f.get(t, gitops.ID); got.State != "holding" {
		t.Fatalf("the gitops change expired with the plan: %s", got.State)
	}
	var rec store.Record
	for _, r := range f.records(t, "deploy.expire") {
		if c, _ := r["change"].(map[string]any); c["id"] == held.ID {
			rec = r
		}
	}
	if rec == nil || rec["result"] != "not cleared within 24 hours" || rec["principal"] != "policy" {
		t.Fatalf("%v", rec)
	}
	// Clearing it now is refused: a new plan registers again.
	if _, err := f.svc.Clear(f.ctx, principals["erin"], held.ID, ""); err == nil {
		t.Fatal("an expired plan was cleared")
	}
	if r, s := ruleOf(func() error {
		_, err := f.svc.Outcome(f.ctx, principals["ci"], held.ID, applied(planDigest))
		return err
	}()); r != "DG-STATE" || s != 409 {
		t.Fatal(r, s)
	}
	// The gitops change still says days.
	f.clock.advance(7 * 24 * time.Hour)
	if _, err := f.svc.Expire(f.ctx); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.records(t, "deploy.expire") {
		if c, _ := r["change"].(map[string]any); c["id"] == gitops.ID && r["result"] != "not cleared within 7 days" {
			t.Fatal(r["result"])
		}
	}
}

// Registration is idempotent by repository, workspace and plan digest: the same plan from another job, PR or commit
// is the same change (one deploy.request); another workspace or another plan is another change.
func TestReRegisteringAPlanReturnsTheSameChange(t *testing.T) {
	f := newGate(t)
	d := canon.SHA256Hex([]byte("idempotent"))
	body := func(over, subj map[string]any) map[string]any {
		s := map[string]any{"planDigest": d}
		for k, v := range subj {
			s[k] = v
		}
		return tfChange(plan(s, res("aws_subnet.c", "aws_subnet", create)), over)
	}
	first := f.register(t, "ci", body(nil, nil))
	for name, over := range map[string]map[string]any{
		"again":           nil,
		"another PR":      {"pr": 99},
		"a pushed commit": {"pr": 0, "head": strings.Repeat("b", 40)},
	} {
		if got := f.register(t, "ci", body(over, nil)); got.ID != first.ID || got.State != "holding" || got.PR != first.PR {
			t.Errorf("%s: %s (%s), want %s", name, got.ID, got.State, first.ID)
		}
	}
	if n := len(f.records(t, "deploy.request")); n != 1 {
		t.Fatalf("%d deploy.request records for one plan", n)
	}
	ws := map[string]any{"backend": "s3", "key": "network/lab/terraform.tfstate", "name": "staging"}
	for name, subj := range map[string]map[string]any{
		"another workspace": {"workspace": ws},
		"another state key": {"workspace": map[string]any{"backend": "s3", "key": "network/prod/terraform.tfstate", "name": "default"}},
		"another plan":      {"planDigest": canon.SHA256Hex([]byte("another"))},
	} {
		if got := f.register(t, "ci", body(nil, subj)); got.ID == first.ID {
			t.Errorf("%s: the same change", name)
		}
	}
	other := body(map[string]any{"repo": "jfillman/other-infra"}, nil)
	if got := f.register(t, "ci", other); got.ID == first.ID {
		t.Fatal("another repository: the same change")
	}
	// A cleared plan registered again is returned as it stands, its outcome too.
	if _, err := f.svc.Clear(f.ctx, principals["erin"], first.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Outcome(f.ctx, principals["ci"], first.ID, applied(d)); err != nil {
		t.Fatal(err)
	}
	if got := f.register(t, "ci", body(nil, nil)); got.ID != first.ID || got.State != "cleared" || got.Outcome == nil || !got.Outcome.Matched {
		t.Fatalf("%s %+v", got.State, got.Outcome)
	}
}

// The HTTP route: strict decoding, the gate's refusals as JSON, the answer.
func TestTheOutcomeRoute(t *testing.T) {
	f := newGate(t)
	mux := serve(f)
	a := f.register(t, "ci", tfChange(tagOnly, nil))
	path := "/v1/clearances/" + a.ID + "/outcome"
	body := map[string]any{"applied": true, "planDigest": planDigest, "changes": []any{map[string]any{"address": "aws_vpc.lab", "action": "update"}},
		"startedAt": T0.Format(time.RFC3339), "finishedAt": T0.Format(time.RFC3339)}
	if code, _ := call(mux, "POST", path, "", body, nil); code != 401 {
		t.Fatal(code)
	}
	extra := map[string]any{"applied": true, "planDigest": planDigest, "startedAt": T0.Format(time.RFC3339),
		"finishedAt": T0.Format(time.RFC3339), "plan": "raw bytes"}
	if code, ans := call(mux, "POST", path, "ci", extra, nil); code != 400 || !strings.Contains(fmt.Sprint(ans["error"]), "unknown field") {
		t.Fatal(code, ans)
	}
	if code, _ := call(mux, "POST", path, "other", body, nil); code != 403 {
		t.Fatal(code)
	}
	code, ans := call(mux, "POST", path, "ci", body, nil)
	if code != 200 || ans["matched"] != true || ans["exception_seq"] != nil || ans["change"].(map[string]any)["outcome"] == nil {
		t.Fatal(code, ans)
	}
	if code, ans := call(mux, "POST", path, "ci", body, nil); code != 409 || ans["rule"] != "DG-STATE" {
		t.Fatal(code, ans)
	}
}

// FuzzOutcomeRoute: whatever the body, the outcome route answers (never panics), and a 200 is an outcome recorded
// once.
func FuzzOutcomeRoute(f *testing.F) {
	f.Add(`{"applied":true,"planDigest":"` + planDigest + `","changes":[{"address":"aws_vpc.lab","action":"update","status":"complete"}],"startedAt":"2026-09-26T12:00:00Z","finishedAt":"2026-09-26T12:00:09Z"}`)
	f.Add(`{"applied":false,"planDigest":"sha256:` + strings.Repeat("ab", 32) + `","startedAt":"2026-09-26T12:00:00Z","finishedAt":"2026-09-26T12:00:00Z","error":"x"}`)
	f.Add(`{"applied":null}`)
	f.Add(`{}{}`)
	f.Fuzz(func(t *testing.T, body string) {
		g := newGate(t)
		a := g.register(t, "ci", tfChange(tagOnly, nil))
		r := httptest.NewRequest("POST", "/v1/clearances/"+a.ID+"/outcome", strings.NewReader(body))
		r = r.WithContext(authn.WithPrincipal(r.Context(), principals["ci"]))
		w := httptest.NewRecorder()
		serve(g).ServeHTTP(w, r)
		n := len(g.records(t, "deploy.outcome"))
		if (w.Code == 200) != (n == 1) || n > 1 {
			t.Fatalf("%d with %d outcomes: %s", w.Code, n, w.Body)
		}
	})
}
