package gate_test

// C-2: the attestation signer, end to end on the gate's fixtures: outcome -> statement -> DSSE -> (fake) Rekor ->
// the envelope digest on the chain and in the store. A cleared change that never synced gets none.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/attest/attesttest"
	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

type flaky struct {
	attest.Backend
	fail int
}

func (f *flaky) Sign(ctx context.Context, p []byte) (attest.Signed, error) {
	if f.fail > 0 {
		f.fail--
		return attest.Signed{}, errors.New("fulcio is down")
	}
	return f.Backend.Sign(ctx, p)
}

// attestorFor wires an Attestor to f's gate with a static backend (the fixture's token key stands in) and a fake Rekor.
func attestorFor(t *testing.T, f *fixture) (*attest.Attestor, *attesttest.Rekor, token.KeySet, *flaky) {
	t.Helper()
	sg := f.svc.Tokens.Signer
	ks := token.KeySet{sg.KeyID(): sg.Public()}
	rekor := attesttest.NewRekor(t)
	rk, err := attest.NewRekor(rekor.URL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	fl := &flaky{Backend: &attest.Static{Signer: sg, Rekor: rk}}
	a := &attest.Attestor{Backend: fl, Store: f.st, Gate: f.svc, Issuer: "clearance-test", Clock: f.clock.now}
	f.svc.OnOutcome = a.Notify
	return a, rekor, ks, fl
}

func (f *fixture) attestation(t *testing.T, id string) (store.Attestation, bool) {
	t.Helper()
	a, err := f.st.Attestation(f.ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return a, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return a, true
}

func TestAnAppliedOutcomeIsAttestedAndTheDigestIsOnTheChain(t *testing.T) {
	f, _ := withTokens(t)
	a, rekor, ks, _ := attestorFor(t, f)
	c := f.register(t, "ci", tfChange(tagOnly, nil))
	if c.State != "cleared" {
		t.Fatal(c.State)
	}
	// Cleared, never synced: nothing to attest, whatever the signer is asked.
	a.Drain(f.ctx)
	if err := a.Catchup(f.ctx); err != nil {
		t.Fatal(err)
	}
	a.Drain(f.ctx)
	if _, ok := f.attestation(t, c.ID); ok || rekor.Logged() != 0 || len(f.records(t, "deploy.attestation")) != 0 {
		t.Fatal("a change that never synced was attested")
	}

	out, err := f.svc.Outcome(f.ctx, principals["ci"], c.ID, applied(planDigest))
	if err != nil || !out.Matched {
		t.Fatalf("%+v %v", out, err)
	}
	a.Drain(f.ctx)
	att, ok := f.attestation(t, c.ID)
	if !ok {
		t.Fatal("no attestation after an applied outcome")
	}
	recs := f.records(t, "deploy.attestation")
	if len(recs) != 1 || rekor.Logged() != 1 {
		t.Fatalf("%d records, %d logged", len(recs), rekor.Logged())
	}
	rec := recs[0]
	fields, _ := rec["attestation"].(map[string]any)
	seq, _ := gate.SeqInt(rec["seq"])
	if fields["digest"] != att.Digest || att.RecordSeq != seq || att.OutcomeSeq != out.AuditSeq || att.RekorLogIndex == nil ||
		*att.RekorLogIndex != 0 || att.Backend != "static" || rec["principal"] != "policy" {
		t.Fatalf("%v vs %+v", rec, att)
	}
	// The bundle verifies offline, names the cleared plan and the change, and its envelope is the recorded digest.
	res, err := attest.Verify(att.Bundle, attest.VerifyOptions{Keys: ks, Subjects: []string{"sha256:" + planDigest}})
	if err != nil {
		t.Fatal(err)
	}
	p := res.Statement.Predicate
	if res.Digest != att.Digest || p.Clearance.ID != c.ID || p.Outcome.Seq != out.AuditSeq || !p.Outcome.Applied ||
		p.Outcome.Matched == nil || !*p.Outcome.Matched || p.Cleared.Kind != "terraform-plan" || p.Tier != 1 || len(p.Limitations) == 0 {
		t.Fatalf("%+v", p)
	}
	// Once: the same outcome processed again, or the catch-up after a restart, adds nothing.
	if err := a.Process(f.ctx, c.ID, out.AuditSeq); err != nil {
		t.Fatal(err)
	}
	if err := a.Catchup(f.ctx); err != nil {
		t.Fatal(err)
	}
	a.Drain(f.ctx)
	if len(f.records(t, "deploy.attestation")) != 1 || rekor.Logged() != 1 {
		t.Fatal("attested twice")
	}
	if ok, bad := evidence.Verify(f.records(t, "")); !ok {
		t.Fatalf("the chain breaks at %d", bad)
	}
}

func TestNoAttestationWhenTheApplyDidNotHappenOrDidNotMatch(t *testing.T) {
	f, _ := withTokens(t)
	a, rekor, _, _ := attestorFor(t, f)

	// Cleared, then an outcome that says it was not applied.
	d1 := canon.SHA256Hex([]byte("plan one"))
	b := heldPlan(t, f, d1)
	if _, err := f.svc.Clear(f.ctx, principals["erin"], b.ID, ""); err != nil {
		t.Fatal(err)
	}
	no := applied(d1)
	no.Applied = new(bool)
	if out, err := f.svc.Outcome(f.ctx, principals["ci"], b.ID, no); err != nil || !out.Matched {
		t.Fatalf("%+v %v", out, err)
	}
	a.Drain(f.ctx)
	if _, ok := f.attestation(t, b.ID); ok {
		t.Fatal("a plan that was not applied was attested")
	}

	// Applied, but it is not the cleared plan: an exception, never an attestation.
	d2 := canon.SHA256Hex([]byte("plan two"))
	c := heldPlan(t, f, d2)
	if _, err := f.svc.Clear(f.ctx, principals["erin"], c.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Outcome(f.ctx, principals["ci"], c.ID, applied(canon.SHA256Hex([]byte("another")))); err != nil {
		t.Fatal(err)
	}
	a.Drain(f.ctx)
	if err := a.Catchup(f.ctx); err != nil {
		t.Fatal(err)
	}
	a.Drain(f.ctx)
	if _, ok := f.attestation(t, c.ID); ok || rekor.Logged() != 0 {
		t.Fatal("a mismatched apply was attested")
	}

	// A held change (never cleared) with a forged outcome record naming it: refused by the builder.
	d3 := canon.SHA256Hex([]byte("plan three"))
	h := heldPlan(t, f, d3)
	row, _ := f.st.Change(f.ctx, h.ID)
	c3, _ := gate.FromRecord(row.Record)
	_, err := attest.BuildStatement(c3, store.Record{"tool": "deploy.outcome", "seq": int64(1), "change": map[string]any{"id": h.ID},
		"outcome": map[string]any{"applied": true}}, "x")
	if !errors.Is(err, attest.ErrNoAttestation) {
		t.Fatalf("a held change: %v", err)
	}
}

func TestASigningFailureIsRetriedAndNothingIsRecordedMeanwhile(t *testing.T) {
	f, _ := withTokens(t)
	a, _, _, fl := attestorFor(t, f)
	fl.fail = 1
	c := f.register(t, "ci", tfChange(tagOnly, nil))
	if _, err := f.svc.Outcome(f.ctx, principals["ci"], c.ID, applied(planDigest)); err != nil {
		t.Fatal(err)
	}
	a.Drain(f.ctx)
	if _, ok := f.attestation(t, c.ID); ok || len(f.records(t, "deploy.attestation")) != 0 {
		t.Fatal("recorded after a failed signing")
	}
	f.clock.advance(time.Minute)
	a.Drain(f.ctx)
	if _, ok := f.attestation(t, c.ID); !ok {
		t.Fatal("not retried")
	}
}

// errTx fails the attestation lookup the way a broken store would.
type errTx struct{ store.Tx }

func (errTx) Attestation(context.Context, string) (store.Attestation, error) {
	return store.Attestation{}, errors.New("the store could not be read")
}

type errStore struct{ store.Store }

func (s errStore) Atomic(ctx context.Context, fn func(store.Tx) error) error {
	return s.Store.Atomic(ctx, func(tx store.Tx) error { return fn(errTx{tx}) })
}

func TestAFailedAttestationLookupNeverOverwritesTheStoredBundle(t *testing.T) {
	f, _ := withTokens(t)
	a, _, _, _ := attestorFor(t, f)
	c := f.register(t, "ci", tfChange(tagOnly, nil))
	out, err := f.svc.Outcome(f.ctx, principals["ci"], c.ID, applied(planDigest))
	if err != nil {
		t.Fatal(err)
	}
	a.Drain(f.ctx)
	before, ok := f.attestation(t, c.ID)
	if !ok {
		t.Fatal("not attested")
	}
	f.svc.Store = errStore{f.st}
	_, err = f.svc.RecordAttestation(f.ctx, store.Attestation{ChangeID: c.ID, Digest: "sha256:other", Backend: "static",
		OutcomeSeq: out.AuditSeq, Bundle: json.RawMessage(`{"other":true}`)})
	if err == nil {
		t.Fatal("a failed lookup was treated as no attestation")
	}
	f.svc.Store = f.st
	after, _ := f.attestation(t, c.ID)
	if after.Digest != before.Digest || len(f.records(t, "deploy.attestation")) != 1 {
		t.Fatalf("overwritten: %+v", after)
	}
}
