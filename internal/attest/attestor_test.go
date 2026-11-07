package attest_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
)

// The manifest path: a provider's deploy.outcome record (POST /v1/records) names a cleared change; the attestor,
// told by NotifyRecord, attests it once, and not an outcome that says nothing was applied.
func TestAProviderOutcomeRecordIsAttestedKeyless(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	now := time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC)
	svc := gate.NewService(gate.Config{}, st, func() time.Time { return now })
	k := newKeyless(t)
	a := &attest.Attestor{Backend: k.b, Store: st, Gate: svc, Issuer: "clearance", Clock: func() time.Time { return now }}

	c := manifestChange()
	raw, _ := json.Marshal(c)
	var rec, none store.Record
	err := st.Atomic(ctx, func(tx store.Tx) error {
		if err := tx.PutChange(ctx, store.Change{ID: c.ID, App: c.App, Env: c.Env, State: c.State, Repo: c.Repo, Head: c.Head,
			PR: int(c.PR), ExpiresAt: now.Add(time.Hour), Record: raw}); err != nil {
			return err
		}
		ev := func(applied bool) store.Event {
			return store.Event{"ts": "2026-11-07T00:59:00Z", "tool": "deploy.outcome", "boundary": "deployment", "app": c.App,
				"target": "t", "principal": "hangar-prod/argocd/agent", "decision": nil, "tier": nil, "task_id": nil, "session": nil,
				"parent": nil, "agent": nil, "rule": nil, "args_sha256": nil, "result": "applied",
				"change":  map[string]any{"id": c.ID, "tree": "sha256:" + treeRoot},
				"outcome": map[string]any{"applied": applied, "digests": map[string]any{"sha256": treeRoot}, "finished_at": "2026-11-07T00:58:59Z"}}
		}
		w := evidence.Writer{Provider: evidence.Provider{Name: "argocd-agent", Version: "1"}}
		var err error
		if none, err = tx.Append(ctx, ev(false), w); err != nil {
			return err
		}
		rec, err = tx.Append(ctx, ev(true), w)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// Never synced: the not-applied outcome gets nothing.
	a.NotifyRecord(none)
	a.Drain(ctx)
	if _, err := st.Attestation(ctx, c.ID); err == nil || k.rekor.Logged() != 0 {
		t.Fatal("a not-applied outcome was attested")
	}
	// A record that is not a deploy.outcome is not queued.
	a.NotifyRecord(store.Record{"tool": "deploy.clear", "seq": int64(1), "change": map[string]any{"id": c.ID}})
	a.NotifyRecord(rec)
	a.Drain(ctx)
	got, err := st.Attestation(ctx, c.ID)
	if err != nil || got.Backend != "keyless" || got.RekorLogIndex == nil || k.rekor.Logged() != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	res, err := attest.Verify(got.Bundle, k.opts)
	if err != nil || res.Statement.Predicate.Cleared.TreeRoot != "sha256:"+treeRoot || res.Digest != got.Digest {
		t.Fatalf("%+v %v", res, err)
	}
	var onChain int
	recs, _ := st.Records(ctx, 0, 100)
	for _, r := range recs {
		if r["tool"] == "deploy.attestation" {
			onChain++
			if r["attestation"].(map[string]any)["digest"] != got.Digest {
				t.Fatalf("%v", r)
			}
		}
	}
	if onChain != 1 {
		t.Fatalf("%d deploy.attestation records", onChain)
	}
}

// A not-applied outcome queued first must not hide the applied one queued with it (or found by Catchup).
func TestANotAppliedOutcomeDoesNotHideALaterAppliedOne(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	now := time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC)
	svc := gate.NewService(gate.Config{}, st, func() time.Time { return now })
	k := newKeyless(t)
	a := &attest.Attestor{Backend: k.b, Store: st, Gate: svc, Issuer: "clearance", Clock: func() time.Time { return now }}
	c := manifestChange()
	raw, _ := json.Marshal(c)
	err := st.Atomic(ctx, func(tx store.Tx) error {
		if err := tx.PutChange(ctx, store.Change{ID: c.ID, App: c.App, Env: c.Env, State: c.State, Repo: c.Repo, Head: c.Head,
			PR: int(c.PR), ExpiresAt: now.Add(time.Hour), Record: raw}); err != nil {
			return err
		}
		w := evidence.Writer{Provider: evidence.Provider{Name: "argocd-agent", Version: "1"}}
		for _, applied := range []bool{false, true} {
			ev := store.Event{"ts": "2026-11-07T00:59:00Z", "tool": "deploy.outcome", "boundary": "deployment", "app": c.App,
				"target": "t", "principal": "hangar-prod/argocd/agent", "decision": nil, "tier": nil, "task_id": nil, "session": nil,
				"parent": nil, "agent": nil, "rule": nil, "args_sha256": nil, "result": "r",
				"change":  map[string]any{"id": c.ID, "tree": "sha256:" + treeRoot},
				"outcome": map[string]any{"applied": applied, "digests": map[string]any{"sha256": treeRoot}, "finished_at": "2026-11-07T00:58:59Z"}}
			if _, err := tx.Append(ctx, ev, w); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Both outcomes are found by the catch-up and signed in one drain: one attestation, of the applied one.
	if err := a.Catchup(ctx); err != nil {
		t.Fatal(err)
	}
	a.Drain(ctx)
	got, err := st.Attestation(ctx, c.ID)
	if err != nil || k.rekor.Logged() != 1 {
		t.Fatalf("%+v %v logged %d", got, err, k.rekor.Logged())
	}
	res, err := attest.Verify(got.Bundle, k.opts)
	if err != nil || !res.Statement.Predicate.Outcome.Applied || res.Statement.Predicate.Outcome.Seq != got.OutcomeSeq {
		t.Fatalf("%+v %v", res, err)
	}
}

// notifyingStore calls hook once, on the first outcome record read: a Notify that lands while Drain is processing.
type notifyingStore struct {
	store.Store
	hook func()
}

func (n *notifyingStore) Records(ctx context.Context, from int64, limit int) ([]store.Record, error) {
	if h := n.hook; h != nil {
		n.hook = nil
		h()
	}
	return n.Store.Records(ctx, from, limit)
}

// An outcome notified while the drain is processing an earlier one is not dropped by that one's verdict.
func TestAnOutcomeNotifiedDuringAProcessingIsNotLost(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	now := time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC)
	svc := gate.NewService(gate.Config{}, mem, func() time.Time { return now })
	k := newKeyless(t)
	ns := &notifyingStore{Store: mem}
	a := &attest.Attestor{Backend: k.b, Store: ns, Gate: svc, Issuer: "clearance", Clock: func() time.Time { return now }}
	c := manifestChange()
	raw, _ := json.Marshal(c)
	var seqs []int64
	err := mem.Atomic(ctx, func(tx store.Tx) error {
		if err := tx.PutChange(ctx, store.Change{ID: c.ID, App: c.App, Env: c.Env, State: c.State, Repo: c.Repo, Head: c.Head,
			PR: int(c.PR), ExpiresAt: now.Add(time.Hour), Record: raw}); err != nil {
			return err
		}
		w := evidence.Writer{Provider: evidence.Provider{Name: "argocd-agent", Version: "1"}}
		for _, applied := range []bool{false, true} {
			ev := store.Event{"ts": "2026-11-07T00:59:00Z", "tool": "deploy.outcome", "boundary": "deployment", "app": c.App,
				"target": "t", "principal": "hangar-prod/argocd/agent", "decision": nil, "tier": nil, "task_id": nil, "session": nil,
				"parent": nil, "agent": nil, "rule": nil, "args_sha256": nil, "result": "r",
				"change":  map[string]any{"id": c.ID, "tree": "sha256:" + treeRoot},
				"outcome": map[string]any{"applied": applied, "digests": map[string]any{"sha256": treeRoot}, "finished_at": "2026-11-07T00:58:59Z"}}
			r, err := tx.Append(ctx, ev, w)
			if err != nil {
				return err
			}
			n, _ := gate.SeqInt(r["seq"])
			seqs = append(seqs, n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	a.Notify(c.ID, seqs[0]) // the not-applied one is queued; the applied one arrives while it is processed
	ns.hook = func() { a.Notify(c.ID, seqs[1]) }
	a.Drain(ctx)
	if _, err := mem.Attestation(ctx, c.ID); err == nil {
		t.Fatal("attested in the same pass: the interleaving did not happen")
	}
	a.Drain(ctx) // still queued: the applied outcome is attested now
	if _, err := mem.Attestation(ctx, c.ID); err != nil || k.rekor.Logged() != 1 {
		t.Fatalf("the later applied outcome was lost: %v, logged %d", err, k.rekor.Logged())
	}
}

// seedOutcomes stores the manifest change and one deploy.outcome per entry of applied; it returns the seqs.
func seedOutcomes(t *testing.T, mem *memory.Store, now time.Time, applied ...bool) []int64 {
	t.Helper()
	ctx := context.Background()
	c := manifestChange()
	raw, _ := json.Marshal(c)
	var seqs []int64
	err := mem.Atomic(ctx, func(tx store.Tx) error {
		if err := tx.PutChange(ctx, store.Change{ID: c.ID, App: c.App, Env: c.Env, State: c.State, Repo: c.Repo, Head: c.Head,
			PR: int(c.PR), ExpiresAt: now.Add(time.Hour), Record: raw}); err != nil {
			return err
		}
		w := evidence.Writer{Provider: evidence.Provider{Name: "argocd-agent", Version: "1"}}
		for _, ap := range applied {
			ev := store.Event{"ts": "2026-11-07T00:59:00Z", "tool": "deploy.outcome", "boundary": "deployment", "app": c.App,
				"target": "t", "principal": "hangar-prod/argocd/agent", "decision": nil, "tier": nil, "task_id": nil, "session": nil,
				"parent": nil, "agent": nil, "rule": nil, "args_sha256": nil, "result": "r",
				"change":  map[string]any{"id": c.ID, "tree": "sha256:" + treeRoot},
				"outcome": map[string]any{"applied": ap, "digests": map[string]any{"sha256": treeRoot}, "finished_at": "2026-11-07T00:58:59Z"}}
			r, err := tx.Append(ctx, ev, w)
			if err != nil {
				return err
			}
			n, _ := gate.SeqInt(r["seq"])
			seqs = append(seqs, n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return seqs
}

// However many not-applied outcomes precede it, an applied one is attested.
func TestAnAppliedOutcomeIsNeverDroppedForTheCountOfEarlierOnes(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	now := time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC)
	k := newKeyless(t)
	a := &attest.Attestor{Backend: k.b, Store: mem, Gate: gate.NewService(gate.Config{}, mem, func() time.Time { return now }),
		Issuer: "clearance", Clock: func() time.Time { return now }}
	flags := make([]bool, 130)
	flags[129] = true
	seqs := seedOutcomes(t, mem, now, flags...)
	for _, s := range seqs {
		a.Notify("chg-9", s)
	}
	a.Drain(ctx)
	got, err := mem.Attestation(ctx, "chg-9")
	if err != nil || got.OutcomeSeq != seqs[129] {
		t.Fatalf("%+v %v", got, err)
	}
}

type failing struct{ calls int }

func (f *failing) Name() string { return "failing" }
func (f *failing) Sign(context.Context, []byte) (attest.Signed, error) {
	f.calls++
	return attest.Signed{}, errors.New("fulcio is down")
}

// The first retry is 5 s after the failure, the next 10 s (docs/core.md).
func TestTheRetryDelayDoublesFromFiveSeconds(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	now := time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC)
	b := &failing{}
	a := &attest.Attestor{Backend: b, Store: mem, Gate: gate.NewService(gate.Config{}, mem, func() time.Time { return now }),
		Issuer: "clearance", Clock: func() time.Time { return now }}
	seqs := seedOutcomes(t, mem, now, true)
	a.Notify("chg-9", seqs[0])
	t0 := now
	for _, step := range []struct {
		at    time.Duration
		calls int
	}{{0, 1}, {4 * time.Second, 1}, {5 * time.Second, 2}, {14 * time.Second, 2}, {15 * time.Second, 3}} {
		now = t0.Add(step.at)
		a.Drain(ctx)
		if b.calls != step.calls {
			t.Fatalf("at +%s: %d signings, want %d", step.at, b.calls, step.calls)
		}
	}
}
