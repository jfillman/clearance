package gate_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/gate"
)

// holdKnob is an EvidenceGate a test turns on and off.
type holdKnob struct{ on atomic.Bool }

func (h *holdKnob) Hold(context.Context) (bool, string) {
	if h.on.Load() {
		return true, "witness-unavailable: no witness answered"
	}
	return false, ""
}

func TestATier3ChangeWaitsWhileEvidenceCannotBeCheckpointed(t *testing.T) {
	f := newGate(t)
	knob := &holdKnob{}
	f.svc.Evidence = knob
	cid := f.register(t, "ci", change(map[string]any{"objects": secret})).ID // tier 3: an owner and an outsider
	if out, err := f.svc.Clear(f.ctx, principals["erin"], cid, ""); err != nil || out.State != "holding" {
		t.Fatal(out, err)
	}

	knob.on.Store(true) // the witness goes away before the last approval
	out, err := f.svc.Clear(f.ctx, principals["root"], cid, "")
	if err != nil || out.State != "holding" || out.EvidenceWait == nil || out.EvidenceWait.Assurance != gate.AssuranceWaiting ||
		!strings.Contains(out.EvidenceWait.Reason, "witness-unavailable") || len(out.Approvals) != 2 {
		t.Fatalf("the change should wait with both approvals recorded: %+v %v", out, err)
	}
	recs := f.records(t, "deploy.clear")
	last := recs[len(recs)-1]
	if res, _ := last["result"].(string); !strings.Contains(res, "waiting") || last["evidence"] == nil {
		t.Fatalf("the record does not say it waited: %v", last)
	}
	if n, err := f.svc.SettleEvidence(f.ctx); err != nil || len(n) != 0 {
		t.Fatalf("settled while the ledger still holds: %v %v", n, err)
	}
	if got := f.get(t, cid); got.State != "holding" {
		t.Fatalf("state %s", got.State)
	}

	knob.on.Store(false) // the ledger recovers
	ids, err := f.svc.SettleEvidence(f.ctx)
	if err != nil || len(ids) != 1 || ids[0] != cid {
		t.Fatalf("settle: %v %v", ids, err)
	}
	got := f.get(t, cid)
	if got.State != "cleared" || got.EvidenceWait != nil || got.ClearedBy == nil {
		t.Fatalf("%+v", got)
	}
	if again, _ := f.svc.SettleEvidence(f.ctx); len(again) != 0 {
		t.Fatal("settled twice")
	}
}

func TestEvidenceWaitOnlyConcernsTier3AndALedger(t *testing.T) {
	// A lower tier clears whatever the ledger says: the knob is for tier 3.
	f := newGate(t)
	knob := &holdKnob{}
	knob.on.Store(true)
	f.svc.Evidence = knob
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas})).ID
	if out, err := f.svc.Clear(f.ctx, principals["erin"], cid, ""); err != nil || out.State != "cleared" || out.EvidenceWait != nil {
		t.Fatalf("%+v %v", out, err)
	}
	// And with no ledger at all a tier 3 change clears as it always did.
	g := newGate(t)
	c3 := g.register(t, "ci", change(map[string]any{"objects": secret})).ID
	_, _ = g.svc.Clear(g.ctx, principals["erin"], c3, "")
	if out, err := g.svc.Clear(g.ctx, principals["root"], c3, ""); err != nil || out.State != "cleared" {
		t.Fatalf("%+v %v", out, err)
	}
}

// waiting registers a tier 3 change and gets it to wait on the ledger: both approvals in, the knob on.
func waiting(t *testing.T, f *fixture, head string) string {
	t.Helper()
	knob := &holdKnob{}
	f.svc.Evidence = knob
	body := map[string]any{"objects": secret}
	if head != "" {
		body["head"] = head
	}
	cid := f.register(t, "ci", change(body)).ID
	if _, err := f.svc.Clear(f.ctx, principals["erin"], cid, ""); err != nil {
		t.Fatal(err)
	}
	knob.on.Store(true)
	out, err := f.svc.Clear(f.ctx, principals["root"], cid, "")
	if err != nil || out.EvidenceWait == nil {
		t.Fatalf("the change should wait: %+v %v", out, err)
	}
	return cid
}

func requireNotWaiting(t *testing.T, f *fixture, cid, state string) {
	t.Helper()
	got := f.get(t, cid)
	if got.State != state || got.EvidenceWait != nil {
		t.Fatalf("want %s with no evidence_wait, got %s with %+v", state, got.State, got.EvidenceWait)
	}
}

func TestAChangeThatEndsHoldingStopsWaitingForTheLedger(t *testing.T) {
	t.Run("denied", func(t *testing.T) {
		f := newGate(t)
		cid := waiting(t, f, "")
		if _, err := f.svc.Deny(f.ctx, principals["erin"], cid, "no", ""); err != nil {
			t.Fatal(err)
		}
		requireNotWaiting(t, f, cid, "denied")
	})
	t.Run("expired", func(t *testing.T) {
		f := newGate(t)
		cid := waiting(t, f, "")
		f.clock.advance(31 * 24 * time.Hour)
		if ids, err := f.svc.Expire(f.ctx); err != nil || len(ids) != 1 {
			t.Fatal(ids, err)
		}
		requireNotWaiting(t, f, cid, "expired")
	})
	t.Run("superseded", func(t *testing.T) {
		f := newGate(t)
		cid := waiting(t, f, "")
		f.register(t, "ci", change(map[string]any{"objects": secret, "head": strings.Repeat("2", 40)}))
		requireNotWaiting(t, f, cid, "superseded")
	})
}
