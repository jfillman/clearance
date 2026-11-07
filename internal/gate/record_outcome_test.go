package gate_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
)

// Only a cleared change takes a provider's outcome (and so an attestation); for any other state the evidence is kept
// and the record says why it was not attached.
func TestOnlyAClearedChangeTakesAnOutcome(t *testing.T) {
	f := newGate(t)
	w := evidence.Writer{Provider: evidence.Provider{Name: "argocd-agent", Version: "1"}}
	post := func(id string) map[string]any {
		t.Helper()
		ev := map[string]any{"ts": "2026-11-07T00:59:00Z", "tool": "deploy.outcome", "boundary": "deployment", "app": "gate-api",
			"target": "t", "principal": "p", "result": "applied", "change": map[string]any{"id": id},
			"release": map[string]any{"id": "r1"}, "outcome": map[string]any{"applied": true, "digests": map[string]any{"sha256": strings.Repeat("c", 64)}}}
		rec, err := f.svc.RecordOutcome(f.ctx, ev, w)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	held := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("1", 40)}))
	denied := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("2", 40), "pr": 8}))
	if _, err := f.svc.Deny(f.ctx, principals["erin"], denied.ID, "no", ""); err != nil {
		t.Fatal(err)
	}
	expired := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("3", 40), "pr": 9}))
	f.clock.advance(7*24*time.Hour + time.Second)
	if _, err := f.svc.Expire(f.ctx); err != nil {
		t.Fatal(err)
	}
	held = f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("4", 40), "pr": 10}))
	for name, c := range map[string]string{"held": held.ID, "denied": denied.ID, "expired": expired.ID} {
		rec := post(c)
		if rec["unattached"] == nil || !strings.Contains(rec["unattached"].(string), "not cleared") {
			t.Errorf("%s: the record does not say why: %v", name, rec["unattached"])
		}
		if got := f.get(t, c); got.Outcome != nil {
			t.Errorf("%s (%s): outcome attached: %+v", name, got.State, got.Outcome)
		}
	}
	if n := len(f.records(t, "deploy.outcome")); n != 3 {
		t.Errorf("the evidence is kept: %d outcome records", n)
	}
	cleared := f.register(t, "ci", change(map[string]any{"objects": nil, "head": strings.Repeat("5", 40), "pr": 11}))
	if st := f.get(t, cleared.ID).State; st != "cleared" {
		t.Fatalf("the control change is %s, not cleared", st)
	}
	if rec := post(cleared.ID); rec["unattached"] != nil || f.get(t, cleared.ID).Outcome == nil {
		t.Errorf("a cleared change takes its outcome: %v", rec["unattached"])
	}
}
