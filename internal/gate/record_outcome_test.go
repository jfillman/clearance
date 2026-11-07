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
	postFor := func(id, app, cluster string) map[string]any {
		t.Helper()
		ev := map[string]any{"ts": "2026-11-07T00:59:00Z", "tool": "deploy.outcome", "boundary": "deployment", "app": app,
			"destination": map[string]any{"cluster": cluster, "environment": "prod"},
			"target":      "t", "principal": "p", "result": "applied", "change": map[string]any{"id": id},
			"release": map[string]any{"id": "r1"}, "outcome": map[string]any{"applied": true, "digests": map[string]any{"sha256": strings.Repeat("c", 64)}}}
		rec, err := f.svc.RecordOutcome(f.ctx, ev, w)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	post := func(id string) map[string]any { return postFor(id, "gate-api", "hangar-prod") }
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
	if got := f.get(t, cleared.ID).Outcome.Provider; got != "argocd-agent" {
		t.Errorf("the outcome's provider is the envelope's name: %q", got)
	}
	// A provider naming another app's (or another cluster's) change attaches nothing, and the record says so.
	for name, rec := range map[string]map[string]any{
		"another app":     postFor(cleared.ID, "other-app", "hangar-prod"),
		"another cluster": postFor(cleared.ID, "gate-api", "hangar-dev"),
	} {
		if u, _ := rec["unattached"].(string); !strings.Contains(u, "not the change's") {
			t.Errorf("%s: %v", name, rec["unattached"])
		}
	}
	other := f.register(t, "ci", change(map[string]any{"objects": nil, "head": strings.Repeat("6", 40), "pr": 12}))
	if rec := postFor(other.ID, "other-app", "hangar-prod"); rec["unattached"] == nil || f.get(t, other.ID).Outcome != nil {
		t.Errorf("an outcome for another app attached to a cleared change: %+v", f.get(t, other.ID).Outcome)
	}
	// A malformed change id is marked too (the signer would retry it), unlike an outcome that names no id at all.
	if rec := postFor("not-a-change-id", "gate-api", "hangar-prod"); rec["unattached"] != "malformed change id: the outcome is recorded, not attached" {
		t.Errorf("malformed change id: %v", rec["unattached"])
	}
	// An unknown change id: recorded, marked, so the signer does not retry it.
	if rec := postFor("ch-0000000000000000", "gate-api", "hangar-prod"); rec["unattached"] != "no such change: the outcome is recorded, not attached" {
		t.Errorf("unknown change: %v", rec["unattached"])
	}
}

// A deploy.outcome naming a cleared terraform-plan change is recorded and marked: the plan's outcome goes through
// POST /v1/clearances/{id}/outcome, and the signer must not attest it from this record.
func TestAProviderOutcomeForATerraformPlanChangeIsNotAttached(t *testing.T) {
	f := newGate(t)
	out := f.register(t, "ci", tfChange(plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), nil))
	if out.State != "cleared" {
		t.Fatal(out.State)
	}
	ev := map[string]any{"ts": "2026-11-07T00:59:00Z", "tool": "deploy.outcome", "boundary": "deployment", "app": out.App,
		"destination": map[string]any{"environment": out.Env}, "target": "t", "principal": "p", "result": "applied",
		"change": map[string]any{"id": out.ID}, "outcome": map[string]any{"applied": true}}
	rec, err := f.svc.RecordOutcome(f.ctx, ev, evidence.Writer{Provider: evidence.Provider{Name: "p", Version: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := rec["unattached"].(string); !strings.Contains(u, "POST /v1/clearances/{id}/outcome") || f.get(t, out.ID).Outcome != nil {
		t.Fatalf("unattached %q outcome %+v", u, f.get(t, out.ID).Outcome)
	}
}
