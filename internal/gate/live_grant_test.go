package gate_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/token"
)

func (f *fixture) applyOutcome(t *testing.T, id string) {
	t.Helper()
	ev := map[string]any{"ts": "2026-11-10T14:30:00Z", "tool": "deploy.outcome", "boundary": "deployment", "app": "gate-api",
		"destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"},
		"target":      "t", "principal": "p", "result": "applied", "change": map[string]any{"id": id},
		"release": map[string]any{"id": "r1"}, "outcome": map[string]any{"applied": true, "digests": map[string]any{"sha256": strings.Repeat("c", 64)}}}
	w := evidence.Writer{Provider: evidence.Provider{Name: "argocd-agent", Version: "1"}}
	if _, err := f.svc.RecordOutcome(f.ctx, ev, w); err != nil {
		t.Fatal(err)
	}
}

func feedIDs(feed *token.Feed) string {
	var ids []string
	for _, e := range feed.Entries {
		ids = append(ids, e.ChangeID)
	}
	return strings.Join(ids, ",")
}

// An applied change stays in the grant feed (its stamps stay valid) after a new head supersedes it, until a later
// change for the same app, environment and cluster applies; its token is no clearance in the meantime.
func TestAnAppliedChangeStaysValidUntilItsSuccessorApplies(t *testing.T) {
	f, ks := withTokens(t)
	a := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	if a.State != "cleared" {
		t.Fatalf("A is %s", a.State)
	}
	f.applyOutcome(t, a.ID)
	f.clock.advance(time.Minute)
	b := f.register(t, "ci", change(map[string]any{"objects": secret, "head": strings.Repeat("e", 40)})) // holds for people
	if b.State != "holding" {
		t.Fatalf("B is %s", b.State)
	}
	if got := f.get(t, a.ID); got.State != "superseded" {
		t.Fatalf("A is %s", got.State)
	}
	feed, toks := f.feed(t, ks, "hangar-prod", 0)
	if feedIDs(feed) != a.ID || len(toks) != 1 {
		t.Fatalf("A's stamps stay valid while B holds: feed %q", feedIDs(feed))
	}
	if len(f.records(t, "deploy.revoke")) != 0 {
		t.Fatal("no revoke is recorded while A is live")
	}
	// The token is no clearance: not served by the clearance read, and a replay by the nonce check.
	if _, tk, err := f.svc.Clearance(f.ctx, a.ID); err != nil || tk != nil {
		t.Fatalf("a superseded change serves no token: %v %v", tk, err)
	}
	if _, err := token.Verify(f.ctx, f.token(t, a.ID).Envelope, ks, token.Options{Issuer: "clearance-test", Now: f.clock.now,
		Nonces: f.svc}); err == nil {
		t.Fatal("the nonce check accepts a superseded change's token")
	}
	// It is kept fresh, past its horizon too, while B holds.
	f.clock.advance(8 * 24 * time.Hour)
	if _, _, err := f.svc.Refresh(f.ctx); err != nil {
		t.Fatal(err)
	}
	if feed, _ = f.feed(t, ks, "hangar-prod", feed.Seq); feedIDs(feed) != a.ID {
		t.Fatalf("A is kept live: %q", feedIDs(feed))
	}
	// A later change applies: A's stamps stop being valid.
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump, "head": strings.Repeat("d", 40)}))
	if c.State != "cleared" {
		t.Fatalf("C is %s", c.State)
	}
	if feed, _ = f.feed(t, ks, "hangar-prod", feed.Seq); len(feed.Entries) != 2 {
		t.Fatalf("C is cleared, A is still live until C applies: %q", feedIDs(feed))
	}
	f.applyOutcome(t, c.ID)
	feed, _ = f.feed(t, ks, "hangar-prod", feed.Seq)
	if feedIDs(feed) != c.ID {
		t.Fatalf("after C applied: %q", feedIDs(feed))
	}
	if n := len(f.records(t, "deploy.revoke")); n != 1 {
		t.Fatalf("%d revokes, want A's", n)
	}
}

// A change that was cleared but never applied is revoked when a new head supersedes it, as before.
func TestAClearedUnappliedChangeIsNotKeptLive(t *testing.T) {
	f, ks := withTokens(t)
	a := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	f.clock.advance(time.Minute)
	f.register(t, "ci", change(map[string]any{"objects": secret, "head": strings.Repeat("e", 40)}))
	if got := f.get(t, a.ID); got.State != "superseded" {
		t.Fatalf("A is %s", got.State)
	}
	if feed, _ := f.feed(t, ks, "hangar-prod", 0); len(feed.Entries) != 0 {
		t.Fatalf("an unapplied A is not valid: %q", feedIDs(feed))
	}
	if n := len(f.records(t, "deploy.revoke")); n != 1 {
		t.Fatalf("%d revokes", n)
	}
}
