package gate_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// G-ARGO-4: a registration without a pull request finds the cleared change for the same app, environment, cluster
// and tree, whatever commit and PR it was cleared under (Argo CD syncs the merge commit, not the PR head).
func TestAMergeCommitFindsTheClearedChangeByTree(t *testing.T) {
	f := newGate(t)
	cleared := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	if cleared.State != "cleared" {
		t.Fatal(cleared.State)
	}
	merge := strings.Repeat("9", 40)
	pushed := func(over map[string]any) map[string]any {
		b := map[string]any{"pr": json.Number("0"), "head": merge, "base": nil, "objects": imageBump}
		for k, v := range over {
			b[k] = v
		}
		return change(b)
	}
	got := f.register(t, "ci", pushed(nil))
	if got.ID != cleared.ID || got.State != "cleared" {
		t.Fatalf("want the cleared change %s, got %s (%s)", cleared.ID, got.ID, got.State)
	}
	if n := len(f.records(t, "deploy.request")); n != 1 {
		t.Fatalf("the lookup registers nothing: %d deploy.request records", n)
	}
	// another tree, environment or cluster is not covered: a new change, held for people (a pushed commit carries no checks)
	other := f.register(t, "ci", pushed(map[string]any{"treeDigest": strings.Repeat("ab", 32),
		"checks": map[string]any{"ci": "unknown", "provenance": "unknown", "render": "ok", "admission": "unknown"}}))
	if other.ID == cleared.ID || other.State != "holding" || other.PR != 0 {
		t.Fatalf("an uncovered tree is a new change: %s %s", other.ID, other.State)
	}
	if env := f.register(t, "ci", pushed(map[string]any{"env": "dev"})); env.ID == cleared.ID {
		t.Fatal("another environment found the change")
	}
	// a PR registration is never answered by tree
	if pr := f.register(t, "ci", change(map[string]any{"objects": imageBump, "pr": json.Number("8"), "head": strings.Repeat("7", 40)})); pr.ID == cleared.ID {
		t.Fatal("a registration with a PR found a change by tree")
	}
	// the clearance lapses with its TTL: the same tree is then a new change
	f.clock.advance(8 * 24 * time.Hour)
	if late := f.register(t, "ci", pushed(nil)); late.ID == cleared.ID {
		t.Fatal("an expired clearance answered")
	}
}
