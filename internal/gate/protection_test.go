package gate_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
)

func TestNormalizePairs(t *testing.T) {
	got, err := gate.NormalizePairs([]gate.ProtectedPair{{"web", "prod"}, {"api", "prod"}, {"api", "dev"}})
	if err != nil || len(got) != 3 || got[0] != (gate.ProtectedPair{"api", "dev"}) || got[2] != (gate.ProtectedPair{"web", "prod"}) {
		t.Fatalf("sorted by app then env: %v %v", got, err)
	}
	for name, in := range map[string][]gate.ProtectedPair{
		"upper":     {{"Web", "prod"}},
		"empty app": {{"", "prod"}},
		"slash":     {{"a/b", "prod"}},
		"twice":     {{"a", "p"}, {"a", "p"}},
	} {
		if _, err := gate.NormalizePairs(in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := gate.NormalizePairs(make([]gate.ProtectedPair, gate.MaxProtectedPairs+1)); err == nil {
		t.Error("over the cap was accepted")
	}
}

// brokenProtection is a store that cannot read the reported pairs.
type brokenProtection struct{ store.Store }

func (brokenProtection) Protections(context.Context) ([]store.ProtectionSet, error) {
	return nil, errors.New("database unreachable")
}

// A store that cannot be read counts as protected: nothing is cleared at tier 0 because the core could not look.
func TestProtectionReadFailureFailsClosed(t *testing.T) {
	svc := gate.NewService(gate.Config{Protected: []string{"hangar-prod/*"}}, brokenProtection{memory.New()}, time.Now)
	if !svc.ProtectsApp(context.Background(), "hangar-dev", "web", "dev") || !svc.ProtectsEnv(context.Background(), "hangar-dev", "dev") {
		t.Fatal("an unreadable report was read as unprotected")
	}
	if svc.StaticProtects("hangar-dev", "dev") {
		t.Fatal("the list does not name hangar-dev/dev")
	}
}

func TestProtectsAppAndEnv(t *testing.T) {
	st := memory.New()
	svc := gate.NewService(gate.Config{Protected: []string{"hangar-prod/*"}}, st, time.Now)
	put := func(cluster, doc string) {
		if err := st.Atomic(context.Background(), func(tx store.Tx) error {
			return tx.PutProtection(context.Background(), store.ProtectionSet{Cluster: cluster, Digest: "d", Doc: []byte(doc)})
		}); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	if svc.ProtectsApp(ctx, "hangar-dev", "web", "dev") || svc.ProtectsEnv(ctx, "hangar-dev", "dev") {
		t.Fatal("nothing reported, not listed")
	}
	put("hangar-dev", `[{"app":"web","env":"dev"}]`)
	if !svc.ProtectsApp(ctx, "hangar-dev", "web", "dev") || svc.ProtectsApp(ctx, "hangar-dev", "api", "dev") ||
		svc.ProtectsApp(ctx, "hangar-dev", "web", "staging") || svc.ProtectsApp(ctx, "hangar-x", "web", "dev") {
		t.Fatal("a report protects exactly its cluster's app/env pair")
	}
	if !svc.ProtectsEnv(ctx, "hangar-dev", "dev") || svc.ProtectsEnv(ctx, "hangar-dev", "staging") {
		t.Fatal("an environment is protected when a pair in it is")
	}
	put("hangar-dev", `[]`)
	if svc.ProtectsApp(ctx, "hangar-dev", "web", "dev") {
		t.Fatal("an explicit empty report removes the pair")
	}
	put("hangar-dev", `"not a list"`) // cannot happen through the route; the gate must still fail closed
	if !svc.ProtectsApp(ctx, "hangar-dev", "web", "dev") {
		t.Fatal("an unreadable stored set was read as unprotected")
	}
}
