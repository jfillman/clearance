package memory

import (
	"context"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T, seed []store.Record) store.Store {
		s, err := Load(seed)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	})
}

func TestLoadRefusesABrokenChain(t *testing.T) {
	recs := storetest.ReadJSONL(t, storetest.EvidenceTestdata("python-chain.jsonl"))
	recs[1]["note"] = "edited"
	if _, err := Load(recs); err == nil {
		t.Fatal("Load accepted an edited chain")
	}
}

func BenchmarkAppend(b *testing.B) {
	s := New()
	ctx := context.Background()
	ev := store.Event{"ts": "2026-11-02T00:00:00Z", "tool": "model.call", "agent": "a", "principal": "ns/a",
		"decision": "allow", "rule": nil, "session": "s-1", "task_id": "t-1", "args_sha256": strings.Repeat("a", 64)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := s.Atomic(ctx, func(tx store.Tx) error { _, err := tx.Append(ctx, ev); return err }); err != nil {
			b.Fatal(err)
		}
	}
}
