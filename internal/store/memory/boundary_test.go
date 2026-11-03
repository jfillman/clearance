package memory

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/storetest"
)

// TestV0ChainExtendedWithV1 loads a v0-draft chain and appends v1 records through the store: one chain across the
// boundary. By default the chain is the python-chain.jsonl fixture; with CLEARANCE_LIVE_CHAIN set to a dump of a
// real chain (psql -Atc "select record::text from clearance_evidence order by seq") it is that copy, and with
// CLEARANCE_LIVE_OUT set the extended chain is written there for `python_chain.py verify` and
// `clearance chain verify --file`, and out+".projected" (every record through evidence.Project) (docs/evidence.md, "Across the v0 to v1 boundary").
func TestV0ChainExtendedWithV1(t *testing.T) {
	path := storetest.EvidenceTestdata("python-chain.jsonl")
	if p := os.Getenv("CLEARANCE_LIVE_CHAIN"); p != "" {
		path = p
	}
	v0 := storetest.ReadJSONL(t, path)
	s, err := Load(v0)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	w := evidence.Writer{Provider: evidence.Provider{Name: "clearance", Version: "0.0.0-test"}}
	events := []store.Event{
		{"ts": "2026-11-03T07:00:00Z", "tool": "session.open", "principal": "autopilot-runs/nightly-reviewer",
			"agent": "nightly-reviewer", "decision": "allow", "args_sha256": canon.SHA256Hex([]byte("{}")), "intent": "nightly review"},
		{"ts": "2026-11-03T07:00:01Z", "tool": "deploy.clear", "boundary": "deployment", "decision": "allow", "app": "gate-api",
			"change": map[string]any{"app": "gate-api", "env": "prod", "tree": string(bytes.Repeat([]byte("c"), 64)), "head": string(bytes.Repeat([]byte("a"), 40))}},
	}
	if err := s.Atomic(ctx, func(tx store.Tx) error {
		for _, e := range events {
			if _, err := tx.Append(ctx, e, w); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	recs, err := s.Records(ctx, 0, len(v0)+len(events))
	if err != nil {
		t.Fatal(err)
	}
	if ok, bad := evidence.Verify(recs); !ok || len(recs) != len(v0)+len(events) {
		t.Fatalf("extended chain: ok=%v bad=%d n=%d", ok, bad, len(recs))
	}
	if recs[len(v0)-1]["schema"] != evidence.SchemaV0 || recs[len(v0)]["schema"] != evidence.Schema ||
		recs[len(v0)]["prev_hash"] != recs[len(v0)-1]["hash"] {
		t.Fatal("the boundary is not where it should be")
	}
	if out := os.Getenv("CLEARANCE_LIVE_OUT"); out != "" {
		var b bytes.Buffer
		for _, r := range recs {
			c, _ := canon.Canonical(r)
			b.Write(c)
			b.WriteByte('\n')
		}
		if err := os.WriteFile(out, b.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		// And every record as clearance-api serves it (evidence.Project), to compare with audit.project.
		b.Reset()
		for _, r := range recs {
			c, _ := canon.Canonical(evidence.Project(r))
			b.Write(c)
			b.WriteByte('\n')
		}
		if err := os.WriteFile(out+".projected", b.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
