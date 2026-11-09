package gate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"

	"github.com/jfillman/clearance/internal/ledger"
	"github.com/jfillman/clearance/internal/store"
)

// The Done-when line end to end: a witness outage during a tier 3 change makes the change wait, the assurance
// state shows it, and the change clears once the witness is back and the evidence is checkpointed.
func TestWitnessOutageMakesATier3ChangeWait(t *testing.T) {
	const origin = "gate-test-ledger"
	skey, _, _, err := ledger.GenerateKey(origin)
	if err != nil {
		t.Fatal(err)
	}
	logSigner, logVerifier, err := f_note.NewEd25519SignerVerifier(skey)
	if err != nil {
		t.Fatal(err)
	}
	wkey, _, wcosig, err := ledger.GenerateKey("gate-test-witness")
	if err != nil {
		t.Fatal(err)
	}
	wsigner, err := f_note.NewSignerForCosignatureV1(wkey)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.NewWitness(wsigner, []note.Verifier{logVerifier}, "")
	if err != nil {
		t.Fatal(err)
	}
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(rw, "down", http.StatusServiceUnavailable)
			return
		}
		w.ServeHTTP(rw, r)
	}))
	defer srv.Close()

	f := newGate(t)
	ctx := f.ctx
	cfg := ledger.Config{
		Log: ledger.LogConfig{Dir: t.TempDir(), Key: ledger.LogKey{Signer: logSigner, Verifiers: []note.Verifier{logVerifier}},
			Policy:             []byte(fmt.Sprintf("witness lab %s %s\nquorum lab\n", wcosig, srv.URL)),
			CheckpointInterval: 200 * time.Millisecond, WitnessTimeout: 2 * time.Second, BatchAge: 20 * time.Millisecond},
		Tier3Wait: true, StallAfter: 5 * time.Second, PollEvery: 50 * time.Millisecond,
	}
	f.register(t, "ci", change(map[string]any{"pr": json.Number("8")})) // some evidence already on the chain
	svc, err := ledger.Open(ctx, cfg, f.st, f.st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close(context.Background()) //nolint:errcheck
	f.svc.Evidence = svc
	until := func(what string, cond func() bool) {
		t.Helper()
		for end := time.Now().Add(30 * time.Second); !cond(); time.Sleep(60 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("timed out waiting for %s: %+v", what, svc.Status(ctx))
			}
			svc.Step(ctx)
		}
	}
	until("the chain to be witnessed", func() bool {
		seq, _, _ := f.st.Head(ctx)
		return svc.Status(ctx).Witnessed == seq+1
	})

	cid := f.register(t, "ci", change(map[string]any{"objects": secret})).ID // tier 3
	if out, err := f.svc.Clear(ctx, principals["erin"], cid, ""); err != nil || out.State != "holding" {
		t.Fatal(out, err)
	}
	down.Store(true)
	until("the outage to show", func() bool { return svc.Status(ctx).State == ledger.StateWitnessUnavailable })
	out, err := f.svc.Clear(ctx, principals["root"], cid, "")
	if err != nil || out.State != "holding" || out.EvidenceWait == nil || out.EvidenceWait.Assurance != "waiting-for-checkpoint" {
		t.Fatalf("the change should wait: %+v %v", out, err)
	}
	if st := svc.Status(ctx); !st.Holding || st.Witnessed >= st.Chain {
		t.Fatalf("the assurance state does not show the outage: %+v", st)
	}
	seq, _, _ := f.st.Head(ctx)
	if a, _ := f.st.Assurance(ctx, seq); a != store.AssuranceRecorded {
		t.Fatalf("the waiting change's own record is %s", a)
	}

	down.Store(false)
	until("the change to clear", func() bool {
		svc.Step(ctx)
		ids, err := f.svc.SettleEvidence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return len(ids) == 1 || f.get(t, cid).State == "cleared"
	})
	if got := f.get(t, cid); got.State != "cleared" || got.EvidenceWait != nil {
		t.Fatalf("%+v", got)
	}
}
