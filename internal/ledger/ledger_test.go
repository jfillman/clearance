package ledger_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	f_log "github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/ledger"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
)

const origin = "clearance-test-ledger"

var bg = context.Background()

// keyPair is a throwaway key made in the test: no real key material is read, written or printed.
type keyPair struct {
	signer note.Signer
	vkey   note.Verifier
	skey   string
	cosig  string // the vkey as a tlog-cosignature/v1 verifier key
}

func newKey(t testing.TB, name string) keyPair {
	t.Helper()
	skey, vkey, cosig, err := ledger.GenerateKey(name)
	if err != nil {
		t.Fatal(err)
	}
	s, v, err := f_note.NewEd25519SignerVerifier(skey)
	if err != nil {
		t.Fatal(err)
	}
	_ = vkey
	return keyPair{signer: s, vkey: v, skey: skey, cosig: cosig}
}

// lab is an in-process witness (the real Witness behind httptest) with a switch that makes it unreachable.
type lab struct {
	t       testing.TB
	witness *ledger.Witness
	srv     *httptest.Server
	down    atomic.Bool
	policy  []byte
}

func newLab(t testing.TB, logs ...keyPair) *lab {
	t.Helper()
	wk := newKey(t, "lab-witness")
	ws, err := f_note.NewSignerForCosignatureV1(wk.skey)
	if err != nil {
		t.Fatal(err)
	}
	var vs []note.Verifier
	for _, l := range logs {
		vs = append(vs, l.vkey)
	}
	w, err := ledger.NewWitness(ws, vs, "")
	if err != nil {
		t.Fatal(err)
	}
	l := &lab{t: t, witness: w}
	l.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if l.down.Load() {
			http.Error(rw, "down", http.StatusServiceUnavailable)
			return
		}
		w.ServeHTTP(rw, r)
	}))
	t.Cleanup(l.srv.Close)
	l.policy = []byte(fmt.Sprintf("witness lab %s %s\nquorum lab\n", wk.cosig, l.srv.URL))
	return l
}

func newChain(t testing.TB) *memory.Store {
	st := memory.New()
	t.Cleanup(st.Close)
	return st
}

func appendN(t testing.TB, st *memory.Store, tag string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := st.Atomic(bg, func(tx store.Tx) error {
			_, err := tx.Append(bg, store.Event{"tool": "t", "tag": tag, "i": i}, evidence.Core("test"))
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func (l *lab) config(dir string, k ledger.LogKey) ledger.Config {
	return ledger.Config{
		Log: ledger.LogConfig{Dir: dir, Key: k, Policy: l.policy, CheckpointInterval: 200 * time.Millisecond,
			WitnessTimeout: 2 * time.Second, BatchAge: 20 * time.Millisecond},
		Tier3Wait: true, StallAfter: 3 * time.Second, PollEvery: 50 * time.Millisecond,
	}
}

func logKey(k keyPair, retired ...keyPair) ledger.LogKey {
	lk := ledger.LogKey{Signer: k.signer, Verifiers: []note.Verifier{k.vkey}}
	for _, r := range retired {
		lk.Verifiers = append(lk.Verifiers, r.vkey)
	}
	return lk
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// run steps the service until cond holds.
func run(t testing.TB, s *ledger.Service, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s; status %+v", what, s.Status(bg))
		}
		s.Step(bg)
		time.Sleep(60 * time.Millisecond)
	}
}

func witnessedAll(s *ledger.Service, st *memory.Store) func() bool {
	return func() bool {
		seq, _, _ := st.Head(bg)
		return s.Status(bg).Witnessed == seq+1
	}
}

func assurance(t testing.TB, st store.Reader, seq int64) string {
	t.Helper()
	a, err := st.Assurance(bg, seq)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func closeSvc(t testing.TB, s *ledger.Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(bg, 10*time.Second)
	defer cancel()
	_ = s.Close(ctx)
}

func TestAssuranceMovesToCheckpointed(t *testing.T) {
	k := newKey(t, origin)
	lab := newLab(t, k)
	st := newChain(t)
	appendN(t, st, "a", 5)
	s, err := ledger.Open(bg, lab.config(t.TempDir(), logKey(k)), st, st, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer closeSvc(t, s)
	if a := assurance(t, st, 4); a != store.AssuranceRecorded {
		t.Fatalf("before any checkpoint: %s", a)
	}
	run(t, s, "5 records witnessed", witnessedAll(s, st))
	for i := int64(0); i < 5; i++ {
		if a := assurance(t, st, i); a != store.AssuranceCheckpointed {
			t.Fatalf("record %d: %s", i, a)
		}
	}
	appendN(t, st, "b", 3)
	if a := assurance(t, st, 7); a != store.AssuranceRecorded {
		t.Fatalf("a new record is recorded-not-checkpointed, got %s", a)
	}
	run(t, s, "8 records witnessed", witnessedAll(s, st))
	if a := assurance(t, st, 7); a != store.AssuranceCheckpointed {
		t.Fatalf("record 7: %s", a)
	}
	cp, err := st.LedgerCheckpoint(bg)
	if err != nil || cp.Size != 8 {
		t.Fatalf("stored checkpoint %+v, %v", cp, err)
	}
	// The stored note carries the log's signature and the witness's countersignature.
	parsed, err := s.Log().ParseCheckpoint(cp.Note)
	if err != nil || !parsed.Witnessed || len(parsed.Cosigned) != 1 {
		t.Fatalf("stored checkpoint does not verify as witnessed: %+v, %v", parsed, err)
	}
	if got := s.Status(bg); got.State != ledger.StateCurrent || got.Holding {
		t.Fatalf("status %+v", got)
	}
}

// Done-when: truncating the ledger and re-signing is refused by the witness.
func TestTruncatedLedgerResignedIsRefused(t *testing.T) {
	k := newKey(t, origin)
	lab := newLab(t, k)
	st := newChain(t)
	appendN(t, st, "real", 8)
	s, err := ledger.Open(bg, lab.config(t.TempDir(), logKey(k)), st, st, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	run(t, s, "8 records witnessed", witnessedAll(s, st))
	closeSvc(t, s)
	if lab.witness.Size(origin) != 8 {
		t.Fatalf("the witness holds %d", lab.witness.Size(origin))
	}

	t.Run("a smaller tree signed with the real key", func(t *testing.T) {
		// The attacker has the log key (the strongest case: the log's own signature proves nothing).
		bad := newChain(t)
		appendN(t, bad, "real", 3)
		s2, err := ledger.Open(bg, lab.config(t.TempDir(), logKey(k)), bad, bad, nil, quiet())
		if err != nil {
			t.Fatal(err)
		}
		defer closeSvc(t, s2)
		run(t, s2, "the witness's refusal", func() bool { return s2.Status(bg).State == ledger.StateWitnessRejected })
		if _, err := bad.LedgerCheckpoint(bg); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a refused checkpoint was recorded: %v", err)
		}
		if a := assurance(t, bad, 2); a != store.AssuranceRecorded {
			t.Fatalf("assurance %s", a)
		}
		if lab.witness.Size(origin) != 8 {
			t.Fatalf("the witness moved to %d", lab.witness.Size(origin))
		}
		if hold, why := s2.Hold(bg); !hold || !strings.Contains(why, "truncated") {
			t.Fatalf("hold = %v %q", hold, why)
		}
	})

	t.Run("a different tree of the same size", func(t *testing.T) {
		fork := newChain(t)
		appendN(t, fork, "rewritten", 8)
		s3, err := ledger.Open(bg, lab.config(t.TempDir(), logKey(k)), fork, fork, nil, quiet())
		if err != nil {
			t.Fatal(err)
		}
		defer closeSvc(t, s3)
		run(t, s3, "the witness's refusal", func() bool { return s3.Status(bg).State == ledger.StateWitnessRejected })
		if _, err := fork.LedgerCheckpoint(bg); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a refused checkpoint was recorded: %v", err)
		}
	})

	t.Run("the protocol", func(t *testing.T) {
		// A checkpoint of 3 records, validly signed, sent as an update from the 8 the witness knows, and from 0.
		root := rfc6962.DefaultHasher.EmptyRoot()
		cpText := f_log.Checkpoint{Origin: origin, Size: 3, Hash: root}.Marshal()
		signed, err := note.Sign(&note.Note{Text: string(cpText)}, k.signer)
		if err != nil {
			t.Fatal(err)
		}
		for _, old := range []int{8, 0, 3} {
			resp := post(t, lab.srv.URL, fmt.Sprintf("old %d\n\n%s", old, signed))
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("old %d: the witness cosigned a truncation", old)
			}
		}
		// An unknown log key is refused too.
		other := newKey(t, origin)
		signed2, _ := note.Sign(&note.Note{Text: string(cpText)}, other.signer)
		if resp := post(t, lab.srv.URL, fmt.Sprintf("old 0\n\n%s", signed2)); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a foreign key: %d", resp.StatusCode)
		}
		if lab.witness.Size(origin) != 8 {
			t.Fatalf("the witness moved to %d", lab.witness.Size(origin))
		}
	})
}

func post(t testing.TB, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url+"/add-checkpoint", "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// Done-when: rotating the signing key leaves old entries verifiable.
func TestKeyRotationKeepsOldEntriesVerifiable(t *testing.T) {
	k1, k2 := newKey(t, origin), newKey(t, origin)
	lab := newLab(t, k1, k2) // the witness trusts both keys under the log's name
	st := newChain(t)
	dir := t.TempDir()
	appendN(t, st, "old", 5)
	s, err := ledger.Open(bg, lab.config(dir, logKey(k1)), st, st, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	run(t, s, "5 witnessed", witnessedAll(s, st))
	oldCP, err := st.LedgerCheckpoint(bg)
	if err != nil {
		t.Fatal(err)
	}
	closeSvc(t, s)

	// Rotate: the new key signs from here; the old vkey stays in the verifier list.
	appendN(t, st, "new", 3)
	s2, err := ledger.Open(bg, lab.config(dir, logKey(k2, k1)), st, st, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer closeSvc(t, s2)
	run(t, s2, "8 witnessed under the new key", witnessedAll(s2, st))

	// The checkpoint the old key signed still verifies, and its entries are under the new checkpoint.
	cp1, err := s2.Log().ParseCheckpoint(oldCP.Note)
	if err != nil || !cp1.Witnessed || cp1.Size != 5 {
		t.Fatalf("the old checkpoint no longer verifies: %+v, %v", cp1, err)
	}
	for seq := int64(0); seq < 8; seq++ {
		recs, _ := st.Records(bg, seq, 1)
		h, _ := hex.DecodeString(recs[0]["hash"].(string))
		p, err := s2.Log().Prove(bg, seq, h)
		if err != nil {
			t.Fatalf("record %d: %v", seq, err)
		}
		if err := ledger.VerifyProof(p); err != nil {
			t.Fatalf("record %d does not verify against the new checkpoint: %v", seq, err)
		}
		if a := assurance(t, st, seq); a != store.AssuranceCheckpointed {
			t.Fatalf("record %d: %s", seq, a)
		}
	}
	// Without the retired vkey the old checkpoint cannot be read: the list is what keeps it verifiable.
	s2NoRetired, err := ledger.Open(bg, lab.config(t.TempDir(), logKey(k2)), st, st, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer closeSvc(t, s2NoRetired)
	if _, err := s2NoRetired.Log().ParseCheckpoint(oldCP.Note); err == nil {
		t.Fatal("the old checkpoint verified without the retired key")
	}
}

type tampered struct {
	ledger.Chain
	seq  int64
	hash string
}

func (c tampered) Records(ctx context.Context, from int64, limit int) ([]store.Record, error) {
	recs, err := c.Chain.Records(ctx, from, limit)
	out := make([]store.Record, len(recs))
	for i, r := range recs {
		cp := store.Record{}
		for k, v := range r {
			cp[k] = v
		}
		if from+int64(i) == c.seq {
			cp["hash"] = c.hash
		}
		out[i] = cp
	}
	return out, err
}

// Done-when: an altered row is named.
func TestAlteredRowIsNamed(t *testing.T) {
	k := newKey(t, origin)
	lab := newLab(t, k)
	st := newChain(t)
	dir := t.TempDir()
	appendN(t, st, "a", 10)
	s, err := ledger.Open(bg, lab.config(dir, logKey(k)), st, st, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	run(t, s, "10 witnessed", witnessedAll(s, st))
	if err := s.Log().Audit(bg, st); err != nil {
		t.Fatalf("an unaltered chain fails the audit: %v", err)
	}
	// A running audit names the row.
	bad := tampered{Chain: st, seq: 6, hash: strings.Repeat("ab", 32)}
	var ar *ledger.AlteredRow
	if err := s.Log().Audit(bg, bad); !errors.As(err, &ar) || ar.Seq != 6 {
		t.Fatalf("audit: %v", err)
	}
	closeSvc(t, s)
	// So does the start: the core does not serve a chain whose row differs from what the ledger committed to.
	_, err = ledger.Open(bg, lab.config(dir, logKey(k)), bad, st, nil, quiet())
	if !errors.As(err, &ar) || ar.Seq != 6 || ar.Ledger == ar.Chain {
		t.Fatalf("open: %v", err)
	}
	if !strings.Contains(err.Error(), "record 6") {
		t.Fatalf("the error does not name the row: %v", err)
	}
}

// The rebuild path: a lost volume is rebuilt from the chain's hashes, reaches the root a witness signed, and is
// refused when the chain no longer reaches it.
func TestRebuildFromChain(t *testing.T) {
	k := newKey(t, origin)
	lab := newLab(t, k)
	st := newChain(t)
	appendN(t, st, "a", 10)
	s, err := ledger.Open(bg, lab.config(t.TempDir(), logKey(k)), st, st, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	run(t, s, "10 witnessed", witnessedAll(s, st))
	closeSvc(t, s)
	held, _ := st.LedgerCheckpoint(bg)

	t.Run("an empty volume reaches the same root and the witness cosigns it again", func(t *testing.T) {
		appendN(t, st, "b", 2) // the chain grew past the checkpoint while the volume was down
		s2, err := ledger.Open(bg, lab.config(t.TempDir(), logKey(k)), st, st, nil, quiet())
		if err != nil {
			t.Fatal(err)
		}
		defer closeSvc(t, s2)
		roots, err := ledger.Roots(bg, st, held.Size)
		if err != nil || hex.EncodeToString(roots[0]) != held.Root {
			t.Fatalf("root at %d: %x, %v (checkpoint %s)", held.Size, roots, err, held.Root)
		}
		run(t, s2, "12 witnessed", witnessedAll(s2, st))
		if a := assurance(t, st, 11); a != store.AssuranceCheckpointed {
			t.Fatalf("assurance %s", a)
		}
	})

	t.Run("a chain that no longer reaches the witnessed root is refused", func(t *testing.T) {
		bad := tampered{Chain: st, seq: 4, hash: strings.Repeat("cd", 32)}
		_, err := ledger.Open(bg, lab.config(t.TempDir(), logKey(k)), bad, st, nil, quiet())
		if !errors.Is(err, ledger.ErrRootMismatch) {
			t.Fatalf("want ErrRootMismatch, got %v", err)
		}
	})

	t.Run("a chain shorter than the witnessed checkpoint is refused", func(t *testing.T) {
		short := newChain(t)
		appendN(t, short, "a", 4)
		// The checkpoint a witness signed lives in the ledger store; the chain it covered is now shorter.
		_, err := ledger.Open(bg, lab.config(t.TempDir(), logKey(k)), short, &fixedLedger{held}, nil, quiet())
		if !errors.Is(err, ledger.ErrChainBehind) {
			t.Fatalf("want ErrChainBehind, got %v", err)
		}
	})
}

// fixedLedger reports one checkpoint, whatever the chain.
type fixedLedger struct{ cp store.LedgerCheckpoint }

func (f *fixedLedger) LedgerCheckpoint(context.Context) (store.LedgerCheckpoint, error) {
	return f.cp, nil
}
func (f *fixedLedger) PutLedgerCheckpoint(context.Context, store.LedgerCheckpoint) error { return nil }

// Done-when (ledger half): a witness outage makes tier 3 evidence wait, and the state says so.
func TestWitnessOutageHoldsAndRecovers(t *testing.T) {
	k := newKey(t, origin)
	lab := newLab(t, k)
	st := newChain(t)
	appendN(t, st, "a", 3)
	s, err := ledger.Open(bg, lab.config(t.TempDir(), logKey(k)), st, st, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer closeSvc(t, s)
	run(t, s, "3 witnessed", witnessedAll(s, st))
	if hold, _ := s.Hold(bg); hold {
		t.Fatal("holding while the witness is up")
	}

	lab.down.Store(true)
	appendN(t, st, "b", 2)
	run(t, s, "the outage to show", func() bool { return s.Status(bg).State == ledger.StateWitnessUnavailable })
	hold, why := s.Hold(bg)
	if !hold || !strings.Contains(why, ledger.StateWitnessUnavailable) {
		t.Fatalf("hold = %v %q", hold, why)
	}
	status := s.Status(bg)
	if status.Witnessed != 3 || status.Chain != 5 || !status.Holding {
		t.Fatalf("status %+v", status)
	}
	if a := assurance(t, st, 4); a != store.AssuranceRecorded {
		t.Fatalf("a record during the outage is %s", a)
	}

	lab.down.Store(false)
	run(t, s, "recovery", witnessedAll(s, st))
	if hold, _ := s.Hold(bg); hold {
		t.Fatal("still holding after recovery")
	}

	// The knob: off by choice, the outage is reported but nothing waits.
	cfg := lab.config(t.TempDir(), logKey(k))
	cfg.Tier3Wait = false
	lab.down.Store(true)
	st2 := newChain(t)
	appendN(t, st2, "a", 3)
	s2, err := ledger.Open(bg, cfg, st2, st2, nil, quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer closeSvc(t, s2)
	run(t, s2, "the outage to show", func() bool { return s2.Status(bg).State == ledger.StateWitnessUnavailable })
	if hold, _ := s2.Hold(bg); hold {
		t.Fatal("the knob is off and the ledger still holds")
	}
}

func TestLogWithoutWitnessIsRefused(t *testing.T) {
	k := newKey(t, origin)
	st := newChain(t)
	cfg := ledger.Config{Log: ledger.LogConfig{Dir: t.TempDir(), Key: logKey(k), Policy: []byte("quorum none\n")}}
	if _, err := ledger.Open(bg, cfg, st, st, nil, quiet()); !errors.Is(err, ledger.ErrNoWitness) {
		t.Fatalf("got %v", err)
	}
}

func TestWitnessStatePersists(t *testing.T) {
	k := newKey(t, origin)
	wk := newKey(t, "w")
	ws, _ := f_note.NewSignerForCosignatureV1(wk.skey)
	path := t.TempDir() + "/state.json"
	w, err := ledger.NewWitness(ws, []note.Verifier{k.vkey}, path)
	if err != nil {
		t.Fatal(err)
	}
	cp := f_log.Checkpoint{Origin: origin, Size: 5, Hash: bytes.Repeat([]byte{7}, 32)}.Marshal()
	signed, _ := note.Sign(&note.Note{Text: string(cp)}, k.signer)
	srv := httptest.NewServer(w)
	defer srv.Close()
	if resp := post(t, srv.URL, "old 0\n\n"+string(signed)); resp.StatusCode != 200 {
		t.Fatalf("first: %d", resp.StatusCode)
	}
	w2, err := ledger.NewWitness(ws, []note.Verifier{k.vkey}, path)
	if err != nil || w2.Size(origin) != 5 {
		t.Fatalf("after a restart the witness holds %d, %v", w2.Size(origin), err)
	}
	_ = base64.StdEncoding
}
