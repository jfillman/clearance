package packet_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/ledger"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
)

// witnessedLab runs the real ledger service and a real in-process witness over st until every record is under a
// witnessed checkpoint, then stops the service. It returns the log's public vkey and the witness policy.
func witnessedLab(t *testing.T, st *memory.Store) (vkey string, policy []byte) {
	t.Helper()
	skey, vk, _, err := ledger.GenerateKey("packet-test-ledger")
	if err != nil {
		t.Fatal(err)
	}
	signer, verifier, err := f_note.NewEd25519SignerVerifier(skey)
	if err != nil {
		t.Fatal(err)
	}
	wskey, wvkey, wcosig, err := ledger.GenerateKey("lab-witness")
	if err != nil {
		t.Fatal(err)
	}
	_ = wvkey
	ws, err := f_note.NewSignerForCosignatureV1(wskey)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.NewWitness(ws, []note.Verifier{verifier}, "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(w.ServeHTTP))
	t.Cleanup(srv.Close)
	policy = []byte(fmt.Sprintf("witness lab %s %s\nquorum lab\n", wcosig, srv.URL))
	cfg := ledger.Config{
		Log: ledger.LogConfig{Dir: t.TempDir(), Key: ledger.LogKey{Signer: signer, Verifiers: []note.Verifier{verifier}}, Policy: policy,
			CheckpointInterval: 200 * time.Millisecond, WitnessTimeout: 2 * time.Second, BatchAge: 20 * time.Millisecond},
		Tier3Wait: true, StallAfter: 3 * time.Second, PollEvery: 50 * time.Millisecond,
	}
	svc, err := ledger.Open(bg, cfg, st, st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := st.Head(bg)
	deadline := time.Now().Add(30 * time.Second)
	for svc.Status(bg).Witnessed != head+1 {
		if time.Now().After(deadline) {
			t.Fatalf("not witnessed in time: %+v", svc.Status(bg))
		}
		svc.Step(bg)
		time.Sleep(60 * time.Millisecond)
	}
	ctx, cancel := bgTimeout()
	defer cancel()
	_ = svc.Close(ctx)
	return vk, policy
}

// The packet carries what an offline verifier needs: the records as hashed, the inclusion proofs, the witnessed
// checkpoint and the public keys it is checked with. This test is that verifier, written without the packet's code:
// it recomputes the hashes, checks the proofs against the root in the checkpoint, and checks the checkpoint's log
// signature and the witness's countersignature.
func TestLedgerPacketCarriesWhatAnOfflineVerifierNeeds(t *testing.T) {
	st, seq := labChain(t)
	vkey, policy := witnessedLab(t, st)
	cp, err := st.LedgerCheckpoint(bg)
	if err != nil {
		t.Fatal(err)
	}
	// Records written after the checkpoint stay recorded-not-checkpointed.
	l := &labber{t: t, st: st}
	l.add(coreW, gate("2026-11-08T12:00:00Z", "deploy.request", "gate-api", "prod", map[string]any{"change": change("ch-00000000000000f6", "gate-api", "prod", "hangar-prod", 1, "holding"), "subject": manifestSubject('1')}))
	l.add(coreW, gate("2026-11-08T12:01:00Z", "deploy.clear", "gate-api", "prod", map[string]any{"change": change("ch-00000000000000f6", "gate-api", "prod", "hangar-prod", 1, "cleared"), "subject": manifestSubject('1'), "cleared_by": "policy", "approvals": []any{}}))

	p := params(t)
	p.LogKeys, p.WitnessPolicy = []string{vkey}, policy
	res, err := packet.Build(bg, st, p)
	if err != nil {
		t.Fatal(err)
	}
	v := res.Packet.Verification
	if v.Ledger.State != "checkpointed" || !v.Ledger.SignaturesChecked || !v.Ledger.Witnessed || len(v.Ledger.Cosigned) != 1 || v.Ledger.Size != cp.Size {
		t.Fatalf("%+v", v.Ledger)
	}
	if v.Ledger.Checkpointed == 0 || v.Ledger.NotCheckpointed != 2 || v.Ledger.ProofsCarried != v.Ledger.Checkpointed {
		t.Fatalf("checkpointed %d, after the checkpoint %d, proofs %d", v.Ledger.Checkpointed, v.Ledger.NotCheckpointed, v.Ledger.ProofsCarried)
	}
	if strings.HasPrefix(v.Statement, "NOT CHECKPOINTED") || !strings.Contains(v.Statement, "recorded-not-checkpointed") {
		t.Fatalf("%s", v.Statement)
	}
	if a := countOf(res.Packet.Coverage.ByAssurance, "recorded-not-checkpointed"); a != 2 {
		t.Fatalf("records after the checkpoint: %d", a)
	}
	// The coverage counts by assurance match the store's column, record by record.
	for _, m := range res.Packet.Coverage.Matrix {
		_ = m
	}
	ck := 0
	for _, r := range allRecords(t, st) {
		if ts := s(r, "ts"); ts >= winFrom && ts < winTo {
			if a, _ := st.Assurance(bg, seqI(r)); a == store.AssuranceCheckpointed {
				ck++
			}
		}
	}
	if got := countOf(res.Packet.Coverage.ByAssurance, "checkpointed"); got != ck || ck == 0 {
		t.Fatalf("checkpointed in the window: packet %d, store %d", got, ck)
	}

	dir := filepath.Join(t.TempDir(), "p")
	if _, err := packet.Write(bg, dir, res, nil, nil); err != nil {
		t.Fatal(err)
	}
	read := func(f string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	// 1. Recompute every carried record's hash from the file alone, and the prev_hash links where seqs are adjacent.
	hashes := map[int64]string{}
	var prevSeq int64 = -2
	var prevHash string
	for _, line := range bytes.Split(bytes.TrimRight(read("evidence/records.jsonl"), "\n"), []byte("\n")) {
		v, err := canon.Parse(line)
		if err != nil {
			t.Fatal(err)
		}
		rec := v.(map[string]any)
		claimed := rec["hash"].(string)
		delete(rec, "hash")
		c, _ := canon.Canonical(rec)
		if canon.SHA256Hex(c) != claimed {
			t.Fatalf("record %v: the hash does not recompute", rec["seq"])
		}
		n, _ := rec["seq"].(json.Number).Int64()
		if n == prevSeq+1 && rec["prev_hash"] != prevHash {
			t.Fatalf("record %d does not link to the one before", n)
		}
		prevSeq, prevHash = n, claimed
		hashes[n] = claimed
	}
	if len(hashes) != len(res.Records) {
		t.Fatal("duplicate seqs in records.jsonl")
	}
	// 2. The checkpoint verifies under the carried keys and policy.
	var vks []note.Verifier
	for _, k := range strings.Fields(string(read("ledger/log-keys.txt"))) {
		nv, err := f_note.NewVerifier(k)
		if err != nil {
			t.Fatal(err)
		}
		vks = append(vks, nv)
	}
	parsed, err := ledger.ParseCheckpointNote(read("ledger/checkpoint.txt"), vks, read("ledger/witness-policy.txt"))
	if err != nil || !parsed.Witnessed || parsed.Size != cp.Size {
		t.Fatalf("%+v %v", parsed, err)
	}
	// ... and not under another log's key.
	otherSkey, _, _, _ := ledger.GenerateKey("packet-test-ledger")
	_, other, _ := f_note.NewEd25519SignerVerifier(otherSkey)
	if _, err := ledger.ParseCheckpointNote(read("ledger/checkpoint.txt"), []note.Verifier{other}, nil); err == nil {
		t.Fatal("a checkpoint verified under a key that did not sign it")
	}
	// 3. Every proof verifies the record's hash against the checkpoint's root.
	var pf struct {
		TreeSize int64 `json:"tree_size"`
		Root     string
		Proofs   []packet.ProofEntry
	}
	if err := json.Unmarshal(read("evidence/proofs.json"), &pf); err != nil {
		t.Fatal(err)
	}
	if pf.TreeSize != parsed.Size || pf.Root != hex.EncodeToString(parsed.Root) || len(pf.Proofs) != v.Ledger.Checkpointed {
		t.Fatalf("%d proofs", len(pf.Proofs))
	}
	for _, p := range pf.Proofs {
		h, ok := hashes[p.Seq]
		if !ok || h != p.Hash || p.Seq >= parsed.Size {
			t.Fatalf("proof for seq %d", p.Seq)
		}
		var path [][]byte
		for _, x := range p.Path {
			b, _ := hex.DecodeString(x)
			path = append(path, b)
		}
		entry, _ := hex.DecodeString(h)
		if err := ledger.VerifyInclusion(p.Seq, parsed.Size, entry, path, parsed.Root); err != nil {
			t.Fatalf("seq %d: %v", p.Seq, err)
		}
		// a tampered record fails: flip one hash bit.
		bad := append([]byte(nil), entry...)
		bad[0] ^= 1
		if ledger.VerifyInclusion(p.Seq, parsed.Size, bad, path, parsed.Root) == nil {
			t.Fatalf("seq %d: a different hash verified", p.Seq)
		}
	}
	// 4. The attestation bundle is carried and the records after the checkpoint have no proof.
	if v.Attestations != 1 || len(read("attestations/"+chA+".json")) == 0 {
		t.Fatalf("attestations %d %v", v.Attestations, v.AttestationsMissing)
	}
	if _, ok := hashes[seq["outcomeA"]]; !ok {
		t.Error("a window record is missing from records.jsonl")
	}
	for _, p := range pf.Proofs {
		if p.Seq >= cp.Size {
			t.Errorf("a proof for a record the checkpoint does not cover: %d", p.Seq)
		}
	}
	// Without the keys the packet says the signatures were not checked here.
	p.LogKeys, p.WitnessPolicy = nil, nil
	res2, err := packet.Build(bg, st, p)
	if err != nil || res2.Packet.Verification.Ledger.SignaturesChecked || !strings.Contains(res2.Packet.Verification.Statement, "NOT checked") {
		t.Fatalf("%v %+v", err, res2.Packet.Verification)
	}
	// A checkpoint that does not match the chain is refused, not papered over.
	bad, _ := labChain(t)
	if err := bad.PutLedgerCheckpoint(bg, store.LedgerCheckpoint{Origin: "x", Size: 3, Root: strings.Repeat("ab", 32), Note: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.Build(bg, bad, params(t)); err == nil || !strings.Contains(err.Error(), "diverged") {
		t.Fatalf("a checkpoint the chain does not hash to: %v", err)
	}
	_ = evidence.Schema
}
