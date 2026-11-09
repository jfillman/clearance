package packet_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	f_log "github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/attest/attesttest"
	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/ledger"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/token"
	"github.com/jfillman/clearance/internal/verify"
)

// The offline verifier (C-4) against real packets: the lab-shaped 30-day window of the packet tests, a real witnessed
// ledger, and a real keyless attestation (a fake Fulcio and Rekor that are gone by the time anything is verified).

const (
	attIdentity = "clearance-recorder@hangar-dev"
	attIssuer   = attesttest.Issuer
)

// attLab is what the lab attestation was signed under: the trust root a verifier is given.
var attLab struct {
	sync.Mutex
	trustRoot []byte
	fulcioPEM []byte
	rekorPEM  []byte
}

// labAttestation signs a keyless attestation of change id with a fake Fulcio and Rekor and returns the bundle (with
// a single-entry Rekor inclusion proof added, since the fake log returns none) and its envelope digest.
func labAttestation(t testing.TB, id string) (json.RawMessage, string) {
	t.Helper()
	tt, ok := t.(*testing.T)
	if !ok {
		t.Fatal("labAttestation needs a *testing.T")
	}
	f, r := attesttest.NewFulcio(tt), attesttest.NewRekor(tt)
	rk, err := attest.NewRekor(r.URL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := &attest.Keyless{Fulcio: f.URL(), Rekor: rk, TokenFile: attesttest.WriteToken(tt, attIssuer, attIdentity)}
	const tree, commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1111111111111111111111111111111111111111"
	st := attest.Statement{Type: attest.StatementType, PredicateType: attest.PredicateType,
		Subject: []attest.Subject{{Name: "manifest-tree:o/r/app/prod", Digest: map[string]string{"sha256": tree}},
			{Name: "commit:o/r", Digest: map[string]string{"gitCommit": commit}}},
		Predicate: attest.Predicate{Clearance: token.Clearance{ID: id, ClearedBy: "policy", DecidedAt: "2026-10-12T08:05:00Z"},
			Approvals: []token.Approval{}, Provenance: token.Provenance{Level: "unknown", Proposer: "p", ProposerKind: "person"},
			Cleared: token.Subjects{Kind: "manifest-tree", Repo: "o/r", PR: 1, Commit: commit, TreeRoot: "sha256:" + tree, Images: []string{}},
			Tier:    2, Coverage: "authorized-and-verified", Limitations: []string{"x"},
			Outcome: attest.Outcome{Seq: 7, Provider: "argocd-agent", Applied: true, At: "2026-10-12T08:20:00Z"}}}
	payload, _ := json.Marshal(st)
	signed, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed.Bundle)
	var b attest.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	for i := range b.VerificationMaterial.TlogEntries {
		e := &b.VerificationMaterial.TlogEntries[i]
		leaf := rfc6962.DefaultHasher.HashLeaf(e.CanonicalizedBody)
		e.InclusionProof = &attest.InclProof{LogIndex: e.LogIndex, RootHash: hex.EncodeToString(leaf), TreeSize: "1", Hashes: []string{}}
	}
	raw, _ = json.Marshal(b)
	tr, err := attest.BuildTrustedRoot([]attest.BuildCA{{URI: "http://fulcio", PEM: f.RootPEM, Window: attest.Window{Start: time.Now().Add(-2 * time.Hour)}}},
		[]attest.BuildLog{{BaseURL: "http://rekor", PEM: r.KeyPEM, Window: attest.Window{Start: time.Now().Add(-2 * time.Hour)}}})
	if err != nil {
		t.Fatal(err)
	}
	attLab.Lock()
	attLab.trustRoot, attLab.fulcioPEM, attLab.rekorPEM = tr, f.RootPEM, r.KeyPEM
	attLab.Unlock()
	return raw, attest.EnvelopeDigest(b.DSSEEnvelope)
}

// labPacket is a written packet and the trust inputs a verifier is given for it.
type labPacket struct {
	dir       string
	logKeys   []byte
	policy    []byte
	trustRoot []byte
	seqs      map[string]int64
}

func (p labPacket) opts(seen string) verify.Options {
	return verify.Options{LogKeys: p.logKeys, LogKeysSrc: "log-vkeys.txt", WitnessPolicy: p.policy, WitnessPolicySrc: "witness-policy.txt",
		TrustRoot: p.trustRoot, TrustRootSrc: "trusted-root.json", Identity: attIdentity, Issuer: attIssuer, SeenFile: seen}
}

// buildLabPacket writes the 30-day lab packet; withLedger runs the real witnessed ledger first.
func buildLabPacket(t *testing.T, withLedger bool) labPacket {
	t.Helper()
	st, seq := labChain(t)
	lp := labPacket{seqs: seq, dir: filepath.Join(t.TempDir(), "packet")}
	p := params(t)
	if withLedger {
		vkey, policy := witnessedLab(t, st)
		p.LogKeys, p.WitnessPolicy = []string{vkey}, policy
		lp.logKeys, lp.policy = []byte(vkey+"\n"), policy
	}
	attLab.Lock()
	lp.trustRoot = attLab.trustRoot
	attLab.Unlock()
	res, err := packet.Build(bg, st, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packet.Write(bg, lp.dir, res, nil, nil); err != nil {
		t.Fatal(err)
	}
	return lp
}

// noNetwork makes any HTTP or DNS use of the process fail the test. Combined with the lab's servers having nothing
// to do with the packet's files, a verification that passes under it made no network call.
func noNetwork(t *testing.T) {
	t.Helper()
	calls := 0
	oldT, oldC, oldR := http.DefaultTransport, http.DefaultClient.Transport, net.DefaultResolver
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		t.Errorf("network call: %s %s", r.Method, r.URL)
		return nil, errors.New("no network in the offline verifier")
	})
	http.DefaultClient.Transport = http.DefaultTransport
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls++
		t.Errorf("DNS lookup via %s %s", network, addr)
		return nil, errors.New("no network in the offline verifier")
	}}
	t.Cleanup(func() {
		http.DefaultTransport, http.DefaultClient.Transport, net.DefaultResolver = oldT, oldC, oldR
		if calls > 0 {
			t.Errorf("%d network call(s)", calls)
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "packet")
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func rd(t *testing.T, dir, f string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wr(t *testing.T, dir, f string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(f)), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// rewriteManifest makes MANIFEST.json match the files as they now are: the tamperer who also fixes the manifest.
func rewriteManifest(t *testing.T, dir string) {
	t.Helper()
	files := map[string]string{}
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		rel, _ := filepath.Rel(dir, p)
		if err != nil || info.IsDir() || rel == "MANIFEST.json" {
			return err
		}
		b, _ := os.ReadFile(p)
		s := sha256.Sum256(b)
		files[filepath.ToSlash(rel)] = hex.EncodeToString(s[:])
		return nil
	})
	raw, _ := json.Marshal(packet.Manifest{Schema: "clearance.packet-manifest/v1", Files: files})
	wr(t, dir, "MANIFEST.json", raw)
}

// editJSON decodes f, applies fn and writes it back.
func editJSON(t *testing.T, dir, f string, fn func(m map[string]any)) {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(string(rd(t, dir, f))))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	raw, _ := json.Marshal(m)
	wr(t, dir, f, raw)
}

func render(r *verify.Report) string {
	var sb strings.Builder
	r.Write(&sb)
	return sb.String()
}

func check(r *verify.Report, nameContains string) *verify.Check {
	for i := range r.Checks {
		if strings.Contains(r.Checks[i].Name, nameContains) {
			return &r.Checks[i]
		}
	}
	return nil
}

func wantFail(t *testing.T, r *verify.Report, check string, substr ...string) {
	t.Helper()
	if r.ExitCode() != 1 {
		t.Fatalf("exit %d, want 1 (failed):\n%s", r.ExitCode(), render(r))
	}
	c := checkOf(r, check)
	if c == nil || c.Status != verify.Fail {
		t.Fatalf("check %q did not fail:\n%s", check, render(r))
	}
	body := c.Name + c.Detail + strings.Join(c.Findings, "\n")
	for _, s := range substr {
		if !strings.Contains(body, s) {
			t.Fatalf("check %q does not say %q:\n%s", check, s, render(r))
		}
	}
}

func checkOf(r *verify.Report, name string) *verify.Check {
	for i := range r.Checks {
		if strings.Contains(r.Checks[i].Name, name) && r.Checks[i].Status == verify.Fail {
			return &r.Checks[i]
		}
	}
	return check(r, name)
}

func TestVerifyThirtyDayLabPacketOffline(t *testing.T) {
	lp := buildLabPacket(t, true)
	seen := filepath.Join(t.TempDir(), "seen.json")
	noNetwork(t)
	rep := verify.Verify(lp.dir, lp.opts(seen))
	if rep.ExitCode() != 0 {
		t.Fatalf("a good packet:\n%s", render(rep))
	}
	out := render(rep)
	for _, want := range []string{"[PASS] manifest", "ledger: checkpoint signed by the log", "ledger: witness countersignatures", "inclusion proofs",
		"attestation of " + chA, "counted figures recompute", "supplied by you", "VERIFIED"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "TAKEN FROM THE PACKET") || strings.Contains(out, "NOT CHECKED") {
		t.Errorf("a fully supplied verification mentions taken-from-packet or not-checked:\n%s", out)
	}
	// The note of checkpoints seen now holds this checkpoint; verifying again is seen-before.
	again := verify.Verify(lp.dir, lp.opts(seen))
	if c := check(again, "seen before"); c == nil || c.Status != verify.Pass || !strings.Contains(strings.Join(c.Findings, " "), "seen before") {
		t.Fatalf("second run:\n%s", render(again))
	}
}

func TestVerifyReportsSelfVouchedKeysAsSuch(t *testing.T) {
	lp := buildLabPacket(t, true)
	noNetwork(t)
	// Nothing supplied: the packet's own keys, policy and the attestation's own identity are used, and said so.
	rep := verify.Verify(lp.dir, verify.Options{})
	out := render(rep)
	if rep.ExitCode() != 2 {
		t.Fatalf("exit %d, want 2:\n%s", rep.ExitCode(), out)
	}
	if c := check(rep, "signed by the log"); c.Status != verify.SelfVouched || !strings.Contains(c.Trust, "TAKEN FROM THE PACKET") {
		t.Fatalf("%+v", c)
	}
	if c := check(rep, "witness countersignatures"); c.Status != verify.SelfVouched {
		t.Fatalf("%+v", c)
	}
	if c := check(rep, "attestation of"); c.Status != verify.NotChecked || !strings.Contains(c.Detail, "no trust root") {
		t.Fatalf("%+v", c)
	}
	if !strings.Contains(out, "TAKEN FROM THE PACKET (ledger/log-keys.txt)") || strings.HasPrefix(rep.Verdict(), "VERIFIED") {
		t.Fatalf("%s", out)
	}
	// A trust root but no pinned identity: the signature verifies and the identity is labelled unpinned.
	rep = verify.Verify(lp.dir, verify.Options{TrustRoot: lp.trustRoot, LogKeys: lp.logKeys, WitnessPolicy: lp.policy})
	if c := check(rep, "attestation of"); c.Status != verify.SelfVouched || !strings.Contains(c.Trust, "not pinned") {
		t.Fatalf("%+v\n%s", c, render(rep))
	}
	// Only the log keys supplied: the policy is the packet's, and the witness line says so.
	rep = verify.Verify(lp.dir, verify.Options{LogKeys: lp.logKeys})
	if c := check(rep, "signed by the log"); c.Status != verify.Pass {
		t.Fatalf("%+v", c)
	}
	if c := check(rep, "witness countersignatures"); c.Status != verify.SelfVouched {
		t.Fatalf("%+v", c)
	}
}

func TestVerifyNoCheckpointIsNotCheckpointedNotAPass(t *testing.T) {
	lp := buildLabPacket(t, false)
	noNetwork(t)
	rep := verify.Verify(lp.dir, lp.opts(""))
	out := render(rep)
	c := check(rep, "ledger checkpoint")
	if c == nil || c.Status != verify.NotCheckpointed || !strings.Contains(c.Detail, "NOT a pass of the witness check") {
		t.Fatalf("%+v\n%s", c, out)
	}
	if rep.ExitCode() != 2 || strings.HasPrefix(rep.Verdict(), "VERIFIED") || rep.Failed() {
		t.Fatalf("exit %d:\n%s", rep.ExitCode(), out)
	}
	if !strings.Contains(out, "[NOT CHECKPOINTED]") {
		t.Fatalf("%s", out)
	}
	for _, c := range rep.Checks {
		if strings.Contains(c.Name, "witness") && c.Status == verify.Pass {
			t.Fatalf("a witness check passed with no checkpoint: %+v", c)
		}
	}
	// ... while the records, the figures and the attestation still verify.
	for _, n := range []string{"records: hashes", "counted figures", "attestation of"} {
		if c := check(rep, n); c == nil || c.Status != verify.Pass {
			t.Errorf("%s: %+v", n, c)
		}
	}
}

func TestVerifyTamperedRecordIsNamed(t *testing.T) {
	lp := buildLabPacket(t, true)
	noNetwork(t)
	target := lp.seqs["outcomeA"]
	mutate := func(fixHash bool) string {
		dir := copyDir(t, lp.dir)
		lines := strings.Split(strings.TrimRight(string(rd(t, dir, "evidence/records.jsonl")), "\n"), "\n")
		hit := -1
		for i, ln := range lines {
			if strings.Contains(ln, `"seq":`+i64(target)+`,`) {
				hit = i
			}
		}
		if hit < 0 || !strings.Contains(lines[hit], `"Healthy"`) {
			t.Fatalf("record %d not found", target)
		}
		lines[hit] = strings.Replace(lines[hit], `"Healthy"`, `"Broken"`, 1)
		if fixHash { // the tamperer recomputes the hash too
			v, _ := canon.Parse([]byte(lines[hit]))
			m := v.(map[string]any)
			delete(m, "hash")
			cb, _ := canon.Canonical(m)
			m["hash"] = canon.SHA256Hex(cb)
			full, _ := canon.Canonical(m)
			lines[hit] = string(full)
		}
		wr(t, dir, "evidence/records.jsonl", []byte(strings.Join(lines, "\n")+"\n"))
		rewriteManifest(t, dir) // and the manifest
		return dir
	}
	rep := verify.Verify(mutate(false), lp.opts(""))
	wantFail(t, rep, "records: hashes", "seq "+i64(target), "ALTERED")
	// With the hash fixed up, the next record's link and the inclusion proof still name it.
	rep = verify.Verify(mutate(true), lp.opts(""))
	wantFail(t, rep, "records: hashes", "seq "+i64(target+1), "altered or replaced")
	wantFail(t, rep, "inclusion proofs", "seq "+i64(target), "changed after it was logged")
}

func i64(n int64) string { return fmt.Sprint(n) }

func TestVerifyTruncatedAndResignedCheckpointIsRefused(t *testing.T) {
	lp := buildLabPacket(t, true)
	noNetwork(t)
	s, _, err := f_note.NewEd25519SignerVerifier(labLogSkey)
	if err != nil {
		t.Fatal(err)
	}
	// An attacker holding the log's own key signs a smaller tree. No witness has seen it, so none countersigns it.
	cp := f_log.Checkpoint{Origin: "packet-test-ledger", Size: 3, Hash: rfc6962.DefaultHasher.EmptyRoot()}
	signed, err := note.Sign(&note.Note{Text: string(cp.Marshal())}, s)
	if err != nil {
		t.Fatal(err)
	}
	dir := copyDir(t, lp.dir)
	wr(t, dir, "ledger/checkpoint.txt", signed)
	rewriteManifest(t, dir)
	rep := verify.Verify(dir, lp.opts(""))
	wantFail(t, rep, "witness countersignatures", "WITNESS POLICY NOT SATISFIED", "truncated or re-signed")
	if c := check(rep, "signed by the log"); c.Status != verify.Pass {
		t.Fatalf("the log's own signature is valid in this attack, which is the point: %+v", c)
	}
	wantFail(t, rep, "inclusion proofs", "different checkpoint")
	// The honest checkpoint with its witness countersignature stripped fails the same way.
	dir2 := copyDir(t, lp.dir)
	raw := rd(t, dir2, "ledger/checkpoint.txt")
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var kept []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "\u2014 lab-witness") {
			kept = append(kept, l)
		}
	}
	if len(kept) == len(lines) {
		t.Fatalf("no witness line in the checkpoint:\n%s", raw)
	}
	wr(t, dir2, "ledger/checkpoint.txt", []byte(strings.Join(kept, "\n")+"\n"))
	rewriteManifest(t, dir2)
	wantFail(t, verify.Verify(dir2, lp.opts("")), "witness countersignatures", "NOT SATISFIED")
	// The checkpoint is not the packet's claimed one either way.
}

func TestVerifyKeyRotationKeepsOldEntriesVerifiable(t *testing.T) {
	lp := buildLabPacket(t, true) // checkpoint signed by the key in use when the packet was made (the old key)
	noNetwork(t)
	_, newV, _, err := ledger.GenerateKey("packet-test-ledger") // the log's name is kept across a rotation
	if err != nil {
		t.Fatal(err)
	}
	o := lp.opts("")
	o.LogKeys = []byte(newV + "\n" + string(lp.logKeys)) // new key in use, the retired one after
	rep := verify.Verify(lp.dir, o)
	if rep.ExitCode() != 0 {
		t.Fatalf("an entry signed by the retired key must verify:\n%s", render(rep))
	}
	o.LogKeys = []byte(newV + "\n") // the retired key dropped from the list
	wantFail(t, verify.Verify(lp.dir, o), "signed by the log", "no signature by a log key you gave")
}

func TestVerifyTamperedPacketFiles(t *testing.T) {
	lp := buildLabPacket(t, true)
	noNetwork(t)
	t.Run("a changed proof", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		var seq json.Number
		editJSON(t, dir, "evidence/proofs.json", func(m map[string]any) {
			for _, p := range m["proofs"].([]any) {
				pm := p.(map[string]any)
				if path := pm["path"].([]any); len(path) > 0 {
					h := []byte(path[0].(string))
					if h[0] == '0' {
						h[0] = '1'
					} else {
						h[0] = '0'
					}
					path[0], seq = string(h), pm["seq"].(json.Number)
					return
				}
			}
		})
		rewriteManifest(t, dir)
		wantFail(t, verify.Verify(dir, lp.opts("")), "inclusion proofs", "seq "+seq.String(), "NOT under the checkpoint")
	})
	t.Run("a dropped proof", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		editJSON(t, dir, "evidence/proofs.json", func(m map[string]any) { m["proofs"] = m["proofs"].([]any)[1:] })
		rewriteManifest(t, dir)
		wantFail(t, verify.Verify(dir, lp.opts("")), "inclusion proofs", "has no valid inclusion proof")
	})
	t.Run("a changed manifest entry", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		editJSON(t, dir, "MANIFEST.json", func(m map[string]any) {
			f := m["files"].(map[string]any)
			f["evidence/records.jsonl"] = strings.Repeat("0", 64)
		})
		wantFail(t, verify.Verify(dir, lp.opts("")), "manifest", "evidence/records.jsonl: changed since the manifest was written")
	})
	t.Run("a changed file the manifest was not updated for", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		wr(t, dir, "csv/changes.csv", append(rd(t, dir, "csv/changes.csv"), []byte("x,y\n")...))
		wantFail(t, verify.Verify(dir, lp.opts("")), "manifest", "csv/changes.csv: changed")
	})
	t.Run("a file added", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		wr(t, dir, "extra.txt", []byte("hello"))
		wantFail(t, verify.Verify(dir, lp.opts("")), "manifest", "extra.txt: in the packet and not in the manifest")
	})
	t.Run("a counted figure", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		editJSON(t, dir, "packet.json", func(m map[string]any) {
			cv := m["coverage_statement"].(map[string]any)
			cv["total_records"] = json.Number("1")
		})
		rewriteManifest(t, dir)
		wantFail(t, verify.Verify(dir, lp.opts("")), "counted figures", "coverage: total records: the packet says 1")
	})
	t.Run("a count by state", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		editJSON(t, dir, "packet.json", func(m map[string]any) {
			bc := m["coverage_statement"].(map[string]any)["by_coverage"].([]any)
			bc[0].(map[string]any)["count"] = json.Number("0")
		})
		rewriteManifest(t, dir)
		wantFail(t, verify.Verify(dir, lp.opts("")), "counted figures", "coverage: records")
	})
	t.Run("a record dropped", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		lines := strings.Split(strings.TrimRight(string(rd(t, dir, "evidence/records.jsonl")), "\n"), "\n")
		mid := len(lines) / 2
		lines = append(lines[:mid], lines[mid+1:]...)
		wr(t, dir, "evidence/records.jsonl", []byte(strings.Join(lines, "\n")+"\n"))
		rewriteManifest(t, dir)
		rep := verify.Verify(dir, lp.opts(""))
		if rep.ExitCode() != 1 {
			t.Fatalf("%s", render(rep))
		}
		wantFail(t, rep, "counted figures", "records carried")
	})
	t.Run("the checkpoint file removed", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		if err := os.Remove(filepath.Join(dir, "ledger", "checkpoint.txt")); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, dir)
		wantFail(t, verify.Verify(dir, lp.opts("")), "ledger checkpoint", "checkpoint file is missing")
	})
	t.Run("an altered checkpoint note", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		raw := rd(t, dir, "ledger/checkpoint.txt")
		wr(t, dir, "ledger/checkpoint.txt", []byte(strings.Replace(string(raw), "packet-test-ledger\n", "packet-test-ledgex\n", 1)))
		rewriteManifest(t, dir)
		wantFail(t, verify.Verify(dir, lp.opts("")), "signed by the log", "does not verify")
	})
	t.Run("a swapped checkpoint root in packet.json", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		editJSON(t, dir, "packet.json", func(m map[string]any) {
			l := m["verification"].(map[string]any)["ledger"].(map[string]any)
			l["root"] = strings.Repeat("ab", 32)
		})
		rewriteManifest(t, dir)
		wantFail(t, verify.Verify(dir, lp.opts("")), "agrees with the checkpoint", "different checkpoint root")
	})
}

func TestVerifyTamperedAttestation(t *testing.T) {
	lp := buildLabPacket(t, true)
	// Another change's attestation, under its own Fulcio and Rekor (made now: the fakes need the network the guard blocks).
	otherBundle, _ := labAttestation(t, "ch-00000000000000ff")
	attLab.Lock()
	otherRoot := attLab.trustRoot
	attLab.Unlock()
	noNetwork(t)
	file := "attestations/" + chA + ".json"
	t.Run("a changed statement", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		editJSON(t, dir, file, func(m map[string]any) {
			env := m["dsseEnvelope"].(map[string]any)
			p, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
			env["payload"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(p), `"tier":2`, `"tier":1`, 1)))
		})
		rewriteManifest(t, dir)
		wantFail(t, verify.Verify(dir, lp.opts("")), "attestation of "+chA)
	})
	t.Run("another change's valid attestation swapped in", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		wr(t, dir, file, otherBundle)
		rewriteManifest(t, dir)
		o := lp.opts("")
		o.TrustRoot = otherRoot // a verifier that trusts the other bundle's log: only the change id and digests stand in the way
		wantFail(t, verify.Verify(dir, o), "attestation of "+chA)
	})
	t.Run("a doctored Rekor inclusion proof", func(t *testing.T) {
		dir := copyDir(t, lp.dir)
		editJSON(t, dir, file, func(m map[string]any) {
			e := m["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
			e["inclusionProof"].(map[string]any)["rootHash"] = strings.Repeat("cd", 32)
		})
		rewriteManifest(t, dir)
		wantFail(t, verify.Verify(dir, lp.opts("")), "attestation of "+chA, "inclusion proof")
	})
	t.Run("the wrong signer pinned", func(t *testing.T) {
		o := lp.opts("")
		o.Identity = "someone-else"
		wantFail(t, verify.Verify(lp.dir, o), "attestation of "+chA, "identity")
	})
	t.Run("a trust root that is not the signer's", func(t *testing.T) {
		o := lp.opts("")
		o.TrustRoot = otherRoot // a different Fulcio and Rekor than the ones that signed this bundle
		wantFail(t, verify.Verify(lp.dir, o), "attestation of "+chA)
	})
}

func TestVerifyKeepsANoteOfCheckpointsSeenAndCatchesAFork(t *testing.T) {
	lp := buildLabPacket(t, true)
	noNetwork(t)
	seen := filepath.Join(t.TempDir(), "sub", "seen.json")
	if rep := verify.Verify(lp.dir, lp.opts(seen)); rep.ExitCode() != 0 {
		t.Fatalf("%s", render(rep))
	}
	var f map[string]any
	raw, err := os.ReadFile(seen)
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatalf("the note: %v %s", err, raw)
	}
	entries := f["logs"].(map[string]any)["packet-test-ledger"].([]any)
	if len(entries) != 1 {
		t.Fatalf("the note: %s", raw)
	}
	// A reader earlier shown a different tree of this size: simulate by changing the root the note holds.
	entries[0].(map[string]any)["root"] = strings.Repeat("ee", 32)
	raw, _ = json.Marshal(f)
	if err := os.WriteFile(seen, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	wantFail(t, verify.Verify(lp.dir, lp.opts(seen)), "seen before", "FORK")
	// A packet checked only against its own keys never writes the note.
	fresh := filepath.Join(t.TempDir(), "seen2.json")
	o := verify.Options{SeenFile: fresh}
	rep := verify.Verify(lp.dir, o)
	if _, err := os.Stat(fresh); err == nil {
		t.Fatalf("the note was written from a self-vouched checkpoint:\n%s", render(rep))
	}
	// A failing packet never writes the note.
	bad := copyDir(t, lp.dir)
	wr(t, bad, "csv/changes.csv", []byte("tampered"))
	fresh2 := filepath.Join(t.TempDir(), "seen3.json")
	if rep := verify.Verify(bad, lp.opts(fresh2)); rep.ExitCode() != 1 {
		t.Fatalf("%s", render(rep))
	}
	if _, err := os.Stat(fresh2); err == nil {
		t.Fatal("the note was written from a failing packet")
	}
}

func TestVerifyLeavesAChainWithNothingToCheckHonest(t *testing.T) {
	lp := buildLabPacket(t, true)
	dir := copyDir(t, lp.dir)
	if err := os.Remove(filepath.Join(dir, "evidence", "records.jsonl")); err != nil {
		t.Fatal(err)
	}
	rewriteManifest(t, dir)
	rep := verify.Verify(dir, lp.opts(""))
	if rep.ExitCode() != 1 {
		t.Fatalf("%s", render(rep))
	}
}

// netless returns a command prefix that runs a process with no network at all (macOS sandbox-exec, Linux
// unshare -n), or nil where neither is usable.
func netless(t *testing.T) []string {
	if p, err := exec.LookPath("sandbox-exec"); err == nil {
		if exec.Command(p, "-p", "(version 1)(allow default)(deny network*)", "true").Run() == nil {
			return []string{p, "-p", "(version 1)(allow default)(deny network*)"}
		}
	}
	if p, err := exec.LookPath("unshare"); err == nil {
		if exec.Command(p, "-rn", "true").Run() == nil {
			return []string{p, "-rn"}
		}
	}
	return nil
}

// The standalone binary, run by a process that cannot reach any network, verifies the lab packet: a failing
// network call is not even possible, so a pass is proof the verifier does not need one.
func TestVerifyBinaryRunsWithNoNetwork(t *testing.T) {
	prefix := netless(t)
	if prefix == nil {
		t.Skip("no sandbox-exec or unshare -n to cut the network with")
	}
	lp := buildLabPacket(t, true)
	bin := filepath.Join(t.TempDir(), "clearance-verify")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/jfillman/clearance/cmd/clearance-verify").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	files := t.TempDir()
	put := func(n string, b []byte) string {
		p := filepath.Join(files, n)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	args := append(prefix[1:len(prefix):len(prefix)], bin, lp.dir,
		"--log-keys", put("keys.txt", lp.logKeys), "--witness-policy", put("policy.txt", lp.policy), "--trust-root", put("tr.json", lp.trustRoot),
		"--identity", attIdentity, "--issuer", attIssuer, "--seen-file", filepath.Join(files, "seen.json"))
	cmd := exec.Command(prefix[0], args...)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "VERIFIED: every check passed") {
		t.Fatalf("%v\n%s", err, out)
	}
	// A tampered copy exits 1 through the same binary.
	bad := copyDir(t, lp.dir)
	wr(t, bad, "csv/changes.csv", []byte("x"))
	args[len(prefix)-1+1] = bad
	cmd = exec.Command(prefix[0], args...)
	out, err = cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 || !strings.Contains(string(out), "csv/changes.csv") {
		t.Fatalf("%v\n%s", err, out)
	}
}

// An observed record with no scope is in the counts when no scopes were named and out of them when some were (the
// builder's scopeWanted); the verifier's recount must agree either way, or a valid packet reads as failed.
func TestVerifyRecountsAnObservedRecordWithNoScope(t *testing.T) {
	for _, named := range []bool{true, false} {
		st, _ := labChain(t)
		l := &labber{t: t, st: st}
		l.add(obsW, observation("2026-10-20T10:00:00Z", "", "PutBucketPolicy", "bucket", nil))
		p := params(t)
		if !named {
			p.Scopes = nil
		}
		res, err := packet.Build(bg, st, p)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "packet")
		if _, err := packet.Write(bg, dir, res, nil, nil); err != nil {
			t.Fatal(err)
		}
		rep := verify.Verify(dir, verify.Options{})
		if c := check(rep, "counted figures"); c == nil || c.Status != verify.Pass {
			t.Fatalf("named=%v:\n%s", named, render(rep))
		}
	}
}
