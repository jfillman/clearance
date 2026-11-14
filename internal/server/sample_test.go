package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"

	"github.com/jfillman/clearance/internal/assurance"
	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/ledger"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/sampling"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
	"github.com/jfillman/clearance/internal/verify"
)

// P-2 fixtures: a 30-day lab chain with real witnessed checkpoint, built into a packet, published to a real core over
// HTTP, opened to a fake recipient that has only a credential.

func p2hex(c byte) string { return strings.Repeat(string(c), 64) }

func p2change(id, app string, tier int, state string) map[string]any {
	return map[string]any{"id": id, "app": app, "env": "prod", "cluster": "hangar-prod", "head": p2hex('a')[:40], "tree": p2hex('b'),
		"tier": json.Number(fmt.Sprint(tier)), "state": state, "objects": json.Number("3")}
}

func p2event(ts, tool, app string, extra map[string]any) store.Event {
	ev := store.Event{"ts": ts, "task_id": nil, "session": nil, "parent": nil, "principal": "policy", "agent": nil, "tool": tool, "tier": nil,
		"decision": "allow", "rule": nil, "target": app + "/prod", "args_sha256": p2hex('0'), "result": tool, "app": app, "boundary": "deployment"}
	maps.Copy(ev, extra)
	return ev
}

func (f *fixture) p2add(t *testing.T, ev store.Event) int64 {
	t.Helper()
	var seq int64
	if err := f.core.Store.Atomic(context.Background(), func(tx store.Tx) error {
		rec, err := tx.Append(context.Background(), ev, evidence.Core("test"))
		if err != nil {
			return err
		}
		n, _ := rec["seq"].(json.Number)
		seq, _ = n.Int64()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return seq
}

// p2clear writes a change's request and clear records (cleared by policy) and returns the clear record's seq.
func (f *fixture) p2clear(t *testing.T, i int, app string, tier int, at time.Time) (string, int64) {
	t.Helper()
	id := fmt.Sprintf("ch-%016x", i)
	subj := map[string]any{"kind": "manifest-tree", "name": app + "/prod", "digests": map[string]any{"sha256": p2hex('b'), "gitCommit": p2hex('a')[:40]}}
	f.p2add(t, p2event(at.Format(time.RFC3339), "deploy.request", app, map[string]any{"change": p2change(id, app, tier, "holding"), "subject": subj}))
	return id, f.p2add(t, p2event(at.Add(time.Minute).Format(time.RFC3339), "deploy.clear", app, map[string]any{"change": p2change(id, app, tier, "cleared"), "subject": subj,
		"cleared_by": "policy", "approvals": []any{}}))
}

// p2witness runs the real ledger service and a real in-process witness over the store until every record is under a
// witnessed checkpoint, then stops the service. It returns the log's public key and the witness policy.
func p2witness(t *testing.T, f *fixture) (vkey string, policy []byte) {
	t.Helper()
	skey, vk, _, err := ledger.GenerateKey("p2-test-ledger")
	if err != nil {
		t.Fatal(err)
	}
	signer, verifier, err := f_note.NewEd25519SignerVerifier(skey)
	if err != nil {
		t.Fatal(err)
	}
	wskey, _, wcosig, err := ledger.GenerateKey("lab-witness")
	if err != nil {
		t.Fatal(err)
	}
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
	ctx := context.Background()
	lst, ok := f.core.Store.(store.Ledger)
	if !ok {
		t.Fatal("the memory store keeps no ledger")
	}
	svc, err := ledger.Open(ctx, cfg, f.core.Store, lst, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := f.core.Store.Head(ctx)
	deadline := time.Now().Add(30 * time.Second)
	for svc.Status(ctx).Witnessed != head+1 {
		if time.Now().After(deadline) {
			t.Fatalf("not witnessed in time: %+v", svc.Status(ctx))
		}
		svc.Step(ctx)
		time.Sleep(60 * time.Millisecond)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = svc.Close(cctx)
	return vk, policy
}

// p2lab is the lab: a core with a published, witnessed, 30-day packet and a recipient opened to it.
type p2lab struct {
	f       *fixture
	coreKey *token.KeySigner
	rcp     *fakeRecipient
	dir     string
	bundle  *packet.Bundle
	id      string
	vkey    string
	policy  []byte
	cl      *assurance.Client
	window  map[string]any
	// the clear records by why they are or are not in the sampling frame
	eligible []int64 // gate-api, cleared, under the checkpoint
	billing  []int64 // another app: in the chain, outside the packet's scope
	late     []int64 // gate-api, cleared after the checkpoint: no inclusion proof
	denied   int     // gate-api changes that were never cleared
}

func p2Lab(t *testing.T, readsPerHour int) *p2lab { return p2LabOn(t, readsPerHour, "") }

// p2LabOn is the lab on the memory store (dsn "") or on a scratch Postgres database.
func p2LabOn(t *testing.T, readsPerHour int, dsn string) *p2lab {
	t.Helper()
	a, b := newFakeRecipient(t, "lab-auditor"), newFakeRecipient(t, "lab-grc-hub")
	var base []map[string]any
	_ = json.Unmarshal([]byte(providersJSON), &base)
	raw, _ := json.Marshal(append(base, a.registration(), b.registration()))
	ps, err := server.ParseProviders(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, dsn)
	cfg.Providers = ps
	s := signer(t)
	cfg.Signer, cfg.TokenIssuer, cfg.TokenTTL = s, "clearance", 15*time.Minute
	cfg.PacketReadsPerHour = readsPerHour
	f := newFixture(t, cfg)
	l := &p2lab{f: f, coreKey: s, rcp: a, cl: &assurance.Client{Base: f.srv.URL}}
	start := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 40; i++ { // 40 cleared changes over 30 days, tiers 0 to 3, October and November
		_, seq := f.p2clear(t, i, "gate-api", i%4, start.Add(time.Duration(i)*17*time.Hour))
		l.eligible = append(l.eligible, seq)
	}
	for i := 0; i < 5; i++ { // requested and refused: never cleared
		id := fmt.Sprintf("ch-%016x", 500+i)
		f.p2add(t, p2event(start.Add(time.Duration(i)*50*time.Hour).Format(time.RFC3339), "deploy.request", "gate-api",
			map[string]any{"change": p2change(id, "gate-api", 3, "holding"), "decision": "deny", "rule": "DG-UNREGISTERED"}))
		l.denied++
	}
	for i := 0; i < 6; i++ { // another app's changes, in the chain and outside the packet's scope
		_, seq := f.p2clear(t, 900+i, "billing", 2, start.Add(time.Duration(i)*40*time.Hour+time.Hour))
		l.billing = append(l.billing, seq)
	}
	l.vkey, l.policy = p2witness(t, f)
	for i := 0; i < 2; i++ { // cleared after the checkpoint: carried, but recorded-not-checkpointed
		_, seq := f.p2clear(t, 700+i, "gate-api", 1, time.Date(2026, 11, 8, 10+i, 0, 0, 0, time.UTC))
		l.late = append(l.late, seq)
	}
	now := time.Date(2026, 11, 9, 6, 0, 0, 0, time.UTC)
	res, err := packet.Build(context.Background(), f.core.Store, packet.Params{From: start.Add(-24 * time.Hour), To: now.Add(-6 * time.Hour), Now: now, Version: "test",
		App: "gate-api", LogKeys: []string{l.vkey}, WitnessPolicy: l.policy})
	if err != nil {
		t.Fatal(err)
	}
	l.dir = filepath.Join(t.TempDir(), "packet")
	if _, err := packet.Write(context.Background(), l.dir, res, []string{"json"}, nil); err != nil {
		t.Fatal(err)
	}
	if l.bundle, err = packet.PackDir(l.dir); err != nil {
		t.Fatal(err)
	}
	l.id = l.bundle.ID
	f.do("POST", "/v1/packets", "user:admin", l.bundle.JSON).want(t, 200, "")
	l.window = map[string]any{"to": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	return l
}

func (l *p2lab) deliver(t *testing.T, scope ...string) server.Delivery {
	t.Helper()
	body := map[string]any{"recipient": l.rcp.name, "window": l.window}
	if len(scope) > 0 {
		body["scope"] = scope
	}
	return l.f.deliver(t, l.id, body)
}

func (l *p2lab) sample(t *testing.T, cred string, r assurance.SampleRequest) (*sampling.Document, []byte) {
	t.Helper()
	d, raw, err := l.cl.Sample(context.Background(), l.id, cred, r)
	if err != nil {
		t.Fatal(err)
	}
	return d, raw
}

func (l *p2lab) sampleRecords() []store.Record { return l.f.toolRecords(server.ToolPacketSample) }

func seqsOf(d *sampling.Document) []int64 {
	var out []int64
	for _, it := range d.Selected {
		out = append(out, it.Seq)
	}
	return out
}

func writeSample(t *testing.T, raw []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sample.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// trust is the verifier's own trust inputs: the log's key and the witness policy, as an auditor would pin them.
func (l *p2lab) trust() verify.Options {
	return verify.Options{LogKeys: []byte(l.vkey + "\n"), LogKeysSrc: "log.pub", WitnessPolicy: l.policy, WitnessPolicySrc: "policy.txt"}
}

// coreRecord is a record as the core serves it (what an auditor reads with GET /v1/evidence/{seq}, or is handed by the subscriber).
func (l *p2lab) coreRecord(t *testing.T, seq int64) []byte {
	t.Helper()
	for _, r := range l.f.records() {
		if n, _ := r["seq"].(json.Number).Int64(); n == seq {
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	t.Fatalf("no record %d", seq)
	return nil
}

// trustFor is trust() with the core's own packet.sample record of doc, which is what lets a verification be exit 0.
func (l *p2lab) trustFor(t *testing.T, doc *sampling.Document) verify.Options {
	o := l.trust()
	o.SampleRecord, o.SampleRecordSrc = l.coreRecord(t, doc.Recorded.Seq), "record.json"
	return o
}

func failedChecks(rep *verify.Report) []string {
	var out []string
	for _, c := range rep.Checks {
		if c.Status == verify.Fail {
			out = append(out, c.Name)
		}
	}
	return out
}

// TestP2SamplingGate is the P-2 gate: one command, `go test ./internal/server -run TestP2SamplingGate -count=1`. A fake
// recipient holding only a credential draws a 25-record sample of a 30-day lab packet through the real HTTP server; the
// sample verifies offline against the log's key and the packet; the same seed reproduces it; a record outside the scope
// (another app's, one with no inclusion proof, one never cleared) cannot be sampled.
func TestP2SamplingGate(t *testing.T) {
	l := p2Lab(t, -1)
	d := l.deliver(t)
	doc, raw := l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "fy26-q4"})
	if len(doc.Selected) != 25 || doc.Params.N != 25 || doc.Params.Seed != "fy26-q4" {
		t.Fatalf("%d records, %+v", len(doc.Selected), doc.Params)
	}
	// The population is printed with the sample: every change of the packet, and why any is not in the frame.
	all, cleared, eligible := sampling.Counts(doc.Population.Changes)
	if all != 40+5+2 || cleared != 42 || eligible != 40 || doc.Population.Count != all || doc.Population.Eligible != 40 {
		t.Fatalf("population %d changes, %d cleared, %d eligible", all, cleared, eligible)
	}
	why := map[string]int{}
	for _, r := range doc.Population.Changes {
		why[r.Excluded]++
	}
	if why[sampling.ExcludedNotCleared] != 5 || why[sampling.ExcludedNoProof] != 2 || why[""] != 40 {
		t.Fatalf("%v", why)
	}
	// Offline, against the log's key and the packet, with nothing asked of the core: the file and the directory.
	file := writeSample(t, raw)
	rep := verify.VerifySample(file, l.dir, l.trustFor(t, doc))
	if rep.ExitCode() != 0 || !rep.Complete() {
		var b strings.Builder
		rep.Write(&b)
		t.Fatalf("the sample does not verify offline:\n%s", b.String())
	}
	var rb strings.Builder
	rep.Write(&rb)
	t.Logf("\n%s", rb.String())
	var out strings.Builder
	keys, pol := filepath.Join(t.TempDir(), "log.pub"), filepath.Join(t.TempDir(), "policy.txt")
	_ = os.WriteFile(keys, []byte(l.vkey+"\n"), 0o644)
	_ = os.WriteFile(pol, l.policy, 0o644)
	recFile := filepath.Join(t.TempDir(), "record.json")
	_ = os.WriteFile(recFile, l.coreRecord(t, doc.Recorded.Seq), 0o644)
	if code := verify.Main([]string{"--sample", file, "--packet", l.dir, "--log-keys", keys, "--witness-policy", pol, "--sample-record", recFile}, &out, io.Discard); code != 0 {
		t.Fatalf("clearance verify --sample exited %d:\n%s", code, out.String())
	}
	// The cleared changes that could not be sampled are counted and reported as a finding, not a failure.
	if doc.Population.ClearedExcluded[sampling.ExcludedNoProof] != 2 || len(doc.Population.ClearedExcluded) != 1 {
		t.Fatalf("%v", doc.Population.ClearedExcluded)
	}
	pc := checkNamed(t, rep, "sample: the population")
	if pc.Status != verify.Pass || len(pc.Findings) != 1 || !strings.Contains(pc.Findings[0], "2 cleared change(s) have no inclusion proof") || !strings.Contains(pc.Detail, "no-inclusion-proof 2") {
		t.Fatalf("%+v", pc)
	}
	// Without the core's own record the verifier cannot say the core drew the sample: NOT CHECKED, exit 2, not a pass.
	if rep := verify.VerifySample(file, l.dir, l.trust()); rep.ExitCode() != 2 || rep.Failed() || checkNamed(t, rep, "sample: the core's packet.sample record").Status != verify.NotChecked {
		t.Fatalf("exit %d, failed %v", rep.ExitCode(), failedChecks(rep))
	}
	// Without the log's key the checkpoint is the sample's own claim: not a pass.
	if rep := verify.VerifySample(file, l.dir, verify.Options{}); rep.ExitCode() != 2 || rep.Failed() {
		t.Fatalf("keys taken from the sample: exit %d, failed %v", rep.ExitCode(), failedChecks(rep))
	}
	// Without the packet the population is the sample's own claim: not a pass either.
	if rep := verify.VerifySample(file, "", l.trust()); rep.ExitCode() != 2 || rep.Failed() {
		t.Fatalf("no packet: exit %d, failed %v", rep.ExitCode(), failedChecks(rep))
	}

	// The same seed reproduces the same sample: by another delivery (another credential), by another recipient, and offline.
	d2 := l.deliver(t)
	again, raw2 := l.sample(t, d2.Credential, assurance.SampleRequest{N: 25, Seed: "fy26-q4"})
	if !slices.Equal(seqsOf(doc), seqsOf(again)) || again.EffectiveSeed != doc.EffectiveSeed || d2.Credential == d.Credential {
		t.Fatal("the same seed drew a different sample")
	}
	if c := verify.VerifySample(writeSample(t, raw2), l.dir, l.trustFor(t, again)); c.ExitCode() != 0 {
		t.Fatal("the reproduced sample does not verify")
	}
	other, _ := l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "fy26-q5"})
	if slices.Equal(seqsOf(doc), seqsOf(other)) {
		t.Fatal("another seed drew the same sample")
	}

	// A record outside the scope cannot be sampled. Ask for every eligible change: exactly the eligible ones come back,
	// never another app's, a record with no proof, or a change that was never cleared.
	full, _ := l.sample(t, d.Credential, assurance.SampleRequest{N: 40, Seed: "all"})
	if got := seqsOf(full); !slices.Equal(got, l.eligible) {
		t.Fatalf("the full sample is %v, the eligible clear records are %v", got, l.eligible)
	}
	for _, out := range slices.Concat(l.billing, l.late) {
		if slices.Contains(seqsOf(full), out) || slices.Contains(seqsOf(doc), out) {
			t.Fatalf("record %d is outside the scope and was sampled", out)
		}
	}
	// And a sample larger than the eligible population is refused, not padded.
	l.f.do("GET", "/v1/packets/"+l.id+"/sample?n=41&seed=x", d.Credential, nil).want(t, 400, "40")
}

// -- query and path validation ----------------------------------------------------------------------------------

// Every query parameter is validated before it can reach a record or an answer: a bad one is 400 and writes nothing.
func TestP2QueryIsValidatedBeforeAnythingIsRecorded(t *testing.T) {
	l := p2Lab(t, -1)
	d := l.deliver(t)
	before := len(l.f.records())
	for _, q := range []string{
		"n=0", "n=-1", "n=101", "n=1000000000000000000000", "n=abc", "n=1.5", "n=1e1", "n=%2B5", "n=%2025", "n=025", "n=",
		"seed=", "seed=a%20b", "seed=a%00b", "seed=a%0ab", "seed=%C3%A9", "seed=a/b", "seed=..%2Fx", "seed=%3Cscript%3E", "seed=" + strings.Repeat("a", 65),
		"stratify=x", "stratify=", "stratify=tier", "stratify=TIER-MONTH", "stratify=tier-month,none",
		"packet=pk-00000000000000000000000000000000", "seq=5", "change=ch-0000000000000001", "part=evidence", "n=5&n=6", "seed=a&seed=b", "stratify=none&stratify=none",
		"seed=ok;n=5", "seed=ok&n=%zz", "seed=ok&%", "seed=ok&n=5&=x",
		"x=" + strings.Repeat("a", 300), "n=5&" + strings.Repeat("a", 300) + "=1",
	} {
		if !strings.Contains(q, "seed") {
			q = "seed=ok&" + q
		}
		a := f(l, "/v1/packets/"+l.id+"/sample?"+q, d.Credential)
		if a.status != 400 {
			t.Errorf("?%.40s: status %d %v", q, a.status, a.body)
		}
		if msg := fmt.Sprint(a.body["error"]); strings.Contains(msg, d.Credential) {
			t.Errorf("?%.40s: the error echoes the credential", q)
		}
	}
	if len(l.f.records()) != before {
		t.Fatal("a bad query wrote a record")
	}
	// A good query is not refused by any of that.
	l.f.do("GET", "/v1/packets/"+l.id+"/sample?n=5&seed=ok.1_2-3&stratify=tier-month", d.Credential, nil).want(t, 200, "")
}

func f(l *p2lab, path, cred string) answer { return l.f.do("GET", path, cred, nil) }

// The path id goes into signed records: only a packet id is accepted, before anything is read or written.
func TestP2APathThatIsNotAPacketIDWritesNoRecord(t *testing.T) {
	l := p2Lab(t, -1)
	d := l.deliver(t)
	before := len(l.f.records())
	for _, id := range []string{"x", "pk-zz", strings.Repeat("a", 3000), "pk-" + strings.Repeat("A", 32), "%00%01bad", "%ff%fe", "pk-0123456789abcdef0123456789abcdef%0a"} {
		if a := f(l, "/v1/packets/"+id+"/sample?seed=s", d.Credential); a.status != 404 && a.status != 400 {
			t.Errorf("%.30s: %d", id, a.status)
		}
	}
	if len(l.f.records()) != before {
		t.Fatal("a bad packet id wrote a record")
	}
}

// -- credential and scope: P-1's model ---------------------------------------------------------------------------

func TestP2CredentialAndScopeAreP1s(t *testing.T) {
	l := p2Lab(t, -1)
	ctx := context.Background()
	d := l.deliver(t)
	now := time.Now()
	mint := func(c token.AccessClaims) string {
		t.Helper()
		c.Type, c.Issuer, c.Audience, c.Digest = token.AccessType, "clearance", token.AccessAudience, l.bundle.Digest
		if c.Packet == "" {
			c.Packet = l.id
		}
		if c.Recipient == "" {
			c.Recipient = l.rcp.name
		}
		if c.Scope == nil {
			c.Scope = []string{packet.PartSummary, packet.PartEvidence}
		}
		if c.NotBefore == 0 {
			c.IssuedAt, c.NotBefore, c.Expires = now.Unix(), now.Unix(), now.Add(time.Hour).Unix()
		}
		s, err := token.IssueAccess(ctx, l.coreKey, c)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	refused := func(cred, path string, status int, rule string) {
		t.Helper()
		before := len(l.sampleRecords())
		a := f(l, path, cred).want(t, status, "")
		if a.body["rule"] != rule {
			t.Fatalf("%s: %v", rule, a.body)
		}
		rs := l.sampleRecords()
		if len(rs) != before+1 || rs[len(rs)-1]["decision"] != "deny" || rs[len(rs)-1]["rule"] != rule {
			t.Fatalf("a refusal is a record: %v", rs)
		}
		if _, has := rs[len(rs)-1]["sample"]; has {
			t.Fatal("a refusal records a sample")
		}
	}
	path := "/v1/packets/" + l.id + "/sample?seed=s"
	refused(mint(token.AccessClaims{Subject: "dl-1", IssuedAt: now.Add(-2 * time.Hour).Unix(), NotBefore: now.Add(-2 * time.Hour).Unix(), Expires: now.Add(-time.Hour).Unix()}), path, 401, server.RulePacketExpired)
	refused(mint(token.AccessClaims{Subject: "dl-1", IssuedAt: now.Unix(), NotBefore: now.Add(time.Hour).Unix(), Expires: now.Add(2 * time.Hour).Unix()}), path, 403, server.RulePacketNotYet)
	// A sample reads the population (summary) and the records and proofs (evidence): a credential cut to one part is refused.
	refused(mint(token.AccessClaims{Subject: "dl-1", Scope: []string{packet.PartSummary}}), path, 403, server.RulePacketScope)
	refused(mint(token.AccessClaims{Subject: "dl-1", Scope: []string{packet.PartEvidence}}), path, 403, server.RulePacketScope)
	refused(d.Credential, "/v1/packets/pk-00000000000000000000000000000000/sample?seed=s", 403, server.RulePacketScope)
	refused(mint(token.AccessClaims{Subject: "dl-1", Recipient: "nobody"}), path, 403, server.RulePacketRecipient)
	// A real delivery cut to the summary is refused the same way, through the real route.
	sd := l.deliver(t, packet.PartSummary)
	refused(sd.Credential, path, 403, server.RulePacketScope)
	// A credential the core did not sign, a clearance token and no credential are nobody: a bare 401 and no record.
	before := len(l.f.records())
	forged, _ := token.IssueAccess(ctx, signer(t), token.AccessClaims{Type: token.AccessType, Issuer: "clearance", Audience: token.AccessAudience, Subject: "dl-1", Packet: l.id,
		Digest: l.bundle.Digest, Recipient: l.rcp.name, Scope: []string{"summary", "evidence"}, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()})
	for _, c := range []string{"", "not-a-credential", forged, ci, strings.Repeat("a", 5000)} {
		f(l, path, c).want(t, 401, "")
	}
	if len(l.f.records()) != before {
		t.Fatal("a credential the core did not sign wrote a record")
	}
	// An allowed sample is recorded as the recipient, not as a Clearance principal.
	l.sample(t, d.Credential, assurance.SampleRequest{N: 3, Seed: "s"})
	rs := l.sampleRecords()
	if last := rs[len(rs)-1]; last["decision"] != "allow" || last["principal"] != "recipient:"+l.rcp.name {
		t.Fatalf("%v", last)
	}
}

// -- idempotence ------------------------------------------------------------------------------------------------

// Asking for a sample already drawn is served from the record that holds it and writes nothing: a repeat, and a hundred
// at once, are one record.
func TestP2ARepeatRequestIsIdempotent(t *testing.T) {
	l := p2Lab(t, -1)
	d := l.deliver(t)
	req := assurance.SampleRequest{N: 25, Seed: "audit", Stratify: sampling.StratifyTierMonth}
	first, raw1 := l.sample(t, d.Credential, req)
	if n := len(l.sampleRecords()); n != 1 {
		t.Fatalf("%d records", n)
	}
	again, raw2 := l.sample(t, d.Credential, req)
	if string(raw1) != string(raw2) || len(l.sampleRecords()) != 1 {
		t.Fatalf("a repeat differs or wrote a record (%d)", len(l.sampleRecords()))
	}
	if again.Recorded == nil || again.Recorded.Seq != first.Recorded.Seq || again.Recorded.Hash != first.Recorded.Hash || string(again.Recorded.Record) != string(first.Recorded.Record) {
		t.Fatal("a repeat names a different record")
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := l.cl.Sample(context.Background(), l.id, d.Credential, assurance.SampleRequest{N: 7, Seed: "race"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := len(l.sampleRecords()); n != 2 {
		t.Fatalf("40 concurrent requests for one sample left %d records, want 2 in all", n)
	}
	// The record holds the sample: its digest is the document's, and its seqs are the ones served, written before the answer.
	rec := l.sampleRecords()[0]
	sm := rec["sample"].(map[string]any)
	sha, _ := first.SHA256()
	if sm["sample_sha256"] != sha || sm["effective_seed"] != first.EffectiveSeed || sm["population_sha256"] != first.Population.SHA256 {
		t.Fatalf("%v", sm)
	}
	var recorded []int64
	for _, v := range sm["selected"].([]any) {
		n, _ := v.(json.Number).Int64()
		recorded = append(recorded, n)
	}
	if !slices.Equal(recorded, seqsOf(first)) || fmt.Sprint(rec["seq"]) != fmt.Sprint(first.Recorded.Seq) || rec["hash"] != first.Recorded.Hash {
		t.Fatalf("the record does not describe what was served: %v", sm)
	}
	// A new delivery asking for the same sample is its own record: the grant is what is recorded.
	d2 := l.deliver(t)
	l.sample(t, d2.Credential, req)
	if len(l.sampleRecords()) != 3 {
		t.Fatal("a second delivery's sample is not a record of its own")
	}
	// A restart (a core reading the same chain) does not append again for a sample the chain holds: the index is rebuilt from it.
	l.f.core.Server.ResetSampleIndexForTest()
	l.sample(t, d.Credential, req)
	if len(l.sampleRecords()) != 3 {
		t.Fatal("a sample already in the chain was recorded again after the index was rebuilt")
	}
}

// -- caps --------------------------------------------------------------------------------------------------------

func TestP2CapsGive429AndWriteNothing(t *testing.T) {
	// Reads per hour: the extras are 429 with Retry-After and no record.
	l := p2Lab(t, 3)
	d := l.deliver(t)
	for i := 0; i < 3; i++ {
		l.sample(t, d.Credential, assurance.SampleRequest{N: 5, Seed: fmt.Sprint("r", i)})
	}
	before := len(l.f.records())
	for i := 0; i < 5; i++ {
		a := f(l, "/v1/packets/"+l.id+"/sample?seed=more"+fmt.Sprint(i), d.Credential).want(t, 429, "")
		_ = a
	}
	if len(l.f.records()) != before {
		t.Fatal("a read past the cap wrote a record")
	}

	// Distinct samples per delivery: 20, then 429 PK-SAMPLE-LIMIT with no record; a sample already drawn is still served.
	l = p2Lab(t, -1)
	d = l.deliver(t)
	for i := 0; i < server.MaxSamplesPerDelivery; i++ {
		l.sample(t, d.Credential, assurance.SampleRequest{N: 5, Seed: fmt.Sprint("d", i)})
	}
	before = len(l.f.records())
	a := f(l, "/v1/packets/"+l.id+"/sample?n=5&seed=one-too-many", d.Credential).want(t, 429, "")
	if a.body["rule"] != server.RuleSampleLimit {
		t.Fatalf("%v", a.body)
	}
	l.sample(t, d.Credential, assurance.SampleRequest{N: 5, Seed: "d0"})
	if len(l.f.records()) != before {
		t.Fatal("a sample past the cap, or one already drawn, wrote a record")
	}
	// The cap is per delivery: a new delivery draws again.
	l.sample(t, l.deliver(t).Credential, assurance.SampleRequest{N: 5, Seed: "one-too-many"})

	// Refusals of one delivery are recorded up to 60 an hour (across both routes), then 429 and not written.
	l = p2Lab(t, -1)
	l.deliver(t)
	now := time.Now()
	expired, _ := token.IssueAccess(context.Background(), l.coreKey, token.AccessClaims{Type: token.AccessType, Issuer: "clearance", Audience: token.AccessAudience, Subject: "dl-1",
		Packet: l.id, Digest: l.bundle.Digest, Recipient: l.rcp.name, Scope: []string{"summary", "evidence"},
		IssuedAt: now.Add(-2 * time.Hour).Unix(), NotBefore: now.Add(-2 * time.Hour).Unix(), Expires: now.Add(-time.Hour).Unix()})
	for i := 0; i < 70; i++ {
		f(l, "/v1/packets/"+l.id+"/sample?seed=s", expired)
	}
	if n := len(l.sampleRecords()); n != 60 {
		t.Fatalf("%d refusals recorded, want 60", n)
	}
	f(l, "/v1/packets/"+l.id+"/sample?seed=s", expired).want(t, 429, "")
}

// -- packets that cannot be sampled ------------------------------------------------------------------------------

// A packet that stood on no witnessed checkpoint has no inclusion proofs: nothing is sampled, nothing is recorded.
func TestP2APacketWithNoCheckpointIsNotSampled(t *testing.T) {
	f0, _, auditor, _ := p1Fixture(t)
	f0.do("POST", "/v1/clearances", ci, change("pass")).want(t, 200, "")
	_, b := f0.buildPacket(t)
	f0.do("POST", "/v1/packets", "user:admin", b.JSON).want(t, 200, "")
	d := f0.deliver(t, b.ID, map[string]any{"recipient": auditor.name, "window": map[string]any{"to": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}})
	before := len(f0.records())
	f0.do("GET", "/v1/packets/"+b.ID+"/sample?seed=s", d.Credential, nil).want(t, 409, "checkpoint")
	if len(f0.records()) != before {
		t.Fatal("a refused sampling wrote a record")
	}
}

// A packet whose stored files do not check (a proof that does not verify) is not sampled.
func TestP2AStoredPacketThatDoesNotCheckIsNotSampled(t *testing.T) {
	l := p2Lab(t, -1)
	// A second packet, the same chain with one carried proof corrupted, published to the core as its own packet.
	raw, _ := os.ReadFile(filepath.Join(l.dir, packet.FileProofs))
	var pd map[string]any
	_ = json.Unmarshal(raw, &pd)
	p0 := pd["proofs"].([]any)[0].(map[string]any)
	p0["path"] = []any{p2hex('0')}
	bad, _ := json.Marshal(pd)
	dir := filepath.Join(t.TempDir(), "bad")
	if err := l.bundle.Unpack(dir); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, packet.FileProofs), bad, 0o644)
	// The manifest is rewritten as a forger would: the bundle is a packet that is internally consistent and whose proof is wrong.
	var man struct {
		Schema string            `json:"schema"`
		Files  map[string]string `json:"files"`
	}
	mb, _ := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	_ = json.Unmarshal(mb, &man)
	man.Files[packet.FileProofs] = sha256Hex(bad)
	mb, _ = json.Marshal(man)
	_ = os.WriteFile(filepath.Join(dir, "MANIFEST.json"), mb, 0o644)
	forged, err := packet.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.f.do("POST", "/v1/packets", "user:admin", forged.JSON).want(t, 200, "")
	d := l.f.deliver(t, forged.ID, map[string]any{"recipient": l.rcp.name, "window": l.window})
	before := len(l.f.records())
	l.f.do("GET", "/v1/packets/"+forged.ID+"/sample?seed=s", d.Credential, nil).want(t, 409, "")
	if len(l.f.records()) != before {
		t.Fatal("a packet whose proof does not verify was sampled")
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// -- the selection -----------------------------------------------------------------------------------------------

func TestP2SelectionIsReproducibleAndHonest(t *testing.T) {
	l := p2Lab(t, -1)
	d := l.deliver(t)
	// The seed is the auditor's: the same seed draws the same sample for every delivery, another seed another sample, and a
	// seed means nothing on another packet (it is bound to this packet's digest).
	a, _ := l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "mine"})
	b, _ := l.sample(t, l.deliver(t).Credential, assurance.SampleRequest{N: 25, Seed: "mine"})
	c, _ := l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "yours"})
	if !slices.Equal(seqsOf(a), seqsOf(b)) || a.EffectiveSeed != b.EffectiveSeed || slices.Equal(seqsOf(a), seqsOf(c)) {
		t.Fatal("a seed does not fix the sample")
	}
	if a.EffectiveSeed != hex.EncodeToString(sampling.EffectiveSeed(l.bundle.Digest, "mine")) || a.EffectiveSeed == hex.EncodeToString(sampling.EffectiveSeed(strings.Repeat("0", 64), "mine")) {
		t.Fatal("the effective seed is not bound to the packet digest")
	}
	// Stratified: proportional by tier and month, every stratum printed, the sizes add to n.
	s, _ := l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "mine", Stratify: sampling.StratifyTierMonth})
	total, pop := 0, 0
	for _, st := range s.Strata {
		total += st.Sample
		pop += st.Population
		if st.Month != "2026-10" && st.Month != "2026-11" {
			t.Fatalf("%+v", st)
		}
	}
	if len(s.Selected) != 25 || total != 25 || pop != 40 || len(s.Strata) < 4 {
		t.Fatalf("%d records, %d in strata, %d population, %d strata", len(s.Selected), total, pop, len(s.Strata))
	}
	for _, it := range s.Selected {
		if it.Tier == nil || it.Month == "" {
			t.Fatalf("%+v", it)
		}
	}
	// And the stratified sample verifies offline.
	_, raw := l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "mine", Stratify: sampling.StratifyTierMonth})
	if rep := verify.VerifySample(writeSample(t, raw), l.dir, l.trustFor(t, s)); rep.ExitCode() != 0 {
		t.Fatal(failedChecks(rep))
	}
	// A sample is not a way to read more than the packet gives: the recipient already holds every one of these records in the
	// evidence part, so the sample's choice is for the audit trail (the record), not for access.
	full, err := l.cl.Pull(context.Background(), l.id, d.Credential, "")
	if err != nil || full.Files["evidence/records.jsonl"] == nil {
		t.Fatal(err)
	}
}

// -- the credential is nowhere a secret could leak to ---------------------------------------------------------------

func TestP2TheCredentialIsInNoRecordAndNoAnswer(t *testing.T) {
	l := p2Lab(t, -1)
	d := l.deliver(t)
	_, raw := l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "x"})
	if strings.Contains(string(raw), d.Credential) {
		t.Fatal("the credential is in the sample document")
	}
	f(l, "/v1/packets/"+l.id+"/sample?n=0", d.Credential)
	f(l, "/v1/packets/"+l.id+"/sample?n=9999", d.Credential)
	for _, r := range l.f.records() {
		if b, _ := json.Marshal(r); strings.Contains(string(b), d.Credential) || strings.Contains(string(b), strings.Split(d.Credential, ".")[1]) {
			t.Fatalf("the credential (or its claims) is in record %v", r["seq"])
		}
	}
}

// -- the offline verifier fails, not passes with a note -----------------------------------------------------------

func TestP2TheVerifierFailsWhenAnythingIsMissingOrAltered(t *testing.T) {
	l := p2Lab(t, -1)
	d := l.deliver(t)
	_, raw := l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "fy26-q4"})
	load := func() *sampling.Document {
		var doc sampling.Document
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		return &doc
	}
	if rep := verify.VerifySample(writeSample(t, raw), l.dir, l.trustFor(t, load())); rep.ExitCode() != 0 {
		t.Fatal("the untouched sample does not verify")
	}
	// The packet's own record and proof of a clear record the sample did not draw, for a swapped-in record.
	carried := map[int64]json.RawMessage{}
	rj, _ := os.ReadFile(filepath.Join(l.dir, packet.FileRecords))
	for _, ln := range strings.Split(strings.TrimRight(string(rj), "\n"), "\n") {
		var m struct{ Seq int64 }
		_ = json.Unmarshal([]byte(ln), &m)
		carried[m.Seq] = json.RawMessage(ln)
	}
	pj, _ := os.ReadFile(filepath.Join(l.dir, packet.FileProofs))
	var pd struct {
		Proofs []sampling.Proof `json:"proofs"`
	}
	_ = json.Unmarshal(pj, &pd)
	proofOf := func(seq int64) sampling.Proof {
		for _, p := range pd.Proofs {
			if p.Seq == seq {
				return p
			}
		}
		t.Fatalf("no proof for %d", seq)
		return sampling.Proof{}
	}
	var notDrawn int64 = -1
	for _, s := range l.eligible {
		if !slices.Contains(seqsOf(load()), s) {
			notDrawn = s
			break
		}
	}
	rehash := func(d *sampling.Document) {
		sha, _ := sampling.PopulationSHA256(d.Population.Changes)
		d.Population.SHA256 = sha
		d.Population.Count, d.Population.Cleared, d.Population.Eligible = sampling.Counts(d.Population.Changes)
	}
	cases := []struct {
		name    string
		mutate  func(*sampling.Document)
		check   string // a check that must fail
		withPkt bool
	}{
		{"a record dropped (n says 25, 24 carried)", func(d *sampling.Document) { d.Selected = d.Selected[1:] }, "sample: the selection", true},
		{"a record added", func(d *sampling.Document) {
			d.Selected = append(d.Selected, sampling.Item{Change: "x", Seq: notDrawn, Record: carried[notDrawn], Proof: proofOf(notDrawn)})
		}, "sample: the selection", true},
		{"a record swapped for another the packet carries and proves (not drawn by the rule)", func(d *sampling.Document) {
			var tier *int64
			var month, change string
			for _, r := range d.Population.Changes {
				if r.ClearSeq != nil && *r.ClearSeq == notDrawn {
					tier, month, change = r.Tier, r.Month, r.Change
				}
			}
			d.Selected[0] = sampling.Item{Change: change, Seq: notDrawn, Tier: tier, Month: month, Record: carried[notDrawn], Proof: proofOf(notDrawn)}
		}, "sample: the selection", true},
		{"a record outside the scope (another app's clear record, carried and proved by the packet)", func(d *sampling.Document) {
			d.Selected[0] = sampling.Item{Change: "ch-0000000000000384", Seq: l.billing[0], Record: carried[l.billing[0]], Proof: proofOf(l.billing[0])}
		}, "sample: the selection", true},
		{"a record with no proof", func(d *sampling.Document) { d.Selected[3].Proof = sampling.Proof{} }, "ledger: inclusion proofs", true},
		{"a proof whose path is cut", func(d *sampling.Document) { d.Selected[3].Proof.Path = d.Selected[3].Proof.Path[1:] }, "ledger: inclusion proofs", true},
		{"a proof of another record", func(d *sampling.Document) { d.Selected[3].Proof = d.Selected[4].Proof }, "ledger: inclusion proofs", true},
		{"a record altered after it was logged", func(d *sampling.Document) {
			d.Selected[3].Record = json.RawMessage(strings.Replace(string(d.Selected[3].Record), `"policy"`, `"mallory"`, 1))
		}, "sample: records", true},
		{"a checkpoint root that is not the log's", func(d *sampling.Document) { d.Checkpoint.Root = p2hex('c') }, "ledger: inclusion proofs", true},
		{"a checkpoint note from another log", func(d *sampling.Document) { d.Checkpoint.Note = "x\n1\nAAAA\n\n— other AAAA\n" }, "ledger", true},
		{"a different seed than the one the sample was drawn with", func(d *sampling.Document) { d.Params.Seed = "fy26-q5" }, "sample: the selection", true},
		{"the seed removed", func(d *sampling.Document) { d.Params.Seed = "" }, "sample: the selection", true},
		{"a different n", func(d *sampling.Document) { d.Params.N = 10 }, "sample: the selection", true},
		{"a different stratification", func(d *sampling.Document) { d.Params.Stratify = sampling.StratifyTierMonth }, "sample: the selection", true},
		{"a population row edited (digest not fixed)", func(d *sampling.Document) { d.Population.Changes[0].State = "tampered" }, "sample: the population", true},
		{"the eligible figure inflated", func(d *sampling.Document) { d.Population.Eligible++ }, "sample: the population", true},
		{"a non-sampled change left out of the population, digest and counts recomputed (only the packet shows it)", func(d *sampling.Document) {
			for i, r := range d.Population.Changes {
				if r.ClearSeq != nil && *r.ClearSeq == notDrawn {
					d.Population.Changes = append(d.Population.Changes[:i], d.Population.Changes[i+1:]...)
					break
				}
			}
			rehash(d)
		}, "sample: against the packet", true},
		{"an undrawn eligible change reported as not cleared (digest recomputed)", func(d *sampling.Document) {
			for i := range d.Population.Changes {
				if r := &d.Population.Changes[i]; r.ClearSeq != nil && *r.ClearSeq == notDrawn {
					r.Eligible, r.Excluded, r.ClearSeq = false, sampling.ExcludedNotCleared, nil
				}
			}
			rehash(d)
		}, "sample: against the packet", true},
		{"a different packet digest", func(d *sampling.Document) {
			d.Packet.Digest = p2hex('9')
			d.Packet.ID = "pk-" + d.Packet.Digest[:32]
		}, "sample: against the packet", true},
		{"no record of the sampling named", func(d *sampling.Document) { d.Recorded = nil }, "sample: document", false},
		{"a sampling record from before the packet existed", func(d *sampling.Document) { d.Recorded.Seq = 1 }, "sample: against the packet", true},
		{"the wrong schema", func(d *sampling.Document) { d.Schema = "clearance.packet-sample/v2" }, "sample: document", false},
		{"no records at all", func(d *sampling.Document) { d.Selected, d.Params.N = nil, 0 }, "sample: records", true},
	}
	for _, c := range cases {
		doc := load()
		c.mutate(doc)
		b, _ := json.Marshal(doc)
		dir := ""
		if c.withPkt {
			dir = l.dir
		}
		rep := verify.VerifySample(writeSample(t, b), dir, l.trust())
		if rep.ExitCode() != 1 {
			var out strings.Builder
			rep.Write(&out)
			t.Errorf("%s: exit %d, not 1 (failed)\n%s", c.name, rep.ExitCode(), out.String())
			continue
		}
		hit := false
		for _, n := range failedChecks(rep) {
			hit = hit || strings.HasPrefix(n, c.check)
		}
		if !hit {
			t.Errorf("%s: the failing checks are %v, want one starting %q", c.name, failedChecks(rep), c.check)
		}
	}
	// The core's own record. A sample assembled offline (the rule is public) with a made-up `recorded` is consistent with
	// itself and is never exit 0; a record the caller read from the core that disagrees with the sample fails.
	fab := load()
	fake := map[string]any{"seq": json.Number("99999"), "prev_hash": p2hex('0'), "ts": "2026-11-09T06:00:00Z", "tool": "packet.sample", "decision": "allow",
		"packet": map[string]any{"id": fab.Packet.ID}, "delivery": map[string]any{"id": fab.Delivery, "recipient": fab.Recipient, "packet": fab.Packet.ID},
		"sample": map[string]any{"method": fab.Method, "population_sha256": fab.Population.SHA256, "effective_seed": fab.EffectiveSeed, "seed": fab.Params.Seed,
			"stratify": fab.Params.Stratify, "n": json.Number("25"), "selected": func() []any {
				var o []any
				for _, it := range fab.Selected {
					o = append(o, json.Number(fmt.Sprint(it.Seq)))
				}
				return o
			}()}}
	cb, _ := canon.Canonical(fake)
	fake["hash"] = canon.SHA256Hex(cb)
	fb, _ := json.Marshal(fake)
	fab.Recorded = &sampling.Recorded{Seq: 99999, Hash: fake["hash"].(string), Record: fb}
	fabRaw, _ := json.Marshal(fab)
	if rep := verify.VerifySample(writeSample(t, fabRaw), l.dir, l.trust()); rep.ExitCode() != 2 || rep.Failed() || checkNamed(t, rep, "sample: the core's packet.sample record").Status != verify.NotChecked {
		t.Errorf("a fabricated recorded: exit %d, failed %v", rep.ExitCode(), failedChecks(rep))
	}
	withReal := l.trust()
	withReal.SampleRecord, withReal.SampleRecordSrc = l.coreRecord(t, load().Recorded.Seq), "record.json"
	if rep := verify.VerifySample(writeSample(t, fabRaw), l.dir, withReal); rep.ExitCode() != 1 {
		t.Errorf("a fabricated recorded checked against the core's real record: exit %d", rep.ExitCode())
	}
	// Records the caller might be handed that are not this sampling's: another sampling's, an altered one, a record of another kind.
	_, otherRaw := l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "another"})
	var otherDoc sampling.Document
	_ = json.Unmarshal(otherRaw, &otherDoc)
	altered := strings.Replace(string(l.coreRecord(t, load().Recorded.Seq)), `"allow"`, `"deny"`, 1)
	for name, rec := range map[string][]byte{"another sampling's record": l.coreRecord(t, otherDoc.Recorded.Seq), "an altered record": []byte(altered), "not a record": []byte("{}"),
		"the packet's clear record": carried[l.eligible[0]]} {
		o := l.trust()
		o.SampleRecord, o.SampleRecordSrc = rec, "record.json"
		if rep := verify.VerifySample(writeSample(t, raw), l.dir, o); rep.ExitCode() != 1 || checkNamed(t, rep, "sample: the core's packet.sample record").Status != verify.Fail {
			t.Errorf("%s: exit %d", name, rep.ExitCode())
		}
	}
	// The wrong packet directory; a file that is not a sample; one that is not there; keys that are not the log's.
	other := filepath.Join(t.TempDir(), "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if rep := verify.VerifySample(writeSample(t, raw), other, l.trust()); rep.ExitCode() != 1 {
		t.Errorf("an empty directory for the packet: exit %d", rep.ExitCode())
	}
	if rep := verify.VerifySample(writeSample(t, []byte("not json")), "", l.trust()); rep.ExitCode() != 1 {
		t.Errorf("not json: exit %d", rep.ExitCode())
	}
	if rep := verify.VerifySample(filepath.Join(t.TempDir(), "absent.json"), "", l.trust()); rep.ExitCode() != 1 {
		t.Errorf("no file: exit %d", rep.ExitCode())
	}
	skey, vk, _, _ := ledger.GenerateKey("p2-test-ledger")
	_ = skey
	wrong := l.trust()
	wrong.LogKeys = []byte(vk + "\n")
	if rep := verify.VerifySample(writeSample(t, raw), l.dir, wrong); rep.ExitCode() != 1 {
		t.Errorf("keys that are not the log's: exit %d", rep.ExitCode())
	}
}

// -- the seed is the auditor's --------------------------------------------------------------------------------------

// There is no default seed: a seed that is a function of the packet alone is one the packet's builder can grind for. No seed
// is 400 and writes nothing.
func TestP2ASeedIsRequired(t *testing.T) {
	l := p2Lab(t, -1)
	d := l.deliver(t)
	before := len(l.f.records())
	for _, q := range []string{"", "n=5", "stratify=tier-month", "n=5&stratify=none", "seed", "seed="} {
		a := f(l, "/v1/packets/"+l.id+"/sample?"+q, d.Credential).want(t, 400, "seed is required")
		_ = a
	}
	if _, _, err := l.cl.Sample(context.Background(), l.id, d.Credential, assurance.SampleRequest{N: 5}); err == nil {
		t.Fatal("the client sent a sample call with no seed")
	}
	if len(l.f.records()) != before {
		t.Fatal("a call with no seed wrote a record")
	}
	var doc sampling.Document
	_, raw := l.sample(t, d.Credential, assurance.SampleRequest{N: 5, Seed: "s"})
	_ = json.Unmarshal(raw, &doc)
	if strings.Contains(string(raw), "seed_source") {
		t.Fatal("the document still has a seed source")
	}
}

// -- a leaked credential cannot lock a recipient out for good ----------------------------------------------------------

// The caps are per delivery: when a leaked credential has spent them, the subscriber's remedy is a new delivery for the same
// recipient and packet, which has fresh sample slots, read budget and refusal budget.
func TestP2ANewDeliveryHasFreshCaps(t *testing.T) {
	l := p2Lab(t, 25)
	old := l.deliver(t)
	for i := 0; i < server.MaxSamplesPerDelivery; i++ {
		l.sample(t, old.Credential, assurance.SampleRequest{N: 5, Seed: fmt.Sprint("x", i)})
	}
	f(l, "/v1/packets/"+l.id+"/sample?n=5&seed=more", old.Credential).want(t, 429, "") // the slots are spent
	for i := 0; i < 10; i++ {
		f(l, "/v1/packets/"+l.id+"/sample?n=5&seed=more", old.Credential).want(t, 429, "") // and the read budget (25 an hour) too
	}
	fresh := l.deliver(t)
	for i := 0; i < server.MaxSamplesPerDelivery; i++ {
		l.sample(t, fresh.Credential, assurance.SampleRequest{N: 5, Seed: fmt.Sprint("y", i)})
	}
	if _, _, err := l.cl.Sample(context.Background(), l.id, fresh.Credential, assurance.SampleRequest{N: 5, Seed: "y0"}); err != nil {
		t.Fatal("a sample already drawn is served again", err)
	}
}

// -- the index and what a repeat is ---------------------------------------------------------------------------------

// A repeat is the same draw, not the same bytes: a sampling the chain holds whose document digest is not today's (the document's
// shape changed since) is served; one whose draw differs (other records, another rule) is a real inconsistency and is refused.
func TestP2ARepeatIsTheSameDrawNotTheSameBytes(t *testing.T) {
	l := p2Lab(t, -1)
	d := l.deliver(t)
	first, _ := l.sample(t, d.Credential, assurance.SampleRequest{N: 5, Seed: "drawn"})
	resample := func(d2 server.Delivery, mut func(sm map[string]any)) {
		sm := map[string]any{"n": json.Number("5"), "seed": "drawn", "stratify": "none", "effective_seed": first.EffectiveSeed, "method": first.Method,
			"population_sha256": first.Population.SHA256, "sample_sha256": p2hex('7'), "selected": func() []any {
				var o []any
				for _, it := range first.Selected {
					o = append(o, json.Number(fmt.Sprint(it.Seq)))
				}
				return o
			}()}
		mut(sm)
		l.f.p2add(t, store.Event{"ts": time.Now().UTC().Format(time.RFC3339), "task_id": nil, "session": nil, "parent": nil, "principal": "recipient:" + l.rcp.name, "agent": nil,
			"tool": server.ToolPacketSample, "tier": nil, "decision": "allow", "rule": nil, "target": "packet:" + l.id, "args_sha256": l.bundle.Digest, "boundary": "deployment",
			"result": "written by hand", "packet": map[string]any{"id": l.id}, "delivery": map[string]any{"id": d2.ID, "recipient": l.rcp.name, "packet": l.id}, "sample": sm})
	}
	same, differs := l.deliver(t), l.deliver(t)
	resample(same, func(map[string]any) {})
	resample(differs, func(sm map[string]any) { sm["population_sha256"] = p2hex('8') })
	l.f.core.Server.ResetSampleIndexForTest()
	before := len(l.f.records())
	got, _, err := l.cl.Sample(context.Background(), l.id, same.Credential, assurance.SampleRequest{N: 5, Seed: "drawn"})
	if err != nil || !slices.Equal(seqsOf(got), seqsOf(first)) || got.Recorded.Seq != int64(before-2) {
		t.Fatalf("a recorded draw with another document digest was not served: %v", err)
	}
	if _, _, err := l.cl.Sample(context.Background(), l.id, differs.Credential, assurance.SampleRequest{N: 5, Seed: "drawn"}); !isStatus(err, 503) {
		t.Fatalf("a recorded draw that is not the draw now computed was served: %v", err)
	}
	if len(l.f.records()) != before {
		t.Fatal("a repeat wrote a record")
	}
}

// -- sizes ---------------------------------------------------------------------------------------------------------

// A sample the verifier would refuse to read is not served and not recorded.
func TestP2ASampleOverTheSizeCapIsRefusedBeforeItIsRecorded(t *testing.T) {
	l := p2Lab(t, -1)
	d := l.deliver(t)
	l.f.core.Server.SetSampleMaxForTest(12000)
	before := len(l.f.records())
	f(l, "/v1/packets/"+l.id+"/sample?n=25&seed=big", d.Credential).want(t, 413, "over 12000 bytes")
	if len(l.f.records()) != before {
		t.Fatal("a sample too large to serve was recorded")
	}
	l.f.core.Server.SetSampleMaxForTest(0)
	l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "big"})
}

// -- a write that may have committed -------------------------------------------------------------------------------

// A write that failed before commit is not served and writes nothing. One that failed after it (the commit happened, the answer
// was lost) is not served either, but the retry finds the record and does not write a second one.
func TestP2AFailedWriteIsNotServedAndARetryDoesNotDuplicate(t *testing.T) {
	l := p2Lab(t, -1)
	d := l.deliver(t)
	l.f.core.Server.FailAtomicForTest("before")
	f(l, "/v1/packets/"+l.id+"/sample?n=5&seed=a", d.Credential).want(t, 503, "not served")
	if n := len(l.sampleRecords()); n != 0 {
		t.Fatalf("%d records after a write that failed before commit", n)
	}
	l.sample(t, d.Credential, assurance.SampleRequest{N: 5, Seed: "a"})
	if n := len(l.sampleRecords()); n != 1 {
		t.Fatalf("%d records", n)
	}
	l.f.core.Server.FailAtomicForTest("after")
	f(l, "/v1/packets/"+l.id+"/sample?n=5&seed=b", d.Credential).want(t, 503, "not served")
	if n := len(l.sampleRecords()); n != 2 {
		t.Fatalf("%d records after a write that committed and failed", n)
	}
	got, _ := l.sample(t, d.Credential, assurance.SampleRequest{N: 5, Seed: "b"})
	if n := len(l.sampleRecords()); n != 2 || got.Recorded.Seq != int64(len(l.f.records())-1) {
		t.Fatalf("the retry wrote a second record for the same sampling (%d)", n)
	}
}

// -- Postgres ------------------------------------------------------------------------------------------------------

// The same flow on the Postgres store (CLEARANCE_TEST_DSN): a sample drawn through the real server, recorded, repeated for
// nothing, read back after the index is rebuilt from the chain, and verified offline with the record read from the core.
func TestP2SamplingOnPostgres(t *testing.T) {
	l := p2LabOn(t, -1, pgDSN(t))
	d := l.deliver(t)
	doc, raw := l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "pg"})
	if len(doc.Selected) != 25 || len(l.sampleRecords()) != 1 {
		t.Fatal(len(doc.Selected), len(l.sampleRecords()))
	}
	l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "pg"})
	l.f.core.Server.ResetSampleIndexForTest()
	again, _ := l.sample(t, d.Credential, assurance.SampleRequest{N: 25, Seed: "pg"})
	if len(l.sampleRecords()) != 1 || again.Recorded.Hash != doc.Recorded.Hash {
		t.Fatal("a repeat on Postgres wrote a record or named another")
	}
	if rep := verify.VerifySample(writeSample(t, raw), l.dir, l.trustFor(t, doc)); rep.ExitCode() != 0 {
		t.Fatal(failedChecks(rep))
	}
}
