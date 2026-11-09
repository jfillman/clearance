package packet_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
	"github.com/jfillman/clearance/internal/token"
)

func mustTime(t testing.TB, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func params(t testing.TB) packet.Params {
	return packet.Params{From: mustTime(t, winFrom), To: mustTime(t, winTo), Now: mustTime(t, nowAt), Version: "test",
		Scopes: []string{"aws-111", "k8s-prod", "ghost"}}
}

func allRecords(t testing.TB, st store.Reader) []store.Record {
	t.Helper()
	recs, err := st.Records(bg, 0, 100000)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func s(r store.Record, k string) string { v, _ := r[k].(string); return v }

func countOf(cs []packet.Count, state string) int {
	for _, c := range cs {
		if c.State == state {
			return c.Count
		}
	}
	return -1
}

// The packet's coverage counts are recounted here from the stored records and the store's own assurance column, not
// from the packet's code.
func TestLabPacketCountsMatchTheRecords(t *testing.T) {
	st, _ := labChain(t)
	res, err := packet.Build(bg, st, params(t))
	if err != nil {
		t.Fatal(err)
	}
	pk := res.Packet
	cov, ass := map[string]int{}, map[string]int{}
	total := 0
	for _, r := range allRecords(t, st) {
		ts := s(r, "ts")
		if ts < winFrom || ts >= winTo {
			continue
		}
		total++
		c := s(r, "coverage")
		cov[c]++
		a, err := st.Assurance(bg, seqI(r))
		if err != nil {
			t.Fatal(err)
		}
		ass[a]++
	}
	if total == 0 || pk.Coverage.Total != total {
		t.Fatalf("total %d, recount %d", pk.Coverage.Total, total)
	}
	sum := 0
	for _, state := range evidence.Coverage {
		n := countOf(pk.Coverage.ByCoverage, state)
		if n < 0 {
			t.Fatalf("coverage state %s is missing from the statement", state)
		}
		if n != cov[state] {
			t.Errorf("%s: packet %d, recount %d", state, n, cov[state])
		}
		if n == 0 {
			t.Errorf("the lab fixture should exercise %s", state)
		}
		sum += n
	}
	if sum != total {
		t.Fatalf("coverage states sum to %d, total %d", sum, total)
	}
	sum = 0
	for _, state := range evidence.Assurance {
		n := countOf(pk.Coverage.ByAssurance, state)
		if n < 0 || n != ass[state] {
			t.Errorf("assurance %s: packet %d, store %d", state, n, ass[state])
		}
		sum += n
	}
	if sum != total {
		t.Fatalf("assurance states sum to %d", sum)
	}
	mx := 0
	for _, m := range pk.Coverage.Matrix {
		mx += m.Total
		if m.Checkpoint+m.Recorded+m.NotRecorded != m.Total {
			t.Errorf("matrix row %+v", m)
		}
	}
	if mx != total {
		t.Fatalf("matrix %d", mx)
	}
	// The coverage statement per scope is the same one clearance-api builds.
	if pk.Header.Chain.Window != total {
		t.Errorf("records_in_window %d", pk.Header.Chain.Window)
	}
}

func TestLabPacketSections(t *testing.T) {
	st, seq := labChain(t)
	res, err := packet.Build(bg, st, params(t))
	if err != nil {
		t.Fatal(err)
	}
	pk := res.Packet

	// Changes: Argo and Terraform subjects side by side; failures, a rollback.
	by := map[string]packet.Change{}
	for _, c := range pk.Changes {
		by[c.ID] = c
	}
	if len(pk.Changes) != 5 {
		t.Fatalf("changes %d: exception and degraded reports are not changes", len(pk.Changes))
	}
	if by[chA].Subject.Kind != "manifest-tree" || by[chB].Subject.Kind != "terraform-plan" || by[chB].Subject.VariableSet != hexOf('e') {
		t.Errorf("subjects %+v %+v", by[chA].Subject, by[chB].Subject)
	}
	if o := by[chB].Outcome; o == nil || o.Matched == nil || !*o.Matched || !o.Verified || o.Reporter.Name != "clearance" {
		t.Errorf("B's outcome was compared and written by the core: %+v", o)
	}
	if o := by[chD].Outcome; o == nil || o.Reporter.Name != "terraform-ci" || o.Reporter.Conformance == "" || !by[chD].Failed {
		t.Errorf("D's outcome names the registered Terraform provider: %+v", o)
	}
	c := by[chC]
	if !c.Failed || c.State != "rolled-back" || c.Outcome.Rollback == nil || !*c.Outcome.Rollback.Used || c.Outcome.Rollback.To != "r1" {
		t.Errorf("C failed and was rolled back: %+v", c)
	}
	if by[chE].State != "denied" {
		t.Errorf("E %s", by[chE].State)
	}
	if by[chA].Attestation == nil || by[chA].Attestation.Bundle == "" {
		t.Errorf("A's attestation: %+v", by[chA].Attestation)
	}
	// The operational class is printed only where a record has it.
	if len(by[chA].OperationalClass) != 1 || by[chA].OperationalClass[0] != "availability" || by[chB].OperationalClass != nil {
		t.Errorf("operational class A %v B %v", by[chA].OperationalClass, by[chB].OperationalClass)
	}

	// Human-cleared: ApproversStatement's line for two people of kind person, and its absence for a pre-C-14 approval.
	hc := map[string]packet.HumanChange{}
	for _, h := range pk.HumanCleared {
		hc[h.Change] = h
	}
	approvals := []token.Approval{{Sub: "alice", Iss: "https://idp.example", Kind: "person"}, {Sub: "bob", Iss: "https://idp.example", Kind: "person"}}
	if want := token.ApproversStatement(approvals); want == "" || hc[chA].Statement != want || hc[chA].Approvers[0].Kind != "person" {
		t.Errorf("A: %+v", hc[chA])
	}
	if hc[chC].Statement != "" || !strings.Contains(hc[chC].Printed, "not provable") || hc[chC].Approvers[0].Kind != "" {
		t.Errorf("C: %+v", hc[chC])
	}
	if _, ok := hc[chB]; ok {
		t.Error("B was cleared by policy, not by a person")
	}

	// Exceptions: one row per class, every class listed.
	for _, class := range packet.ExceptionClasses {
		if countOf(pk.Exceptions.ByClass, class) < 1 {
			t.Errorf("class %s has no row", class)
		}
	}
	var oob packet.Exception
	for _, e := range pk.Exceptions.Rows {
		if e.Seq == seq["oob"] {
			oob = e
		}
	}
	if oob.Class != packet.ClassOutOfBand || oob.Window != "bg-1" || !strings.Contains(oob.Diff, "Deployment/gate-api/gate-api") || !strings.Contains(oob.Resolution, "bg-1") {
		t.Errorf("out-of-band row: %+v", oob)
	}
	var obs2 packet.Exception
	for _, e := range pk.Exceptions.Rows {
		if e.Seq == seq["obs2"] {
			obs2 = e
		}
	}
	if obs2.Resolution != "reverted" || obs2.Cause != "human-initiated" || obs2.Actor == "" {
		t.Errorf("observed out-of-band row: %+v", obs2)
	}
	if pk.Exceptions.Count != len(pk.Exceptions.Rows) {
		t.Error("count")
	}
	// The statement per scope counts what the exceptions rows count for observations.
	seen := 0
	for _, sc := range pk.Coverage.Scopes {
		seen += sc.Statement.Seen.Count
	}
	obsRows := 0
	for _, e := range pk.Exceptions.Rows {
		if e.Source == "observation" && e.Class != packet.ClassCorrelation {
			obsRows++
		}
	}
	if seen != obsRows {
		t.Errorf("statements saw %d not-cleared observations, the exceptions list %d", seen, obsRows)
	}

	// Coverage: the scope with no collector prints blind; the feed that went quiet is blind from then on.
	scopes := map[string]packet.ScopeState{}
	for _, sc := range pk.Coverage.Scopes {
		scopes[sc.Scope] = sc
	}
	if g := scopes["ghost"]; g.Collector || !strings.Contains(g.Text, "blind") || g.Statement.Clean {
		t.Errorf("ghost: %+v", g)
	}
	if k := scopes["k8s-prod"]; !k.Collector || k.Statement.State != "blind" || k.Statement.Clean || k.Statement.Blind.Seconds < 27*86400 {
		t.Errorf("k8s-prod: %+v", k.Statement.Health)
	}
	if a := scopes["aws-111"]; a.Statement.State != "healthy" || a.Statement.Clean {
		t.Errorf("aws-111 was healthy but saw things: %+v", a.Statement.State)
	}
	if pk.Coverage.WindowVerified || pk.Exceptions.Clean != "" {
		t.Error("a window with a blind scope is not verified")
	}
	kinds := map[string]bool{}
	for _, d := range pk.Coverage.Degraded {
		kinds[d.Kind] = true
	}
	for _, k := range []string{"core-outage", "feed-blind", "break-glass"} {
		if !kinds[k] {
			t.Errorf("degraded windows lack %s: %v", k, kinds)
		}
	}
	// Acceptances, policy, AI identities.
	ak := map[string]bool{}
	for _, a := range pk.Acceptances {
		ak[a.Kind] = true
	}
	if !ak["ratified"] || !ak["break-glass-window"] {
		t.Errorf("acceptances %v", ak)
	}
	pol := 0
	for _, p := range pk.Policy {
		if p.Kind == "policy-in-force" {
			pol++
		}
	}
	if pol != 2 {
		t.Errorf("policy in force changed twice: %+v", pk.Policy)
	}
	if len(pk.AIIdentities) != 1 || pk.AIIdentities[0].Agent != "triage-agent" || pk.AIIdentities[0].Denied != 1 {
		t.Errorf("ai identities %+v", pk.AIIdentities)
	}
	// Assertions: SOC 2 2017 CC8.1 first, 2027 draft CC7.1 second; nothing rests on a claim.
	if len(pk.Assertions) != 2 || pk.Assertions[0].Framework+"/"+pk.Assertions[0].Version != "soc2/2017" || pk.Assertions[0].Control != "CC8.1" ||
		pk.Assertions[1].Version != "2027-draft" || pk.Assertions[1].Control != "CC7.1" {
		t.Fatalf("assertions %+v", pk.Assertions)
	}
	st1 := map[string]packet.Assertion{}
	for _, c := range pk.Assertions {
		for _, a := range c.Assertions {
			st1[a.ID] = a
		}
	}
	if a := st1["cc8.1-applied-is-cleared"]; a.Supported != 1 || a.ClaimedOnly != 2 {
		t.Errorf("only the core's own plan comparison is support: %+v", a)
	}
	if a := st1["cc8.1-failures-rolled-back"]; a.Status != "not-met" || a.ClaimedOnly != 1 || a.Failed != 1 {
		t.Errorf("rollback: %+v", a)
	}
	if st1["cc8.1-no-unauthorized-change"].Status != "not-met" || st1["cc7.1-feeds-healthy"].Status == "met" {
		t.Errorf("%+v %+v", st1["cc8.1-no-unauthorized-change"], st1["cc7.1-feeds-healthy"])
	}
	if st1["cc8.1-evidence-checkpointed"].Status != "not-met" {
		t.Errorf("no ledger: %+v", st1["cc8.1-evidence-checkpointed"])
	}
}

// With no ledger the packet says so, and carries no proofs it cannot have.
func TestPacketWithoutALedgerSaysNotCheckpointed(t *testing.T) {
	st, _ := labChain(t)
	res, err := packet.Build(bg, st, params(t))
	if err != nil {
		t.Fatal(err)
	}
	v := res.Packet.Verification
	if v.Ledger.State != "no-checkpoint" || !strings.HasPrefix(v.Statement, "NOT CHECKPOINTED") || len(res.Proofs) != 0 || v.Proofs != "" || v.Ledger.Checkpointed != 0 {
		t.Fatalf("%+v", v)
	}
	if res.Packet.Header.Chain.Carried != len(res.Records) || len(res.Records) < res.Packet.Header.Chain.Window {
		t.Fatalf("carried %d records", len(res.Records))
	}
}

func miniChain(t testing.TB, evs ...store.Event) *memory.Store {
	st := memory.New()
	t.Cleanup(st.Close)
	l := &labber{t: t, st: st}
	for _, ev := range evs {
		w := obsW
		if ev["tool"] == "definition.load" {
			w = coreW
		}
		l.add(w, ev)
	}
	return st
}

// A clean exceptions list is printed only for a window with a healthy health record.
func TestCleanExceptionsListNeedsAHealthyWindow(t *testing.T) {
	p := packet.Params{From: mustTime(t, winFrom), To: mustTime(t, winTo), Now: mustTime(t, nowAt), Version: "test"}
	build := func(st *memory.Store, scopes ...string) *packet.Packet {
		q := p
		q.Scopes = scopes
		res, err := packet.Build(bg, st, q)
		if err != nil {
			t.Fatal(err)
		}
		return res.Packet
	}
	// Healthy for the whole window: the sentence is printed.
	pk := build(miniChain(t, health("2026-10-09T00:00:00Z", "aws-111", "healthy", 5184000)), "aws-111")
	if !pk.Coverage.WindowVerified || !strings.HasPrefix(pk.Exceptions.Clean, "No exceptions detected") || pk.Exceptions.Unverified != "" {
		t.Fatalf("healthy window: %+v", pk.Exceptions)
	}
	if !strings.Contains(string(packet.PDF(pk)), "No exceptions detected") {
		t.Error("the PDF should print it")
	}
	// A feed that starts late: blind for the stretch before it.
	pk = build(miniChain(t, health("2026-10-20T00:00:00Z", "aws-111", "healthy", 5184000)), "aws-111")
	if pk.Exceptions.Clean != "" || pk.Exceptions.Unverified == "" || pk.Coverage.WindowVerified {
		t.Fatalf("late feed: %+v", pk.Exceptions)
	}
	// A feed that stops: blind from when its hold ran out.
	pk = build(miniChain(t, health("2026-10-09T00:00:00Z", "aws-111", "healthy", 3600)), "aws-111")
	if pk.Exceptions.Clean != "" || !strings.Contains(pk.Exceptions.Unverified, "NOT verified") {
		t.Fatalf("stopped feed: %+v", pk.Exceptions)
	}
	if strings.Contains(string(packet.PDF(pk)), "No exceptions detected") || !strings.Contains(string(packet.PDF(pk)), "NOT A CLEAN LIST") {
		t.Error("the PDF must not print a clean list")
	}
	// Degraded is not healthy.
	pk = build(miniChain(t, health("2026-10-09T00:00:00Z", "aws-111", "degraded", 5184000)), "aws-111")
	if pk.Exceptions.Clean != "" {
		t.Fatal("degraded feed")
	}
	// A named scope with no collector prints blind.
	pk = build(miniChain(t, health("2026-10-09T00:00:00Z", "aws-111", "healthy", 5184000)), "aws-111", "nobody")
	if pk.Exceptions.Clean != "" || pk.Coverage.Scopes[1].Collector || !strings.Contains(pk.Coverage.Scopes[1].Text, "blind") {
		t.Fatalf("scope with no collector: %+v", pk.Coverage.Scopes)
	}
	// No scope at all (no collector anywhere): blind, never clean.
	pk = build(miniChain(t, health("2026-10-09T00:00:00Z", "aws-111", "healthy", 5184000)), []string{}...)
	_ = pk
	pk = build(memory.New())
	if pk.Exceptions.Clean != "" || pk.Coverage.WindowVerified || !strings.Contains(pk.Coverage.Text, "blind") {
		t.Fatalf("no collector: %+v", pk.Coverage)
	}
	if pk.Coverage.Total != 0 || len(pk.Coverage.ByCoverage) != len(evidence.Coverage) {
		t.Fatalf("an empty window still lists every state: %+v", pk.Coverage.ByCoverage)
	}
	// Healthy but something was seen: the list is not empty, and no clean sentence.
	pk = build(miniChain(t, health("2026-10-09T00:00:00Z", "aws-111", "healthy", 5184000), observation("2026-10-20T00:00:00Z", "aws-111", "PutBucketPolicy", "Bucket", nil)), "aws-111")
	if pk.Exceptions.Clean != "" || pk.Exceptions.Count != 1 {
		t.Fatalf("%+v", pk.Exceptions)
	}
}

func TestViewsAreScopedAndKeepTheCoverageStatement(t *testing.T) {
	st, _ := labChain(t)
	p := params(t)
	p.View, p.Title, p.Env, p.Cluster = packet.ViewIncident, "INC-42", "prod", "hangar-prod"
	res, err := packet.Build(bg, st, p)
	if err != nil {
		t.Fatal(err)
	}
	pk := res.Packet
	if pk.Header.View != "incident" || pk.Header.Title != "INC-42" || len(pk.Timeline) == 0 || len(pk.Assertions) != 0 || len(pk.HumanCleared) != 0 {
		t.Fatalf("incident view: %+v", pk.Header)
	}
	for _, c := range pk.Changes {
		if c.Env != "prod" || c.Place != "hangar-prod" {
			t.Errorf("out of scope: %+v", c)
		}
	}
	if len(pk.Coverage.ByCoverage) != len(evidence.Coverage) || len(pk.Coverage.ByAssurance) != len(evidence.Assurance) || pk.Coverage.Text == "" {
		t.Error("a scoped view still carries every coverage state")
	}
	for i := range pk.Timeline[1:] {
		if pk.Timeline[i].TS > pk.Timeline[i+1].TS {
			t.Fatal("timeline order")
		}
	}
	p.View = packet.ViewFreeze
	p.Title = "end-of-quarter freeze"
	res, err = packet.Build(bg, st, p)
	if err != nil || res.Packet.Header.View != "freeze" || len(res.Packet.Timeline) != 0 {
		t.Fatalf("%v %+v", err, res.Packet.Header)
	}
	if !strings.Contains(string(packet.PDF(res.Packet)), "CHANGE-FREEZE REPORT") {
		t.Error("freeze title")
	}
	p.View = "bogus"
	if _, err := packet.Build(bg, st, p); err == nil {
		t.Fatal("unknown view")
	}
	p.View = ""
	p.From = p.To
	if _, err := packet.Build(bg, st, p); err == nil {
		t.Fatal("empty window")
	}
}

func TestOutputsRenderInAllThreeFormsAndAreDeterministic(t *testing.T) {
	st, _ := labChain(t)
	dir1, dir2 := filepath.Join(t.TempDir(), "p"), filepath.Join(t.TempDir(), "p")
	var js [][]byte
	for _, dir := range []string{dir1, dir2} {
		res, err := packet.Build(bg, st, params(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := packet.Write(bg, dir, res, nil, nil); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(filepath.Join(dir, "packet.json"))
		js = append(js, b)
	}
	for _, f := range []string{"packet.json", "packet.pdf", "csv/changes.csv", "evidence/records.jsonl", "MANIFEST.json"} {
		a, _ := os.ReadFile(filepath.Join(dir1, f))
		b, _ := os.ReadFile(filepath.Join(dir2, f))
		if len(a) == 0 || !bytes.Equal(a, b) {
			t.Errorf("%s is not reproducible (%d, %d bytes)", f, len(a), len(b))
		}
	}
	if _, err := packet.Write(bg, dir1, &packet.Result{}, nil, nil); err == nil {
		t.Fatal("Write replaced a packet")
	}
	// JSON is canonical: parsing and canonicalizing it again gives the same bytes.
	v, err := canon.Parse(bytes.TrimRight(js[0], "\n"))
	if err != nil {
		t.Fatal(err)
	}
	again, _ := canon.Canonical(v)
	if !bytes.Equal(again, bytes.TrimRight(js[0], "\n")) {
		t.Error("packet.json is not canonical")
	}
	var pk packet.Packet
	if err := json.Unmarshal(js[0], &pk); err != nil {
		t.Fatal(err)
	}

	// CSV: one row per section row.
	rows := func(name string) int {
		f, err := os.Open(filepath.Join(dir1, "csv", name))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		recs, err := csv.NewReader(f).ReadAll()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return len(recs) - 1
	}
	humanRows := 0
	for _, h := range pk.HumanCleared {
		humanRows += len(h.Approvers)
	}
	ctl := 0
	for _, c := range pk.Assertions {
		ctl += len(c.Assertions)
	}
	for name, want := range map[string]int{"changes.csv": len(pk.Changes), "exceptions.csv": len(pk.Exceptions.Rows), "human-cleared.csv": humanRows,
		"ai-identities.csv": len(pk.AIIdentities), "assertions.csv": ctl, "policy-changes.csv": len(pk.Policy), "acceptances.csv": len(pk.Acceptances),
		"degraded-windows.csv": len(pk.Coverage.Degraded), "coverage-scopes.csv": len(pk.Coverage.Scopes), "coverage.csv": len(pk.Coverage.ByCoverage) + 1} {
		if got := rows(name); got != want || want == 0 {
			t.Errorf("%s: %d rows, section has %d", name, got, want)
		}
	}

	// PDF: structurally sound, and it prints the section's own numbers.
	pdf, _ := os.ReadFile(filepath.Join(dir1, "packet.pdf"))
	checkPDF(t, pdf)
	text := pdfText(pdf)
	for _, want := range []string{"COVERAGE STATEMENT", "CONTROL ASSERTIONS", "HUMAN-CLEARED CHANGES", "AI IDENTITIES", "EXCEPTIONS", "POLICY CHANGES", "VERIFICATION", "ACCEPTANCES",
		"terraform-plan", "manifest-tree", "terraform-ci", "approvers: distinct subjects, none automation", "NOT CHECKPOINTED", "ghost blind (no collector)",
		"soc2/2017 CC8.1", "soc2/2027-draft CC7.1", "operational class availability", "break-glass"} {
		if !strings.Contains(text, want) {
			t.Errorf("the PDF lacks %q", want)
		}
	}
	for _, c := range pk.Coverage.ByCoverage {
		if !strings.Contains(text, c.State) {
			t.Errorf("the PDF lacks coverage state %s", c.State)
		}
	}
	if strings.Contains(text, "No exceptions detected") {
		t.Error("the PDF printed a clean list for a window that was not verified")
	}
	// The manifest names every file with its digest.
	var man packet.Manifest
	raw, _ := os.ReadFile(filepath.Join(dir1, "MANIFEST.json"))
	if err := json.Unmarshal(raw, &man); err != nil || len(man.Files) < 15 {
		t.Fatalf("manifest: %v %d", err, len(man.Files))
	}
	for f, h := range man.Files {
		b, err := os.ReadFile(filepath.Join(dir1, filepath.FromSlash(f)))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != h {
			t.Errorf("%s digest", f)
		}
	}
	// CSV injection: a cell that begins with a formula character stays text.
	if cs, _ := packet.CSVs(&packet.Packet{Acceptances: []packet.Acceptance{{Detail: "=cmd()"}}}); !strings.Contains(string(cs["acceptances.csv"]), "'=cmd()") {
		t.Error("csv formula injection")
	}
}

var tjRx = regexp.MustCompile(`(?m)^BT /F\d [\d.]+ Tf [\d.]+ [\d.]+ Td \((.*)\) Tj ET$`)

func pdfText(pdf []byte) string {
	var sb strings.Builder
	for _, m := range tjRx.FindAllSubmatch(pdf, -1) {
		sb.Write(m[1])
		sb.WriteByte('\n')
	}
	return strings.NewReplacer(`\(`, "(", `\)`, ")", `\\`, `\`).Replace(sb.String())
}

// checkPDF verifies the file structure: header, EOF, every xref offset points at its object, the trailer's startxref
// at the table, and every stream's /Length is the stream's length.
func checkPDF(t *testing.T, pdf []byte) {
	t.Helper()
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4\n")) || !bytes.HasSuffix(pdf, []byte("%%EOF\n")) {
		t.Fatal("not a PDF 1.4 file")
	}
	i := bytes.LastIndex(pdf, []byte("startxref\n"))
	var off int
	if _, err := fmtSscan(string(pdf[i+len("startxref\n"):]), &off); err != nil || !bytes.HasPrefix(pdf[off:], []byte("xref\n")) {
		t.Fatalf("startxref: %v", err)
	}
	lines := strings.Split(string(pdf[off:]), "\n")
	var n int
	fmtSscan(lines[1], new(int), &n)
	for k := 1; k < n; k++ {
		o, _ := strconv.Atoi(lines[2+k][:10]) // Sscan would read the leading zeros as octal
		if !bytes.HasPrefix(pdf[o:], []byte(itoa(k)+" 0 obj\n")) {
			t.Fatalf("xref entry %d points at %q", k, pdf[o:o+12])
		}
	}
	for _, m := range regexp.MustCompile(`<< /Length (\d+) >>\nstream\n`).FindAllSubmatchIndex(pdf, -1) {
		var l int
		fmtSscan(string(pdf[m[2]:m[3]]), &l)
		if !bytes.HasPrefix(pdf[m[1]+l:], []byte("\nendstream")) {
			t.Fatalf("a stream's /Length is wrong")
		}
	}
	if !bytes.Contains(pdf, []byte("/BaseFont /Courier")) || !bytes.Contains(pdf, []byte("/Type /Catalog")) {
		t.Fatal("fonts or catalog")
	}
}

func TestOSCALComponentDefinitionIsPublishedAndSigned(t *testing.T) {
	ms, err := packet.AllMappings()
	if err != nil || len(ms) < 2 || ms[0].Key() != "soc2/2017" || ms[1].Key() != "soc2/2027-draft" ||
		ms[0].Controls[0].ID != "CC8.1" || ms[1].Controls[0].ID != "CC7.1" {
		t.Fatalf("mappings %v %v", ms, err)
	}
	doc, err := packet.OSCAL(ms)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := packet.OSCAL(ms)
	if !bytes.Equal(doc, again) {
		t.Fatal("the document is not reproducible")
	}
	var d struct {
		CD struct {
			UUID     string
			Metadata map[string]any
			Comps    []struct {
				UUID, Type, Title, Description string
				CI                             []struct {
					UUID, Source string
					IR           []struct {
						UUID      string
						ControlID string `json:"control-id"`
						Stmts     []struct {
							ID   string `json:"statement-id"`
							UUID string
						} `json:"statements"`
					} `json:"implemented-requirements"`
				} `json:"control-implementations"`
			} `json:"components"`
		} `json:"component-definition"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		t.Fatal(err)
	}
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	cd := d.CD
	if !uuid.MatchString(cd.UUID) || cd.Metadata["oscal-version"] != packet.OSCALVersion || cd.Metadata["title"] == "" || cd.Metadata["last-modified"] == "" || cd.Metadata["version"] == "" ||
		len(cd.Comps) != 1 || cd.Comps[0].Type != "service" || len(cd.Comps[0].CI) != 2 {
		t.Fatalf("%+v", cd)
	}
	ci := cd.Comps[0].CI
	if ci[0].Source != "urn:clearance:mapping:soc2:2017" || ci[0].IR[0].ControlID != "CC8.1" || ci[1].IR[0].ControlID != "CC7.1" || len(ci[0].IR[0].Stmts) == 0 {
		t.Fatalf("%+v", ci)
	}
	for _, c := range ci {
		for _, ir := range c.IR {
			if !uuid.MatchString(ir.UUID) {
				t.Errorf("uuid %s", ir.UUID)
			}
		}
	}
	// Signed as DSSE with an ECDSA P-256 key: the signature verifies over the PAE.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := token.NewKeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	env, err := packet.SignOSCAL(bg, doc, signer)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	sig, _ := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	dg := sha256.Sum256(token.PAE(env.PayloadType, payload))
	if !bytes.Equal(payload, doc) || env.PayloadType != packet.OSCALPayloadType || !ecdsa.VerifyASN1(&key.PublicKey, dg[:], sig) || env.Signatures[0].KeyID != signer.KeyID() {
		t.Fatal("the DSSE envelope does not verify")
	}
	// A packet written with a key carries the signed document.
	st, _ := labChain(t)
	res, err := packet.Build(bg, st, params(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "p")
	if _, err := packet.Write(bg, dir, res, []string{"json"}, signer); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"oscal/component-definition.json", "oscal/component-definition.dsse.json", "packet.json", "evidence/records.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "packet.pdf")); err == nil {
		t.Error("--format json wrote a pdf")
	}
	if _, err := packet.SelectMappings([]string{"nist/800-53"}); err == nil {
		t.Error("unknown mapping")
	}
}

// Free text from a provider reaches the PDF: parentheses, backslashes, control characters and wide runes cannot break
// out of the string they are written in.
func TestHostileTextCannotBreakThePDF(t *testing.T) {
	hostile := ") Tj ET BT /F1 99 Tf 0 0 Td (injected \\ \x1b ‮ \U0001F600 \r\n(((("
	st := miniChain(t, health("2026-10-09T00:00:00Z", "aws-111", "healthy", 5184000))
	l := &labber{t: t, st: st}
	l.add(argoW, gate("2026-10-20T00:00:00Z", "deploy.exception", "gate-api", "prod", map[string]any{"coverage": "out-of-band-detected",
		"destination": map[string]any{"cluster": "c", "environment": "prod"}, "exception": map[string]any{"kind": "out-of-band", "detail": hostile, "actor": hostile}}))
	res, err := packet.Build(bg, st, packet.Params{From: mustTime(t, winFrom), To: mustTime(t, winTo), Now: mustTime(t, nowAt), Version: "test", Scopes: []string{"aws-111"}})
	if err != nil {
		t.Fatal(err)
	}
	pdf := packet.PDF(res.Packet)
	checkPDF(t, pdf)
	// Every text line is exactly one well-formed text object: a line starting BT matches the whole pattern, so the
	// hostile text, which contains operators of its own, stayed inside its string.
	if bt, whole := len(regexp.MustCompile(`(?m)^BT `).FindAll(pdf, -1)), len(tjRx.FindAll(pdf, -1)); bt != whole || bt < 100 {
		t.Fatalf("%d text objects, %d well formed", bt, whole)
	}
	if !strings.Contains(pdfText(pdf), "injected") {
		t.Fatal("the hostile text should print as text")
	}
	csvs, _ := packet.CSVs(res.Packet)
	if len(csvs["exceptions.csv"]) == 0 {
		t.Fatal("no csv")
	}
}
