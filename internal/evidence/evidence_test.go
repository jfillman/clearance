package evidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/canon"
)

var update = flag.Bool("update", false, "rewrite testdata/go-extended.jsonl (then run python_chain.py verify on it)")

// ReadJSONL reads one record per line, as the Python AuditLog and `psql -Atc "select record::text ..."` write.
func readJSONL(t testing.TB, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		v, err := canon.Parse(l)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v.(map[string]any))
	}
	return out
}

// GoEvents extends the Python fixture chain; deterministic, so go-extended.jsonl is reproducible.
var GoEvents = []map[string]any{
	{"ts": "2026-11-02T11:00:00Z", "tool": "session.open", "agent": "go", "decision": "allow", "rule": nil,
		"args_sha256": mustDigest(map[string]any{"b": 1, "a": []any{1.0, 2}})},
	{"ts": "2026-11-02T11:00:01Z", "tool": "model.call", "spend": map[string]any{"usd": 0.0123, "tokens": 1500},
		"ratio": 1e-05, "big": json.Number("123456789012345678901234567890"), "note": "café   \U0001f600 <&> \x7f \t\n\"\\"},
	{"ts": "2026-11-02T11:00:02Z", "tool": "repo.pr.open", "effect": map[string]any{"repo": "jfillman/x", "pr": 8},
		"coverage": "observed-not-attributed", "labels": []string{"b", "a"}, "env": map[string]string{"￿": "1", "\U00010000": "2"}},
	{"ts": "2026-11-02T11:00:03Z", "tool": "deploy.clear", "boundary": "deployment",
		"floats": []any{0.1, 1.5, 100.0, 1e-7, 2.5e-300, 9999999999999998.0, json.Number("1.50"), json.Number("1E2")}},
}

// goWriter seals GoEvents.
var goWriter = Writer{Provider: Provider{Name: "clearance", Version: "0.0.0-test"}}

func mustDigest(v any) string {
	d, err := canon.ArgsDigest(v)
	if err != nil {
		panic(err)
	}
	return d
}

func TestPythonChainVerifies(t *testing.T) {
	recs := readJSONL(t, "testdata/python-chain.jsonl")
	if ok, bad := Verify(recs); !ok || len(recs) != 4 {
		t.Fatalf("Python-written chain: ok=%v bad=%d n=%d", ok, bad, len(recs))
	}
	// The Python args_digest of the same value is the Go one.
	if recs[0]["args_sha256"] != mustDigest(map[string]any{"b": 1, "a": []any{1.0, 2}}) {
		t.Fatal("args digest differs from Python's")
	}
}

// TestExtendPythonChain appends Go records to the Python chain. testdata/go-extended.jsonl is this output,
// checked by Python's own audit.verify (python_chain.py verify) when it was written; the test proves Go still
// produces exactly those bytes.
func TestExtendPythonChain(t *testing.T) {
	recs := readJSONL(t, "testdata/python-chain.jsonl")
	v := NewVerifier()
	for _, r := range recs {
		if err := v.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	for _, r := range recs {
		c, _ := canon.Canonical(r)
		out.Write(c)
		out.WriteByte('\n')
	}
	head := v.Checkpoint()
	for _, e := range GoEvents {
		rec, full, err := Seal(head, e, goWriter)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Add(rec); err != nil {
			t.Fatal(err)
		}
		head = v.Checkpoint()
		out.Write(full)
		out.WriteByte('\n')
	}
	if *update {
		if err := os.WriteFile("testdata/go-extended.jsonl", out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/go-extended.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, out.Bytes()) {
		t.Fatalf("Go's extension differs from the Python-verified go-extended.jsonl")
	}
	if head.Count != 8 {
		t.Fatalf("count %d", head.Count)
	}
}

func TestFields(t *testing.T) {
	w := Writer{Provider: Provider{Name: "fixture-provider", Version: "1.2.3"}}
	f, err := Fields(map[string]any{"tool": "x", "zeta": json.Number("1"), "app": "a", "coverage": "observed-not-attributed"}, w)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := canon.Canonical(f)
	// test_evidence.py test_evidence_is_the_envelope_seal_adds: the same envelope.
	want := `{"boundary":"runtime","claimed":["zeta"],"coverage":"observed-not-attributed","provider":{"name":"fixture-provider","version":"1.2.3"},"schema":"clearance.evidence/v1","subject":null,"verified":["app","provider","subject","tool"]}`
	if string(got) != want {
		t.Fatalf("got %s", got)
	}
	if _, err := Fields(map[string]any{"boundary": nil}, w); !errors.Is(err, ErrInvalid) {
		t.Fatal("v1 refuses a null boundary")
	}
}

func lines(t *testing.T, path string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, l := range bytes.Split(must(os.ReadFile(path)), []byte("\n")) {
		if len(bytes.TrimSpace(l)) > 0 {
			out = append(out, l)
		}
	}
	return out
}

// v1Writer is python_chain.py writer(): the Writer a v1-events.jsonl line names.
func v1Writer(t *testing.T, w map[string]any) Writer {
	p := w["provider"].(map[string]any)
	out := Writer{Provider: Provider{Name: p["name"].(string), Version: p["version"].(string)}}
	if c, ok := w["intent_capture"].(string); ok {
		out.IntentCapture = c
	}
	switch w["verified"] {
	case nil, "gateway":
	case "provider":
		out.Verified = ProviderVerified
	default:
		t.Fatalf("verified %v", w["verified"])
	}
	return out
}

// TestPythonV1Identical seals v1-events.jsonl after the v0-draft python-chain.jsonl, as python_chain.py write-v1
// did with audit.AuditLog: every line must be the bytes Python wrote (python-v1.jsonl), so the Go and Python
// writers produce the same record for the same event, across the v0 to v1 boundary.
func TestPythonV1Identical(t *testing.T) {
	want := lines(t, "testdata/python-v1.jsonl")
	base := readJSONL(t, "testdata/python-chain.jsonl")
	v := NewVerifier()
	for _, r := range base {
		if err := v.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	head := v.Checkpoint()
	n := len(base)
	for i, l := range lines(t, "testdata/v1-events.jsonl") {
		x, err := canon.Parse(l)
		if err != nil {
			t.Fatal(err)
		}
		m := x.(map[string]any)
		rec, full, err := Seal(head, m["event"].(map[string]any), v1Writer(t, m["writer"].(map[string]any)))
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if !bytes.Equal(full, want[n+i]) {
			t.Fatalf("event %d: Go sealed\n%s\nPython sealed\n%s", i, full, want[n+i])
		}
		if err := v.Add(rec); err != nil {
			t.Fatal(err)
		}
		head = v.Checkpoint()
	}
	if int(head.Count) != len(want) {
		t.Fatalf("count %d, want %d", head.Count, len(want))
	}
}

// TestProjectMatchesPython: Project of each v0-draft row is audit.project's (python-projected.jsonl), and Stored
// gives back the row that was hashed.
func TestProjectMatchesPython(t *testing.T) {
	want := lines(t, "testdata/python-projected.jsonl")
	for i, r := range readJSONL(t, "testdata/python-chain.jsonl") {
		p := Project(r)
		got, _ := canon.Canonical(p)
		if !bytes.Equal(got, want[i]) {
			t.Fatalf("row %d: Go projected\n%s\nPython projected\n%s", i, got, want[i])
		}
		if ok, _ := Verify([]map[string]any{Stored(p)}); i == 0 && !ok {
			t.Fatal("Stored(Project(row 0)) does not verify")
		}
	}
	rec, _, err := Seal(Start, map[string]any{"tool": "x"}, goWriter)
	if err != nil {
		t.Fatal(err)
	}
	if p := Project(rec); len(p["projected"].([]any)) != 0 || p["provider"].(map[string]any)["name"] != "clearance" {
		t.Fatalf("a v1 record projects as itself: %v", p)
	}
}

func TestSubjectAndIntent(t *testing.T) {
	tree, head := strings.Repeat("c", 64), strings.Repeat("a", 40)
	for _, c := range []struct {
		ev   map[string]any
		want string // canonical subject
		tag  string // verified or claimed
	}{
		{map[string]any{"tool": "repo.pr.open", "args_sha256": tree}, `{"digests":{"sha256":"` + tree + `"},"kind":"tool-call","name":"repo.pr.open"}`, "verified"},
		{map[string]any{"tool": "deploy.clear", "boundary": "deployment", "change": map[string]any{"app": "g", "env": "prod", "tree": tree, "head": head}},
			`{"digests":{"gitCommit":"` + head + `","sha256":"` + tree + `"},"kind":"manifest-tree","name":"g/prod"}`, "claimed"},
		{map[string]any{"tool": "deploy.request", "boundary": "deployment", "args_sha256": tree}, `null`, "verified"},
		{map[string]any{"tool": "deploy.answer", "boundary": "deployment", "change": map[string]any{"tree": Genesis}}, `null`, "verified"},
		{map[string]any{"tool": "definition.load", "target": "r@1 p", "args_sha256": tree}, `{"digests":{"sha256":"` + tree + `"},"kind":"definition","name":"r@1 p"}`, "verified"},
		{map[string]any{"tool": "x", "subject": map[string]any{"kind": "terraform-plan", "digests": map[string]string{"sha256": "f"}}}, `{"digests":{"sha256":"f"},"kind":"terraform-plan"}`, "claimed"},
	} {
		rec, _, err := Seal(Start, c.ev, goWriter)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := canon.Canonical(rec["subject"])
		if string(got) != c.want {
			t.Errorf("%v: subject %s, want %s", c.ev["tool"], got, c.want)
		}
		tagged := false
		for _, k := range rec[c.tag].([]any) {
			tagged = tagged || k == "subject"
		}
		if !tagged {
			t.Errorf("%v: subject not %s", c.ev["tool"], c.tag)
		}
	}
	rec, full, err := Seal(Start, map[string]any{"tool": "x", "intent": "use hunter2"}, goWriter)
	if err != nil || bytes.Contains(full, []byte("hunter2")) || rec["intent"].(map[string]any)["capture"] != "redacted" {
		t.Fatalf("intent is redacted by default: %s %v", full, err)
	}
	full2 := Writer{Provider: goWriter.Provider, IntentCapture: "full"}
	if rec, _, _ := Seal(Start, map[string]any{"tool": "x", "intent": "use hunter2"}, full2); rec["intent"].(map[string]any)["text"] != "use hunter2" {
		t.Fatal("full capture keeps the text")
	}
}

func TestSealRejectsInvalid(t *testing.T) {
	for _, c := range []struct {
		ev map[string]any
		w  Writer
	}{
		{map[string]any{"boundary": "build"}, goWriter},
		{map[string]any{"coverage": "observed"}, goWriter},
		{map[string]any{"subject": map[string]any{"kind": "image", "digests": map[string]any{"sha256": "x"}}}, goWriter},
		{map[string]any{"subject": map[string]any{"kind": "tool-call", "digests": map[string]any{}}}, goWriter},
		{map[string]any{"subject": map[string]any{"kind": "tool-call", "digests": map[string]any{"sha-256": "x"}}}, goWriter},
		{map[string]any{"subject": "tool-call"}, goWriter},
		{map[string]any{"intent": map[string]any{"text": "x"}}, goWriter},
		{map[string]any{"intent": strings.Repeat("x", MaxIntent+1)}, goWriter},
		{map[string]any{}, Writer{Provider: Provider{Name: "Has Space", Version: "1"}}},
		{map[string]any{}, Writer{Provider: Provider{Name: "ok"}}},
		{map[string]any{}, Writer{Provider: Provider{Name: "ok", Version: "1"}, IntentCapture: "summary"}},
	} {
		if _, _, err := Seal(Start, c.ev, c.w); !errors.Is(err, ErrInvalid) {
			t.Errorf("Seal(%v, %v) = %v, want ErrInvalid", c.ev, c.w, err)
		}
	}
	if _, _, err := Seal(Start, map[string]any{"provider": map[string]any{"name": "me"}}, goWriter); !errors.Is(err, ErrEnvelopeField) {
		t.Errorf("an event may not name its provider: %v", err)
	}
}

func TestSealRejects(t *testing.T) {
	for _, c := range []struct {
		ev   map[string]any
		want error
	}{
		{map[string]any{"seq": 1}, ErrEnvelopeField},
		{map[string]any{"hash": "x", "verified": []any{}}, ErrEnvelopeField},
		{map[string]any{"x": math.NaN()}, ErrNotStorable},
		{map[string]any{"x": math.Inf(1)}, ErrNotStorable},
		{map[string]any{"x": []any{1e16}}, ErrNotStorable},
		{map[string]any{"x": map[string]any{"y": math.Copysign(0, -1)}}, ErrNotStorable},
		{map[string]any{"x": json.Number("1e400")}, ErrNotStorable},
		{map[string]any{"x": []float64{2e20}}, ErrNotStorable},
		{map[string]any{"x": "a\x00b"}, ErrNotStorable},
		{map[string]any{"a\x00": 1}, ErrNotStorable},
	} {
		if _, _, err := Seal(Start, c.ev, goWriter); !errors.Is(err, c.want) {
			t.Errorf("Seal(%v) = %v, want %v", c.ev, err, c.want)
		}
	}
	for _, ok := range []map[string]any{{"coverage": "coverage-unavailable", "boundary": "deployment"}, {"x": 9999999999999998.0}, {"x": 1e-300}, {"x": json.Number("-0")}} {
		if _, _, err := Seal(Start, ok, goWriter); err != nil {
			t.Errorf("Seal(%v): %v", ok, err)
		}
	}
}

func chain(t *testing.T, n int) []map[string]any {
	head := Start
	var out []map[string]any
	for i := 0; i < n; i++ {
		rec, _, err := Seal(head, map[string]any{"tool": "t", "i": i}, goWriter)
		if err != nil {
			t.Fatal(err)
		}
		head = Checkpoint{Count: head.Count + 1, Head: rec["hash"].(string)}
		out = append(out, rec)
	}
	return out
}

func clone(r map[string]any) map[string]any {
	c, _ := canon.Canonical(r)
	v, _ := canon.Parse(c)
	return v.(map[string]any)
}

func TestVerifyTamper(t *testing.T) {
	good := chain(t, 5)
	if ok, bad := Verify(good); !ok || bad != -1 {
		t.Fatal("good chain fails")
	}
	for name, mut := range map[string]func([]map[string]any) []map[string]any{
		"edit field":   func(c []map[string]any) []map[string]any { c[2]["i"] = json.Number("9"); return c },
		"edit hash":    func(c []map[string]any) []map[string]any { c[2]["hash"] = strings.Repeat("a", 64); return c },
		"drop":         func(c []map[string]any) []map[string]any { return append(c[:2], c[3:]...) },
		"swap":         func(c []map[string]any) []map[string]any { c[2], c[3] = c[3], c[2]; return c },
		"float seq":    func(c []map[string]any) []map[string]any { c[2]["seq"] = json.Number("2.0"); return c },
		"missing hash": func(c []map[string]any) []map[string]any { delete(c[2], "hash"); return c },
	} {
		c := make([]map[string]any, len(good))
		for i := range good {
			c[i] = clone(good[i])
		}
		if ok, bad := Verify(mut(c)); ok || bad != 2 {
			t.Errorf("%s: ok=%v bad=%d, want bad at 2", name, ok, bad)
		}
	}
}

func TestVerifyAgainst(t *testing.T) {
	c := chain(t, 4)
	h := func(i int) string { return c[i]["hash"].(string) }
	for _, tc := range []struct {
		recs []map[string]any
		cp   Checkpoint
		ok   bool
		msg  string
	}{
		{c, Checkpoint{4, h(3)}, true, "ok"},
		{c, Checkpoint{2, h(1)}, true, "ok"},
		{c, Start, true, "ok"},
		{c[:3], Checkpoint{4, h(3)}, false, "truncated: 3 records, anchored 4"},
		{c, Checkpoint{2, h(3)}, false, "history rewritten: anchored head does not match"},
		{c[1:], Checkpoint{1, h(1)}, false, "chain broken at record 0"},
	} {
		ok, msg := VerifyAgainst(tc.recs, tc.cp)
		if ok != tc.ok || msg != tc.msg {
			t.Errorf("VerifyAgainst(%d recs, %v) = %v %q, want %v %q", len(tc.recs), tc.cp, ok, msg, tc.ok, tc.msg)
		}
	}
}

// FuzzVerifyLine feeds arbitrary chain lines through Parse and the Verifier: never a panic.
func FuzzVerifyLine(f *testing.F) {
	sc := bufio.NewScanner(bytes.NewReader(must(os.ReadFile("testdata/python-chain.jsonl"))))
	for sc.Scan() {
		f.Add(append([]byte(nil), sc.Bytes()...))
	}
	f.Add([]byte(`{"seq":0,"prev_hash":"` + Genesis + `","hash":1}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		v, err := canon.Parse(line)
		if err != nil {
			return
		}
		r, ok := v.(map[string]any)
		if !ok {
			return
		}
		_ = NewVerifier().Add(r)
	})
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
