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
		"coverage": "observed", "labels": []string{"b", "a"}, "env": map[string]string{"￿": "1", "\U00010000": "2"}},
	{"ts": "2026-11-02T11:00:03Z", "tool": "deploy.clear", "boundary": "deployment",
		"floats": []any{0.1, 1.5, 100.0, 1e-7, 2.5e-300, 9999999999999998.0, json.Number("1.50"), json.Number("1E2")}},
}

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
		rec, full, err := Seal(head, e)
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
	f := Fields(map[string]any{"tool": "x", "zeta": 1, "app": "a", "coverage": "observed", "seq": 3})
	got, _ := canon.Canonical(f)
	want := `{"boundary":"runtime","claimed":["zeta"],"coverage":"observed","schema":"clearance.evidence/v0-draft","verified":["app","tool"]}`
	if string(got) != want {
		t.Fatalf("got %s", got)
	}
	f = Fields(map[string]any{"boundary": nil})
	if b, ok := f["boundary"]; !ok || b != nil {
		t.Fatal("a present boundary (even null) is kept, as event.get does")
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
		if _, _, err := Seal(Start, c.ev); !errors.Is(err, c.want) {
			t.Errorf("Seal(%v) = %v, want %v", c.ev, err, c.want)
		}
	}
	for _, ok := range []map[string]any{{"coverage": "x", "boundary": "deployment"}, {"x": 9999999999999998.0}, {"x": 1e-300}, {"x": json.Number("-0")}} {
		if _, _, err := Seal(Start, ok); err != nil {
			t.Errorf("Seal(%v): %v", ok, err)
		}
	}
}

func chain(t *testing.T, n int) []map[string]any {
	head := Start
	var out []map[string]any
	for i := 0; i < n; i++ {
		rec, _, err := Seal(head, map[string]any{"tool": "t", "i": i})
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
