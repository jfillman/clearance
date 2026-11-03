package canon

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

type vector struct {
	In        string  `json:"in"`
	Out       *string `json:"out"`
	GoRejects bool    `json:"go_rejects"`
}

// TestPythonVectors replays testdata/vectors.jsonl, generated once by gen_vectors.py from Python's own
// json.loads + canonical: Go must produce the same bytes, or fail where Python fails.
func TestPythonVectors(t *testing.T) {
	f, err := os.Open("testdata/vectors.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	var n, agree, pyErr, rejects int
	for sc.Scan() {
		var v vector
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		n++
		val, err := Parse([]byte(v.In))
		var got []byte
		if err == nil {
			got, err = Canonical(val)
		}
		switch {
		case v.GoRejects:
			rejects++
			if err == nil {
				t.Errorf("line %d: %q: Go accepted a NaN/Infinity token", n, v.In)
			}
		case v.Out == nil:
			pyErr++
			if err == nil {
				t.Errorf("line %d: %q: Python fails, Go gave %q", n, v.In, got)
			}
		case err != nil:
			t.Errorf("line %d: %q: Go failed (%v), Python gave %q", n, v.In, err, *v.Out)
		case string(got) != *v.Out:
			t.Errorf("line %d: %q:\n got %q\nwant %q", n, v.In, got, *v.Out)
		default:
			agree++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 3000 || agree < 2900 {
		t.Fatalf("only %d vectors (%d agreeing): the comparison is vacuous", n, agree)
	}
	t.Logf("%d vectors: %d byte-identical, %d both fail, %d NaN/Infinity rejected by design", n, agree, pyErr, rejects)
}

func TestPyFloat(t *testing.T) {
	for _, c := range []struct {
		f    float64
		want string
	}{
		{1, "1.0"}, {-1, "-1.0"}, {0, "0.0"}, {math.Copysign(0, -1), "-0.0"}, {1e-5, "1e-05"}, {1e-4, "0.0001"},
		{1e16, "1e+16"}, {9999999999999998, "9999999999999998.0"}, {1e22, "1e+22"}, {0.1, "0.1"},
		{1.5e300, "1.5e+300"}, {5e-324, "5e-324"}, {123456789012345678, "1.2345678901234568e+17"},
		{math.Inf(1), "Infinity"}, {math.Inf(-1), "-Infinity"}, {math.NaN(), "NaN"}, {100, "100.0"},
		{1.25e-7, "1.25e-07"}, {0.000123, "0.000123"}, {1e15, "1000000000000000.0"},
	} {
		if got := PyFloat(c.f); got != c.want {
			t.Errorf("PyFloat(%v) = %q, want %q", c.f, got, c.want)
		}
	}
}

// TestGoValues covers the Go types callers pass directly (not from Parse).
func TestGoValues(t *testing.T) {
	type ss []string
	for _, c := range []struct {
		v    any
		want string
	}{
		{map[string]any{"b": 1, "a": []any{true, nil, 1.0, json.Number("2"), "x"}}, `{"a":[true,null,1.0,2,"x"],"b":1}`},
		{[]string{"a", "<&>"}, `["a","<&>"]`},
		{ss{"z"}, `["z"]`},
		{map[string]string{"k": "\u2028"}, "{\"k\":\"\u2028\"}"},
		{[]int{1, 2}, `[1,2]`},
		{json.RawMessage(`{"b":1.50, "a":-0}`), `{"a":0,"b":1.5}`},
		{map[string]any{"\U00010000": 1, "\uffff": 2}, "{\"\uffff\":2,\"\U00010000\":1}"},
		{"\x00\x1f\x7f", `"\u0000\u001f` + "\x7f\""},
		{int64(-9223372036854775808), "-9223372036854775808"},
		{uint64(18446744073709551615), "18446744073709551615"},
		{json.Number("-0.0"), "-0.0"},
		{json.Number("1e400"), "Infinity"},
		{(*int)(nil), "null"},
	} {
		got, err := Canonical(c.v)
		if err != nil {
			t.Errorf("Canonical(%#v): %v", c.v, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("Canonical(%#v) = %q, want %q", c.v, got, c.want)
		}
	}
	for _, bad := range []any{"\xff", json.Number("01"), json.Number("1."), map[int]any{1: 1}, struct{}{}, json.Number(strings.Repeat("9", 4301))} {
		if _, err := Canonical(bad); err == nil {
			t.Errorf("Canonical(%#v): want an error", bad)
		}
	}
}

func TestArgsDigest(t *testing.T) {
	// Python: hashlib.sha256(json.dumps({}, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()).hexdigest()
	got, err := ArgsDigest(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		t.Fatalf("ArgsDigest({}) = %s", got)
	}
}

func TestParseDepth(t *testing.T) {
	deep := strings.Repeat("[", MaxDepth+2) + strings.Repeat("]", MaxDepth+2)
	if _, err := Parse([]byte(deep)); err == nil {
		t.Fatal("want a depth error")
	}
}

func FuzzCanonical(f *testing.F) {
	for _, s := range []string{`{}`, `[1,2.0,-0,"\u2028"]`, `{"a":{"b":[null,true,1e400]}}`, `"\ud83d\ude00"`, `1E5`, `-0.0`, "\"\x7f\""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Parse(data)
		if err != nil {
			return
		}
		if !json.Valid(data) {
			t.Fatalf("Parse accepted invalid JSON %q", data)
		}
		c, err := Canonical(v)
		if err != nil {
			// The only values Parse yields that Canonical refuses: none, every parsed value is printable.
			t.Fatalf("Canonical of a parsed value failed: %v", err)
		}
		if strings.Contains(string(c), "Infinity") {
			return // an overflowed float literal prints as Python does, and that token does not re-parse
		}
		v2, err := Parse(c)
		if err != nil {
			t.Fatalf("canonical output %q does not re-parse: %v", c, err)
		}
		c2, err := Canonical(v2)
		if err != nil || string(c2) != string(c) {
			t.Fatalf("canonical is not idempotent: %q -> %q (%v)", c, c2, err)
		}
	})
}
