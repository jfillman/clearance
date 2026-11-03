package pycompat

import (
	"bytes"
	"encoding/json"
	"math"
	"math/big"
	"os"
	"regexp"
	"testing"
)

type vectors struct {
	FloatRepr [][2]json.RawMessage `json:"float_repr"`
	StrRepr   [][2]string          `json:"str_repr"`
	Lower     [][2]string          `json:"lower"`
	Strip     [][2]string          `json:"strip"`
	DumpsLen  [][2]json.RawMessage `json:"dumps_len"`
	// DumpsSorted is [value, [compact, compact+ascii, spaced+ascii]] for json.dumps(sort_keys=True).
	DumpsSorted [][2]json.RawMessage `json:"dumps_sorted"`
	// Fnmatch is [name, pattern, fnmatch.fnmatchcase(name, pattern)].
	Fnmatch [][3]json.RawMessage `json:"fnmatch"`
}

// TestAgainstPython checks repr, lower, strip and json.dumps length against values Python produced
// (tools/golden/gen_vectors.py).
func TestAgainstPython(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.FloatRepr {
		var f float64
		var want string
		_ = json.Unmarshal(c[0], &f)
		_ = json.Unmarshal(c[1], &want)
		if string(c[0]) == "-0.0" {
			f = math.Copysign(0, -1)
		}
		if got := FloatRepr(f); got != want {
			t.Errorf("FloatRepr(%v) = %q, Python %q", f, got, want)
		}
	}
	for _, c := range v.StrRepr {
		if got := StrRepr(c[0]); got != c[1] {
			t.Errorf("StrRepr(%q) = %q, Python %q", c[0], got, c[1])
		}
	}
	for _, c := range v.Lower {
		if got := Lower(c[0]); got != c[1] {
			t.Errorf("Lower(%q) = %q, Python %q", c[0], got, c[1])
		}
	}
	for _, c := range v.Strip {
		if got := Strip(c[0]); got != c[1] {
			t.Errorf("Strip(%q) = %q, Python %q", c[0], got, c[1])
		}
	}
	for _, c := range v.DumpsLen {
		val, err := DecodeJSON(c[0])
		if err != nil {
			t.Fatal(err)
		}
		var want int
		_ = json.Unmarshal(c[1], &want)
		if got, _ := DumpsLen(val); got != want {
			t.Errorf("DumpsLen(%s) = %d, Python %d", c[0], got, want)
		}
	}
	if len(v.DumpsSorted) == 0 || len(v.Fnmatch) == 0 {
		t.Fatal("vectors.json has no dumps_sorted or fnmatch cases: regenerate it")
	}
	for _, c := range v.DumpsSorted {
		var want [3]string
		_ = json.Unmarshal(c[1], &want)
		opts := [3]Options{{}, {ASCII: true}, {ASCII: true, Spaced: true}}
		// Both value models: the dict model (DecodeJSON) and the JSON model (Decode).
		dict, err := DecodeJSON(c[0])
		if err != nil {
			t.Fatal(err)
		}
		plain, err := Decode(bytes.NewReader(c[0]))
		if err != nil {
			t.Fatal(err)
		}
		for i, o := range opts {
			for _, val := range []any{dict, plain} {
				if got, err := Dumps(val, o); err != nil || string(got) != want[i] {
					t.Errorf("Dumps(%s, %+v) = %s, %v; Python %s", c[0], o, got, err, want[i])
				}
			}
		}
	}
	for _, c := range v.Fnmatch {
		var name, pat string
		var want bool
		_ = json.Unmarshal(c[0], &name)
		_ = json.Unmarshal(c[1], &pat)
		_ = json.Unmarshal(c[2], &want)
		if got := Match(name, pat); got != want {
			t.Errorf("Match(%q, %q) = %v, fnmatchcase %v (regexp %s)", name, pat, got, want, FnmatchTranslate(pat))
		}
	}
}

func TestPythonEquality(t *testing.T) {
	nan := math.NaN()
	big1 := new(big.Int).Lsh(big.NewInt(1), 70)
	m1, m2 := NewMap(2), NewMap(2)
	m1.Set("a", int64(1))
	m1.Set("b", true)
	m2.Set("b", int64(1))
	m2.Set("a", 1.0)
	for _, c := range []struct {
		a, b   any
		eq, in bool
	}{
		{true, int64(1), true, true}, {int64(1), 1.0, true, true}, {false, 0.0, true, true}, {"1", int64(1), false, false},
		{nan, nan, false, true}, {[]any{nan}, []any{nan}, true, true}, {big1, big1, true, true},
		{big1, 1180591620717411303424.0, true, true}, {int64(9007199254740993), 9007199254740992.0, false, false},
		{m1, m2, true, true}, {nil, nil, true, true}, {nil, false, false, false},
		{Date{2024, 1, 1}, DateTime{Y: 2024, M: 1, D: 1}, false, false},
		{DateTime{Y: 2024, M: 1, D: 1, H: 5, Aware: true}, DateTime{Y: 2024, M: 1, D: 1, Aware: true, Offset: -5 * 3600}, true, true},
	} {
		if got := Equal(c.a, c.b); got != c.eq {
			t.Errorf("Equal(%v, %v) = %v", c.a, c.b, got)
		}
		if got := EqualIn(c.a, c.b); got != c.in {
			t.Errorf("EqualIn(%v, %v) = %v", c.a, c.b, got)
		}
	}
	// Keys that compare equal are one key: {1: x, True: y} is {1: 'y'}.
	m := NewMap(2)
	m.Set(int64(1), "x")
	m.Set(true, "y")
	if m.Len() != 1 || Repr(m) != "{1: 'y'}" {
		t.Errorf("python key equality: %s", Repr(m))
	}
	if !m.Set("k", nil) || m.Set([]any{}, nil) {
		t.Error("a list must be unhashable")
	}
}

func TestDecodeJSON(t *testing.T) {
	v, err := DecodeJSON([]byte(`{"b": 1, "a": [1.0, 1e400, 123456789012345678901234567890], "b": 2}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := Repr(v); got != "{'b': 2, 'a': [1.0, inf, 123456789012345678901234567890]}" {
		t.Errorf("got %s", got)
	}
	for _, bad := range []string{`{"a":1} x`, `{1:2}`, `[`, ``} {
		if _, err := DecodeJSON([]byte(bad)); err == nil {
			t.Errorf("DecodeJSON(%q) should fail", bad)
		}
	}
	deep := make([]byte, 0, 200)
	for range MaxDepth + 2 {
		deep = append(deep, '[')
	}
	if _, err := DecodeJSON(deep); err == nil {
		t.Error("deep nesting must fail")
	}
}

// FuzzFnmatchTranslate: every pattern translates to an expression Go compiles (so no glob silently matches nothing
// for a reason Python would not have), and matching never panics.
func FuzzFnmatchTranslate(f *testing.F) {
	for _, p := range []string{"a*c", "[z-a]", "[!z-a]", "[a-cz-x]", "[]-]", "[!]]", "[", "[[:alpha:]]", "[a&&b]", "é[é-ü]"} {
		f.Add(p, "abc")
	}
	f.Fuzz(func(t *testing.T, pat, name string) {
		if len(pat) > 256 {
			return
		}
		if _, err := regexp.Compile(FnmatchTranslate(pat)); err != nil {
			t.Fatalf("%q -> %s: %v", pat, FnmatchTranslate(pat), err)
		}
		_ = Match(name, pat)
	})
}
