package pycompat

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFloatRepr(t *testing.T) {
	for f, want := range map[float64]string{1: "1.0", 1.5: "1.5", 1e16: "1e+16", 1e15: "1000000000000000.0", 0.0001: "0.0001",
		0.00001: "1e-05", -0.0: "0.0", 123456789.123: "123456789.123", 1.5e-07: "1.5e-07", 2.5e20: "2.5e+20"} {
		if got := FloatRepr(f); got != want {
			t.Errorf("%v: %s, want %s", f, got, want)
		}
	}
}

func TestDumpsMatchesJSONDumps(t *testing.T) {
	v := map[string]any{"b": []any{json.Number("1"), json.Number("1.50"), true, nil}, "a": "café <&> \u2028\x01", "z": map[string]any{}}
	cases := map[Options]string{
		{}:                          `{"a":"café <&> ` + "\u2028" + `\u0001","b":[1,1.5,true,null],"z":{}}`,
		{ASCII: true}:               `{"a":"caf\u00e9 <&> \u2028\u0001","b":[1,1.5,true,null],"z":{}}`,
		{ASCII: true, Spaced: true}: `{"a": "caf\u00e9 <&> \u2028\u0001", "b": [1, 1.5, true, null], "z": {}}`,
	}
	for o, want := range cases {
		got, err := Dumps(v, o)
		if err != nil || string(got) != want {
			t.Errorf("%+v:\n got %s\nwant %s", o, got, want)
		}
	}
}

func TestMatchIsFnmatchcase(t *testing.T) {
	for _, c := range []struct {
		name, pat string
		want      bool
	}{{"app-gate-api-cicd/pipeline-runner", "app-*-cicd/pipeline-runner", true}, {"a/b/c", "a*c", true}, {"abc", "a?c", true},
		{"aXc", "a[!X]c", false}, {"a-c", "a[a-z-]c", true}, {"user:root", "user:*", true}, {"User:root", "user:*", false},
		{"x", "[", false}, {"[", "[", true}, {"a\nb", "a*b", true}} {
		if got := Match(c.name, c.pat); got != c.want {
			t.Errorf("Match(%q, %q) = %v", c.name, c.pat, got)
		}
	}
}

func TestReprAndStr(t *testing.T) {
	for v, want := range map[any]string{"it's": `"it's"`, "a'b\"c": `'a\'b"c'`, "x": "'x'"} {
		if got := Repr(v); got != want {
			t.Errorf("%v: %s", v, got)
		}
	}
	if Str(nil) != "None" || Str(json.Number("1.0")) != "1.0" || Str(json.Number("1e2")) != "100.0" || Str(true) != "True" ||
		Str(map[string]any{"k": "v", "a": json.Number("1")}) != "{'a': 1, 'k': 'v'}" {
		t.Fatal("str")
	}
}

func TestIsoformat(t *testing.T) {
	t0 := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	if Isoformat(t0) != "2026-09-26T12:00:00+00:00" || Isoformat(t0.Add(1500*time.Microsecond)) != "2026-09-26T12:00:00.001500+00:00" || ISO(t0) != "2026-09-26T12:00:00Z" {
		t.Fatal(Isoformat(t0))
	}
	back, err := ParseIsoformat("2026-09-26T12:00:00.001500+00:00")
	if err != nil || !back.Equal(t0.Add(1500*time.Microsecond)) {
		t.Fatal(back, err)
	}
	if Truncate("héllo", 2) != "hé" || Len("hé") != 2 || !strings.HasPrefix(ArgsDigest(map[string]any{"run": 1}), "") {
		t.Fatal("truncate")
	}
}

func TestArgsDigestOfAStructIsItsObject(t *testing.T) {
	type s struct {
		B int    `json:"b"`
		A string `json:"a"`
	}
	if ArgsDigest(s{1, "x"}) != ArgsDigest(map[string]any{"a": "x", "b": json.Number("1")}) || ArgsDigest(s{1, "x"}) == "" {
		t.Fatal("digest")
	}
	// audit.args_digest({"rule": "DG-POLICY"}) in Python
	if got := ArgsDigest(map[string]any{"rule": "DG-POLICY"}); got != SHA256Hex([]byte(`{"rule":"DG-POLICY"}`)) {
		t.Fatal(got)
	}
}
