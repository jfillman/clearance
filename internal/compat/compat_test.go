package compat

import "testing"

func TestEmbeddedTableParses(t *testing.T) {
	tab := Embedded()
	if _, ok := tab.Exact("0.57.3"); !ok {
		t.Fatal("0.57.3, the last release before N-6, is not in the table")
	}
}

func TestAcceptsAndRefuses(t *testing.T) {
	tab := Table{Format: 1, Releases: []Release{
		{Core: "0.58.0", MinCore: "0.0.0", Providers: map[string]Range{"a": {Min: "0.57.0"}, "b": {Min: "0.50.0", Max: "0.60.0"}}},
	}}
	for _, c := range []struct {
		core, prog, ver string
		ok              bool
	}{
		{"0.58.0", "a", "0.57.0", true},
		{"0.58.0", "a", "v0.58.3", true},
		{"0.58.0", "a", "0.56.9", false}, // older than min
		{"0.58.4", "a", "0.56.9", false}, // a patch follows the 0.58.0 row
		{"0.58.0", "b", "0.60.0", false}, // max is exclusive
		{"0.58.0", "b", "0.59.9", true},
		{"0.58.0", "zzz", "0.0.1", true},    // no range for the program
		{"0.58.0", "a", "dev", true},        // a version that is not X.Y.Z is not checked
		{"0.58.0", "a", "0.57.0-rc1", true}, // suffix ignored
		{"dev", "a", "0.0.1", true},         // a core without a version checks nothing
		{"0.57.0", "a", "0.0.1", true},      // older than every row
	} {
		if ok, why := tab.Accepts(c.core, c.prog, c.ver); ok != c.ok || (!ok && why == "") {
			t.Errorf("%+v: ok=%v why=%q", c, ok, why)
		}
	}
}

func TestParseRejectsABadTable(t *testing.T) {
	for _, in := range []string{
		`{"format":2,"releases":[]}`,
		`{"format":1,"releases":[{"core":"1.0","min_core":"0.0.0"}]}`,
		`{"format":1,"releases":[{"core":"0.2.0","min_core":"0.0.0"},{"core":"0.1.0","min_core":"0.0.0"}]}`,
		`{"format":1,"releases":[{"core":"0.1.0","min_core":"0.0.0","extra":1}]}`,
		`{"format":1,"releases":[{"core":"0.1.0","min_core":"0.0.0","providers":{"a":{"min":"x"}}}]}`,
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("accepted %s", in)
		}
	}
}

func TestParseHeader(t *testing.T) {
	if p, v, ok := ParseHeader("argocd-agent/0.58.0"); !ok || p != "argocd-agent" || v != "0.58.0" {
		t.Fatal(p, v, ok)
	}
	for _, bad := range []string{"", "x", "/1.0.0", "a/", "a b/1.0.0"} {
		if _, _, ok := ParseHeader(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
}
