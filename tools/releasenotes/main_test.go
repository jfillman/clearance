package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/release"
)

func TestNotesAndTagCheckAgainstTheRepo(t *testing.T) {
	v, err := release.Version("../..")
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{v, "../../CHANGELOG.md"}, &out, &errb); code != 0 || strings.TrimSpace(out.String()) == "" ||
		strings.Contains(out.String(), "## [") {
		t.Fatalf("notes for %s: %d %q %q", v, code, out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := run([]string{"999.0.0", "../../CHANGELOG.md"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "999.0.0") {
		t.Errorf("a missing version: %d %q", code, errb.String())
	}
	out.Reset()
	if code := run([]string{"-root", "../..", "-check-tag", "v" + v}, &out, &errb); code != 0 || strings.TrimSpace(out.String()) != v {
		t.Errorf("the tag v%s: %d %q", v, code, out.String())
	}
	errb.Reset()
	if code := run([]string{"-root", "../..", "-check-tag", "v999.0.0"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), v) {
		t.Errorf("a tag VERSION does not name: %d %q", code, errb.String())
	}
	if code := run(nil, &out, &errb); code != 2 {
		t.Errorf("no arguments: %d", code)
	}
}
