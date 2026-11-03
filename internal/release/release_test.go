package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const root = "../.."

// The version a tag names is the repository's VERSION, and CHANGELOG.md says what it shipped (the release workflow
// fails a tag whose section is missing).
func TestTheChangelogHasASectionForThisVersion(t *testing.T) {
	v, err := Version(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, ChangelogPath))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "## [Unreleased]") {
		t.Error("CHANGELOG.md has no ## [Unreleased] section")
	}
	if !HasDatedSection(text, v) {
		t.Errorf("CHANGELOG.md has no '## [%s] - <date>' section", v)
	}
	notes, ok := Notes(text, v)
	if !ok || strings.Contains(notes, "## [") {
		t.Errorf("the notes for %s: ok=%v %q", v, ok, notes[:min(len(notes), 80)])
	}
}

func TestNotesExtractOneSection(t *testing.T) {
	cl := "# Changelog\n\n## [Unreleased]\n\n- next\n\n## [1.2.0] - 2026-11-03\n\nLead.\n\n### Added\n- a\n\n" +
		"## [1.1.0] - 2026-11-01\n\n- b\n\n[1.2.0]: https://x/compare/v1.1.0...v1.2.0\n"
	if got, ok := Notes(cl, "1.2.0"); !ok || got != "Lead.\n\n### Added\n- a" {
		t.Errorf("1.2.0: %v %q", ok, got)
	}
	if got, ok := Notes(cl, "v1.1.0"); !ok || got != "- b" {
		t.Errorf("1.1.0 stops at the link references: %v %q", ok, got)
	}
	if _, ok := Notes(cl, "999.0.0"); ok {
		t.Error("a missing version has notes")
	}
	if _, ok := Notes("## [2.0.0] - 2026-11-03\n\n## [1.0.0]\n- x\n", "2.0.0"); ok {
		t.Error("an empty section has notes")
	}
	if _, ok := Notes(cl, "1.2"); ok {
		t.Error("1.2 matched 1.2.0")
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{"0.29.0\n": "0.29.0", "1.2.3": "1.2.3", " 1.0.0rc1 \n": "1.0.0rc1"} {
		if got, err := ParseVersion([]byte(in)); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "\n", "latest", "v1.2.3", "1.2", "1.2.3\n1.2.4\n"} {
		if got, err := ParseVersion([]byte(in)); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}
