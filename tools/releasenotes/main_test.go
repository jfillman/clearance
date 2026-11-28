package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/release"
	"github.com/jfillman/clearance/internal/store/pg"
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
	if code := run([]string{"-root", "../..", "-check-tag", "v" + v}, &out, &errb); code != 0 && !strings.Contains(errb.String(), "labelled for release") {
		// Until the release that ships migration 1 is cut, VERSION is before it and the tag check says so.
		t.Errorf("the tag v%s: %d %q", v, code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"-root", "../..", "-check-tag", "v999.0.0"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), v) {
		t.Errorf("a tag VERSION does not name: %d %q", code, errb.String())
	}
	if code := run(nil, &out, &errb); code != 2 {
		t.Errorf("no arguments: %d", code)
	}
}

// releaseRoot is a module root whose VERSION is version, with the repository's compatibility table and the changelog's
// section.
func releaseRoot(t *testing.T, version, notes string) string {
	t.Helper()
	root := t.TempDir()
	tab, err := os.ReadFile("../../internal/compat/compat.json")
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		"VERSION":                     version + "\n",
		"CHANGELOG.md":                "# Changelog\n\n## [" + version + "] - 2026-12-01\n\n" + notes + "\n",
		"internal/compat/compat.json": string(tab),
	} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestTheTagOfTheReleaseThatShipsMigrationOnePasses(t *testing.T) {
	var out, errb bytes.Buffer
	root := releaseRoot(t, "0.58.0", "### Added\n\n- versioned migrations\n")
	if code := run([]string{"-root", root, "-check-tag", "v0.58.0"}, &out, &errb); code != 0 {
		t.Fatalf("%d %q", code, errb.String())
	}
}

// A contract migration's release must say so: no-rollback, and the migration's name (N-6b).
func TestAContractReleaseMustNameItsMigrationInTheNotes(t *testing.T) {
	list := []pg.Migration{{Version: 1, Name: "baseline", Kind: pg.KindExpand, Release: "0.58.0", MinCore: "0.0.0", DDL: pg.Schema},
		{Version: 2, Name: "drop-legacy", Kind: pg.KindContract, Release: "0.58.0", MinCore: "0.58.0", DDL: "ALTER TABLE a DROP COLUMN b;"}}
	bare := releaseRoot(t, "0.58.0", "### Changed\n\n- things\n")
	problems := strings.Join(checkMigrations(bare, "0.58.0", list), "\n")
	if !strings.Contains(problems, "must say the release is no-rollback and name contract migration 2 (drop-legacy)") {
		t.Fatalf("notes that do not name the migration passed:\n%s", problems)
	}
	named := releaseRoot(t, "0.58.0", "### Changed\n\n- **no-rollback**: migration 2 (drop-legacy) drops a column; restore the pre-upgrade backup to go back.\n")
	if problems := strings.Join(checkMigrations(named, "0.58.0", list), "\n"); strings.Contains(problems, "must say") {
		t.Fatalf("notes that name it failed:\n%s", problems)
	}
	// Notes that are missing are not an exemption.
	empty := t.TempDir()
	tab, _ := os.ReadFile("../../internal/compat/compat.json")
	_ = os.MkdirAll(filepath.Join(empty, "internal", "compat"), 0o755)
	_ = os.WriteFile(filepath.Join(empty, "internal", "compat", "compat.json"), tab, 0o644)
	if problems := strings.Join(checkMigrations(empty, "0.58.0", list), "\n"); !strings.Contains(problems, "its notes cannot be read") {
		t.Fatalf("a contract release with no changelog passed:\n%s", problems)
	}
	// And a migration labelled for a later release than the tag is refused.
	if problems := strings.Join(checkMigrations(named, "0.57.3", list), "\n"); !strings.Contains(problems, "labelled for release 0.58.0, after 0.57.3") {
		t.Fatalf("%s", problems)
	}
}
