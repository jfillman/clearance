// Command releasenotes prints one version's section of CHANGELOG.md, the GitHub Release's notes
// (.github/workflows/release.yaml), or checks that a tag names the repository's VERSION.
//
//	go run ./tools/releasenotes 0.29.0 [CHANGELOG.md]   # the notes; exit 1, naming the version, when there are none
//	go run ./tools/releasenotes -check-tag v0.29.0      # exit 1 unless the tag is v<VERSION>, the migrations obey the rules
//	                                                    # (N-6e), none is labelled for a later release, and the notes of a
//	                                                    # release with a contract migration name it and say no-rollback (N-6b)
//
// A tag cut without its notes fails the release instead of publishing an empty one.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfillman/clearance/internal/compat"
	"github.com/jfillman/clearance/internal/release"
	"github.com/jfillman/clearance/internal/store/pg"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// checkMigrations is what the tag's release must satisfy about its schema: the rules of N-6e (pg.CheckMigrations) against
// the compatibility table, no migration labelled for a release after this one, and, for each contract migration released
// here, notes that say the release is no-rollback and name the migration.
func checkMigrations(root, version string, list []pg.Migration) []string {
	var problems []string
	b, err := os.ReadFile(filepath.Join(root, "internal", "compat", "compat.json"))
	if err != nil {
		return []string{err.Error()}
	}
	tab, err := compat.Parse(b)
	if err != nil {
		return []string{"internal/compat/compat.json: " + err.Error()}
	}
	problems = append(problems, pg.CheckMigrations(list, tab, pg.UnusedShapes())...)
	notes, notesErr := "", error(nil)
	if cl, err := os.ReadFile(filepath.Join(root, release.ChangelogPath)); err != nil {
		notesErr = err
	} else if n, ok := release.Notes(string(cl), version); ok {
		notes = n
	} else {
		notesErr = fmt.Errorf("%s has no section for %s", release.ChangelogPath, version)
	}
	for _, m := range list {
		if later, ok := compat.Less(version, m.Release); ok && later {
			problems = append(problems, fmt.Sprintf("migration %d (%s) is labelled for release %s, after %s", m.Version, m.Name, m.Release, version))
		}
		if m.Kind == pg.KindContract && m.Release == version {
			low := strings.ToLower(notes)
			if notesErr != nil {
				problems = append(problems, fmt.Sprintf("release %s carries contract migration %d (%s) and its notes cannot be read: %v", version, m.Version, m.Name, notesErr))
			} else if !strings.Contains(low, "no-rollback") || !strings.Contains(low, strings.ToLower(m.Name)) {
				problems = append(problems, fmt.Sprintf(
					"the notes for %s must say the release is no-rollback and name contract migration %d (%s): its only way back is the pre-upgrade backup",
					version, m.Version, m.Name))
			}
		}
	}
	return problems
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("releasenotes", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tag := fs.String("check-tag", "", "check that this tag is v<VERSION> and print the version")
	root := fs.String("root", ".", "the module root (VERSION)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tag != "" {
		v, err := release.Version(*root)
		if err != nil {
			fmt.Fprintln(stderr, "releasenotes:", err)
			return 1
		}
		if *tag != "v"+v {
			fmt.Fprintf(stderr, "releasenotes: tag %s but VERSION says %s\n", *tag, v)
			return 1
		}
		if problems := checkMigrations(*root, v, pg.Migrations()); len(problems) > 0 {
			for _, p := range problems {
				fmt.Fprintln(stderr, "releasenotes:", p)
			}
			return 1
		}
		fmt.Fprintln(stdout, v)
		return 0
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		fmt.Fprintln(stderr, "usage: releasenotes X.Y.Z [CHANGELOG.md] | releasenotes -check-tag vX.Y.Z")
		return 2
	}
	version, path := fs.Arg(0), release.ChangelogPath
	if fs.NArg() == 2 {
		path = fs.Arg(1)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(stderr, "releasenotes:", err)
		return 1
	}
	notes, ok := release.Notes(string(b), version)
	if !ok {
		fmt.Fprintf(stderr, "%s has no section for %s: add '## [%s] - YYYY-MM-DD' before tagging v%s\n",
			path, version, version, version)
		return 1
	}
	fmt.Fprintln(stdout, notes)
	return 0
}
