// Command releasenotes prints one version's section of CHANGELOG.md, the GitHub Release's notes
// (.github/workflows/release.yaml), or checks that a tag names the repository's VERSION.
//
//	go run ./tools/releasenotes 0.29.0 [CHANGELOG.md]   # the notes; exit 1, naming the version, when there are none
//	go run ./tools/releasenotes -check-tag v0.29.0      # exit 1 unless the tag is v<VERSION>
//
// A tag cut without its notes fails the release instead of publishing an empty one.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jfillman/clearance/internal/release"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

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
