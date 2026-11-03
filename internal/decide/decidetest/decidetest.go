// Package decidetest loads the policy bundle fixture the golden corpus was recorded under (testdata/bundles), for
// tests only. The fixture is a deployment's bundle as data; nothing in the core reads it.
package decidetest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jfillman/clearance/internal/decide"
)

// Root is the repository root.
func Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

// FixtureDir is the corpus deployment's bundle directory: bundle.json and the contract its source reads.
func FixtureDir() string { return filepath.Join(Root(), "testdata", "bundles", "hangar") }

// FixtureBundle is the fixture's bundle file, or the one CLEARANCE_GOLDEN_BUNDLE names (a deployment proving its
// own bundle decides as the corpus did).
func FixtureBundle() string {
	if p := os.Getenv("CLEARANCE_GOLDEN_BUNDLE"); p != "" {
		return p
	}
	return filepath.Join(FixtureDir(), "bundle.json")
}

// FixtureSource is the document every source of the fixture reads, or the one CLEARANCE_GOLDEN_SOURCE names.
func FixtureSource() string {
	if p := os.Getenv("CLEARANCE_GOLDEN_SOURCE"); p != "" {
		return p
	}
	return filepath.Join(FixtureDir(), "glidepath-contract.json")
}

// FileFetch serves every source from one file.
func FileFetch(path string) decide.Fetch {
	return func(_ string, _ decide.SourceSpec) ([]byte, string, error) {
		b, err := os.ReadFile(path)
		return b, path, err
	}
}

// Bundle loads the fixture bundle.
func Bundle(t testing.TB) *decide.Bundle {
	t.Helper()
	data, err := os.ReadFile(FixtureBundle())
	if err != nil {
		t.Fatal(err)
	}
	b, err := decide.LoadBundle(data, FileFetch(FixtureSource()))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Environments is the corpus deployment's environment naming (its CLEARANCE_ENV_* values).
func Environments() *decide.Environments {
	return &decide.Environments{LowerNames: []string{"dev", "development", "sandbox", "scratch"},
		LowerPrefixes: []string{"pr-", "agent-"}, LowerProjectSuffixes: []string{"-lower"},
		UpperRepoPrefixes: []string{"gitops-"}}
}

// Options is the corpus deployment: the fixture bundle and its environment naming.
func Options(t testing.TB) decide.Options {
	return decide.Options{Bundles: []*decide.Bundle{Bundle(t)}, Environments: Environments()}
}

// Engine is an engine for the corpus deployment.
func Engine(t testing.TB) *decide.Engine {
	t.Helper()
	e, err := decide.New(Options(t))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
