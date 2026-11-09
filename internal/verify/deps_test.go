package verify_test

import (
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The verifier stays installable alone: its dependency closure holds no database driver and none of the core's
// packages (the store, the gate, the ledger, the packet builder, the server).
func TestVerifierLinksNothingOfTheCoreOrADatabase(t *testing.T) {
	for _, target := range []string{"github.com/jfillman/clearance/internal/verify", "github.com/jfillman/clearance/cmd/clearance-verify"} {
		out, err := exec.Command("go", "list", "-deps", target).CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		deps := strings.Fields(string(out))
		if len(deps) < 50 {
			t.Fatalf("go list gave %d packages: not a real listing", len(deps))
		}
		for _, d := range deps {
			for _, banned := range []string{"jackc/pgx", "database/sql", "internal/store", "internal/core", "internal/gate", "internal/ledger", "internal/packet",
				"internal/server", "internal/api", "internal/attestor", "cel-go", "internal/authn"} {
				if strings.Contains(d, banned) {
					t.Errorf("%s depends on %s", target, d)
				}
			}
		}
		own := 0
		for _, d := range deps {
			if strings.HasPrefix(d, "github.com/jfillman/clearance/") {
				own++
			}
		}
		if own == 0 {
			t.Fatal("no clearance packages in the listing: the check is vacuous")
		}
	}
}

// The package's own sources import neither net nor net/http, nor os/exec.
func TestVerifierSourcesImportNoNetwork(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) < 5 {
		t.Fatalf("%v %v", files, err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, im := range af.Imports {
			switch p := strings.Trim(im.Path.Value, `"`); {
			case p == "net", strings.HasPrefix(p, "net/"), p == "os/exec":
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
	if checked < 5 {
		t.Fatal("too few sources checked")
	}
}
