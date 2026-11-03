// Command contract writes the Go contracts from their route tables and Go types: the core's OpenAPI document
// (contract/clearance-core.json, internal/server) or, with -api, clearance-api's (contract/clearance-api.json,
// internal/api). Run it with `go generate ./internal/server ./internal/api`; each package's contract test fails when
// the committed file differs from what this writes.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jfillman/clearance/internal/api"
	"github.com/jfillman/clearance/internal/server"
)

func main() {
	apiDoc := flag.Bool("api", false, "write clearance-api's contract instead of the core's")
	out := flag.String("o", "", "where to write the contract (default the committed path)")
	flag.Parse()
	gen, path := server.Contract, server.ContractPath
	if *apiDoc {
		gen, path = api.ContractJSON, api.ContractPath
	}
	if *out != "" {
		path = *out
	}
	doc, err := gen()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, doc, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
