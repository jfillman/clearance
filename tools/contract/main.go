// Command contract writes the Go core's OpenAPI contract (contract/clearance-core.json) from internal/server's
// route table and Go types. Run it with `go generate ./internal/server`; internal/server's TestContractIsCurrent
// fails when the committed file differs from what this writes.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jfillman/clearance/internal/server"
)

func main() {
	out := flag.String("o", server.ContractPath, "where to write the contract")
	flag.Parse()
	doc, err := server.Contract()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, doc, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
