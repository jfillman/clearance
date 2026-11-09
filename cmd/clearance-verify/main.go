// Command clearance-verify is the offline evidence-packet verifier on its own: `go install
// github.com/jfillman/clearance/cmd/clearance-verify@latest`. It is `clearance verify` without the rest of Clearance,
// and links nothing of the core or its database.
package main

import (
	"os"

	"github.com/jfillman/clearance/internal/verify"
)

func main() { os.Exit(verify.Main(os.Args[1:], os.Stdout, os.Stderr)) }
