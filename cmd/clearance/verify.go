package main

import (
	"context"
	"io"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/verify"
)

func init() {
	cli.Register(cli.Command{Name: "verify", Summary: "check an evidence packet offline: records, proofs, checkpoint, witnesses, attestations (also installable alone as clearance-verify)",
		Run: func(_ context.Context, args []string, stdout, stderr io.Writer) int {
			return verify.Main(args, stdout, stderr)
		}})
}
