package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/ledger"
)

func init() {
	cli.Register(cli.Command{Name: "ledger keygen", Summary: "make a signing key for the evidence ledger's log or a witness (writes the secret to a file, prints the public key)", Run: ledgerKeygen})
}

// ledgerKeygen writes a new secret key to --out (mode 0600, refusing to replace a file) and prints only the public
// half. The secret is never printed: it goes from the generator to the file, and from the file to a Secret.
func ledgerKeygen(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ledger keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "the key's name: for the log, its origin (it stays the same across rotations); for a witness, its name")
	out := fs.String("out", "", "the file to write the secret key to (new, mode 0600)")
	witness := fs.Bool("witness", false, "a witness key: print the vkey in the form a witness policy lists it (tlog-cosignature)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: clearance ledger keygen --name <name> --out <file> [--witness]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *name == "" || *out == "" || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	skey, vkey, cosig, err := ledger.GenerateKey(*name)
	if err != nil {
		fmt.Fprintln(stderr, "ledger keygen:", err)
		return 1
	}
	if err := ledger.WriteKeyFile(*out, skey); err != nil {
		fmt.Fprintln(stderr, "ledger keygen:", err)
		return 1
	}
	if *witness {
		fmt.Fprintln(stdout, cosig)
	} else {
		fmt.Fprintln(stdout, vkey)
	}
	fmt.Fprintf(stderr, "secret key written to %s; the public key above is what the other side needs\n", *out)
	return 0
}
