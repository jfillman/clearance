// Command clearance is Clearance's one binary: the core service, the read API, the CLI (chain verify,
// register, conformance) and the test core. Subcommands register themselves (internal/cli).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/jfillman/clearance/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
