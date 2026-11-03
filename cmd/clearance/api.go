package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/jfillman/clearance/internal/api"
	"github.com/jfillman/clearance/internal/cli"
)

func init() {
	cli.Register(cli.Command{Name: "api", Summary: "serve clearance-api, the read-only API over the evidence, the gate and the policy", Run: apiCmd})
}

// apiCmd is `clearance api [--listen addr]`: internal/api.Run on the environment (internal/api Config lists it).
// main's signal context makes SIGTERM a graceful shutdown.
func apiCmd(ctx context.Context, args []string, _, stderr io.Writer) int {
	fs := flag.NewFlagSet("api", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "", "listen address (default $CLEARANCE_LISTEN, or :$PORT, or :8080)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2
	}
	cfg, err := api.FromEnv(os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "api:", err)
		return 2
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	if err := api.Run(ctx, cfg, log, nil); err != nil {
		fmt.Fprintln(stderr, "api:", err)
		return 1
	}
	return 0
}
