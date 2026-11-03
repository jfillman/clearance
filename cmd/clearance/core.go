package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/core"
)

func init() {
	cli.Register(cli.Command{Name: "core", Summary: "serve the Clearance core (decisions, records, the gate) over HTTP", Run: coreCmd})
}

// coreCmd is `clearance core [--memory] [--listen addr] [--insecure-dev-auth] [--max-clock-skew d]`:
// internal/core.Run on the environment (internal/core's package doc lists it). main's signal context makes SIGTERM
// a graceful shutdown.
func coreCmd(ctx context.Context, args []string, _, stderr io.Writer) int {
	fs := flag.NewFlagSet("core", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mem := fs.Bool("memory", false, "run on an in-memory store (tests and local runs; nothing is kept)")
	listen := fs.String("listen", "", "listen address (default $CLEARANCE_LISTEN or :8080)")
	dev := fs.Bool("insecure-dev-auth", false, "with --memory only: accept `Bearer <principal>` as that principal, "+
		"and serve the chain at GET /v1/dev/records")
	skew := fs.String("max-clock-skew", "", "how far an evaluation's context.now may be from the core's clock "+
		"(default $CLEARANCE_MAX_CLOCK_SKEW or 5m); 0 is off, with --memory only")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	if *dev && !*mem {
		fmt.Fprintln(stderr, "core: --insecure-dev-auth needs --memory")
		return 2
	}
	getenv := os.Getenv
	if *dev {
		// The real authenticator is not built: its configuration errors do not apply to a dev run.
		getenv = func(k string) string {
			for _, a := range devSkippedEnv {
				if k == a {
					return ""
				}
			}
			return os.Getenv(k)
		}
	}
	cfg, err := core.FromEnv(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "core:", err)
		return 2
	}
	cfg.Memory = *mem
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *skew != "" {
		if cfg.MaxClockSkew, err = core.ParseMaxClockSkew(*skew); err != nil {
			fmt.Fprintln(stderr, "core: --max-clock-skew:", err)
			return 2
		}
	}
	if err := cfg.CheckMaxClockSkew(); err != nil {
		fmt.Fprintln(stderr, "core:", err)
		return 2
	}
	if *dev {
		log.Warn("INSECURE: --insecure-dev-auth: every bearer token is accepted as the principal it names")
		cfg.Auth = core.DevAuthenticator()
		cfg.DevRecords = true // GET /v1/dev/records: other packages' tests read what the core recorded
	}
	cfg.Version = buildVersion()
	if err := core.Run(ctx, cfg, log, nil); err != nil {
		fmt.Fprintln(stderr, "core:", err)
		return 1
	}
	return 0
}

// devSkippedEnv are the authenticator's variables, ignored under --insecure-dev-auth.
var devSkippedEnv = []string{"CLEARANCE_OIDC_ISSUER", "CLEARANCE_OIDC_AUDIENCE", "CLEARANCE_OIDC_ALLOWED_USERS",
	"TOWER_ISSUER", "TOWER_CLUSTER", "TOWER_SERVICE_ACCOUNTS", "CLEARANCE_GITHUB_OIDC_AUDIENCE"}

func buildVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return ""
}
