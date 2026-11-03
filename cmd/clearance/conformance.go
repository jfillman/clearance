package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/conformance"
)

func init() {
	cli.Register(cli.Command{Name: "conformance",
		Summary: "prove a provider follows the provider protocol (docs/provider-protocol.md)", Run: conformanceCmd})
}

// conformanceCmd is `clearance conformance --provider <url> --role runtime|deployment [--report file]`: an in-memory
// core and a fake target, the provider driven through its test-only control interface. One PASS or FAIL line per
// assertion; exit 0 when every assertion passes, 1 when one fails, 2 on a usage or harness error.
func conformanceCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("conformance", flag.ContinueOnError)
	fs.SetOutput(stderr)
	provider := fs.String("provider", "", "the provider's conformance control address (http://host:port)")
	role := fs.String("role", "", "the role to test: runtime or deployment")
	report := fs.String("report", "", "write the JSON report to this file")
	timeout := fs.Duration("timeout", conformance.DefaultTimeout, "how long to wait for the provider at each step")
	hold := fs.Duration("hold-window", conformance.DefaultHoldWindow,
		"how long a held change must stay unapplied (and the wait for a late or duplicate apply)")
	poll := fs.Duration("poll-interval", conformance.DefaultPollInterval, "the poll hint handed to a deployment provider")
	listen := fs.String("listen-host", "127.0.0.1", "the address the in-memory core and the fake target listen on")
	advertise := fs.String("advertise-host", "", "the host the provider reaches them at (default: --listen-host)")
	verbose := fs.Bool("verbose", false, "log the in-memory core to stderr")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: clearance conformance --provider <url> --role runtime|deployment [--report file]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *provider == "" || *role == "" {
		if err == nil {
			fs.Usage()
		}
		return 2
	}
	opt := conformance.Options{Provider: *provider, Role: *role, Timeout: *timeout, HoldWindow: *hold,
		PollInterval: *poll, ListenHost: *listen, AdvertiseHost: *advertise}
	if *verbose {
		opt.CoreLog = slog.New(slog.NewJSONHandler(stderr, nil))
	}
	rep, err := conformance.Run(ctx, opt)
	if err != nil {
		fmt.Fprintln(stderr, "conformance:", err)
		return 2
	}
	rep.Print(stdout)
	if *report != "" {
		raw, err := json.MarshalIndent(rep, "", "  ")
		if err == nil {
			err = os.WriteFile(*report, append(raw, '\n'), 0o644)
		}
		if err != nil {
			fmt.Fprintln(stderr, "conformance: writing the report:", err)
			return 2
		}
	}
	if !rep.Pass {
		return 1
	}
	return 0
}
