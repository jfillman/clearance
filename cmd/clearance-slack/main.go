// Command clearance-slack is Clearance's Slack surface (docs/slack.md): it tells people about changes waiting on them,
// exceptions, break-glass, coverage and stuck attestations, and lets a person whose Slack account is linked to
// their sign-in clear (tier 2 by default) and deny from Slack. It is a delegate and a notifier of the core and
// clearance-api, holds no signing key and no evidence, and reads its secrets from files.
//
// Configuration is the environment (docs/slack.md lists every variable); secrets are *_FILE mounts.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jfillman/clearance/internal/slack"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx))
}

func run(ctx context.Context) int {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("clearance-slack", version)
		return 0
	}
	cfg, err := slack.ConfigFromEnv(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "clearance-slack:", err)
		return 2
	}
	pg, err := slack.OpenPG(ctx, cfg.DSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "clearance-slack: the database:", err)
		return 1
	}
	defer pg.Close()
	svc, err := slack.Build(cfg, pg, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "clearance-slack:", err)
		return 2
	}
	log.Info("clearance-slack starting", "version", version, "transport", cfg.Transport)
	if err := svc.Run(ctx); err != nil {
		log.Error("clearance-slack stopped", "error", err.Error())
		return 1
	}
	return 0
}
