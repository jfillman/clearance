// Command clearance-grc pushes a summary of each production change, and a periodic coverage report, to a GRC hub
// (Vanta first) as evidence items that link back to Clearance (docs/grc-push.md). It is off unless configured, a
// reader of clearance-api and a registered provider of the core for its own grc.push and grc.report records only,
// and never on the decision path. Configuration is the environment; secrets are *_FILE mounts.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jfillman/clearance/internal/grc"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run is main with its inputs: 0 is a clean stop (or off), 2 a configuration it refuses.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer, opts ...grc.ConfigOption) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	if len(args) > 0 && (args[0] == "version" || args[0] == "--version") {
		fmt.Fprintln(stdout, "clearance-grc", version)
		return 0
	}
	cfg, err := grc.ConfigFromEnv(getenv, opts...)
	if errors.Is(err, grc.ErrOff) {
		fmt.Fprintln(stderr, "clearance-grc:", err, "(nothing is sent)")
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "clearance-grc:", err)
		return 2
	}
	vopts := []grc.VantaOption{grc.WithHTTPClient(grc.NewHTTPClient(cfg.UseProxy))}
	if cfg.AllowLoopback() {
		vopts = append(vopts, grc.InsecureLoopbackForTest())
	}
	target, err := grc.NewVanta(cfg.VantaBaseURL, cfg.VantaClientID, cfg.VantaSecretFile, cfg.VantaEvidenceResource, cfg.VantaReportResource, vopts...)
	if err != nil {
		fmt.Fprintln(stderr, "clearance-grc:", err)
		return 2
	}
	svc := grc.NewService(cfg, target, log)
	srv := &http.Server{Addr: cfg.Listen, Handler: svc.Mux(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("health listener stopped", "error", err.Error())
		}
	}()
	log.Info("clearance-grc starting", "version", version, "target", target.Name(), "envs", cfg.Envs, "interval", cfg.Interval.String(),
		"allow_shrink", cfg.AllowShrink)
	svc.Run(ctx)
	sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sd)
	return 0
}
