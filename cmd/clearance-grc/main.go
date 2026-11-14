// Command clearance-grc pushes a summary of each production change, and a periodic coverage report, to a GRC hub
// (Vanta first) as evidence items that link back to Clearance (docs/grc-push.md). It is off unless configured, a
// reader of clearance-api and a registered provider of the core for its own grc.push and grc.report records only,
// and never on the decision path. Configuration is the environment; secrets are *_FILE mounts.
package main

import (
	"context"
	"errors"
	"fmt"
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
	os.Exit(run(ctx))
}

func run(ctx context.Context) int {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("clearance-grc", version)
		return 0
	}
	cfg, err := grc.ConfigFromEnv(os.Getenv)
	if errors.Is(err, grc.ErrOff) {
		fmt.Fprintln(os.Stderr, "clearance-grc:", err, "(nothing is sent)")
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "clearance-grc:", err)
		return 2
	}
	target, err := grc.NewVanta(cfg.VantaBaseURL, cfg.VantaClientID, cfg.VantaSecretFile, cfg.VantaSecret, cfg.VantaEvidenceResource, cfg.VantaReportResource)
	if err != nil {
		fmt.Fprintln(os.Stderr, "clearance-grc:", err)
		return 2
	}
	svc := grc.NewService(cfg, target, log)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("health listener stopped", "error", err.Error())
		}
	}()
	log.Info("clearance-grc starting", "version", version, "target", target.Name(), "envs", cfg.Envs, "interval", cfg.Interval.String())
	svc.Run(ctx)
	sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sd)
	return 0
}
