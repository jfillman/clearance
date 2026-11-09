// Command clearance-witness is the evidence ledger's witness (C-3): a C2SP tlog-witness that cosigns a log's
// checkpoint only when it extends the last one it cosigned, so a truncated or rewritten ledger cannot get a
// countersignature however it is signed. It is a separate binary and image from Clearance on purpose: the witness
// is only worth anything run by someone the log's operator does not control.
//
// Configuration (flags, or the environment variable in brackets):
//
//	--listen        address to serve on (CLEARANCE_WITNESS_LISTEN, default :8080)
//	--key-file      the witness's signing key, a signed-note Ed25519 secret key (CLEARANCE_WITNESS_KEY_FILE; required)
//	--logs-file     the logs it cosigns for: one verifier key (vkey) per line (CLEARANCE_WITNESS_LOGS_FILE; required)
//	--state-file    where it keeps the latest checkpoint it cosigned per log, on a persistent volume
//	                (CLEARANCE_WITNESS_STATE_FILE; required: a witness that forgets can be rolled back)
//
// The key is read from the file and never printed. `clearance ledger keygen --witness` makes one.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jfillman/clearance/internal/ledger"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stderr))
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("clearance-witness", flag.ContinueOnError)
	fs.SetOutput(stderr)
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	listen := fs.String("listen", env("CLEARANCE_WITNESS_LISTEN", ":8080"), "listen address")
	keyFile := fs.String("key-file", env("CLEARANCE_WITNESS_KEY_FILE", ""), "the witness's signing key file")
	logsFile := fs.String("logs-file", env("CLEARANCE_WITNESS_LOGS_FILE", ""), "the verifier keys of the logs it cosigns for")
	stateFile := fs.String("state-file", env("CLEARANCE_WITNESS_STATE_FILE", ""), "the file its state is kept in")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	if *keyFile == "" || *logsFile == "" || *stateFile == "" {
		fmt.Fprintln(stderr, "clearance-witness: --key-file, --logs-file and --state-file are required")
		return 2
	}
	signer, err := ledger.LoadWitnessKey(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "clearance-witness:", err)
		return 2
	}
	logs, err := ledger.LoadLogVerifiers(*logsFile)
	if err != nil {
		fmt.Fprintln(stderr, "clearance-witness:", err)
		return 2
	}
	w, err := ledger.NewWitness(signer, logs, *stateFile)
	if err != nil {
		fmt.Fprintln(stderr, "clearance-witness:", err)
		return 1
	}
	srv := &http.Server{Addr: *listen, Handler: w, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	names := make([]string, 0, len(logs))
	for _, l := range logs {
		names = append(names, l.Name())
	}
	log.Info("clearance-witness serving", "addr", *listen, "witness", w.Name(), "logs", names)
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "clearance-witness:", err)
			return 1
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	return 0
}
