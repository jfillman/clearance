package main

// `clearance federate traefik-hub`: the Traefik Hub adapter (C-9, internal/federate/traefikhub). It reads a Hub log
// and an access log, joins decisions to requests on trace_id, and posts each decision to the core as a
// federated.decision record (POST /v1/records, provider traefik-hub). Without --core it prints the records as JSON
// lines and posts nothing. Status: Unverified (no running Hub's records yet). Exit codes: 0 done, 1 a failure, 2 a
// usage error.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/federate/traefikhub"
)

const (
	federateOK     = 0
	federateFailed = 1
)

func init() {
	cli.Register(cli.Command{Name: "federate traefik-hub",
		Summary: "ingest Traefik Hub decision records into the ledger (Unverified)", Run: federateTraefikHub})
}

func federateTraefikHub(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("federate traefik-hub", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hubLog := fs.String("hub-log", "", "the Traefik Hub log (log.filePath, log.format json): its decision records")
	accessLog := fs.String("access-log", "", "the access log (accessLog.filePath, accessLog.format json); optional")
	taskHeader := fs.String("task-header", traefikhub.DefaultTaskHeader, "the kept request header carrying the task_id")
	agentHeader := fs.String("agent-header", traefikhub.DefaultAgentHeader, "the kept request header naming the agent (- for none)")
	principalHeader := fs.String("principal-header", "", "a kept request header naming the caller when ClientUsername is unset")
	coreURL := fs.String("core", "", "the core's URL; empty prints the records and posts nothing")
	tokenFile := fs.String("token-file", "", "the bearer token file, read per request (a projected service-account token)")
	provider := fs.String("provider", traefikhub.ProviderName, "the registered provider name")
	statePath := fs.String("state", "", "a file of the keys already posted, so a re-run posts nothing twice")
	timeout := fs.Duration("timeout", 5*time.Second, "each request's deadline")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: clearance federate traefik-hub --hub-log <file> [--access-log <file>] "+
			"[--core <url> --token-file <file> [--state <file>]]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *hubLog == "" || fs.NArg() != 0 || (*coreURL != "" && *tokenFile == "") || (*coreURL == "" && *statePath != "") {
		fs.Usage()
		return exitUsage
	}
	hub, err := os.Open(*hubLog)
	if err != nil {
		fmt.Fprintln(stderr, "federate:", err)
		return federateFailed
	}
	defer hub.Close()
	var access io.Reader
	if *accessLog != "" {
		f, err := os.Open(*accessLog)
		if err != nil {
			fmt.Fprintln(stderr, "federate:", err)
			return federateFailed
		}
		defer f.Close()
		access = f
	}
	recs, st, err := traefikhub.Ingest(hub, access, traefikhub.Options{
		Correlator: traefikhub.HeaderCorrelator{Header: *taskHeader}, AgentHeader: *agentHeader,
		PrincipalHeader: *principalHeader})
	if err != nil {
		fmt.Fprintln(stderr, "federate:", err)
		return federateFailed
	}
	for i := range recs {
		recs[i].Provider = *provider
	}
	report := map[string]any{"read": st}
	defer func() {
		b, _ := json.Marshal(report)
		fmt.Fprintln(stderr, string(b))
	}()
	if *coreURL == "" {
		enc := json.NewEncoder(stdout)
		for i := range recs {
			if err := enc.Encode(&recs[i]); err != nil {
				fmt.Fprintln(stderr, "federate:", err)
				return federateFailed
			}
		}
		return federateOK
	}
	c, err := client.New(client.Options{BaseURL: *coreURL, Token: client.FileToken(*tokenFile), Provider: *provider,
		Timeout: *timeout, UserAgent: "clearance-federate-traefik-hub"})
	if err != nil {
		fmt.Fprintln(stderr, "federate:", err)
		return exitUsage
	}
	var state *traefikhub.State
	if *statePath != "" {
		s, closer, err := traefikhub.OpenState(*statePath)
		if err != nil {
			fmt.Fprintln(stderr, "federate:", err)
			return federateFailed
		}
		defer closer.Close()
		state = s
	}
	ps, err := traefikhub.PostCounted(ctx, c, recs, state)
	report["posted"] = ps
	if err != nil {
		fmt.Fprintln(stderr, "federate:", err)
		return federateFailed
	}
	return federateOK
}
