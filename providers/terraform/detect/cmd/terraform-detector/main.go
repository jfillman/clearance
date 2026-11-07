// Command terraform-detector runs the Terraform gate's two exception detectors once (G-TF-5): drift (a plan with a
// diff) and untraced applies (state versions no deploy.outcome explains). It is meant for a schedule (cron, a
// scheduled workflow). It holds no secret: Clearance sees it as a projected or OIDC token, AWS as credentials from
// the environment or a web-identity role, both read per run and never stored.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/providers/terraform/detect"
)

var version = "dev"

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "terraform-detector:", err)
		var u usageError
		if errors.As(err, &u) || errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

// usageError is a bad invocation: exit 2, nothing run.
type usageError string

func (u usageError) Error() string { return string(u) }

func run() error {
	fs := flag.NewFlagSet("terraform-detector", flag.ContinueOnError)
	var (
		cfgFile   = fs.String("config", env("DETECTOR_CONFIG", ""), "JSON file: {\"workspaces\":[{name,key,bucket,dir,env}]}")
		apiURL    = fs.String("api-url", env("CLEARANCE_API_URL", ""), "clearance-api's URL (outcomes and exceptions already filed)")
		coreURL   = fs.String("core-url", env("CLEARANCE_CORE_URL", ""), "the core's URL (records)")
		tokenFile = fs.String("token-file", env("CLEARANCE_TOKEN_FILE", ""), "a bearer token Clearance accepts, audience clearance")
		region    = fs.String("region", env("AWS_REGION", ""), "the state bucket's region")
		only      = fs.String("only", "all", "drift, untraced or all")
		window    = fs.Duration("window", 2*time.Hour, "how far back state versions are checked (longer than the schedule)")
		settle    = fs.Duration("settle", 10*time.Minute, "a state version younger than this waits for its outcome")
		slack     = fs.Duration("slack", 5*time.Minute, "tolerance around an apply window")
		tfBin     = fs.String("terraform", "terraform", "the terraform binary")
		showVer   = fs.Bool("version", false, "print the version")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *only != "all" && *only != "drift" && *only != "untraced" {
		return usageError("--only is all, drift or untraced, not " + *only)
	}
	if *showVer {
		fmt.Println(detect.ProviderName + "/" + version)
		return nil
	}
	for k, v := range map[string]string{"config": *cfgFile, "api-url": *apiURL, "core-url": *coreURL, "token-file": *tokenFile, "region": *region} {
		if v == "" {
			return fmt.Errorf("--%s is required", k)
		}
	}
	raw, err := os.ReadFile(*cfgFile)
	if err != nil {
		return err
	}
	var file struct {
		Workspaces []detect.Workspace `json:"workspaces"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("--config: %w", err)
	}
	if len(file.Workspaces) == 0 {
		return fmt.Errorf("--config lists no workspaces")
	}
	for _, w := range file.Workspaces {
		if w.Name == "" || w.Key == "" || w.Bucket == "" || w.Env == "" || w.Dir == "" {
			return fmt.Errorf("--config: every workspace needs name, key, bucket, dir and env")
		}
	}
	tok := client.FileToken(*tokenFile)
	cc, err := client.New(client.Options{BaseURL: *coreURL, Token: tok, Provider: detect.ProviderName, Timeout: 10 * time.Second,
		UserAgent: detect.ProviderName + "/" + version})
	if err != nil {
		return err
	}
	aws := &detect.AWS{Region: *region, Creds: detect.EnvCreds}
	d := &detect.Detector{
		Cfg:   detect.Config{Workspaces: file.Workspaces, Window: *window, Settle: *settle, Slack: *slack, Version: version},
		Plan:  detect.Terraform{Bin: *tfBin},
		State: aws, Trail: aws,
		Ev:   &detect.HTTPEvidence{Base: *apiURL, Token: tok},
		Core: cc, Log: slog.New(slog.NewJSONHandler(os.Stderr, nil))}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var errs []string
	if *only == "all" || *only == "drift" {
		if err := d.Drift(ctx); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if *only == "all" || *only == "untraced" {
		if err := d.Untraced(ctx); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
