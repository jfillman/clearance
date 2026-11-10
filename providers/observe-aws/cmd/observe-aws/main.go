// Command observe-aws is the AWS collector (O-4): it drains the EventBridge queue, reads the S3 trail with digest-chain
// validation, reconciles AWS Config items with the events that caused them, runs G-TF-5's two detectors as stages,
// and reports each account's health. It holds no secret: Clearance sees it as a projected service account token, AWS
// as web-identity roles assumed per run (a read-only role in the observed account, and one in the logging account).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/internal/vocab"
	"github.com/jfillman/clearance/providers/observe-aws/collector"
	"github.com/jfillman/clearance/providers/observe-aws/detect"
	"github.com/jfillman/clearance/providers/observe-aws/feeds"
	"github.com/jfillman/clearance/providers/observe-aws/scope"
)

var version = "dev"

// fileConfig is --config.
type fileConfig struct {
	Account      string             `json:"account"`       // the observed account
	Region       string             `json:"region"`        // the queue's region
	QueueURL     string             `json:"queueURL"`      // the SQS queue
	TrailBucket  string             `json:"trailBucket"`   // the organization trail's bucket (logging account); empty: the S3 trail is not read
	TrailPrefix  string             `json:"trailPrefix"`   // AWSLogs/<org id>/<account>/
	TrailRegion  string             `json:"trailRegion"`   // the bucket's region
	TrailName    string             `json:"trailName"`     // the trail expected (health)
	DataTrail    string             `json:"dataTrail"`     // the account's own trail that records the data buckets' events; empty: any trail in the account (or the main trail) that does
	Regions      []string           `json:"regions"`       // regions whose digests are read
	DataBuckets  []string           `json:"dataBuckets"`   // state, artifact and secrets buckets whose data events are assessed
	Rules        []string           `json:"rules"`         // EventBridge rules that must be enabled
	ScopeEnv     string             `json:"environment"`   // the environment the account's cleared applies are recorded under
	SecondWave   bool               `json:"secondWave"`    // also evaluate VPC routing, Secrets Manager, Lambda, EKS access, RDS
	Settle       string             `json:"settle"`        // how long an event waits for its Config item and the apply outcome (default 10m)
	Workspaces   []detect.Workspace `json:"workspaces"`    // the Terraform workspaces the detector stages watch (may be empty)
	UntracedEach string             `json:"untracedEvery"` // default 30m
	DriftEach    string             `json:"driftEvery"`    // default 24h
	TerraformBin string             `json:"terraform"`
}

func dur(s string, d time.Duration) time.Duration {
	if t, err := time.ParseDuration(s); err == nil && t > 0 {
		return t
	}
	return d
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "observe-aws:", err)
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func run() error {
	fs := flag.NewFlagSet("observe-aws", flag.ContinueOnError)
	var (
		cfgFile   = fs.String("config", env("OBSERVE_CONFIG", ""), "JSON configuration")
		apiURL    = fs.String("api-url", env("CLEARANCE_API_URL", ""), "clearance-api (outcomes for the lookups and the detectors)")
		coreURL   = fs.String("core-url", env("CLEARANCE_CORE_URL", ""), "the core (records)")
		tokenFile = fs.String("token-file", env("CLEARANCE_TOKEN_FILE", ""), "a bearer token Clearance accepts")
		rulesFile = fs.String("rules", env("OBSERVE_RULES", ""), "a rule set bundle (clearance.observe-rules/v1); empty: the built-in default")
		stage     = fs.String("stage", "", "run one detector stage once and exit: drift (needs the terraform binary and the module checkout) or untraced")
		showVer   = fs.Bool("version", false, "print the version")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *stage != "" && *stage != "drift" && *stage != "untraced" {
		return errors.New("--stage is drift or untraced")
	}
	if *showVer {
		fmt.Println(collector.ProviderName + "/" + version)
		return nil
	}
	for _, f := range [][2]string{{"config", *cfgFile}, {"api-url", *apiURL}, {"core-url", *coreURL}, {"token-file", *tokenFile}} {
		if f[1] == "" {
			return fmt.Errorf("--%s is required", f[0])
		}
	}
	raw, err := os.ReadFile(*cfgFile)
	if err != nil {
		return err
	}
	var fc fileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		return fmt.Errorf("--config: %w", err)
	}
	if fc.Account == "" || fc.Region == "" || fc.QueueURL == "" {
		return errors.New("--config needs account, region and queueURL")
	}
	var rs *pipeline.RuleSet
	if *rulesFile != "" {
		b, err := os.ReadFile(*rulesFile)
		if err != nil {
			return err
		}
		rs, err = pipeline.Load(b)
		if err != nil {
			return fmt.Errorf("--rules: %w", err)
		}
	} else if rs, err = pipeline.Default(); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	tok := client.FileToken(*tokenFile)
	cc, err := client.New(client.Options{BaseURL: *coreURL, Token: tok, Provider: collector.ProviderName, Timeout: 10 * time.Second,
		UserAgent: collector.ProviderName + "/" + version})
	if err != nil {
		return err
	}
	ev := &detect.HTTPEvidence{Base: *apiURL, Token: tok}
	// Observed account: the queue, Config, EventBridge, the state bucket. Logging account: the trail bucket and
	// the CloudTrail describe calls. Both roles are assumed from the pod's projected token.
	labAWS := &detect.AWS{Region: fc.Region, Creds: detect.EnvCreds}
	lab := &feeds.API{AWS: labAWS}
	tokenPath := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	var trail *collector.TrailReader
	ctl := collector.Control{Recorders: lab.Recorders, Rules: lab.Rules}
	if len(fc.DataBuckets) > 0 {
		// The account's own trails (the data events of the state bucket), read with the observed-account role.
		ctl.DataTrails = func(ctx context.Context) ([]collector.TrailState, error) { return lab.TrailsIn(ctx, fc.Account) }
	}
	if fc.TrailBucket != "" {
		role := os.Getenv("OBSERVE_TRAIL_ROLE_ARN")
		if role == "" || tokenPath == "" {
			return errors.New("the S3 trail is configured: set OBSERVE_TRAIL_ROLE_ARN (the logging account's read role) and AWS_WEB_IDENTITY_TOKEN_FILE")
		}
		logAWS := &detect.AWS{Region: orS(fc.TrailRegion, fc.Region), Creds: detect.WebIdentityCreds(role, tokenPath)}
		logging := &feeds.API{AWS: logAWS}
		ctl.Trails = logging.Trails
		trail = &collector.TrailReader{Objects: feeds.S3{API: logging}, Keys: &feeds.PublicKeys{API: logging}, Bucket: fc.TrailBucket,
			Prefix: fc.TrailPrefix, Regions: fc.Regions}
	}
	lk := &collector.EvidenceLookups{Src: ev, ScopeEnv: map[string]string{fc.Account: fc.ScopeEnv}}
	rec := &collector.Reconciler{Settle: dur(fc.Settle, 10*time.Minute)}
	col := &collector.Collector{Cfg: collector.Config{Accounts: []string{fc.Account}, Version: version}, Pipe: pipeline.New(rs, lk, vocab.Vocabulary{}),
		Filter: &scope.Filter{DataBuckets: fc.DataBuckets, MaxWave: map[bool]int{false: 1, true: 2}[fc.SecondWave]}, Rec: rec, Core: cc, Lookups: lk, Log: log}
	hl := &collector.Health{Cfg: collector.HealthConfig{Account: fc.Account, Trail: fc.TrailName, DataTrail: fc.DataTrail, DataBuckets: fc.DataBuckets, Rules: fc.Rules,
		MustCoverRegions: fc.Regions}, Ctl: ctl, Trail: trail, Col: col, Core: cc}
	hl.Start()
	drain := &collector.Drainer{Q: &feeds.SQS{API: lab, QueueURL: fc.QueueURL}, Col: col, Health: hl, Log: log}
	tasks := []*collector.Task{
		{Name: "drain", Every: 5 * time.Second, Fn: func(ctx context.Context) error { _, err := drain.Drain(ctx); return err }},
		{Name: "step", Every: 15 * time.Second, Fn: col.Step},
		{Name: "health", Every: 5 * time.Minute, Fn: func(ctx context.Context) error { st, err := hl.Post(ctx); log.Info("health", "state", st); return err }},
	}
	if trail != nil {
		tasks = append(tasks, &collector.Task{Name: "trail", Every: 5 * time.Minute, Fn: func(ctx context.Context) error {
			for {
				items, more, err := trail.Read(ctx)
				for _, it := range items {
					if e := col.Ingest(it); e != nil {
						log.Warn("trail record skipped", "err", e.Error())
					}
				}
				if err != nil || !more {
					return err
				}
			}
		}})
	}
	if len(fc.Workspaces) > 0 || *stage != "" {
		aws := &detect.AWS{Region: fc.Region, Creds: detect.EnvCreds}
		d := &detect.Detector{Cfg: detect.Config{Workspaces: fc.Workspaces, Version: version}, Plan: detect.Terraform{Bin: orS(fc.TerraformBin, "terraform")},
			State: aws, Trail: aws, Ev: ev, Core: cc, Log: log}
		switch *stage {
		case "drift":
			return d.Drift(context.Background())
		case "untraced":
			return d.Untraced(context.Background())
		}
		tasks = append(tasks, &collector.Task{Name: "untraced-apply", Every: dur(fc.UntracedEach, 30*time.Minute), Fn: d.Untraced})
		// The scheduled plan needs the terraform binary and a checkout of each module; the collector image has neither,
		// so the drift stage runs where they are (`observe-aws --stage drift` in the repository's scheduled workflow).
		if _, err := exec.LookPath(orS(fc.TerraformBin, "terraform")); err == nil {
			tasks = append(tasks, &collector.Task{Name: "drift", Every: dur(fc.DriftEach, 24*time.Hour), Fn: d.Drift})
		} else {
			log.Info("the drift stage is not scheduled here: no terraform binary; run it with --stage drift where one is")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	(&collector.Runner{Tasks: tasks, Log: log}).Run(ctx, time.Second)
	return nil
}

func orS(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
