package main

// `clearance hold`, `clearance release` and `clearance report`: the plain-CI adapter for a saved Terraform plan
// (G-TF-3, docs/terraform-gate.md). hold registers the plan as a terraform-plan change and waits for it; release
// re-hashes the plan and proves it is the cleared one before the workflow applies; report posts the apply's outcome.
// The CLI never applies, and the plan file is never uploaded: only digests, addresses and counts leave the runner.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/tfplan"
)

func init() {
	cli.Register(cli.Command{Name: "hold", Summary: "register a saved Terraform plan with the gate and wait for it (CI step)",
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
			return holdMain(ctx, args, environ(), actionsToken, stdout, stderr)
		}})
	cli.Register(cli.Command{Name: "release", Summary: "prove a saved plan is the cleared one, before the apply (CI step)",
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
			return releaseMain(ctx, args, environ(), actionsToken, stdout, stderr)
		}})
	cli.Register(cli.Command{Name: "report", Summary: "report a Terraform apply's outcome to the gate (CI step)",
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
			return reportMain(ctx, args, environ(), actionsToken, stdout, stderr)
		}})
}

// tfCommon are the flags every one of the three takes: where Clearance is and who the caller is.
type tfCommon struct{ url, audience, tokenFile string }

func (c *tfCommon) bind(fs *flag.FlagSet, env map[string]string) {
	fs.StringVar(&c.url, "url", env["CLEARANCE_URL"], "Clearance's gateway (CLEARANCE_URL)")
	fs.StringVar(&c.audience, "audience", "clearance", "the OIDC token's audience")
	fs.StringVar(&c.tokenFile, "token-file", "", "a bearer token Clearance accepts, instead of GitHub's OIDC")
}

// token is the bearer token: --token-file, else the workflow's OIDC token.
func (c *tfCommon) token(ctx context.Context, env map[string]string, fetch tokenFetcher) (string, error) {
	if c.url == "" {
		return "", usagef("--url or CLEARANCE_URL is required")
	}
	if c.tokenFile != "" {
		b, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return fetch(ctx, env, c.audience)
}

func parseFlags(fs *flag.FlagSet, argv []string, stderr io.Writer) (int, bool) {
	fs.SetOutput(stderr)
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, false
		}
		return exitUsage, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "clearance %s: unrecognized arguments: %s\n", fs.Name(), strings.Join(fs.Args(), " "))
		return exitUsage, false
	}
	return 0, true
}

func requireFlags(name string, stderr io.Writer, pairs ...[2]string) bool {
	var missing []string
	for _, p := range pairs {
		if p[1] == "" {
			missing = append(missing, p[0])
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "clearance %s: the following arguments are required: %s\n", name, strings.Join(missing, ", "))
		return false
	}
	return true
}

// callJSON is one request to Clearance; a body that is not Clearance's JSON says what answered instead.
func callJSON(ctx context.Context, method, base, path, token string, body []byte, timeout time.Duration) (int, map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return 0, nil, err
	}
	v, err := pycompat.Decode(bytes.NewReader(raw))
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		what := strings.TrimSpace(strings.ToValidUTF8(string(raw[:min(len(raw), 200)]), "�"))
		if what == "" {
			what = "(empty body)"
		}
		return res.StatusCode, map[string]any{"error": "not from Clearance: " + what}, nil
	}
	return res.StatusCode, m, nil
}

func refusal(name string, status int, out map[string]any) string {
	why := ""
	for _, k := range []string{"message", "error", "detail"} {
		if v := out[k]; pycompat.Truthy(v) {
			why = pycompat.Str(v)
			break
		}
	}
	rule := ""
	if pycompat.Truthy(out["rule"]) {
		rule = pycompat.Str(out["rule"])
	}
	return strings.TrimRight(fmt.Sprintf("clearance %s: refused (%d) %s %s", name, status, rule, why), " \t\n")
}

func hashFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return tfplan.Digest(b), nil
}

// ---- hold ----

// showRunner runs `<binary> show -json <plan>` (a variable so tests need no terraform).
type showRunner func(ctx context.Context, binary, plan string, stderr io.Writer) ([]byte, error)

func terraformShow(ctx context.Context, binary, plan string, stderr io.Writer) ([]byte, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, "show", "-json", plan)
	cmd.Stdout, cmd.Stderr = &out, stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s show -json %s: %w", binary, plan, err)
	}
	return out.Bytes(), nil
}

type holdArgs struct {
	tfCommon
	plan, planJSON, workspace, binary, backend, stateKey, lockFile string
	app, env, cluster, owner, repo, head, proposer, proposerKind   string
	pr                                                             *int64
	targeted, noWait, dryRun                                       bool
	waitTimeout                                                    time.Duration
	checks, paths                                                  []string
}

func parseHoldArgs(argv []string, env map[string]string, stderr io.Writer) (*holdArgs, int) {
	a := &holdArgs{}
	fs := flag.NewFlagSet("hold", flag.ContinueOnError)
	a.bind(fs, env)
	fs.StringVar(&a.plan, "plan", "", "the saved plan file, terraform plan -out (required)")
	fs.StringVar(&a.planJSON, "json", "", "the plan's `terraform show -json` output (default: run it)")
	fs.StringVar(&a.workspace, "workspace", "default", "the Terraform workspace's name")
	fs.StringVar(&a.binary, "binary", "terraform", "terraform or tofu")
	fs.StringVar(&a.backend, "backend", "", "the state backend's type, e.g. s3 (required)")
	fs.StringVar(&a.stateKey, "state-key", "", "the state key, e.g. network/lab/terraform.tfstate (required)")
	fs.StringVar(&a.lockFile, "lock-file", ".terraform.lock.hcl", "the dependency lock file the provider versions come from (missing: none)")
	fs.BoolVar(&a.targeted, "targeted", false, "the plan was made with -target")
	fs.StringVar(&a.app, "app", "", "the application's name in Clearance (required)")
	fs.StringVar(&a.env, "env", "", "the environment's name (required)")
	fs.StringVar(&a.cluster, "cluster", "", "the cluster the environment runs on, if any")
	fs.StringVar(&a.owner, "owner", "", "the app's owner group (group:<ns>/<name>); default: Clearance looks it up")
	fs.StringVar(&a.repo, "repo", "", "owner/name (default GITHUB_REPOSITORY)")
	fs.StringVar(&a.head, "head", "", "the commit (default: the event's PR head, else GITHUB_SHA)")
	fs.Func("pr", "default: the event's pull request, else 0 (a pushed commit)", func(s string) error {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid int value: %q", s)
		}
		a.pr = &n
		return nil
	})
	fs.StringVar(&a.proposer, "proposer", "", "default: user:$GITHUB_ACTOR")
	fs.StringVar(&a.proposerKind, "proposer-kind", "person", "person, agent or unknown")
	fs.Func("check", "name=value, e.g. ci=pass (repeatable)", func(s string) error { a.checks = append(a.checks, s); return nil })
	fs.Func("path", "a file the change touches (repeatable): the gate's path rules apply", func(s string) error { a.paths = append(a.paths, s); return nil })
	fs.BoolVar(&a.noWait, "no-wait", false, "register and answer; exit 3 when the change is holding")
	fs.DurationVar(&a.waitTimeout, "wait-timeout", 0, "stop waiting after this long, exit 3 (default: until the change leaves holding)")
	fs.BoolVar(&a.dryRun, "dry-run", false, "print the request body and stop")
	if code, ok := parseFlags(fs, argv, stderr); !ok {
		return nil, code
	}
	if !requireFlags("hold", stderr, [2]string{"--plan", a.plan}, [2]string{"--app", a.app}, [2]string{"--env", a.env},
		[2]string{"--backend", a.backend}, [2]string{"--state-key", a.stateKey}) {
		return nil, exitUsage
	}
	if !slices.Contains(gate.ProposerKinds, a.proposerKind) {
		fmt.Fprintf(stderr, "clearance hold: argument --proposer-kind: invalid choice: %s (choose from %s)\n",
			pycompat.Repr(a.proposerKind), strings.Join(gate.ProposerKinds, ", "))
		return nil, exitUsage
	}
	return a, -1
}

// holdBody is the request for a terraform-plan change, in a stable order.
type holdBody struct {
	App          string            `json:"app"`
	Env          string            `json:"env"`
	Cluster      string            `json:"cluster,omitempty"`
	Repo         string            `json:"repo"`
	PR           int64             `json:"pr"`
	Head         string            `json:"head"`
	Proposer     string            `json:"proposer"`
	ProposerKind string            `json:"proposerKind"`
	Paths        []string          `json:"paths"`
	Checks       map[string]string `json:"checks"`
	Owner        string            `json:"owner,omitempty"`
	Subject      *tfplan.Subject   `json:"subject"`
}

func buildHoldBody(ctx context.Context, a *holdArgs, env map[string]string, show showRunner, stderr io.Writer) (*holdBody, error) {
	event := githubEvent(env)
	prDoc, _ := event["pull_request"].(map[string]any)
	repo := strings.ToLower(firstOf(a.repo, env["GITHUB_REPOSITORY"]))
	head := firstOf(a.head, strAt(prDoc, "head", "sha"), env["GITHUB_SHA"])
	if repo == "" || head == "" {
		return nil, usagef("the repository and commit come from GITHUB_REPOSITORY and GITHUB_SHA, or --repo and --head")
	}
	var pr int64
	if a.pr != nil {
		pr = *a.pr
	} else if n, ok := pycompat.AsInt(prDoc["number"]); ok {
		pr = n
	}
	planFile, err := os.ReadFile(a.plan)
	if err != nil {
		return nil, usagef("--plan: %s", err)
	}
	var planJSON []byte
	if a.planJSON != "" {
		if planJSON, err = os.ReadFile(a.planJSON); err != nil {
			return nil, usagef("--json: %s", err)
		}
	} else if planJSON, err = show(ctx, a.binary, a.plan, stderr); err != nil {
		return nil, err
	}
	opts := tfplan.Options{Workspace: gate.Workspace{Backend: a.backend, Key: a.stateKey, Name: a.workspace}, Targeted: a.targeted}
	if lock, err := os.ReadFile(a.lockFile); err == nil {
		opts.Providers = tfplan.ProvidersFromLock(lock)
	}
	subject, err := tfplan.Compute(planFile, planJSON, opts)
	if err != nil {
		return nil, usagef("%s", err)
	}
	checks := map[string]string{}
	for _, c := range a.checks {
		k, v, _ := strings.Cut(c, "=")
		if k == "" || v == "" {
			return nil, usagef("--check is name=value, not %s", pycompat.Repr(c))
		}
		checks[k] = v
	}
	actor := a.proposer
	if actor == "" {
		actor = "unknown"
		if u := env["GITHUB_ACTOR"]; u != "" {
			actor = "user:" + u
		}
	}
	paths := a.paths
	if paths == nil {
		paths = []string{}
	}
	return &holdBody{App: a.app, Env: strings.ToLower(a.env), Cluster: a.cluster, Repo: repo, PR: pr, Head: head, Proposer: actor,
		ProposerKind: a.proposerKind, Paths: paths, Checks: checks, Owner: a.owner, Subject: subject}, nil
}

func holdMain(ctx context.Context, argv []string, env map[string]string, fetch tokenFetcher, stdout, stderr io.Writer) int {
	return holdWith(ctx, argv, env, fetch, terraformShow, stdout, stderr)
}

func holdWith(ctx context.Context, argv []string, env map[string]string, fetch tokenFetcher, show showRunner, stdout, stderr io.Writer) int {
	a, code := parseHoldArgs(argv, env, stderr)
	if a == nil {
		return code
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "clearance hold: %s\n", err)
		return exitUsage
	}
	body, err := buildHoldBody(ctx, a, env, show, stderr)
	if err != nil {
		return fail(err)
	}
	raw, err := marshal(body, false)
	if err != nil {
		return fail(err)
	}
	// The gate's own validation, before anything is sent.
	generic, err := pycompat.Decode(bytes.NewReader(raw))
	if err != nil {
		return fail(err)
	}
	if _, err := gate.ParseRequest(generic); err != nil {
		return fail(err)
	}
	if a.dryRun {
		pretty, err := marshal(body, true)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "%s\n", pretty)
		return exitCleared
	}
	token, err := a.token(ctx, env, fetch)
	if err != nil {
		return fail(err)
	}
	status, out, err := callJSON(ctx, "POST", a.url, "/v1/clearances", token, raw, 30*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "clearance hold: Clearance unreachable: %s\n", err)
		return exitDenied
	}
	if status >= 300 {
		fmt.Fprintln(stderr, refusal("hold", status, out))
		return exitDenied
	}
	id := pycompat.Str(out["id"])
	state, _ := out["state"].(string)
	printState := func(o map[string]any) {
		line := fmt.Sprintf("%s %s tier %s", id, pycompat.Str(o["state"]), pycompat.Str(o["tier"]))
		if pycompat.Truthy(o["cleared_by"]) {
			line += " cleared_by " + pycompat.Str(o["cleared_by"])
		}
		fmt.Fprintln(stdout, line)
	}
	printState(out)
	if state == "holding" {
		req, _ := out["requirement"].(map[string]any)
		fmt.Fprintf(stdout, "holding for people: %s from %s\n", pycompat.Str(orDefault(req["owner"], json.Number("0"))),
			pycompat.Str(orDefault(req["ownerGroup"], "?")))
		if a.noWait {
			return exitHolding
		}
		wctx := ctx
		if a.waitTimeout > 0 {
			var cancel context.CancelFunc
			wctx, cancel = context.WithTimeout(ctx, a.waitTimeout)
			defer cancel()
		}
		for state == "holding" {
			st, w, err := callJSON(wctx, "GET", a.url, "/v1/clearances/"+url.PathEscape(id)+"/wait?state=holding&timeout=60", token, nil, 75*time.Second)
			if wctx.Err() != nil {
				fmt.Fprintln(stderr, "clearance hold: still holding when the wait ended")
				return exitHolding
			}
			if err != nil || st >= 500 {
				time.Sleep(2 * time.Second) // Clearance restarting: try again until the wait ends
				continue
			}
			if st >= 300 {
				fmt.Fprintln(stderr, refusal("hold", st, w))
				return exitDenied
			}
			if state, _ = w["state"].(string); state != "holding" {
				printState(w)
				out = w
			}
		}
	}
	if state == "cleared" {
		fmt.Fprintf(stdout, "plan %s\n", body.Subject.PlanDigest)
		return exitCleared
	}
	if pycompat.Truthy(out["deny_reason"]) {
		fmt.Fprintf(stderr, "denied: %s\n", pycompat.Str(out["deny_reason"]))
	}
	return exitDenied
}

func orDefault(v, def any) any {
	if v == nil {
		return def
	}
	return v
}

// ---- release ----

func releaseMain(ctx context.Context, argv []string, env map[string]string, fetch tokenFetcher, stdout, stderr io.Writer) int {
	var c tfCommon
	var plan, id string
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	c.bind(fs, env)
	fs.StringVar(&plan, "plan", "", "the saved plan file the apply will use (required)")
	fs.StringVar(&id, "clearance", "", "the change's id, from `clearance hold` (required)")
	if code, ok := parseFlags(fs, argv, stderr); !ok {
		return code
	}
	if !requireFlags("release", stderr, [2]string{"--plan", plan}, [2]string{"--clearance", id}) {
		return exitUsage
	}
	digest, err := hashFile(plan)
	if err != nil {
		fmt.Fprintf(stderr, "clearance release: %s\n", err)
		return exitUsage
	}
	token, err := c.token(ctx, env, fetch)
	if err != nil {
		fmt.Fprintf(stderr, "clearance release: %s\n", err)
		return exitUsage
	}
	st, out, err := callJSON(ctx, "GET", c.url, "/v1/clearances/"+url.PathEscape(id), token, nil, 30*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "clearance release: Clearance unreachable: %s\n", err)
		return exitDenied
	}
	if st >= 300 {
		fmt.Fprintln(stderr, refusal("release", st, out))
		return exitDenied
	}
	if s := pycompat.Str(out["state"]); s != "cleared" {
		fmt.Fprintf(stderr, "clearance release: %s is %s, not cleared: do not apply\n", id, s)
		return exitDenied
	}
	cleared := pycompat.Str(out["tree_digest"])
	if tfplan.Hex(cleared) == "" || tfplan.Hex(cleared) != tfplan.Hex(digest) {
		fmt.Fprintf(stderr, "clearance release: the plan file is sha256:%s but %s was cleared for sha256:%s: do not apply\n",
			tfplan.Hex(digest), id, tfplan.Hex(cleared))
		return exitDenied
	}
	fmt.Fprintf(stdout, "%s released: plan %s is the cleared plan\n", id, digest)
	return exitCleared
}

// ---- report ----

type applyLog struct {
	changes           []gate.AppliedChange
	applied           bool
	errText           string
	started, finished time.Time
}

// parseApplyLog reads `terraform apply -json` lines: the apply hooks and the error diagnostics' summaries (a
// diagnostic's detail can quote a value, so it is never read), and the first and last timestamps.
func parseApplyLog(r io.Reader) (*applyLog, error) {
	l := &applyLog{}
	idx := map[string]int{}
	saw, errored := false, false
	var errs []string
	dec := json.NewDecoder(r)
	for dec.More() {
		var line struct {
			Type string `json:"type"`
			TS   string `json:"@timestamp"`
			Hook struct {
				Resource struct {
					Addr string `json:"addr"`
				} `json:"resource"`
				Action string `json:"action"`
			} `json:"hook"`
			Diag struct {
				Severity string `json:"severity"`
				Summary  string `json:"summary"`
			} `json:"diagnostic"`
		}
		if err := dec.Decode(&line); err != nil {
			return nil, fmt.Errorf("the apply log is not JSON lines (terraform apply -json): %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, line.TS); err == nil {
			if l.started.IsZero() || t.Before(l.started) {
				l.started = t
			}
			if t.After(l.finished) {
				l.finished = t
			}
		}
		switch line.Type {
		case "apply_start", "apply_complete", "apply_errored":
			saw = true
			addr, action := line.Hook.Resource.Addr, line.Hook.Action
			if addr == "" || !slices.Contains(gate.ApplyActions, action) {
				continue
			}
			status := map[string]string{"apply_complete": "complete", "apply_errored": "errored"}[line.Type]
			if line.Type == "apply_errored" {
				errored = true
			}
			i, ok := idx[addr]
			if !ok {
				idx[addr] = len(l.changes)
				l.changes = append(l.changes, gate.AppliedChange{Address: addr, Action: action})
				i = idx[addr]
			}
			if status != "" {
				l.changes[i].Status = status
			}
		case "change_summary":
			saw = true
		case "diagnostic":
			if line.Diag.Severity == "error" {
				errored = true
				if line.Diag.Summary != "" {
					errs = append(errs, line.Diag.Summary)
				}
			}
		}
	}
	l.applied = saw && !errored
	l.errText = strings.Join(errs, "; ")
	if len(l.errText) > gate.MaxOutcomeError {
		l.errText = strings.ToValidUTF8(l.errText[:gate.MaxOutcomeError], "")
	}
	if !saw && !errored {
		l.errText = "the apply log has no apply events"
	}
	if l.started.IsZero() {
		l.started, l.finished = time.Now().UTC(), time.Now().UTC()
	}
	if len(l.changes) > gate.MaxResources {
		l.changes = l.changes[:gate.MaxResources]
	}
	return l, nil
}

func reportMain(ctx context.Context, argv []string, env map[string]string, fetch tokenFetcher, stdout, stderr io.Writer) int {
	var c tfCommon
	var plan, id, logPath string
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	c.bind(fs, env)
	fs.StringVar(&plan, "plan", "", "the saved plan file that was applied, re-hashed now (required)")
	fs.StringVar(&logPath, "apply-log", "", "terraform apply -json's output, one JSON object per line (required)")
	fs.StringVar(&id, "clearance", "", "the change's id, from `clearance hold` (required)")
	if code, ok := parseFlags(fs, argv, stderr); !ok {
		return code
	}
	if !requireFlags("report", stderr, [2]string{"--plan", plan}, [2]string{"--apply-log", logPath}, [2]string{"--clearance", id}) {
		return exitUsage
	}
	digest, err := hashFile(plan)
	if err != nil {
		fmt.Fprintf(stderr, "clearance report: %s\n", err)
		return exitUsage
	}
	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(stderr, "clearance report: %s\n", err)
		return exitUsage
	}
	defer f.Close()
	l, err := parseApplyLog(f)
	if err != nil {
		fmt.Fprintf(stderr, "clearance report: %s\n", err)
		return exitUsage
	}
	changes := l.changes
	if changes == nil {
		changes = []gate.AppliedChange{}
	}
	applied := l.applied
	raw, err := marshal(gate.OutcomeRequest{Applied: &applied, PlanDigest: digest, Changes: changes,
		StartedAt: l.started.UTC().Format(time.RFC3339), FinishedAt: l.finished.UTC().Format(time.RFC3339), Error: l.errText}, false)
	if err != nil {
		fmt.Fprintf(stderr, "clearance report: %s\n", err)
		return exitUsage
	}
	token, err := c.token(ctx, env, fetch)
	if err != nil {
		fmt.Fprintf(stderr, "clearance report: %s\n", err)
		return exitUsage
	}
	st, out, err := callJSON(ctx, "POST", c.url, "/v1/clearances/"+url.PathEscape(id)+"/outcome", token, raw, 30*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "clearance report: Clearance unreachable: %s\n", err)
		return exitDenied
	}
	if st >= 300 {
		fmt.Fprintln(stderr, refusal("report", st, out))
		return exitDenied
	}
	matched := out["matched"] == true
	fmt.Fprintf(stdout, "%s outcome recorded: applied=%t matched=%t audit_seq %s\n", id, applied, matched, pycompat.Str(out["audit_seq"]))
	if !matched {
		fmt.Fprintf(stderr, "clearance report: the plan applied (%s) is not the cleared one: the gate recorded a digest-mismatch exception\n", digest)
		return exitDenied
	}
	return exitCleared
}
