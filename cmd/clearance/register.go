package main

// `clearance register`: a CI step that registers what a workflow is about to deploy with Clearance's deployment
// gate (register.py, docs/provenance-app.md phase 2b). Same flags, output and exit codes: 0 cleared, 3 holding for
// people, 1 denied or refused, 2 a usage error.

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
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/gate/render"
	"github.com/jfillman/clearance/internal/pycompat"
)

// Exit codes of register.py.
const (
	exitCleared = 0
	exitDenied  = 1
	exitUsage   = 2
	exitHolding = 3
)

func init() {
	cli.Register(cli.Command{Name: "register", Summary: "register a deployment with the deployment gate (CI step)",
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
			return registerMain(ctx, args, environ(), postChange, actionsToken, stdout, stderr)
		}})
}

func environ() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return &usageError{fmt.Sprintf(format, a...)} }

// poster sends the body to Clearance; it returns the status and the decoded answer.
type poster func(ctx context.Context, url, token string, body []byte) (int, map[string]any, error)

// tokenFetcher is the workflow's OIDC token for an audience.
type tokenFetcher func(ctx context.Context, env map[string]string, audience string) (string, error)

type registerArgs struct {
	url, app, env, cluster, before, after, owner, audience, tokenFile string
	repo, head, base, proposer, proposerKind                          string
	pr                                                                *int64
	pathsFromGit, dryRun                                              bool
	linesChanged                                                      int64
	checks                                                            []string
}

func parseRegisterArgs(argv []string, env map[string]string, stderr io.Writer) (*registerArgs, int) {
	a := &registerArgs{}
	fs := flag.NewFlagSet("clearance register", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&a.url, "url", env["CLEARANCE_URL"], "Clearance's gateway (CLEARANCE_URL)")
	fs.StringVar(&a.app, "app", "", "the application's name in Clearance (required)")
	fs.StringVar(&a.env, "env", "", "the GitHub environment's name; Clearance matches it lowercased (required)")
	fs.StringVar(&a.cluster, "cluster", "", "the cluster the environment runs on (required)")
	fs.StringVar(&a.before, "before", "", "rendered manifests before this commit (missing: everything is added)")
	fs.StringVar(&a.after, "after", "", "rendered manifests at this commit (required)")
	fs.StringVar(&a.owner, "owner", "", "the app's owner group (group:<ns>/<name>); default: Clearance looks it up")
	fs.StringVar(&a.audience, "audience", "clearance", "the OIDC token's audience")
	fs.StringVar(&a.tokenFile, "token-file", "", "a bearer token Clearance accepts as a verifier, instead of GitHub's OIDC")
	fs.StringVar(&a.repo, "repo", "", "owner/name (default GITHUB_REPOSITORY)")
	fs.StringVar(&a.head, "head", "", "the commit (default: the event's PR head, else GITHUB_SHA)")
	fs.StringVar(&a.base, "base", "", "the base commit (default: the event's PR base)")
	fs.Func("pr", "default: the event's pull request, else 0 (a pushed commit)", func(s string) error {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid int value: %q", s)
		}
		a.pr = &n
		return nil
	})
	fs.BoolVar(&a.pathsFromGit, "paths-from-git", false, "paths from `git diff --name-only base...head` (not in the Go binary)")
	fs.StringVar(&a.proposer, "proposer", "", "default: user:$GITHUB_ACTOR")
	fs.StringVar(&a.proposerKind, "proposer-kind", "person", "person, agent or unknown")
	fs.Int64Var(&a.linesChanged, "lines-changed", 0, "lines the diff changes")
	fs.Func("check", "name=value, e.g. ci=pass (repeatable)", func(s string) error { a.checks = append(a.checks, s); return nil })
	fs.BoolVar(&a.dryRun, "dry-run", false, "print the request body and stop")
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, 0
		}
		return nil, exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "clearance register: unrecognized arguments: %s\n", strings.Join(fs.Args(), " "))
		return nil, exitUsage
	}
	var missing []string
	for _, r := range []struct{ name, v string }{{"--app", a.app}, {"--env", a.env}, {"--cluster", a.cluster}, {"--after", a.after}} {
		if r.v == "" {
			missing = append(missing, r.name)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "clearance register: the following arguments are required: %s\n", strings.Join(missing, ", "))
		return nil, exitUsage
	}
	if !contains(gate.ProposerKinds, a.proposerKind) {
		fmt.Fprintf(stderr, "clearance register: argument --proposer-kind: invalid choice: %s (choose from %s)\n",
			pycompat.Repr(a.proposerKind), strings.Join(gate.ProposerKinds, ", "))
		return nil, exitUsage
	}
	return a, -1
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// checksBody is the checks object in register.py's order: render first, then each --check (a repeat updates it).
type checksBody struct {
	keys []string
	vals map[string]string
}

func (c *checksBody) set(k, v string) {
	if _, ok := c.vals[k]; !ok {
		c.keys = append(c.keys, k)
	}
	c.vals[k] = v
}

func (c checksBody) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range c.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(c.vals[k])
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// registerBody is the request, in register.py's key order.
type registerBody struct {
	App          string          `json:"app"`
	Env          string          `json:"env"`
	Cluster      string          `json:"cluster"`
	Repo         string          `json:"repo"`
	PR           int64           `json:"pr"`
	Head         string          `json:"head"`
	Proposer     string          `json:"proposer"`
	ProposerKind string          `json:"proposerKind"`
	TreeDigest   string          `json:"treeDigest"`
	Paths        []string        `json:"paths"`
	LinesChanged int64           `json:"linesChanged"`
	Objects      []render.Object `json:"objects"`
	Checks       checksBody      `json:"checks"`
	Base         string          `json:"base,omitempty"`
	Owner        string          `json:"owner,omitempty"`
}

func githubEvent(env map[string]string) map[string]any {
	p := env["GITHUB_EVENT_PATH"]
	if p == "" {
		return map[string]any{}
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return map[string]any{}
	}
	v, err := pycompat.Decode(bytes.NewReader(raw))
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return map[string]any{}
	}
	return m
}

func strAt(m map[string]any, keys ...string) string {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[k]
	}
	s, _ := cur.(string)
	return s
}

func buildBody(a *registerArgs, env map[string]string) (*registerBody, error) {
	event := githubEvent(env)
	prDoc, _ := event["pull_request"].(map[string]any)
	repo := a.repo
	if repo == "" {
		repo = env["GITHUB_REPOSITORY"]
	}
	repo = strings.ToLower(repo)
	head := firstOf(a.head, strAt(prDoc, "head", "sha"), env["GITHUB_SHA"])
	var pr int64
	if a.pr != nil {
		pr = *a.pr
	} else if n, ok := pycompat.AsInt(prDoc["number"]); ok {
		pr = n
	}
	base := firstOf(a.base, strAt(prDoc, "base", "sha"))
	if repo == "" || head == "" {
		return nil, usagef("the repository and commit come from GITHUB_REPOSITORY and GITHUB_SHA, or --repo and --head")
	}
	before, err := render.LoadDir(a.before)
	if err != nil {
		return nil, err
	}
	after, err := render.LoadDir(a.after)
	if err != nil {
		return nil, err
	}
	var paths []string
	if a.pathsFromGit && base != "" {
		// register.py shells out to `git diff --name-only base...head`; the Go binary never shells out.
		return nil, usagef("--paths-from-git is not supported by the Go binary; without it, paths are the files that differ between --before and --after")
	}
	if paths, err = render.ChangedFiles(a.before, a.after); err != nil {
		return nil, err
	}
	checks := checksBody{vals: map[string]string{}}
	checks.set("render", "ok")
	for _, c := range a.checks {
		k, v, _ := strings.Cut(c, "=")
		if k == "" || v == "" {
			return nil, usagef("--check is name=value, not %s", pycompat.Repr(c))
		}
		checks.set(k, v)
	}
	actor := a.proposer
	if actor == "" {
		actor = "unknown"
		if u := env["GITHUB_ACTOR"]; u != "" {
			actor = "user:" + u
		}
	}
	objects, err := render.Objects(before, after)
	if err != nil {
		var tm *render.TooMany
		if errors.As(err, &tm) {
			return nil, usagef("%s", tm.Error())
		}
		return nil, err
	}
	if len(paths) > gate.MaxPaths {
		paths = paths[:gate.MaxPaths]
	}
	b := &registerBody{App: a.app, Env: strings.ToLower(a.env), Cluster: a.cluster, Repo: repo, PR: pr, Head: head,
		Proposer: actor, ProposerKind: a.proposerKind, TreeDigest: render.TreeDigest(after), Paths: paths,
		LinesChanged: a.linesChanged, Objects: objects, Checks: checks, Owner: a.owner}
	if len(base) == 40 {
		b.Base = base
	}
	return b, nil
}

func firstOf(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func marshal(v any, indent bool) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return pycompat.ASCIIEscape(bytes.TrimRight(b.Bytes(), "\n")), nil
}

func userAgent() string {
	v := version
	if v == "" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		}
	}
	if v == "" {
		return "clearance-register"
	}
	return "clearance-register/" + v
}

// postChange is register.post: POST /v1/clearances with our own User-Agent (an edge in front of Clearance may
// refuse a default one); a refusal that is not Clearance's JSON says what answered instead.
func postChange(ctx context.Context, base, token string, body []byte) (int, map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(base, "/")+"/v1/clearances", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	limit := int64(64 << 10)
	if res.StatusCode < 300 {
		limit = 16 << 20
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit))
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

// actionsToken is register.actions_token: the workflow's OIDC ID token for the audience.
func actionsToken(ctx context.Context, env map[string]string, audience string) (string, error) {
	u, bearer := env["ACTIONS_ID_TOKEN_REQUEST_URL"], env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
	if u == "" || bearer == "" {
		return "", usagef("no GitHub Actions OIDC token: give the job `permissions: id-token: write`, or pass --token-file")
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", u+sep+"audience="+strings.ReplaceAll(url.QueryEscape(audience), "+", "%20"), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var doc struct {
		Value string `json:"value"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&doc) != nil || doc.Value == "" {
		return "", usagef("GitHub returned no OIDC token")
	}
	return doc.Value, nil
}

func registerMain(ctx context.Context, argv []string, env map[string]string, post poster, fetch tokenFetcher, stdout, stderr io.Writer) int {
	a, code := parseRegisterArgs(argv, env, stderr)
	if a == nil {
		return code
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "clearance register: %s\n", err)
		return exitUsage
	}
	body, err := buildBody(a, env)
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
	if a.url == "" {
		return fail(usagef("--url or CLEARANCE_URL is required"))
	}
	var token string
	if a.tokenFile != "" {
		b, err := os.ReadFile(a.tokenFile)
		if err != nil {
			return fail(err)
		}
		token = strings.TrimSpace(string(b))
	} else if token, err = fetch(ctx, env, a.audience); err != nil {
		return fail(err)
	}
	status, out, err := post(ctx, a.url, token, raw)
	if err != nil {
		fmt.Fprintf(stderr, "clearance register: Clearance unreachable: %s\n", err)
		return exitDenied
	}
	if status >= 300 {
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
		fmt.Fprintln(stderr, strings.TrimRight(fmt.Sprintf("clearance register: refused (%d) %s %s", status, rule, why), " \t\n"))
		return exitDenied
	}
	state := out["state"]
	line := fmt.Sprintf("%s %s tier %s", pycompat.Str(out["id"]), pycompat.Str(state), pycompat.Str(out["tier"]))
	if pycompat.Truthy(out["cleared_by"]) {
		line += " cleared_by " + pycompat.Str(out["cleared_by"])
	}
	fmt.Fprintln(stdout, line)
	if state == "cleared" {
		return exitCleared
	}
	if state == "holding" {
		req, _ := out["requirement"].(map[string]any)
		owner, group := any(json.Number("0")), any("?")
		if v, ok := req["owner"]; ok {
			owner = v
		}
		if v, ok := req["ownerGroup"]; ok {
			group = v
		}
		msg := fmt.Sprintf("holding for people: %s from %s", pycompat.Str(owner), pycompat.Str(group))
		if pycompat.Truthy(req["outside"]) {
			var gs []string
			if l, ok := req["outsideGroups"].([]any); ok {
				for _, g := range l {
					gs = append(gs, pycompat.Str(g))
				}
			}
			msg += fmt.Sprintf(", %s from %s", pycompat.Str(req["outside"]), strings.Join(gs, ", "))
		}
		fmt.Fprintln(stdout, msg)
		return exitHolding
	}
	if pycompat.Truthy(out["deny_reason"]) {
		fmt.Fprintf(stderr, "denied: %s\n", pycompat.Str(out["deny_reason"]))
	}
	return exitDenied
}
