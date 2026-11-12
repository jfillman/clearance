// Package githubapp is the Clearance GitHub App (github_app.py, docs/provenance-app.md).
//
// Phase 1: GitHub sends pull_request and check_run webhooks; Clearance verifies the signature, gathers what
// provenance.Verify needs from GitHub itself with an installation token scoped to that one repository, records the
// verdict and posts two check runs on the PR's head (Clearance / agent-identity, Clearance / agent-scope). PR
// comments are off unless Comments is "agent-failures".
//
// Phase 2: the App is a custom deployment protection rule. A GitHub Actions job deploying to an environment the
// App protects waits until Clearance answers from the deployment gate's change for that commit and environment;
// answers are retried until GitHub takes them.
//
// The webhook answers at once and the work is queued (GitHub gives a delivery 10 seconds). Every GitHub call has a
// deadline; the App's private key is read from its file for each JWT and never logged; the App's token is only
// ever sent to the configured API base.
package githubapp

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/jfillman/clearance/internal/vocab"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/store"
)

// Constants of github_app.py.
const (
	API           = "https://api.github.com"
	IdentityCheck = "Clearance / agent-identity"
	ScopeCheck    = "Clearance / agent-scope"
	CommentMarker = "<!-- clearance:provenance -->"
	// NeedsPersonTitle starts the title of the agent-scope check run of a PR that needs a person's merge; Glidepath's
	// readers match it (docs/provenance-app.md).
	NeedsPersonTitle = "needs a person: "
	MaxPages         = 30
	// MaxCommitPages is GitHub's limit on a PR's commit list: 250 commits, 100 to a page.
	MaxCommitPages = 3
	MaxAnnotations = 50
	SweepEvery     = 60 * time.Second
	QueueSize      = 1000
	DefaultTimeout = 20 * time.Second
)

var (
	prActions    = map[string]bool{"opened": true, "synchronize": true, "reopened": true, "edited": true, "ready_for_review": true}
	commentModes = []string{"off", "agent-failures"}
	callbackRx   = regexp.MustCompile(`^/repos/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/actions/runs/([0-9]+)/deployment_protection_rule\z`)
	shaRx        = regexp.MustCompile(`^[0-9a-f]{40}\z`)
)

// Error is GitHubAppError: GitHub failed or refused; logged, never shown on the PR.
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

func gherr(format string, a ...any) *Error { return &Error{fmt.Sprintf(format, a...)} }

// VerifySignature checks X-Hub-Signature-256: the HMAC-SHA256 of the raw body with the webhook secret, compared
// in constant time.
func VerifySignature(secret, body []byte, header string) bool {
	if !strings.HasPrefix(header, "sha256=") {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(want), []byte(header[len("sha256="):])) == 1
}

// Config is the App's configuration (github_app.AppConfig).
type Config struct {
	AppID             string        `json:"appId"`             // CLEARANCE_GITHUB_APP_ID
	KeyFile           string        `json:"keyFile"`           // CLEARANCE_GITHUB_APP_KEY_FILE: the App's private key (PEM)
	WebhookSecretFile string        `json:"webhookSecretFile"` // CLEARANCE_GITHUB_APP_WEBHOOK_SECRET_FILE
	Comments          string        `json:"comments"`          // CLEARANCE_GITHUB_APP_COMMENTS: off | agent-failures
	API               string        `json:"api"`               // GitHub's API base (tests inject a fake)
	Timeout           time.Duration `json:"timeout"`           // per call; default 20s
}

// ReadConfig is github_app.read_config: nil when the App is not configured (id, key and secret are all needed).
func ReadConfig(appID, keyFile, secretFile, comments, api string) (*Config, error) {
	if appID == "" || keyFile == "" || secretFile == "" {
		return nil, nil
	}
	if comments == "" {
		comments = "off"
	}
	if api == "" {
		api = API
	}
	c := &Config{AppID: appID, KeyFile: keyFile, WebhookSecretFile: secretFile, Comments: comments,
		API: strings.TrimRight(api, "/"), Timeout: DefaultTimeout}
	return c, c.Validate()
}

// Validate is AppConfig.__post_init__.
func (c *Config) Validate() error {
	for _, m := range commentModes {
		if c.Comments == m {
			return nil
		}
	}
	return fmt.Errorf("comments is one of %v", commentModes)
}

// Provenance is what the App asks the core for PRs (provenance.Service).
type Provenance interface {
	FromApp(ctx context.Context, installation string, req provenance.Request) (provenance.Verdict, error)
	RecordInstallation(ctx context.Context, installation, action, account string, repos []string) (store.Record, error)
}

// Deployments is what the App asks the gate for deployments (gate.Service).
type Deployments interface {
	DeploymentRequested(ctx context.Context, installation, repo, head, environment string, runID int64, callbackURL string) (gate.DeploymentResult, error)
	UndeliveredDeployments(ctx context.Context) ([]gate.Undelivered, error)
	DeploymentDelivered(ctx context.Context, changeID string, runID int64, environment string) (store.Record, error)
}

// CheckRun is one check run posted.
type CheckRun struct {
	Name        string `json:"name"`
	Conclusion  string `json:"conclusion"`
	ID          any    `json:"id"`
	Annotations int    `json:"annotations"`
}

// Answer is one deployment answer posted (or a status report: Answer nil).
type Answer struct {
	Run         int64   `json:"run"`
	Environment string  `json:"environment"`
	Answer      *string `json:"answer"`
}

type item struct {
	event   string
	payload map[string]any
	sweep   bool
}

// App is the App's GitHub client and its webhook handling.
type App struct {
	cfg   Config
	prov  Provenance
	dep   Deployments
	gh    *client
	clock func() time.Time
	log   *slog.Logger
	queue chan item
	done  chan struct{}
}

// New is an App. clock may be nil (time.Now); log may be nil (slog.Default()).
func New(cfg Config, prov Provenance, dep Deployments, clock func() time.Time, log *slog.Logger) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.API == "" {
		cfg.API = API
	}
	cfg.API = strings.TrimRight(cfg.API, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if clock == nil {
		clock = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &App{cfg: cfg, prov: prov, dep: dep, gh: newClient(cfg.API, cfg.Timeout), clock: clock, log: log,
		queue: make(chan item, QueueSize)}, nil
}

func (a *App) secret() ([]byte, error) {
	b, err := os.ReadFile(a.cfg.WebhookSecretFile)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(string(b))), nil
}

// Accept is the webhook's answer: 401 on a bad signature, 202 queued, 200 ignored, 503 when the queue is full.
// It never does the work inline.
func (a *App) Accept(event string, body []byte, signature string) (int, string) {
	secret, err := a.secret()
	if err != nil {
		a.log.Error("github app: webhook secret unreadable")
		return 500, "unavailable"
	}
	if !VerifySignature(secret, body, signature) {
		return 401, "bad signature"
	}
	payload, err := decodeObject(body)
	if err != nil {
		return 400, "not JSON"
	}
	if !Wanted(event, payload) {
		return 200, "ignored"
	}
	select {
	case a.queue <- item{event: event, payload: payload}:
		return 202, "queued"
	default:
		return 503, "busy"
	}
}

// Wanted says whether an event is one the App acts on.
func Wanted(event string, payload map[string]any) bool {
	action, _ := payload["action"].(string)
	switch event {
	case "pull_request":
		if action == "closed" { // a merge decides a PR that needed a person (provenance.NeedsPerson); a close without one decides nothing
			pr, _ := payload["pull_request"].(map[string]any)
			merged, _ := pr["merged"].(bool)
			return merged
		}
		return prActions[action]
	case "check_run", "check_suite":
		return action == "rerequested"
	case "deployment_protection_rule":
		return action == "requested"
	}
	return event == "installation" || event == "installation_repositories"
}

// Poke asks the worker to deliver answered deployments (the gate calls it when people decide a change).
func (a *App) Poke() {
	select {
	case a.queue <- item{sweep: true}:
	default: // the periodic sweep delivers it
	}
}

// Run is the worker and the sweeper; it returns when ctx is done.
func (a *App) Run(ctx context.Context) {
	tick := time.NewTicker(SweepEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.Poke()
		case it := <-a.queue:
			var err error
			name := it.event
			if it.sweep {
				name = "_sweep"
				_, err = a.DeliverAnswers(ctx)
			} else {
				_, err = a.Handle(ctx, it.event, it.payload)
			}
			if err != nil {
				// One bad delivery must not end the worker.
				a.log.Error("github app: delivery failed", "event", name, "error", err.Error())
			}
		}
	}
}

// Handle processes one delivery; it returns the check runs (CheckRun) or deployment answers (Answer) posted.
func (a *App) Handle(ctx context.Context, event string, payload map[string]any) ([]any, error) {
	inst, _ := payload["installation"].(map[string]any)
	installation := inst["id"]
	if event == "deployment_protection_rule" {
		id, ok := asInt(installation)
		if !ok {
			return nil, errors.New("deployment_protection_rule without an installation")
		}
		return a.Protect(ctx, id, payload)
	}
	if event == "installation" || event == "installation_repositories" {
		list, _ := payload["repositories"].([]any)
		if len(list) == 0 {
			list, _ = payload["repositories_added"].([]any)
		}
		repos := []string{}
		for _, r := range list {
			if m, ok := r.(map[string]any); ok {
				if n, ok := m["full_name"].(string); ok && n != "" {
					repos = append(repos, n)
				}
			}
		}
		action, _ := payload["action"].(string)
		account := ""
		if acc, ok := inst["account"].(map[string]any); ok {
			account, _ = acc["login"].(string)
		}
		_, err := a.prov.RecordInstallation(ctx, pyStr(installation), action, account, repos)
		return []any{}, err
	}
	repoDoc, _ := payload["repository"].(map[string]any)
	repoName, _ := repoDoc["full_name"].(string)
	repo := strings.ToLower(repoName)
	var prs []int64
	switch event {
	case "pull_request":
		pr, _ := payload["pull_request"].(map[string]any)
		n, ok := asInt(pr["number"])
		if !ok {
			return nil, errors.New("pull_request without a number")
		}
		prs = []int64{n}
	case "check_run":
		run, _ := payload["check_run"].(map[string]any)
		if name, _ := run["name"].(string); name != IdentityCheck && name != ScopeCheck {
			return []any{}, nil
		}
		var err error
		if prs, err = numbers(run["pull_requests"]); err != nil {
			return nil, err
		}
	case "check_suite":
		suite, _ := payload["check_suite"].(map[string]any)
		var err error
		if prs, err = numbers(suite["pull_requests"]); err != nil {
			return nil, err
		}
	}
	id, ok := asInt(installation)
	if !ok || id == 0 || repo == "" || len(prs) == 0 {
		return []any{}, nil
	}
	token, err := a.InstallationToken(ctx, id, repo)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, pr := range prs {
		runs, err := a.Check(ctx, token, id, repo, pr)
		if err != nil {
			return out, err
		}
		for _, r := range runs {
			out = append(out, r)
		}
	}
	return out, nil
}

func numbers(v any) ([]int64, error) {
	list, _ := v.([]any)
	var out []int64
	for _, x := range list {
		m, _ := x.(map[string]any)
		n, ok := asInt(m["number"])
		if !ok {
			return nil, errors.New("a pull request without a number")
		}
		out = append(out, n)
	}
	return out, nil
}

// Check gathers one PR, decides, and posts the two check runs (and the comment, when on).
func (a *App) Check(ctx context.Context, token string, installation int64, repo string, pr int64) ([]CheckRun, error) {
	req, err := a.Gather(ctx, token, repo, pr)
	if err != nil {
		return nil, err
	}
	v, err := a.prov.FromApp(ctx, fmt.Sprint(installation), req)
	if err != nil {
		return nil, err
	}
	var violations []provenance.Violation
	if v.Scope.Violations != nil {
		violations = *v.Scope.Violations
	}
	idRun, err := a.postCheck(ctx, token, repo, req.Head, IdentityCheck, v.Identity, nil, v)
	if err != nil {
		return nil, err
	}
	scRun, err := a.postCheck(ctx, token, repo, req.Head, ScopeCheck, v.Scope, violations, v)
	if err != nil {
		return []CheckRun{idRun}, err
	}
	failed := !(v.Identity.OK && v.Scope.OK)
	if a.cfg.Comments == "agent-failures" && v.AgentPR && failed {
		if err := a.comment(ctx, token, repo, pr, v); err != nil {
			return []CheckRun{idRun, scRun}, err
		}
	}
	return []CheckRun{idRun, scRun}, nil
}

// -- deployments (phase 2) --------------------------------------------------------------------------------------------

// callback is the repo and run of GitHub's callback URL, only when it is the configured API's own: the App's token
// never goes anywhere a payload names.
func (a *App) callback(url string) (string, int64, bool) {
	if !strings.HasPrefix(url, a.cfg.API+"/") {
		return "", 0, false
	}
	m := callbackRx.FindStringSubmatch(url[len(a.cfg.API):])
	if m == nil {
		return "", 0, false
	}
	var run int64
	if _, err := fmt.Sscan(m[2], &run); err != nil {
		return "", 0, false
	}
	return strings.ToLower(m[1]), run, true
}

// Protect answers a deployment_protection_rule event.
func (a *App) Protect(ctx context.Context, installation int64, payload map[string]any) ([]any, error) {
	environment, _ := payload["environment"].(string)
	dep, _ := payload["deployment"].(map[string]any)
	sha, _ := dep["sha"].(string)
	sha = strings.ToLower(sha)
	url, _ := payload["deployment_callback_url"].(string)
	cbRepo, run, ok := a.callback(url)
	repoDoc, _ := payload["repository"].(map[string]any)
	repoName, _ := repoDoc["full_name"].(string)
	repo := strings.ToLower(repoName)
	if environment == "" || !shaRx.MatchString(sha) || !ok || cbRepo != repo {
		a.log.Warn("github app: deployment_protection_rule without a usable environment, sha or callback")
		return []any{}, nil
	}
	out, err := a.dep.DeploymentRequested(ctx, fmt.Sprint(installation), repo, sha, environment, run, url)
	if err != nil {
		return nil, err
	}
	if out.Answer == nil {
		// Waiting on people: a status report (no state) so the run page says who must clear it. Best effort: the
		// answer itself is delivered (and retried) when people decide.
		token, err := a.DeploymentToken(ctx, installation, repo)
		if err == nil {
			err = a.review(ctx, token, repo, run, environment, nil, out.Comment)
		}
		if err != nil {
			a.log.Warn("github app: status report not posted", "run", run, "error", err.Error())
		}
		return []any{Answer{run, environment, nil}}, nil
	}
	if out.Change == nil {
		token, err := a.DeploymentToken(ctx, installation, repo)
		if err != nil {
			return nil, err
		}
		rejected := "rejected"
		if err := a.review(ctx, token, repo, run, environment, &rejected, out.Comment); err != nil {
			return nil, err
		}
		return []any{Answer{run, environment, &rejected}}, nil
	}
	return a.DeliverAnswers(ctx)
}

// DeliverAnswers delivers every answered deployment GitHub has not taken yet; a failure stays for the next sweep.
func (a *App) DeliverAnswers(ctx context.Context) ([]any, error) {
	pending, err := a.dep.UndeliveredDeployments(ctx)
	if err != nil {
		return nil, err
	}
	done := []any{}
	for _, d := range pending {
		_, run, ok := a.callback(d.CallbackURL)
		if !ok {
			continue
		}
		inst, okInst := asInt(jsonNumber(d.Installation))
		if !okInst {
			continue
		}
		token, err := a.DeploymentToken(ctx, inst, d.Repo)
		if err == nil {
			err = a.review(ctx, token, d.Repo, run, d.Environment, d.Answer, d.Comment)
		}
		var ghe *Error
		if errors.As(err, &ghe) {
			a.log.Warn("github app: deployment answer not delivered", "run", d.RunID, "error", err.Error())
			continue
		}
		if err != nil {
			return done, err
		}
		if _, err := a.dep.DeploymentDelivered(ctx, d.Change, d.RunID, d.Environment); err != nil {
			return done, err
		}
		done = append(done, Answer{d.RunID, d.Environment, d.Answer})
	}
	return done, nil
}

// DeploymentToken is a token for one repository asking only to answer deployments.
func (a *App) DeploymentToken(ctx context.Context, installation int64, repo string) (string, error) {
	return a.token(ctx, installation, repo, map[string]string{"deployments": "write", "actions": "read", "metadata": "read"})
}

func (a *App) review(ctx context.Context, token, repo string, run int64, environment string, state *string, comment string) error {
	body := map[string]any{"environment_name": environment, "comment": truncate(comment, 1024)}
	if state != nil && *state != "" {
		body["state"] = *state
	}
	status, doc, err := a.gh.call(ctx, "POST", fmt.Sprintf("/repos/%s/actions/runs/%d/deployment_protection_rule", repo, run), "token", token, body)
	if err != nil {
		return err
	}
	if status != 200 && status != 201 && status != 204 {
		return gherr("deployment review %s run %d: %d %s", repo, run, status, truncate(message(doc), 200))
	}
	return nil
}

// -- GitHub -------------------------------------------------------------------------------------------------------------

// AppJWT is the App's JWT: RS256 over {iat: now-60, exp: now+540, iss: app id}, with the key read from its file.
func (a *App) AppJWT() (string, error) {
	pemBytes, err := os.ReadFile(a.cfg.KeyFile)
	if err != nil {
		return "", gherr("the App's private key is unreadable")
	}
	key, err := parseKey(pemBytes)
	if err != nil {
		return "", gherr("the App's private key does not parse")
	}
	now := a.clock().Unix()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(struct {
		IAT int64  `json:"iat"`
		EXP int64  `json:"exp"`
		ISS string `json:"iss"`
	}{now - 60, now + 540, a.cfg.AppID})
	if err != nil {
		return "", err
	}
	signing := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", gherr("signing the App's JWT failed")
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func parseKey(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return rk, nil
}

// InstallationToken is a token for one repository: checks write, contents, pull requests and metadata read (issues
// write when comments are on).
func (a *App) InstallationToken(ctx context.Context, installation int64, repo string) (string, error) {
	perms := map[string]string{"checks": "write", "contents": "read", "pull_requests": "read", "metadata": "read"}
	if a.cfg.Comments != "off" {
		perms["issues"] = "write"
	}
	return a.token(ctx, installation, repo, perms)
}

func (a *App) token(ctx context.Context, installation int64, repo string, perms map[string]string) (string, error) {
	jwt, err := a.AppJWT()
	if err != nil {
		return "", err
	}
	name := repo
	if i := strings.Index(repo, "/"); i >= 0 {
		name = repo[i+1:]
	}
	status, doc, err := a.gh.call(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", installation), "Bearer", jwt,
		map[string]any{"repositories": []string{name}, "permissions": perms})
	if err != nil {
		return "", err
	}
	m, _ := doc.(map[string]any)
	tok, _ := m["token"].(string)
	if status != 201 || tok == "" {
		return "", gherr("installation token: %d %s", status, truncate(message(doc), 200))
	}
	return tok, nil
}

// Gather is what provenance.Verify needs, from GitHub: the head, the author, every changed path (and a rename's old
// name), the head commit's trailers and its co-author trailers (Co-Authored-By, Assisted-by, Generated-by), which
// provenance matches against the AI co-author matchers. The <prefix>* trailers come from the head commit only; the
// co-author trailers come from every commit of the PR (GitHub lists at most 250), so an agent's commit under a
// person's later commit, or a merge from main, still counts.
func (a *App) Gather(ctx context.Context, token, repo string, pr int64) (provenance.Request, error) {
	status, doc, err := a.gh.call(ctx, "GET", fmt.Sprintf("/repos/%s/pulls/%d", repo, pr), "token", token, nil)
	if err != nil {
		return provenance.Request{}, err
	}
	if status != 200 {
		return provenance.Request{}, gherr("pull %s#%d: %d", repo, pr, status)
	}
	p, _ := doc.(map[string]any)
	headDoc, _ := p["head"].(map[string]any)
	head, ok := headDoc["sha"].(string)
	if !ok {
		return provenance.Request{}, gherr("pull %s#%d: no head sha", repo, pr)
	}
	author := ""
	if u, ok := p["user"].(map[string]any); ok {
		author, _ = u["login"].(string)
	}
	merged, _ := p["merged"].(bool)
	mergedBy, mergedByBot := "", false
	if mb, ok := p["merged_by"].(map[string]any); ok && merged {
		mergedBy, _ = mb["login"].(string)
		typ, _ := mb["type"].(string)
		mergedByBot = typ != "User" || strings.HasSuffix(strings.ToLower(mergedBy), "[bot]") // an account that is not a user is not a person
	}
	var paths []any
	for page := 1; page <= MaxPages; page++ {
		status, doc, err := a.gh.call(ctx, "GET", fmt.Sprintf("/repos/%s/pulls/%d/files?per_page=100&page=%d", repo, pr, page), "token", token, nil)
		if err != nil {
			return provenance.Request{}, err
		}
		files, isList := doc.([]any)
		if status != 200 || !isList {
			return provenance.Request{}, gherr("files %s#%d: %d", repo, pr, status)
		}
		for _, f := range files {
			fm, _ := f.(map[string]any)
			name, ok := fm["filename"].(string)
			if !ok {
				return provenance.Request{}, gherr("files %s#%d: a file without a name", repo, pr)
			}
			paths = append(paths, name)
			if prev, ok := fm["previous_filename"].(string); ok && prev != "" {
				paths = append(paths, prev)
			}
		}
		if len(files) < 100 {
			break
		}
	}
	status, doc, err = a.gh.call(ctx, "GET", fmt.Sprintf("/repos/%s/commits/%s", repo, head), "token", token, nil)
	if err != nil {
		return provenance.Request{}, err
	}
	if status != 200 {
		return provenance.Request{}, gherr("commit %s: %d", truncate(head, 7), status)
	}
	c, _ := doc.(map[string]any)
	commit, _ := c["commit"].(map[string]any)
	msg, _ := commit["message"].(string)
	trailers := map[string]any{}
	coauthors := []any{}
	trailerRx := regexp.MustCompile(`^` + regexp.QuoteMeta(vocab.Get().TrailerPrefix) + `(Task|Session|Run|Agent): *([^ ]+) *\z`)
	for _, line := range messageLines(msg) {
		if m := trailerRx.FindStringSubmatch(line); m != nil {
			trailers[strings.ToLower(m[1])] = m[2]
		}
	}
	addCoauthors := func(sha, message string) {
		for _, line := range messageLines(message) {
			if key, _, ok := strings.Cut(line, ":"); ok && vocab.IsCoauthorKey(key) && len(line) <= provenance.MaxTrailer &&
				len(coauthors) < provenance.MaxCoauthors {
				coauthors = append(coauthors, map[string]any{"commit": sha, "trailer": line})
			}
		}
	}
	addCoauthors(head, msg) // the head first, so a verdict names it when it matches
	for page := 1; page <= MaxCommitPages; page++ {
		status, doc, err := a.gh.call(ctx, "GET", fmt.Sprintf("/repos/%s/pulls/%d/commits?per_page=100&page=%d", repo, pr, page), "token", token, nil)
		if err != nil {
			return provenance.Request{}, err
		}
		list, isList := doc.([]any)
		if status != 200 || !isList {
			return provenance.Request{}, gherr("commits %s#%d: %d", repo, pr, status)
		}
		for _, x := range list {
			cm, _ := x.(map[string]any)
			sha, _ := cm["sha"].(string)
			inner, _ := cm["commit"].(map[string]any)
			message, _ := inner["message"].(string)
			if sha != "" && sha != head {
				addCoauthors(sha, message)
			}
		}
		if len(list) < 100 {
			break
		}
	}
	if len(paths) > provenance.MaxPaths {
		paths = paths[:provenance.MaxPaths]
	}
	if paths == nil {
		paths = []any{}
	}
	body := map[string]any{"repo": repo, "pr": pr, "head": head, "author": author,
		"paths": paths, "trailers": trailers, "coauthors": coauthors}
	if merged {
		body["merged"], body["mergedBy"], body["mergedByBot"] = true, mergedBy, mergedByBot
	}
	req, err := provenance.ParseRequest(body)
	if err != nil {
		return provenance.Request{}, err
	}
	return req, nil
}

// messageLines splits a commit message into trimmed lines.
func messageLines(msg string) []string {
	lines := strings.Split(strings.ReplaceAll(msg, "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return lines
}

func (a *App) postCheck(ctx context.Context, token, repo, head, name string, result provenance.Check, violations []provenance.Violation, v provenance.Verdict) (CheckRun, error) {
	// An unattested verdict (agent work outside Clearance) is a warning: neutral, never failure (2026-11-04). So is a PR that
	// needs a person and has none merging it yet: neutral, never success, titled "needs a person: <paths>" (Glidepath's readers
	// match that title and do not read it as success).
	needs := result.OK && result.Status == provenance.NeedsPerson
	warn := (result.OK && result.Status == provenance.Unattested) || needs
	word := "Failed"
	switch {
	case warn:
		word = "Warning"
	case result.OK:
		word = "Passed"
	}
	title := word + ": " + result.Status
	if needs {
		title = NeedsPersonTitle + strings.Join(result.NeedsPerson, ", ")
	}
	if result.Rule != nil && *result.Rule != "" {
		title += " (" + *result.Rule + ")"
	}
	summary := result.Message
	if !result.OK && result.Hint != "" {
		summary += "\n\n**Fix:** " + result.Hint
	}
	if needs {
		summary = result.Message + "\n\nThis agent PR proposes a change that only a person may merge (a change a document's scope marks `propose`: a " +
			"production environment or its values). The check is neutral, never success, until it is merged: by a person, it passes; by a bot " +
			"or one of the agents' logins, it fails (AS005)."
		if result.Hint != "" {
			summary += "\n\n**Note:** " + result.Hint
		}
	} else if warn {
		summary = "This PR was co-authored by an AI agent outside Clearance, so it carries no Clearance attestation."
		if c := result.Coauthor; c != nil {
			summary += fmt.Sprintf("\n\nCommit `%s` carries the trailer `%s`.", truncate(c.Commit, 12), strings.ReplaceAll(c.Trailer, "`", "'"))
		}
		summary += "\n\n" + result.Message
		if result.Hint != "" {
			summary += "\n\n**Note:** " + result.Hint + " This check is a warning only: it never fails."
		}
	}
	if v.Record != nil {
		summary += fmt.Sprintf("\n\nClearance opened this PR for agent `%s` (task `%s`).", pyStr(v.Record.Agent), pyStr(v.Record.TaskID))
	}
	summary += fmt.Sprintf("\n\nClearance evidence record `%s`.", pyStr(v.AuditSeq))
	annotations := []map[string]any{}
	for _, x := range violations {
		if x.Path == "" {
			continue
		}
		if len(annotations) == MaxAnnotations {
			break
		}
		annotations = append(annotations, map[string]any{"path": x.Path, "start_line": 1, "end_line": 1,
			"annotation_level": "failure", "title": x.Rule, "message": x.Message})
	}
	conclusion := "failure"
	switch {
	case warn:
		conclusion = "neutral"
	case result.OK:
		conclusion = "success"
	}
	external := ""
	if v.AuditSeq != nil {
		external = pyStr(v.AuditSeq)
	}
	body := map[string]any{"name": name, "head_sha": head, "status": "completed", "conclusion": conclusion,
		"external_id": external,
		"output":      map[string]any{"title": truncate(title, 255), "summary": truncate(summary, 60000), "annotations": annotations}}
	status, doc, err := a.gh.call(ctx, "POST", fmt.Sprintf("/repos/%s/check-runs", repo), "token", token, body)
	if err != nil {
		return CheckRun{}, err
	}
	if status != 201 {
		return CheckRun{}, gherr("check run %s: %d %s", name, status, truncate(message(doc), 200))
	}
	m, _ := doc.(map[string]any)
	return CheckRun{name, conclusion, m["id"], len(annotations)}, nil
}

func (a *App) comment(ctx context.Context, token, repo string, pr int64, v provenance.Verdict) error {
	lines := []string{CommentMarker, "### ❌ Clearance: this agent PR is not vouched for", ""}
	for _, kl := range []struct {
		r     provenance.Check
		label string
	}{{v.Identity, "agent-identity"}, {v.Scope, "agent-scope"}} {
		mark := "❌"
		if kl.r.OK {
			mark = "✅"
		}
		line := fmt.Sprintf("- %s **%s**: %s", mark, kl.label, kl.r.Message)
		if kl.r.Rule != nil && *kl.r.Rule != "" {
			line += " (" + *kl.r.Rule + ")"
		}
		lines = append(lines, line)
		if !kl.r.OK && kl.r.Hint != "" {
			lines = append(lines, "  - Fix: "+kl.r.Hint)
		}
	}
	body := strings.Join(lines, "\n")
	status, doc, err := a.gh.call(ctx, "GET", fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100", repo, pr), "token", token, nil)
	if err != nil {
		return err
	}
	var mine []map[string]any
	if list, ok := doc.([]any); ok && status == 200 {
		for _, c := range list {
			if m, ok := c.(map[string]any); ok && strings.HasPrefix(pyStr(orEmpty(m["body"])), CommentMarker) {
				mine = append(mine, m)
			}
		}
	}
	if len(mine) > 0 {
		_, _, err = a.gh.call(ctx, "PATCH", fmt.Sprintf("/repos/%s/issues/comments/%s", repo, pyStr(mine[0]["id"])), "token", token, map[string]any{"body": body})
	} else {
		_, _, err = a.gh.call(ctx, "POST", fmt.Sprintf("/repos/%s/issues/%d/comments", repo, pr), "token", token, map[string]any{"body": body})
	}
	return err
}

func orEmpty(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func message(doc any) string {
	if m, ok := doc.(map[string]any); ok {
		return pyStr(orEmpty(m["message"]))
	}
	return ""
}
