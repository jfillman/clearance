package hcprun

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/httpjson"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/tfplan"
)

// Limits.
const (
	// MaxBody is the route's body cap: a run task payload is a couple of kilobytes.
	MaxBody = 64 << 10
	// MaxPlanBytes caps the plan JSON read from HCP Terraform.
	MaxPlanBytes = 64 << 20
	maxKeyBytes  = 4 << 10
	// SignatureHeader carries the HMAC-SHA512 of the body, hex.
	SignatureHeader = "X-Tfc-Task-Signature"
	// DefaultMaxWait is how long a run is held for people: under HCP Terraform's 60 minute limit on a task.
	DefaultMaxWait = 55 * time.Minute
	// DefaultKeepAlive is the interval of the running updates: HCP Terraform fails a task that reports no progress
	// for 10 minutes.
	DefaultKeepAlive = 4 * time.Minute
	// MaxInFlight caps the runs worked on at once.
	MaxInFlight = 64
	maxMessage  = 500
)

// Gate is what the adapter needs of the deployment gate (*gate.Service).
type Gate interface {
	Register(ctx context.Context, p authn.Principal, body any) (*gate.Change, error)
	Watch(id string) (<-chan struct{}, func(), error)
	Clearance(ctx context.Context, id string) (*gate.Change, *store.Token, error)
}

// Payload is a run task request (payload_version 1). Fields HCP Terraform adds later are ignored.
type Payload struct {
	PayloadVersion             int          `json:"payload_version"`
	Stage                      string       `json:"stage"`
	AccessToken                string       `json:"access_token"`
	Capabilities               Capabilities `json:"capabilities"`
	ConfigurationVersionID     string       `json:"configuration_version_id"`
	IsSpeculative              bool         `json:"is_speculative"`
	OrganizationName           string       `json:"organization_name"`
	PlanJSONAPIURL             string       `json:"plan_json_api_url"`
	RunAppURL                  string       `json:"run_app_url"`
	RunCreatedBy               string       `json:"run_created_by"`
	RunID                      string       `json:"run_id"`
	TaskResultCallbackURL      string       `json:"task_result_callback_url"`
	TaskResultEnforcementLevel string       `json:"task_result_enforcement_level"`
	TaskResultID               string       `json:"task_result_id"`
	VCSBranch                  *string      `json:"vcs_branch"`
	VCSCommitHash              *string      `json:"vcs_commit_hash"`
	VCSCommitURL               *string      `json:"vcs_commit_url"`
	VCSPullRequestURL          *string      `json:"vcs_pull_request_url"`
	VCSRepoURL                 *string      `json:"vcs_repo_url"`
	WorkspaceID                string       `json:"workspace_id"`
	WorkspaceName              string       `json:"workspace_name"`
	WorkspaceWorkingDirectory  string       `json:"workspace_working_directory"`
}

// Capabilities is what the caller accepts.
type Capabilities struct {
	Outcomes bool `json:"outcomes"`
}

// Service is the run task adapter. The zero value is not usable: set Config and Gate (HTTP, Log, MaxWait
// and KeepAlive have defaults).
type Service struct {
	Config *Config
	Gate   Gate
	// HTTP is the client for HCP Terraform; its redirects are always checked by the adapter (tests pass a client
	// that trusts their server).
	HTTP      *http.Client
	Log       *slog.Logger
	MaxWait   time.Duration
	KeepAlive time.Duration
	// Poll is the wait loop's fallback when the gate's watchers are exhausted (default 15s).
	Poll time.Duration

	mu       sync.Mutex
	base     context.Context
	inflight map[string]bool
	wg       sync.WaitGroup
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Run ties the background work to ctx and returns when ctx is done and the runs in flight have stopped.
func (s *Service) Run(ctx context.Context) {
	s.mu.Lock()
	s.base = ctx
	s.mu.Unlock()
	<-ctx.Done()
	s.wg.Wait()
}

func (s *Service) baseCtx() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.base == nil {
		return context.Background()
	}
	return s.base
}

func (s *Service) installation(org string) *Installation {
	if s.Config == nil {
		return nil
	}
	for i := range s.Config.Installations {
		if s.Config.Installations[i].Organization == org {
			return &s.Config.Installations[i]
		}
	}
	return nil
}

// Sign is the signature HCP Terraform puts on body with key: the hex HMAC-SHA512.
func Sign(key, body []byte) string {
	m := hmac.New(sha512.New, key)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// verify compares the header's signature with the body's, in constant time.
func verify(key, body []byte, header string) bool {
	got, err := hex.DecodeString(strings.TrimSpace(header))
	if err != nil || len(got) == 0 {
		return false
	}
	m := hmac.New(sha512.New, key)
	m.Write(body)
	return hmac.Equal(got, m.Sum(nil))
}

func readKey(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeyBytes+1))
	if err != nil {
		return nil, err
	}
	b = bytes.TrimRight(b, "\r\n")
	if len(b) == 0 || len(b) > maxKeyBytes {
		return nil, errors.New("the HMAC key file is empty or too large")
	}
	return b, nil
}

// Handler serves POST /v1/terraform/run-task. The route is authenticated by the payload's signature, never a bearer
// token. A nil Service or Config is a Clearance with no run task (404).
type Handler struct{ Svc *Service }

// Routes registers the route.
func (h *Handler) Routes(mux *http.ServeMux) { mux.HandleFunc("POST "+Path, h.serve) }

// Path is the route.
const Path = "/v1/terraform/run-task"

// Answer is the route's body.
type Answer struct {
	Result string `json:"result"`
	Reason string `json:"reason,omitempty"`
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	s := h.Svc
	if s == nil || s.Config == nil || s.Gate == nil {
		httpjson.Write(w, http.StatusNotFound, map[string]any{"error": "this Clearance runs no HCP Terraform run task"})
		return
	}
	// The size limit comes before the read; the server's body cap has already refused a declared length over it.
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil {
		httpjson.Write(w, http.StatusBadRequest, Answer{Result: "unreadable"})
		return
	}
	if len(raw) > MaxBody {
		httpjson.Write(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large"})
		return
	}
	status, ans := s.Accept(raw, r.Header.Get(SignatureHeader))
	httpjson.Write(w, status, ans)
}

// Accept authenticates and validates one request and starts its run: the status and answer for HCP Terraform.
func (s *Service) Accept(raw []byte, signature string) (int, Answer) {
	var who struct {
		Org string `json:"organization_name"`
	}
	in := (*Installation)(nil)
	if json.Unmarshal(raw, &who) == nil {
		in = s.installation(who.Org)
	}
	// An unknown organization, a missing signature and a wrong one answer alike.
	if in == nil || signature == "" {
		return http.StatusUnauthorized, Answer{Result: "bad signature"}
	}
	key, err := readKey(in.HMACKeyFile)
	if err != nil {
		s.log().Error("hcp run task: the HMAC key is unreadable", "organization", in.Organization)
		return http.StatusServiceUnavailable, Answer{Result: "unavailable"}
	}
	if !verify(key, raw, signature) {
		return http.StatusUnauthorized, Answer{Result: "bad signature"}
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil || p.PayloadVersion != 1 {
		return http.StatusBadRequest, Answer{Result: "refused", Reason: "not a version 1 run task payload"}
	}
	if p.Stage == "test" {
		return http.StatusOK, Answer{Result: "verified"} // HCP Terraform's check of a new run task's URL
	}
	switch p.Stage {
	case "pre_plan", "post_plan", "pre_apply", "post_apply":
	default:
		return http.StatusBadRequest, Answer{Result: "refused", Reason: "unknown stage"}
	}
	if p.AccessToken == "" || p.RunID == "" || p.TaskResultID == "" {
		return http.StatusBadRequest, Answer{Result: "refused", Reason: "no access_token, run_id or task_result_id"}
	}
	// SSRF: both URLs are the installation's own host, before anything is called.
	if err := in.checkURL(p.TaskResultCallbackURL, "/api/v2/task-results/"); err != nil {
		return http.StatusBadRequest, Answer{Result: "refused", Reason: "task_result_callback_url: " + err.Error()}
	}
	if p.Stage == "post_plan" || p.Stage == "pre_apply" { // the stages that fetch the plan
		if err := in.checkURL(p.PlanJSONAPIURL, "/api/v2/"); err != nil {
			return http.StatusBadRequest, Answer{Result: "refused", Reason: "plan_json_api_url: " + err.Error()}
		}
	}
	key2 := in.Organization + "/" + p.TaskResultID
	s.mu.Lock()
	if s.inflight == nil {
		s.inflight = map[string]bool{}
	}
	if s.inflight[key2] { // HCP Terraform retried a request that is being worked on
		s.mu.Unlock()
		return http.StatusOK, Answer{Result: "accepted"}
	}
	if len(s.inflight) >= MaxInFlight {
		s.mu.Unlock()
		return http.StatusServiceUnavailable, Answer{Result: "busy"} // HCP Terraform retries
	}
	s.inflight[key2] = true
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.inflight, key2)
			s.mu.Unlock()
		}()
		s.work(s.baseCtx(), in, p)
	}()
	return http.StatusOK, Answer{Result: "accepted"}
}

// checkURL is whether raw is an https URL on the installation's host, under prefix, with nothing that could steer it
// elsewhere (credentials, dot segments, a fragment).
func (in *Installation) checkURL(raw, prefix string) error {
	if raw == "" {
		return errors.New("missing")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("not a URL")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Host), ":443")
	switch {
	case u.Scheme != "https":
		return errors.New("not https")
	case u.User != nil:
		return errors.New("carries credentials")
	case host == "" || host != strings.TrimSuffix(in.Host, ":443"):
		return errors.New("not the configured HCP Terraform host")
	case u.Fragment != "" || strings.Contains(raw, "\\"):
		return errors.New("malformed")
	case u.EscapedPath() != path.Clean(u.EscapedPath()) || !strings.HasPrefix(u.EscapedPath(), prefix) ||
		strings.Contains(strings.ToLower(u.EscapedPath()), "%2e") || strings.Contains(strings.ToLower(u.EscapedPath()), "%2f"):
		return errors.New("not an HCP Terraform API path")
	}
	return nil
}

// ---- the run ----

// work is one run task, start to finish. Whatever happens, HCP Terraform gets a final answer if it can be reached.
func (s *Service) work(ctx context.Context, in *Installation, p Payload) {
	log := s.log().With("organization", in.Organization, "run", p.RunID, "workspace", p.WorkspaceName, "stage", p.Stage)
	cb := &callback{svc: s, in: in, url: p.TaskResultCallbackURL, token: p.AccessToken}
	final := func(status, msg string) {
		if err := cb.patch(ctx, status, msg); err != nil {
			log.Error("hcp run task: the result could not be reported", "status", status, "error", err.Error())
			return
		}
		log.Info("hcp run task: reported", "status", status)
	}
	switch p.Stage {
	case "pre_plan":
		final("failed", "Clearance judges a plan: attach this run task at the post-plan stage")
		return
	case "post_apply":
		final("passed", "Clearance has nothing to gate after the apply (outcome recording is not built for HCP Terraform)")
		return
	}
	if err := cb.patch(ctx, "running", "Clearance is reading the plan"); err != nil {
		log.Error("hcp run task: could not report running", "error", err.Error())
		return
	}
	planJSON, err := s.fetchPlan(ctx, in, p)
	if err != nil {
		log.Error("hcp run task: the plan could not be read", "error", err.Error())
		final("failed", "Clearance could not read the plan JSON from HCP Terraform: "+err.Error())
		return
	}
	body, err := s.registration(in, p, planJSON)
	if err != nil {
		log.Warn("hcp run task: the plan is not one the gate takes", "error", err.Error())
		final("failed", "Clearance cannot judge this plan: "+err.Error())
		return
	}
	principal := authn.Principal{ID: PrincipalPrefix + in.Organization, Kind: PrincipalKind}
	ch, err := s.Gate.Register(ctx, principal, body)
	if err != nil {
		log.Error("hcp run task: registering failed", "error", err.Error())
		final("failed", "Clearance refused to register this plan: "+truncate(err.Error()))
		return
	}
	log.Info("hcp run task: registered", "change", ch.ID, "state", ch.State, "tier", ch.Tier)
	status, msg := s.await(ctx, cb, ch, log)
	final(status, msg)
}

// await returns the final status and message once the change is decided, reporting progress while it holds.
func (s *Service) await(ctx context.Context, cb *callback, ch *gate.Change, log *slog.Logger) (string, string) {
	maxWait, keep, poll := s.MaxWait, s.KeepAlive, s.Poll
	if maxWait <= 0 {
		maxWait = DefaultMaxWait
	}
	if keep <= 0 {
		keep = DefaultKeepAlive
	}
	if poll <= 0 {
		poll = 15 * time.Second
	}
	deadline := time.NewTimer(maxWait)
	defer deadline.Stop()
	keepAlive := time.NewTicker(keep)
	defer keepAlive.Stop()
	told := ""
	for {
		var changed <-chan struct{}
		cancel := func() {}
		if ch.State == gate.StateHolding {
			if c, f, err := s.Gate.Watch(ch.ID); err == nil {
				changed, cancel = c, f
			}
			// Read after the watch is set, so a decision in between is not missed.
			if cur, _, err := s.Gate.Clearance(ctx, ch.ID); err == nil {
				ch = cur
			}
		}
		if ch.State != gate.StateHolding {
			cancel()
			return outcomeOf(ch)
		}
		if w := holdingWords(ch); w != told {
			told = w
			if err := cb.patch(ctx, "running", w); err != nil {
				log.Warn("hcp run task: progress could not be reported", "error", err.Error())
			}
		}
		var poller <-chan time.Time
		if changed == nil {
			poller = time.After(poll)
		}
		select {
		case <-changed:
		case <-poller:
			if cur, _, err := s.Gate.Clearance(ctx, ch.ID); err == nil {
				ch = cur
			}
		case <-keepAlive.C:
			_ = cb.patch(ctx, "running", told)
		case <-deadline.C:
			cancel()
			return "failed", "Clearance is still holding this plan for people (" + ch.ID + "); it was not cleared in time, so apply nothing. Start a new run once it is decided."
		case <-ctx.Done():
			cancel()
			return "failed", "Clearance is shutting down; the plan was not cleared. Start a new run."
		}
		cancel()
		if cur, _, err := s.Gate.Clearance(ctx, ch.ID); err == nil {
			ch = cur
		}
	}
}

func holdingWords(c *gate.Change) string {
	w := fmt.Sprintf("Clearance holds this plan (%s, tier %d) for people to clear it", c.ID, c.Tier)
	if q := c.Requirement; q != nil {
		w += fmt.Sprintf(": %d from %s", q.Owner, q.OwnerGroup)
	}
	return truncate(w)
}

func outcomeOf(c *gate.Change) (string, string) {
	switch c.State {
	case gate.StateCleared:
		by := "policy"
		if c.ClearedBy != nil {
			by = *c.ClearedBy
		}
		return "passed", truncate(fmt.Sprintf("Clearance cleared this plan (%s, tier %d, cleared by %s)", c.ID, c.Tier, by))
	case gate.StateDenied:
		why := "denied"
		if c.DenyReason != nil {
			why = *c.DenyReason
		}
		return "failed", truncate(fmt.Sprintf("Clearance denied this plan (%s): %s", c.ID, why))
	}
	return "failed", truncate(fmt.Sprintf("Clearance did not clear this plan (%s is %s)", c.ID, c.State))
}

func truncate(s string) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) > maxMessage {
		s = strings.ToValidUTF8(s[:maxMessage], "") + "..."
	}
	return s
}

// ---- the subject ----

var (
	shaRx    = regexp.MustCompile(`^[0-9a-f]{40}\z`)
	slugRx   = regexp.MustCompile(`[^a-z0-9-]+`)
	prNumber = regexp.MustCompile(`/pull/([0-9]{1,9})/?\z`)
	repoPath = regexp.MustCompile(`^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(\.git)?/?\z`)
)

// registration is the gate's change request for the run's plan. The plan file the gate binds to is the plan JSON as
// HCP Terraform serves it (HCP Terraform does not hand out the binary plan), so planDigest is the digest of those
// bytes. The workspace is {backend: "remote", key: the workspace id, name: the workspace name}.
func (s *Service) registration(in *Installation, p Payload, planJSON []byte) (map[string]any, error) {
	if p.WorkspaceName == "" || p.WorkspaceID == "" {
		return nil, errors.New("the payload names no workspace")
	}
	sub, err := tfplan.Compute(planJSON, planJSON, tfplan.Options{
		Workspace: gate.Workspace{Backend: "remote", Key: p.WorkspaceID, Name: p.WorkspaceName}})
	if err != nil {
		return nil, err
	}
	app := strings.Trim(slugRx.ReplaceAllString(strings.ToLower(p.WorkspaceName), "-"), "-")
	if len(app) > 63 {
		app = strings.Trim(app[:63], "-")
	}
	deref := func(v *string) string {
		if v == nil {
			return ""
		}
		return *v
	}
	repo := strings.ToLower(in.Organization + "/" + p.WorkspaceName)
	if u, err := url.Parse(deref(p.VCSRepoURL)); err == nil && u.Scheme == "https" {
		if m := repoPath.FindStringSubmatch(u.Path); m != nil {
			repo = strings.ToLower(m[1] + "/" + m[2])
		}
	}
	head := deref(p.VCSCommitHash)
	if !shaRx.MatchString(head) {
		head = ""
		if u := deref(p.VCSCommitURL); u != "" {
			head = u[strings.LastIndex(u, "/")+1:]
		}
	}
	if !shaRx.MatchString(head) {
		sum := sha256.Sum256([]byte(p.RunID))
		head = hex.EncodeToString(sum[:])[:40] // no commit (a CLI-driven run): the run stands in for it
	}
	pr := 0
	if m := prNumber.FindStringSubmatch(deref(p.VCSPullRequestURL)); m != nil {
		pr, _ = strconv.Atoi(m[1])
	}
	proposer := "hcp:" + in.Organization
	if u := p.RunCreatedBy; u != "" && len(u) <= 100 && regexp.MustCompile(`^[A-Za-z0-9_.@-]+\z`).MatchString(u) {
		proposer = "hcp:" + u
	}
	wire, err := json.Marshal(sub)
	if err != nil {
		return nil, err
	}
	subject, err := pycompat.Decode(bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	body := map[string]any{"app": app, "env": in.Environment, "repo": repo, "pr": json.Number(strconv.Itoa(pr)), "head": head,
		"proposer": proposer, "proposerKind": "person", "subject": subject}
	// The gate's own validation of the whole request, here, so a refusal is the run's message and not a 500.
	if _, err := gate.ParseRequest(body); err != nil {
		return nil, err
	}
	return body, nil
}

// ---- HCP Terraform ----

func (s *Service) client(in *Installation) *http.Client {
	base := s.HTTP
	if base == nil {
		base = &http.Client{Timeout: 60 * time.Second}
	}
	c := *base
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("too many redirects")
		}
		host := strings.ToLower(req.URL.Host)
		allowed := host == in.Host
		for _, h := range in.RedirectHosts {
			allowed = allowed || host == h
		}
		if req.URL.Scheme != "https" || !allowed || req.URL.User != nil {
			return errors.New("redirected away from the HCP Terraform host")
		}
		if host != in.Host {
			req.Header.Del("Authorization") // the run's token goes to the HCP Terraform host only
		}
		return nil
	}
	return &c
}

// fetchPlan reads the plan JSON with the run's access token.
func (s *Service) fetchPlan(ctx context.Context, in *Installation, p Payload) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.PlanJSONAPIURL, nil)
	if err != nil {
		return nil, errors.New("bad plan URL")
	}
	req.Header.Set("Authorization", "Bearer "+p.AccessToken)
	req.Header.Set("Accept", "application/json")
	res, err := s.client(in).Do(req)
	if err != nil {
		return nil, errors.New(scrub(err, p.AccessToken))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HCP Terraform answered %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxPlanBytes+1))
	if err != nil {
		return nil, errors.New("reading the plan failed")
	}
	if len(b) > MaxPlanBytes {
		return nil, fmt.Errorf("the plan JSON is over %d MiB", MaxPlanBytes>>20)
	}
	return b, nil
}

// scrub is err's text without the token, however a library quoted it.
func scrub(err error, token string) string {
	t := err.Error()
	if token != "" {
		t = strings.ReplaceAll(t, token, "***")
	}
	// Never repeat a URL (its query may be signed).
	if i := strings.Index(t, "http"); i >= 0 {
		t = strings.TrimSpace(t[:i]) + " (request failed)"
	}
	return truncate(t)
}

// callback reports a run task's result: PATCH to task_result_callback_url, authorized by the run's access token.
type callback struct {
	svc        *Service
	url, token string
	in         *Installation
}

func (c *callback) patch(ctx context.Context, status, message string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]any{"data": map[string]any{"type": "task-results",
		"attributes": map[string]any{"status": status, "message": message}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.url, bytes.NewReader(body))
	if err != nil {
		return errors.New("bad callback URL")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/vnd.api+json")
	res, err := c.svc.client(c.in).Do(req)
	if err != nil {
		return errors.New(scrub(err, c.token))
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("HCP Terraform answered %d", res.StatusCode)
	}
	return nil
}
