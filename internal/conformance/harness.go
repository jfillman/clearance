package conformance

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
)

// The identities the harness controls. The provider authenticates to the in-memory core as Principal; the
// approver is the second identity that clears a held change; the proposer is the change's author (and the runtime
// session's person), who never clears.
const (
	Principal  = "conformance/provider"
	Approver   = "user:conformance-approver"
	Proposer   = "user:conformance-proposer"
	OwnerGroup = "group:default/conformance-owners"
)

// The fake change's and fake call's fixed parts.
const (
	changeApp     = "conformance-app"
	changeEnv     = "prod"
	changeCluster = "conformance"
	changeRepo    = "conformance/gitops"
	callRepo      = "conformance/app"
)

// Defaults of Options.
const (
	DefaultTimeout      = 15 * time.Second
	DefaultHoldWindow   = 500 * time.Millisecond
	DefaultPollInterval = 50 * time.Millisecond
)

// Options are a run's settings.
type Options struct {
	// Provider is the provider's control address (http://host:port), where it serves /conformance/v1/*.
	Provider string
	Role     string
	// Timeout bounds each wait for the provider (default DefaultTimeout).
	Timeout time.Duration
	// HoldWindow is how long a held change must stay unapplied, and how long the harness waits after a terminal
	// state for a late or duplicate apply (default DefaultHoldWindow).
	HoldWindow time.Duration
	// PollInterval is the poll hint handed to a deployment provider (default DefaultPollInterval).
	PollInterval time.Duration
	// ListenHost is the address the in-memory core and the fake target listen on (default 127.0.0.1);
	// AdvertiseHost is the host the provider is told to reach them at (default ListenHost).
	ListenHost, AdvertiseHost string
	// Client calls the provider's control interface (default: a client with a 10 s timeout).
	Client *http.Client
	// CoreLog receives the in-memory core's log (default: discarded).
	CoreLog *slog.Logger
}

func (o *Options) defaults() {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.HoldWindow <= 0 {
		o.HoldWindow = DefaultHoldWindow
	}
	if o.PollInterval <= 0 {
		o.PollInterval = DefaultPollInterval
	}
	if o.ListenHost == "" {
		o.ListenHost = "127.0.0.1"
	}
	if o.AdvertiseHost == "" {
		o.AdvertiseHost = o.ListenHost
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if o.CoreLog == nil {
		o.CoreLog = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Assertions is the assertion list per role, in run order: what docs/provider-protocol.md promises and
// testdata/conformance/assertions.json pins.
var Assertions = map[string][]string{
	RoleRuntime: {"control.info", "runtime.deny-not-acted", "runtime.allow-acted-once",
		"runtime.outcome-references-decision", "runtime.spend-applied", "runtime.outage-fails-closed", "chain.verify"},
	RoleDeployment: {"control.info", "deployment.register-subject", "deployment.hold", "deployment.clear",
		"deployment.release-once", "deployment.outcome-digest", "deployment.policy-clear",
		"deployment.deny-never-applied", "deployment.expiry-never-applied", "chain.verify"},
}

// Run runs the suite for opt.Role against opt.Provider. An error is a harness that could not start (a bad option,
// a port it could not bind); everything the provider does or fails to do is an assertion in the report.
func Run(ctx context.Context, opt Options) (*Report, error) {
	opt.defaults()
	if opt.Role != RoleRuntime && opt.Role != RoleDeployment {
		return nil, fmt.Errorf("conformance: role is %s or %s", RoleRuntime, RoleDeployment)
	}
	if err := httpURL("--provider", opt.Provider); err != nil {
		return nil, fmt.Errorf("conformance: %w", err)
	}
	h := &harness{opt: opt, provider: strings.TrimRight(opt.Provider, "/"),
		rep: &Report{Suite: SuiteVersion, Role: opt.Role, Provider: ProviderRef{URL: opt.Provider}, Started: time.Now().UTC()}}
	defer func() { h.rep.Finished = time.Now().UTC() }()

	info, err := h.fetchInfo(ctx)
	if err != nil {
		h.rep.add("control.info", "the provider serves its control interface", false, err.Error())
		h.finish()
		return h.rep, nil
	}
	h.rep.Provider.Name, h.rep.Provider.Version = info.Name, info.Version
	h.rep.add("control.info", "the provider serves its control interface for this role", true,
		fmt.Sprintf("%s %s, roles %v", info.Name, info.Version, info.Roles))

	if err := h.start(ctx, info); err != nil {
		return nil, err
	}
	defer h.stop()

	switch opt.Role {
	case RoleRuntime:
		h.runtime(ctx)
	case RoleDeployment:
		h.deployment(ctx)
	}
	h.verifyChain(ctx)
	h.finish()
	return h.rep, nil
}

type harness struct {
	opt      Options
	provider string
	rep      *Report
	info     Info

	core   *core.Core
	proxy  *coreProxy
	target *Target
	offset atomic.Int64 // added to the wall clock: the core's clock, moved forward to expire a change

	coreURL, targetURL                 string
	providerTok, approverTok, targetTk string
	stops                              []func()
}

func (h *harness) finish() {
	h.rep.Pass = len(h.rep.Failed()) == 0 && len(h.rep.Assertions) > 0
}

func (h *harness) clock() time.Time { return time.Now().Add(time.Duration(h.offset.Load())) }

func (h *harness) fetchInfo(ctx context.Context) (Info, error) {
	var info Info
	if err := h.call(ctx, "GET", h.provider+PathInfo, nil, http.StatusOK, &info); err != nil {
		return info, err
	}
	switch {
	case !slices.Contains(info.Roles, h.opt.Role):
		return info, fmt.Errorf("the provider's roles %v do not include %s", info.Roles, h.opt.Role)
	case info.Name == "" || info.Version == "":
		return info, errors.New("info names no provider name or version")
	}
	if _, err := server.ParseProviders(mustJSON([]server.Provider{{Name: info.Name, Version: info.Version,
		Principals: []string{Principal}}})); err != nil {
		return info, fmt.Errorf("the provider cannot be registered: %w", err)
	}
	return info, nil
}

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b)
}

// start builds the in-memory core with the provider registered, the fake target, and serves both.
func (h *harness) start(ctx context.Context, info Info) error {
	h.info = info
	h.providerTok, h.approverTok, h.targetTk = token(), token(), token()
	principals := []struct {
		tok string
		p   authn.Principal
	}{
		{h.providerTok, authn.Principal{ID: Principal, Kind: authn.KindServiceAccount}},
		{h.approverTok, authn.Principal{ID: Approver, Kind: authn.KindPerson}},
	}
	auth := authn.AuthenticatorFunc(func(_ context.Context, tok string) (authn.Principal, error) {
		for _, x := range principals {
			if subtle.ConstantTimeCompare([]byte(tok), []byte(x.tok)) == 1 {
				return x.p, nil
			}
		}
		return authn.Principal{}, errors.New("not a token this run minted")
	})
	prov := server.Provider{Name: info.Name, Version: info.Version, Principals: []string{Principal}}
	cfg := core.Config{Memory: true, Version: "conformance", Providers: []server.Provider{prov}, Auth: auth,
		AgentLogins: []string{core.DefaultAgentLogin}}
	cfg.Gate.Verifiers = []string{Principal}
	c, err := core.Build(ctx, cfg, h.clock, h.opt.CoreLog)
	if err != nil {
		return fmt.Errorf("conformance: building the core: %w", err)
	}
	// core.Build wires no group directory (nobody could clear by person); the harness supplies its own.
	c.Gate.Directory = directory{Approver: {OwnerGroup}}
	h.core = c
	h.stops = append(h.stops, c.Close)

	h.proxy = &coreProxy{next: c.Server.Handler(), seen: map[string]evaluated{}}
	if h.coreURL, err = h.serve(h.proxy); err != nil {
		return err
	}
	h.target = NewTarget(h.targetTk, nil)
	if h.targetURL, err = h.serve(h.target.Handler()); err != nil {
		return err
	}
	return nil
}

func (h *harness) serve(handler http.Handler) (string, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(h.opt.ListenHost, "0"))
	if err != nil {
		return "", fmt.Errorf("conformance: listen: %w", err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
		ErrorLog: slog.NewLogLogger(h.opt.CoreLog.Handler(), slog.LevelWarn)}
	go func() { _ = srv.Serve(ln) }()
	h.stops = append(h.stops, func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	})
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return "http://" + net.JoinHostPort(h.opt.AdvertiseHost, port), nil
}

func (h *harness) stop() {
	for i := len(h.stops) - 1; i >= 0; i-- {
		h.stops[i]()
	}
}

type directory map[string][]string

func (d directory) Groups(_ context.Context, person string) []string { return d[person] }

// coreProxy sits in front of the core's handler: it notes every decision the core answered (to compare the spend
// the provider says it applied), and simulates an outage.
type coreProxy struct {
	next http.Handler
	mode atomic.Int32 // modeUp, modeUnavailable, modeUnreachable

	mu   sync.Mutex
	seen map[string]evaluated // by decision_id
}

const (
	modeUp          = 0
	modeUnavailable = 1 // the core answers 503 (it could not record)
	modeUnreachable = 2 // the connection is dropped without an answer
)

type evaluated struct {
	Decision bool
	Spend    json.RawMessage
	Rule     string
}

func (p *coreProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch p.mode.Load() {
	case modeUnavailable:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "conformance: the core is down"})
		return
	case modeUnreachable:
		panic(http.ErrAbortHandler) // the server drops the connection without a response
	}
	if r.Method != http.MethodPost || r.URL.Path != "/access/v1/evaluation" {
		p.next.ServeHTTP(w, r)
		return
	}
	rec := &recorder{header: http.Header{}, status: http.StatusOK}
	p.next.ServeHTTP(rec, r)
	var out struct {
		Decision bool `json:"decision"`
		Context  struct {
			Rule  string          `json:"rule"`
			Spend json.RawMessage `json:"spend"`
		} `json:"context"`
		DecisionID *string `json:"decision_id"`
	}
	if rec.status == http.StatusOK && json.Unmarshal(rec.body.Bytes(), &out) == nil && out.DecisionID != nil {
		p.mu.Lock()
		p.seen[*out.DecisionID] = evaluated{out.Decision, out.Context.Spend, out.Context.Rule}
		p.mu.Unlock()
	}
	for k, v := range rec.header {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.status)
	_, _ = w.Write(rec.body.Bytes())
}

func (p *coreProxy) decision(id string) (evaluated, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.seen[id]
	return e, ok
}

type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
	wrote  bool
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) WriteHeader(s int) {
	if !r.wrote {
		r.status, r.wrote = s, true
	}
}
func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.body.Write(b)
}

// call sends a JSON request and decodes a JSON answer of status want (a bounded read, unknown fields allowed:
// a provider may say more than the protocol asks).
func (h *harness) call(ctx context.Context, method, url string, body any, want int, out any, headers ...string) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, method, url, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := h.opt.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxControlBody+1))
	if err != nil {
		return err
	}
	if resp.StatusCode != want {
		return fmt.Errorf("%s %s: status %d, want %d: %s", method, url, resp.StatusCode, want, truncate(string(raw), 300))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: %w", method, url, err)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func (h *harness) applyReq(id string) ApplyRequest {
	return ApplyRequest{ID: id, Role: h.opt.Role, Core: Endpoint{URL: h.coreURL, Bearer: h.providerTok},
		Provider: h.info.Name, Target: Endpoint{URL: h.targetURL, Bearer: h.targetTk},
		PollIntervalMS: int(h.opt.PollInterval / time.Millisecond)}
}

func (h *harness) apply(ctx context.Context, a ApplyRequest) error {
	return h.call(ctx, "POST", h.provider+PathApply, a, http.StatusAccepted, nil)
}

func (h *harness) status(ctx context.Context, id string) (Status, error) {
	var st Status
	err := h.call(ctx, "GET", h.provider+PathApplies+id, nil, http.StatusOK, &st)
	return st, err
}

// waitFor polls the apply's status until done says so, or Timeout.
func (h *harness) waitFor(ctx context.Context, id string, done func(Status) bool) (Status, error) {
	deadline := time.Now().Add(h.opt.Timeout)
	for {
		st, err := h.status(ctx, id)
		if err == nil && done(st) {
			return st, nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return st, fmt.Errorf("waiting for %s: %w", id, err)
			}
			return st, fmt.Errorf("waiting for %s: still %q after %s", id, st.State, h.opt.Timeout)
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func terminal(st Status) bool { return Terminal(st.State) }

// drive applies a and waits for a terminal state, then a hold window for a late or duplicate apply.
func (h *harness) drive(ctx context.Context, a ApplyRequest) (Status, error) {
	if err := h.apply(ctx, a); err != nil {
		return Status{}, err
	}
	st, err := h.waitFor(ctx, a.ID, terminal)
	h.settle(ctx)
	return st, err
}

func (h *harness) settle(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(h.opt.HoldWindow):
	}
}

func (h *harness) records(ctx context.Context) ([]store.Record, error) {
	var all []store.Record
	for {
		page, err := h.core.Store.Records(ctx, int64(len(all)), 1000)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < 1000 {
			return all, nil
		}
	}
}

func (h *harness) verifyChain(ctx context.Context) {
	recs, err := h.records(ctx)
	if err != nil {
		h.rep.add("chain.verify", "the evidence chain verifies", false, err.Error())
		return
	}
	ok, bad := evidence.Verify(recs)
	seq, head, _ := h.core.Store.Head(ctx)
	h.rep.Chain = &Chain{OK: ok, Records: seq + 1, Head: head}
	ownRecords := 0
	for _, r := range recs {
		if p, _ := r["provider"].(map[string]any); p != nil && p["name"] == h.info.Name {
			ownRecords++
		}
	}
	detail := fmt.Sprintf("%d records, head %s, %d written as %s", len(recs), head, ownRecords, h.info.Name)
	switch {
	case !ok:
		detail = fmt.Sprintf("record %d does not verify (%d records)", bad, len(recs))
	case len(recs) == 0:
		ok, detail = false, "the chain is empty: nothing was recorded"
	}
	h.rep.add("chain.verify", "the evidence chain verifies from genesis", ok, detail)
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	}
	return fmt.Sprint(v)
}

func field(r map[string]any, path ...string) any {
	var v any = r
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func hexOf(s string) string { return strings.TrimPrefix(s, "sha256:") }

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---- runtime --------------------------------------------------------------------------------------------------

// evaluation is a repo.pr.open call in a fresh session; permitted=false leaves the tool out of the session's tools,
// so the core denies it (R006).
func (h *harness) evaluation(session string, permitted bool) json.RawMessage {
	now := h.clock().UTC().Truncate(time.Second)
	tools := []string{"catalog.read", "repo.file.get"}
	if permitted {
		tools = append(tools, "repo.pr.open")
	}
	zero := map[string]int{"children": 0, "github_calls": 0, "model_tokens": 0, "open_prs": 0, "tool_calls": 0}
	ev := map[string]any{
		"subject": map[string]any{"type": "principal", "id": Proposer,
			"properties": map[string]any{"kind": "user", "tier_ceiling": 1}},
		"action": map[string]any{"name": "tool.call", "properties": map[string]any{"args": map[string]any{
			"repo": callRepo, "branch": "agent/" + session, "title": "conformance " + session,
			"files": []any{map[string]any{"path": "charts/values.yaml", "content": "replicas: 2\n"}}}}},
		"resource": map[string]any{"type": "tool", "id": "repo.pr.open"},
		"context": map[string]any{
			"now": now.Format(time.RFC3339), "session_id": session,
			"scope": map[string]any{"agent_kind": "task", "api_allow": []string{}, "deny_paths": []string{".tekton/**"},
				"field_allow": []string{}, "field_deny": []string{}, "repos_allow": []string{"conformance/*"}},
			"session": map[string]any{
				"id": session, "principal": Proposer, "agent": "conformance-agent", "task_id": "t-" + session,
				"parent_id": nil, "depth": 0, "closed": false, "tripped": false, "denials": 0,
				"expires_at": now.Add(30 * time.Minute).Format(time.RFC3339),
				"limits": map[string]any{"tier_ceiling": "T1", "ttl_minutes": 30, "tool_calls": 200, "github_calls": 300,
					"open_prs": 3, "model_tokens": 500000, "children": 2, "tools": tools, "models": []string{},
					"network": "clearance", "compute": "small"},
				"used": zero, "reserved": zero,
			},
		},
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		panic(err)
	}
	return raw
}

func (h *harness) runtimeApply(id string, permitted bool) ApplyRequest {
	a := h.applyReq(id)
	a.Evaluation = h.evaluation("s-"+id, permitted)
	return a
}

func (h *harness) outcomesOf(recs []store.Record, decisionID string) []store.Record {
	var out []store.Record
	for _, r := range recs {
		if decisionID != "" && str(field(r, "outcome_of", "seq")) == decisionID {
			out = append(out, r)
		}
	}
	return out
}

func recordAt(recs []store.Record, seq string) store.Record {
	for _, r := range recs {
		if str(r["seq"]) == seq {
			return r
		}
	}
	return nil
}

func sameSpend(a, b json.RawMessage) (bool, string) {
	var x, y decide.Spend
	if len(bytes.TrimSpace(a)) == 0 {
		a = json.RawMessage("{}")
	}
	if len(bytes.TrimSpace(b)) == 0 {
		b = json.RawMessage("{}")
	}
	if err := json.Unmarshal(a, &x); err != nil {
		return false, "the provider's spend is not a spend: " + err.Error()
	}
	if err := json.Unmarshal(b, &y); err != nil {
		return false, "the core's spend is not a spend: " + err.Error()
	}
	xj, yj := mustJSON(x), mustJSON(y)
	return xj == yj, fmt.Sprintf("applied %s, the core asked for %s", xj, yj)
}

func (h *harness) runtime(ctx context.Context) {
	// Deny: the core denies the call; the provider must not touch the target, and records no outcome.
	deny, derr := h.drive(ctx, h.runtimeApply("rt-deny", false))
	denySeen, denyKnown := h.proxy.decision(deny.DecisionID)
	recs, _ := h.records(ctx)
	{
		got := len(h.target.For("rt-deny"))
		outs := len(h.outcomesOf(recs, deny.DecisionID))
		pass := derr == nil && deny.State == StateRefused && got == 0 && outs == 0 && denyKnown && !denySeen.Decision
		detail := fmt.Sprintf("decision %s %s, state %q, target applies %d, outcome records %d", deny.DecisionID,
			ruleOr(denySeen, denyKnown), deny.State, got, outs)
		if derr != nil {
			detail += ": " + derr.Error()
		}
		h.rep.add("runtime.deny-not-acted", "a denied call is not acted on", pass, detail)
	}

	// Allow: acted on exactly once.
	allow, aerr := h.drive(ctx, h.runtimeApply("rt-allow", true))
	allowSeen, allowKnown := h.proxy.decision(allow.DecisionID)
	applies := h.target.For("rt-allow")
	{
		pass := aerr == nil && allow.State == StateApplied && len(applies) == 1 && allowKnown && allowSeen.Decision
		detail := fmt.Sprintf("decision %s allow=%v, state %q, target applies %d", allow.DecisionID,
			allowKnown && allowSeen.Decision, allow.State, len(applies))
		if aerr != nil {
			detail += ": " + aerr.Error()
		}
		h.rep.add("runtime.allow-acted-once", "an allowed call is acted on exactly once", pass, detail)
	}

	// The outcome: one record linked to the decision by outcome_of {seq, hash}, written as the provider.
	recs, _ = h.records(ctx)
	{
		outs := h.outcomesOf(recs, allow.DecisionID)
		dec := recordAt(recs, allow.DecisionID)
		pass, detail := false, fmt.Sprintf("%d outcome records for decision %q", len(outs), allow.DecisionID)
		if len(outs) == 1 && dec != nil {
			o := outs[0]
			linked := str(field(o, "outcome_of", "hash")) == str(dec["hash"])
			own := str(field(o, "provider", "name")) == h.info.Name && str(field(dec, "caller", "provider")) == h.info.Name
			pass = linked && own && allow.Outcome != nil && allow.Outcome.Seq == mustSeq(o)
			detail = fmt.Sprintf("outcome seq %s -> decision seq %s, hash linked %v, provider %s, result %q", str(o["seq"]),
				allow.DecisionID, linked, str(field(o, "provider", "name")), str(o["result"]))
			if allow.Outcome == nil {
				detail += ", the provider's status names no outcome record"
			}
		}
		h.rep.add("runtime.outcome-references-decision", "the outcome record references the decision", pass, detail)
	}

	// Spend: the provider applied exactly the spend each decision carried (the allow's budgets, the deny's denial).
	{
		var notes []string
		pass := denyKnown && allowKnown
		for _, c := range []struct {
			name string
			st   Status
			ev   evaluated
		}{{"deny", deny, denySeen}, {"allow", allow, allowSeen}} {
			ok, note := sameSpend(c.st.Spend, c.ev.Spend)
			pass = pass && ok
			notes = append(notes, c.name+": "+note)
		}
		h.rep.add("runtime.spend-applied", "the spend each decision carries is applied", pass, strings.Join(notes, "; "))
	}

	// Outage: with the core unavailable (503) and unreachable (dropped), the provider fails closed.
	{
		var notes []string
		pass := true
		for _, c := range []struct {
			id   string
			mode int32
		}{{"rt-outage-503", modeUnavailable}, {"rt-outage-drop", modeUnreachable}} {
			h.proxy.mode.Store(c.mode)
			st, err := h.drive(ctx, h.runtimeApply(c.id, true))
			h.proxy.mode.Store(modeUp)
			got := len(h.target.For(c.id))
			ok := err == nil && st.State == StateRefused && got == 0
			pass = pass && ok
			note := fmt.Sprintf("%s: state %q, target applies %d", c.id, st.State, got)
			if err != nil {
				note += " (" + err.Error() + ")"
			}
			notes = append(notes, note)
		}
		h.rep.add("runtime.outage-fails-closed", "an unavailable or unreachable core fails closed", pass,
			strings.Join(notes, "; "))
	}
}

func ruleOr(e evaluated, known bool) string {
	switch {
	case !known:
		return "(not seen by the core)"
	case e.Decision:
		return "allow (harness: the deny scenario was allowed)"
	}
	return "deny " + e.Rule
}

func mustSeq(r store.Record) int64 {
	n, _ := gate.SeqInt(r["seq"])
	return n
}

// ---- deployment -----------------------------------------------------------------------------------------------

type fakeChange struct {
	id       string // the apply id
	pr       int64
	head     string
	manifest string
	digest   string // hex sha256 of manifest
	changeID string
	body     json.RawMessage
}

// change is a fake change for apply id: tier 2 (a Deployment's replicas, one owner must clear) or tier 0 (a docs
// path, cleared by policy). Each has its own PR so none supersedes another.
func (h *harness) change(id string, pr int64, tier2 bool) fakeChange {
	head := sha("conformance-head-" + id)[:40]
	manifest := fmt.Sprintf("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  namespace: conformance\n"+
		"  annotations:\n    conformance.clearance.hangarplatform.dev/apply: %s\nspec:\n  replicas: 3\n", id)
	digest := sha(manifest)
	body := map[string]any{"app": changeApp, "env": changeEnv, "cluster": changeCluster, "repo": changeRepo,
		"pr": pr, "head": head, "proposer": Proposer, "proposerKind": "person", "owner": OwnerGroup,
		"protected": true, "treeDigest": "sha256:" + digest,
		"checks": map[string]string{"ci": "pass", "provenance": "not-agent", "render": "ok"}}
	if tier2 {
		body["paths"] = []string{"values-prod.yaml"}
		body["linesChanged"] = 1
		body["objects"] = []any{map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "namespace": "conformance",
			"name": "web", "op": "changed", "fields": []string{"/spec/replicas"}}}
	} else {
		body["paths"] = []string{"docs/README.md"}
		body["linesChanged"] = 1
	}
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return fakeChange{id: id, pr: pr, head: head, manifest: manifest, digest: digest,
		changeID: gate.ChangeRequest{Repo: changeRepo, PR: pr, Head: head}.ID(), body: raw}
}

func (h *harness) deployApply(c fakeChange) ApplyRequest {
	a := h.applyReq(c.id)
	a.Change, a.Manifest = c.body, c.manifest
	return a
}

func (h *harness) storedChange(ctx context.Context, id string) (*gate.Change, error) {
	row, err := h.core.Store.Change(ctx, id)
	if err != nil {
		return nil, err
	}
	return gate.FromRecord(row.Record)
}

// person sends a person's clear or deny for a change, as the approver.
func (h *harness) person(ctx context.Context, verb, changeID string, body any) (*gate.Change, error) {
	var out gate.Change
	err := h.call(ctx, "POST", h.coreURL+"/v1/clearances/"+changeID+"/"+verb, body, http.StatusOK, &out,
		"Authorization", "Bearer "+h.approverTok)
	return &out, err
}

func (h *harness) deployOutcomes(recs []store.Record, changeID string) []store.Record {
	var out []store.Record
	for _, r := range recs {
		if r["tool"] == "deploy.outcome" && str(field(r, "change", "id")) == changeID {
			out = append(out, r)
		}
	}
	return out
}

// outcomeMatches checks the provider's one deploy.outcome for c: applied, its digest the cleared subject's, and
// the digest the target observed.
func (h *harness) outcomeMatches(recs []store.Record, c fakeChange, cleared *gate.Change) (bool, string) {
	outs := h.deployOutcomes(recs, c.changeID)
	applies := h.target.For(c.id)
	if len(outs) != 1 {
		return false, fmt.Sprintf("%d deploy.outcome records name change %s (want 1)", len(outs), c.changeID)
	}
	o := outs[0]
	got := hexOf(str(field(o, "outcome", "digests", "sha256")))
	want := ""
	if cleared != nil {
		want = hexOf(cleared.TreeDigest)
	}
	observed := ""
	if len(applies) > 0 {
		observed = applies[0].SHA256
	}
	subj := hexOf(str(field(o, "subject", "digests", "sha256")))
	applied, _ := field(o, "outcome", "applied").(bool)
	own := str(field(o, "provider", "name")) == h.info.Name
	pass := applied && own && got != "" && got == want && got == observed && (subj == "" || subj == want) &&
		cleared != nil && cleared.State == "cleared"
	return pass, fmt.Sprintf("outcome seq %s by %s: applied %v, digest %s, cleared subject %s, target observed %s, subject %s",
		str(o["seq"]), str(field(o, "provider", "name")), applied, short(got), short(want), short(observed), short(subj))
}

func short(d string) string {
	if d == "" {
		return "(none)"
	}
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func holdingOrDone(st Status) bool { return st.State == StateHolding || terminal(st) }

func (h *harness) appliedOutcome(recs []store.Record, changeID string) int {
	n := 0
	for _, o := range h.deployOutcomes(recs, changeID) {
		if applied, _ := field(o, "outcome", "applied").(bool); applied {
			n++
		}
	}
	return n
}

func (h *harness) deployment(ctx context.Context) {
	// Register and hold: a tier-2 change is registered with its subject digest and is not applied before a person
	// clears it.
	held := h.change("dp-held", 1, true)
	st, err := func() (Status, error) {
		if err := h.apply(ctx, h.deployApply(held)); err != nil {
			return Status{}, err
		}
		return h.waitFor(ctx, held.id, holdingOrDone)
	}()
	if err == nil {
		h.settle(ctx)
	}
	{
		c, cerr := h.storedChange(ctx, held.changeID)
		pass, detail := false, ""
		switch {
		case err != nil:
			detail = err.Error()
		case cerr != nil:
			detail = fmt.Sprintf("change %s is not registered: %v", held.changeID, cerr)
		default:
			pass = hexOf(c.TreeDigest) == held.digest && c.RegisteredBy == Principal && st.ChangeID == held.changeID
			detail = fmt.Sprintf("change %s by %s, tier %d, tree %s (want %s), status names %q", c.ID, c.RegisteredBy,
				c.Tier, short(hexOf(c.TreeDigest)), short(held.digest), st.ChangeID)
		}
		h.rep.add("deployment.register-subject", "the change is registered with its subject digest", pass, detail)
	}
	{
		got := len(h.target.For(held.id))
		pass := err == nil && st.State == StateHolding && got == 0
		detail := fmt.Sprintf("state %q after a %s hold window, target applies %d", st.State, h.opt.HoldWindow, got)
		h.rep.add("deployment.hold", "a tier-2 change is not applied before it is cleared", pass, detail)
	}

	// Clear: a person from the owner group, not the provider and not the proposer.
	clearStart := time.Now()
	cleared, cerr := h.person(ctx, "clear", held.changeID, nil)
	{
		pass := cerr == nil && cleared.State == "cleared" && len(cleared.Approvals) == 1 &&
			cleared.Approvals[0].Person == Approver
		detail := fmt.Sprintf("%s cleared %s: state %q", Approver, held.changeID, cleared.State)
		if cerr != nil {
			detail = cerr.Error()
		}
		h.rep.add("deployment.clear", "a person (a second identity) clears the held change", pass, detail)
	}

	// Release: applied after the clear, exactly once, the cleared digest.
	rst, rerr := h.waitFor(ctx, held.id, terminal)
	h.settle(ctx)
	applies := h.target.For(held.id)
	{
		pass := rerr == nil && rst.State == StateApplied && len(applies) == 1 && applies[0].At.After(clearStart) &&
			applies[0].SHA256 == held.digest
		detail := fmt.Sprintf("state %q, target applies %d", rst.State, len(applies))
		if len(applies) > 0 {
			detail += fmt.Sprintf(", first %s the clear, digest %s (cleared %s)", beforeAfter(applies[0].At, clearStart),
				short(applies[0].SHA256), short(held.digest))
		}
		if rerr != nil {
			detail += ": " + rerr.Error()
		}
		h.rep.add("deployment.release-once", "the cleared change is applied after the clear, exactly once", pass, detail)
	}

	// The outcome: one deploy.outcome whose digest is the cleared subject's and what the target received.
	recs, _ := h.records(ctx)
	{
		after, _ := h.storedChange(ctx, held.changeID)
		pass, detail := h.outcomeMatches(recs, held, after)
		h.rep.add("deployment.outcome-digest", "the deploy.outcome digest matches the cleared subject", pass, detail)
	}

	// Cleared by policy: a tier-0 change is applied without a person, once, with a matching outcome.
	pol := h.change("dp-policy", 2, false)
	pst, perr := h.drive(ctx, h.deployApply(pol))
	{
		recs, _ := h.records(ctx)
		c, _ := h.storedChange(ctx, pol.changeID)
		got := len(h.target.For(pol.id))
		ok, odetail := h.outcomeMatches(recs, pol, c)
		pass := perr == nil && pst.State == StateApplied && got == 1 && ok && c != nil && c.ClearedBy != nil &&
			*c.ClearedBy == "policy"
		detail := fmt.Sprintf("state %q, target applies %d; %s", pst.State, got, odetail)
		if perr != nil {
			detail += ": " + perr.Error()
		}
		h.rep.add("deployment.policy-clear", "a change cleared by policy is applied once, with its outcome", pass, detail)
	}

	// Deny: a held change a person denies is never applied.
	den := h.change("dp-denied", 3, true)
	h.refusedAfter(ctx, den, "deployment.deny-never-applied", "a denied change is never applied", func() error {
		_, err := h.person(ctx, "deny", den.changeID, map[string]string{"reason": "conformance: the harness denies it"})
		return err
	})

	// Expiry: a held change past its TTL is never applied. The core's clock moves past the TTL and the gate's
	// expiry runs, as the core's loop would.
	exp := h.change("dp-expired", 4, true)
	h.refusedAfter(ctx, exp, "deployment.expiry-never-applied", "an expired change is never applied", func() error {
		h.offset.Add(int64(time.Duration(gate.MaxTTLDays+1) * 24 * time.Hour))
		ids, err := h.core.Gate.Expire(ctx)
		if err != nil {
			return err
		}
		if !slices.Contains(ids, exp.changeID) {
			return fmt.Errorf("the gate did not expire %s (expired %v)", exp.changeID, ids)
		}
		return nil
	})
}

// refusedAfter registers c, waits for it to hold, runs decide (a deny or an expiry), and asserts the provider
// refuses: never applied, no applied outcome.
func (h *harness) refusedAfter(ctx context.Context, c fakeChange, id, title string, decide func() error) {
	var notes []string
	pass := true
	if err := h.apply(ctx, h.deployApply(c)); err != nil {
		h.rep.add(id, title, false, err.Error())
		return
	}
	st, err := h.waitFor(ctx, c.id, holdingOrDone)
	if err != nil || st.State != StateHolding {
		pass = false
		notes = append(notes, fmt.Sprintf("before the decision: state %q %v", st.State, errText(err)))
	}
	if err := decide(); err != nil {
		pass = false
		notes = append(notes, "the decision: "+err.Error())
	}
	st, err = h.waitFor(ctx, c.id, terminal)
	h.settle(ctx)
	got := len(h.target.For(c.id))
	recs, _ := h.records(ctx)
	outs := h.appliedOutcome(recs, c.changeID)
	stored, _ := h.storedChange(ctx, c.changeID)
	state := ""
	if stored != nil {
		state = stored.State
	}
	pass = pass && err == nil && st.State == StateRefused && got == 0 && outs == 0
	notes = append(notes, fmt.Sprintf("change %s is %s; provider state %q, target applies %d, applied outcomes %d",
		c.changeID, state, st.State, got, outs))
	if err != nil {
		notes = append(notes, err.Error())
	}
	h.rep.add(id, title, pass, strings.Join(notes, "; "))
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return "(" + err.Error() + ")"
}

func beforeAfter(t, ref time.Time) string {
	if t.After(ref) {
		return "after"
	}
	return "before"
}
