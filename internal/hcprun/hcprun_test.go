package hcprun_test

// G-TF-6 contract tests: the run task payload is HashiCorp's published example (testdata/post_plan_payload.json, from
// https://developer.hashicorp.com/terraform/cloud-docs/api-docs/tasks/run-tasks-integration), signed as HCP Terraform
// signs it (HMAC-SHA512 over the body, hex, X-TFC-Task-Signature); a fake HCP Terraform serves the plan JSON and
// records the callbacks (JSON:API task-results PATCHes).

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/hcprun"
	"github.com/jfillman/clearance/internal/store"
)

const token = "4QEuyyxug1f2rw.atlasv1.test-only-not-a-real-token"

type call struct {
	method, host, path, auth, ctype string
	body                            string
}

// fakeHCP answers any host name (the transport sends every connection here) and records every request.
type fakeHCP struct {
	srv       *httptest.Server
	mu        sync.Mutex
	calls     []call
	plan      []byte
	redirect  string // the plan answer is a 307 to this URL, when set
	callbacks chan struct{}
}

func newFake(t *testing.T) *fakeHCP {
	t.Helper()
	f := &fakeHCP{plan: mustRead(t, "testdata/plan.json"), callbacks: make(chan struct{}, 64)}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, call{r.Method, r.Host, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(b)})
		redirect, plan := f.redirect, f.plan
		f.mu.Unlock()
		switch {
		case r.Method == http.MethodPatch:
			w.WriteHeader(http.StatusOK)
			f.callbacks <- struct{}{}
		case redirect != "":
			http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
		case strings.HasSuffix(r.URL.Path, "/json-output"):
			w.Write(plan)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHCP) client() *http.Client {
	addr := f.srv.Listener.Addr().String()
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

func (f *fakeHCP) all() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

// patches are the statuses reported, in order.
func (f *fakeHCP) patches(t *testing.T) []string {
	var out []string
	for _, c := range f.all() {
		if c.method != http.MethodPatch {
			continue
		}
		var b struct {
			Data struct {
				Type       string
				Attributes struct{ Status, Message string }
			}
		}
		if err := json.Unmarshal([]byte(c.body), &b); err != nil || b.Data.Type != "task-results" {
			t.Fatalf("callback is not a task-results body: %s", c.body)
		}
		out = append(out, b.Data.Attributes.Status)
	}
	return out
}

func (f *fakeHCP) waitPatches(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-f.callbacks:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for callback %d of %d; saw %v", i+1, n, f.patches(t))
		}
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeGate is a scripted gate: Register answers state, and set() decides a holding change.
type fakeGate struct {
	mu         sync.Mutex
	state      string
	deny       *string
	registered []map[string]any
	who        []authn.Principal
	err        error
	ch         chan struct{}
}

func newGate(state string) *fakeGate { return &fakeGate{state: state, ch: make(chan struct{})} }

func (g *fakeGate) change() *gate.Change {
	return &gate.Change{ID: "ch-0123456789abcdef", State: g.state, Tier: 2, DenyReason: g.deny,
		Requirement: &gate.Requirement{Owner: 1, OwnerGroup: "group:default/platform"}}
}

func (g *fakeGate) Register(_ context.Context, p authn.Principal, body any) (*gate.Change, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return nil, g.err
	}
	g.who = append(g.who, p)
	g.registered = append(g.registered, body.(map[string]any))
	return g.change(), nil
}

func (g *fakeGate) Watch(string) (<-chan struct{}, func(), error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ch, func() {}, nil
}

func (g *fakeGate) Clearance(context.Context, string) (*gate.Change, *store.Token, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.change(), nil, nil
}

func (g *fakeGate) decide(state, why string) {
	g.mu.Lock()
	g.state = state
	if why != "" {
		g.deny = &why
	}
	old := g.ch
	g.ch = make(chan struct{})
	g.mu.Unlock()
	close(old)
}

type env struct {
	svc  *hcprun.Service
	gate *fakeGate
	hcp  *fakeHCP
	key  []byte
	logs *syncBuf
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func newEnv(t *testing.T, state string) *env {
	t.Helper()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	key := []byte("a-per-installation-hmac-key\n")
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &hcprun.Config{Installations: []hcprun.Installation{{Organization: "hashicorp", HMACKeyFile: keyFile, Environment: "prod"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	hcp := newFake(t)
	g := newGate(state)
	svc := &hcprun.Service{Config: cfg, Gate: g, HTTP: hcp.client(), Log: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		MaxWait: 3 * time.Second, KeepAlive: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return &env{svc, g, hcp, []byte("a-per-installation-hmac-key"), logs}
}

func (e *env) post(t *testing.T, body []byte, sig string) (int, string) {
	t.Helper()
	mux := http.NewServeMux()
	(&hcprun.Handler{Svc: e.svc}).Routes(mux)
	req := httptest.NewRequest("POST", hcprun.Path, strings.NewReader(string(body)))
	if sig != "" {
		req.Header.Set(hcprun.SignatureHeader, sig)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func (e *env) signed(t *testing.T, body []byte) (int, string) {
	return e.post(t, body, hcprun.Sign(e.key, body))
}

func payload(t *testing.T, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(mustRead(t, "testdata/post_plan_payload.json"), &m); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func TestClearedPlanPasses(t *testing.T) {
	e := newEnv(t, gate.StateCleared)
	if code, body := e.signed(t, payload(t, nil)); code != 200 || !strings.Contains(body, "accepted") {
		t.Fatalf("got %d %s", code, body)
	}
	e.hcp.waitPatches(t, 2)
	if got := e.hcp.patches(t); len(got) != 2 || got[0] != "running" || got[1] != "passed" {
		t.Fatalf("callbacks %v, want running then passed", got)
	}
	// The plan is read, and the callback made, with the run's token and the JSON:API content type, on the HCP host.
	var sawPlan bool
	for _, c := range e.hcp.all() {
		if c.host != "app.terraform.io" || c.auth != "Bearer "+token {
			t.Fatalf("call %+v: wrong host or authorization", c)
		}
		if c.method == "GET" {
			sawPlan = c.path == "/api/v2/plans/plan-6AFmRJW1PFJ7qbAh/json-output"
		} else if c.ctype != "application/vnd.api+json" || c.path != "/api/v2/task-results/5ea8d46c-2ceb-42cd-83f2-82e54697bddd/callback" {
			t.Fatalf("callback %+v", c)
		}
	}
	if !sawPlan {
		t.Fatal("the plan JSON was not read")
	}
	// What was registered: a terraform-plan change under the run task's principal, values never in it.
	if len(e.gate.registered) != 1 || e.gate.who[0].ID != "hcp-run-task:hashicorp" {
		t.Fatalf("registered %v by %v", e.gate.registered, e.gate.who)
	}
	reg := e.gate.registered[0]
	raw, _ := json.Marshal(reg)
	if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), token) {
		t.Fatal("a secret reached the registration")
	}
	if reg["app"] != "tfr-github-0" || reg["env"] != "prod" || reg["repo"] != "hashicorp/terraform-random" ||
		reg["head"] != "7d8fb2a2d601edebdb7a59ad2088a96673637d22" {
		t.Fatalf("registration %v", reg)
	}
	req, err := gate.ParseRequest(reg)
	if err != nil {
		t.Fatal(err)
	}
	if s := req.Subject; s.Workspace.Name != "tfr_github_0" || s.Workspace.Key != "ws-ck4G5bb1Yei5szRh" || len(s.Resources) != 2 ||
		s.Versions.Terraform != "1.9.5" {
		t.Fatalf("subject %+v", s)
	}
	if strings.Contains(e.logs.String(), token) {
		t.Fatal("the access token was logged")
	}
}

func TestDeniedPlanFails(t *testing.T) {
	e := newEnv(t, gate.StateDenied)
	why := "a destroy in a protected workspace"
	e.gate.deny = &why
	e.signed(t, payload(t, nil))
	e.hcp.waitPatches(t, 2)
	got := e.hcp.patches(t)
	if got[1] != "failed" || !strings.Contains(e.hcp.all()[len(e.hcp.all())-1].body, why) {
		t.Fatalf("callbacks %v, last %s", got, e.hcp.all()[len(e.hcp.all())-1].body)
	}
}

func TestHoldingThenCleared(t *testing.T) {
	e := newEnv(t, gate.StateHolding)
	e.signed(t, payload(t, nil))
	e.hcp.waitPatches(t, 2) // running (reading), running (holding)
	e.gate.decide(gate.StateCleared, "")
	e.hcp.waitPatches(t, 1)
	if got := e.hcp.patches(t); strings.Join(got, ",") != "running,running,passed" {
		t.Fatalf("callbacks %v", got)
	}
}

func TestHoldingDeniedByPeople(t *testing.T) {
	e := newEnv(t, gate.StateHolding)
	e.signed(t, payload(t, nil))
	e.hcp.waitPatches(t, 2)
	e.gate.decide(gate.StateDenied, "not now")
	e.hcp.waitPatches(t, 1)
	if got := e.hcp.patches(t); got[len(got)-1] != "failed" {
		t.Fatalf("callbacks %v", got)
	}
}

func TestHoldingPastTheWaitFails(t *testing.T) {
	e := newEnv(t, gate.StateHolding)
	e.svc.MaxWait = 200 * time.Millisecond
	e.signed(t, payload(t, nil))
	e.hcp.waitPatches(t, 3)
	if got := e.hcp.patches(t); got[len(got)-1] != "failed" {
		t.Fatalf("callbacks %v", got)
	}
}

func TestRegistrationRefusedFails(t *testing.T) {
	e := newEnv(t, gate.StateCleared)
	e.gate.err = errors.New("DG-REPO: nope")
	e.signed(t, payload(t, nil))
	e.hcp.waitPatches(t, 2)
	if got := e.hcp.patches(t); got[1] != "failed" {
		t.Fatalf("callbacks %v", got)
	}
}

func TestStages(t *testing.T) {
	for stage, want := range map[string]string{"pre_plan": "failed", "post_apply": "passed"} {
		e := newEnv(t, gate.StateCleared)
		e.signed(t, payload(t, func(m map[string]any) {
			m["stage"] = stage
			delete(m, "plan_json_api_url") // neither stage reads the plan, so neither needs the URL
		}))
		e.hcp.waitPatches(t, 1)
		if got := e.hcp.patches(t); len(got) != 1 || got[0] != want {
			t.Fatalf("%s: callbacks %v", stage, got)
		}
		if len(e.gate.registered) != 0 {
			t.Fatalf("%s registered a change", stage)
		}
	}
	// pre_apply carries the plan too.
	e := newEnv(t, gate.StateCleared)
	e.signed(t, payload(t, func(m map[string]any) { m["stage"] = "pre_apply" }))
	e.hcp.waitPatches(t, 2)
	if got := e.hcp.patches(t); got[1] != "passed" {
		t.Fatalf("pre_apply: %v", got)
	}
}

func TestSignature(t *testing.T) {
	e := newEnv(t, gate.StateCleared)
	body := payload(t, nil)
	good := hcprun.Sign(e.key, body)
	for name, c := range map[string]struct {
		body []byte
		sig  string
	}{
		"none":         {body, ""},
		"wrong key":    {body, hcprun.Sign([]byte("other"), body)},
		"tampered":     {payload(t, func(m map[string]any) { m["run_id"] = "run-x" }), good},
		"not hex":      {body, "zz" + good[2:]},
		"truncated":    {body, good[:64]},
		"sha256 style": {body, "sha256=" + good},
		"unknown org":  {payload(t, func(m map[string]any) { m["organization_name"] = "evil" }), good},
		"not json":     {[]byte("nope"), hcprun.Sign(e.key, []byte("nope"))},
	} {
		if code, _ := e.post(t, c.body, c.sig); code != 401 {
			t.Errorf("%s: got %d, want 401", name, code)
		}
	}
	if n := len(e.hcp.all()); n != 0 {
		t.Fatalf("%d calls to HCP Terraform from unauthenticated requests", n)
	}
	if code, _ := e.post(t, body, strings.ToUpper(good)); code != 200 {
		t.Errorf("an upper-case hex signature: got %d", code)
	}
}

func TestOffByDefault(t *testing.T) {
	mux := http.NewServeMux()
	(&hcprun.Handler{}).Routes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", hcprun.Path, strings.NewReader("{}")))
	if rec.Code != 404 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	e := newEnv(t, gate.StateCleared)
	big := []byte(`{"organization_name":"hashicorp","pad":"` + strings.Repeat("a", hcprun.MaxBody) + `"}`)
	if code, _ := e.post(t, big, hcprun.Sign(e.key, big)); code != 413 {
		t.Fatalf("got %d", code)
	}
}

func TestUnreadableKeyFailsClosed(t *testing.T) {
	e := newEnv(t, gate.StateCleared)
	e.svc.Config.Installations[0].HMACKeyFile = filepath.Join(t.TempDir(), "missing")
	if code, _ := e.signed(t, payload(t, nil)); code != 503 {
		t.Fatalf("got %d", code)
	}
}

func TestVerificationRequest(t *testing.T) {
	e := newEnv(t, gate.StateCleared)
	body := payload(t, func(m map[string]any) { m["stage"] = "test" })
	if code, out := e.signed(t, body); code != 200 || !strings.Contains(out, "verified") {
		t.Fatalf("got %d %s", code, out)
	}
	if len(e.hcp.all()) != 0 {
		t.Fatal("a verification request called HCP Terraform")
	}
}

// SSRF: neither URL may name another host; nothing is called, and the token goes nowhere else.
func TestURLsAreRestrictedToTheHCPHost(t *testing.T) {
	cb := "https://app.terraform.io/api/v2/task-results/5ea8d46c/callback"
	plan := "https://app.terraform.io/api/v2/plans/plan-1/json-output"
	for name, edit := range map[string]func(m map[string]any){
		"callback other host": func(m map[string]any) {
			m["task_result_callback_url"] = "https://evil.example/api/v2/task-results/1/callback"
		},
		"plan other host":       func(m map[string]any) { m["plan_json_api_url"] = "https://evil.example/api/v2/plans/1/json-output" },
		"plan metadata service": func(m map[string]any) { m["plan_json_api_url"] = "https://169.254.169.254/api/v2/plans/1/json-output" },
		"callback http": func(m map[string]any) {
			m["task_result_callback_url"] = "http://app.terraform.io/api/v2/task-results/1/callback"
		},
		"plan http": func(m map[string]any) { m["plan_json_api_url"] = "http://app.terraform.io/api/v2/plans/1/json-output" },
		"userinfo trick": func(m map[string]any) {
			m["plan_json_api_url"] = "https://app.terraform.io@evil.example/api/v2/plans/1/json-output"
		},
		"userinfo on host": func(m map[string]any) {
			m["task_result_callback_url"] = "https://user:pw@app.terraform.io" + cb[len("https://app.terraform.io"):]
		},
		"suffix host": func(m map[string]any) {
			m["plan_json_api_url"] = "https://app.terraform.io.evil.example/api/v2/plans/1/json-output"
		},
		"other port": func(m map[string]any) {
			m["plan_json_api_url"] = "https://app.terraform.io:8443/api/v2/plans/1/json-output"
		},
		"dot segments":           func(m map[string]any) { m["plan_json_api_url"] = "https://app.terraform.io/api/v2/../../internal" },
		"encoded dots":           func(m map[string]any) { m["plan_json_api_url"] = "https://app.terraform.io/api/v2/%2e%2e/x" },
		"not an api path":        func(m map[string]any) { m["plan_json_api_url"] = "https://app.terraform.io/admin" },
		"callback outside tasks": func(m map[string]any) { m["task_result_callback_url"] = "https://app.terraform.io/api/v2/plans/1" },
		"backslash": func(m map[string]any) {
			m["plan_json_api_url"] = "https://app.terraform.io\\@evil.example/api/v2/plans/1"
		},
		"missing callback":          func(m map[string]any) { delete(m, "task_result_callback_url") },
		"missing plan at post_plan": func(m map[string]any) { delete(m, "plan_json_api_url") },
		"no token":                  func(m map[string]any) { m["access_token"] = "" },
	} {
		e := newEnv(t, gate.StateCleared)
		_ = plan
		if code, body := e.signed(t, payload(t, edit)); code != 400 {
			t.Errorf("%s: got %d %s, want 400", name, code, body)
		}
		if n := len(e.hcp.all()); n != 0 {
			t.Errorf("%s: %d calls were made", name, n)
		}
	}
}

// A redirect off the HCP host (or to a host that is not one of its download hosts) is not followed, and the token
// is never sent to the download host.
func TestRedirects(t *testing.T) {
	e := newEnv(t, gate.StateCleared)
	e.hcp.redirect = "https://evil.example/steal"
	e.signed(t, payload(t, nil))
	e.hcp.waitPatches(t, 2)
	if got := e.hcp.patches(t); got[1] != "failed" {
		t.Fatalf("callbacks %v", got)
	}
	for _, c := range e.hcp.all() {
		if c.host == "evil.example" {
			t.Fatalf("followed a redirect to %s", c.host)
		}
	}

	// The download host is followed, without the token.
	e = newEnv(t, gate.StateCleared)
	e.hcp.redirect = "https://archivist.terraform.io/v1/object/abc"
	e.signed(t, payload(t, nil))
	// the fake answers the redirect target 307 again (it redirects every non-PATCH): that is a loop, so the run fails
	e.hcp.waitPatches(t, 2)
	hops := 0
	for _, c := range e.hcp.all() {
		if c.host == "archivist.terraform.io" {
			hops++
			if c.auth != "" {
				t.Fatalf("the access token was sent to the download host: %+v", c)
			}
		}
	}
	if hops == 0 {
		t.Fatal("the redirect to the download host was not followed")
	}
}

func TestRetriedRequestIsOneRun(t *testing.T) {
	e := newEnv(t, gate.StateHolding)
	body := payload(t, nil)
	e.signed(t, body)
	e.signed(t, body)
	e.hcp.waitPatches(t, 2)
	time.Sleep(100 * time.Millisecond)
	e.gate.mu.Lock()
	n := len(e.gate.registered)
	e.gate.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d registrations for one task result", n)
	}
}

func TestConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "c.json")
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	if c, err := hcprun.ReadConfig(""); c != nil || err != nil {
		t.Fatal("unset is off")
	}
	ok := `{"installations":[{"organization":"acme","hmacKeyFile":"/k","environment":"prod"}]}`
	c, err := hcprun.ReadConfig(write(ok))
	if err != nil || c.Installations[0].Host != "app.terraform.io" || c.Installations[0].RedirectHosts[0] != "archivist.terraform.io" {
		t.Fatalf("%v %+v", err, c)
	}
	for _, bad := range []string{`{}`, `{"installations":[]}`, `{"installations":[{"organization":"a b","hmacKeyFile":"/k","environment":"prod"}]}`,
		`{"installations":[{"organization":"acme","environment":"prod"}]}`, `{"installations":[{"organization":"acme","hmacKeyFile":"/k"}]}`,
		`{"installations":[{"organization":"acme","hmacKeyFile":"/k","environment":"prod","host":"a/b"}]}`,
		`{"installations":[{"organization":"acme","hmacKeyFile":"/k","environment":"prod","extra":1}]}`,
		`{"installations":[{"organization":"acme","hmacKeyFile":"/k","environment":"prod"},{"organization":"acme","hmacKeyFile":"/k","environment":"prod"}]}`} {
		if _, err := hcprun.ReadConfig(write(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
