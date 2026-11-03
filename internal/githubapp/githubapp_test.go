package githubapp_test

// Ported from tests/test_github_app.py and tests/test_deploy_protection.py: a fake GitHub (httptest), the real
// provenance and gate services on R-1b's memory store.

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/definitions/deftest"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/githubapp"
	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
)

var secret = []byte("s3cret")

const (
	bot  = "hangar-autopilot-agents[bot]"
	head = "0000000000000000000000000000000000000001"
)

var testKey *rsa.PrivateKey

func init() {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	testKey = k
}

type call struct{ method, path, auth string }

// fakeGitHub is test_github_app.FakeGitHub and test_deploy_protection.FakeGitHub in one.
type fakeGitHub struct {
	mu        sync.Mutex
	calls     []call
	author    string
	files     []string
	head      string
	message   string
	tokens    []map[string]any
	reviews   []review
	failRev   bool
	srv       *httptest.Server
	tokenAuth []string
}

type review struct {
	path string
	body map[string]any
}

func newFake(t *testing.T, author string, trailers map[string]string, h string) *fakeGitHub {
	f := &fakeGitHub{author: author, files: []string{"src/app.js"}, head: h}
	var lines []string
	for _, k := range []string{"Task", "Session", "Agent"} {
		if v, ok := trailers[k]; ok {
			lines = append(lines, fmt.Sprintf("Hangar-%s: %s", k, v))
		}
	}
	f.message = "fix\n\n" + strings.Join(lines, "\n")
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	path := r.URL.RequestURI()
	auth := r.Header.Get("Authorization")
	f.calls = append(f.calls, call{r.Method, path, auth[:min(6, len(auth))]})
	reply := func(status int, v any) {
		w.WriteHeader(status)
		if v != nil {
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	switch {
	case strings.HasPrefix(path, "/app/installations/") && strings.HasSuffix(path, "/access_tokens"):
		f.tokens = append(f.tokens, body)
		f.tokenAuth = append(f.tokenAuth, auth)
		reply(201, map[string]any{"token": "inst-token"})
	case strings.HasSuffix(path, "/deployment_protection_rule"):
		if f.failRev {
			reply(502, map[string]any{})
			return
		}
		f.reviews = append(f.reviews, review{path, body})
		reply(204, nil)
	case strings.HasSuffix(path, "/pulls/1"):
		reply(200, map[string]any{"head": map[string]any{"sha": f.head}, "user": map[string]any{"login": f.author}})
	case strings.Contains(path, "/pulls/1/files"):
		var out []map[string]any
		for _, x := range f.files {
			out = append(out, map[string]any{"filename": x})
		}
		reply(200, out)
	case strings.Contains(path, "/commits/"+f.head):
		reply(200, map[string]any{"commit": map[string]any{"message": f.message}})
	case strings.HasSuffix(path, "/check-runs"):
		reply(201, map[string]any{"id": len(f.calls)})
	case strings.Contains(path, "/issues/1/comments"):
		if r.Method == "GET" {
			reply(200, []any{})
		} else {
			reply(201, map[string]any{})
		}
	default:
		reply(404, map[string]any{})
	}
}

type env struct {
	st   *memory.Store
	prov *provenance.Service
	gate *gate.Service
	dir  string
	clk  *time.Time
}

var (
	ci   = authn.Principal{ID: "app-gate-api-cicd/pipeline-runner", Kind: authn.KindServiceAccount}
	erin = authn.Principal{ID: "user:erin", Kind: authn.KindPerson}
)

type groups struct{}

func (groups) Groups(_ context.Context, p string) []string {
	if p == "user:erin" {
		return []string{"group:default/team-gate"}
	}
	return nil
}

func newEnv(t *testing.T) *env {
	dir := t.TempDir()
	der, _ := x509.MarshalPKCS8PrivateKey(testKey)
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret"), append(append([]byte{}, secret...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	clk := &now
	clock := func() time.Time { return *clk }
	coding := definitions.Definition{Name: "coding-agent", ReposAllow: []string{"jfillman/*"}, DenyPaths: deftest.BaselineDenyPaths}
	prov := &provenance.Service{Store: st, Clock: clock, Defs: definitions.NewRegistry(map[string]definitions.Definition{"coding-agent": coding})}
	g := gate.NewService(gate.Config{Verifiers: []string{"app-*-cicd/pipeline-runner"}}, st, clock)
	g.Directory, g.Tools, g.Parse = groups{}, deftest.Tools(), deftest.Parse
	return &env{st, prov, g, dir, clk}
}

func (e *env) app(t *testing.T, f *fakeGitHub, comments string) *githubapp.App {
	cfg := githubapp.Config{AppID: "123", KeyFile: filepath.Join(e.dir, "key.pem"), WebhookSecretFile: filepath.Join(e.dir, "secret"),
		Comments: comments, API: f.srv.URL}
	a, err := githubapp.New(cfg, e.prov, e.gate, func() time.Time { return *e.clk }, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (e *env) records(t *testing.T, tool string) []store.Record {
	all, err := e.st.Records(context.Background(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.Record
	for _, r := range all {
		if tool == "" || r["tool"] == tool {
			out = append(out, r)
		}
	}
	return out
}

func sign(body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func decode(t *testing.T, v any) map[string]any {
	raw, _ := json.Marshal(v)
	out, err := pycompat.Decode(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return out.(map[string]any)
}

func prEvent(action string) map[string]any {
	return map[string]any{"action": action, "installation": map[string]any{"id": 9}, "repository": map[string]any{"full_name": "jfillman/flight-api"},
		"pull_request": map[string]any{"number": 1}}
}

// -- phase 1 (test_github_app.py) ---------------------------------------------------------------------------------------

func TestSignatureAndWhatIsQueued(t *testing.T) {
	e := newEnv(t)
	a := e.app(t, newFake(t, "alice", nil, head), "off")
	body, _ := json.Marshal(prEvent("opened"))
	if !githubapp.VerifySignature(secret, body, sign(body)) || githubapp.VerifySignature(secret, body, "sha256=00") || githubapp.VerifySignature(secret, body, "") {
		t.Fatal("signature")
	}
	if s, w := a.Accept("pull_request", body, ""); s != 401 || w != "bad signature" {
		t.Fatal(s, w)
	}
	tampered := append([]byte{}, body...)
	tampered[len(tampered)-2] = '2'
	if s, _ := a.Accept("pull_request", tampered, sign(body)); s != 401 {
		t.Fatal("a tampered body passed", s)
	}
	if s, w := a.Accept("pull_request", body, sign(body)); s != 202 || w != "queued" {
		t.Fatal(s, w)
	}
	closed, _ := json.Marshal(prEvent("closed"))
	if s, w := a.Accept("pull_request", closed, sign(closed)); s != 200 || w != "ignored" {
		t.Fatal(s, w)
	}
	if s, w := a.Accept("push", body, sign(body)); s != 200 || w != "ignored" {
		t.Fatal(s, w)
	}
	notJSON := []byte("[1,2")
	if s, _ := a.Accept("pull_request", notJSON, sign(notJSON)); s != 400 {
		t.Fatal(s)
	}
}

func TestTheAppJwtAndAOneRepoReadOnlyToken(t *testing.T) {
	e := newEnv(t)
	f := newFake(t, "alice", nil, head)
	a := e.app(t, f, "off")
	jwt, err := a.AppJWT()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatal("JWT signature:", err)
	}
	var claims struct {
		IAT, EXP int64
		ISS      string
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(raw, &claims)
	if claims.ISS != "123" || claims.EXP-claims.IAT > 600 {
		t.Fatal(claims)
	}
	if _, err := a.InstallationToken(context.Background(), 9, "jfillman/flight-api"); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"repositories": []any{"flight-api"}, "permissions": map[string]any{"checks": "write", "contents": "read", "pull_requests": "read", "metadata": "read"}}
	if !reflect.DeepEqual(f.tokens[0], want) || !strings.HasPrefix(f.tokenAuth[0], "Bearer ") {
		t.Fatal(f.tokens[0], f.tokenAuth[0])
	}
}

func checks(runs []any) [][2]string {
	var out [][2]string
	for _, r := range runs {
		c := r.(githubapp.CheckRun)
		out = append(out, [2]string{c.Name, c.Conclusion})
	}
	return out
}

func TestAPersonsPrGetsTwoPassingChecksAndARecord(t *testing.T) {
	e := newEnv(t)
	f := newFake(t, "alice", nil, head)
	runs, err := e.app(t, f, "off").Handle(context.Background(), "pull_request", decode(t, prEvent("opened")))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(checks(runs), [][2]string{{githubapp.IdentityCheck, "success"}, {githubapp.ScopeCheck, "success"}}) {
		t.Fatal(runs)
	}
	recs := e.records(t, "")
	rec := recs[len(recs)-1]
	if rec["tool"] != "provenance.verify" || rec["principal"] != "app:9" || rec["target"] != "jfillman/flight-api#1" || rec["result"] != "identity:not-agent scope:not-agent" {
		t.Fatal(rec)
	}
	for _, c := range f.calls {
		if strings.Contains(c.path, "/comments") {
			t.Fatal("commented", c)
		}
	}
}

func TestAnAgentsLoginWithoutAReceiptFailsIdentityAndCommentsOnlyWhenOn(t *testing.T) {
	e := newEnv(t)
	e.prov.Config.AgentLogins = []string{bot}
	off := newFake(t, bot, nil, head)
	runs, err := e.app(t, off, "off").Handle(context.Background(), "pull_request", decode(t, prEvent("opened")))
	if err != nil || runs[0].(githubapp.CheckRun).Conclusion != "failure" {
		t.Fatal(runs, err)
	}
	for _, c := range off.calls {
		if strings.Contains(c.path, "/comments") {
			t.Fatal("commented while off")
		}
	}
	on := newFake(t, bot, nil, head)
	if _, err := e.app(t, on, "agent-failures").Handle(context.Background(), "pull_request", decode(t, prEvent("opened"))); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range on.calls {
		if c == (call{"POST", "/repos/jfillman/flight-api/issues/1/comments", "token "}) {
			found = true
		}
	}
	if !found || on.tokens[0]["permissions"].(map[string]any)["issues"] != "write" {
		t.Fatal(on.calls, on.tokens)
	}
}

func TestAPrClearanceOpenedIsConfirmed(t *testing.T) {
	e := newEnv(t)
	e.prov.Config.AgentLogins = []string{bot}
	commit := "c0ffee0000000000000000000000000000000000"
	err := e.st.Atomic(context.Background(), func(tx store.Tx) error {
		_, err := tx.Append(context.Background(), store.Event{"ts": "2026-09-26T12:00:00Z", "task_id": "t-1", "session": "s-000001", "parent": nil,
			"principal": "user:alice", "agent": "coding-agent", "tool": "repo.pr.open", "tier": "T1", "decision": "allow", "rule": nil,
			"target": "jfillman/flight-api", "args_sha256": strings.Repeat("0", 64), "result": "ok",
			"effect": map[string]any{"pr": json.Number("1"), "commit": commit, "branch": "agent/t-1", "repo": "jfillman/flight-api", "paths": []any{"src/app.js"}}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	f := newFake(t, bot, map[string]string{"Task": "t-1", "Session": "s-000001", "Agent": "coding-agent"}, commit)
	runs, err := e.app(t, f, "off").Handle(context.Background(), "pull_request", decode(t, prEvent("opened")))
	if err != nil || runs[0].(githubapp.CheckRun).Conclusion != "success" || runs[1].(githubapp.CheckRun).Conclusion != "success" {
		t.Fatal(runs, err)
	}
	recs := e.records(t, "")
	if recs[len(recs)-1]["result"] != "identity:confirmed scope:in-scope" {
		t.Fatal(recs[len(recs)-1])
	}
}

func TestRerequestAndInstallationEvents(t *testing.T) {
	e := newEnv(t)
	a := e.app(t, newFake(t, "alice", nil, head), "off")
	ev := map[string]any{"action": "rerequested", "installation": map[string]any{"id": 9}, "repository": map[string]any{"full_name": "jfillman/flight-api"},
		"check_run": map[string]any{"name": githubapp.ScopeCheck, "pull_requests": []any{map[string]any{"number": 1}}}}
	if runs, err := a.Handle(context.Background(), "check_run", decode(t, ev)); err != nil || len(runs) != 2 {
		t.Fatal(runs, err)
	}
	ev["check_run"] = map[string]any{"name": "someone else", "pull_requests": []any{map[string]any{"number": 1}}}
	if runs, _ := a.Handle(context.Background(), "check_run", decode(t, ev)); len(runs) != 0 {
		t.Fatal(runs)
	}
	inst := map[string]any{"action": "created", "installation": map[string]any{"id": 9, "account": map[string]any{"login": "jfillman"}},
		"repositories": []any{map[string]any{"full_name": "jfillman/flight-api"}, map[string]any{"full_name": "jfillman/gate-api"}}}
	if _, err := a.Handle(context.Background(), "installation", decode(t, inst)); err != nil {
		t.Fatal(err)
	}
	recs := e.records(t, "")
	r := recs[len(recs)-1]
	if r["tool"] != "app.installation" || r["principal"] != "app:9" || r["target"] != "jfillman" || r["result"] != "created: 2 repositories" {
		t.Fatal(r)
	}
}

func TestTheWebhookRoute(t *testing.T) {
	e := newEnv(t)
	a := e.app(t, newFake(t, "alice", nil, head), "off")
	mux := http.NewServeMux()
	(&githubapp.Handler{App: a}).Routes(mux)
	body, _ := json.Marshal(prEvent("opened"))
	post := func(m *http.ServeMux, hdr map[string]string) int {
		r := httptest.NewRequest("POST", "/v1/github/webhook", strings.NewReader(string(body)))
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		return w.Code
	}
	if c := post(mux, map[string]string{"X-GitHub-Event": "pull_request"}); c != 401 {
		t.Fatal(c)
	}
	if c := post(mux, map[string]string{"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sign(body)}); c != 202 {
		t.Fatal(c)
	}
	bare := http.NewServeMux()
	(&githubapp.Handler{}).Routes(bare)
	if c := post(bare, nil); c != 404 {
		t.Fatal(c)
	}
}

func TestTheWorkerProcessesTheQueue(t *testing.T) {
	e := newEnv(t)
	f := newFake(t, "alice", nil, head)
	a := e.app(t, f, "off")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	body, _ := json.Marshal(prEvent("opened"))
	if s, _ := a.Accept("pull_request", body, sign(body)); s != 202 {
		t.Fatal(s)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(e.records(t, "provenance.verify")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if len(e.records(t, "provenance.verify")) != 1 {
		t.Fatal("the queued delivery was not processed")
	}
}

func TestConfig(t *testing.T) {
	if c, err := githubapp.ReadConfig("", "k", "s", "", ""); c != nil || err != nil {
		t.Fatal(c, err)
	}
	c, err := githubapp.ReadConfig("1", "/k", "/s", "agent-failures", "https://api.example/")
	if err != nil || c.Comments != "agent-failures" || c.API != "https://api.example" {
		t.Fatal(c, err)
	}
	if _, err := githubapp.ReadConfig("1", "/k", "/s", "always", ""); err == nil {
		t.Fatal("always is not a comment mode")
	}
}

// -- phase 2 (test_deploy_protection.py) -----------------------------------------------------------------------------------

const repo = "jfillman/gitops-gate-api"
const dhead = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func changeBody(t *testing.T, objects []any, over map[string]any) map[string]any {
	b := map[string]any{"app": "gate-api", "env": "prod", "cluster": "hangar-prod", "repo": repo, "pr": 7, "head": dhead,
		"proposer": "user:dana", "owner": "group:default/team-gate", "treeDigest": strings.Repeat("c", 64),
		"paths": []any{"hangar-prod/prod/release.yaml"}, "linesChanged": 4, "objects": objects,
		"checks": map[string]any{"ci": "pass", "provenance": "not-agent", "render": "ok"}}
	for k, v := range over {
		b[k] = v
	}
	return decode(t, b)
}

func rollout(field string, images ...string) []any {
	return []any{map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Rollout", "namespace": "app-gate-api-prod", "name": "gate-api",
		"op": "changed", "fields": []any{field}, "images": append([]string{}, images...), "digest": strings.Repeat("d", 64)}}
}

var imageBump = rollout("/spec/template/spec/containers/0/image", "ghcr.io/jfillman/flight/gate-api@sha256:"+strings.Repeat("e", 64))
var replicas = rollout("/spec/replicas")

func (e *env) register(t *testing.T, objects []any, over map[string]any) *gate.Change {
	c, err := e.gate.Register(context.Background(), ci, changeBody(t, objects, over))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fakeGitHub) callback(r string) string {
	return f.srv.URL + "/repos/" + r + "/actions/runs/555/deployment_protection_rule"
}

func depEvent(t *testing.T, f *fakeGitHub, environment, sha, callback string) map[string]any {
	if callback == "" {
		callback = f.callback(repo)
	}
	return decode(t, map[string]any{"action": "requested", "environment": environment, "event": "push", "deployment": map[string]any{"sha": sha},
		"deployment_callback_url": callback, "repository": map[string]any{"full_name": repo}, "installation": map[string]any{"id": 9}})
}

func answers(t *testing.T) func(out []any, err error) []githubapp.Answer {
	return func(out []any, err error) []githubapp.Answer {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		var as []githubapp.Answer
		for _, x := range out {
			as = append(as, x.(githubapp.Answer))
		}
		return as
	}
}

func ans(s string) *string { return &s }

func TestTheEventIsWantedAndTheTokenAsksForDeploymentsOnly(t *testing.T) {
	e := newEnv(t)
	f := newFake(t, "alice", nil, head)
	a := e.app(t, f, "off")
	if !githubapp.Wanted("deployment_protection_rule", map[string]any{"action": "requested"}) {
		t.Fatal("not wanted")
	}
	e.register(t, imageBump, nil)
	answers(t)(a.Handle(context.Background(), "deployment_protection_rule", depEvent(t, f, "prod", dhead, "")))
	want := map[string]any{"repositories": []any{"gitops-gate-api"}, "permissions": map[string]any{"deployments": "write", "actions": "read", "metadata": "read"}}
	if !reflect.DeepEqual(f.tokens[0], want) {
		t.Fatal(f.tokens[0])
	}
}

func TestAClearedChangeApprovesTheDeploymentAndRecordsIt(t *testing.T) {
	e := newEnv(t)
	f := newFake(t, "alice", nil, head)
	e.register(t, imageBump, nil) // tier 1: cleared by policy
	out := answers(t)(e.app(t, f, "off").Handle(context.Background(), "deployment_protection_rule", depEvent(t, f, "Prod", dhead, "")))
	if !reflect.DeepEqual(out, []githubapp.Answer{{555, "Prod", ans("approved")}}) {
		t.Fatal(out)
	}
	rv := f.reviews[0]
	if rv.path != "/repos/"+repo+"/actions/runs/555/deployment_protection_rule" || rv.body["state"] != "approved" || rv.body["environment_name"] != "Prod" ||
		!strings.Contains(rv.body["comment"].(string), "Cleared by policy") {
		t.Fatal(rv)
	}
	recs := e.records(t, "")
	tail := recs[len(recs)-2:]
	if tail[0]["tool"] != "deploy.request" || tail[0]["principal"] != "app:9" || tail[1]["tool"] != "deploy.answer" || tail[1]["principal"] != "app:9" {
		t.Fatal(tail)
	}
	if u, _ := e.gate.UndeliveredDeployments(context.Background()); len(u) != 0 {
		t.Fatal(u)
	}
}

func TestAnUnregisteredCommitIsRejected(t *testing.T) {
	e := newEnv(t)
	f := newFake(t, "alice", nil, head)
	answers(t)(e.app(t, f, "off").Handle(context.Background(), "deployment_protection_rule", depEvent(t, f, "prod", strings.Repeat("f", 40), "")))
	b := f.reviews[0].body
	if b["state"] != "rejected" || !strings.Contains(b["comment"].(string), "clearance register") {
		t.Fatal(b)
	}
	recs := e.records(t, "deploy.request")
	r := recs[len(recs)-1]
	if r["decision"] != "deny" || r["rule"] != "DG-UNREGISTERED" || r["principal"] != "app:9" {
		t.Fatal(r)
	}
}

func TestAnotherEnvironmentDoesNotMatch(t *testing.T) {
	e := newEnv(t)
	f := newFake(t, "alice", nil, head)
	e.register(t, imageBump, nil)
	answers(t)(e.app(t, f, "off").Handle(context.Background(), "deployment_protection_rule", depEvent(t, f, "staging", dhead, "")))
	if f.reviews[0].body["state"] != "rejected" {
		t.Fatal(f.reviews)
	}
}

func TestAHeldChangeKeepsTheDeploymentWaitingUntilPeopleClearIt(t *testing.T) {
	e := newEnv(t)
	f := newFake(t, "alice", nil, head)
	a := e.app(t, f, "off")
	cid := e.register(t, replicas, nil).ID // tier 2: holds for the owner group
	out := answers(t)(a.Handle(context.Background(), "deployment_protection_rule", depEvent(t, f, "prod", dhead, "")))
	if !reflect.DeepEqual(out, []githubapp.Answer{{555, "prod", nil}}) {
		t.Fatal(out)
	}
	b := f.reviews[0].body
	if _, ok := b["state"]; ok || !strings.Contains(b["comment"].(string), "Held for people") {
		t.Fatal(b) // a status report, the run keeps waiting
	}
	poked := 0
	e.gate.OnAnswered = append(e.gate.OnAnswered, func() { poked++ })
	if _, err := e.gate.Clear(context.Background(), erin, cid, ""); err != nil {
		t.Fatal(err)
	}
	u, _ := e.gate.UndeliveredDeployments(context.Background())
	if poked == 0 || *u[0].Answer != "approved" {
		t.Fatal(poked, u)
	}
	if out := answers(t)(a.DeliverAnswers(context.Background())); !reflect.DeepEqual(out, []githubapp.Answer{{555, "prod", ans("approved")}}) {
		t.Fatal(out)
	}
	if f.reviews[len(f.reviews)-1].body["state"] != "approved" {
		t.Fatal(f.reviews)
	}
	if u, _ := e.gate.UndeliveredDeployments(context.Background()); len(u) != 0 {
		t.Fatal(u)
	}
}

func TestADeniedChangeRejectsTheWaitingDeployment(t *testing.T) {
	e := newEnv(t)
	f := newFake(t, "alice", nil, head)
	a := e.app(t, f, "off")
	cid := e.register(t, replicas, nil).ID
	answers(t)(a.Handle(context.Background(), "deployment_protection_rule", depEvent(t, f, "prod", dhead, "")))
	if _, err := e.gate.Deny(context.Background(), erin, cid, "not this week", ""); err != nil {
		t.Fatal(err)
	}
	answers(t)(a.DeliverAnswers(context.Background()))
	last := f.reviews[len(f.reviews)-1].body
	if last["state"] != "rejected" || !strings.Contains(last["comment"].(string), "not this week") {
		t.Fatal(last)
	}
}

func TestExpiryRejectsAndAFailedDeliveryIsRetried(t *testing.T) {
	e := newEnv(t)
	f := newFake(t, "alice", nil, head)
	f.failRev = true
	a := e.app(t, f, "off")
	e.register(t, replicas, nil)
	answers(t)(a.Handle(context.Background(), "deployment_protection_rule", depEvent(t, f, "prod", dhead, "")))
	*e.clk = e.clk.Add(8 * 24 * time.Hour)
	if _, err := e.gate.Expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	u, _ := e.gate.UndeliveredDeployments(context.Background())
	if out := answers(t)(a.DeliverAnswers(context.Background())); len(out) != 0 || *u[0].Answer != "rejected" {
		t.Fatal(out, u)
	}
	f.mu.Lock()
	f.failRev = false
	f.mu.Unlock()
	if out := answers(t)(a.DeliverAnswers(context.Background())); !reflect.DeepEqual(out, []githubapp.Answer{{555, "prod", ans("rejected")}}) {
		t.Fatal(out)
	}
}

func TestARepeatedRequestIsOneEntryAndAForeignCallbackIsIgnored(t *testing.T) {
	e := newEnv(t)
	f := newFake(t, "alice", nil, head)
	a := e.app(t, f, "off")
	cid := e.register(t, replicas, nil).ID
	answers(t)(a.Handle(context.Background(), "deployment_protection_rule", depEvent(t, f, "prod", dhead, "")))
	answers(t)(a.Handle(context.Background(), "deployment_protection_rule", depEvent(t, f, "prod", dhead, "")))
	row, _ := e.st.Change(context.Background(), cid)
	c, _ := gate.FromRecord(row.Record)
	if len(c.Deployments) != 1 {
		t.Fatal(c.Deployments)
	}
	before := len(f.reviews)
	for _, cb := range []string{"https://evil.example/repos/x/y/actions/runs/1/deployment_protection_rule", f.callback("other/repo"),
		f.callback(repo) + "\n", f.srv.URL + "/repos/" + repo + "/actions/runs/555/deployment_protection_rule/../../x"} {
		if out := answers(t)(a.Handle(context.Background(), "deployment_protection_rule", depEvent(t, f, "prod", dhead, cb))); len(out) != 0 {
			t.Fatal(cb, out)
		}
	}
	if len(f.reviews) != before {
		t.Fatal("a review went to a foreign callback")
	}
}

func TestAPushDeployRegistersWithoutAPr(t *testing.T) {
	req, err := gate.ParseRequest(changeBody(t, []any{}, map[string]any{"pr": 0}))
	if err != nil || req.PR != 0 {
		t.Fatal(req, err)
	}
}

func decodeForFuzz(b []byte) (map[string]any, error) {
	v, err := pycompat.Decode(strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not an object")
	}
	return m, nil
}
