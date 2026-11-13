package personcli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// memStore is the keychain's in-memory fake.
type memStore struct {
	mu  sync.Mutex
	st  *Stored
	err error // returned by Set (a machine with no keychain)
}

func (m *memStore) Get() (Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return Stored{}, ErrNoToken
	}
	return *m.st, nil
}
func (m *memStore) Set(s Stored) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.st = &s
	return nil
}
func (m *memStore) Delete() error { m.mu.Lock(); defer m.mu.Unlock(); m.st = nil; return nil }

// jwt is an unsigned test token (the CLI does not verify signatures; the api does).
func jwt(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256"}`)) + "." + enc(b) + "." + enc([]byte("sig"))
}

func personToken(iss string, exp, iat time.Time) string {
	return jwt(map[string]any{"iss": iss, "aud": "clearance", "sub": "abc", "preferred_username": "erin",
		"exp": exp.Unix(), "iat": iat.Unix()})
}

type harness struct {
	t     *testing.T
	env   *Env
	store *memStore
	out   *bytes.Buffer
	errw  *bytes.Buffer
	now   time.Time
}

func newHarness(t *testing.T, apiURL string) *harness {
	t.Helper()
	h := &harness{t: t, store: &memStore{}, out: &bytes.Buffer{}, errw: &bytes.Buffer{}, now: t0}
	env := map[string]string{"CLEARANCE_API_URL": apiURL}
	h.env = &Env{Stdin: strings.NewReader(""), Stdout: h.out, Stderr: h.errw, Store: h.store, HTTP: NewHTTP(5 * time.Second),
		StreamHTTP: NewHTTP(0), Now: func() time.Time { return h.now },
		Sleep:  func(ctx context.Context, d time.Duration) error { return ctx.Err() },
		Getenv: func(k string) string { return env[k] }, Version: "test", Prog: "clearance"}
	h.signIn(personToken("https://idp.example", t0.Add(time.Hour), t0))
	return h
}

func (h *harness) setenv(k, v string) {
	old := h.env.Getenv
	h.env.Getenv = func(x string) string {
		if x == k {
			return v
		}
		return old(x)
	}
}

func (h *harness) signIn(tok string) { _ = h.store.Set(Stored{IDToken: tok, SavedAt: h.now.Unix()}) }

func (h *harness) run(fn func(*Env, context.Context, []string) int, args ...string) (int, string, string) {
	h.out.Reset()
	h.errw.Reset()
	code := fn(h.env, context.Background(), args)
	return code, h.out.String(), h.errw.String()
}

// fakeAPI records the requests it saw and serves canned answers.
type fakeAPI struct {
	mu     sync.Mutex
	seen   []string // "path?query"
	tokens []string
	routes map[string]func(w http.ResponseWriter, r *http.Request)
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.RequestURI())
	f.tokens = append(f.tokens, r.Header.Get("Authorization"))
	f.mu.Unlock()
	if h, ok := f.routes[r.URL.Path]; ok {
		h(w, r)
		return
	}
	jsonAnswer(w, 404, map[string]any{"error": "not found"})
}

func (f *fakeAPI) last() string { f.mu.Lock(); defer f.mu.Unlock(); return f.seen[len(f.seen)-1] }

func jsonAnswer(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func serve(t *testing.T, routes map[string]func(http.ResponseWriter, *http.Request)) (*fakeAPI, string) {
	t.Helper()
	f := &fakeAPI{routes: routes}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv.URL
}

func ok(v any) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { jsonAnswer(w, 200, v) }
}

func status(code int, msg string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { jsonAnswer(w, code, map[string]any{"error": msg}) }
}

var change1 = map[string]any{"id": "c-1", "app": "gate-api", "env": "prod", "cluster": "hangar-prod", "tier": 3, "state": "holding",
	"proposer": "user:alice", "proposer_kind": "person", "owner": "group:default/team-gate", "updated_at": "2026-11-01T10:00:00+00:00",
	"expires_at": "2026-11-08T10:00:00+00:00", "target": "jfillman/gitops#7@1111111", "head": "1111111", "tree_digest": "sha256:abc",
	"reasons":     []any{map[string]any{"subject": "Rollout/gate-api", "rule": "kind:Rollout", "tier": 3}},
	"requirement": map[string]any{"owner": 1, "outside": 1, "ownerGroup": "group:default/team-gate", "outsideGroups": []any{"group:default/platform"}},
	"approvals":   []any{map[string]any{"person": "user:erin", "role": "owner", "at": "2026-11-01T11:00:00+00:00", "via": "delegate:tower"}},
	"subject":     map[string]any{"kind": "manifest-tree", "name": "gate-api", "digests": map[string]any{"sha256": "abc"}},
	"outcome":     map[string]any{"seq": 9, "applied": true, "matched": true, "at": "2026-11-01T12:00:00+00:00"},
	"attestation": map[string]any{"digest": "sha256:dd", "backend": "keyless", "rekor_log_index": 42, "outcome_seq": 9, "record_seq": 10, "created_at": "2026-11-01T12:01:00+00:00"}}

// ---- config -------------------------------------------------------------------------------------------------------

func TestConfigPrecedenceFlagsEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("url: https://core.file\napi_url: https://api.file\noidc_issuer: https://idp.file\noidc_client_id: from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	c, err := LoadConfig(get, path, Flags{})
	if err != nil || c.APIURL != "https://api.file" || c.ClientID != "from-file" || c.Scopes != DefaultScopes {
		t.Fatalf("file: %+v %v", c, err)
	}
	env["CLEARANCE_API_URL"], env["CLEARANCE_OIDC_CLIENT_ID"] = "https://api.env/", "from-env"
	c, _ = LoadConfig(get, path, Flags{})
	if c.APIURL != "https://api.env" || c.ClientID != "from-env" || c.Issuer != "https://idp.file" {
		t.Fatalf("env over file: %+v", c)
	}
	c, _ = LoadConfig(get, path, Flags{APIURL: "https://api.flag"})
	if c.APIURL != "https://api.flag" {
		t.Fatalf("flag over env: %+v", c)
	}
	// every variable the docs name
	env = map[string]string{"CLEARANCE_URL": "https://c.env", "CLEARANCE_OIDC_ISSUER": "https://i.env"}
	if c, _ = LoadConfig(get, "", Flags{}); c.URL != "https://c.env" || c.Issuer != "https://i.env" {
		t.Fatalf("env: %+v", c)
	}
}

func TestConfigFileRefusesATokenAndBadURLs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	_ = os.WriteFile(path, []byte("api_url: https://api\ntoken: eyJ.secret.x\n"), 0o600)
	_, err := LoadConfig(func(string) string { return "" }, path, Flags{})
	if err == nil || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "never a token") {
		t.Fatalf("a token key must be refused without echoing it: %v", err)
	}
	for _, bad := range []string{"http://api.example.com", "ftp://x", "https://user:pw@x", "https://x?y=1", "nope"} {
		if _, err := LoadConfig(func(k string) string {
			if k == "CLEARANCE_API_URL" {
				return bad
			}
			return ""
		}, "", Flags{}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := LoadConfig(func(k string) string {
		if k == "CLEARANCE_API_URL" {
			return "http://127.0.0.1:8080"
		}
		return ""
	}, "", Flags{}); err != nil {
		t.Errorf("loopback http refused: %v", err)
	}
}

// ---- sign-in ------------------------------------------------------------------------------------------------------

type fakeIDP struct {
	srv       *httptest.Server
	polls     int
	pending   int    // authorization_pending answers before the token
	finalErr  string // an error to end with instead of a token
	deviceReq url.Values
	tokenReq  []url.Values
	claims    map[string]any
	noDevice  bool
	slowDown  bool
}

func newIDP(t *testing.T) *fakeIDP {
	f := &fakeIDP{pending: 2}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		d := map[string]any{"issuer": f.srv.URL, "token_endpoint": f.srv.URL + "/token"}
		if !f.noDevice {
			d["device_authorization_endpoint"] = f.srv.URL + "/device/code"
		}
		jsonAnswer(w, 200, d)
	})
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.deviceReq = r.PostForm
		jsonAnswer(w, 200, map[string]any{"device_code": "dev-123", "user_code": "ABCD-EFGH", "verification_uri": f.srv.URL + "/device",
			"verification_uri_complete": f.srv.URL + "/device?user_code=ABCD-EFGH", "expires_in": 600, "interval": 1})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.tokenReq = append(f.tokenReq, r.PostForm)
		f.polls++
		switch {
		case f.slowDown && f.polls == 1:
			jsonAnswer(w, 400, map[string]any{"error": "slow_down"})
		case f.polls <= f.pending:
			jsonAnswer(w, 400, map[string]any{"error": "authorization_pending"})
		case f.finalErr != "":
			jsonAnswer(w, 400, map[string]any{"error": f.finalErr})
		default:
			cl := f.claims
			if cl == nil {
				cl = map[string]any{"iss": f.srv.URL, "aud": "clearance", "sub": "s", "preferred_username": "erin",
					"exp": t0.Add(time.Hour).Unix(), "iat": t0.Unix()}
			}
			jsonAnswer(w, 200, map[string]any{"id_token": jwt(cl), "access_token": "at-secret", "refresh_token": "rt-secret", "token_type": "bearer"})
		}
	})
	return f
}

func loginHarness(t *testing.T, idp *fakeIDP) *harness {
	h := newHarness(t, "https://api.example")
	_ = h.store.Delete()
	h.setenv("CLEARANCE_OIDC_ISSUER", idp.srv.URL)
	h.setenv("CLEARANCE_OIDC_CLIENT_ID", "clearance")
	return h
}

func TestLoginDeviceFlowStoresOnlyTheIDToken(t *testing.T) {
	idp := newIDP(t)
	idp.slowDown = true
	h := loginHarness(t, idp)
	code, out, errw := h.run((*Env).Login)
	if code != 0 {
		t.Fatalf("login: %d %s", code, errw)
	}
	if !strings.Contains(errw, "ABCD-EFGH") || !strings.Contains(errw, "/device") {
		t.Errorf("the user code and URL are shown: %q", errw)
	}
	if !strings.Contains(out, "user:erin") || !strings.Contains(out, "at most 1 hour") {
		t.Errorf("out: %q", out)
	}
	if idp.deviceReq.Get("client_id") != "clearance" || idp.deviceReq.Get("scope") != DefaultScopes {
		t.Errorf("device request: %v", idp.deviceReq)
	}
	for _, tr := range idp.tokenReq {
		if tr.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || tr.Get("device_code") != "dev-123" || tr.Get("client_secret") != "" {
			t.Errorf("token request: %v (a public client sends no secret)", tr)
		}
	}
	if idp.polls != 3 { // slow_down, one pending, the token
		t.Errorf("polls: %d", idp.polls)
	}
	st, err := h.store.Get()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(st)
	if strings.Contains(string(b), "rt-secret") || strings.Contains(string(b), "at-secret") || strings.Contains(out+errw, "rt-secret") {
		t.Errorf("only the ID token is kept: %s", b)
	}
	if c, _ := ParseClaims(st.IDToken); c.Username != "erin" {
		t.Errorf("stored: %+v", c)
	}
}

func TestLoginFailures(t *testing.T) {
	cases := []struct {
		name string
		set  func(*fakeIDP, *harness)
		want string
	}{
		{"denied", func(i *fakeIDP, _ *harness) { i.finalErr = "access_denied" }, "denied"},
		{"expired", func(i *fakeIDP, _ *harness) { i.finalErr = "expired_token" }, "expired"},
		{"other", func(i *fakeIDP, _ *harness) { i.finalErr = "invalid_client" }, "invalid_client"},
		{"no device flow", func(i *fakeIDP, _ *harness) { i.noDevice = true }, "device authorization"},
		{"wrong issuer", func(i *fakeIDP, _ *harness) {
			i.claims = map[string]any{"iss": "https://evil", "aud": "clearance", "exp": t0.Add(time.Hour).Unix()}
		}, "issuer"},
		{"wrong audience", func(i *fakeIDP, _ *harness) {
			i.claims = map[string]any{"iss": i.srv.URL, "aud": "other", "exp": t0.Add(time.Hour).Unix()}
		}, "not for client"},
		{"already expired", func(i *fakeIDP, _ *harness) {
			i.claims = map[string]any{"iss": i.srv.URL, "aud": "clearance", "exp": t0.Add(-time.Minute).Unix()}
		}, "expired"},
		{"no keychain", func(_ *fakeIDP, h *harness) { h.store.err = fmt.Errorf("%w: dbus", ErrNoKeychain) }, "never written to a file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idp := newIDP(t)
			h := loginHarness(t, idp)
			c.set(idp, h)
			code, _, errw := h.run((*Env).Login)
			if code == 0 || !strings.Contains(errw, c.want) {
				t.Errorf("%s: code %d, %q (want %q)", c.name, code, errw, c.want)
			}
			if _, err := h.store.Get(); err == nil {
				t.Errorf("a failed login stored a token")
			}
		})
	}
	h := loginHarness(t, newIDP(t))
	h.setenv("CLEARANCE_OIDC_ISSUER", "")
	if code, _, errw := h.run((*Env).Login); code != ExitUsage || !strings.Contains(errw, "CLEARANCE_OIDC_ISSUER") {
		t.Errorf("no issuer: %d %q", code, errw)
	}
}

func TestLoginCodeExpiryByTheClock(t *testing.T) {
	idp := newIDP(t)
	idp.pending = 1 << 20
	h := loginHarness(t, idp)
	// each sleep moves the clock 4 minutes: the 10-minute code runs out
	h.env.Sleep = func(ctx context.Context, d time.Duration) error { h.now = h.now.Add(4 * time.Minute); return ctx.Err() }
	if code, _, errw := h.run((*Env).Login); code == 0 || !strings.Contains(errw, "expired") {
		t.Errorf("%d %q", code, errw)
	}
}

// ---- token handling -----------------------------------------------------------------------------------------------

func TestTokenRules(t *testing.T) {
	f, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/whoami": ok(map[string]any{"principal": "user:erin", "person": "user:erin",
		"roles": []any{"person"}, "admin": false, "groups": []any{"group:default/team-gate"}, "apps": []any{}})})
	h := newHarness(t, api)

	// the stored token is sent as the person's own bearer
	code, out, errw := h.run((*Env).Whoami, "-o", "table")
	if code != 0 || !strings.Contains(out, "user:erin") || !strings.Contains(out, "token valid until") {
		t.Fatalf("whoami: %d %q %q", code, out, errw)
	}
	tok, _ := h.store.Get()
	if f.tokens[0] != "Bearer "+tok.IDToken {
		t.Errorf("bearer: %q", f.tokens[0])
	}
	if strings.Contains(out+errw, tok.IDToken) {
		t.Errorf("the token is never printed")
	}

	// capped at one hour: exp is a day away but it was saved 61 minutes ago
	h.signIn(personToken("https://idp.example", t0.Add(24*time.Hour), t0.Add(24*time.Hour)))
	st, _ := h.store.Get()
	st.SavedAt = t0.Add(-61 * time.Minute).Unix()
	_ = h.store.Set(st)
	if code, _, errw = h.run((*Env).Whoami); code != ExitUnauthorized || !strings.Contains(errw, "clearance login") {
		t.Errorf("a token older than an hour: %d %q", code, errw)
	}
	if _, err := h.store.Get(); err == nil {
		t.Errorf("the expired token is removed from the keychain")
	}

	// an expired exp
	h.signIn(personToken("https://idp.example", t0.Add(-time.Second), t0.Add(-time.Hour+time.Minute)))
	if code, _, errw = h.run((*Env).Whoami); code != ExitUnauthorized || !strings.Contains(errw, "expired") {
		t.Errorf("exp: %d %q", code, errw)
	}

	// not signed in
	if code, _, errw = h.run((*Env).Whoami); code != ExitUnauthorized || !strings.Contains(errw, "clearance login") {
		t.Errorf("signed out: %d %q", code, errw)
	}
}

func TestTokenStdinStaysInMemory(t *testing.T) {
	f, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/whoami": ok(map[string]any{"principal": "user:erin", "person": "user:erin", "roles": []any{}, "groups": []any{}, "apps": []any{}})})
	h := newHarness(t, api)
	_ = h.store.Delete()
	tok := personToken("https://idp.example", t0.Add(30*time.Minute), t0)
	h.env.Stdin = strings.NewReader(tok + "\n")
	if code, _, errw := h.run((*Env).Whoami, "--token-stdin"); code != 0 {
		t.Fatalf("%d %s", code, errw)
	}
	if f.tokens[0] != "Bearer "+tok {
		t.Errorf("bearer %q", f.tokens[0])
	}
	if _, err := h.store.Get(); err == nil {
		t.Errorf("--token-stdin must not write the keychain")
	}
	// a token that has outlived its hour (iat) is refused even if exp is later
	h.env.Stdin = strings.NewReader(personToken("https://idp.example", t0.Add(5*time.Hour), t0.Add(-2*time.Hour)))
	if code, _, errw := h.run((*Env).Whoami, "--token-stdin"); code != ExitUnauthorized || !strings.Contains(errw, "expired") {
		t.Errorf("iat cap: %d %q", code, errw)
	}
	for _, bad := range []string{"", "two tokens here", strings.Repeat("a", 17<<10)} {
		h.env.Stdin = strings.NewReader(bad)
		if code, _, _ := h.run((*Env).Whoami, "--token-stdin"); code != ExitUsage {
			t.Errorf("stdin %.10q: %d", bad, code)
		}
	}
	// CLEARANCE_TOKEN is for automation
	h2 := newHarness(t, api)
	_ = h2.store.Delete()
	h2.setenv("CLEARANCE_TOKEN", tok)
	if code, _, _ := h2.run((*Env).Whoami); code != 0 {
		t.Errorf("CLEARANCE_TOKEN: %d", code)
	}
}

func TestLogout(t *testing.T) {
	h := newHarness(t, "https://api.example")
	if code, out, _ := h.run((*Env).Logout); code != 0 || !strings.Contains(out, "signed out") {
		t.Errorf("%d %q", code, out)
	}
	if _, err := h.store.Get(); err == nil {
		t.Error("still stored")
	}
	if code, _, _ := h.run((*Env).Logout); code != 0 {
		t.Error("logout twice is fine")
	}
}

// ---- reads --------------------------------------------------------------------------------------------------------

func TestWhoamiFormatsAndAPIGaps(t *testing.T) {
	who := map[string]any{"principal": "user:erin", "person": "user:erin", "roles": []any{"person"}, "admin": true,
		"groups": []any{"group:default/team-gate"}, "apps": []any{"gate-api"}, "via": nil}
	_, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/whoami": ok(who)})
	h := newHarness(t, api)
	code, out, _ := h.run((*Env).Whoami, "-o", "table")
	if code != 0 || !strings.Contains(out, "group:default/team-gate") || !strings.Contains(out, "admin") {
		t.Errorf("table: %q", out)
	}
	if _, out, _ = h.run((*Env).Whoami, "-o", "json"); !strings.Contains(out, "\"principal\": \"user:erin\"") {
		t.Errorf("json: %q", out)
	}
	if _, out, _ = h.run((*Env).Whoami, "-o", "jsonl"); strings.Count(out, "\n") != 1 || !strings.HasPrefix(out, "{") {
		t.Errorf("jsonl: %q", out)
	}
	if _, out, _ = h.run((*Env).Whoami, "-o", "yaml"); !strings.Contains(out, "principal: user:erin") {
		t.Errorf("yaml: %q", out)
	}
	if code, _, _ = h.run((*Env).Whoami, "-o", "xml"); code != ExitUsage {
		t.Errorf("bad format: %d", code)
	}
	// default format: table on a terminal, json otherwise
	h.env.IsTTY = true
	if _, out, _ = h.run((*Env).Whoami); !strings.Contains(out, "principal  ") {
		t.Errorf("tty default: %q", out)
	}
	h.env.IsTTY = false
	if _, out, _ = h.run((*Env).Whoami); !strings.HasPrefix(out, "{") {
		t.Errorf("pipe default: %q", out)
	}
	// an older api
	_, old := serve(t, nil)
	h2 := newHarness(t, old)
	if code, _, errw := h2.run((*Env).Whoami); code != ExitNotFound || !strings.Contains(errw, "predates") {
		t.Errorf("old api: %d %q", code, errw)
	}
	// no api configured
	h3 := newHarness(t, "")
	if code, _, errw := h3.run((*Env).Whoami); code != ExitUsage || !strings.Contains(errw, "CLEARANCE_API_URL") {
		t.Errorf("no url: %d %q", code, errw)
	}
}

func TestErrorsMapToMessagesAndExitCodes(t *testing.T) {
	for _, c := range []struct {
		status int
		code   int
		want   string
	}{{401, ExitUnauthorized, "run `clearance login`"}, {403, ExitForbidden, "forbidden: nope"}, {404, ExitNotFound, "not found: nope"},
		{400, ExitError, "nope"}, {429, ExitUnavailable, "rate limited"}, {503, ExitUnavailable, "unavailable"}} {
		_, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/clearances": status(c.status, "nope")})
		h := newHarness(t, api)
		code, _, errw := h.run((*Env).ChangesList)
		if code != c.code || !strings.Contains(errw, c.want) {
			t.Errorf("HTTP %d: %d %q", c.status, code, errw)
		}
	}
	h := newHarness(t, "http://127.0.0.1:1") // nothing listens
	if code, _, errw := h.run((*Env).ChangesList); code != ExitUnavailable || !strings.Contains(errw, "cannot reach clearance-api") {
		t.Errorf("unreachable: %d %q", code, errw)
	}
	// a redirect is not followed (the token must not travel)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://elsewhere.example/", 302) }))
	defer redir.Close()
	h = newHarness(t, redir.URL)
	if code, _, _ := h.run((*Env).ChangesList); code == 0 {
		t.Error("redirect followed")
	}
}

func TestInboxAsksForAwaitingMe(t *testing.T) {
	f, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/clearances": ok(map[string]any{"items": []any{change1}, "next": nil})})
	h := newHarness(t, api)
	code, out, errw := h.run((*Env).Awaiting, "-o", "table")
	if code != 0 {
		t.Fatalf("%d %s", code, errw)
	}
	if !strings.Contains(f.last(), "awaiting=me") || !strings.Contains(f.last(), "limit=50") {
		t.Errorf("request: %s", f.last())
	}
	for _, want := range []string{"ID", "NEEDS", "c-1", "gate-api", "owner 1/1, outside 0/1", "2026-11-01 10:00:00"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	// empty
	_, api2 := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/clearances": ok(map[string]any{"items": []any{}, "next": nil})})
	h2 := newHarness(t, api2)
	if _, out, _ = h2.run((*Env).Awaiting, "-o", "table"); !strings.Contains(out, "nothing is waiting on you") {
		t.Errorf("empty: %q", out)
	}
	if _, out, _ = h2.run((*Env).Awaiting, "-o", "json"); !strings.Contains(out, "\"items\": []") {
		t.Errorf("empty json: %q", out)
	}
	// an older api refuses the parameter
	_, old := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/clearances": status(400, `unknown query parameter "awaiting"`)})
	h3 := newHarness(t, old)
	if code, _, errw := h3.run((*Env).Awaiting); code == 0 || !strings.Contains(errw, "predates") {
		t.Errorf("old api: %d %q", code, errw)
	}
	if code, _, _ := h.run((*Env).Awaiting, "--limit", "999"); code != ExitUsage {
		t.Errorf("limit: %d", code)
	}
}

func TestChangesListFiltersPagingAndFormats(t *testing.T) {
	var pages int
	f, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/clearances": func(w http.ResponseWriter, r *http.Request) {
		pages++
		if r.URL.Query().Get("after") == "" {
			jsonAnswer(w, 200, map[string]any{"items": []any{change1}, "next": "2026-11-01T10:00:00+00:00"})
			return
		}
		c2 := map[string]any{"id": "c-2", "app": "other", "env": "prod", "tier": 0, "state": "cleared", "proposer": "user:bob", "updated_at": "2026-10-31T10:00:00+00:00"}
		jsonAnswer(w, 200, map[string]any{"items": []any{c2}, "next": nil})
	}})
	h := newHarness(t, api)
	code, out, errw := h.run((*Env).ChangesList, "--app", "gate-api", "--env", "prod", "--state", "holding", "--tier", "3", "--since", "24h", "-o", "table")
	if code != 0 {
		t.Fatalf("%d %s", code, errw)
	}
	u, _ := url.Parse(f.last())
	q := u.Query()
	if q.Get("app") != "gate-api" || q.Get("env") != "prod" || q.Get("state") != "holding" || q.Get("tier") != "3" || q.Get("since") != "2026-11-12T12:00:00+00:00" {
		t.Errorf("query: %v", q)
	}
	if !strings.Contains(out, "c-1") || strings.Contains(out, "c-2") {
		t.Errorf("one page: %s", out)
	}
	pages = 0
	_, out, _ = h.run((*Env).ChangesList, "--all", "-o", "jsonl")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if pages != 2 || len(lines) != 2 || !strings.Contains(lines[0], `"c-1"`) || !strings.Contains(lines[1], `"c-2"`) {
		t.Errorf("--all: %d pages %v", pages, lines)
	}
	if _, out, _ = h.run((*Env).ChangesList, "-o", "yaml"); !strings.Contains(out, "items:") || !strings.Contains(out, "id: c-1") {
		t.Errorf("yaml: %s", out)
	}
	for _, bad := range []string{"yesterday", "99x"} {
		if code, _, errw := h.run((*Env).ChangesList, "--since", bad); code != ExitUsage || !strings.Contains(errw, "--since") {
			t.Errorf("since %q: %d %q", bad, code, errw)
		}
	}
	if code, _, _ := h.run((*Env).ChangesList, "stray"); code != ExitUsage {
		t.Errorf("stray positional: %d", code)
	}
}

func TestChangesShow(t *testing.T) {
	f, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/clearances/c-1": ok(change1), "/v1/clearances/nope": status(404, "no such change")})
	h := newHarness(t, api)
	code, out, errw := h.run((*Env).ChangesShow, "c-1", "-o", "table")
	if code != 0 {
		t.Fatalf("%d %s", code, errw)
	}
	for _, want := range []string{"why this tier", "tier 3  kind:Rollout", "needs   owner 1/1, outside 0/1", "group:default/platform",
		"owner    user:erin", "via delegate:tower", "binds to", "sha256:abc", "digest sha256", "outcome  applied=true matched=true", "Rekor #42", "attest verify c-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if f.last() != "/v1/clearances/c-1" {
		t.Errorf("path %s", f.last())
	}
	// flags after the id work too
	if code, out, _ = h.run((*Env).ChangesShow, "c-1", "-o", "json"); code != 0 || !strings.Contains(out, `"tier": 3`) {
		t.Errorf("json after id: %d %q", code, out)
	}
	if code, _, errw = h.run((*Env).ChangesShow, "nope"); code != ExitNotFound || !strings.Contains(errw, "no such change") {
		t.Errorf("404: %d %q", code, errw)
	}
	if code, _, _ = h.run((*Env).ChangesShow); code != ExitUsage {
		t.Errorf("no id: %d", code)
	}
	// ids are escaped, never path-injected
	h.run((*Env).ChangesShow, "../evidence")
	if strings.Contains(f.last(), "/../") || !strings.Contains(f.last(), "%2F") {
		t.Errorf("id escaping: %s", f.last())
	}
}

func TestChangesHistoryAndMissingRoute(t *testing.T) {
	recs := map[string]any{"items": []any{
		map[string]any{"seq": 5, "tool": "deploy.request", "ts": "2026-11-01T10:00:00Z", "principal": "ci/x", "record": map[string]any{"decision": "allow", "result": "registered"}},
		map[string]any{"seq": 7, "tool": "deploy.clear", "ts": "2026-11-01T11:00:00Z", "principal": "user:erin", "record": map[string]any{"result": "cleared"}}}, "next": nil}
	_, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/clearances/c-1/records": ok(recs), "/v1/clearances/gone/records": status(404, "no such change")})
	h := newHarness(t, api)
	code, out, errw := h.run((*Env).ChangesHistory, "c-1", "-o", "table")
	if code != 0 || !strings.Contains(out, "deploy.request") || !strings.Contains(out, "deploy.clear") || !strings.Contains(out, "user:erin") {
		t.Errorf("history: %d %q %q", code, out, errw)
	}
	if code, _, errw = h.run((*Env).ChangesHistory, "gone"); code != ExitNotFound || !strings.Contains(errw, "no such change") {
		t.Errorf("no such change: %d %q", code, errw)
	}
	_, old := serve(t, nil) // an api without the route: the router's own 404
	h2 := newHarness(t, old)
	if code, _, errw = h2.run((*Env).ChangesHistory, "c-1"); code != ExitNotFound || !strings.Contains(errw, "predates the change-history API") {
		t.Errorf("old api: %d %q", code, errw)
	}
}

func TestAttestCommands(t *testing.T) {
	bundle := map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "dsseEnvelope": map[string]any{"payload": "e30="}}
	verified := map[string]any{"verified": true, "cached": false, "mode": "keyless", "digest": "sha256:dd", "identity": "core@x", "issuer": "https://oidc", "rekor": map[string]any{"log_index": 42, "verified": true}}
	failed := map[string]any{"verified": false, "errors": []any{"signature does not verify"}}
	_, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){
		"/v1/clearances/c-1":                    ok(change1),
		"/v1/clearances/c-2":                    ok(map[string]any{"id": "c-2", "attestation": nil}),
		"/v1/clearances/c-1/attestation":        ok(bundle),
		"/v1/clearances/c-1/attestation/verify": ok(verified),
		"/v1/clearances/c-3/attestation/verify": ok(failed),
		"/v1/clearances/c-2/attestation":        status(404, "no attestation"),
		"/v1/clearances/c-4/attestation/verify": status(404, "no such change"),
	})
	h := newHarness(t, api)
	code, out, errw := h.run((*Env).AttestGet, "c-1", "-o", "table")
	if code != 0 || !strings.Contains(out, "sha256:dd") || !strings.Contains(out, "rekor log index") {
		t.Errorf("get: %d %q %q", code, out, errw)
	}
	if code, _, errw = h.run((*Env).AttestGet, "c-2"); code != ExitNotFound || !strings.Contains(errw, "no attestation yet") {
		t.Errorf("get none: %d %q", code, errw)
	}

	// download
	dir := t.TempDir()
	file := filepath.Join(dir, "b.json")
	if code, out, errw = h.run((*Env).AttestDownload, "c-1", "-o", file); code != 0 || !strings.Contains(out, "wrote") {
		t.Fatalf("download: %d %q %q", code, out, errw)
	}
	b, _ := os.ReadFile(file)
	if !strings.Contains(string(b), "dsseEnvelope") {
		t.Errorf("file: %s", b)
	}
	if code, _, errw = h.run((*Env).AttestDownload, "c-1", "-o", file); code == 0 || !strings.Contains(errw, "--force") {
		t.Errorf("overwrite must be refused: %d %q", code, errw)
	}
	if code, _, _ = h.run((*Env).AttestDownload, "c-1", "-o", file, "--force"); code != 0 {
		t.Errorf("--force: %d", code)
	}
	if code, out, _ = h.run((*Env).AttestDownload, "c-1", "-o", "-"); code != 0 || !strings.Contains(out, "mediaType") {
		t.Errorf("stdout: %d %q", code, out)
	}
	if code, _, errw = h.run((*Env).AttestDownload, "c-2", "-o", filepath.Join(dir, "x.json")); code != ExitNotFound {
		t.Errorf("none: %d %q", code, errw)
	}
	if code, _, _ = h.run((*Env).AttestDownload, "c-1"); code != ExitUsage {
		t.Errorf("no -o: %d", code)
	}

	// server-side verify
	code, out, _ = h.run((*Env).AttestVerify, "c-1", "-o", "table")
	if code != 0 || !strings.Contains(out, "verified") || !strings.Contains(out, "its trust, not yours") || !strings.Contains(out, "core@x") {
		t.Errorf("verify: %d %q", code, out)
	}
	if code, _, errw = h.run((*Env).AttestVerify, "c-3", "-o", "table"); code != 1 || !strings.Contains(errw, "signature does not verify") {
		t.Errorf("verify failed must exit 1: %d %q", code, errw)
	}
	if code, _, _ = h.run((*Env).AttestVerify, "c-3", "-o", "json"); code != 1 {
		t.Errorf("verify failed json must exit 1: %d", code)
	}
	if code, _, errw = h.run((*Env).AttestVerify, "c-4"); code != ExitNotFound || !strings.Contains(errw, "no such change") {
		t.Errorf("verify 404: %d %q", code, errw)
	}

	// offline: the bundle comes from the api, the verdict from the local code with the person's own trust
	var gotArgs []string
	var gotBundle []byte
	h.env.OfflineVerify = func(_ context.Context, bundle []byte, args []string, stdout, _ io.Writer) int {
		gotBundle, gotArgs = bundle, args
		fmt.Fprintln(stdout, "ok: keyless attestation")
		return 0
	}
	code, out, _ = h.run((*Env).AttestVerify, "c-1", "--trust-root", "tr.json", "--subject", "sha256:aa", "--subject", "sha256:bb")
	if code != 0 || !strings.Contains(out, "ok: keyless") || !strings.Contains(string(gotBundle), "dsseEnvelope") {
		t.Fatalf("offline: %d %q", code, out)
	}
	joined := strings.Join(gotArgs, " ")
	for _, want := range []string{"--trust-root tr.json", "--subject sha256:aa", "--subject sha256:bb"} {
		if !strings.Contains(joined, want) {
			t.Errorf("offline args %q lack %q", joined, want)
		}
	}
	h.env.OfflineVerify = func(context.Context, []byte, []string, io.Writer, io.Writer) int { return 1 }
	if code, _, _ = h.run((*Env).AttestVerify, "c-1", "--key", "k.pem"); code != 1 {
		t.Errorf("offline failure code: %d", code)
	}

	// an api that cannot verify
	_, old := serve(t, nil)
	h2 := newHarness(t, old)
	if code, _, errw = h2.run((*Env).AttestVerify, "c-1"); code != ExitNotFound || !strings.Contains(errw, "offline") {
		t.Errorf("old api: %d %q", code, errw)
	}
}

func TestExceptionsList(t *testing.T) {
	items := []any{
		map[string]any{"seq": 3, "ts": "2026-11-01T10:00:00Z", "tool": "deploy.exception", "app": "gate-api", "target": "gate-api-prod", "principal": "argo", "exception": map[string]any{"kind": "out-of-band"}, "destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"}},
		map[string]any{"seq": 2, "ts": "2026-11-01T09:00:00Z", "tool": "breakglass.open", "app": "flight-api", "target": "flight-api-prod", "principal": "user:erin", "destination": map[string]any{"cluster": "hangar-dev", "environment": "dev"}},
	}
	f, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/exceptions": ok(map[string]any{"items": items, "next": nil})})
	h := newHarness(t, api)
	code, out, errw := h.run((*Env).ExceptionsList, "--kind", "out-of-band", "--since", "7d", "--tool", "deploy.exception", "-o", "table")
	if code != 0 {
		t.Fatalf("%d %s", code, errw)
	}
	u, _ := url.Parse(f.last())
	if u.Query().Get("kind") != "out-of-band" || u.Query().Get("since") != "2026-11-06T12:00:00Z" || u.Query().Get("tool") != "deploy.exception" {
		t.Errorf("query %v", u.Query())
	}
	if !strings.Contains(out, "out-of-band") || !strings.Contains(out, "gate-api-prod") {
		t.Errorf("table: %s", out)
	}
	// --scope filters here, on app, target, cluster or environment
	_, out, _ = h.run((*Env).ExceptionsList, "--scope", "hangar-dev", "-o", "jsonl")
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "breakglass.open") {
		t.Errorf("scope: %q", out)
	}
	_, out, _ = h.run((*Env).ExceptionsList, "--scope", "nothing", "-o", "json")
	if !strings.Contains(out, `"items": []`) {
		t.Errorf("scope none: %q", out)
	}
}

func TestCoverageExitCodes(t *testing.T) {
	st := func(scope, state string, clean bool) map[string]any {
		return map[string]any{"scope": scope, "state": state, "clean": clean, "text": scope + " was " + state}
	}
	cases := []struct {
		name   string
		answer any
		args   []string
		code   int
	}{
		{"covered", st("aws-prod", "healthy", true), []string{"aws-prod"}, 0},
		{"healthy with exceptions seen", st("aws-prod", "healthy", false), []string{"aws-prod"}, 0},
		{"degraded", st("aws-prod", "degraded", false), []string{"aws-prod"}, 2},
		{"blind", st("aws-prod", "blind", false), []string{"aws-prod"}, 3},
		{"all scopes, worst wins", map[string]any{"scopes": []any{st("a", "healthy", true), st("b", "degraded", false)}}, nil, 2},
		{"all scopes, a blind one", map[string]any{"scopes": []any{st("a", "degraded", true), st("b", "blind", false)}}, nil, 3},
		{"no scope observed", map[string]any{"scopes": []any{}}, nil, 3},
	}
	for _, c := range cases {
		_, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/coverage": ok(c.answer)})
		h := newHarness(t, api)
		code, out, errw := h.run((*Env).Coverage, append(c.args, "-o", "table")...)
		if code != c.code {
			t.Errorf("%s: exit %d, want %d (%q %q)", c.name, code, c.code, out, errw)
		}
		if out == "" {
			t.Errorf("%s: no output", c.name)
		}
	}
	// unavailable: 503, unreachable and a missing route are 3; a refused sign-in is still 4
	for status_, want := range map[int]int{503: 3, 404: 3, 401: ExitUnauthorized, 403: ExitForbidden} {
		_, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/coverage": status(status_, "x")})
		h := newHarness(t, api)
		if code, _, _ := h.run((*Env).Coverage, "scope"); code != want {
			t.Errorf("HTTP %d: exit %d, want %d", status_, code, want)
		}
	}
	if code, _, _ := newHarness(t, "http://127.0.0.1:1").run((*Env).Coverage); code != 3 {
		t.Errorf("unreachable: %d", code)
	}
	f, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/coverage": ok(st("s", "healthy", true))})
	h := newHarness(t, api)
	h.run((*Env).Coverage, "s", "--from", "2026-11-01T00:00:00Z", "--to", "2026-11-02T00:00:00Z")
	if !strings.Contains(f.last(), "scope=s") || !strings.Contains(f.last(), "from=2026-11-01") {
		t.Errorf("request %s", f.last())
	}
}

func TestEvidenceQuery(t *testing.T) {
	items := []any{map[string]any{"seq": 12, "ts": "2026-11-01T10:00:00Z", "tool": "deploy.clear", "principal": "user:erin", "decision": "allow", "coverage": "authorized-and-verified", "app": "gate-api", "target": "c-1"}}
	f, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/evidence": func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "" {
			jsonAnswer(w, 200, map[string]any{"items": items, "next": 12})
			return
		}
		jsonAnswer(w, 200, map[string]any{"items": []any{}, "next": nil})
	}})
	h := newHarness(t, api)
	code, out, errw := h.run((*Env).EvidenceList, "--tool", "deploy.clear", "--app", "gate-api", "--coverage", "authorized-and-verified", "--since", "2h", "--limit", "10", "-o", "table")
	if code != 0 {
		t.Fatalf("%d %s", code, errw)
	}
	u, _ := url.Parse(f.last())
	q := u.Query()
	if q.Get("tool") != "deploy.clear" || q.Get("app") != "gate-api" || q.Get("coverage") != "authorized-and-verified" || q.Get("limit") != "10" || q.Get("since") != "2026-11-13T10:00:00Z" {
		t.Errorf("query %v", q)
	}
	if !strings.Contains(out, "SEQ") || !strings.Contains(out, "deploy.clear") || !strings.Contains(out, "authorized-and-verified") {
		t.Errorf("table: %s", out)
	}
	if code, _, _ = h.run((*Env).EvidenceList, "--all"); code != 0 {
		t.Fatal("--all")
	}
	if !strings.Contains(f.last(), "after=12") {
		t.Errorf("the numeric cursor is followed: %s", f.last())
	}
}

func sse(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(200)
	for _, e := range events {
		fmt.Fprint(w, e)
	}
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
}

func TestWatchReconnectsDedupesAndFilters(t *testing.T) {
	var mu sync.Mutex
	var lastIDs []string
	conn := 0
	_, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/stream": func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		conn++
		n := conn
		lastIDs = append(lastIDs, r.Header.Get("Last-Event-ID")+"|"+r.URL.Query().Get("after")+"|"+r.URL.Query().Get("types"))
		mu.Unlock()
		if n == 1 {
			sse(w, ": hello\n\n",
				"id: 5\nevent: clearance\ndata: {\"seq\":5,\"tool\":\"deploy.request\",\"ts\":\"2026-11-01T10:00:00Z\",\"change\":{\"id\":\"c-1\",\"app\":\"gate-api\",\"env\":\"prod\",\"tier\":3,\"state\":\"holding\"}}\n\n",
				"id: 6\nevent: clearance\ndata: {\"seq\":6,\"tool\":\"deploy.request\",\"ts\":\"2026-11-01T10:01:00Z\",\"change\":{\"id\":\"c-2\",\"app\":\"other\",\"env\":\"prod\",\"tier\":1,\"state\":\"holding\"}}\n\n")
			return // the server ends the stream (it does every 10 minutes)
		}
		// after the reconnect: seq 6 again (at-least-once), then new ones
		sse(w, "id: 6\nevent: clearance\ndata: {\"seq\":6,\"tool\":\"deploy.request\",\"change\":{\"id\":\"c-2\",\"app\":\"other\"}}\n\n",
			"id: 7\nevent: clearance\ndata: {\"seq\":7,\"tool\":\"deploy.clear\",\"ts\":\"2026-11-01T10:02:00Z\",\"change\":{\"id\":\"c-1\",\"app\":\"gate-api\",\"env\":\"prod\",\"tier\":3,\"state\":\"cleared\"}}\n\n",
			"id: 8\nevent: record\ndata: {\"seq\":8,\"tool\":\"repo.pr.open\",\"app\":\"gate-api\",\"principal\":\"user:alice\"}\n\n")
	}})
	h := newHarness(t, api)
	code, out, errw := h.run((*Env).Watch, "--app", "gate-api", "--count", "3", "-o", "jsonl", "--types", "records,clearances")
	if code != 0 {
		t.Fatalf("%d %s", code, errw)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"seq":5`) || !strings.Contains(lines[1], `"seq":7`) || !strings.Contains(lines[2], `"seq":8`) {
		t.Errorf("filtered, deduped lines: %v", lines)
	}
	if len(lastIDs) != 2 || lastIDs[0] != "||records,clearances" || lastIDs[1] != "6|6|records,clearances" {
		t.Errorf("resume with Last-Event-ID: %v", lastIDs)
	}

	// table rendering
	conn = 0
	h2 := newHarness(t, api)
	_, out, _ = h2.run((*Env).Watch, "--change", "c-1", "--count", "2", "-o", "table")
	if !strings.Contains(out, "deploy.request") || !strings.Contains(out, "c-1 gate-api/prod tier 3 cleared") {
		t.Errorf("table: %s", out)
	}
	if strings.Contains(out, "c-2") {
		t.Errorf("filtered: %s", out)
	}
}

func TestWatchAuthFailureAndExpiry(t *testing.T) {
	_, api := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/stream": status(401, "token not accepted")})
	h := newHarness(t, api)
	if code, _, errw := h.run((*Env).Watch, "--count", "1"); code != ExitUnauthorized || !strings.Contains(errw, "clearance login") {
		t.Errorf("401: %d %q", code, errw)
	}
	// the token runs out while watching: the next reconnect refuses
	h2 := newHarness(t, "")
	_, api2 := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/stream": func(w http.ResponseWriter, _ *http.Request) { sse(w, ": nothing\n\n") }})
	h2.setenv("CLEARANCE_API_URL", api2)
	h2.env.Sleep = func(ctx context.Context, d time.Duration) error { h2.now = h2.now.Add(2 * time.Hour); return ctx.Err() }
	if code, _, errw := h2.run((*Env).Watch); code != ExitUnauthorized || !strings.Contains(errw, "expired") {
		t.Errorf("expiry: %d %q", code, errw)
	}
}

func TestUsageAndHelp(t *testing.T) {
	h := newHarness(t, "https://api.example")
	if code, _, errw := h.run((*Env).ChangesShow, "-h"); code != 0 || !strings.Contains(errw, "usage: clearance changes show") {
		t.Errorf("-h: %d %q", code, errw)
	}
	if code, _, _ := h.run((*Env).Awaiting, "--nope"); code != ExitUsage {
		t.Errorf("bad flag: %d", code)
	}
	h.env.Prog = "clr"
	if _, _, errw := h.run((*Env).ChangesShow); !strings.Contains(errw, "usage: clr changes show") {
		t.Errorf("clr names itself: %q", errw)
	}
}
