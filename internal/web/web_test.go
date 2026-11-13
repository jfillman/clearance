package web

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/gate"
)

func TestSignInFlowAndCookie(t *testing.T) {
	e := newEnv(t, nil)
	// No session: the entry page sends the person to sign in; assets are public.
	if w := e.do("GET", "/changes?x=1", nil, ""); w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "/auth/login?return=") {
		t.Fatalf("index without session: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := e.do("GET", "/assets/app-abc.js", nil, ""); w.Code != 200 {
		t.Fatalf("asset: %d", w.Code)
	}
	cb, lw := e.startLogin("?return=%2Fchanges")
	q := e.idp.lastAuthRequest
	for k, want := range map[string]string{"response_type": "code", "client_id": testClientID, "code_challenge_method": "S256",
		"redirect_uri": testPublic + "/auth/callback", "scope": "openid email profile"} {
		if q.Get(k) != want {
			t.Errorf("auth request %s = %q, want %q", k, q.Get(k), want)
		}
	}
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if len(q.Get(k)) < 32 {
			t.Errorf("auth request %s too short: %q", k, q.Get(k))
		}
	}
	if q.Get("prompt") != "" || q.Get("max_age") != "" {
		t.Error("an ordinary login must not force reauthentication")
	}
	if c := lw.Result().Cookies(); len(c) != 1 || c[0].Name != loginCookie || !c[0].HttpOnly || !c[0].Secure {
		t.Errorf("login cookie: %+v", c)
	}
	w := e.callback(cb)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `url=/changes"`) {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	var sc *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			sc = c
		}
	}
	if sc == nil || !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteStrictMode || sc.Path != "/" || sc.Domain != "" || len(sc.Value) != 43 {
		t.Fatalf("session cookie: %+v", sc)
	}
	if e.jar[loginCookie] != "" {
		t.Error("the login cookie must be cleared after the callback")
	}
	si := e.info()
	if si.User != "ada" || len(si.CSRF) != 43 {
		t.Fatalf("session info: %+v", si)
	}
	raw := e.do("GET", "/auth/session", nil, "").Body.String()
	if strings.Contains(raw, "eyJ") || strings.Contains(raw, "AT-must") {
		t.Error("session info leaks a token")
	}
	if w := e.do("GET", "/changes", nil, ""); w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("index with session: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	if g := e.do("GET", "/assets/app-abc.js", nil, "").Header().Get("Cache-Control"); !strings.Contains(g, "immutable") || !strings.Contains(g, "31536000") {
		t.Errorf("assets cache: %q", g)
	}
	if strings.Contains(e.logs.String(), testSecret) || strings.Contains(e.logs.String(), "eyJ") {
		t.Error("a secret or token was logged")
	}
}

func TestSignInRefusals(t *testing.T) {
	empty := ""
	cases := map[string]func(e *env, cb string) string{
		"wrong nonce": func(e *env, cb string) string {
			e.idp.nonceOverride = new(string)
			*e.idp.nonceOverride = "other"
			return cb
		},
		"missing nonce":  func(e *env, cb string) string { e.idp.nonceOverride = &empty; return cb },
		"wrong audience": func(e *env, cb string) string { e.idp.aud = "someone-else"; return cb },
		"wrong issuer":   func(e *env, cb string) string { e.idp.iss = "https://evil.example"; return cb },
		"expired token":  func(e *env, cb string) string { e.idp.expIn = -time.Hour; return cb },
		"bad signature":  func(e *env, cb string) string { e.idp.badSig = true; return cb },
		"pkce verifier":  func(e *env, cb string) string { e.idp.verifierBreaks = true; return cb },
		"token endpoint": func(e *env, cb string) string { e.idp.tokenError = true; return cb },
		"wrong state":    func(e *env, cb string) string { return strings.Replace(cb, "state=", "state=AAAA", 1) },
		"idp error": func(e *env, cb string) string {
			return testPublic + "/auth/callback?error=access_denied&state=" + stateOf(cb)
		},
		"no code":         func(e *env, cb string) string { return testPublic + "/auth/callback?state=" + stateOf(cb) },
		"issuer mismatch": func(e *env, cb string) string { return cb + "&iss=https%3A%2F%2Fevil.example" },
		"no login cookie": func(e *env, cb string) string { delete(e.jar, loginCookie); return cb },
		"other browser's cookie": func(e *env, cb string) string {
			e.jar[loginCookie] = strings.Repeat("A", 43)
			return cb
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			cb, _ := e.startLogin("")
			cb = mut(e, cb)
			w := e.callback(cb)
			if w.Code == 200 || e.jar[sessionCookie] != "" {
				t.Fatalf("accepted: %d", w.Code)
			}
			if e.do("GET", "/auth/session", nil, "").Code != 401 {
				t.Error("a refused sign-in left a session")
			}
		})
	}
}

func stateOf(cb string) string { u, _ := url.Parse(cb); return url.QueryEscape(u.Query().Get("state")) }

func TestStateIsSingleUse(t *testing.T) {
	e := newEnv(t, nil)
	cb, lw := e.startLogin("")
	login := lw.Result().Cookies()[0].Value
	if w := e.callback(cb); w.Code != 200 {
		t.Fatal(w.Code)
	}
	e.jar = map[string]string{loginCookie: login}
	if w := e.callback(cb); w.Code == 200 {
		t.Fatal("a replayed callback was accepted")
	}
}

func TestSessionLifetime(t *testing.T) {
	t.Run("capped by token exp", func(t *testing.T) {
		e := newEnv(t, func(*Config, *Options) {})
		e.idp.expIn = 10 * time.Minute
		e.signIn()
		e.clk.add(9 * time.Minute)
		e.info()
		e.clk.add(2 * time.Minute)
		if e.do("GET", "/auth/session", nil, "").Code != 401 {
			t.Fatal("session outlived the token")
		}
	})
	t.Run("capped at one hour", func(t *testing.T) {
		e := newEnv(t, func(c *Config, _ *Options) { c.IdleTimeout = 24 * time.Hour; c.SessionTTL = 24 * time.Hour })
		e.idp.expIn = 5 * time.Hour
		e.signIn()
		e.clk.add(59 * time.Minute)
		e.info()
		e.clk.add(2 * time.Minute)
		if e.do("GET", "/auth/session", nil, "").Code != 401 {
			t.Fatal("session outlived one hour")
		}
	})
	t.Run("idle", func(t *testing.T) {
		e := newEnv(t, func(c *Config, _ *Options) { c.IdleTimeout = time.Minute })
		e.signIn()
		e.clk.add(50 * time.Second)
		e.info() // activity
		e.clk.add(50 * time.Second)
		e.info()
		e.clk.add(61 * time.Second)
		if e.do("GET", "/auth/session", nil, "").Code != 401 {
			t.Fatal("idle session kept")
		}
	})
	t.Run("logout", func(t *testing.T) {
		e := newEnv(t, nil)
		si := e.signIn()
		id := e.jar[sessionCookie]
		if w := e.do("POST", "/auth/logout", nil, ""); w.Code != 403 {
			t.Fatalf("logout without CSRF: %d", w.Code)
		}
		if w := e.do("POST", "/auth/logout", map[string]string{"Origin": testPublic, "X-CSRF-Token": si.CSRF}, ""); w.Code != 204 {
			t.Fatalf("logout: %d", w.Code)
		}
		if _, ok := e.srv.store.Get(id); ok {
			t.Fatal("session survives logout")
		}
	})
}

func TestStoreEvictionAndBound(t *testing.T) {
	clk := &clock{t: time.Now()}
	s := NewStore(3, time.Hour, clk.now)
	var ids []string
	for i := 0; i < 5; i++ {
		clk.add(time.Second)
		id, err := s.Create(Session{Token: "t", Expires: clk.now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if s.Len() != 3 {
		t.Fatalf("len %d", s.Len())
	}
	for i, id := range ids {
		_, ok := s.Get(id)
		if (i < 2) == ok {
			t.Errorf("session %d present=%v", i, ok)
		}
	}
	if s.Evicted != 2 {
		t.Errorf("evicted %d", s.Evicted)
	}
	// Expired go before live ones are evicted.
	clk.add(2 * time.Hour)
	live, _ := s.Create(Session{Token: "t", Expires: clk.now().Add(time.Hour)})
	if _, ok := s.Get(live); !ok || s.Len() != 1 {
		t.Errorf("expired not swept: len %d", s.Len())
	}
	if _, ok := s.Get("not-an-id"); ok {
		t.Error("garbage id accepted")
	}
}

func TestCSRFAndOrigin(t *testing.T) {
	e := newEnv(t, nil)
	si := e.signIn()
	good := map[string]string{"Origin": testPublic, "X-CSRF-Token": si.CSRF}
	cases := map[string]map[string]string{
		"no token":        {"Origin": testPublic},
		"wrong token":     {"Origin": testPublic, "X-CSRF-Token": "nope"},
		"no origin":       {"X-CSRF-Token": si.CSRF},
		"foreign origin":  {"Origin": "https://evil.example", "X-CSRF-Token": si.CSRF},
		"null origin":     {"Origin": "null", "X-CSRF-Token": si.CSRF},
		"token in cookie": {"Origin": testPublic, "Cookie": "csrf=" + si.CSRF},
	}
	for name, h := range cases {
		if w := e.do("POST", "/api/write/v1/changes/c1/clear", h, `{}`); w.Code != 403 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if e.core.count() != 0 {
		t.Fatal("a refused write reached the core")
	}
	if w := e.do("POST", "/api/write/v1/changes/c1/clear", good, `{}`); w.Code != 200 {
		t.Fatalf("good write: %d %s", w.Code, w.Body)
	}
	// GETs need no token.
	if w := e.do("GET", "/api/read/v1/changes", nil, ""); w.Code != 200 {
		t.Fatalf("read: %d", w.Code)
	}
}

func TestForwardingHeadersAndBearer(t *testing.T) {
	e := newEnv(t, nil)
	si := e.signIn()
	token := ""
	e.srv.store.mu.Lock()
	for _, s := range e.srv.store.m {
		token = s.Token
	}
	e.srv.store.mu.Unlock()
	e.api.h = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Set-Cookie", "evil=1")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "public, max-age=999")
		io.WriteString(w, `{"changes":[]}`)
	}
	w := e.do("GET", "/api/read/v1/changes?app=shop&state=holding", map[string]string{
		"Authorization": "Bearer attacker", "X-Forwarded-For": "1.2.3.4", "X-Clearance-Via": "slack", "X-Custom": "x",
		"Accept": "application/json", "Cookie": "other=1", "Proxy-Authorization": "p",
	}, "")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	r := e.api.last()
	if r.URL.Path != "/v1/changes" || r.URL.RawQuery != "app=shop&state=holding" {
		t.Errorf("upstream URL: %s", r.URL)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+token {
		t.Errorf("authorization %q", got)
	}
	for _, h := range []string{"Cookie", "X-Forwarded-For", "X-Custom", "Proxy-Authorization", "X-Clearance-Via", "Forwarded"} {
		if r.Header.Get(h) != "" {
			t.Errorf("%s was forwarded: %q", h, r.Header.Get(h))
		}
	}
	if r.Header.Get("Accept") != "application/json" {
		t.Error("Accept not forwarded")
	}
	if len(r.Header.Values("Authorization")) != 1 {
		t.Error("more than one Authorization")
	}
	if w.Header().Get("Set-Cookie") != "" || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("upstream cookie or CORS header leaked to the browser")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("answer cacheable: %q", w.Header().Get("Cache-Control"))
	}
	// Writes go to the core with the via header and the body.
	w = e.write(si, "/api/write/v1/changes/c1/clear", `{"why":"ok"}`)
	cr := e.core.last()
	if w.Code != 200 || cr.Method != "POST" || cr.URL.Path != "/v1/changes/c1/clear" || cr.Header.Get("X-Clearance-Via") != "web" ||
		cr.Header.Get("Authorization") != "Bearer "+token || e.core.body[len(e.core.body)-1] != `{"why":"ok"}` {
		t.Errorf("core call: %+v body %v", cr, e.core.body)
	}
	if e.api.count() != 1 {
		t.Error("write went to the api")
	}
	// Gateway.
	w = e.write(si, "/api/gateway/v1/agents/a/pause", `{}`)
	if gr := e.gw.last(); w.Code != 200 || gr == nil || gr.Header.Get("X-Clearance-Via") != "web" || gr.Header.Get("Authorization") != "Bearer "+token {
		t.Errorf("gateway call: %d %+v", w.Code, gr)
	}
	// The session cookie never crosses.
	for _, u := range []*upstream{e.api, e.core, e.gw} {
		for _, rq := range u.reqs {
			if strings.Contains(rq.Header.Get("Cookie"), "clearance") {
				t.Error("session cookie forwarded")
			}
		}
	}
}

func TestForwardingRefusals(t *testing.T) {
	e := newEnv(t, nil)
	if w := e.do("GET", "/api/read/v1/changes", nil, ""); w.Code != 401 || e.api.count() != 0 {
		t.Fatalf("unauthenticated read: %d", w.Code)
	}
	si := e.signIn()
	for _, p := range []string{"/api/read/../write/v1/x", "/api/read/v1/%2e%2e/x", "/api/read/v1%2fchanges", "/api/read/v1/a%5cb",
		"/api/read/", "/api/read/v1//x", "/api/read/v1/./x", "/api/read/v1/%00"} {
		if w := e.do("GET", p, nil, ""); w.Code == 200 {
			t.Errorf("%s accepted", p)
		}
	}
	if e.api.count() != 0 {
		t.Errorf("traversal reached the api: %v", e.api.reqs[0].URL)
	}
	if w := e.write(si, "/api/read/v1/changes", `{}`); w.Code != 405 {
		t.Errorf("POST on the read route: %d", w.Code)
	}
	if w := e.do("GET", "/api/write/v1/changes", nil, ""); w.Code != 405 {
		t.Errorf("GET on the write route: %d", w.Code)
	}
	if w := e.do("GET", "/api/other/x", nil, ""); w.Code != 404 {
		t.Errorf("unknown api prefix: %d", w.Code)
	}
	// Redirects are not passed on.
	e.api.h = func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://internal.example/x", 302) }
	if w := e.do("GET", "/api/read/v1/redir", nil, ""); w.Code != 502 || w.Header().Get("Location") != "" {
		t.Errorf("redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
	// Body limit.
	e2 := newEnv(t, func(c *Config, _ *Options) { c.MaxBodyBytes = 10 })
	si2 := e2.signIn()
	if w := e2.write(si2, "/api/write/v1/x", strings.Repeat("a", 100)); w.Code != 413 || e2.core.count() != 0 {
		t.Errorf("oversize body: %d", w.Code)
	}
	// Response limit: the connection is cut, never a silent truncation.
	e3 := newEnv(t, func(c *Config, _ *Options) { c.MaxResponseBytes = 10 })
	e3.signIn()
	e3.api.h = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, strings.Repeat("a", 100))
	}
	if w := e3.do("GET", "/api/read/v1/big", nil, ""); w.Code == 200 && w.Body.Len() == 100 {
		t.Error("an oversize answer was passed whole")
	}
}

func TestGatewayAbsentWhenNotConfigured(t *testing.T) {
	e := newEnv(t, func(c *Config, _ *Options) { c.GatewayURL = "" })
	si := e.signIn()
	if si.Gateway {
		t.Error("gateway advertised")
	}
	if w := e.write(si, "/api/gateway/v1/x", `{}`); w.Code != 404 {
		t.Errorf("gateway route: %d", w.Code)
	}
}

func TestUpstreamAnswersPassThrough(t *testing.T) {
	e := newEnv(t, nil)
	e.signIn()
	for _, code := range []int{401, 403, 404, 409} {
		e.api.h = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			io.WriteString(w, `{"detail":"no"}`)
		}
		w := e.do("GET", "/api/read/v1/x", nil, "")
		if w.Code != code || w.Body.String() != `{"detail":"no"}` || w.Header().Get(reauthHeader) != "" {
			t.Errorf("%d: got %d %q", code, w.Code, w.Body)
		}
	}
}

func TestSSEPassthrough(t *testing.T) {
	e := newEnv(t, nil)
	e.signIn()
	release := make(chan struct{})
	e.api.h = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "id: 1\nevent: change\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
		io.WriteString(w, "id: 2\ndata: {}\n\n")
	}
	ts := httptest.NewServer(e.h)
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/read/v1/stream", nil)
	req.Header.Set("Cookie", sessionCookie+"="+e.jar[sessionCookie])
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Last-Event-ID", "0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	rd := bufio.NewReader(resp.Body)
	got := make(chan string, 1)
	go func() { l, _ := rd.ReadString('\n'); got <- l }()
	select {
	case l := <-got:
		if l != "id: 1\n" {
			t.Fatalf("first line %q", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first event was buffered until the stream ended")
	}
	if e.api.last().Header.Get("Last-Event-ID") != "0" {
		t.Error("Last-Event-ID not forwarded")
	}
	close(release)
	rest, _ := io.ReadAll(rd)
	if !strings.Contains(string(rest), "id: 2") {
		t.Errorf("rest %q", rest)
	}
}

// realCore is the actual core (internal/core, memory store) trusting the fake IdP's ID tokens, with a 15 minute
// freshness limit on break-glass, so the refusal the step-up reacts to is the real handler's, not a hand-written one.
func realCore(t *testing.T, e *env) string {
	t.Helper()
	keys := authn.NewJWKS(e.idp.ts.URL + "/jwks")
	oidc := authn.NewOIDCAuthenticator(e.idp.ts.URL, testClientID, keys, []string{"*"})
	cfg := core.Config{Memory: true, Version: "test", Auth: oidc, MaxClockSkew: -1}
	cfg.Gate.Admins = []string{"user:ada@example.com"}
	cfg.Gate.Fresh = gate.Freshness{Tier3Breakglass: 15 * time.Minute}
	c, err := core.Build(context.Background(), cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	srv := httptest.NewServer(c.Server.Handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestFreshLoginStepUpAgainstTheRealCore(t *testing.T) {
	e := newEnvHook(t, func(e *env) string { return realCore(t, e) }, nil)
	e.idp.authTimeAgo = time.Hour // the sign-in is an hour old: fine to sign in, too old for break-glass
	si := e.signIn()
	old := e.jar[sessionCookie]
	glass := `{"reason":"prod is down","ttl":"45m","cluster":"hangar-prod","env":"prod"}`
	w := e.do("POST", "/api/write/v1/breakglass", map[string]string{"Origin": testPublic, "X-CSRF-Token": si.CSRF,
		"Content-Type": "application/json", "Referer": testPublic + "/breakglass"}, glass)
	if w.Code != 401 {
		t.Fatalf("the core's freshness refusal is a 401, got %d %s", w.Code, w.Body)
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["rule"] != "DG-AUTH-NOT-FRESH" || body["max_age"] != "15m0s" || body["age"] == "" {
		t.Fatalf("the refusal is not the shape the step-up expects: %s", w.Body)
	}
	loc := w.Header().Get(reauthHeader)
	if !strings.HasPrefix(loc, "/auth/login?reauth=1&max_age=900&return=") || !strings.Contains(loc, url.QueryEscape("/breakglass")) {
		t.Fatalf("reauth header %q", loc)
	}
	// The login asks the IdP to reauthenticate, and an IdP that ignores it does not satisfy it.
	cb, _ := e.startLogin(strings.TrimPrefix(loc, "/auth/login"))
	if q := e.idp.lastAuthRequest; q.Get("prompt") != "login" || q.Get("max_age") != "900" {
		t.Fatalf("auth request: %v", q)
	}
	if w := e.callback(cb); w.Code == 200 {
		t.Fatal("a stale auth_time was accepted for a fresh login")
	}
	e.jar[sessionCookie] = old
	e.idp.authTimeAgo = 5 * time.Second
	cb, _ = e.startLogin(strings.TrimPrefix(loc, "/auth/login"))
	w = e.callback(cb)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `url=/breakglass"`) {
		t.Fatalf("fresh callback: %d %s", w.Code, w.Body)
	}
	if e.jar[sessionCookie] == old {
		t.Error("session id was not rotated")
	}
	if _, ok := e.srv.store.Get(old); ok {
		t.Error("the old session survives the fresh login")
	}
	// The repeated write now clears the core's check, and the core accepts X-Clearance-Via: web (a built-in via).
	si = e.info()
	if w := e.write(si, "/api/write/v1/breakglass", glass); w.Code != 200 {
		t.Fatalf("the write after a fresh login: %d %s", w.Code, w.Body)
	}
	// No auth_time at all: a fresh login is refused.
	e.idp.noAuthTime = true
	cb, _ = e.startLogin("?reauth=1")
	if w := e.callback(cb); w.Code == 200 {
		t.Fatal("fresh login accepted without auth_time")
	}
}

func TestStepUpOnlyOnTheFreshnessRefusal(t *testing.T) {
	e := newEnv(t, nil)
	si := e.signIn()
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"other 401":            {401, `{"error":"no bearer token","rule":"DG-AUTH","hint":""}`},
		"other rule":           {401, `{"error":"x","rule":"DG-OTHER","max_age":"5m0s"}`},
		"fresh rule but a 403": {403, `{"error":"x","rule":"DG-AUTH-NOT-FRESH","max_age":"5m0s"}`},
		"nested rule":          {401, `{"detail":{"rule":"DG-AUTH-NOT-FRESH"}}`},
	} {
		e.core.h = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(c.status)
			io.WriteString(w, c.body)
		}
		w := e.write(si, "/api/write/v1/x", `{}`)
		if w.Header().Get(reauthHeader) != "" || w.Code != c.status || w.Body.String() != c.body {
			t.Errorf("%s: %d %q %q", name, w.Code, w.Header().Get(reauthHeader), w.Body)
		}
	}
}

func TestFreshRefusalParsing(t *testing.T) {
	for body, want := range map[string]struct {
		d  time.Duration
		ok bool
	}{
		`{"error":"e","rule":"DG-AUTH-NOT-FRESH","hint":"h","max_age":"10m0s","age":"20m0s"}`: {10 * time.Minute, true},
		`{"rule":"DG-AUTH-NOT-FRESH"}`:                    {0, true},
		`{"rule":"DG-AUTH-NOT-FRESH","max_age":"banana"}`: {0, true},
		`{"rule":"DG-AUTH-NOT-FRESH","max_age":"999h"}`:   {0, true},
		`{"rule":"auth-not-fresh"}`:                       {0, false},
		`{"detail":{"rule":"DG-AUTH-NOT-FRESH"}}`:         {0, false},
		`not json`: {0, false},
		`[]`:       {0, false},
	} {
		if d, ok := freshRefusal([]byte(body)); d != want.d || ok != want.ok {
			t.Errorf("%s: %v %v", body, d, ok)
		}
	}
}

func TestHeaders(t *testing.T) {
	e := newEnv(t, func(c *Config, _ *Options) {})
	check := func(name string, w *httptest.ResponseRecorder, hsts bool) {
		h := w.Header()
		c := h.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "object-src 'none'"} {
			if !strings.Contains(c, want) {
				t.Errorf("%s: CSP lacks %s: %s", name, want, c)
			}
		}
		if strings.Contains(c, "script-src 'self' 'unsafe-inline'") || strings.Contains(c, "unsafe-eval") {
			t.Errorf("%s: CSP allows inline script", name)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: headers %v", name, h)
		}
		if (h.Get("Strict-Transport-Security") != "") != hsts {
			t.Errorf("%s: HSTS %q", name, h.Get("Strict-Transport-Security"))
		}
	}
	check("healthz", e.do("GET", "/healthz", nil, ""), false)
	check("auth", e.do("GET", "/auth/session", nil, ""), false)
	check("api", e.do("GET", "/api/read/v1/x", nil, ""), false)
	check("static", e.do("GET", "/assets/app-abc.js", nil, ""), false)
	s := newEnv(t, func(c *Config, _ *Options) { c.PublicURL = "https://clearance.example.com" })
	check("https", s.do("GET", "/healthz", nil, ""), true)
	if w := e.do("GET", "/readyz", nil, ""); w.Code != 200 {
		t.Errorf("readyz: %d", w.Code)
	}
}

func TestReadyzWhenIdPDown(t *testing.T) {
	e := newEnv(t, nil)
	e.idp.ts.Close()
	if w := e.do("GET", "/readyz", nil, ""); w.Code != 503 {
		t.Errorf("readyz: %d", w.Code)
	}
	if w := e.do("GET", "/healthz", nil, ""); w.Code != 200 {
		t.Errorf("healthz: %d", w.Code)
	}
	if w := e.do("GET", "/auth/login", nil, ""); w.Code != 503 {
		t.Errorf("login: %d", w.Code)
	}
}

func TestStaticFallbackAndEmbeddedPlaceholder(t *testing.T) {
	e := newEnv(t, func(_ *Config, o *Options) {
		o.Static = fstest.MapFS{"index.html": {Data: []byte("idx")}, "assets/x.js": {Data: []byte("x")}}
	})
	e.signIn()
	if w := e.do("GET", "/missing.js", nil, ""); w.Code != 404 {
		t.Errorf("missing file: %d", w.Code)
	}
	if w := e.do("GET", "/some/route", nil, ""); w.Code != 200 || w.Body.String() != "idx" {
		t.Errorf("fallback: %d", w.Code)
	}
	if w := e.do("POST", "/some/route", nil, ""); w.Code != 405 {
		t.Errorf("POST static: %d", w.Code)
	}
	p := newEnv(t, func(_ *Config, o *Options) { o.Static = nil })
	p.signIn()
	if w := p.do("GET", "/", nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "not built") {
		t.Errorf("placeholder: %d %s", w.Code, w.Body)
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"/changes?a=1": "/changes?a=1", "": "/", "//evil.example": "/", "https://evil.example": "/", "/\\evil": "/",
		"/auth/login": "/", "/api/read/x": "/", "evil": "/", "/a\nb": "/", "/ok/path": "/ok/path",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	good := Config{PublicURL: "https://c.example.com", Issuer: "https://dex.example.com", ClientID: "x", ClientSecretFile: "/s",
		APIURL: "http://api.svc:8080", CoreURL: "http://core.svc:8080"}
	if err := good.withDefaults().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"missing issuer": func(c *Config) { c.Issuer = "" },
		"missing secret": func(c *Config) { c.ClientSecretFile = "" },
		"http public":    func(c *Config) { c.PublicURL = "http://c.example.com" },
		"http issuer":    func(c *Config) { c.Issuer = "http://dex.example.com" },
		"public path":    func(c *Config) { c.PublicURL = "https://c.example.com/ui" },
		"creds in url":   func(c *Config) { c.APIURL = "http://u:p@api.svc" },
		"half tls":       func(c *Config) { c.TLSCertFile = "/c" },
	} {
		c := good
		mut(&c)
		if err := c.withDefaults().Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c := good.withDefaults()
	c.SessionTTL = 5 * time.Hour
	if c.withDefaults().SessionTTL != MaxSessionTTL {
		t.Error("session TTL not capped at one hour")
	}
	if _, err := readSecretFile("/nonexistent/secret"); err == nil {
		t.Error("missing secret file accepted")
	}
}

func TestUpstreamPath(t *testing.T) {
	if p, ok := upstreamPath("/api/read/", "/api/read/v1/changes/c 1", "/api/read/v1/changes/c%201"); !ok || p != "/v1/changes/c 1" {
		t.Errorf("%q %v", p, ok)
	}
}

func FuzzParseID(f *testing.F) {
	id, _ := newID()
	for _, s := range []string{id, "", "AAAA", strings.Repeat("A", 43), strings.Repeat("A", 44), "a=b; c", id + "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, ok := parseID(s)
		if ok && (got != s || len(s) != 43 || strings.ContainsAny(s, "=+/ ;,\x00")) {
			t.Fatalf("accepted %q", s)
		}
	})
}

func FuzzSafeReturn(f *testing.F) {
	for _, s := range []string{"/", "//x", "/a?b=c", "\\\\x", "/\t/", "http://x", "/%2f%2fevil"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := safeReturn(s)
		u, err := url.Parse(got)
		if err != nil || got == "" || got[0] != '/' || strings.HasPrefix(got, "//") || u.Host != "" || u.Scheme != "" ||
			strings.ContainsAny(got, "\\\r\n") {
			t.Fatalf("safeReturn(%q) = %q", s, got)
		}
	})
}

func FuzzUpstreamPath(f *testing.F) {
	for _, s := range []string{"v1/changes", "../x", "a//b", "%2e%2e/x", "a/./b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := url.Parse("http://h/api/read/" + s)
		if err != nil {
			return
		}
		got, ok := upstreamPath("/api/read/", u.Path, u.EscapedPath())
		if !ok {
			return
		}
		for _, seg := range strings.Split(got, "/")[1:] {
			if seg == ".." || seg == "." || strings.ContainsAny(seg, "\\\x00") {
				t.Fatalf("accepted %q -> %q", s, got)
			}
		}
		if got[0] != '/' {
			t.Fatalf("not rooted: %q", got)
		}
	})
}
