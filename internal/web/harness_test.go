package web

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

const (
	testClientID = "clearance-web"
	testSecret   = "s3cr3t-value-for-tests"
	testPublic   = "http://localhost:8080"
)

// clock is a settable time.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeIdP is a people IdP: discovery, JWKS, and a token endpoint that checks the client secret and PKCE.
type fakeIdP struct {
	t   *testing.T
	ts  *httptest.Server
	key *rsa.PrivateKey
	bad *rsa.PrivateKey // signs when badSig is set
	clk *clock

	mu    sync.Mutex
	codes map[string]codeEntry

	// knobs
	nonceOverride   *string
	aud, iss        string
	audList         []string // aud as a list (overrides aud)
	azp             string   // azp claim (overrides what the scope implies)
	crossClient     bool     // behave like Dex: scope audience:server:client_id:<peer> gives aud=[peer, client], azp=client
	expIn           time.Duration
	noAuthTime      bool
	authTimeAgo     time.Duration
	badSig          bool
	verifierBreaks  bool // the token endpoint refuses the PKCE verifier
	tokenError      bool
	tokenRequests   int
	lastAuthRequest url.Values
}

type codeEntry struct {
	challenge, nonce, redirect string
	maxAge                     string
	scope                      string
}

func newIdP(t *testing.T, clk *clock) *fakeIdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{t: t, key: k, bad: bad, clk: clk, codes: map[string]codeEntry{}, expIn: time.Hour}
	mux := http.NewServeMux()
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	f.iss, f.aud = f.ts.URL, testClientID
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": f.ts.URL, "authorization_endpoint": f.ts.URL + "/auth",
			"token_endpoint": f.ts.URL + "/token", "jwks_uri": f.ts.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": b64u(k.N.Bytes()), "e": b64u(big.NewInt(int64(k.E)).Bytes())}}})
	})
	mux.HandleFunc("/token", f.token)
	return f
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// authorize is the browser going to the IdP and the person approving: it returns the callback URL.
func (f *fakeIdP) authorize(authLocation string) string {
	f.t.Helper()
	u, err := url.Parse(authLocation)
	if err != nil {
		f.t.Fatal(err)
	}
	q := u.Query()
	f.lastAuthRequest = q
	code := "code-" + q.Get("state")[:8]
	f.mu.Lock()
	f.codes[code] = codeEntry{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri"), maxAge: q.Get("max_age"), scope: q.Get("scope")}
	f.mu.Unlock()
	return q.Get("redirect_uri") + "?code=" + code + "&state=" + url.QueryEscape(q.Get("state"))
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.tokenRequests++
	f.mu.Unlock()
	user, pass, ok := r.BasicAuth()
	if !ok || user != testClientID || pass != testSecret {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"invalid_client"}`)
		return
	}
	r.ParseForm()
	f.mu.Lock()
	ce, ok := f.codes[r.Form.Get("code")]
	delete(f.codes, r.Form.Get("code"))
	f.mu.Unlock()
	h := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !ok || f.tokenError || f.verifierBreaks || b64u(h[:]) != ce.challenge || r.Form.Get("redirect_uri") != ce.redirect ||
		r.Form.Get("grant_type") != "authorization_code" {
		w.WriteHeader(400)
		io.WriteString(w, `{"error":"invalid_grant"}`)
		return
	}
	nonce := ce.nonce
	if f.nonceOverride != nil {
		nonce = *f.nonceOverride
	}
	now := f.clk.now()
	claims := map[string]any{"iss": f.iss, "aud": f.aud, "sub": "u-1", "email": "ada@example.com", "email_verified": true,
		"preferred_username": "ada", "iat": now.Unix(), "exp": now.Add(f.expIn).Unix()}
	if f.crossClient {
		for _, sc := range strings.Fields(ce.scope) {
			if peer, ok := strings.CutPrefix(sc, "audience:server:client_id:"); ok {
				claims["aud"], claims["azp"] = []string{peer, testClientID}, testClientID
			}
		}
	}
	if f.audList != nil {
		claims["aud"] = f.audList
	}
	if f.azp != "" {
		claims["azp"] = f.azp
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if !f.noAuthTime {
		claims["auth_time"] = now.Add(-f.authTimeAgo).Unix()
	}
	key := f.key
	if f.badSig {
		key = f.bad
	}
	json.NewEncoder(w).Encode(map[string]any{"id_token": signJWT(key, claims), "access_token": "AT-must-not-be-used", "refresh_token": "RT-must-not-be-used", "token_type": "Bearer"})
}

func signJWT(key *rsa.PrivateKey, claims map[string]any) string {
	hb, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	cb, _ := json.Marshal(claims)
	in := b64u(hb) + "." + b64u(cb)
	d := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	return in + "." + b64u(sig)
}

// upstream records what it was sent.
type upstream struct {
	ts   *httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
	body []string
	h    http.HandlerFunc // per-test behaviour
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{}
	u.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.reqs = append(u.reqs, r.Clone(r.Context()))
		u.body = append(u.body, string(b))
		h := u.h
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(u.ts.Close)
	return u
}

func (u *upstream) count() int { u.mu.Lock(); defer u.mu.Unlock(); return len(u.reqs) }
func (u *upstream) last() *http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.reqs) == 0 {
		return nil
	}
	return u.reqs[len(u.reqs)-1]
}

// env is the server under test with its IdP and three upstreams.
type env struct {
	t             *testing.T
	clk           *clock
	idp           *fakeIdP
	api, core, gw *upstream
	srv           *Server
	h             http.Handler
	jar           map[string]string
	logs          *strings.Builder
	cfg           Config
}

func newEnv(t *testing.T, mut func(*Config, *Options)) *env { return newEnvHook(t, nil, mut) }

// newEnvHook is newEnv with a hook that runs once the IdP exists and may return a URL to use as the core instead of
// the fake one (a real core, whose authenticator trusts the fake IdP).
func newEnvHook(t *testing.T, coreFor func(e *env) string, mut func(*Config, *Options)) *env {
	t.Helper()
	clk := &clock{t: time.Now().Truncate(time.Second)}
	e := &env{t: t, clk: clk, jar: map[string]string{}, logs: &strings.Builder{}}
	e.idp = newIdP(t, clk)
	e.api, e.core, e.gw = newUpstream(t), newUpstream(t), newUpstream(t)
	cfg := Config{PublicURL: testPublic, Issuer: e.idp.ts.URL, ClientID: testClientID, ClientSecretFile: "unused",
		APIURL: e.api.ts.URL, CoreURL: e.core.ts.URL, GatewayURL: e.gw.ts.URL}
	o := Options{Now: clk.now, Secret: testSecret, Static: fstest.MapFS{
		"index.html":        {Data: []byte("<!doctype html><title>ui</title>")},
		"assets/app-abc.js": {Data: []byte("console.log(1)")},
	}}
	if coreFor != nil {
		cfg.CoreURL = coreFor(e)
	}
	if mut != nil {
		mut(&cfg, &o)
	}
	e.cfg = cfg
	srv, err := New(cfg, slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})), o)
	if err != nil {
		t.Fatal(err)
	}
	e.srv, e.h = srv, srv.Handler()
	return e
}

// do sends a request through the handler with the cookie jar and records Set-Cookie.
func (e *env) do(method, target string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rd)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	for k, v := range e.jar {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(e.jar, c.Name)
		} else {
			e.jar[c.Name] = c.Value
		}
	}
	return w
}

// startLogin begins a sign-in and returns the IdP callback URL for an approving person.
func (e *env) startLogin(query string) (string, *httptest.ResponseRecorder) {
	e.t.Helper()
	w := e.do("GET", "/auth/login"+query, nil, "")
	if w.Code != 302 {
		e.t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	return e.idp.authorize(w.Header().Get("Location")), w
}

func (e *env) callback(cb string) *httptest.ResponseRecorder {
	u, _ := url.Parse(cb)
	return e.do("GET", u.RequestURI(), nil, "")
}

// signIn signs in and returns the session info.
func (e *env) signIn() sessionInfo {
	e.t.Helper()
	cb, _ := e.startLogin("")
	if w := e.callback(cb); w.Code != 200 || e.jar[sessionCookie] == "" {
		e.t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	return e.info()
}

type sessionInfo struct {
	User    string `json:"user"`
	CSRF    string `json:"csrf"`
	Expires string `json:"expires"`
	Gateway bool   `json:"gateway"`
}

func (e *env) info() sessionInfo {
	e.t.Helper()
	w := e.do("GET", "/auth/session", nil, "")
	var si sessionInfo
	if w.Code != 200 {
		e.t.Fatalf("session: %d", w.Code)
	}
	json.Unmarshal(w.Body.Bytes(), &si)
	return si
}

func (e *env) write(si sessionInfo, path, body string) *httptest.ResponseRecorder {
	return e.do("POST", path, map[string]string{"Origin": testPublic, "X-CSRF-Token": si.CSRF, "Content-Type": "application/json"}, body)
}
