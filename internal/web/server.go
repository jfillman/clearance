package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/authn"
)

// Options are the parts a test (or the build) swaps: the HTTP client for the IdP, the clock, the bundle, the secret.
type Options struct {
	HTTPClient *http.Client // the IdP; default a client with a 10 s timeout and no redirects
	Now        func() time.Time
	Static     fs.FS  // the UI bundle; default the embedded one (static.go)
	Secret     string // the client secret; default read from Config.ClientSecretFile
	Version    string
}

// Server is the web tier. It holds sessions and flows in memory and nothing else.
type Server struct {
	cfg     Config
	log     *slog.Logger
	hc      *http.Client
	now     func() time.Time
	secret  string
	version string
	static  fs.FS
	store   *Store
	flows   *flows
	origin  string // scheme://host of the public URL, what Origin must equal
	secure  bool   // the public URL is https: HSTS
	api     *url.URL
	core    *url.URL
	gateway *url.URL
	proxies map[string]*proxy

	mu       sync.Mutex
	provider *idp
	tried    time.Time
}

// New validates cfg and builds the server. It does not contact the IdP: discovery happens on first use and is
// retried, so the page and /healthz come up while the IdP is down.
func New(cfg Config, log *slog.Logger, o Options) (*Server, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, log: log, hc: o.HTTPClient, now: o.Now, secret: o.Secret, version: o.Version, static: o.Static}
	if s.secret == "" {
		sec, err := readSecretFile(cfg.ClientSecretFile)
		if err != nil {
			return nil, err
		}
		s.secret = sec
	}
	if s.hc == nil {
		s.hc = &http.Client{Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.version == "" {
		s.version = "dev"
	}
	if s.static == nil {
		b, err := bundle()
		if err != nil {
			return nil, err
		}
		s.static = b
	}
	pu, _ := url.Parse(cfg.PublicURL)
	s.origin = pu.Scheme + "://" + pu.Host
	s.secure = pu.Scheme == "https"
	s.store = NewStore(cfg.MaxSessions, cfg.IdleTimeout, s.now)
	s.flows = newFlows(1000, 10*time.Minute, s.now)
	s.api, _ = url.Parse(cfg.APIURL)
	s.core, _ = url.Parse(cfg.CoreURL)
	if cfg.GatewayURL != "" {
		s.gateway, _ = url.Parse(cfg.GatewayURL)
	}
	s.proxies = map[string]*proxy{
		"/api/read/":  s.newProxy(s.api, false),
		"/api/write/": s.newProxy(s.core, true),
	}
	if s.gateway != nil {
		s.proxies["/api/gateway/"] = s.newProxy(s.gateway, false)
	}
	return s, nil
}

// Handler is the whole server: routes inside the security headers.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/readyz", s.readyz)
	mux.HandleFunc("/auth/login", s.login)
	mux.HandleFunc("/auth/callback", s.callback)
	mux.HandleFunc("/auth/session", s.sessionInfo)
	mux.HandleFunc("/auth/logout", s.logout)
	for prefix := range s.proxies {
		mux.HandleFunc(prefix, s.forward(prefix))
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "not found", http.StatusNotFound) })
	mux.HandleFunc("/", s.serveStatic)
	return s.securityHeaders(mux)
}

// Run serves until ctx is done, then drains. TLS when the cert and key are set (else a gateway terminates it).
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr: s.cfg.Listen, Handler: s.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
		MaxHeaderBytes: 32 << 10,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
		// No WriteTimeout: the event stream is long-lived; it is bounded by the session's expiry instead.
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	go s.sweepLoop(ctx)
	errc := make(chan error, 1)
	go func() {
		if s.cfg.TLSCertFile != "" {
			errc <- srv.ServeTLS(ln, s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	s.log.Info("clearance web listening", "addr", ln.Addr().String(), "public_url", s.cfg.PublicURL, "tls", s.cfg.TLSCertFile != "")
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) sweepLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.store.Sweep()
		}
	}
}

// idpFor returns the discovered IdP, discovering it (at most every 15 s after a failure) when not yet known.
func (s *Server) idpFor(ctx context.Context) (*idp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provider != nil {
		return s.provider, nil
	}
	if !s.tried.IsZero() && s.now().Sub(s.tried) < 15*time.Second {
		return nil, errors.New("the IdP is unavailable")
	}
	s.tried = s.now()
	d, err := discover(ctx, s.hc, s.cfg.Issuer)
	if err != nil {
		s.log.Warn("OIDC discovery failed", "err", err.Error())
		return nil, err
	}
	keys := authn.NewJWKS(d.JWKSURI)
	keys.Client = s.hc
	s.provider = &idp{d: d, keys: keys}
	return s.provider, nil
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if _, err := s.idpFor(r.Context()); err != nil {
		http.Error(w, "the IdP is not reachable", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ready")
}

// csp is the content security policy of every response: this origin only, no inline script, no framing. Styles allow
// inline because the UI's CSS-in-JS (MUI) injects style elements; scripts never do.
const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if s.secure {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// ---- cookies and sessions ----

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: sameSite})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string, sameSite http.SameSite) {
	s.setCookie(w, name, "", -1, sameSite)
}

// sessionFrom is the live session the request's cookie names.
func (s *Server) sessionFrom(r *http.Request) (string, Session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", Session{}, false
	}
	sess, ok := s.store.Get(c.Value)
	if !ok {
		return "", Session{}, false
	}
	return c.Value, sess, true
}

// checkCSRF is for every request that is not GET, HEAD or OPTIONS: the Origin must be this server's own, and the
// X-CSRF-Token header must be the session's synchronizer token. It writes the refusal.
func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request, sess Session) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return true
	}
	if r.Header.Get("Origin") != s.origin {
		jsonError(w, http.StatusForbidden, "csrf", "cross-origin request refused")
		return false
	}
	if !equalStrings(r.Header.Get("X-CSRF-Token"), sess.CSRF) || sess.CSRF == "" {
		jsonError(w, http.StatusForbidden, "csrf", "missing or wrong CSRF token")
		return false
	}
	return true
}

func jsonError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

// safeReturn is a same-origin path (with query) the person is sent back to after sign-in: anything else is "/".
func safeReturn(s string) string {
	if s == "" || len(s) > 512 || s[0] != '/' || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") {
		return "/"
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "/"
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	if strings.HasPrefix(u.Path, "/auth/") || strings.HasPrefix(u.Path, "/api/") {
		return "/"
	}
	return u.RequestURI()
}

// ---- sign-in ----

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, err := s.idpFor(r.Context())
	if err != nil {
		errorPage(w, http.StatusServiceUnavailable, "The identity provider is not reachable. Try again in a moment.")
		return
	}
	q := r.URL.Query()
	ret := safeReturn(q.Get("return"))
	var maxAge time.Duration
	if q.Get("reauth") == "1" {
		maxAge = s.cfg.FreshMaxAge
		if n, err := strconv.Atoi(q.Get("max_age")); err == nil && n >= 1 && n <= int(maxFreshAge.Seconds()) {
			maxAge = time.Duration(n) * time.Second
		}
	} else if _, _, ok := s.sessionFrom(r); ok {
		http.Redirect(w, r, ret, http.StatusFound)
		return
	}
	var ids [4]string
	for i := range ids {
		if ids[i], err = newID(); err != nil {
			errorPage(w, http.StatusInternalServerError, "Could not start sign-in.")
			return
		}
	}
	state, nonce, verifier, binding := ids[0], ids[1], ids[2], ids[3]
	s.flows.put(state, flow{Verifier: verifier, Nonce: nonce, Binding: binding, Return: ret, MaxAge: maxAge})
	// The login cookie is Lax, not Strict: the IdP's redirect back is a cross-site navigation, which Strict cookies skip.
	s.setCookie(w, loginCookie, binding, 600, http.SameSiteLaxMode)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL(p.d, s.cfg.ClientID, s.cfg.UpstreamAudience, s.cfg.PublicURL+"/auth/callback", state, nonce, verifier, maxAge), http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func(status int, why string) {
		s.log.Warn("sign-in refused", "why", why)
		s.clearCookie(w, loginCookie, http.SameSiteLaxMode)
		errorPage(w, status, "Sign-in did not complete.")
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	// The flow is taken (single-use) before anything else is judged: a replayed or guessed state finds nothing.
	fl, ok := s.flows.take(q.Get("state"))
	bc, cerr := r.Cookie(loginCookie)
	switch {
	case !ok:
		fail(http.StatusBadRequest, "unknown or expired state")
		return
	case cerr != nil || !equalStrings(bc.Value, fl.Binding):
		fail(http.StatusBadRequest, "state is not bound to this browser")
		return
	case q.Get("error") != "":
		fail(http.StatusUnauthorized, "the IdP returned an error: "+safeLog(q.Get("error")))
		return
	}
	if iss := q.Get("iss"); iss != "" && strings.TrimRight(iss, "/") != s.cfg.Issuer { // RFC 9207
		fail(http.StatusBadRequest, "issuer mismatch in the callback")
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 4096 {
		fail(http.StatusBadRequest, "no code")
		return
	}
	p, err := s.idpFor(r.Context())
	if err != nil {
		fail(http.StatusServiceUnavailable, "IdP unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, err := exchange(ctx, s.hc, p.d, s.cfg.ClientID, s.secret, s.cfg.PublicURL+"/auth/callback", code, fl.Verifier)
	if err != nil {
		fail(http.StatusUnauthorized, err.Error())
		return
	}
	now := s.now()
	cl, err := p.checkIDToken(ctx, tok, s.cfg.ClientID, s.cfg.UpstreamAudience, fl.Nonce, fl.MaxAge, now)
	if err != nil {
		fail(http.StatusUnauthorized, "ID token: "+err.Error())
		return
	}
	// The session ends at the earliest of: the token's exp, an hour after it was issued, the configured TTL.
	end := now.Add(s.cfg.SessionTTL)
	for _, t := range []time.Time{cl.Exp, cl.Iat.Add(MaxSessionTTL)} {
		if !t.IsZero() && t.Before(end) {
			end = t
		}
	}
	if !end.After(now) {
		fail(http.StatusUnauthorized, "the token is already expired")
		return
	}
	authTime := cl.AuthTime
	if authTime.IsZero() {
		authTime = now
	}
	id, err := s.store.Create(Session{Token: tok, User: cl.User, Expires: end, AuthTime: authTime})
	if err != nil {
		fail(http.StatusInternalServerError, "no session")
		return
	}
	if old, _, ok := s.sessionFrom(r); ok {
		s.store.Delete(old)
	}
	s.clearCookie(w, loginCookie, http.SameSiteLaxMode)
	s.setCookie(w, sessionCookie, id, int(end.Sub(now).Seconds()), http.SameSiteStrictMode)
	// Not a 302: the redirect chain began at the IdP (cross-site), so the browser would not send the Strict session
	// cookie on its next request. A page that navigates itself is a same-site navigation.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	target := html.EscapeString(fl.Return)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=%s"><title>Signed in</title><a href="%s">Continue</a>`, target, target)
}

// safeLog is a short printable form of an IdP-supplied value for the log.
func safeLog(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strconv.QuoteToASCII(s)
}

func errorPage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Clearance</title><p>%s</p><p><a href="/auth/login">Sign in again</a></p>`, html.EscapeString(msg))
}

// sessionInfo tells the page who is signed in and hands it the CSRF token. It never returns the ID token.
func (s *Server) sessionInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, sess, ok := s.sessionFrom(r)
	if !ok {
		jsonError(w, http.StatusUnauthorized, "unauthenticated", "sign in")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user": sess.User, "csrf": sess.CSRF, "expires": sess.Expires.UTC().Format(time.RFC3339),
		"auth_time": sess.AuthTime.UTC().Format(time.RFC3339), "gateway": s.gateway != nil,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, sess, ok := s.sessionFrom(r)
	if !ok {
		s.clearCookie(w, sessionCookie, http.SameSiteStrictMode)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !s.checkCSRF(w, r, sess) {
		return
	}
	s.store.Delete(id)
	s.clearCookie(w, sessionCookie, http.SameSiteStrictMode)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
