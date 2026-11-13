package slack

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/authn"
)

// The identity link: a Slack user (in a workspace) bound to a person at the IdP, by two proofs made in one browser
// session, in this order:
//
//  1. Sign in with Slack (OIDC): the ID token's sub and team id must be the Slack user who asked for the link.
//  2. The people IdP's login (authorization code with PKCE): the ID token, verified exactly as the core verifies it
//     (issuer, audience, signature, allowlist), names the person.
//
// Only then is the pair stored. Nothing Slack sends about a user's name or email is ever used to name a person.

const (
	ticketTTL  = 10 * time.Minute
	cookieName = "clearance_slack_link"
)

type ticket struct {
	team, user string
	at         time.Time
}

type session struct {
	team, user               string
	slackState, slackNonce   string
	idpState, idpNonce, pkce string
	stage                    int // 1: waiting for Slack, 2: waiting for the IdP
	at                       time.Time
}

// LinkFlow serves the link pages.
type LinkFlow struct {
	Cfg   *Config
	Store Store
	HTTP  *http.Client
	Log   *slog.Logger
	Now   func() time.Time
	// OnLinked is told when a link is made (the service DMs the person).
	OnLinked func(ctx context.Context, l Link)

	mu       sync.Mutex
	tickets  map[string]ticket
	sessions map[string]*session

	slackAuth, idpAuth *authn.OIDCAuthenticator
	disc               *discovery
	discAt             time.Time
}

type discovery struct{ Issuer, AuthURL, TokenURL string }

// NewLinkFlow is a LinkFlow for cfg.
func NewLinkFlow(cfg *Config, st Store, log *slog.Logger) *LinkFlow {
	f := &LinkFlow{Cfg: cfg, Store: st, Log: log, tickets: map[string]ticket{}, sessions: map[string]*session{},
		HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	slackJWKS := authn.NewJWKS(cfg.SlackBase + "/openid/connect/keys")
	slackJWKS.Client = f.HTTP
	f.slackAuth = authn.NewOIDCAuthenticator(cfg.SlackIssuer, cfg.SlackClientID, slackJWKS, []string{"*"})
	f.slackAuth.UserClaim = "sub"
	jwks := cfg.IdPJWKSURL
	if jwks == "" {
		jwks = cfg.IdPIssuer + "/keys"
	}
	idpJWKS := authn.NewJWKS(jwks)
	idpJWKS.Client = f.HTTP
	f.idpAuth = authn.NewOIDCAuthenticator(cfg.IdPIssuer, cfg.IdPClientID, idpJWKS, cfg.IdPAllowed)
	f.idpAuth.UserClaim = cfg.IdPUserClaim
	return f
}

func (f *LinkFlow) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("slack: no randomness")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (f *LinkFlow) sweep() { // callers hold mu
	now := f.now()
	for k, t := range f.tickets {
		if now.Sub(t.at) > ticketTTL {
			delete(f.tickets, k)
		}
	}
	for k, s := range f.sessions {
		if now.Sub(s.at) > ticketTTL {
			delete(f.sessions, k)
		}
	}
}

// NewURL makes a one-time link URL for the Slack user, good for ten minutes.
func (f *LinkFlow) NewURL(team, user string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweep()
	t := random(32)
	f.tickets[t] = ticket{team: team, user: user, at: f.now()}
	return f.Cfg.PublicURL + "/link?t=" + t
}

// Mount adds /link, /link/slack and /link/idp.
func (f *LinkFlow) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /link", f.start)
	mux.HandleFunc("GET /link/slack", f.slackCallback)
	mux.HandleFunc("GET /link/idp", f.idpCallback)
}

func page(w http.ResponseWriter, status int, title, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>%s</title><body style="font-family:system-ui;max-width:32em;margin:4em auto"><h1>%s</h1><p>%s</p>`,
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(msg))
}

func (f *LinkFlow) fail(w http.ResponseWriter, status int, why string, err error) {
	f.Log.Warn("link flow refused", "reason", why, "error", errText(err))
	page(w, status, "Could not link", "The link did not complete. Run /clearance link in Slack to start again.")
}

func (f *LinkFlow) start(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("t")
	f.mu.Lock()
	f.sweep()
	tk, ok := f.tickets[t]
	delete(f.tickets, t) // one time
	var s *session
	var sid string
	if ok {
		s = &session{team: tk.team, user: tk.user, slackState: random(24), slackNonce: random(24), stage: 1, at: f.now()}
		sid = random(32)
		f.sessions[sid] = s
	}
	f.mu.Unlock()
	if !ok {
		f.fail(w, http.StatusBadRequest, "unknown or used ticket", nil)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sid, Path: "/link", HttpOnly: true,
		Secure: strings.HasPrefix(f.Cfg.PublicURL, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: int(ticketTTL.Seconds())})
	q := url.Values{"response_type": {"code"}, "scope": {"openid"}, "client_id": {f.Cfg.SlackClientID},
		"redirect_uri": {f.Cfg.PublicURL + "/link/slack"}, "state": {s.slackState}, "nonce": {s.slackNonce}, "team": {s.team}}
	http.Redirect(w, r, f.Cfg.SlackBase+"/openid/connect/authorize?"+q.Encode(), http.StatusFound)
}

// take returns the session the browser's cookie names, if the state matches the stage's.
func (f *LinkFlow) take(r *http.Request, stage int, state string) *session {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweep()
	s := f.sessions[c.Value]
	if s == nil || s.stage != stage {
		return nil
	}
	want := s.slackState
	if stage == 2 {
		want = s.idpState
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(state)) != 1 {
		return nil
	}
	return s
}

func (f *LinkFlow) postForm(ctx context.Context, u string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("token endpoint answered HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(b, out)
}

func (f *LinkFlow) slackCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s := f.take(r, 1, q.Get("state"))
	if s == nil || q.Get("code") == "" {
		f.fail(w, http.StatusBadRequest, "slack callback: no session, wrong state or no code", nil)
		return
	}
	var tok struct {
		OK      bool   `json:"ok"`
		IDToken string `json:"id_token"`
	}
	err := f.postForm(r.Context(), f.Cfg.SlackAPIBase+"/openid.connect.token", url.Values{"client_id": {f.Cfg.SlackClientID},
		"client_secret": {f.Cfg.SlackClientSecret}, "code": {q.Get("code")}, "redirect_uri": {f.Cfg.PublicURL + "/link/slack"}}, &tok)
	if err != nil || !tok.OK || tok.IDToken == "" {
		f.fail(w, http.StatusBadGateway, "slack token exchange", err)
		return
	}
	if _, err := f.slackAuth.Authenticate(r.Context(), tok.IDToken); err != nil {
		f.fail(w, http.StatusUnauthorized, "slack id token", err)
		return
	}
	jwt, err := authn.ParseJWT(tok.IDToken)
	if err != nil {
		f.fail(w, http.StatusUnauthorized, "slack id token", err)
		return
	}
	sub, _ := jwt.Claims["sub"].(string)
	team, _ := jwt.Claims["https://slack.com/team_id"].(string)
	nonce, _ := jwt.Claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(s.slackNonce)) != 1 || sub != s.user || team != s.team {
		f.fail(w, http.StatusForbidden, "the Slack account that signed in is not the one that asked for the link", nil)
		return
	}
	d, err := f.discover(r.Context())
	if err != nil {
		f.fail(w, http.StatusBadGateway, "idp discovery", err)
		return
	}
	f.mu.Lock()
	s.idpState, s.idpNonce, s.pkce, s.stage = random(24), random(24), random(48), 2
	state, nonce2, verifier := s.idpState, s.idpNonce, s.pkce
	f.mu.Unlock()
	sum := sha256.Sum256([]byte(verifier))
	aq := url.Values{"response_type": {"code"}, "client_id": {f.Cfg.IdPClientID}, "redirect_uri": {f.Cfg.PublicURL + "/link/idp"},
		"scope": {"openid profile email"}, "state": {state}, "nonce": {nonce2}, "prompt": {"login"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	sep := "?"
	if strings.Contains(d.AuthURL, "?") {
		sep = "&"
	}
	http.Redirect(w, r, d.AuthURL+sep+aq.Encode(), http.StatusFound)
}

func (f *LinkFlow) idpCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s := f.take(r, 2, q.Get("state"))
	if s == nil || q.Get("code") == "" {
		f.fail(w, http.StatusBadRequest, "idp callback: no session, wrong state or no code", nil)
		return
	}
	d, err := f.discover(r.Context())
	if err != nil {
		f.fail(w, http.StatusBadGateway, "idp discovery", err)
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {f.Cfg.PublicURL + "/link/idp"},
		"client_id": {f.Cfg.IdPClientID}, "code_verifier": {s.pkce}}
	if f.Cfg.IdPClientSecret != "" {
		form.Set("client_secret", f.Cfg.IdPClientSecret)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := f.postForm(r.Context(), d.TokenURL, form, &tok); err != nil || tok.IDToken == "" {
		f.fail(w, http.StatusBadGateway, "idp token exchange", err)
		return
	}
	p, err := f.idpAuth.Authenticate(r.Context(), tok.IDToken)
	if err != nil {
		f.fail(w, http.StatusUnauthorized, "idp id token", err)
		return
	}
	jwt, _ := authn.ParseJWT(tok.IDToken)
	if nonce, _ := jwt.Claims["nonce"].(string); subtle.ConstantTimeCompare([]byte(nonce), []byte(s.idpNonce)) != 1 {
		f.fail(w, http.StatusForbidden, "idp nonce", nil)
		return
	}
	// The session is spent: whatever happens next, this browser starts over.
	f.mu.Lock()
	for k, v := range f.sessions {
		if v == s {
			delete(f.sessions, k)
		}
	}
	f.mu.Unlock()
	sub, _ := p.Claims["sub"].(string)
	var authTime int64
	if at, ok := p.Claims[authn.ClaimAuthTime].(int64); ok && p.Claims[authn.ClaimAuthTimeSource] == "auth_time" {
		authTime = at // only a time the IdP itself said: an iat is when the token was minted, not a proven sign-in
	}
	now := f.now()
	l := Link{Team: s.team, User: s.user, Issuer: f.Cfg.IdPIssuer, Subject: sub, Person: p.ID, AuthTime: authTime,
		LinkedAt: now, VerifiedAt: now, DM: true}
	if old, _ := f.Store.GetLink(r.Context(), s.team, s.user); old != nil {
		l.DM = old.DM
		if old.Person == l.Person && old.Subject == l.Subject {
			l.LinkedAt = old.LinkedAt
		}
	}
	if err := f.Store.PutLink(r.Context(), l); err != nil {
		f.fail(w, http.StatusInternalServerError, "store", err)
		return
	}
	f.Log.Info("slack identity linked", "team", l.Team, "slack_user", l.User, "person", l.Person)
	if f.OnLinked != nil {
		go f.OnLinked(context.WithoutCancel(r.Context()), l)
	}
	page(w, http.StatusOK, "Linked", "Your Slack account is linked to "+p.ID+". You can close this tab and go back to Slack.")
}

func (f *LinkFlow) discover(ctx context.Context) (*discovery, error) {
	f.mu.Lock()
	if f.disc != nil && f.now().Sub(f.discAt) < 10*time.Minute {
		d := f.disc
		f.mu.Unlock()
		return d, nil
	}
	f.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, "GET", f.Cfg.IdPIssuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, errors.New("OIDC discovery failed")
	}
	defer resp.Body.Close()
	var doc struct {
		Issuer string `json:"issuer"`
		Auth   string `json:"authorization_endpoint"`
		Token  string `json:"token_endpoint"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 || json.Unmarshal(b, &doc) != nil {
		return nil, errors.New("OIDC discovery failed")
	}
	if strings.TrimRight(doc.Issuer, "/") != f.Cfg.IdPIssuer {
		return nil, errors.New("OIDC discovery names another issuer")
	}
	for _, e := range []string{doc.Auth, doc.Token} {
		if u, err := url.Parse(e); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, errors.New("OIDC discovery has a bad endpoint")
		}
	}
	d := &discovery{Issuer: doc.Issuer, AuthURL: doc.Auth, TokenURL: doc.Token}
	f.mu.Lock()
	f.disc, f.discAt = d, f.now()
	f.mu.Unlock()
	return d, nil
}

// Stale says whether a link must be made again: both proofs are older than the re-verification period.
func (l *Link) Stale(now time.Time, after time.Duration) bool {
	return after > 0 && now.Sub(l.VerifiedAt) > after
}
