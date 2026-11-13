package slack

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type idpCode struct {
	nonce, challenge, email, sub string
	authTime                     int64
	wrongNonce                   bool
}

type fakeIdP struct {
	t      *testing.T
	srv    *httptest.Server
	signer *signer
	mu     sync.Mutex
	codes  map[string]*idpCode
}

func newFakeIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{t: t, signer: newSigner(t, "idp-k1"), codes: map[string]*idpCode{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) { w.Write(f.signer.jwks()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		c := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if c == nil || r.Form.Get("grant_type") != "authorization_code" || b64u(sum[:]) != c.challenge || r.Form.Get("client_id") != "idp-client" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		now := time.Now().Unix()
		claims := map[string]any{"iss": f.srv.URL, "aud": "idp-client", "sub": c.sub, "email": c.email, "email_verified": true, "iat": now, "exp": now + 3600, "nonce": c.nonce}
		if c.wrongNonce {
			claims["nonce"] = "not-the-nonce"
		}
		if c.authTime != 0 {
			claims["auth_time"] = c.authTime
		}
		json.NewEncoder(w).Encode(map[string]any{"id_token": f.signer.mint(t, claims), "token_type": "Bearer"})
	})
	return f
}

// browser walks the link flow the way a browser does, one hop at a time, with its own cookie.
type browser struct {
	t      *testing.T
	base   string
	cookie string
}

func (b *browser) get(rawurl string) (*http.Response, string) {
	b.t.Helper()
	u, _ := url.Parse(rawurl)
	req, _ := http.NewRequest("GET", b.base+u.RequestURI(), nil)
	if b.cookie != "" {
		req.Header.Set("Cookie", cookieName+"="+b.cookie)
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			b.cookie = c.Value
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
				b.t.Errorf("the link cookie must be HttpOnly and SameSite=Lax: %+v", c)
			}
		}
	}
	return resp, resp.Header.Get("Location")
}

type linkRig struct {
	*rig
	idp  *fakeIdP
	web  *httptest.Server
	code int
}

func newLinkRig(t *testing.T) *linkRig {
	idp := newFakeIdP(t)
	r := newRig(t, "", func(c *Config) { c.IdPIssuer = idp.srv.URL })
	web := httptest.NewServer(r.svc.Mux())
	t.Cleanup(web.Close)
	return &linkRig{rig: r, idp: idp, web: web}
}

func (l *linkRig) newCode() string {
	l.code++
	return "code-" + string(rune('a'+l.code))
}

// run drives a whole link for the Slack user. slackAs is who Sign in with Slack says signed in; idpEmail who the IdP says.
func (l *linkRig) run(team, user, slackSub, idpEmail string, mod ...func(*idpCode)) (slackStatus, idpStatus int) {
	t := l.t
	b := &browser{t: t, base: l.web.URL}
	resp, loc := b.get(l.svc.Link.NewURL(team, user))
	if resp.StatusCode != 302 || !strings.HasPrefix(loc, l.slack.srv.URL+"/openid/connect/authorize?") {
		t.Fatalf("start: %d %s", resp.StatusCode, loc)
	}
	q := mustQuery(t, loc)
	if q.Get("team") != team || q.Get("client_id") != "slack-client" || q.Get("scope") != "openid" || q.Get("response_type") != "code" {
		t.Fatalf("slack authorize: %v", q)
	}
	sc := l.newCode()
	l.slack.mu.Lock()
	l.slack.codes[sc] = map[string]string{"sub": slackSub, "team": team, "nonce": q.Get("nonce")}
	l.slack.mu.Unlock()
	resp, loc = b.get("/link/slack?code=" + sc + "&state=" + url.QueryEscape(q.Get("state")))
	if resp.StatusCode != 302 {
		return resp.StatusCode, 0
	}
	if !strings.HasPrefix(loc, l.idp.srv.URL+"/auth?") {
		t.Fatalf("idp authorize: %s", loc)
	}
	iq := mustQuery(t, loc)
	if iq.Get("code_challenge_method") != "S256" || iq.Get("client_id") != "idp-client" || iq.Get("prompt") != "login" || iq.Get("state") == "" {
		t.Fatalf("idp authorize params: %v", iq)
	}
	c := &idpCode{nonce: iq.Get("nonce"), challenge: iq.Get("code_challenge"), email: idpEmail, sub: "idp-sub-1", authTime: time.Now().Unix() - 5}
	for _, m := range mod {
		m(c)
	}
	ic := l.newCode()
	l.idp.mu.Lock()
	l.idp.codes[ic] = c
	l.idp.mu.Unlock()
	resp, _ = b.get("/link/idp?code=" + ic + "&state=" + url.QueryEscape(iq.Get("state")))
	return 302, resp.StatusCode
}

func mustQuery(t *testing.T, loc string) url.Values {
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestTheLinkNeedsBothProofs(t *testing.T) {
	l := newLinkRig(t)
	if _, idp := l.run("T1", "U1", "U1", "pat@acme.example"); idp != 200 {
		t.Fatalf("a good link: %d", idp)
	}
	got, _ := l.store.GetLink(bg, "T1", "U1")
	if got == nil || got.Person != "user:pat@acme.example" || got.Subject != "idp-sub-1" || got.Issuer != l.idp.srv.URL || !got.DM || got.AuthTime == 0 {
		t.Fatalf("the link: %+v", got)
	}
	if !got.VerifiedAt.Equal(l.now) {
		t.Errorf("verified at %v", got.VerifiedAt)
	}
}

func TestALinkIsRefusedWhenAProofDoesNotMatch(t *testing.T) {
	for name, tc := range map[string]struct {
		run func(l *linkRig) (int, int)
	}{
		"Sign in with Slack names another user": {func(l *linkRig) (int, int) { return l.run("T1", "U1", "U2", "pat@acme.example") }},
		"the IdP user is not on the allowlist":  {func(l *linkRig) (int, int) { return l.run("T1", "U1", "U1", "mallory@evil.example") }},
		"the IdP's nonce is not ours": {func(l *linkRig) (int, int) {
			return l.run("T1", "U1", "U1", "pat@acme.example", func(c *idpCode) { c.wrongNonce = true })
		}},
	} {
		t.Run(name, func(t *testing.T) {
			l := newLinkRig(t)
			tc.run(l)
			if got, _ := l.store.GetLink(bg, "T1", "U1"); got != nil {
				t.Fatalf("a link was made: %+v", got)
			}
			links, _ := l.store.ListLinks(bg)
			if len(links) != 0 {
				t.Fatalf("links: %v", links)
			}
		})
	}
}

func TestALinkTicketIsOneTimeShortLivedAndBoundToTheBrowser(t *testing.T) {
	l := newLinkRig(t)
	u := l.svc.Link.NewURL("T1", "U1")
	b := &browser{t: t, base: l.web.URL}
	if resp, _ := b.get(u); resp.StatusCode != 302 {
		t.Fatalf("first use: %d", resp.StatusCode)
	}
	if resp, _ := (&browser{t: t, base: l.web.URL}).get(u); resp.StatusCode != 400 {
		t.Fatalf("the ticket worked twice: %d", resp.StatusCode)
	}
	// expired
	u = l.svc.Link.NewURL("T1", "U1")
	l.now = l.now.Add(11 * time.Minute)
	if resp, _ := (&browser{t: t, base: l.web.URL}).get(u); resp.StatusCode != 400 {
		t.Fatalf("an expired ticket: %d", resp.StatusCode)
	}
	l.now = time.Now()
	// a callback from a browser that never started the flow (no cookie) or with the wrong state
	other := &browser{t: t, base: l.web.URL}
	if resp, _ := other.get("/link/slack?code=x&state=y"); resp.StatusCode != 400 {
		t.Fatalf("no session: %d", resp.StatusCode)
	}
	b2 := &browser{t: t, base: l.web.URL}
	_, loc := b2.get(l.svc.Link.NewURL("T1", "U1"))
	if resp, _ := b2.get("/link/slack?code=x&state=forged"); resp.StatusCode != 400 {
		t.Fatalf("wrong state: %d", resp.StatusCode)
	}
	// the IdP step cannot be reached before the Slack step
	if resp, _ := b2.get("/link/idp?code=x&state=" + mustQuery(t, loc).Get("state")); resp.StatusCode != 400 {
		t.Fatalf("idp before slack: %d", resp.StatusCode)
	}
	// the page says nothing about why
	resp, _ := b2.get("/link/slack?code=x&state=forged")
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("link pages carry CSP and no-store: %v", resp.Header)
	}
}

func TestRelinkingKeepsTheLinkedAtAndTheDMChoice(t *testing.T) {
	l := newLinkRig(t)
	l.run("T1", "U1", "U1", "pat@acme.example")
	first, _ := l.store.GetLink(bg, "T1", "U1")
	l.store.SetDM(bg, "T1", "U1", false)
	l.now = l.now.Add(31 * 24 * time.Hour)
	l.run("T1", "U1", "U1", "pat@acme.example")
	again, _ := l.store.GetLink(bg, "T1", "U1")
	if !again.LinkedAt.Equal(first.LinkedAt) || !again.VerifiedAt.Equal(l.now) || again.DM {
		t.Fatalf("first %+v, again %+v", first, again)
	}
}
