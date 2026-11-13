package slack

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// -- JWT minting (RS256) ------------------------------------------------------------------------------------------

type signer struct {
	key *rsa.PrivateKey
	kid string
}

func newSigner(t *testing.T, kid string) *signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{key: k, kid: kid}
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s *signer) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": s.kid, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	in := b64u(h) + "." + b64u(c)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64u(sig)
}

func (s *signer) jwks() []byte {
	b, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": s.kid, "alg": "RS256", "use": "sig",
		"n": b64u(s.key.N.Bytes()), "e": b64u(big.NewInt(int64(s.key.E)).Bytes())}}})
	return b
}

// -- a fake Slack -------------------------------------------------------------------------------------------------

type slackCall struct {
	Method string
	Auth   string
	Body   map[string]any
}

type fakeSlack struct {
	t      *testing.T
	srv    *httptest.Server
	signer *signer

	mu       sync.Mutex
	calls    []slackCall
	nextTS   int
	wsURL    string
	failNext map[string]int // method -> status to answer once
	// the OIDC side
	codes   map[string]map[string]string // code -> {sub, team}
	clientI string
	nonces  map[string]string
}

func newFakeSlack(t *testing.T) *fakeSlack {
	f := &fakeSlack{t: t, signer: newSigner(t, "slack-k1"), failNext: map[string]int{}, codes: map[string]map[string]string{},
		clientI: "slack-client", nonces: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSlack) api() string { return f.srv.URL + "/api" }

func (f *fakeSlack) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.URL.Path == "/openid/connect/keys":
		w.Write(f.signer.jwks())
		return
	case r.URL.Path == "/api/openid.connect.token":
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		_ = r.ParseForm()
		f.mu.Lock()
		who := f.codes[r.Form.Get("code")]
		f.mu.Unlock()
		if who == nil || r.Form.Get("client_secret") != "slack-secret" || r.Form.Get("client_id") != f.clientI {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid_code"})
			return
		}
		now := time.Now().Unix()
		id := f.signer.mint(f.t, map[string]any{"iss": f.srv.URL, "aud": f.clientI, "sub": who["sub"], "iat": now, "exp": now + 300,
			"nonce": who["nonce"], "https://slack.com/team_id": who["team"]})
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "id_token": id})
		return
	}
	method := strings.TrimPrefix(r.URL.Path, "/api/")
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	f.mu.Lock()
	f.calls = append(f.calls, slackCall{Method: method, Auth: r.Header.Get("Authorization"), Body: m})
	if st := f.failNext[method]; st != 0 {
		delete(f.failNext, method)
		f.mu.Unlock()
		if st == 429 {
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(st)
		return
	}
	f.nextTS++
	ts := fmt.Sprintf("1700000000.%06d", f.nextTS)
	wsURL := f.wsURL
	f.mu.Unlock()
	switch method {
	case "chat.postMessage":
		ch, _ := m["channel"].(string)
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "channel": ch, "ts": ts})
	case "conversations.open":
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "channel": map[string]any{"id": "D" + fmt.Sprint(m["users"])}})
	case "chat.getPermalink":
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "permalink": fmt.Sprintf("https://acme.slack.com/archives/%v/p%v", m["channel"], strings.ReplaceAll(fmt.Sprint(m["message_ts"]), ".", ""))})
	case "apps.connections.open":
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "url": wsURL})
	case "users.info":
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "user": map[string]any{"deleted": m["user"] == "UGONE"}})
	default:
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
}

func (f *fakeSlack) called(method string) []slackCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []slackCall
	for _, c := range f.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeSlack) reset() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}

// -- a fake Clearance (api and core in one) ---------------------------------------------------------------------

type coreWrite struct {
	Path   string
	Header http.Header
	Body   map[string]any
}

type fakeClearance struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	token     string
	changes   []map[string]any // newest first
	persons   map[string]map[string]any
	writes    []coreWrite
	failWrite *CallErrorSpec
	counts    map[string]map[string]int64 // since -> key -> n (by attestation)
	countFn   func(since string) map[string]int64
	coverage  []map[string]any
	excs      []map[string]any
	// the stream: events to send on each connection, and what each connection asked for
	streamLast []string
	streamEv   []string
}

type CallErrorSpec struct {
	Status int
	Body   map[string]any
}

func newFakeClearance(t *testing.T) *fakeClearance {
	f := &fakeClearance{t: t, token: "sa-token-value", persons: map[string]map[string]any{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeClearance) setChanges(cs ...map[string]any) {
	f.mu.Lock()
	f.changes = cs
	f.mu.Unlock()
}

func (f *fakeClearance) setPerson(person string, groups []string, admin bool) {
	f.mu.Lock()
	f.persons[person] = map[string]any{"principal": "ns/clearance-slack", "person": person, "admin": admin, "groups": groups}
	f.mu.Unlock()
}

func (f *fakeClearance) lastWrite() *coreWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.writes) == 0 {
		return nil
	}
	w := f.writes[len(f.writes)-1]
	return &w
}

func (f *fakeClearance) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (f *fakeClearance) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		writeJSON(w, 401, map[string]any{"error": "bad token"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	obo := r.Header.Get("X-Clearance-On-Behalf-Of")
	path := r.URL.Path
	switch {
	case r.Method == "GET" && path == "/v1/whoami":
		p, ok := f.persons[obo]
		if !ok {
			p = map[string]any{"principal": "ns/clearance-slack", "person": obo, "admin": false, "groups": []string{}}
		}
		writeJSON(w, 200, p)
	case r.Method == "GET" && path == "/v1/clearances":
		var items []any
		q := r.URL.Query()
		for _, c := range f.changes {
			if s := q.Get("state"); s != "" && c["state"] != s {
				continue
			}
			if a := q.Get("app"); a != "" && c["app"] != a {
				continue
			}
			items = append(items, c)
		}
		writeJSON(w, 200, map[string]any{"items": items, "next": nil})
	case r.Method == "GET" && strings.HasPrefix(path, "/v1/clearances/") && path != "/v1/clearances/counts" && !strings.HasSuffix(path, "/clear") && !strings.HasSuffix(path, "/deny"):
		id := strings.TrimPrefix(path, "/v1/clearances/")
		for _, c := range f.changes {
			if c["id"] == id {
				writeJSON(w, 200, c)
				return
			}
		}
		writeJSON(w, 404, map[string]any{"error": "no such change"})
	case r.Method == "GET" && path == "/v1/clearances/counts":
		since := r.URL.Query().Get("since")
		m := map[string]int64{}
		if f.countFn != nil {
			m = f.countFn(since)
		}
		var items []any
		for k, n := range m {
			items = append(items, map[string]any{"key": k, "count": n})
		}
		writeJSON(w, 200, map[string]any{"by": "attestation", "items": items, "total": 0})
	case r.Method == "GET" && path == "/v1/coverage":
		writeJSON(w, 200, map[string]any{"scopes": f.coverage, "truncated": false})
	case r.Method == "GET" && path == "/v1/exceptions":
		writeJSON(w, 200, map[string]any{"items": f.excs, "next": nil})
	case r.Method == "GET" && path == "/v1/stream":
		f.streamLast = append(f.streamLast, r.Header.Get("Last-Event-ID"))
		evs := f.streamEv
		f.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		io.WriteString(w, ": hello\n\n")
		for _, e := range evs {
			io.WriteString(w, e)
		}
		fl.Flush()
		f.mu.Lock()
	case r.Method == "POST":
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		f.writes = append(f.writes, coreWrite{Path: path, Header: r.Header.Clone(), Body: body})
		if f.failWrite != nil {
			writeJSON(w, f.failWrite.Status, f.failWrite.Body)
			return
		}
		switch {
		case strings.HasSuffix(path, "/clear"):
			writeJSON(w, 200, map[string]any{"id": strings.Split(path, "/")[3], "state": "cleared", "audit_seq": 41})
		case strings.HasSuffix(path, "/deny"):
			writeJSON(w, 200, map[string]any{"id": strings.Split(path, "/")[3], "state": "denied", "audit_seq": 42})
		default:
			writeJSON(w, 200, map[string]any{"seq": 43})
		}
	default:
		writeJSON(w, 404, map[string]any{"error": "not found"})
	}
}

// change builds a change record as the api serves it.
func change(id, app, env string, tier int, owner string, outside []string, approvals ...map[string]any) map[string]any {
	req := map[string]any{"owner": 1, "outside": 0, "ownerGroup": owner, "outsideGroups": []string{}}
	if tier >= 3 {
		req["outside"] = 1
		req["outsideGroups"] = outside
	}
	if approvals == nil {
		approvals = []map[string]any{}
	}
	now := time.Now().UTC()
	return map[string]any{"id": id, "app": app, "env": env, "cluster": "c1", "repo": "acme/" + app, "pr": 7, "head": "0123456789abcdef", "base": "main",
		"proposer": "user:pat", "proposer_kind": "person", "owner": owner, "tier": tier,
		"reasons":     []map[string]any{{"subject": "Rollout/web", "rule": "kind:Rollout", "tier": tier}},
		"requirement": req, "state": "holding", "approvals": approvals,
		"created_at": now.Format("2006-01-02T15:04:05+00:00"), "updated_at": now.Format("2006-01-02T15:04:05+00:00"),
		"expires_at": now.Add(72 * time.Hour).Format("2006-01-02T15:04:05+00:00")}
}

func approval(person, role string, at time.Time) map[string]any {
	return map[string]any{"person": person, "role": role, "at": at.UTC().Format(time.RFC3339)}
}

// -- the service under test ---------------------------------------------------------------------------------------

type rig struct {
	t     *testing.T
	slack *fakeSlack
	clr   *fakeClearance
	store *MemStore
	svc   *Service
	cfg   Config
	now   time.Time
}

func newRig(t *testing.T, routes string, mod ...func(*Config)) *rig {
	t.Helper()
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "sa-token")
	os.WriteFile(tokFile, []byte("sa-token-value\n"), 0o600)
	routesFile := ""
	if routes != "" {
		routesFile = filepath.Join(dir, "routes.yaml")
		os.WriteFile(routesFile, []byte(routes), 0o600)
	}
	r := &rig{t: t, slack: newFakeSlack(t), clr: newFakeClearance(t), store: NewMemStore(), now: time.Now()}
	r.cfg = Config{Transport: TransportSocket, Listen: "127.0.0.1:0", PublicURL: "https://clearance-slack.example",
		BotToken: "xoxb-test", AppToken: "xapp-test", SlackClientID: r.slack.clientI, SlackClientSecret: "slack-secret",
		SlackBase: r.slack.srv.URL, SlackAPIBase: r.slack.api(), SlackIssuer: r.slack.srv.URL,
		IdPIssuer: "http://idp.invalid", IdPClientID: "idp-client", IdPUserClaim: "email", IdPAllowed: []string{"*@acme.example"},
		APIURL: r.clr.srv.URL, CoreURL: r.clr.srv.URL, SATokenFile: tokFile, OnBehalfOfHeader: "X-Clearance-On-Behalf-Of",
		RoutesFile: routesFile, WebURL: "https://clearance-web.example/changes/{id}", ClearMaxTier: 2, ForwardAuthTime: true,
		RelinkAfter: 30 * 24 * time.Hour, AlertInterval: time.Hour, ReconcileInterval: time.Hour,
		StuckAttestAfter: 30 * time.Minute, Tier3OutsideAfter: 15 * time.Minute, ReplayWindow: 5 * time.Minute}
	for _, m := range mod {
		m(&r.cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := Build(r.cfg, r.store, log)
	if err != nil {
		t.Fatal(err)
	}
	svc.Slack.MinInterval = 0
	svc.Notifier.Now = func() time.Time { return r.now }
	svc.Now = func() time.Time { return r.now }
	svc.Link.Now = func() time.Time { return r.now }
	r.svc = svc
	return r
}

func (r *rig) link(team, user, person string, authTime int64) {
	r.t.Helper()
	err := r.store.PutLink(context.Background(), Link{Team: team, User: user, Issuer: "http://idp.invalid", Subject: "sub-" + user, Person: person,
		AuthTime: authTime, LinkedAt: r.now, VerifiedAt: r.now, DM: true})
	if err != nil {
		r.t.Fatal(err)
	}
}

// -- a fake websocket peer for Socket Mode ------------------------------------------------------------------------

func wsServer(t *testing.T, onConn func(c *websocket.Conn, n int)) (*httptest.Server, func() int) {
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		mu.Lock()
		n++
		i := n
		mu.Unlock()
		defer c.CloseNow()
		onConn(c, i)
	}))
	t.Cleanup(srv.Close)
	return srv, func() int { mu.Lock(); defer mu.Unlock(); return n }
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func form(kv ...string) string {
	v := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v.Encode()
}

var bg = context.Background()

func json_(v any) ([]byte, error) { return json.Marshal(v) }
