package slack

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestVerifyRequest(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	body := []byte(`{"type":"event_callback"}`)
	ts := strconv.FormatInt(now.Unix(), 10)
	good := Sign("secret", now.Unix(), body)
	win := 5 * time.Minute
	// Slack's documented example: the algorithm is v0=HMAC-SHA256("v0:ts:body").
	if got := Sign("8f742231b10e8888abcd99yyyzzz85a5", 1531420618,
		[]byte("token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c")); got != "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503" {
		t.Errorf("signature of Slack's documented example: %s", got)
	}
	for name, tc := range map[string]struct {
		secret, ts, sig string
		at              time.Time
		want            error
	}{
		"good":                 {"secret", ts, good, now, nil},
		"edge of the window":   {"secret", ts, good, now.Add(win), nil},
		"wrong secret":         {"other", ts, good, now, ErrBadSignature},
		"tampered signature":   {"secret", ts, flip(good), now, ErrBadSignature},
		"no v0 prefix":         {"secret", ts, strings.TrimPrefix(good, "v0="), now, ErrBadSignature},
		"missing signature":    {"secret", ts, "", now, ErrNoSignature},
		"missing timestamp":    {"secret", "", good, now, ErrNoSignature},
		"bad timestamp":        {"secret", "soon", good, now, ErrNoSignature},
		"no secret configured": {"", ts, good, now, ErrNoSignature},
		"replayed, too old":    {"secret", ts, good, now.Add(win + time.Second), ErrStale},
		"from the future":      {"secret", ts, good, now.Add(-win - time.Second), ErrStale},
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyRequest(tc.secret, tc.ts, tc.sig, body, tc.at, win); err != tc.want {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
	// the body is covered: a signature over another body does not verify
	if err := VerifyRequest("secret", ts, good, []byte(`{"type":"other"}`), now, win); err != ErrBadSignature {
		t.Errorf("a different body: %v", err)
	}
}

// flip changes the signature's last hex digit.
func flip(sig string) string {
	last := sig[len(sig)-1]
	if last == 'a' {
		return sig[:len(sig)-1] + "b"
	}
	return sig[:len(sig)-1] + "a"
}

func TestDedupe(t *testing.T) {
	d := NewDedupe(time.Minute, 3)
	clock := time.Unix(0, 0)
	d.now = func() time.Time { return clock }
	if !d.First("a") || d.First("a") {
		t.Fatal("a key is new once")
	}
	clock = clock.Add(2 * time.Minute)
	if !d.First("a") {
		t.Error("a key expires")
	}
	for _, k := range []string{"b", "c", "d", "e"} { // past max: the oldest goes, memory stays bounded
		d.First(k)
	}
	if len(d.seen) > 3 {
		t.Errorf("unbounded: %d", len(d.seen))
	}
}

type recorder struct {
	n   atomic.Int64
	got chan Inbound
	ack any
}

func (r *recorder) Handle(_ context.Context, in Inbound) any {
	r.n.Add(1)
	select {
	case r.got <- in:
	default:
	}
	return r.ack
}

func eventsServer(t *testing.T, h Handler, now time.Time) *httptest.Server {
	mux := http.NewServeMux()
	(&EventsHTTP{Secret: "s3cret", Window: 5 * time.Minute, Handler: h, Dedupe: NewDedupe(6*time.Minute, 100),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, srv *httptest.Server, path, secret string, ts time.Time, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(ts.Unix(), 10))
	req.Header.Set("X-Slack-Signature", Sign(secret, ts.Unix(), []byte(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestEventsAPIVerifiesRepliesAndRefusesReplays(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rec := &recorder{got: make(chan Inbound, 4), ack: map[string]any{"text": "ok"}}
	srv := eventsServer(t, rec, now)

	// a bad signature never reaches the handler, and says nothing about why
	resp := post(t, srv, "/slack/command", "wrong-secret", now, form("team_id", "T1", "user_id", "U1", "text", "link"))
	if resp.StatusCode != 401 || rec.n.Load() != 0 {
		t.Fatalf("bad signature: %d, handled %d", resp.StatusCode, rec.n.Load())
	}
	// a stale timestamp (a captured request replayed later) is refused even with a good signature
	resp = post(t, srv, "/slack/command", "s3cret", now.Add(-6*time.Minute), form("team_id", "T1"))
	if resp.StatusCode != 401 || rec.n.Load() != 0 {
		t.Fatalf("stale: %d", resp.StatusCode)
	}
	// a good one: the form becomes a JSON object for the handler and the handler's reply is the response
	body := form("team_id", "T1", "user_id", "U1", "text", "link")
	resp = post(t, srv, "/slack/command", "s3cret", now, body)
	b, _ := io.ReadAll(resp.Body)
	var reply map[string]any
	if resp.StatusCode != 200 || json.Unmarshal(b, &reply) != nil || reply["text"] != "ok" {
		t.Fatalf("good: %d %s", resp.StatusCode, b)
	}
	in := <-rec.got
	var cmd map[string]string
	_ = json.Unmarshal(in.Payload, &cmd)
	if in.Kind != "slash_commands" || cmd["user_id"] != "U1" || cmd["text"] != "link" {
		t.Fatalf("handler got %s %v", in.Kind, cmd)
	}
	// the exact same signed request inside the window is a replay: acknowledged, not handled again
	resp = post(t, srv, "/slack/command", "s3cret", now, body)
	if resp.StatusCode != 200 || rec.n.Load() != 1 {
		t.Fatalf("replay: %d, handled %d", resp.StatusCode, rec.n.Load())
	}
	// interactivity: payload=<json>
	resp = post(t, srv, "/slack/interactive", "s3cret", now, form("payload", `{"type":"block_actions"}`))
	if resp.StatusCode != 200 || rec.n.Load() != 2 {
		t.Fatalf("interactive: %d", resp.StatusCode)
	}
	if in := <-rec.got; in.Kind != "interactive" || string(in.Payload) != `{"type":"block_actions"}` {
		t.Fatalf("interactive payload: %s", in.Payload)
	}
	// Slack's URL verification handshake answers with the challenge (and is signed like everything else)
	resp = post(t, srv, "/slack/events", "s3cret", now, `{"type":"url_verification","challenge":"abc123"}`)
	if b, _ := io.ReadAll(resp.Body); string(b) != "abc123" {
		t.Fatalf("challenge: %s", b)
	}
	resp = post(t, srv, "/slack/events", "wrong", now, `{"type":"url_verification","challenge":"abc123"}`)
	if resp.StatusCode != 401 {
		t.Fatalf("an unsigned challenge: %d", resp.StatusCode)
	}
}

func TestSocketModeAcksDedupesAndReconnects(t *testing.T) {
	rec := &recorder{got: make(chan Inbound, 8), ack: map[string]any{"text": "from handler"}}
	acks := make(chan map[string]any, 8)
	ws, conns := wsServer(t, func(c *websocket.Conn, n int) {
		ctx := context.Background()
		c.Write(ctx, websocket.MessageText, []byte(`{"type":"hello"}`))
		if n == 1 {
			env := `{"envelope_id":"E1","type":"slash_commands","accepts_response_payload":true,"payload":{"team_id":"T1","user_id":"U1","text":"status"}}`
			c.Write(ctx, websocket.MessageText, []byte(env))
			c.Write(ctx, websocket.MessageText, []byte(env)) // Slack sends it again: it was not acked in time
			for i := 0; i < 2; i++ {
				_, b, err := c.Read(ctx)
				if err != nil {
					return
				}
				var m map[string]any
				_ = json.Unmarshal(b, &m)
				acks <- m
			}
			c.Write(ctx, websocket.MessageText, []byte(`{"type":"disconnect","reason":"refresh_requested"}`))
			time.Sleep(time.Second)
			return
		}
		<-ctx.Done()
	})
	s := newFakeSlack(t)
	s.wsURL = "ws" + strings.TrimPrefix(ws.URL, "http")
	api := NewAPI(s.api(), "xoxb", 0)
	sock := &Socket{API: api, AppToken: "xapp-1", Handler: rec, Dedupe: NewDedupe(time.Minute, 10), MinBackoff: time.Millisecond, MaxBackoff: 10 * time.Millisecond,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sock.Run(ctx)

	for i := 0; i < 2; i++ {
		select {
		case a := <-acks:
			if a["envelope_id"] != "E1" {
				t.Fatalf("ack %v", a)
			}
			// the handler's reply rides in the first ack; a redelivery is acked again, empty
			if p, ok := a["payload"].(map[string]any); i == 0 && (!ok || p["text"] != "from handler") {
				t.Fatalf("the first ack carries the reply: %v", a)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no ack")
		}
	}
	if rec.n.Load() != 1 {
		t.Errorf("the redelivered envelope was handled %d times", rec.n.Load())
	}
	waitFor(t, "a reconnect after Slack's disconnect", func() bool { return conns() >= 2 })
	// the app token authenticates apps.connections.open, never the bot token
	for _, c := range s.called("apps.connections.open") {
		if c.Auth != "Bearer xapp-1" {
			t.Errorf("connections.open auth %q", c.Auth)
		}
	}
}
