package slack

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// The whole service, wired as in a deployment: Socket Mode delivers a slash command and a Clear click, the notifier
// posts a hold to the owner channel and to the linked person, and the write reaches the core as the delegate.
func TestTheWholeServiceOverSocketMode(t *testing.T) {
	r := newRig(t, testRoutes, func(c *Config) { c.ReconcileInterval = 100 * time.Millisecond; c.AlertInterval = time.Hour })
	setupPeople(r)
	r.link("T1", "U1", "user:ann", 0)
	r.clr.setChanges(change("c-1", "web", "prod", 2, "group:default/payments", nil))

	acks := make(chan map[string]any, 4)
	ws, _ := wsServer(t, func(c *websocket.Conn, n int) {
		ctx := context.Background()
		c.Write(ctx, websocket.MessageText, []byte(`{"type":"hello"}`))
		c.Write(ctx, websocket.MessageText, []byte(`{"envelope_id":"E1","type":"slash_commands","payload":{"team_id":"T1","user_id":"U1","text":"status"}}`))
		click := map[string]any{"envelope_id": "E2", "type": "interactive", "payload": map[string]any{"type": "block_actions", "trigger_id": "t1",
			"team": map[string]any{"id": "T1"}, "user": map[string]any{"id": "U1"}, "container": map[string]any{"channel_id": "C_PAY", "message_ts": "1.1"},
			"actions": []any{map[string]any{"action_id": ActClear, "value": "c-1"}}}}
		b, _ := json.Marshal(click)
		c.Write(ctx, websocket.MessageText, b)
		for {
			_, b, err := c.Read(ctx)
			if err != nil {
				return
			}
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			acks <- m
		}
	})
	r.slack.wsURL = "ws" + strings.TrimPrefix(ws.URL, "http")

	ctx, cancel := context.WithCancel(bg)
	done := make(chan error, 1)
	go func() { done <- r.svc.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the service did not stop")
		}
	}()

	got := map[string]map[string]any{}
	for len(got) < 2 {
		select {
		case a := <-acks:
			got[a["envelope_id"].(string)] = a
		case <-time.After(5 * time.Second):
			t.Fatalf("acks: %v", got)
		}
	}
	if p, _ := got["E1"]["payload"].(map[string]any); !strings.Contains(p["text"].(string), "Linked as user:ann") {
		t.Errorf("the slash command's reply: %v", got["E1"])
	}
	waitFor(t, "the hold in the owner channel and in ann's DM", func() bool {
		p := posted(r.slack)
		return len(p["C_PAY"]) == 1 && len(p["DU1"]) == 1
	})
	waitFor(t, "the Clear form", func() bool { return len(r.slack.called("views.open")) == 1 })
	if r.clr.writeCount() != 0 {
		t.Error("a click wrote")
	}
}

// A listener that cannot bind ends Run with its error and stops every goroutine; it does not hang waiting for a
// context nobody cancels.
func TestRunReturnsWhenTheListenerCannotBind(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	r := newRig(t, testRoutes, func(c *Config) { c.Listen = taken.Addr().String() })
	ws, _ := wsServer(t, func(c *websocket.Conn, n int) { <-context.Background().Done() })
	r.slack.wsURL = "ws" + strings.TrimPrefix(ws.URL, "http")
	done := make(chan error, 1)
	go func() { done <- r.svc.Run(bg) }() // bg is never cancelled
	select {
	case err := <-done:
		if err == nil {
			t.Error("Run returned no error for a port that is taken")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run hung")
	}
}
