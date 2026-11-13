package slack

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/coder/websocket"
)

// Inbound is one thing Slack sent: a slash command, an interaction (button, modal), or an event.
type Inbound struct {
	Kind    string // "slash_commands", "interactive" or "events_api"
	Payload json.RawMessage
}

// Handler takes an Inbound and returns the body to acknowledge it with (nil: an empty ack). It must return within
// three seconds; anything slower is started in a goroutine by the handler.
type Handler interface {
	Handle(ctx context.Context, in Inbound) any
}

// Socket is the Socket Mode transport: an outbound websocket Slack pushes envelopes down, each acknowledged by
// envelope id. No inbound port, no public ingress. The service reconnects when Slack asks (a `disconnect` message
// comes before it recycles a connection) and when the socket drops, with backoff.
type Socket struct {
	API      *API
	AppToken string
	// AppTokenFn, when set, supplies the app-level token on each connect.
	AppTokenFn func() string
	Handler    Handler
	Log        *slog.Logger
	Dedupe     *Dedupe
	// Backoff bounds the wait between reconnects.
	MinBackoff, MaxBackoff time.Duration
}

type envelope struct {
	Type       string          `json:"type"`
	EnvelopeID string          `json:"envelope_id"`
	Payload    json.RawMessage `json:"payload"`
	Reason     string          `json:"reason"`
}

// Run connects and serves until ctx ends.
func (s *Socket) Run(ctx context.Context) error {
	min, max := s.MinBackoff, s.MaxBackoff
	if min <= 0 {
		min = time.Second
	}
	if max <= 0 {
		max = 30 * time.Second
	}
	wait := min
	for ctx.Err() == nil {
		start := time.Now()
		err := s.once(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(start) > time.Minute { // a connection that lived is not a failure to back off from
			wait = min
		}
		s.Log.Warn("socket mode connection ended", "error", errText(err), "retry_in", wait.String())
		if sleep(ctx, wait) != nil {
			return nil
		}
		if wait *= 2; wait > max {
			wait = max
		}
	}
	return nil
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Socket) once(ctx context.Context) error {
	tok := s.AppToken
	if s.AppTokenFn != nil {
		tok = s.AppTokenFn()
	}
	url, err := s.API.ConnectionsOpen(ctx, tok)
	if err != nil {
		return err
	}
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return errors.New("socket dial failed") // the URL carries a ticket: never echo it
	}
	defer c.CloseNow()
	c.SetReadLimit(4 << 20)
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return err
		}
		var env envelope
		if json.Unmarshal(data, &env) != nil {
			continue
		}
		switch env.Type {
		case "hello":
			s.Log.Info("socket mode connected")
			continue
		case "disconnect":
			return errors.New("slack asked to reconnect: " + env.Reason)
		}
		if env.EnvelopeID == "" {
			continue
		}
		// Slack redelivers an envelope it did not see acknowledged: acknowledge it again, process it once.
		var ack any
		if s.Dedupe == nil || s.Dedupe.First("env:"+env.EnvelopeID) {
			ack = s.Handler.Handle(ctx, Inbound{Kind: env.Type, Payload: env.Payload})
		}
		reply := map[string]any{"envelope_id": env.EnvelopeID}
		if ack != nil {
			reply["payload"] = ack
		}
		b, _ := json.Marshal(reply)
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = c.Write(wctx, websocket.MessageText, b)
		cancel()
		if err != nil {
			return err
		}
	}
}
