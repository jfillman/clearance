package slack

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// EventsHTTP is the Events API transport: Slack POSTs events, interactions and slash commands to /slack/events,
// /slack/interactive and /slack/command. Every request is verified (HMAC v0 over the raw body, a 5-minute replay
// window, a short memory of what was seen) before anything is parsed.
type EventsHTTP struct {
	Secret  string
	Window  time.Duration
	Handler Handler
	Dedupe  *Dedupe
	Log     *slog.Logger
	Now     func() time.Time
}

const maxInbound = 1 << 20

// Mount adds the routes to mux.
func (e *EventsHTTP) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /slack/events", e.serve("events_api"))
	mux.HandleFunc("POST /slack/interactive", e.serve("interactive"))
	mux.HandleFunc("POST /slack/command", e.serve("slash_commands"))
}

func (e *EventsHTTP) serve(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxInbound))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		now := time.Now
		if e.Now != nil {
			now = e.Now
		}
		sig := r.Header.Get("X-Slack-Signature")
		if err := VerifyRequest(e.Secret, r.Header.Get("X-Slack-Request-Timestamp"), sig, body, now(), e.Window); err != nil {
			e.Log.Warn("slack request refused", "reason", err.Error(), "path", r.URL.Path)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// The same signed request inside the window is a replay: refuse it, though it carries a good signature.
		if e.Dedupe != nil && !e.Dedupe.First("sig:"+sig) {
			e.Log.Warn("slack request replayed", "path", r.URL.Path)
			w.WriteHeader(http.StatusOK) // Slack's own retries look the same; acknowledge, do nothing
			return
		}
		payload := json.RawMessage(body)
		switch kind {
		case "interactive": // payload=<json> in a form body
			v, err := url.ParseQuery(string(body))
			if err != nil || v.Get("payload") == "" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			payload = json.RawMessage(v.Get("payload"))
		case "slash_commands": // a form body: hand it over as a JSON object of its first values
			v, err := url.ParseQuery(string(body))
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			m := map[string]string{}
			for k := range v {
				m[k] = v.Get(k)
			}
			payload, _ = json.Marshal(m)
		case "events_api":
			var c struct {
				Type      string `json:"type"`
				Challenge string `json:"challenge"`
			}
			if json.Unmarshal(body, &c) == nil && c.Type == "url_verification" {
				w.Header().Set("Content-Type", "text/plain")
				io.WriteString(w, c.Challenge)
				return
			}
		}
		ack := e.Handler.Handle(r.Context(), Inbound{Kind: kind, Payload: payload})
		if ack == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ack)
	}
}
