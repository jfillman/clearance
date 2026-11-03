package githubapp

import (
	"encoding/json"
	"io"
	"net/http"
)

// MaxWebhookBody is GitHub's own payload cap (25 MiB).
const MaxWebhookBody = 25 << 20

// Handler serves POST /v1/github/webhook. The route is authenticated by the payload's signature, never a bearer
// token: R-1d's authentication must let it through without a principal. App nil is a Clearance with no App (404).
type Handler struct {
	App *App
}

// Routes registers the webhook route.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/github/webhook", h.webhook)
}

func (h *Handler) webhook(w http.ResponseWriter, r *http.Request) {
	if h.App == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "this Clearance runs no GitHub App"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxWebhookBody+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"result": "not JSON"})
		return
	}
	if len(raw) > MaxWebhookBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large"})
		return
	}
	status, word := h.App.Accept(r.Header.Get("X-GitHub-Event"), raw, r.Header.Get("X-Hub-Signature-256"))
	writeJSON(w, status, map[string]any{"result": word})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
