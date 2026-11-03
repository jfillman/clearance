package githubapp

import (
	"io"
	"net/http"

	"github.com/jfillman/clearance/internal/httpjson"
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
		httpjson.Write(w, http.StatusNotFound, map[string]any{"error": "this Clearance runs no GitHub App"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxWebhookBody+1))
	if err != nil {
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"result": "not JSON"})
		return
	}
	if len(raw) > MaxWebhookBody {
		httpjson.Write(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large"})
		return
	}
	status, word := h.App.Accept(r.Header.Get("X-GitHub-Event"), raw, r.Header.Get("X-Hub-Signature-256"))
	httpjson.Write(w, status, map[string]any{"result": word})
}
