package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/jfillman/clearance/internal/vocab"
	"io"
	"log/slog"
	"net/http"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/httpjson"
	"github.com/jfillman/clearance/internal/pycompat"
)

// Body caps: server.py's MAX_BODY for a registration, _body's 64 KiB for a person's call.
const (
	MaxRegisterBody = 4 << 20
	MaxPersonBody   = 64 << 10
)

// Handler serves the gate's write routes: the check's registration and people's clear and deny.
type Handler struct {
	Svc *Service
	Log *slog.Logger
}

// Routes registers POST /v1/clearances, POST /v1/clearances/{change_id}/clear and .../deny, and a plan's
// .../outcome (G-TF-2).
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/clearances/{change_id}/outcome", h.outcome)
	mux.HandleFunc("POST /v1/clearances", h.register)
	mux.HandleFunc("POST /v1/clearances/{change_id}/clear", h.clear)
	mux.HandleFunc("POST /v1/clearances/{change_id}/deny", h.deny)
	mux.HandleFunc("POST /v1/breakglass", h.openBreakglass)
	mux.HandleFunc("POST /v1/breakglass/{id}/close", h.closeBreakglass)
	mux.HandleFunc("POST /v1/observations/{seq}/resolution", h.setResolution)
	mux.HandleFunc("POST /v1/observations/resolutions", h.setResolutions)
}

func (h *Handler) openBreakglass(w http.ResponseWriter, r *http.Request) {
	p, ok := authn.From(r.Context())
	if !ok {
		httpjson.Write(w, http.StatusUnauthorized, map[string]any{"error": "a bearer token is required"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBreakglassBody+1))
	if err != nil {
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": "the body could not be read"})
		return
	}
	if len(raw) > MaxBreakglassBody {
		httpjson.Write(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large"})
		return
	}
	var req BreakglassRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		msg := "the body is {reason, ttl, cluster, env, app?}"
		if err != nil {
			msg += ": " + err.Error()
		}
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": msg})
		return
	}
	out, err := h.Svc.OpenBreakglass(r.Context(), p, req, r.Header.Get(vocab.Get().OnBehalfOfHeader))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpjson.Write(w, http.StatusOK, out)
}

func (h *Handler) closeBreakglass(w http.ResponseWriter, r *http.Request) {
	p, ok := authn.From(r.Context())
	if !ok {
		httpjson.Write(w, http.StatusUnauthorized, map[string]any{"error": "a bearer token is required"})
		return
	}
	out, err := h.Svc.CloseBreakglass(r.Context(), p, r.PathValue("id"), r.Header.Get(vocab.Get().OnBehalfOfHeader))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpjson.Write(w, http.StatusOK, out)
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	p, ok := authn.From(r.Context())
	if !ok {
		httpjson.Write(w, http.StatusUnauthorized, map[string]any{"error": "a bearer token is required"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxRegisterBody+1))
	if err != nil {
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": "the body could not be read"})
		return
	}
	if len(raw) > MaxRegisterBody {
		httpjson.Write(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large"})
		return
	}
	body, err := pycompat.Decode(bytes.NewReader(raw))
	if err != nil {
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": "the body is not JSON"})
		return
	}
	out, err := h.Svc.Register(r.Context(), p, body)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpjson.Write(w, http.StatusOK, out)
}

func (h *Handler) clear(w http.ResponseWriter, r *http.Request) {
	p, ok := authn.From(r.Context())
	if !ok {
		httpjson.Write(w, http.StatusUnauthorized, map[string]any{"error": "a bearer token is required"})
		return
	}
	out, err := h.Svc.Clear(r.Context(), p, r.PathValue("change_id"), r.Header.Get(vocab.Get().OnBehalfOfHeader))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpjson.Write(w, http.StatusOK, out)
}

func (h *Handler) deny(w http.ResponseWriter, r *http.Request) {
	p, ok := authn.From(r.Context())
	if !ok {
		httpjson.Write(w, http.StatusUnauthorized, map[string]any{"error": "a bearer token is required"})
		return
	}
	body, status, msg := PersonBody(r)
	if status != 0 {
		httpjson.Write(w, status, map[string]any{"error": msg})
		return
	}
	for k := range body {
		if k != "reason" {
			httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": "unknown field " + pycompat.Repr(k)})
			return
		}
	}
	out, err := h.Svc.Deny(r.Context(), p, r.PathValue("change_id"), body["reason"], r.Header.Get(vocab.Get().OnBehalfOfHeader))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpjson.Write(w, http.StatusOK, out)
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	var ge *Error
	var bc *BadChange
	var nv *NotVerifier
	var br *BadReport
	switch {
	case errors.As(err, &nv):
		httpjson.Write(w, http.StatusForbidden, map[string]any{"error": nv.Message})
	case errors.As(err, &bc):
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": bc.Message})
	case errors.As(err, &br):
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": br.Message})
	case errors.As(err, &ge):
		httpjson.Write(w, ge.Status, ErrorBody{ge.Message, ge.Rule, ge.Hint})
	default:
		if h.Log != nil {
			h.Log.Error("gate: operation failed", "error", err.Error())
		}
		httpjson.Write(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
	}
}

// ErrorBody is a gate refusal's JSON: {"error", "rule", "hint"}.
type ErrorBody struct {
	Error string `json:"error"`
	Rule  string `json:"rule"`
	Hint  string `json:"hint"`
}

// PersonBody is server.py _body: at most 64 KiB (413), empty is {}, not JSON is 400, a non-object is {}.
func PersonBody(r *http.Request) (map[string]any, int, string) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxPersonBody+1))
	if err != nil {
		return nil, http.StatusBadRequest, "the body could not be read"
	}
	if len(raw) > MaxPersonBody {
		return nil, http.StatusRequestEntityTooLarge, "body too large"
	}
	if len(raw) == 0 {
		return map[string]any{}, 0, ""
	}
	v, err := pycompat.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, http.StatusBadRequest, "the body is not JSON"
	}
	m, ok := v.(map[string]any)
	if !ok {
		return map[string]any{}, 0, ""
	}
	return m, 0, ""
}
