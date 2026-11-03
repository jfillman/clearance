package review

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/jfillman/clearance/internal/vocab"
	"io"
	"net/http"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/httpjson"
	"github.com/jfillman/clearance/internal/pycompat"
)

// MaxBody is the review route's body cap (server.py _body: 64 KiB).
const MaxBody = 64 << 10

// Config is what the review route needs from the deployment (Gateway's verifiers, delegates, model routes and
// runtime images).
type Config struct {
	// Verifiers are principal globs a CI check calls as (CLEARANCE_VERIFIERS).
	Verifiers []string `json:"verifiers"`
	// Delegates are principal globs that may act for a person they name (CLEARANCE_DELEGATES).
	Delegates []string `json:"delegates"`
	// Models are the deployment's model routes; nil = not checked (no model proxy).
	Models []string `json:"models"`
	// ImageAllow are globs a runtime.image must match: RUNTIME_IMAGES_EXTRA plus the runtime catalog's images.
	ImageAllow []string `json:"imageAllow"`
}

// Handler serves POST /v1/definitions/review.
type Handler struct {
	Config   Config
	Registry Registry
	Parse    definitions.Parser
}

// Routes registers the review route.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/definitions/review", h.review)
}

// ErrNotAllowed is provenance.NotVerifier for the review route (403).
type ErrNotAllowed struct{ Principal string }

func (e ErrNotAllowed) Error() string { return e.Principal + " may not review definitions" }

// BadRequest is gate.BadChange raised by review_definition (400).
type BadRequest struct{ Message string }

func (e BadRequest) Error() string { return e.Message }

// Result is review_definition's answer: ok, the problems, and (with none) the tier and its reasons.
type Result struct {
	OK       bool      `json:"ok"`
	Problems []Problem `json:"problems"`
	Tier     *int      `json:"tier,omitempty"`
	Changes  []Change  `json:"changes,omitempty"`
}

// Review is Gateway.review_definition: stateless and unrecorded. body is {doc, old?, name?, owner?, path?}.
func (h *Handler) Review(_ context.Context, p authn.Principal, body map[string]any, onBehalfOf string) (Result, error) {
	allowed := pycompat.MatchAny(p.ID, h.Config.Verifiers) || p.IsPerson() ||
		(onBehalfOf != "" && pycompat.MatchAny(p.ID, h.Config.Delegates))
	if !allowed {
		return Result{}, ErrNotAllowed{p.ID}
	}
	for k := range body {
		switch k {
		case "doc", "old", "name", "owner", "path":
		default:
			return Result{}, BadRequest{fmt.Sprintf("unknown field %s", pycompat.Repr(k))}
		}
	}
	opt := Options{Models: h.Config.Models, ImageAllow: h.Config.ImageAllow}
	for _, k := range []string{"name", "owner", "path"} {
		v, present := body[k]
		if !present || v == nil {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return Result{}, BadRequest{k + " is a string"}
		}
		switch k {
		case "name":
			opt.Name = &s
		case "owner":
			opt.Owner = &s
		case "path":
			opt.Path = &s
		}
	}
	doc, docOK := body["doc"].(map[string]any)
	if body["doc"] != nil && !docOK {
		return Result{}, BadRequest{"doc is the definition document, or null for a removal"}
	}
	old, oldOK := body["old"].(map[string]any)
	if body["old"] != nil && !oldOK {
		return Result{}, BadRequest{"old is the previous definition document, or null for a new agent"}
	}
	if doc == nil && old == nil {
		return Result{}, BadRequest{"doc or old is required"}
	}
	var problems []Problem
	if doc != nil {
		problems = Validate(doc, h.Registry, h.Parse, opt)
	}
	out := Result{OK: len(problems) == 0, Problems: problems}
	if out.Problems == nil {
		out.Problems = []Problem{}
	}
	if len(problems) == 0 {
		tier, changes := Classify(old, doc, h.Registry)
		out.Tier, out.Changes = &tier, changes
	}
	return out, nil
}

func (h *Handler) review(w http.ResponseWriter, r *http.Request) {
	p, ok := authn.From(r.Context())
	if !ok {
		httpjson.Write(w, http.StatusUnauthorized, map[string]any{"error": "a bearer token is required"})
		return
	}
	body, status, msg := ReadBody(r, MaxBody)
	if status != 0 {
		httpjson.Write(w, status, map[string]any{"error": msg})
		return
	}
	out, err := h.Review(r.Context(), p, body, r.Header.Get(vocab.Get().OnBehalfOfHeader))
	var na ErrNotAllowed
	var br BadRequest
	switch {
	case errors.As(err, &na):
		httpjson.Write(w, http.StatusForbidden, map[string]any{"error": na.Error()})
	case errors.As(err, &br):
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": br.Error()})
	case err != nil:
		httpjson.Write(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
	default:
		httpjson.Write(w, http.StatusOK, out)
	}
}

// ReadBody is server.py _body: at most max bytes (413), empty is {}, not JSON is 400, a non-object is {}.
func ReadBody(r *http.Request, max int64) (map[string]any, int, string) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return nil, http.StatusBadRequest, "the body could not be read"
	}
	if int64(len(raw)) > max {
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
