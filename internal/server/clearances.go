package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/token"
)

// getClearance is GET /v1/clearances/{change_id}: a change's state and its live clearance token, for the callers
// that act on it: a registered provider (a gate provider waiting to deploy), or the verifier that registered the
// change. People read changes through clearance-api.
func (s *Server) getClearance(w http.ResponseWriter, r *http.Request) {
	g := s.opt.Gate
	if g == nil {
		writeError(w, http.StatusNotFound, "this core keeps no changes")
		return
	}
	p, ok := authn.From(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "a bearer token is required")
		return
	}
	c, tk, err := g.Clearance(r.Context(), r.PathValue("change_id"))
	var ge *gate.Error
	switch {
	case errors.As(err, &ge):
		writeJSON(w, ge.Status, gate.ErrorBody{Error: ge.Message, Rule: ge.Rule, Hint: ge.Hint})
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "clearance read failed", "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	registrant := c.RegisteredBy == p.ID && pycompat.MatchAny(p.ID, g.Config.Verifiers)
	if providerFor(s.opt.Providers, p.ID) == nil && !registrant {
		writeError(w, http.StatusForbidden, p.ID+" is neither a registered provider nor the verifier that registered this change")
		return
	}
	out, err := gate.Answer(c, tk)
	if err != nil {
		s.log.ErrorContext(r.Context(), "clearance token unreadable", "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the stored token could not be read")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// KeysWindow is how long a retired signing key stays in GET /v1/keys: past the longest a token signed by it lives.
const KeysWindow = token.MaxLifetime

// keys is GET /v1/keys: the clearance token verification keys (a JWKS), the one in use and those retired within
// KeysWindow. Public; no token asked.
func (s *Server) keys(w http.ResponseWriter, r *http.Request) {
	rows, err := s.opt.Store.SigningKeys(r.Context(), s.opt.Clock().Add(-KeysWindow))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	out := token.JWKS{Keys: []token.JWK{}}
	for _, k := range rows {
		var j token.JWK
		if err := json.Unmarshal(k.JWK, &j); err != nil {
			continue
		}
		out.Keys = append(out.Keys, j)
	}
	w.Header().Set("Cache-Control", "max-age=300")
	writeJSON(w, http.StatusOK, out)
}
