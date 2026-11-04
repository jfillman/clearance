package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

// getClearance is GET /v1/clearances/{change_id}: a change's state and its live clearance token, for the callers
// that act on it: a registered provider (a gate provider waiting to deploy), or the verifier that registered the
// change. People read changes through clearance-api.
func (s *Server) getClearance(w http.ResponseWriter, r *http.Request) {
	c, tk, ok := s.readClearance(w, r)
	if !ok {
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

// readClearance reads a change and its live token for the caller, or answers the refusal (false).
func (s *Server) readClearance(w http.ResponseWriter, r *http.Request) (*gate.Change, *store.Token, bool) {
	g := s.opt.Gate
	if g == nil {
		writeError(w, http.StatusNotFound, "this core keeps no changes")
		return nil, nil, false
	}
	p, ok := authn.From(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "a bearer token is required")
		return nil, nil, false
	}
	c, tk, err := g.Clearance(r.Context(), r.PathValue("change_id"))
	var ge *gate.Error
	switch {
	case errors.As(err, &ge):
		writeJSON(w, ge.Status, gate.ErrorBody{Error: ge.Message, Rule: ge.Rule, Hint: ge.Hint})
		return nil, nil, false
	case err != nil:
		s.log.ErrorContext(r.Context(), "clearance read failed", "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return nil, nil, false
	}
	registrant := c.RegisteredBy == p.ID && pycompat.MatchAny(p.ID, g.Config.Verifiers)
	if providerFor(s.opt.Providers, p.ID) == nil && !registrant {
		writeError(w, http.StatusForbidden, p.ID+" is neither a registered provider nor the verifier that registered this change")
		return nil, nil, false
	}
	return c, tk, true
}

// Wait bounds (GET /v1/clearances/{id}/wait).
const (
	MaxWait     = 60 * time.Second
	DefaultWait = 30 * time.Second
)

// WaitAnswer is the wait route's answer: getClearance's, and whether the state changed (false: the timeout).
type WaitAnswer struct {
	gate.ClearanceAnswer
	Changed bool `json:"changed"`
}

// waitClearance is GET /v1/clearances/{change_id}/wait: getClearance, held until the change's state is not the one
// given (or the one it had when the call arrived), or until the timeout. It watches the gate's notifier before
// each read, so a write between the read and the wait still wakes it; nothing polls the store.
func (s *Server) waitClearance(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k, vs := range q {
		if k != "state" && k != "timeout" {
			writeError(w, http.StatusBadRequest, "unknown query parameter "+strconv.Quote(k))
			return
		}
		if len(vs) > 1 {
			writeError(w, http.StatusBadRequest, k+" is given more than once")
			return
		}
	}
	timeout := DefaultWait
	if raw := q.Get("timeout"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || time.Duration(n)*time.Second > MaxWait {
			writeError(w, http.StatusBadRequest, "timeout is seconds, 1 to 60")
			return
		}
		timeout = time.Duration(n) * time.Second
	}
	known := q.Get("state")
	if len(known) > 32 {
		writeError(w, http.StatusBadRequest, "state is a change state")
		return
	}
	g := s.opt.Gate
	if g == nil {
		writeError(w, http.StatusNotFound, "this core keeps no changes")
		return
	}
	id := r.PathValue("change_id")
	// The long poll's own deadlines: the write deadline past the wait (the server's WriteTimeout is shorter), and no
	// read deadline (a GET has no body; an expired one would cancel the request).
	rc := http.NewResponseController(w)
	if err := errors.Join(rc.SetReadDeadline(time.Time{}), rc.SetWriteDeadline(time.Now().Add(timeout+WriteTimeout))); err != nil {
		s.log.ErrorContext(r.Context(), "wait: the connection's deadlines cannot be set", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "this server cannot hold a long poll")
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		woken, cancel, err := g.Watch(id)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "too many calls are waiting; retry")
			return
		}
		c, tk, ok := s.readClearance(w, r)
		if !ok {
			cancel()
			return
		}
		if known == "" {
			known = c.State
		}
		changed := c.State != known
		if !changed {
			select {
			case <-woken:
				cancel()
				continue // re-watch, re-read
			case <-timer.C:
			case <-r.Context().Done():
				cancel()
				return
			}
		}
		cancel()
		out, err := gate.Answer(c, tk)
		if err != nil {
			s.log.ErrorContext(r.Context(), "clearance token unreadable", "error", err.Error())
			writeError(w, http.StatusServiceUnavailable, "the stored token could not be read")
			return
		}
		writeJSON(w, http.StatusOK, WaitAnswer{ClearanceAnswer: out, Changed: changed})
		return
	}
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
