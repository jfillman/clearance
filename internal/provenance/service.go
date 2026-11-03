package provenance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"encoding/json"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
)

// MaxBody is server.py's MAX_BODY for /v1/provenance.
const MaxBody = 4 << 20

// Config is provenance's part of the deployment.
type Config struct {
	// Verifiers are principal globs that may ask for a PR's provenance (CLEARANCE_VERIFIERS).
	Verifiers []string `json:"verifiers"`
	// AgentLogins are the GitHub logins agents open PRs as (AGENT_LOGINS; default the agents' App's bot login).
	AgentLogins []string `json:"agentLogins"`
}

// Service records every verdict: one provenance.verify record per question, in one transaction with the read of
// the receipts.
type Service struct {
	Config Config
	Store  store.Store
	Clock  func() time.Time
	Defs   Lookup
	Writer evidence.Writer // zero: evidence.Core("")
	mu     sync.Mutex
}

// Provenance is Gateway.provenance: the verdicts for one PR, for a CI gate. The caller must be a verifier.
// Errors: *NotVerifier, *BadRequest.
func (s *Service) Provenance(ctx context.Context, p authn.Principal, body any) (Verdict, error) {
	if !pycompat.MatchAny(p.ID, s.Config.Verifiers) {
		return Verdict{}, &NotVerifier{p.ID + " is not a provenance verifier"}
	}
	req, err := ParseRequest(body)
	if err != nil {
		return Verdict{}, err
	}
	return s.verify(ctx, p.ID, req, body)
}

// FromApp is Gateway.provenance_from_app: the same verdicts for the Clearance GitHub App, whose webhook signature
// is its authentication; the record names the installation (app:<id>).
func (s *Service) FromApp(ctx context.Context, installation string, req Request) (Verdict, error) {
	return s.verify(ctx, "app:"+installation, req, req.Body())
}

func (s *Service) verify(ctx context.Context, principal string, req Request, body any) (Verdict, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out Verdict
	err := s.Store.Atomic(ctx, func(tx store.Tx) error {
		receipts, err := tx.Receipts(ctx, req.Repo, int(req.PR), PRTools)
		if err != nil {
			return err
		}
		v := Verify(req, receipts, s.Defs, s.Config.AgentLogins)
		var r RecordSummary
		if v.Record != nil {
			r = *v.Record
		}
		var ruleV any
		if v.Identity.Rule != nil {
			ruleV = *v.Identity.Rule
		} else if v.Scope.Rule != nil {
			ruleV = *v.Scope.Rule
		}
		rec, err := appendAs(ctx, tx, s.Writer.OrCore(), store.Event{
			"ts": pycompat.ISO(s.Clock()), "task_id": r.TaskID, "session": r.Session, "parent": nil,
			"principal": principal, "agent": r.Agent, "tool": "provenance.verify", "tier": nil,
			"decision": "allow", "rule": ruleV, "target": fmt.Sprintf("%s#%d", req.Repo, req.PR),
			"args_sha256": pycompat.ArgsDigest(body),
			"result":      fmt.Sprintf("identity:%s scope:%s", v.Identity.Status, v.Scope.Status)})
		if err != nil {
			return err
		}
		v.AuditSeq = rec["seq"]
		out = v
		return nil
	})
	if err != nil {
		return Verdict{}, fmt.Errorf("provenance: %w", err)
	}
	return out, nil
}

// RecordInstallation is Gateway.record_app_installation: an App installation created, changed or removed.
func (s *Service) RecordInstallation(ctx context.Context, installation, action, account string, repos []string) (store.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var target any
	if account != "" {
		target = account
	}
	if repos == nil {
		repos = []string{}
	}
	var out store.Record
	err := s.Store.Atomic(ctx, func(tx store.Tx) error {
		rec, err := appendAs(ctx, tx, s.Writer.OrCore(), store.Event{
			"ts": pycompat.ISO(s.Clock()), "task_id": nil, "session": nil, "parent": nil,
			"principal": "app:" + installation, "agent": nil, "tool": "app.installation", "tier": nil,
			"decision": "allow", "rule": nil, "target": target, "args_sha256": pycompat.ArgsDigest(repos),
			"result": fmt.Sprintf("%s: %d repositories", action, len(repos))})
		out = rec
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("provenance: %w", err)
	}
	return out, nil
}

// Handler serves POST /v1/provenance.
type Handler struct {
	Svc *Service
	Log *slog.Logger
}

// Routes registers the provenance route.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/provenance", h.serve)
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	p, ok := authn.From(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "a bearer token is required"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the body could not be read"})
		return
	}
	if len(raw) > MaxBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large"})
		return
	}
	body, err := pycompat.Decode(bytes.NewReader(raw))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the body is not JSON"})
		return
	}
	out, err := h.Svc.Provenance(r.Context(), p, body)
	var nv *NotVerifier
	var br *BadRequest
	switch {
	case errors.As(err, &nv):
		writeJSON(w, http.StatusForbidden, map[string]any{"error": nv.Message})
	case errors.As(err, &br):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": br.Message})
	case err != nil:
		if h.Log != nil {
			h.Log.Error("provenance: failed", "error", err.Error())
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
	default:
		writeJSON(w, http.StatusOK, out)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// appendAs is tx.Append with the writer first, so the event literal can close the call.
func appendAs(ctx context.Context, tx store.Tx, w evidence.Writer, ev store.Event) (store.Record, error) {
	return tx.Append(ctx, ev, w)
}
