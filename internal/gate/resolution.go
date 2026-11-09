package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strconv"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/httpjson"
	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/vocab"
)

// A person's resolution of an observation (O-5). A collector writes the first resolution of an observation it
// reported (still-live, or reverted when it saw the revert); a person sets what a human knows: why it happened, or that
// it was ratified. The write is a `resolution` record like the collector's, about the same observation, so the
// newest record about a seq is the resolution (observe.Build reads it that way) and an edit never rewrites one: it is a
// new record, and every earlier one stays in the chain. The record names the person: principal, initiator {sub, iss}
// (a delegate's name is in iss, as for every person-acting route) and resolution.by. An admin (CLEARANCE_ADMINS), or a
// delegate naming one, may write it, as for break-glass: a resolution changes what an auditor reads as explained.
const (
	// MaxResolutionBody caps POST /v1/observations/{seq}/resolution.
	MaxResolutionBody = 16 << 10
)

// ResolutionRequest is POST /v1/observations/{seq}/resolution's body.
type ResolutionRequest struct {
	// State is reverted, ratified, declared-break-glass or still-live (observe.ResolutionStates).
	State string `json:"state" contract:"required"`
	// Cause is one of observe.RevertCauses, and only for state reverted.
	Cause *string `json:"cause,omitempty"`
	// Note is free text (at most 4 KiB) beside it.
	Note *string `json:"note,omitempty"`
}

// ResolutionRecorded is the answer: the record written, and who it names.
type ResolutionRecorded struct {
	Seq   int64   `json:"seq"`
	About int64   `json:"about"`
	Scope string  `json:"scope"`
	State string  `json:"state"`
	Cause *string `json:"cause"`
	Note  *string `json:"note"`
	// By is the person the record names; Via the delegate that acted for them (null: they signed in themselves).
	By  string  `json:"by"`
	Via *string `json:"via"`
	TS  string  `json:"ts"`
}

// SetResolution is POST /v1/observations/{seq}/resolution. Errors: *Error (DG-PERSON, DG-DELEGATE, DG-RESOLUTION 403 for a
// person who is not an admin, 400 for a state or cause outside the vocabulary, 404 for a seq that is not an
// observation).
func (s *Service) SetResolution(ctx context.Context, p authn.Principal, about int64, req ResolutionRequest, onBehalfOf string) (*ResolutionRecorded, error) {
	if err := s.gateOn(); err != nil {
		return nil, err
	}
	person, via, who, err := s.admin(ctx, p, onBehalfOf)
	if err != nil {
		return nil, err
	}
	res := map[string]any{"state": req.State, "by": person}
	if req.Cause != nil {
		res["cause"] = *req.Cause
	}
	if req.Note != nil {
		res["note"] = *req.Note
	}
	var out *ResolutionRecorded
	err = s.op(ctx, func(tx store.Tx, w *writer) error {
		rs, err := tx.Records(ctx, about, 1)
		if err != nil {
			return err
		}
		if len(rs) == 0 {
			return gerr("DG-UNKNOWN", "no such observation", "", 404)
		}
		o := rs[0]
		if seq, _ := SeqInt(o["seq"]); seq != about || o["tool"] != evidence.KindObservation {
			return gerr("DG-UNKNOWN", fmt.Sprintf("seq %d is not an observation: a person resolves an observation", about),
				"List the scope's observations with GET /v1/observations.", 404)
		}
		scope, _ := o["scope"].(string)
		ev := store.Event{
			"ts": evidence.ISO(w.now), "tool": evidence.KindResolution, "boundary": "deployment",
			"task_id": nil, "session": nil, "parent": nil, "principal": person, "agent": nil, "target": nil,
			"decision": nil, "rule": nil, "args_sha256": nil, "tier": nil,
			"result":     fmt.Sprintf("observation %d resolved %s by %s", about, req.State, person),
			"scope":      scope,
			"about":      map[string]any{"seq": json.Number(strconv.FormatInt(about, 10))},
			"resolution": res,
			"initiator":  map[string]any{"sub": who.sub, "iss": who.iss},
		}
		if _, err := observe.Check(evidence.KindResolution, ev, vocab.Get()); err != nil {
			return &Error{Rule: "DG-RESOLUTION", Message: err.Error(), Status: http.StatusBadRequest,
				Hint: fmt.Sprintf("state is one of %v; a reverted resolution names its cause, one of %v.", observe.ResolutionStates, observe.RevertCauses)}
		}
		wr := w.wr
		v := maps.Clone(evidence.GatewayVerified)
		for _, k := range []string{"scope", "about", "resolution", "initiator", "ts"} {
			v[k] = true
		}
		if via != nil {
			delete(v, "initiator") // a delegate asked: the person is named by the delegate, not signed in
		}
		wr.Verified = v
		rec := w.appendWith(ev, wr)
		if w.err != nil {
			return w.err
		}
		seq, _ := SeqInt(rec["seq"])
		out = &ResolutionRecorded{Seq: seq, About: about, Scope: scope, State: req.State, Cause: req.Cause, Note: req.Note,
			By: person, Via: via, TS: evidence.ISO(w.now)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (h *Handler) setResolution(w http.ResponseWriter, r *http.Request) {
	p, ok := authn.From(r.Context())
	if !ok {
		httpjson.Write(w, http.StatusUnauthorized, map[string]any{"error": "a bearer token is required"})
		return
	}
	about, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
	if err != nil || about < 0 {
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": "seq is the seq of an observation"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxResolutionBody+1))
	if err != nil {
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": "the body could not be read"})
		return
	}
	if len(raw) > MaxResolutionBody {
		httpjson.Write(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large"})
		return
	}
	var req ResolutionRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		msg := "the body is {state, cause?, note?}"
		if err != nil {
			msg += ": " + err.Error()
		}
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": msg})
		return
	}
	out, err := h.Svc.SetResolution(r.Context(), p, about, req, r.Header.Get(vocab.Get().OnBehalfOfHeader))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpjson.Write(w, http.StatusOK, out)
}
