package server

import (
	"fmt"
	"maps"
	"net/http"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
)

// EvaluationResult is POST /access/v1/evaluation's answer: the AuthZEN response (decision, context) plus the
// decision's id and record. decision_id is null when the decision is not recorded (decide.RecordFields nil).
type EvaluationResult struct {
	Decision   bool                   `json:"decision"`
	Context    decide.DecisionContext `json:"context"`
	DecisionID *string                `json:"decision_id"`
	Record     *RecordRef             `json:"record,omitempty"`
}

// RecordRef names a stored evidence record.
type RecordRef struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
	// Duplicate is true when POST /v1/records found the provider's own event (source.event_id) already recorded and
	// answers with that record's reference instead of writing another (O-1). Absent otherwise.
	Duplicate bool `json:"duplicate,omitempty"`
}

// Caller is the `caller` field of a decision or outcome record: the registered provider that asked, and the
// principal it authenticated as. The core establishes it, so it is verified.
func callerField(prov *Provider, p authn.Principal) map[string]any {
	return map[string]any{"provider": prov.Name, "principal": p.ID}
}

// decisionVerified is GatewayVerified plus caller and policy: the core's own decision records.
var decisionVerified = union(evidence.GatewayVerified, "caller", "policy")

// policyField is a decision record's `policy` (the evidence schema's Decision group): ref names the core and each
// policy bundle with its declared version, version is the digest of everything that decided, engine the evaluator.
func policyField(p decide.PolicyRef) map[string]any {
	ref := "clearance-core"
	for _, b := range p.Bundles {
		ref += "+" + b.Name + "@" + b.Version
	}
	return map[string]any{"ref": ref, "version": p.Version, "engine": "cel-go"}
}

func union(base map[string]bool, more ...string) map[string]bool {
	out := maps.Clone(base)
	for _, k := range more {
		out[k] = true
	}
	return out
}

func (s *Server) coreWriter(verified map[string]bool) evidence.Writer {
	w := evidence.Core(s.opt.Version)
	w.Verified = verified
	return w
}

func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) {
	p, prov, ok := s.caller(w, r)
	if !ok {
		return
	}
	req, err := decide.DecodeEvaluation(r.Body)
	if err != nil {
		bodyError(w, err)
		return
	}
	if s.opt.MaxClockSkew > 0 {
		skew := req.Context.Now.Sub(s.opt.Clock())
		if skew > s.opt.MaxClockSkew || -skew > s.opt.MaxClockSkew {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("context.now is more than %s from the core's clock",
				s.opt.MaxClockSkew))
			return
		}
	}
	eng := s.opt.Engine
	resp := eng.Decide(r.Context(), req)
	out := EvaluationResult{Decision: resp.Decision, Context: resp.Context}
	if ev := eng.RecordFields(req, resp); ev != nil {
		ev["caller"] = callerField(prov, p)
		ev["policy"] = policyField(resp.Context.Policy)
		var rec store.Record
		err := s.opt.Store.Atomic(r.Context(), func(tx store.Tx) error {
			var err error
			rec, err = tx.Append(r.Context(), ev, s.coreWriter(decisionVerified))
			return err
		})
		if err != nil {
			// Fail closed: an unrecorded decision is no decision.
			s.log.ErrorContext(r.Context(), "evaluation: recording the decision failed", "error", err.Error())
			writeError(w, http.StatusServiceUnavailable, "the decision could not be recorded")
			return
		}
		ref := refOf(rec)
		id := seqString(ref.Seq)
		out.DecisionID, out.Record = &id, &ref
	}
	writeJSON(w, http.StatusOK, out)
}

func refOf(rec store.Record) RecordRef {
	seq, _ := gate.SeqInt(rec["seq"])
	h, _ := rec["hash"].(string)
	return RecordRef{Seq: seq, Hash: h}
}
