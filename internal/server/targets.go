package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/targets"
)

// MaxTargetsBody is PUT /v1/targets/{source}'s body cap.
const MaxTargetsBody = targets.MaxBody

// TargetsRequest is PUT /v1/targets/{source}'s body: every target the source declares. It replaces the set the core
// holds for that source (an empty list withdraws all of it); other sources' targets are untouched.
type TargetsRequest struct {
	Targets []targets.Target `json:"targets" contract:"required"`
}

// TargetsResult is what a publish did: the source, the content address of the set now held (sha256 hex of its
// canonical JSON, sorted by id), how many targets it declares, and whether it differs from what the core held. A
// changed publish is one targets.load record (its seq is in `seq`); an unchanged one records nothing.
type TargetsResult struct {
	Source  string `json:"source"`
	Digest  string `json:"digest"`
	Targets int    `json:"targets"`
	Changed bool   `json:"changed"`
	Seq     *int64 `json:"seq"`
}

// targetsVerified: what the core establishes on a targets.load record. It authenticated the caller, set ts and chose
// the record's kind; the source, the digest and the count are the core's own computation from the body it validated.
var targetsVerified = union(evidence.ProviderVerified, "ts", "caller", "tool", "tier", "decision", "rule",
	"task_id", "session", "parent", "target", "args_sha256", "result")

func (s *Server) publishTargets(w http.ResponseWriter, r *http.Request) {
	p, prov, ok := s.caller(w, r)
	if !ok {
		return
	}
	source := r.PathValue("source")
	if !targets.SourceRx.MatchString(source) {
		writeError(w, http.StatusBadRequest, "source is a lower-case name (the cluster or account that publishes)")
		return
	}
	if !prov.mayPublishTargets(source) {
		writeError(w, http.StatusForbidden, fmt.Sprintf("provider %q may not publish targets for source %q", prov.Name, source))
		return
	}
	// A source belongs to the first provider that lists it: another provider's publish for it is refused.
	for i := range s.opt.Providers {
		if o := &s.opt.Providers[i]; o.mayPublishTargets(source) {
			if o.Name != prov.Name {
				writeError(w, http.StatusForbidden, fmt.Sprintf("source %q belongs to provider %q", source, o.Name))
				return
			}
			break
		}
	}
	var body TargetsRequest
	if err := strictDecode(r.Body, &body); err != nil {
		bodyError(w, err)
		return
	}
	ts, err := targets.Normalize(body.Targets)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	digest := targets.Digest(ts)
	s.targetsMu.Lock()
	defer s.targetsMu.Unlock()
	out := TargetsResult{Source: source, Digest: digest, Targets: len(ts)}
	err = s.opt.Store.Atomic(r.Context(), func(tx store.Tx) error {
		held, err := tx.Targets(r.Context())
		if err != nil {
			return err
		}
		was := ""
		for _, h := range held {
			if h.Source == source {
				was = h.Digest
			}
		}
		if was == digest {
			return nil
		}
		doc, err := json.Marshal(ts)
		if err != nil {
			return err
		}
		if err := tx.PutTargets(r.Context(), store.TargetSet{Source: source, Digest: digest, Doc: doc}); err != nil {
			return err
		}
		result := fmt.Sprintf("%d targets sha256:%s", len(ts), digest)
		if was != "" {
			result += " (was sha256:" + was + ")"
		}
		rec, err := tx.Append(r.Context(), store.Event{"ts": pycompat.ISO(s.opt.Clock()), "task_id": nil, "session": nil,
			"parent": nil, "principal": "provider:" + prov.Name, "agent": nil, "tool": "targets.load", "tier": nil,
			"decision": "allow", "rule": nil, "target": "targets:" + source, "args_sha256": digest, "result": result,
			"caller": callerField(prov, p)}, s.coreWriter(targetsVerified))
		if err != nil {
			return err
		}
		seq, _ := gate.SeqInt(rec["seq"])
		out.Changed, out.Seq = true, &seq
		return nil
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "targets: publishing failed", "source", source, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the targets could not be recorded")
		return
	}
	writeJSON(w, http.StatusOK, out)
}
