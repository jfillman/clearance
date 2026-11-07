package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/httpjson"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
)

// The change-bound outcome (G-TF-2): POST /v1/clearances/{change_id}/outcome. The principal that registered a
// terraform-plan change reports what its apply did, once. The core compares the digest of the plan that was applied
// with the digest the change was cleared for and records deploy.outcome with matched; on a mismatch it also records
// deploy.exception of kind digest-mismatch (the shape C-6 defines: exception {kind, expected, observed, detected_at,
// detail}, coverage out-of-band-detected, the change named by change.id). Both records and the change's outcome
// commit in one transaction. A second outcome for the same change is DG-STATE.

// Outcome limits.
const (
	MaxOutcomeBody  = MaxRegisterBody
	MaxOutcomeError = 4 << 10
	// outcomeSkew is how far past the core's clock an outcome's finishedAt may be.
	outcomeSkew = 5 * time.Minute
)

// ApplyActions are the actions of `terraform apply -json`'s apply hooks (apply_start, apply_complete,
// apply_errored: hook.action), as OpenTofu writes them too.
var ApplyActions = []string{"noop", "create", "read", "update", "replace", "delete", "move", "import", "remove", "forget"}

// ApplyStatuses are what became of one resource's apply: apply_complete or apply_errored.
var ApplyStatuses = []string{"complete", "errored"}

// AppliedChange is one resource the apply acted on, from its JSON log: the address, the action and, when the log
// says, whether it completed or errored. Never a value.
type AppliedChange struct {
	Address string `json:"address" contract:"required"`
	Action  string `json:"action" contract:"required"`
	Status  string `json:"status,omitempty"`
}

// OutcomeRequest is POST /v1/clearances/{change_id}/outcome's body: what the apply did. planDigest is the sha256
// of the saved plan file that was applied (re-hashed by the reporter at apply time); changes come from the apply's
// JSON log; error is the apply's error, when it failed (a diagnostic's summary, never a variable's value).
type OutcomeRequest struct {
	Applied    *bool           `json:"applied" contract:"required"`
	PlanDigest string          `json:"planDigest" contract:"required"`
	Changes    []AppliedChange `json:"changes"`
	StartedAt  string          `json:"startedAt" contract:"required"`
	FinishedAt string          `json:"finishedAt" contract:"required"`
	Error      string          `json:"error,omitempty"`
}

// Outcome is a change's recorded outcome: the deploy.outcome record's seq, whether the apply ran and whether its
// plan was the cleared one, the digest it reported, when the core recorded it, and on a mismatch the
// deploy.exception's seq.
type Outcome struct {
	Seq        int64  `json:"seq"`
	Applied    bool   `json:"applied"`
	Matched    bool   `json:"matched"`
	PlanDigest string `json:"plan_digest,omitempty"`
	At         string `json:"at"`
	Exception  *int64 `json:"exception,omitempty"`
	// Digest, Release, Hash and Provider are a manifest change's outcome as its provider reported it through
	// POST /v1/records (G-ARGO-6): the digest it applied (bare hex; matched is whether it is the cleared tree), the
	// release it names (release {id}), the deploy.outcome record's hash (with seq, the join key into the chain) and
	// the provider. Claimed by the provider; the core did not observe the target.
	Digest   string `json:"digest,omitempty"`
	Release  string `json:"release,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Provider string `json:"provider,omitempty"`
}

// RecordOutcome appends a provider's deploy.outcome record and, in the same transaction, sets the outcome of the
// manifest change it names (the latest outcome stands: an Application can sync more than once), so the change's
// view shows what the deploy reported, with the release it names and the record's seq and hash
// (GET /v1/clearances/{id}). An outcome that names no change, or one the core does not know, is only recorded. A
// terraform-plan change takes its outcome through POST /v1/clearances/{id}/outcome, not here. Judging the outcome
// (an exception for a mismatch) is the provider's report to make; the attestation signer is notified by the caller.
func (s *Service) RecordOutcome(ctx context.Context, ev store.Event, wr evidence.Writer) (store.Record, error) {
	// An outcome whose change names no valid id (the agent sends change {tree} for objects that carry no grant) is
	// still recorded: the id is only needed to set a change's outcome.
	id, err := changeRef(ev)
	if err != nil {
		id = ""
	}
	var out store.Record
	err = s.op(ctx, func(tx store.Tx, w *writer) error {
		rec, err := tx.Append(ctx, ev, wr)
		if err != nil {
			return err
		}
		out = rec
		if id == "" || s.Config.Off {
			return nil
		}
		c, err := load(ctx, tx, id)
		if err != nil {
			return err
		}
		if c == nil || (c.Subject != nil && c.Subject.Kind == KindTerraformPlan) {
			return nil
		}
		seq, ok := SeqInt(rec["seq"])
		if !ok {
			return nil
		}
		oc, _ := ev["outcome"].(map[string]any)
		applied, _ := oc["applied"].(bool)
		digest := ""
		if dg, _ := oc["digests"].(map[string]any); dg != nil {
			digest, _ = dg["sha256"].(string)
		}
		digest = strings.TrimPrefix(digest, "sha256:")
		rel, _ := ev["release"].(map[string]any)
		relID, _ := rel["id"].(string)
		hash, _ := rec["hash"].(string)
		prov, _ := rec["provider"].(string)
		at := pycompat.ISO(w.now)
		c.Outcome = &Outcome{Seq: seq, Applied: applied, Matched: digest != "" && digest == strings.TrimPrefix(c.TreeDigest, "sha256:"),
			At: at, Digest: digest, Release: relID, Hash: hash, Provider: prov}
		c.UpdatedAt = PyTime{w.now}
		w.put(c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// OutcomeResult is the outcome route's answer: the change as recorded (with its outcome), whether the plan matched,
// the deploy.outcome record's seq and the deploy.exception's (null when it matched).
type OutcomeResult struct {
	Change       *Change `json:"change" contract:"required"`
	Matched      bool    `json:"matched"`
	AuditSeq     int64   `json:"audit_seq"`
	ExceptionSeq *int64  `json:"exception_seq"`
}

// checked is an OutcomeRequest that passed check: the digest bare, the times parsed.
type checked struct {
	applied           bool
	digest            string
	changes           []AppliedChange
	started, finished time.Time
	err               string
}

// check validates the body (a *BadChange when it is not valid).
func (r OutcomeRequest) check(now time.Time) (checked, error) {
	var o checked
	if r.Applied == nil {
		return o, bad("applied is required: whether the apply ran")
	}
	o.applied = *r.Applied
	if !treeRx.MatchString(r.PlanDigest) {
		return o, bad("planDigest is the sha256 of the saved plan file that was applied")
	}
	o.digest = bareHex(r.PlanDigest)
	if len(r.Changes) > MaxResources {
		return o, bad("changes is a list of at most %d applied resource changes", MaxResources)
	}
	o.changes = make([]AppliedChange, 0, len(r.Changes))
	for _, c := range r.Changes {
		if !printable(c.Address, 1024) || !slices.Contains(ApplyActions, c.Action) ||
			(c.Status != "" && !slices.Contains(ApplyStatuses, c.Status)) {
			return o, bad("changes[] are {address, action, status}: a resource address, one of %v, and complete or errored", ApplyActions)
		}
		o.changes = append(o.changes, c)
	}
	var err error
	if o.started, err = time.Parse(time.RFC3339, r.StartedAt); err != nil {
		return o, bad("startedAt is an RFC 3339 time")
	}
	if o.finished, err = time.Parse(time.RFC3339, r.FinishedAt); err != nil {
		return o, bad("finishedAt is an RFC 3339 time")
	}
	if o.finished.Before(o.started) || o.finished.After(now.Add(outcomeSkew)) {
		return o, bad("finishedAt is not before startedAt, and not in the future")
	}
	if len(r.Error) > MaxOutcomeError || !utf8.ValidString(r.Error) || strings.ContainsRune(r.Error, 0) {
		return o, bad("error is a string of at most %d bytes", MaxOutcomeError)
	}
	o.err = r.Error
	return o, nil
}

// Outcome records the outcome of the apply of a cleared terraform-plan change, for the principal that registered
// it. Errors: *BadChange (400), *Error (DG-OFF, DG-UNKNOWN 404, DG-FORBIDDEN 403, DG-SUBJECT 400, DG-STATE 409).
func (s *Service) Outcome(ctx context.Context, p authn.Principal, changeID string, req OutcomeRequest) (OutcomeResult, error) {
	if err := s.gateOn(); err != nil {
		return OutcomeResult{}, err
	}
	o, err := req.check(s.now())
	if err != nil {
		return OutcomeResult{}, err
	}
	var out OutcomeResult
	err = s.op(ctx, func(tx store.Tx, w *writer) error {
		c, err := load(ctx, tx, changeID)
		if err != nil {
			return err
		}
		if c == nil {
			return gerr("DG-UNKNOWN", "no such change", "", 404)
		}
		if p.ID != c.RegisteredBy && !s.SameRepoWorkflow(c, p) {
			return gerr("DG-FORBIDDEN", p.ID+" did not register this change",
				"Only the principal that registered a change reports its outcome (the same workflow, the same verifier, or, for a plan registered by a GitHub Actions workflow, another job of that repository's workflows).", 403)
		}
		if c.Subject == nil || c.Subject.Kind != KindTerraformPlan {
			return gerr("DG-SUBJECT", "this route takes the outcome of a terraform-plan change",
				"A manifest change's provider reports deploy.outcome through POST /v1/records.", 400)
		}
		if c.Outcome != nil {
			return gerr("DG-STATE", fmt.Sprintf("this change's outcome is already recorded (seq %d)", c.Outcome.Seq),
				"One outcome per change: a new plan registers a new change.", 409)
		}
		if c.State != StateCleared {
			return gerr("DG-STATE", "this change is "+c.State+": only a cleared change has an outcome",
				"Apply a plan only once its change is cleared.", 409)
		}
		cleared := c.Subject.PlanDigest
		matched := o.digest == cleared
		args := outcomeArgs(req)
		changes := make([]any, 0, len(o.changes))
		for _, ch := range o.changes {
			m := map[string]any{"address": ch.Address, "action": ch.Action}
			if ch.Status != "" {
				m["status"] = ch.Status
			}
			changes = append(changes, m)
		}
		outcome := map[string]any{"applied": o.applied, "digests": map[string]any{"sha256": o.digest}, "changes": changes,
			"started_at": o.started.UTC().Format(time.RFC3339), "finished_at": o.finished.UTC().Format(time.RFC3339)}
		if o.err != "" {
			outcome["error"] = o.err
		}
		dest := destinationOf(c)
		rec := w.recordVerified([]string{"matched"}, func() store.Record {
			return w.record(p.ID, nil, "deploy.outcome", c, "", nil, outcomeLine(o, matched, cleared), args,
				map[string]any{"decision": nil, "matched": matched, "outcome": outcome, "destination": dest})
		})
		seq, _ := SeqInt(recordSeq(rec))
		var exc *int64
		if !matched {
			detail := fmt.Sprintf("deploy.outcome seq %d reports the plan sha256:%s; the change was cleared for sha256:%s",
				seq, o.digest, cleared)
			x := w.record(p.ID, nil, KindException, c, "", nil, "digest mismatch: what was applied is not what was cleared", args,
				map[string]any{"decision": nil, "coverage": "out-of-band-detected", "destination": dest,
					"exception": map[string]any{"kind": "digest-mismatch", "expected": "sha256:" + cleared,
						"observed": "sha256:" + o.digest, "detected_at": w.now.Format(time.RFC3339), "detail": detail}})
			if n, ok := SeqInt(recordSeq(x)); ok {
				exc = &n
			}
		}
		now := PyTime{w.now}
		if exc != nil {
			// What was applied is not what was cleared: the change leaves cleared for exception (C-6), and its token
			// is revoked in this transaction (deploy.revoke).
			w.move(c, StateException, "exception: digest-mismatch", map[string]any{"exception": *exc, "kind": "digest-mismatch"})
			c.Ended = &Ended{Seq: *exc, Tool: KindException, Kind: "digest-mismatch"}
			c.DecidedAt = &now
			w.settle(c)
		}
		c.Outcome = &Outcome{Seq: seq, Applied: o.applied, Matched: matched, PlanDigest: o.digest, At: pycompat.ISO(w.now), Exception: exc}
		c.UpdatedAt = now
		w.put(c)
		out = OutcomeResult{c.View(), matched, seq, exc}
		return nil
	})
	if err == nil && out.Matched && out.Change != nil && s.OnOutcome != nil {
		s.OnOutcome(changeID, out.AuditSeq)
	}
	return out, err
}

// outcomeArgs is the body the records' args_sha256 digests: the request as sent.
func outcomeArgs(r OutcomeRequest) any {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil
	}
	v, err := pycompat.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	return v
}

// outcomeLine is deploy.outcome's result: whether it ran, whether the plan was the cleared one, and the counts.
func outcomeLine(o checked, matched bool, cleared string) string {
	word := "applied"
	if !o.applied {
		word = "not applied"
	}
	n := map[string]int{}
	for _, c := range o.changes {
		n[c.Action]++
	}
	var parts []string
	for _, a := range ApplyActions {
		if n[a] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[a], a))
		}
	}
	line := word
	if len(parts) > 0 {
		line += " (" + strings.Join(parts, ", ") + ")"
	}
	if matched {
		line += ": the cleared plan"
	} else {
		line += fmt.Sprintf(": plan sha256:%s is not the cleared sha256:%s", pycompat.Truncate(o.digest, 12), pycompat.Truncate(cleared, 12))
	}
	if o.err != "" {
		line += ": " + pycompat.Truncate(o.err, 200)
	}
	return line
}

// destinationOf is a change's destination for its outcome records: the environment, and the cluster when it has one
// (a plan has none).
func destinationOf(c *Change) map[string]any {
	d := map[string]any{"environment": c.Env}
	if c.Cluster != "" {
		d["cluster"] = c.Cluster
	}
	return d
}

// recordVerified runs fn with the writer's verified set extended by fields the core establishes itself on that
// record (deploy.outcome's matched: the core compared the digests).
func (w *writer) recordVerified(fields []string, fn func() store.Record) store.Record {
	saved := w.wr
	base := w.wr.Verified
	if base == nil {
		base = evidence.GatewayVerified
	}
	v := make(map[string]bool, len(base)+len(fields))
	for k, ok := range base {
		v[k] = ok
	}
	for _, f := range fields {
		v[f] = true
	}
	w.wr.Verified = v
	defer func() { w.wr = saved }()
	return fn()
}

// outcome is POST /v1/clearances/{change_id}/outcome: the body strictly decoded (unknown fields refused), at most
// MaxOutcomeBody.
func (h *Handler) outcome(w http.ResponseWriter, r *http.Request) {
	p, ok := authn.From(r.Context())
	if !ok {
		httpjson.Write(w, http.StatusUnauthorized, map[string]any{"error": "a bearer token is required"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxOutcomeBody+1))
	if err != nil {
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": "the body could not be read"})
		return
	}
	if len(raw) > MaxOutcomeBody {
		httpjson.Write(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large"})
		return
	}
	var req OutcomeRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		msg := "the body is {applied, planDigest, changes, startedAt, finishedAt, error}"
		if err != nil {
			msg += ": " + err.Error()
		}
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": msg})
		return
	}
	out, err := h.Svc.Outcome(r.Context(), p, r.PathValue("change_id"), req)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpjson.Write(w, http.StatusOK, out)
}

// workflowRepo is the "owner/name" (lower-cased) of a GitHub Actions principal id (github:repo:owner/name:<ref or
// environment>), or "" for any other principal.
func workflowRepo(id string) string {
	rest, ok := strings.CutPrefix(id, "github:repo:")
	if !ok {
		return ""
	}
	repo, _, _ := strings.Cut(rest, ":")
	return strings.ToLower(repo)
}

// SameRepoWorkflow reports whether p may read and report a terraform-plan change that a GitHub Actions workflow
// registered, although p is not that exact principal. The plan is held in one job (sub ...:ref:refs/heads/main) and
// released and applied in another, inside a GitHub environment (sub ...:environment:lab), so the subjects differ.
// It holds only for a terraform-plan change, a registrant and a caller that are both workflows of one repository (the
// repository DG-REPO bound at registration, and the caller's own verified claim when it has one), and a caller that
// is still a configured verifier. Every other change kind keeps the exact-registrant rule.
func (s *Service) SameRepoWorkflow(c *Change, p authn.Principal) bool {
	if c == nil || c.Subject == nil || c.Subject.Kind != KindTerraformPlan {
		return false
	}
	repo := workflowRepo(c.RegisteredBy)
	if repo == "" || repo != workflowRepo(p.ID) || repo != strings.ToLower(c.Repo) {
		return false
	}
	if claim, ok := p.Claims["repository"].(string); ok && strings.ToLower(claim) != repo {
		return false
	}
	return pycompat.MatchAny(p.ID, s.Config.Verifiers)
}
