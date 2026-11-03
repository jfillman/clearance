package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/scope"
	"github.com/jfillman/clearance/internal/store"
)

// Outcome limits.
const (
	MaxResultBytes = 4 << 10
	MaxReceiptKeys = 32
	MaxReceiptText = 1 << 10
)

// OutcomeRequest is POST /v1/decisions/{id}/outcome's body: what the provider saw when it acted on an allowed
// decision.
type OutcomeRequest struct {
	// Result is the call's result line ("ok", "error:<Kind>", a handler's refusal), as the Python gateway recorded it.
	Result string `json:"result" contract:"required"`
	// Effect is the receipt of a write (dispatch.py _effect): for a pull request repo, pr, commit, branch and the
	// paths its commit carried. Only for a tool whose spec has a receipt or writes files.
	Effect *Effect `json:"effect,omitempty"`
	// Receipt is the provider's own reference for the call (a backend's id, a URL): flat, scalar values only.
	Receipt map[string]any `json:"receipt,omitempty"`
	// Refusal is a refusal the provider's handler made after the core allowed the call (a rule the core cannot see:
	// the gateway's launch R004/R001, the inbox's HR-*, artifacts' ART-*), with its rule and message, as the Python
	// gateway's deny record carried them. The record keeps the decision's own decision and rule (verified) and adds
	// refusal (claimed).
	Refusal *Refusal `json:"refusal,omitempty"`
}

// Refusal is a handler's refusal: its rule id and message.
type Refusal struct {
	Rule    string `json:"rule" contract:"required"`
	Message string `json:"message" contract:"required"`
}

// Effect is a write's receipt; provenance reads it (store.Reader.Receipts on effect.repo and effect.pr).
type Effect struct {
	Repo   string   `json:"repo,omitempty"`
	PR     int64    `json:"pr,omitempty"`
	Commit string   `json:"commit,omitempty"`
	Branch string   `json:"branch,omitempty"`
	Paths  []string `json:"paths,omitempty"`
}

var (
	repoRx   = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z`)
	commitRx = regexp.MustCompile(`^[0-9a-f]{7,64}\z`)
	ruleRx   = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*\z`)
	seqRx    = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})\z`)
)

// copied are the decision record's fields an outcome record repeats: the core read them from its own record, so
// they are verified on the outcome too.
var copied = []string{"task_id", "session", "parent", "principal", "agent", "tool", "tier", "decision", "rule",
	"target", "args_sha256", "app"}

// outcomeVerified: provider, ts and outcome_of the core sets, caller it authenticated, and the copied fields.
var outcomeVerified = union(evidence.ProviderVerified, append([]string{"ts", "outcome_of", "caller"}, copied...)...)

func (s *Server) outcome(w http.ResponseWriter, r *http.Request) {
	p, prov, ok := s.caller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !seqRx.MatchString(id) {
		writeError(w, http.StatusNotFound, "no such decision")
		return
	}
	seq, _ := strconv.ParseInt(id, 10, 64)
	var body OutcomeRequest
	if err := strictDecode(r.Body, &body); err != nil {
		bodyError(w, err)
		return
	}
	effect, err := body.validate()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.outcomeMu.Lock()
	defer s.outcomeMu.Unlock()
	if s.outcomes[seq] {
		writeError(w, http.StatusConflict, "decision "+id+" already has an outcome")
		return
	}
	var rec store.Record
	var refusal *httpError
	err = s.opt.Store.Atomic(r.Context(), func(tx store.Tx) error {
		recs, err := tx.Records(r.Context(), seq, 1)
		if err != nil {
			return err
		}
		if len(recs) == 0 {
			refusal = &httpError{http.StatusNotFound, "no such decision"}
			return errRefused
		}
		d := recs[0]
		caller, isDecision := d["caller"].(map[string]any)
		if !isDecision || d["outcome_of"] != nil {
			refusal = &httpError{http.StatusNotFound, "no such decision"}
			return errRefused
		}
		if caller["provider"] != prov.Name {
			refusal = &httpError{http.StatusForbidden, "decision " + id + " was asked for by another provider"}
			return errRefused
		}
		if d["decision"] != "allow" {
			refusal = &httpError{http.StatusConflict, "decision " + id + " was a deny: there is no outcome to record"}
			return errRefused
		}
		if effect != nil {
			tool, _ := d["tool"].(string)
			spec := s.opt.Engine.Tool(tool)
			if spec == nil || (len(spec.Receipt) == 0 && !spec.WritesFiles) {
				refusal = &httpError{http.StatusBadRequest, fmt.Sprintf("%s has no receipt: effect is not accepted", tool)}
				return errRefused
			}
		}
		ev := store.Event{"ts": evidence.ISO(s.opt.Clock())}
		for _, k := range copied {
			if v, present := d[k]; present {
				ev[k] = v
			}
		}
		if b, ok := d["boundary"]; ok {
			ev["boundary"] = b
		}
		ev["result"] = body.Result
		if effect != nil {
			ev["effect"] = effect
		}
		if len(body.Receipt) > 0 {
			ev["receipt"] = body.Receipt
		}
		if body.Refusal != nil {
			ev["refusal"] = map[string]any{"rule": body.Refusal.Rule, "message": body.Refusal.Message}
		}
		ev["outcome_of"] = map[string]any{"seq": json.Number(id), "hash": d["hash"]}
		ev["caller"] = callerField(prov, p)
		wr := prov.Writer()
		wr.Verified = outcomeVerified
		rec, err = tx.Append(r.Context(), ev, wr)
		return err
	})
	switch {
	case refusal != nil:
		writeError(w, refusal.status, refusal.msg)
		return
	case errors.Is(err, evidence.ErrInvalid), errors.Is(err, evidence.ErrNotStorable):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "outcome: recording failed", "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the outcome could not be recorded")
		return
	}
	s.outcomes[seq] = true
	writeJSON(w, http.StatusOK, refOf(rec))
}

type httpError struct {
	status int
	msg    string
}

var errRefused = errors.New("refused")

// validate checks the body and returns the effect as the record stores it (nil without one): repo lowercased,
// paths normalised, sorted and unique, as dispatch.py _effect built it.
func (b *OutcomeRequest) validate() (map[string]any, error) {
	if b.Result == "" || len(b.Result) > MaxResultBytes || !utf8.ValidString(b.Result) || strings.ContainsRune(b.Result, 0) {
		return nil, fmt.Errorf("result is a non-empty string of at most %d bytes", MaxResultBytes)
	}
	if f := b.Refusal; f != nil {
		if len(f.Rule) > 64 || !ruleRx.MatchString(f.Rule) {
			return nil, errors.New("refusal.rule is a rule id (R004, HR-003, ART-002)")
		}
		if f.Message == "" || len(f.Message) > MaxResultBytes || !utf8.ValidString(f.Message) ||
			strings.ContainsRune(f.Message, 0) {
			return nil, fmt.Errorf("refusal.message is a non-empty string of at most %d bytes", MaxResultBytes)
		}
		if b.Effect != nil {
			return nil, errors.New("a refused call made no write: refusal and effect do not go together")
		}
	}
	if len(b.Receipt) > MaxReceiptKeys {
		return nil, fmt.Errorf("receipt has at most %d keys", MaxReceiptKeys)
	}
	for k, v := range b.Receipt {
		if k == "" || len(k) > 64 {
			return nil, errors.New("receipt keys are 1 to 64 characters")
		}
		switch x := v.(type) {
		case string:
			if len(x) > MaxReceiptText || strings.ContainsRune(x, 0) {
				return nil, fmt.Errorf("receipt.%s is a string of at most %d bytes", k, MaxReceiptText)
			}
		case bool, nil:
		default:
			if _, isNum := pycompat.AsInt(v); !isNum {
				return nil, fmt.Errorf("receipt.%s is a string, an integer, a boolean or null", k)
			}
		}
	}
	e := b.Effect
	if e == nil {
		return nil, nil
	}
	out := map[string]any{}
	if e.Repo != "" {
		if !repoRx.MatchString(e.Repo) {
			return nil, errors.New("effect.repo is owner/name")
		}
		out["repo"] = strings.ToLower(e.Repo)
	}
	if e.PR != 0 {
		if e.PR < 1 || e.Repo == "" {
			return nil, errors.New("effect.pr is a positive integer, with effect.repo")
		}
		out["pr"] = json.Number(strconv.FormatInt(e.PR, 10))
	}
	if e.Commit != "" {
		if !commitRx.MatchString(e.Commit) {
			return nil, errors.New("effect.commit is a hex commit sha")
		}
		out["commit"] = e.Commit
	}
	if e.Branch != "" {
		if len(e.Branch) > 255 || strings.ContainsAny(e.Branch, "\x00 ~^:?*[\\") {
			return nil, errors.New("effect.branch is not a branch name")
		}
		out["branch"] = e.Branch
	}
	if e.Paths != nil {
		if len(e.Paths) > provenance.MaxPaths {
			return nil, fmt.Errorf("effect.paths holds at most %d paths", provenance.MaxPaths)
		}
		ps := make([]string, 0, len(e.Paths))
		for _, p := range e.Paths {
			n, ok := normalPath(p)
			if !ok {
				return nil, fmt.Errorf("effect.paths: %q is not a path inside the repository", p)
			}
			ps = append(ps, n)
		}
		slices.Sort(ps)
		list := []any{}
		for _, p := range slices.Compact(ps) {
			list = append(list, p)
		}
		out["paths"] = list
	}
	if len(out) == 0 {
		return nil, errors.New("effect is empty")
	}
	return out, nil
}

// normalPath is scope.normalize (internal/scope) on a path of at most 4096 bytes.
func normalPath(p string) (string, bool) {
	if len(p) > 4096 {
		return "", false
	}
	n, err := scope.Normalize(p)
	return n, err == nil
}
