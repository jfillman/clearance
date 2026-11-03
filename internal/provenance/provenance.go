// Package provenance answers whether a pull request is the one a Clearance session opened, and whether what it
// changes is inside that agent's scope (provenance.py): the agent-identity and agent-scope verdicts a CI gate (or
// the Clearance GitHub App) posts on every PR. The evidence is the receipt Clearance wrote when its own call opened
// the PR; nothing the PR says about itself is trusted.
//
//	identity  confirmed | not-agent | AI001 forged trailers | AI002 agents' login, no record | AI003 commits added
//	          after the agent's | AI004 trailers differ from the record
//	scope     in-scope | not-agent | AS001 a path the agent's commit did not carry | AS002 a path the definition
//	          denies | AS003 the repo left repos.allow | AS004 the definition is gone
package provenance

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
)

// PRTools are the tools whose receipt is a pull request. glidepath.cicd.propose is the Hangar pack's.
var PRTools = []string{"repo.pr.open", "repo.pr.open_upper", "glidepath.cicd.propose"}

// TrailerKeys are the commit trailers compared with the receipt.
var TrailerKeys = []string{"task", "session", "run", "agent"}

// MaxPaths caps a request's paths.
const MaxPaths = 3000

var (
	shaRx  = regexp.MustCompile(`^[0-9a-f]{40}\z`)
	repoRx = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z`)
)

// BadRequest is provenance.BadRequest (400).
type BadRequest struct{ Message string }

func (e *BadRequest) Error() string { return e.Message }

// NotVerifier is provenance.NotVerifier (403).
type NotVerifier struct{ Message string }

func (e *NotVerifier) Error() string { return e.Message }

// Request is one PR as the caller (or the App) gathered it.
type Request struct {
	Repo     string
	PR       int64
	Head     string
	Paths    []string
	Author   string
	Trailers map[string]string // lower-cased keys, only TrailerKeys
}

var requestKeys = map[string]bool{"repo": true, "pr": true, "head": true, "paths": true, "author": true, "trailers": true}

// ParseRequest is Request.from_dict, refusing unknown fields (strict decoding; provenance.py ignored them).
func ParseRequest(v any) (Request, error) {
	d, ok := v.(map[string]any)
	if !ok {
		return Request{}, &BadRequest{"the body is a JSON object"}
	}
	repo, _ := d["repo"].(string)
	if _, isStr := d["repo"].(string); !isStr || !repoRx.MatchString(repo) {
		return Request{}, &BadRequest{"repo is owner/name"}
	}
	pr, isInt := pycompat.AsInt(d["pr"])
	if !isInt || pr < 1 {
		return Request{}, &BadRequest{"pr is a positive integer"}
	}
	head, isStr := d["head"].(string)
	if !isStr || !shaRx.MatchString(head) {
		return Request{}, &BadRequest{"head is a 40-character commit sha"}
	}
	rawPaths, isList := d["paths"].([]any)
	if !isList || len(rawPaths) > MaxPaths {
		return Request{}, &BadRequest{fmt.Sprintf("paths is a list of at most %d strings", MaxPaths)}
	}
	paths := make([]string, 0, len(rawPaths))
	for _, p := range rawPaths {
		s, ok := p.(string)
		if !ok {
			return Request{}, &BadRequest{fmt.Sprintf("paths is a list of at most %d strings", MaxPaths)}
		}
		paths = append(paths, s)
	}
	author := ""
	if v, present := d["author"]; present {
		s, ok := v.(string)
		if !ok {
			return Request{}, &BadRequest{"author is a string"}
		}
		author = s
	}
	known := map[string]string{}
	if v := d["trailers"]; truthy(v) {
		m, ok := v.(map[string]any)
		if !ok {
			return Request{}, &BadRequest{"trailers is an object of strings"}
		}
		for k, x := range m {
			s, ok := x.(string)
			if !ok {
				return Request{}, &BadRequest{"trailers is an object of strings"}
			}
			lk := strings.ToLower(k)
			for _, t := range TrailerKeys {
				if lk == t {
					known[lk] = s
				}
			}
		}
	}
	for k := range d {
		if !requestKeys[k] {
			return Request{}, &BadRequest{"unknown field " + pycompat.Repr(k)}
		}
	}
	return Request{strings.ToLower(repo), pr, head, paths, author, known}, nil
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	if f, ok := pycompat.Number(v); ok {
		return f.Sign() != 0
	}
	return true
}

// Body is the request as a JSON object (what provenance_from_app digests: repo, pr, head, author, paths, trailers).
func (r Request) Body() map[string]any {
	paths := make([]any, len(r.Paths))
	for i, p := range r.Paths {
		paths[i] = p
	}
	tr := map[string]any{}
	for k, v := range r.Trailers {
		tr[k] = v
	}
	return map[string]any{"repo": r.Repo, "pr": r.PR, "head": r.Head, "author": r.Author, "paths": paths, "trailers": tr}
}

// Violation is one scope violation.
type Violation struct {
	Path    string `json:"path"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// Check is one verdict: {ok, status, rule, message, hint} (and, for scope with a record, violations).
type Check struct {
	OK         bool         `json:"ok"`
	Status     string       `json:"status"`
	Rule       *string      `json:"rule"`
	Message    string       `json:"message"`
	Hint       string       `json:"hint"`
	Violations *[]Violation `json:"violations,omitempty"`
}

func check(ok bool, status, message, hint string, rule *string) Check {
	return Check{OK: ok, Status: status, Rule: rule, Message: message, Hint: hint}
}

func rule(s string) *string { return &s }

// RecordSummary is the receipt the verdict rests on: seq, hash, ts, task_id, session, agent, principal, tool.
type RecordSummary struct {
	Seq       any `json:"seq"`
	Hash      any `json:"hash"`
	TS        any `json:"ts"`
	TaskID    any `json:"task_id"`
	Session   any `json:"session"`
	Agent     any `json:"agent"`
	Principal any `json:"principal"`
	Tool      any `json:"tool"`
}

// Verdict is verify()'s answer, plus the seq of the record that recorded it.
type Verdict struct {
	AgentPR  bool           `json:"agent_pr"`
	Identity Check          `json:"identity"`
	Scope    Check          `json:"scope"`
	Record   *RecordSummary `json:"record"`
	AuditSeq any            `json:"audit_seq,omitempty"`
}

// Lookup finds a live agent definition by name (definitions.Registry.Get).
type Lookup interface {
	Get(name string) (definitions.Definition, bool)
}

func seqOf(r store.Record) (float64, bool) {
	switch x := r["seq"].(type) {
	case int64:
		return float64(x), true
	case int:
		return float64(x), true
	case float64:
		return x, true
	case interface{ Float64() (float64, error) }:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

// Verify is provenance.verify: the verdict for one PR from the receipts Clearance holds for (repo, pr). The newest
// receipt wins.
func Verify(req Request, receipts []store.Record, defs Lookup, agentLogins []string) Verdict {
	var rec store.Record
	best := 0.0
	for _, r := range receipts {
		s, _ := seqOf(r)
		if rec == nil || s > best {
			rec, best = r, s
		}
	}
	byAgentLogin := false
	for _, a := range agentLogins {
		if strings.ToLower(a) == strings.ToLower(req.Author) {
			byAgentLogin = true
		}
	}
	if rec == nil {
		var ident Check
		switch {
		case req.Trailers["task"] != "" || req.Trailers["session"] != "":
			task, ok := req.Trailers["task"]
			if !ok {
				task = "?"
			}
			ident = check(false, "unrecorded", fmt.Sprintf("the PR's commit trailers name task %s, but Clearance has no record of opening this PR", task),
				"Only Clearance opens agent PRs. If a person wrote this change, remove the "+TrailerPrefix+"* trailers; otherwise treat the PR as forged.", rule("AI001"))
		case byAgentLogin:
			ident = check(false, "unrecorded", fmt.Sprintf("the PR is authored by %s, an agents' login, but Clearance has no record of opening it", req.Author),
				"The agents' GitHub App was used outside Clearance. Close the PR and review the App's credentials and installations.", rule("AI002"))
		default:
			ident = check(true, "not-agent", "not an agent PR: no Clearance record, no "+TrailerPrefix[:len(TrailerPrefix)-1]+" trailers, and not authored by an agents' login", "", nil)
		}
		var scope Check
		if ident.OK {
			scope = check(true, "not-agent", "not an agent PR", "", nil)
		} else {
			scope = check(false, "unknown", "no record to check the scope against", ident.Hint, ident.Rule)
		}
		return Verdict{AgentPR: !ident.OK, Identity: ident, Scope: scope}
	}
	eff, _ := rec["effect"].(map[string]any)
	if eff == nil {
		eff = map[string]any{}
	}
	summary := &RecordSummary{rec["seq"], rec["hash"], rec["ts"], rec["task_id"], rec["session"], rec["agent"], rec["principal"], rec["tool"]}
	var mismatched []string
	for _, kw := range []struct {
		k    string
		want any
	}{{"task", rec["task_id"]}, {"session", rec["session"]}, {"agent", rec["agent"]}} {
		if t := req.Trailers[kw.k]; t != "" {
			if w, ok := kw.want.(string); !ok || w != t {
				mismatched = append(mismatched, kw.k)
			}
		}
	}
	var ident Check
	commit, isStr := eff["commit"].(string)
	switch {
	case !isStr || commit != req.Head:
		ident = check(false, "modified", fmt.Sprintf("the PR's head %s is not the commit the agent made (%s): commits were added after it",
			pycompat.Truncate(req.Head, 12), pycompat.Truncate(pycompat.Str(eff["commit"]), 12)),
			"Review the added commits as a person's change. The agent gates vouch only for the agent's own commit.", rule("AI003"))
	case len(mismatched) > 0:
		ident = check(false, "mismatch", fmt.Sprintf("the commit trailers' %s differ from Clearance's record of this PR", strings.Join(mismatched, ", ")),
			"The trailers were edited after Clearance wrote them; treat the PR as tampered with.", rule("AI004"))
	default:
		ident = check(true, "confirmed", fmt.Sprintf("opened by agent %s through Clearance (task %s, session %s, record %s)",
			pycompat.Str(rec["agent"]), pycompat.Str(rec["task_id"]), pycompat.Str(rec["session"]), pycompat.Str(rec["seq"])), "", nil)
	}
	return Verdict{AgentPR: true, Identity: ident, Scope: scopeOf(req, rec, eff, defs), Record: summary}
}

func scopeOf(req Request, rec store.Record, eff map[string]any, defs Lookup) Check {
	agent, _ := rec["agent"].(string)
	var d definitions.Definition
	ok := false
	if defs != nil {
		d, ok = defs.Get(agent)
	}
	if !ok {
		c := check(false, "violations", fmt.Sprintf("agent definition %s is not in this deployment", pycompat.Repr(rec["agent"])),
			"A PR from a retired agent needs a person's review.", rule("AS004"))
		c.Violations = &[]Violation{}
		return c
	}
	violations := []Violation{}
	allow := make([]string, len(d.ReposAllow))
	for i, a := range d.ReposAllow {
		allow[i] = strings.ToLower(a)
	}
	if !repoAllowed(req.Repo, allow) {
		violations = append(violations, Violation{"", "AS003", fmt.Sprintf("%s is not in %s's repos.allow", req.Repo, d.Name)})
	}
	carried := map[string]bool{}
	if ps, ok := eff["paths"].([]any); ok {
		for _, p := range ps {
			if s, ok := p.(string); ok {
				carried[s] = true
			}
		}
	}
	for _, p := range req.Paths {
		if !carried[normal(p)] {
			violations = append(violations, Violation{p, "AS001", "changed, but not in the agent's commit"})
		}
	}
	for _, p := range pathViolations(req.Paths, d.DenyPaths) {
		violations = append(violations, Violation{p, "AS002", fmt.Sprintf("denied to %s (path-not-allowed, R015)", d.Name)})
	}
	if len(violations) == 0 {
		c := check(true, "in-scope", fmt.Sprintf("%d changed paths, all inside %s's scope", len(req.Paths), d.Name), "", nil)
		c.Violations = &violations
		return c
	}
	first := violations[0]
	where := first.Path
	if where == "" {
		where = req.Repo
	}
	c := check(false, "violations", fmt.Sprintf("%d scope violations; first: %s (%s)", len(violations), where, first.Message),
		"An agent may not change these paths. Revert them, or have a person make the change in a PR of their own.", rule(first.Rule))
	c.Violations = &violations
	return c
}
