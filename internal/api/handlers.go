package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/token"
)

// CountBy are the record fields evidence counts group by; ChangeCountBy the change fields (api.py COUNT_BY,
// CHANGE_COUNT_BY). ChangeStates are a change's states.
var (
	CountBy       = []string{"rule", "tool", "agent", "app", "decision"}
	ChangeCountBy = []string{"state", "tier", "app", "env", "cleared_by"}
	ChangeStates  = []string{"holding", "cleared", "denied", "expired", "superseded"}
	outcomeModes  = []string{OutcomesInclude, OutcomesExclude, OutcomesOnly}
)

// isoTime is the shape of a time Python's datetime.fromisoformat reads (with Z for +00:00): a date, optionally a
// time to the microsecond, optionally an offset.
var isoTime = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}([T ]\d{2}(:\d{2}(:\d{2}([.,]\d{1,9})?)?)?)?(Z|[+-]\d{2}(:?\d{2}(:?\d{2})?)?)?$`)

var digits = regexp.MustCompile(`^[0-9]+$`)

func limitOf(q map[string]string) (int, *apiError) {
	raw := strings.TrimSpace(q["limit"])
	if raw == "" {
		return DefaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errorf(400, "limit must be a number")
	}
	return max(1, min(n, MaxLimit)), nil
}

// query is the request's query as one value per parameter (checkQuery has refused repeats).
func query(r *http.Request) map[string]string {
	out := map[string]string{}
	for k, vs := range r.URL.Query() {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

// project is a stored record as served: evidence.Project (a v0-draft row gains provider and subject, named in
// projected), with assurance kept beside it.
func project(r Record) map[string]any { return evidence.Project(r) }

func projectAll(rs []Record) []Record {
	out := make([]Record, len(rs))
	for i, r := range rs {
		out[i] = project(r)
	}
	return out
}

func evidenceFilter(q map[string]string, outcomesDefault string) (EvidenceFilter, *apiError) {
	f := EvidenceFilter{Task: q["task"], Session: q["session"], Agent: q["agent"], Tool: q["tool"],
		Principal: q["principal"], Decision: q["decision"], Rule: q["rule"], App: q["app"], Since: q["since"],
		Until: q["until"], Outcomes: q["outcomes"]}
	inst, aerr := installationOf(q)
	if aerr != nil {
		return f, aerr
	}
	f.Installation = inst
	for k, v := range map[string]string{"since": f.Since, "until": f.Until} {
		if v != "" && !isoTime.MatchString(v) {
			return f, errorf(400, "%s is an ISO time", k)
		}
	}
	if f.Outcomes == "" {
		f.Outcomes = outcomesDefault
	}
	if !in(outcomeModes, f.Outcomes) {
		return f, errorf(400, "outcomes is one of %s", strings.Join(outcomeModes, ", "))
	}
	return f, nil
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	limit, aerr := limitOf(q)
	if aerr != nil {
		aerr.write(w)
		return
	}
	f, aerr := evidenceFilter(q, OutcomesInclude)
	if aerr != nil {
		aerr.write(w)
		return
	}
	var after *int64
	if a := q["after"]; a != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
		if err != nil {
			writeError(w, 400, "after is a seq")
			return
		}
		after = &n
	}
	items, err := s.opt.Store.Evidence(r.Context(), f, v, limit, after)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	page := EvidencePage{Items: projectAll(items)}
	if len(items) == limit && limit > 0 {
		if n, ok := seqOf(items[len(items)-1]); ok {
			page.Next = &n
		}
	}
	writeJSON(w, 200, page)
}

func seqOf(r Record) (int64, bool) {
	switch x := r["seq"].(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case int64:
		return x, true
	case float64:
		return int64(x), true
	}
	return 0, false
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request, v *Viewer) {
	seq, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("seq")), 10, 64)
	if err != nil {
		writeError(w, 400, "seq is a number")
		return
	}
	rec, err := s.opt.Store.EvidenceOne(r.Context(), seq, v)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	if rec == nil {
		writeError(w, 404, "no such record")
		return
	}
	writeJSON(w, 200, project(rec))
}

func (s *Server) verifyEvidence(w http.ResponseWriter, r *http.Request, _ *Viewer) {
	out, err := s.opt.Store.Verify(r.Context())
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}

func total(items []Count) int64 {
	var n int64
	for _, c := range items {
		n += c.Count
	}
	return n
}

func (s *Server) countEvidence(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	by := q["by"]
	if by == "" {
		by = "rule"
	}
	if !in(CountBy, by) {
		writeError(w, 400, "by is one of "+strings.Join(CountBy, ", "))
		return
	}
	f, aerr := evidenceFilter(q, OutcomesExclude)
	if aerr != nil {
		aerr.write(w)
		return
	}
	items, err := s.opt.Store.Counts(r.Context(), f, v, by)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	writeJSON(w, 200, Counts{By: by, Items: items, Total: total(items), Outcomes: f.Outcomes})
}

// byPR is api.py receipts_or_verdicts: repo (owner/name, lower-cased) is required, pr is a number when given.
func (s *Server) byPR(w http.ResponseWriter, r *http.Request, v *Viewer, tools []string) {
	q := query(r)
	repo := strings.ToLower(q["repo"])
	if repo == "" || !strings.Contains(repo, "/") {
		writeError(w, 400, "repo is required (owner/name)")
		return
	}
	pr, hasPR := q["pr"]
	if hasPR && !digits.MatchString(pr) {
		writeError(w, 400, "pr is a number")
		return
	}
	inst, aerr := installationOf(q)
	if aerr != nil {
		aerr.write(w)
		return
	}
	f := PRFilter{Repo: repo, PR: pr, Installation: inst, ByInstaller: len(tools) == 1 && tools[0] == "provenance.verify"}
	items, err := s.opt.Store.ByPR(r.Context(), tools, f, v)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	writeJSON(w, 200, RecordList{Items: projectAll(items)})
}

func (s *Server) listReceipts(w http.ResponseWriter, r *http.Request, v *Viewer) {
	s.byPR(w, r, v, provenance.PRTools())
}

func (s *Server) listProvenance(w http.ResponseWriter, r *http.Request, v *Viewer) {
	s.byPR(w, r, v, []string{"provenance.verify"})
}

// -- the deployment gate ------------------------------------------------------------------------------------------

func (s *Server) listClearances(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	limit, aerr := limitOf(q)
	if aerr != nil {
		aerr.write(w)
		return
	}
	f := ChangeFilter{App: strings.ToLower(q["app"]), Env: q["env"], State: q["state"],
		Repo: strings.ToLower(q["repo"]), Since: q["since"], Cluster: q["cluster"]}
	if f.State != "" && !in(ChangeStates, f.State) {
		writeError(w, 400, "state is one of "+strings.Join(ChangeStates, ", "))
		return
	}
	// The grant feed: one cluster's cleared changes whose token is live, each with its token.
	feed := f.Cluster != "" && f.State == "cleared"
	if v.Role == RoleFeed && (!feed || !v.FeedOf(f.Cluster)) {
		writeError(w, 403, fmt.Sprintf("%s reads the grant feed of %s only (cluster=<cluster>&state=cleared)",
			v.Person, strings.Join(v.Clusters, ", ")))
		return
	}
	now := s.opt.Clock().UTC()
	if feed {
		f.LiveAt = &now
	}
	for _, k := range []string{"pr", "tier"} {
		raw := q[k]
		if raw == "" {
			continue
		}
		if !digits.MatchString(raw) {
			writeError(w, 400, k+" is a number")
			return
		}
		n, err := strconv.ParseInt(raw, 10, 32)
		if err != nil {
			writeError(w, 400, k+" is a number")
			return
		}
		if k == "pr" {
			f.PR = &n
		} else {
			f.Tier = &n
		}
	}
	if f.Since != "" && !isoTime.MatchString(f.Since) {
		writeError(w, 400, "since is an ISO time")
		return
	}
	items, err := s.opt.Store.Changes(r.Context(), f, v, limit, q["after"])
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	if feed {
		if items, err = s.withTokens(r, items, now, false); err != nil {
			s.readFailed(w, r, err)
			return
		}
	}
	page := ChangePage{Items: items}
	if len(items) == limit && limit > 0 {
		var last struct {
			UpdatedAt *string `json:"updated_at"`
		}
		if json.Unmarshal(items[len(items)-1], &last) == nil {
			page.Next = last.UpdatedAt
		}
	}
	writeJSON(w, 200, page)
}

// changeVisible is api.py change_visible, on the stored record.
func changeVisible(raw json.RawMessage, v *Viewer) bool {
	if v.All() {
		return true
	}
	var c struct {
		App         string `json:"app"`
		Cluster     string `json:"cluster"`
		Owner       string `json:"owner"`
		Requirement *struct {
			OutsideGroups []string `json:"outsideGroups"`
		} `json:"requirement"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return false
	}
	if v.Role == RoleFeed {
		return v.FeedOf(c.Cluster)
	}
	if (c.App != "" && in(v.Apps, c.App)) || (c.Owner != "" && in(v.Groups, c.Owner)) {
		return true
	}
	if c.Requirement != nil {
		for _, g := range c.Requirement.OutsideGroups {
			if in(v.Groups, g) {
				return true
			}
		}
	}
	return false
}

func (s *Server) getClearance(w http.ResponseWriter, r *http.Request, v *Viewer) {
	raw, err := s.opt.Store.Change(r.Context(), r.PathValue("id"))
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	if raw == nil || !changeVisible(raw, v) {
		writeError(w, 404, "no such change")
		return
	}
	out, err := s.withTokens(r, []json.RawMessage{raw}, s.opt.Clock().UTC(), true)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	writeJSON(w, 200, out[0])
}

// withTokens adds each change's live token beside it ("token"; null, when always, for a change without one).
func (s *Server) withTokens(r *http.Request, items []json.RawMessage, now time.Time, always bool) ([]json.RawMessage, error) {
	ids := make([]string, 0, len(items))
	for _, raw := range items {
		var c struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("api: a stored change: %w", err)
		}
		ids = append(ids, c.ID)
	}
	tokens, err := s.opt.Store.Tokens(r.Context(), ids, now)
	if err != nil {
		return nil, err
	}
	out := make([]json.RawMessage, 0, len(items))
	for i, raw := range items {
		var view any
		if tk, ok := tokens[ids[i]]; ok {
			v, err := gate.ViewToken(tk)
			if err != nil {
				return nil, err
			}
			view = v
		} else if !always {
			out = append(out, raw)
			continue
		}
		tb, err := json.Marshal(view)
		if err != nil {
			return nil, err
		}
		// A stored change record is a JSON object without a "token" key (gate.Change has none).
		trimmed := bytes.TrimRight(raw, " \t\r\n")
		if len(trimmed) < 2 || trimmed[len(trimmed)-1] != '}' {
			return nil, errors.New("api: a stored change is not a JSON object")
		}
		joined := append([]byte{}, trimmed[:len(trimmed)-1]...)
		if len(trimmed) > 2 {
			joined = append(joined, ',')
		}
		joined = append(append(append(joined, `"token":`...), tb...), '}')
		out = append(out, joined)
	}
	return out, nil
}

// getKeys is the clearance token verification keys (the core's JWKS), read from the core's store.
func (s *Server) getKeys(w http.ResponseWriter, r *http.Request, _ *Viewer) {
	rows, err := s.opt.Store.SigningKeys(r.Context(), s.opt.Clock().Add(-token.MaxLifetime))
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	out := token.JWKS{Keys: []token.JWK{}}
	for _, k := range rows {
		var j token.JWK
		if json.Unmarshal(k.JWK, &j) == nil {
			out.Keys = append(out.Keys, j)
		}
	}
	w.Header().Set("Cache-Control", "max-age=300")
	writeJSON(w, 200, out)
}

func (s *Server) countClearances(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	by := q["by"]
	if by == "" {
		by = "state"
	}
	if !in(ChangeCountBy, by) {
		writeError(w, 400, "by is one of "+strings.Join(ChangeCountBy, ", "))
		return
	}
	f := ChangeFilter{App: strings.ToLower(q["app"]), Env: q["env"], State: q["state"], Since: q["since"]}
	// The same checks listClearances makes: a state or since that can match nothing is a 400, not empty counts.
	if f.State != "" && !in(ChangeStates, f.State) {
		writeError(w, 400, "state is one of "+strings.Join(ChangeStates, ", "))
		return
	}
	if f.Since != "" && !isoTime.MatchString(f.Since) {
		writeError(w, 400, "since is an ISO time")
		return
	}
	items, err := s.opt.Store.ChangeCounts(r.Context(), f, v, by)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	writeJSON(w, 200, Counts{By: by, Items: items, Total: total(items)})
}

func (s *Server) getClearancePolicy(w http.ResponseWriter, _ *http.Request, _ *Viewer) {
	if s.opt.GatePolicy == nil {
		writeError(w, 404, "this deployment runs no deployment gate")
		return
	}
	writeJSON(w, 200, s.opt.GatePolicy)
}

// -- the contract -------------------------------------------------------------------------------------------------

func (s *Server) getContract(w http.ResponseWriter, _ *http.Request, _ *Viewer) {
	doc, err := ContractDoc(s.opt.GatewayURL, s.opt.CoreURL)
	if err != nil {
		writeError(w, 500, fmt.Sprint("contract: ", err))
		return
	}
	writeJSON(w, 200, doc)
}
