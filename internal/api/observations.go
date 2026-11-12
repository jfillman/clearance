package api

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/observe"
)

// The observation reads (O-1): clearance.evidence/v1.1's observation records by scope, the health of the feeds
// behind them, and the coverage statement GET /v1/coverage builds from both. They are reads for any signed-in person
// (owner decision O-5, 2026-11-12) and for a delegate acting for one: an observation is about an account or a cluster,
// not an agent or an app, so there is no narrower scope to give a person, and the per-person evidence scope (which would
// show a person none of them) does not apply. What a person reads is redacted (redactForPerson); an auditor reads the
// records as stored.

// ObservationKinds are listObservations's `kind`.
var ObservationKinds = []string{evidence.KindObservation, evidence.KindAssessment, evidence.KindResolution, evidence.KindVerification}

var scopeParam = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)

const (
	// MaxCoverageRecords caps the records of each kind one statement reads; past it the statement says truncated
	// and is never clean.
	MaxCoverageRecords = 10000
	// MaxCoverageWindow is the longest window one statement speaks for.
	MaxCoverageWindow = 92 * 24 * time.Hour
	// DefaultCoverageWindow is the window of a statement with no from.
	DefaultCoverageWindow = 24 * time.Hour
)

// readerOf is the viewer the store is read as for an observation read: every record of the scope, whoever asks.
func readerOf(v *Viewer) *Viewer {
	if v.All() {
		return v
	}
	return &Viewer{Role: RoleAuditor, Person: v.Person}
}

func scopeOf(q map[string]string) (string, *apiError) {
	sc := q["scope"]
	if !scopeParam.MatchString(sc) {
		return "", errorf(400, "scope is required: the account, cluster or workspace observed")
	}
	return sc, nil
}

func sourceOf(q map[string]string) (string, *apiError) {
	src := q["source"]
	if src != "" && !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`).MatchString(src) {
		return "", errorf(400, "source is a lowercase source name")
	}
	return src, nil
}

func (s *Server) listObservations(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	f, aerr := evidenceFilter(map[string]string{"since": q["since"], "until": q["until"]}, OutcomesInclude)
	if aerr != nil {
		aerr.write(w)
		return
	}
	if f.Scope, aerr = scopeOf(q); aerr != nil {
		aerr.write(w)
		return
	}
	if f.Source, aerr = sourceOf(q); aerr != nil {
		aerr.write(w)
		return
	}
	kind := q["kind"]
	if kind == "" {
		kind = evidence.KindObservation
	}
	if !in(ObservationKinds, kind) {
		writeError(w, 400, "kind is one of "+strings.Join(ObservationKinds, ", "))
		return
	}
	f.Tools = []string{kind}
	s.observationPage(w, r, v, q, f)
}

func (s *Server) listObservationHealth(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	f, aerr := evidenceFilter(map[string]string{"since": q["since"], "until": q["until"]}, OutcomesInclude)
	if aerr != nil {
		aerr.write(w)
		return
	}
	if f.Scope, aerr = scopeOf(q); aerr != nil {
		aerr.write(w)
		return
	}
	if f.Source, aerr = sourceOf(q); aerr != nil {
		aerr.write(w)
		return
	}
	f.Tools = []string{evidence.KindHealth, evidence.KindAuditGap}
	s.observationPage(w, r, v, q, f)
}

// observationPage is evidencePage for the observation kinds: the store is read as an auditor (readerOf) and a person
// is given each record with its state_change redacted (redactForPerson).
func (s *Server) observationPage(w http.ResponseWriter, r *http.Request, v *Viewer, q map[string]string, f EvidenceFilter) {
	s.evidencePageAs(w, r, readerOf(v), q, f, !v.All())
}

// collect reads every record matching f, newest first, up to max; truncated says there were more.
func (s *Server) collect(ctx context.Context, f EvidenceFilter, v *Viewer, max int) (out []Record, truncated bool, err error) {
	var after *int64
	for len(out) < max {
		page, err := s.opt.Store.Evidence(ctx, f, readerOf(v), MaxLimit, after)
		if err != nil {
			return nil, false, err
		}
		out = append(out, page...)
		if len(page) < MaxLimit {
			return out, false, nil
		}
		n, ok := seqOf(page[len(page)-1])
		if !ok {
			return out, true, nil
		}
		after = &n
	}
	return out, true, nil
}

// ScopeStatements is GET /v1/coverage with no scope: the statement of every scope observed, in scope order.
type ScopeStatements struct {
	From   string              `json:"from"`
	To     string              `json:"to"`
	Scopes []observe.Statement `json:"scopes"`
	// Truncated: more scopes were observed than MaxCoverageScopes, or a read of the scope list was cut.
	Truncated bool `json:"truncated"`
}

// MaxCoverageScopes caps the scopes one unscoped coverage answer carries.
const MaxCoverageScopes = 100

// getCoverage is GET /v1/coverage: the three-part statement of a scope's window (observe.Statement), or with no scope
// the statements of every scope observed in it ({from, to, scopes: [...]}).
func (s *Server) getCoverage(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	scope := ""
	if q["scope"] != "" {
		var aerr *apiError
		if scope, aerr = scopeOf(q); aerr != nil {
			aerr.write(w)
			return
		}
	}
	now := s.opt.Clock().UTC()
	to, from := now, time.Time{}
	var err error
	if x := q["to"]; x != "" {
		if to, err = time.Parse(time.RFC3339, x); err != nil {
			writeError(w, 400, "to is an RFC 3339 time")
			return
		}
	}
	if x := q["from"]; x != "" {
		if from, err = time.Parse(time.RFC3339, x); err != nil {
			writeError(w, 400, "from is an RFC 3339 time")
			return
		}
	} else {
		from = to.Add(-DefaultCoverageWindow)
	}
	to, from = to.UTC(), from.UTC()
	switch {
	case !from.Before(to):
		writeError(w, 400, "from is before to")
		return
	case to.Sub(from) > MaxCoverageWindow:
		writeError(w, 400, "the window is at most 92 days")
		return
	}
	if to.After(now) {
		to = now // a statement cannot speak for the future
		if !from.Before(to) {
			writeError(w, 400, "from is before now")
			return
		}
	}
	ctx := r.Context()
	if scope != "" {
		st, err := s.statement(ctx, v, scope, from, to, now)
		if err != nil {
			s.readFailed(w, r, err)
			return
		}
		writeJSON(w, 200, st)
		return
	}
	scopes, cut, err := s.scopesIn(ctx, v, from, to)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	out := ScopeStatements{From: evidence.ISO(from), To: evidence.ISO(to), Scopes: []observe.Statement{}, Truncated: cut}
	if len(scopes) > MaxCoverageScopes {
		scopes, out.Truncated = scopes[:MaxCoverageScopes], true
	}
	for _, sc := range scopes {
		st, err := s.statement(ctx, v, sc, from, to, now)
		if err != nil {
			s.readFailed(w, r, err)
			return
		}
		out.Scopes = append(out.Scopes, st)
	}
	writeJSON(w, 200, out)
}

// scopesIn is the scopes with an observation, audit gap or health record in the window, or a health record before it
// (a scope whose feed went quiet is still a scope), sorted. cut says a read hit MaxCoverageRecords.
func (s *Server) scopesIn(ctx context.Context, v *Viewer, from, to time.Time) ([]string, bool, error) {
	seen := map[string]bool{}
	cut := false
	f, t := evidence.ISO(from), evidence.ISO(to)
	for _, rd := range []struct {
		tools        []string
		since, until string
	}{{[]string{evidence.KindObservation, evidence.KindAuditGap}, f, t}, {[]string{evidence.KindHealth}, "", t}} {
		rs, c, err := s.collect(ctx, EvidenceFilter{Tools: rd.tools, Since: rd.since, Until: rd.until, Outcomes: OutcomesInclude}, v, MaxCoverageRecords)
		if err != nil {
			return nil, false, err
		}
		cut = cut || c
		for _, r := range rs {
			if sc, _ := r["scope"].(string); sc != "" && scopeParam.MatchString(sc) {
				seen[sc] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for sc := range seen {
		out = append(out, sc)
	}
	sort.Strings(out)
	return out, cut, nil
}

// statement is the coverage statement of one scope and window.
func (s *Server) statement(ctx context.Context, v *Viewer, scope string, from, to, now time.Time) (observe.Statement, error) {
	var err error
	base := EvidenceFilter{Scope: scope, Outcomes: OutcomesInclude}
	input := observe.Input{Scope: scope, Window: observe.Window{From: from, To: to}}
	read := func(tools []string, since, until string) []Record {
		if err != nil {
			return nil
		}
		f := base
		f.Tools, f.Since, f.Until = tools, since, until
		var rs []Record
		var cut bool
		if rs, cut, err = s.collect(ctx, f, v, MaxCoverageRecords); err == nil && cut {
			input.Truncated = true
		}
		return rs
	}
	f, t := evidence.ISO(from), evidence.ISO(to)
	input.Observations = read([]string{evidence.KindObservation}, f, t)
	input.Assessments = read([]string{evidence.KindAssessment}, f, "")
	input.Resolutions = read([]string{evidence.KindResolution}, f, "")
	input.Verifications = read([]string{evidence.KindVerification}, f, "")
	input.Health = read([]string{evidence.KindHealth}, "", t)
	input.Gaps = read([]string{evidence.KindAuditGap}, f, t)
	if err != nil {
		return observe.Statement{}, err
	}
	return observe.Build(input, now), nil
}

// Redaction for a person. The providers keep secrets out of an observation at the source (observe-k8s records a Secret at
// Metadata with no state_change, the core refuses a Secret observation that carries one, observe-aws strips
// secret-bearing request keys), but a state_change is a provider's object as it was and a non-Secret object can still
// carry a value (a ConfigMap, a pod's env, an AWS Config property). A person reads the record with the value of every
// secret-bearing key under state_change replaced, so what they read never depends on a provider having got it right.
// The record's stored hash is of the unredacted record: redacted says so, and an auditor reads it as stored.
const redactedValue = "[redacted]"

var secretKeyNames = map[string]bool{
	"password": true, "masteruserpassword": true, "adminpassword": true, "newpassword": true, "oldpassword": true,
	"secretstring": true, "secretbinary": true, "secretaccesskey": true, "sessiontoken": true, "securitytoken": true,
	"userdata": true, "privatekey": true, "keymaterial": true, "keymaterialwithprivate": true, "plaintext": true,
	"ciphertextblob": true, "ciphertext": true, "importedkeymaterial": true, "clientsecret": true, "authtoken": true,
	"authorizationtoken": true, "apikey": true, "credentials": true, "connectionpassword": true, "kmsdatakey": true,
	"certificatechain": true, "pfx": true, "token": true, "accesstoken": true, "refreshtoken": true, "idtoken": true,
	"environment": true, "variables": true, "stringdata": true, "binarydata": true,
}

var secretNameParts = []string{"password", "secret", "privatekey", "passphrase", "credential", "token", "apikey"}

func secretName(k string) bool {
	n := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(k))
	if secretKeyNames[n] {
		return true
	}
	for _, p := range secretNameParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// redactValue copies v with the value of every secret-bearing key replaced; in a {name, value} pair (a container's env
// entry) the value is replaced when the name is secret-bearing. Past depth 12 the rest is replaced.
func redactValue(v any, depth int) any {
	if depth > 12 {
		return redactedValue
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		named := false
		if n, ok := x["name"].(string); ok && secretName(n) {
			named = true
		}
		for k, e := range x {
			if secretName(k) || (named && k == "value") {
				out[k] = redactedValue
				continue
			}
			out[k] = redactValue(e, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redactValue(e, depth+1)
		}
		return out
	}
	return v
}

// redactForPerson returns r with its state_change and exception objects redacted, naming them in redacted (r is not changed); a record with none is returned as is.
func redactForPerson(r Record) Record {
	var done []any
	out := r
	for _, k := range []string{"state_change", "exception"} {
		x, ok := r[k]
		if !ok || x == nil {
			continue
		}
		if done == nil {
			out = make(Record, len(r)+1)
			for kk, vv := range r {
				out[kk] = vv
			}
		}
		out[k] = redactValue(x, 0)
		done = append(done, k)
	}
	if done != nil {
		out["redacted"] = done
	}
	return out
}
