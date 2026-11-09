package api

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/observe"
)

// The observation reads (O-1): clearance.evidence/v1.1's observation records by scope, the health of the feeds
// behind them, and the coverage statement GET /v1/coverage builds from both. They are auditor reads: an observation
// is about an account or a cluster, not an agent or an app, so there is no narrower scope to give a person.

// ObservationKinds are listObservations's `kind`.
var ObservationKinds = []string{evidence.KindObservation, evidence.KindAssessment, evidence.KindResolution}

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
	s.evidencePage(w, r, v, q, f)
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
	s.evidencePage(w, r, v, q, f)
}

// collect reads every record matching f, newest first, up to max; truncated says there were more.
func (s *Server) collect(ctx context.Context, f EvidenceFilter, v *Viewer, max int) (out []Record, truncated bool, err error) {
	var after *int64
	for len(out) < max {
		page, err := s.opt.Store.Evidence(ctx, f, v, MaxLimit, after)
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

// getCoverage is GET /v1/coverage: the three-part statement of a scope's window (observe.Statement).
func (s *Server) getCoverage(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	scope, aerr := scopeOf(q)
	if aerr != nil {
		aerr.write(w)
		return
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
	input.Health = read([]string{evidence.KindHealth}, "", t)
	input.Gaps = read([]string{evidence.KindAuditGap}, f, t)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	writeJSON(w, 200, observe.Build(input, now))
}
