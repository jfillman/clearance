package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/pg"
)

// PG is Store on the read-only Postgres store (pg.OpenReader: no lock, no migration, every session read only,
// statement_timeout on every connection). The queries are api.py PgReadStore's on the core's tables, with one
// change: a person's own records are found from the chain, not from the gateway's clearance_sessions table (which
// moves to the gateway's database in R-3). A session's owner is the principal of the first session.open record
// of its task: the person who opened it, and every session spawned under it shares its task and its principal.
type PG struct {
	R *pg.Reader
}

var _ Store = (*PG)(nil)

// q builds one statement's WHERE clauses and their $n arguments.
type q struct {
	where []string
	args  []any
}

func (b *q) arg(v any) string {
	b.args = append(b.args, v)
	return "$" + strconv.Itoa(len(b.args))
}

func (b *q) add(clause string) { b.where = append(b.where, clause) }

func (b *q) eq(col, v string) {
	if v != "" {
		b.add(col + " = " + b.arg(v))
	}
}

func (b *q) sql() string {
	if len(b.where) == 0 {
		return "TRUE"
	}
	return strings.Join(b.where, " AND ")
}

// opened is the first session.open record of every task: its principal owns the task's sessions.
const opened = `WITH opened AS MATERIALIZED (SELECT DISTINCT ON (o.record->>'task_id') o.record->>'task_id' AS task, ` +
	`o.record->>'principal' AS principal FROM clearance_evidence o WHERE o.record->>'tool' = 'session.open' ` +
	`AND o.record->>'task_id' IS NOT NULL ORDER BY o.record->>'task_id', o.seq) `

// evidenceScope is api.py _evidence_scope. It returns the WITH prefix the scope needs ("" for an auditor).
func (b *q) evidenceScope(v *Viewer) string {
	if v.All() {
		return ""
	}
	p := b.arg(v.Person)
	b.add("(e.record->>'agent' = ANY(" + b.arg(v.Agents) + ") OR e.record->>'app' = ANY(" + b.arg(v.Apps) + ") " +
		"OR (e.record->>'session' IS NULL AND e.record->>'principal' = " + p + ") " +
		"OR (e.record->>'session' IS NOT NULL AND e.record->>'task_id' IN (SELECT task FROM opened WHERE principal = " + p + ")))")
	return opened
}

func (b *q) evidenceFilter(f EvidenceFilter) {
	for _, c := range []struct{ field, v string }{{"task_id", f.Task}, {"session", f.Session}, {"agent", f.Agent},
		{"tool", f.Tool}, {"principal", f.Principal}, {"decision", f.Decision}, {"rule", f.Rule}, {"app", f.App}} {
		b.eq("e.record->>'"+c.field+"'", c.v)
	}
	if f.Installation != "" {
		b.add("e.record->>'principal' = " + b.arg(InstallationPrincipal(f.Installation)))
	}
	if len(f.Coverage) > 0 {
		b.add("e.record->>'coverage' = ANY(" + b.arg(f.Coverage) + ")")
	}
	if f.Since != "" {
		b.add("e.record->>'ts' >= " + b.arg(f.Since))
	}
	if f.Until != "" {
		b.add("e.record->>'ts' < " + b.arg(f.Until))
	}
	if f.Exceptions {
		// The exact predicate of the clearance_evidence_exceptions partial index (store/pg Schema).
		b.add("(e.record->>'tool' IN ('deploy.exception', 'deploy.degraded', 'breakglass.open', 'breakglass.close') " +
			"OR e.record->>'coverage' = 'coverage-unavailable')")
	}
	if f.Kind != "" {
		b.add("e.record->'exception'->>'kind' = " + b.arg(f.Kind))
	}
	if f.Scope != "" {
		b.add("e.record->>'scope' = " + b.arg(f.Scope))
	}
	if f.Source != "" {
		b.add("e.record->'source'->>'name' = " + b.arg(f.Source))
	}
	if len(f.Tools) > 0 {
		b.add(toolPredicate(f.Tools, b))
	}
	switch f.Outcomes {
	case OutcomesExclude:
		b.add("NOT (e.record ? 'outcome_of')")
	case OutcomesOnly:
		b.add("e.record ? 'outcome_of'")
	}
}

// pagedTools are the kinds of the clearance_evidence_obs_page partial index (store/pg MapIndexes spells its predicate
// from this list's literals): the kinds a coverage statement pages through.
var pagedTools = []string{evidence.KindObservation, evidence.KindAssessment, evidence.KindResolution, evidence.KindVerification, evidence.KindAuditGap}

// literalTools are the kinds toolPredicate spells as literals: pagedTools, and the health kind, whose pages read
// clearance_evidence_health_page (store/pg MapIndexes).
var literalTools = append(append([]string{}, pagedTools...), evidence.KindHealth)

// toolPredicate is the tool condition of a read. When every tool is one of literalTools it is spelled with literals
// (tool = 'x', or tool IN ('x', 'y')): the planner proves a partial index from a literal predicate and matches an equality on
// the index's tool column only from a literal; tool = ANY($n) does neither, so the read fell back to the (scope, ts)
// index and sorted. The literals come from literalTools, never from the request. Any other tool is an ANY($n) bind.
func toolPredicate(tools []string, b *q) string {
	lits := make([]string, 0, len(tools))
	for _, t := range tools {
		if !in(literalTools, t) {
			return "e.record->>'tool' = ANY(" + b.arg(tools) + ")"
		}
		lits = append(lits, "'"+t+"'")
	}
	if len(lits) == 1 {
		return "e.record->>'tool' = " + lits[0]
	}
	return "e.record->>'tool' IN (" + strings.Join(lits, ", ") + ")"
}

func (s *PG) records(ctx context.Context, sql string, args []any) ([]Record, error) {
	rows, done, err := s.R.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var text, assurance string
		if err := rows.Scan(&text, &assurance); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		m, err := parseStored(text, assurance)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func parseStored(text, assurance string) (Record, error) {
	v, err := canon.Parse([]byte(text))
	if err != nil {
		return nil, fmt.Errorf("pg: stored record: %w", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("pg: stored record is not an object")
	}
	m["assurance"] = assurance
	return m, nil
}

func (s *PG) Evidence(ctx context.Context, f EvidenceFilter, v *Viewer, limit int, after *int64) ([]Record, error) {
	sql, args := evidenceSQL(f, v, limit, after)
	return s.records(ctx, sql, args)
}

// evidenceSQL is the statement of one page of Evidence: newest seq first, seq < after.
func evidenceSQL(f EvidenceFilter, v *Viewer, limit int, after *int64) (string, []any) {
	b := &q{}
	with := b.evidenceScope(v)
	b.evidenceFilter(f)
	if after != nil {
		b.add("e.seq < " + b.arg(*after))
	}
	col := "e.record::text"
	if f.Slim { // the jsonb minus its heavy keys: they are dropped in the database, never sent or parsed
		col = "(e.record"
		for _, k := range SlimFields { // constants, never request text
			col += " - '" + k + "'"
		}
		col += ")::text"
	}
	return with + "SELECT " + col + ", e.assurance FROM clearance_evidence e WHERE " + b.sql() +
		" ORDER BY e.seq DESC LIMIT " + b.arg(limit), b.args
}

// observedTools is the predicate of the clearance_evidence_observed partial index, spelled as the index spells it: the
// planner proves a query against a partial index only from a literal predicate (tool = ANY($n) never matches it).
const observedTools = "e.record->>'tool' IN ('observation', 'assessment', 'resolution', 'observation.health', 'observation.audit-gap')"

// withRecursive turns evidenceScope's WITH prefix ("" or "WITH opened AS ... ") into the head of a WITH RECURSIVE list
// that more CTEs follow.
func withRecursive(with string) string {
	if with == "" {
		return "WITH RECURSIVE "
	}
	return "WITH RECURSIVE " + strings.TrimRight(strings.TrimPrefix(with, "WITH "), " ") + ", "
}

// Scopes reads the scope names with an observation or audit gap in [since, until) or a health record before until. It
// never reads the scopes' records: a skip scan over clearance_evidence_observed (scope, seq) walks the distinct names,
// one index probe each, and each name is kept by up to three LIMIT 1 probes on the partial indexes (a health record
// before until, then an observation or an audit gap in the window), each of which stops at its first match; the cheap
// and usual one, health, is first. The probes name no other kind: an IN list of the observed kinds let the planner pick
// clearance_evidence_observed and walk the scope's every record looking for an audit gap. A DISTINCT over the matching records read every health record ever written before until (the whole
// health history of every scope, about one record a minute per source, each a TOAST fetch): on a lab's two weeks of
// history that passed the statement timeout, and every unscoped GET /v1/coverage failed with 503.
func (s *PG) Scopes(ctx context.Context, v *Viewer, since, until string, limit int) ([]string, error) {
	sql, args := scopesSQL(v, since, until, limit)
	rows, done, err := s.R.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var sc string
		if err := rows.Scan(&sc); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// scopesSQL is the statement of Scopes.
func scopesSQL(v *Viewer, since, until string, limit int) (string, []any) {
	b := &q{}
	with := b.evidenceScope(v)
	vis := b.sql() // the viewer's condition ("TRUE" for an auditor), inside each probe
	sn, un := b.arg(since), b.arg(until)
	next := "SELECT e.record->>'scope' FROM clearance_evidence e WHERE " + observedTools + " AND e.record->>'scope' "
	probe := func(cond string) string {
		return "(SELECT true FROM clearance_evidence e WHERE e.record->>'scope' = c.scope AND " + vis +
			" AND " + cond + " LIMIT 1)"
	}
	inWindow := " AND e.record->>'ts' >= " + sn + " AND e.record->>'ts' < " + un
	sql := withRecursive(with) + "c(scope) AS ((" + next + "IS NOT NULL ORDER BY 1 LIMIT 1) UNION ALL " +
		"SELECT (" + next + "> c.scope ORDER BY 1 LIMIT 1) FROM c WHERE c.scope IS NOT NULL) " +
		`SELECT c.scope COLLATE "C" AS scope FROM c WHERE c.scope IS NOT NULL AND (` +
		probe("e.record->>'tool' = 'observation.health' AND e.record->>'ts' < "+un) + " OR " +
		probe("e.record->>'tool' = 'observation'"+inWindow) + " OR " +
		probe("e.record->>'tool' = 'observation.audit-gap'"+inWindow) +
		") ORDER BY scope LIMIT " + b.arg(limit)
	return sql, b.args
}

// HealthBefore is the scope's health records before `before`, per source from the newest record the collector wrote as
// healthy (its anchor; every record of a source with none), in seq order. Per source: the sources are a skip scan over
// clearance_evidence_health_src (scope, source), the anchor is one backward probe of clearance_evidence_health_ok, and the
// records are a range of clearance_evidence_health_src from the anchor's seq, ts tested on the index tuple. So it reads the
// records it returns and the anchors, not the history before them. (A window function over the scope's whole health
// history found the same anchors, and read every record to do it: it passed the statement timeout on two weeks of a lab.)
// The anchor is proved against clearance_evidence_health_ok's predicate, so the core's provider name is a literal here.
func (s *PG) HealthBefore(ctx context.Context, v *Viewer, scope, before string) ([]Record, error) {
	sql, args := healthBeforeSQL(v, scope, before)
	return s.records(ctx, sql, args)
}

// healthBeforeSQL is the statement of HealthBefore.
func healthBeforeSQL(v *Viewer, scope, before string) (string, []any) {
	b := &q{}
	with := b.evidenceScope(v)
	vis := b.sql()
	health := "e.record->>'tool' = 'observation.health' AND e.record->>'scope' = " + b.arg(scope)
	bf := b.arg(before)
	cn := "'" + strings.ReplaceAll(evidence.CoreProviderName, "'", "''") + "'"
	src := "COALESCE(e.record->'source'->>'name', '')"
	sql := withRecursive(with) +
		"src(name) AS ((SELECT " + src + " FROM clearance_evidence e WHERE " + health + " ORDER BY 1 LIMIT 1) UNION ALL " +
		"SELECT (SELECT " + src + " FROM clearance_evidence e WHERE " + health + " AND " + src + " > src.name ORDER BY 1 LIMIT 1) " +
		"FROM src WHERE src.name IS NOT NULL), " +
		"an AS MATERIALIZED (SELECT src.name, COALESCE((SELECT e.seq FROM clearance_evidence e WHERE " + health +
		" AND COALESCE(e.record->'provider'->>'name', '') <> " + cn + " AND e.record->'health'->>'state' = 'healthy' AND " +
		src + " = src.name AND e.record->>'ts' < " + bf + " AND " + vis + " ORDER BY e.seq DESC LIMIT 1), -1) AS aseq " +
		"FROM src WHERE src.name IS NOT NULL) " +
		// ORDER BY inside the lateral keeps it a subquery the planner cannot pull up: a parameterised range scan per source,
		// not a hash join over the scope's whole health history.
		"SELECT r.record::text, r.assurance FROM an CROSS JOIN LATERAL (SELECT e.seq, e.record, e.assurance FROM clearance_evidence e WHERE " +
		health + " AND " + src + " = an.name AND e.seq >= an.aseq AND e.record->>'ts' < " + bf + " AND " + vis + " ORDER BY e.seq) r ORDER BY r.seq"
	return sql, b.args
}

func (s *PG) EvidenceOne(ctx context.Context, seq int64, v *Viewer) (Record, error) {
	b := &q{}
	b.add("e.seq = " + b.arg(seq))
	with := b.evidenceScope(v)
	rs, err := s.records(ctx, with+"SELECT e.record::text, e.assurance FROM clearance_evidence e WHERE "+b.sql(), b.args)
	if err != nil || len(rs) == 0 {
		return nil, err
	}
	return rs[0], nil
}

func (s *PG) counts(ctx context.Context, sql string, args []any) ([]Count, error) {
	rows, done, err := s.R.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.Count); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// countColumn is the SQL expression of a counts `by` (provider is the record's provider.name).
func countColumn(by string) (string, bool) {
	if !in(CountBy, by) {
		return "", false
	}
	if by == "provider" {
		return "e.record->'provider'->>'name'", true
	}
	return "e.record->>'" + by + "'", true
}

func (s *PG) Counts(ctx context.Context, f EvidenceFilter, v *Viewer, by string) ([]Count, error) {
	if !in(CountBy, by) {
		return nil, fmt.Errorf("api: count by %q", by)
	}
	b := &q{}
	with := b.evidenceScope(v)
	b.evidenceFilter(f)
	col, _ := countColumn(by)
	return s.counts(ctx, with+"SELECT "+col+", count(*) FROM clearance_evidence e WHERE "+b.sql()+
		" GROUP BY "+col+" ORDER BY count(*) DESC, 1 LIMIT "+b.arg(MaxLimit), b.args)
}

// CostRecords is the records counts by=cost sums: the model-call outcomes that carry usage and the run.finish
// records that carry cost. The core's clearance_evidence_cost partial index (pg.Schema) covers exactly these.
const costRecords = "((e.record->>'tool' = 'model.call' AND e.record ? 'outcome_of' AND e.record ? 'usage') OR " +
	"(e.record->>'tool' = 'run.finish' AND e.record ? 'cost'))"

// sumOf is the sum of an integer field of a record's object (a value that is not a number counts 0), as bigint.
func sumOf(obj, k, filter string) string {
	v := "e.record->'" + obj + "'->'" + k + "'"
	return "coalesce(sum(CASE WHEN jsonb_typeof(" + v + ") = 'number' THEN (" + v + ")::text::numeric END) FILTER (WHERE " +
		filter + "), 0)::bigint"
}

const (
	isModelCall = "e.record->>'tool' = 'model.call'"
	isRunFinish = "e.record->>'tool' = 'run.finish'"
)

// costSQL is Costs's statement and its arguments.
func costSQL(f EvidenceFilter, v *Viewer, per string) (string, []any, error) {
	field, ok := costField[per]
	if !ok {
		return "", nil, fmt.Errorf("api: cost per %q", per)
	}
	b := &q{}
	with := b.evidenceScope(v)
	f.Outcomes = OutcomesInclude
	b.evidenceFilter(f)
	b.add(costRecords)
	col := "e.record->>'" + field + "'"
	charged := sumOf("usage", "charged_tokens", isModelCall)
	// g is every group; the page is the most charged MaxLimit of them, each row carrying the sums over all of g (a
	// window over the groups, computed before the LIMIT), so the answer's totals are never the page's.
	grouped := "SELECT " + col + " AS k, count(*) FILTER (WHERE " + isModelCall + ") AS calls, " + charged + " AS charged, " +
		sumOf("usage", "input_tokens", isModelCall) + " AS input, " + sumOf("usage", "output_tokens", isModelCall) + " AS output, " +
		sumOf("usage", "cache_creation_input_tokens", isModelCall) + " AS cwrite, " +
		sumOf("usage", "cache_read_input_tokens", isModelCall) + " AS cread, count(*) FILTER (WHERE " + isRunFinish + ") AS runs, " +
		sumOf("cost", "wall_seconds", isRunFinish) + " AS wall" +
		" FROM clearance_evidence e WHERE " + b.sql() + " GROUP BY " + col
	if with == "" {
		with = "WITH "
	} else {
		with += ", "
	}
	tot := func(c string) string { return "coalesce(sum(" + c + ") OVER (), 0)::bigint" }
	sql := with + "g AS (" + grouped + ") SELECT k, calls, charged, input, output, cwrite, cread, runs, wall, " +
		tot("calls") + ", " + tot("charged") + ", " + tot("input") + ", " + tot("output") + ", " + tot("cwrite") + ", " +
		tot("cread") + ", " + tot("runs") + ", " + tot("wall") + " FROM g ORDER BY charged DESC, k LIMIT " + b.arg(MaxLimit)
	return sql, b.args, nil
}

func (s *PG) Costs(ctx context.Context, f EvidenceFilter, v *Viewer, per string) ([]Count, CostSum, error) {
	var all CostSum
	sql, args, err := costSQL(f, v, per)
	if err != nil {
		return nil, all, err
	}
	rows, done, err := s.R.Query(ctx, sql, args...)
	if err != nil {
		return nil, all, err
	}
	defer done()
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		c := Count{Cost: &CostSum{}}
		x := c.Cost
		if err := rows.Scan(&c.Key, &x.ModelCalls, &x.ChargedTokens, &x.InputTokens, &x.OutputTokens,
			&x.CacheCreationInputTokens, &x.CacheReadInputTokens, &x.Runs, &x.WallSeconds, &all.ModelCalls,
			&all.ChargedTokens, &all.InputTokens, &all.OutputTokens, &all.CacheCreationInputTokens,
			&all.CacheReadInputTokens, &all.Runs, &all.WallSeconds); err != nil {
			return nil, all, fmt.Errorf("pg: %w", err)
		}
		c.Count = x.ModelCalls
		out = append(out, c)
	}
	return out, all, rows.Err()
}

// likeEscape escapes LIKE's wildcards (api.py did not: a repo with "_" matched one character more).
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (s *PG) ByPR(ctx context.Context, tools []string, f PRFilter, v *Viewer) ([]Record, error) {
	b := &q{}
	repo, pr := f.Repo, f.PR
	b.add("e.record->>'tool' = ANY(" + b.arg(tools) + ")")
	match := "(e.record->'effect'->>'repo' = " + b.arg(repo)
	if pr != "" {
		match += " AND e.record->'effect'->>'pr' = " + b.arg(pr) + ") OR e.record->>'target' = " + b.arg(repo+"#"+pr)
	} else {
		match += ") OR e.record->>'target' LIKE " + b.arg(likeEscape(repo)+"#%")
	}
	b.add("(" + match + ")")
	if f.Installation != "" {
		inst := b.arg(InstallationPrincipal(f.Installation))
		if f.ByInstaller {
			b.add("e.record->>'principal' = " + inst)
		} else {
			// A receipt's pull request is its effect's repo#pr, or its target. clearance_evidence_app serves the
			// lookup (the installation's records by principal).
			b.add("EXISTS (SELECT 1 FROM clearance_evidence i WHERE i.record->>'principal' = " + inst +
				" AND i.record->>'principal' LIKE 'app:%' AND i.record->>'tool' = 'provenance.verify' AND i.record->>'target' = " +
				"COALESCE((e.record->'effect'->>'repo') || '#' || (e.record->'effect'->>'pr'), e.record->>'target'))")
		}
	}
	with := b.evidenceScope(v)
	return s.records(ctx, with+"SELECT e.record::text, e.assurance FROM clearance_evidence e WHERE "+b.sql()+
		" ORDER BY e.seq DESC LIMIT "+b.arg(MaxLimit), b.args)
}

func (s *PG) Verify(ctx context.Context) (Verified, error) {
	cp, err := s.R.Verify(ctx, nil)
	var bad *evidence.BadRecord
	switch {
	case errors.As(err, &bad):
		seq := bad.Seq
		return Verified{OK: false, Count: cp.Count, Head: cp.Head, BadSeq: &seq}, nil
	case err != nil:
		return Verified{}, err
	}
	return Verified{OK: true, Count: cp.Count, Head: cp.Head}, nil
}

// changeScope is api.py _change_scope: changes on apps the person owns, and changes whose owner group or outside
// groups include one of theirs (the people who may clear them). An outsideGroups that is not an array (JSON null:
// a change with no outside requirement) is none; api.py's COALESCE let a null fail the whole query.
func (b *q) changeScope(v *Viewer) {
	if v.AllChanges() {
		return
	}
	if v.Role == RoleFeed {
		if !in(v.Clusters, "*") {
			b.add("c.record->>'cluster' = ANY(" + b.arg(v.Clusters) + ")")
		}
		return
	}
	g := b.arg(v.Groups)
	b.add("(c.app = ANY(" + b.arg(v.Apps) + ") OR c.record->>'owner' = ANY(" + g + ") " +
		"OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(c.record->'requirement'->'outsideGroups') = 'array' " +
		"THEN c.record->'requirement'->'outsideGroups' ELSE '[]'::jsonb END) g " +
		"WHERE g = ANY(" + g + ")))")
}

func (b *q) changeFilter(f ChangeFilter, list bool) {
	b.eq("c.app", f.App)
	b.eq("c.env", f.Env)
	b.eq("c.state", f.State)
	if list {
		b.eq("c.repo", f.Repo)
		if f.PR != nil {
			b.add("c.pr = " + b.arg(*f.PR))
		}
		if f.Tier != nil {
			b.add("(c.record->>'tier')::int = " + b.arg(*f.Tier))
		}
		if f.Cluster != "" {
			b.add("c.record->>'cluster' = " + b.arg(f.Cluster))
		}
		if f.LiveAt != nil {
			// clearance_tokens_feed (cluster, expires_at) WHERE revoked_at IS NULL, by the token's primary key.
			at := b.arg(*f.LiveAt)
			b.add("EXISTS (SELECT 1 FROM clearance_tokens t WHERE t.change_id = c.id AND t.revoked_at IS NULL " +
				"AND t.expires_at > " + at + ")")
		}
	}
	if f.Since != "" {
		b.add("c.record->>'updated_at' >= " + b.arg(f.Since))
	}
}

func (s *PG) raws(ctx context.Context, sql string, args []any) ([]json.RawMessage, error) {
	rows, done, err := s.R.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		out = append(out, json.RawMessage(text))
	}
	return out, rows.Err()
}

func (s *PG) Changes(ctx context.Context, f ChangeFilter, v *Viewer, limit int, after string) ([]json.RawMessage, error) {
	b := &q{}
	b.changeScope(v)
	b.changeFilter(f, true)
	if after != "" {
		ts, id := splitCursor(after)
		if id == "" { // the older cursor: strictly older than a time
			b.add("c.record->>'updated_at' < " + b.arg(ts))
		} else {
			tsArg, idArg := b.arg(ts), b.arg(id)
			b.add("(c.record->>'updated_at' < " + tsArg + " OR (c.record->>'updated_at' = " + tsArg + " AND c.id < " + idArg + "))")
		}
	}
	return s.raws(ctx, "SELECT c.record::text FROM clearance_changes c WHERE "+b.sql()+
		" ORDER BY c.record->>'updated_at' DESC, c.id DESC LIMIT "+b.arg(limit), b.args)
}

func (s *PG) Change(ctx context.Context, id string) (json.RawMessage, error) {
	rs, err := s.raws(ctx, "SELECT record::text FROM clearance_changes WHERE id = $1", []any{id})
	if err != nil || len(rs) == 0 {
		return nil, err
	}
	return rs[0], nil
}

// changeCountCol is api.py change_counts' column per `by`.
var changeCountCol = map[string]string{"state": "c.state", "tier": "c.record->>'tier'", "app": "c.app",
	"env": "c.env", "cleared_by": "c.record->>'cleared_by'", "attestation": attestationState}

func (s *PG) ChangeCounts(ctx context.Context, f ChangeFilter, v *Viewer, by string) ([]Count, error) {
	col, ok := changeCountCol[by]
	if !ok {
		return nil, fmt.Errorf("api: count changes by %q", by)
	}
	b := &q{}
	b.changeScope(v)
	b.changeFilter(f, false)
	return s.counts(ctx, "SELECT "+col+", count(*) FROM clearance_changes c WHERE "+b.sql()+
		" GROUP BY "+col+" ORDER BY count(*) DESC", b.args)
}

func (s *PG) Definitions(ctx context.Context) ([]store.Definition, error) {
	return s.R.Definitions(ctx)
}

func (s *PG) Tokens(ctx context.Context, ids []string, now time.Time) (map[string]store.Token, error) {
	out := map[string]store.Token{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, done, err := s.R.Query(ctx, "SELECT "+pg.TokenCols+" FROM clearance_tokens WHERE change_id = ANY($1) "+
		"AND revoked_at IS NULL AND expires_at > $2", ids, now)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	for rows.Next() {
		tk, err := pg.ScanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		out[tk.ChangeID] = tk
	}
	return out, rows.Err()
}

func (s *PG) SigningKeys(ctx context.Context, since time.Time) ([]store.SigningKey, error) {
	return s.R.SigningKeys(ctx, since)
}

func (s *PG) Ping(ctx context.Context) error {
	_, _, err := s.R.Head(ctx)
	return err
}

func (s *PG) Head(ctx context.Context) (int64, error) {
	seq, _, err := s.R.Head(ctx)
	return seq, err
}

func (s *PG) EvidenceAfter(ctx context.Context, f EvidenceFilter, v *Viewer, after int64, limit int) ([]Record, error) {
	b := &q{}
	with := b.evidenceScope(v)
	b.evidenceFilter(f)
	b.add("e.seq > " + b.arg(after))
	return s.records(ctx, with+"SELECT e.record::text, e.assurance FROM clearance_evidence e WHERE "+b.sql()+
		" ORDER BY e.seq LIMIT "+b.arg(limit), b.args)
}

// DeploysAfter reads the primary key's range above after; the change by its primary key.
func (s *PG) DeploysAfter(ctx context.Context, after int64, limit int) ([]DeployEvent, error) {
	rows, done, err := s.R.Query(ctx, "SELECT e.seq, e.record->>'tool', COALESCE(e.record->>'ts', ''), "+
		"(e.record->'change')::text, c.record::text FROM clearance_evidence e "+
		"LEFT JOIN clearance_changes c ON c.id = e.record->'change'->>'id' "+
		"WHERE e.seq > $1 AND e.record->>'tool' LIKE 'deploy.%' AND jsonb_typeof(e.record->'change') = 'object' "+
		"ORDER BY e.seq LIMIT $2", after, limit)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	out := []DeployEvent{}
	for rows.Next() {
		var d DeployEvent
		var summary string
		var change *string
		if err := rows.Scan(&d.Seq, &d.Tool, &d.TS, &summary, &change); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		d.Summary = json.RawMessage(summary)
		if change != nil {
			d.Change = json.RawMessage(*change)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *PG) Attestation(ctx context.Context, changeID string) (*store.Attestation, error) {
	a, err := s.R.Attestation(ctx, changeID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *PG) Feed(ctx context.Context, cluster string) (*store.Feed, error) {
	f, err := s.R.Feed(ctx, cluster)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// Installations reads clearance_evidence_app (the App installations' records, by principal and seq).
func (s *PG) Installations(ctx context.Context) ([]Installation, error) {
	const app = "e.record->>'principal' LIKE 'app:%'"
	byID := map[string]*Installation{}
	var order []string
	rows, done, err := s.R.Query(ctx, "SELECT p, tool, n, first, last, first_ts, last_ts FROM (SELECT "+
		"e.record->>'principal' AS p, COALESCE(e.record->>'tool', '') AS tool, count(*) AS n, min(e.seq) AS first, "+
		"max(e.seq) AS last, COALESCE(min(e.record->>'ts'), '') AS first_ts, COALESCE(max(e.record->>'ts'), '') AS last_ts "+
		"FROM clearance_evidence e WHERE "+app+" GROUP BY 1, 2) g "+`ORDER BY p COLLATE "C", tool COLLATE "C"`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p, tool, firstTS, lastTS string
		var n, first, last int64
		if err := rows.Scan(&p, &tool, &n, &first, &last, &firstTS, &lastTS); err != nil {
			rows.Close()
			done()
			return nil, fmt.Errorf("pg: %w", err)
		}
		in := byID[p]
		if in == nil {
			if len(order) >= MaxLimit {
				continue
			}
			in = newInstallation(p)
			byID[p] = in
			order = append(order, p)
		}
		in.add(tool, n, first, last, firstTS, lastTS)
	}
	rows.Close()
	done()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, done, err = s.R.Query(ctx, "SELECT DISTINCT ON (e.record->>'principal') e.record->>'principal', "+
		"e.record->>'target', COALESCE(e.record->>'result', '') FROM clearance_evidence e WHERE "+app+
		" AND e.record->>'tool' = 'app.installation' ORDER BY e.record->>'principal', e.seq DESC")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p, result string
		var account *string
		if err := rows.Scan(&p, &account, &result); err != nil {
			rows.Close()
			done()
			return nil, fmt.Errorf("pg: %w", err)
		}
		if in := byID[p]; in != nil {
			in.last(account, result)
		}
	}
	rows.Close()
	done()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, done, err = s.R.Query(ctx, "SELECT p, repo FROM (SELECT DISTINCT e.record->>'principal' AS p, "+
		"split_part(e.record->>'target', '#', 1) AS repo FROM clearance_evidence e WHERE "+app+
		" AND e.record->>'tool' = 'provenance.verify' AND e.record->>'target' LIKE '%#%') r "+
		`ORDER BY p COLLATE "C", repo COLLATE "C"`)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	for rows.Next() {
		var p, repo string
		if err := rows.Scan(&p, &repo); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		if in := byID[p]; in != nil && len(in.Repos) < MaxLimit {
			in.Repos = append(in.Repos, repo)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Installation, 0, len(order))
	for _, p := range order {
		out = append(out, *byID[p])
	}
	return out, nil
}

func in(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// attestationState is the by=attestation group of a change: attested (an attestation row), pending (the deploy
// reported an applied outcome and no attestation is stored yet: the signer is waiting or retrying) or none (nothing
// to attest: no applied outcome).
const attestationState = "CASE WHEN EXISTS (SELECT 1 FROM clearance_attestations a WHERE a.change_id = c.id) THEN 'attested' " +
	"WHEN c.record->'outcome'->>'applied' = 'true' THEN 'pending' ELSE 'none' END"

// ChangeRecords reads clearance_evidence_change: (the change id, seq) of the deploy.* records. The LIKE is the
// index's own predicate, spelled as the index spells it.
func (s *PG) ChangeRecords(ctx context.Context, id, tool string, limit int, after *int64) ([]Record, error) {
	b := &q{}
	b.add("e.record->'change'->>'id' = " + b.arg(id))
	b.add("e.record->>'tool' LIKE 'deploy.%'")
	if tool != "" {
		b.add("e.record->>'tool' = " + b.arg(tool))
	}
	if after != nil {
		b.add("e.seq > " + b.arg(*after))
	}
	return s.records(ctx, "SELECT e.record::text, e.assurance FROM clearance_evidence e WHERE "+b.sql()+
		" ORDER BY e.seq LIMIT "+b.arg(limit), b.args)
}

// attestationRefCols are clearance_attestations' columns without the bundle, in scanAttestationRef's order.
const attestationRefCols = "a.change_id, a.digest, a.backend, a.key_id, a.rekor_log_index, a.rekor_uuid, a.outcome_seq, a.record_seq, a.created_at"

func scanAttestationRef(row pgx.Row, extra ...any) (store.Attestation, error) {
	var a store.Attestation
	dst := append([]any{&a.ChangeID, &a.Digest, &a.Backend, &a.KeyID, &a.RekorLogIndex, &a.RekorUUID, &a.OutcomeSeq,
		&a.RecordSeq, &a.CreatedAt}, extra...)
	err := row.Scan(dst...)
	return a, err
}

// Attestations walks clearance_attestations_seq (record_seq DESC) and joins each row's change by its primary key.
func (s *PG) Attestations(ctx context.Context, f AttestationFilter, v *Viewer, limit int, after *int64) ([]AttestationRow, error) {
	b := &q{}
	b.changeScope(v)
	b.eq("c.app", f.App)
	b.eq("c.env", f.Env)
	if !f.Since.IsZero() {
		b.add("a.created_at >= " + b.arg(f.Since))
	}
	if !f.Until.IsZero() {
		b.add("a.created_at < " + b.arg(f.Until))
	}
	if after != nil {
		b.add("a.record_seq < " + b.arg(*after))
	}
	rows, done, err := s.R.Query(ctx, "SELECT "+attestationRefCols+", c.record::text FROM clearance_attestations a "+
		"JOIN clearance_changes c ON c.id = a.change_id WHERE "+b.sql()+" ORDER BY a.record_seq DESC LIMIT "+b.arg(limit), b.args...)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	out := []AttestationRow{}
	for rows.Next() {
		var text string
		a, err := scanAttestationRef(rows, &text)
		if err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		out = append(out, AttestationRow{Attestation: a, Change: json.RawMessage(text)})
	}
	return out, rows.Err()
}

func (s *PG) AttestationsOf(ctx context.Context, ids []string) (map[string]store.Attestation, error) {
	out := map[string]store.Attestation{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, done, err := s.R.Query(ctx, "SELECT "+attestationRefCols+" FROM clearance_attestations a WHERE a.change_id = ANY($1)", ids)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	for rows.Next() {
		a, err := scanAttestationRef(rows)
		if err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		out[a.ChangeID] = a
	}
	return out, rows.Err()
}
