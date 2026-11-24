package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
)

// The Map's reads (GET /v1/map): each is one aggregate statement (the gate read also probes for its first seq, one index
// lookup), so the Map costs a fixed number of queries (five) however
// many gates, targets and records there are. None pages a history into Go.

// MaxGateRows caps the groups GateActivity returns; past it the Map says truncated.
const MaxGateRows = 5000

// GateRow is a group of the gate records in a window: who wrote them (Provider: the registered provider's name, ""
// when the core wrote them; RegisteredBy: the principal that registered the change they name, "" when they name none),
// the boundary, tool, decision and coverage, the application and environment of the change, how many records and how
// many distinct changes.
type GateRow struct {
	Provider, RegisteredBy, Boundary, Tool, Decision, Coverage, App, Env string
	// Applied and Matched are a deploy.outcome's outcome.applied and matched ("true" or "false"; "" on any other record).
	Applied, Matched string
	Count, Changes   int64
}

// ScopeRow is a group of a scope's observation records in a window: observations, and assessments with their coverage
// (an assessment counts once per observation it is about).
type ScopeRow struct {
	Scope, Tool, Coverage string
	Count                 int64
}

// HoldRow is a group of the changes holding now: the registrant, application, environment and tier.
type HoldRow struct {
	RegisteredBy, App, Env string
	Tier                   int
	Count                  int64
	Oldest                 string // the oldest change's created_at
}

// gateTools are the deployment records the Map counts: the change's life (request, decided, expired), what happened
// to the cluster (outcome) and what a gate or an observer reported (exception, degraded).
const gateTools = "('deploy.request', 'deploy.clear', 'deploy.deny', 'deploy.expire', 'deploy.outcome', 'deploy.exception', 'deploy.degraded')"

// GateActivity groups the gate records of [from, to) the viewer may see. A runtime decision is a record the core
// wrote with a `policy` that is not an outcome. With clearance_evidence_gate built, the statement reads only the
// records on that partial index (the gate predicate below, spelled as the index spells it), by ts range. Before it is
// built, the statement reads the chain from the first record written at or after from, as it did before the index
// existed: the cost is the window's records, not the whole chain.
func (s *PG) GateActivity(ctx context.Context, v *Viewer, from, to string) ([]GateRow, bool, error) {
	b := &q{}
	with := b.evidenceScope(v)
	core := b.arg(evidence.CoreProviderName)
	fromT, err := time.Parse(time.RFC3339, from)
	if err != nil {
		return nil, false, fmt.Errorf("api: gate activity from %q", from)
	}
	// Bounded below by the first record written at or after from (clearance_evidence_written, which exists from the
	// first start of any version): a record's ts is stamped when it is written, so none with ts >= from was written
	// long before from. This is what keeps the statement off the older chain until clearance_evidence_gate is built.
	// The first seq is read on its own so that the statement carries it as a plain number: as a subselect the planner
	// guesses a third of the chain and walks it with a table scan.
	lo, found, err := s.firstSeqWrittenAt(ctx, fromT)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil // nothing was written in the window, so nothing in it has gate activity
	}
	b.add("e.seq >= " + b.arg(lo))
	b.add("e.record->>'ts' >= " + b.arg(from))
	b.add("e.record->>'ts' < " + b.arg(to))
	b.add("(e.record->>'tool' IN " + gateTools + " OR (e.record->>'boundary' = 'runtime' AND e.record ? 'policy' AND NOT (e.record ? 'outcome_of')))")
	// One jsonb_to_record per record: a record is TOASTed, and each e.record->>'f' would fetch and decompress it again.
	cols := "COALESCE(NULLIF(x.provider->>'name', " + core + "), ''), COALESCE(c.record->>'registered_by', ''), " +
		"COALESCE(x.boundary, ''), COALESCE(x.tool, ''), COALESCE(x.decision, ''), " +
		"COALESCE(x.coverage, ''), CASE WHEN x.boundary = 'deployment' THEN COALESCE(x.app, '') ELSE '' END, " +
		"COALESCE(x.change->>'env', ''), COALESCE(x.outcome->>'applied', ''), COALESCE(x.matched, '')"
	rows, done, err := s.R.Query(ctx, with+"SELECT "+cols+", count(*), count(DISTINCT x.change->>'id') "+
		"FROM clearance_evidence e CROSS JOIN LATERAL jsonb_to_record(e.record) AS x(provider jsonb, boundary text, tool text, "+
		"decision text, coverage text, app text, change jsonb, outcome jsonb, matched text) "+
		"LEFT JOIN clearance_changes c ON c.id = x.change->>'id' WHERE "+b.sql()+
		" GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 LIMIT "+b.arg(MaxGateRows+1), b.args...)
	if err != nil {
		return nil, false, err
	}
	defer done()
	defer rows.Close()
	var out []GateRow
	for rows.Next() {
		var g GateRow
		if err := rows.Scan(&g.Provider, &g.RegisteredBy, &g.Boundary, &g.Tool, &g.Decision, &g.Coverage, &g.App, &g.Env,
			&g.Applied, &g.Matched, &g.Count, &g.Changes); err != nil {
			return nil, false, fmt.Errorf("pg: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	cut := len(out) > MaxGateRows
	if cut {
		out = out[:MaxGateRows]
	}
	return out, cut, nil
}

// firstSeqWrittenAt is the seq of the first record written at or after t, and whether there is one. It orders by written_at, so it
// is served by clearance_evidence_written; min(seq) with a filter walks the primary key from the first record instead.
func (s *PG) firstSeqWrittenAt(ctx context.Context, t time.Time) (int64, bool, error) {
	rows, done, err := s.R.Query(ctx, "SELECT seq FROM clearance_evidence WHERE written_at >= $1 ORDER BY written_at, seq LIMIT 1", t)
	if err != nil {
		return 0, false, err
	}
	defer done()
	defer rows.Close()
	var n int64
	if !rows.Next() {
		return 0, false, rows.Err()
	}
	if err := rows.Scan(&n); err != nil {
		return 0, false, fmt.Errorf("pg: %w", err)
	}
	return n, true, rows.Err()
}

// ScopeCoverage groups the observations and assessments of the scopes in [from, to), on the clearance_evidence_obs_ts
// partial index (scope, ts: the tool predicate is repeated literally), so it reads the records of the window and no others.
func (s *PG) ScopeCoverage(ctx context.Context, v *Viewer, scopes []string, from, to string) ([]ScopeRow, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	b := &q{}
	with := b.evidenceScope(v)
	b.add("e.record->>'tool' IN ('observation', 'assessment')")
	b.add("e.record->>'scope' = ANY(" + b.arg(scopes) + ")")
	b.add("e.record->>'ts' >= " + b.arg(from))
	b.add("e.record->>'ts' < " + b.arg(to))
	rows, done, err := s.R.Query(ctx, with+"SELECT e.record->>'scope', e.record->>'tool', COALESCE(e.record->>'coverage', ''), "+
		"CASE WHEN e.record->>'tool' = 'assessment' THEN count(DISTINCT e.record->'about'->>'seq') ELSE count(*) END "+
		"FROM clearance_evidence e WHERE "+b.sql()+" GROUP BY 1, 2, 3", b.args...)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	var out []ScopeRow
	for rows.Next() {
		var r ScopeRow
		if err := rows.Scan(&r.Scope, &r.Tool, &r.Coverage, &r.Count); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// healthTail is how many of a scope's newest health records HealthBeforeScopes reads (see there).
const healthTail = 500

// HealthBeforeScopes is HealthBefore for many scopes in one pass: per scope and source, the health records before
// `before` from the last one the collector wrote as healthy through the newest. One statement, two parts:
//   - the newest healthTail health records of each scope (clearance_evidence_health_page, backwards from `before`), from the
//     newest healthy collector record among them (or all of them, when there is none);
//   - every health record the core wrote (a flip: monitoring forced blind or degraded) after the newest healthy collector
//     record of its source, however old (clearance_evidence_health_core and clearance_evidence_health_ok). A flip holds
//     until the collector reports healthy, so a flip older than the tail is still read, and the Map never shows a source
//     better than the core's standing declaration.
//
// Its cost is the tail, the core's records since each source last reported healthy (few), and one index probe per
// such record: bounded however long the chain is. What the bound still loses is the collector's own older records: a
// source with no record among a scope's newest healthTail and no core flip since its last healthy report reads as
// never seen, not stale (both blind). The viewer here is always an auditor (readerOf), so the anchor probe applies no
// viewer condition.
func (s *PG) HealthBeforeScopes(ctx context.Context, v *Viewer, scopes []string, before string) ([]Record, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	b := &q{}
	with := b.evidenceScope(v)
	bf := b.arg(before)
	b.add("e.record->>'tool' = 'observation.health'")
	b.add("e.record->>'scope' = s.scope")
	b.add("e.record->>'ts' < " + bf)
	core := b.arg(evidence.CoreProviderName)
	list := b.arg(scopes)
	conds := b.sql()
	cn := "'" + strings.ReplaceAll(evidence.CoreProviderName, "'", "''") + "'" // inline: a partial index is proved from a literal
	pre := "h AS (SELECT t.seq, t.record, t.assurance, " +
		"max(CASE WHEN COALESCE(t.record->'provider'->>'name', '') <> " + core + " AND t.record->'health'->>'state' = 'healthy' " +
		"THEN t.seq END) OVER (PARTITION BY s.scope, COALESCE(t.record->'source'->>'name', '')) AS aseq " +
		"FROM unnest(" + list + "::text[]) AS s(scope) CROSS JOIN LATERAL (SELECT e.seq, e.record, e.assurance FROM clearance_evidence e WHERE " +
		conds + " AND e.record->>'tool' = 'observation.health' ORDER BY e.seq DESC LIMIT " + fmt.Sprint(healthTail) + ") t) "
	flips := "SELECT c.record::text, c.assurance, c.seq FROM unnest(" + list + "::text[]) AS s(scope) CROSS JOIN LATERAL (" +
		"SELECT e.seq, e.record, e.assurance FROM clearance_evidence e WHERE " + conds + " AND e.record->'provider'->>'name' = " + cn + ") c " +
		"WHERE c.seq > COALESCE((SELECT a.seq FROM clearance_evidence a WHERE a.record->>'tool' = 'observation.health' " +
		"AND COALESCE(a.record->'provider'->>'name', '') <> " + cn + " AND a.record->'health'->>'state' = 'healthy' " +
		"AND a.record->>'scope' = s.scope AND COALESCE(a.record->'source'->>'name', '') = COALESCE(c.record->'source'->>'name', '') " +
		"AND a.record->>'ts' < " + bf + " ORDER BY a.seq DESC LIMIT 1), -1)"
	if with == "" {
		with = "WITH "
	} else {
		with = strings.TrimRight(with, " ") + ", "
	}
	rows, done, err := s.R.Query(ctx, with+pre+"SELECT h.record::text, h.assurance, h.seq FROM h WHERE h.seq >= COALESCE(h.aseq, -1) UNION ALL "+flips+
		" ORDER BY 3", b.args...)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	out := []Record{}
	seen := map[int64]bool{} // a core flip inside the tail is in both parts
	for rows.Next() {
		var text, assurance string
		var seq int64
		if err := rows.Scan(&text, &assurance, &seq); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		if seen[seq] {
			continue
		}
		seen[seq] = true
		m, err := parseStored(text, assurance)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Holding groups the changes holding now that the viewer may see (clearance_changes_state).
func (s *PG) Holding(ctx context.Context, v *Viewer) ([]HoldRow, error) {
	b := &q{}
	b.changeScope(v)
	b.add("c.state = 'holding'")
	rows, done, err := s.R.Query(ctx, "SELECT COALESCE(c.record->>'registered_by', ''), c.app, c.env, "+
		"COALESCE((c.record->>'tier')::int, 0), count(*), COALESCE(min(c.record->>'created_at'), '') "+
		"FROM clearance_changes c WHERE "+b.sql()+" GROUP BY 1, 2, 3, 4", b.args...)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	var out []HoldRow
	for rows.Next() {
		var h HoldRow
		if err := rows.Scan(&h.RegisteredBy, &h.App, &h.Env, &h.Tier, &h.Count, &h.Oldest); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Targets are the declared target sets (clearance_targets).
func (s *PG) Targets(ctx context.Context) ([]store.TargetSet, error) { return s.R.Targets(ctx) }

// MaxBucketItems caps the groups of a bucketed count.
const MaxBucketItems = 10000

// CountBuckets is Counts with the records' ts cut into buckets of `bucket` (aligned to the epoch): each group is a
// bucket and a key, in bucket order. A record whose ts is not a timestamp is not counted.
func (s *PG) CountBuckets(ctx context.Context, f EvidenceFilter, v *Viewer, by string, bucket time.Duration) ([]Count, error) {
	col, ok := countColumn(by)
	if !ok {
		return nil, fmt.Errorf("api: count by %q", by)
	}
	b := &q{}
	with := b.evidenceScope(v)
	b.evidenceFilter(f)
	b.add("e.record->>'ts' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'")
	secs := b.arg(int64(bucket / time.Second))
	bk := "floor(extract(epoch FROM (e.record->>'ts')::timestamptz) / " + secs + ")::bigint"
	rows, done, err := s.R.Query(ctx, with+"SELECT "+col+", "+bk+", count(*) FROM clearance_evidence e WHERE "+b.sql()+
		" GROUP BY 1, 2 ORDER BY 2, 3 DESC, 1 LIMIT "+b.arg(MaxBucketItems), b.args...)
	if err != nil {
		return nil, err
	}
	defer done()
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		var n int64
		if err := rows.Scan(&c.Key, &n, &c.Count); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		at := time.Unix(n*int64(bucket/time.Second), 0).UTC().Format(time.RFC3339)
		c.Bucket = &at
		out = append(out, c)
	}
	return out, rows.Err()
}
