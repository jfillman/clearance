package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
)

// The Map's reads (GET /v1/map): each is one aggregate statement, so the Map costs a fixed number of queries however
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
// wrote with a `policy` that is not an outcome. The statement reads only the records on the clearance_evidence_gate
// partial index (the gate predicate below, spelled as the index spells it), by ts range: it never walks the chain.
func (s *PG) GateActivity(ctx context.Context, v *Viewer, from, to string) ([]GateRow, bool, error) {
	b := &q{}
	with := b.evidenceScope(v)
	core := b.arg(evidence.CoreProviderName)
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
// `before` from the last one the collector wrote as healthy through the newest. It reads the newest healthTail
// records of each scope (clearance_evidence_health, backwards from `before`) and finds the anchor among them, so its
// cost is bounded however long the chain is. The Map reads the state at the window's end, so only a core-written flip
// (monitoring forced blind or degraded) that has held for more than healthTail records of one scope, with no healthy
// collector record since, loses its start: its state still reads as the flip's, from the oldest record read.
func (s *PG) HealthBeforeScopes(ctx context.Context, v *Viewer, scopes []string, before string) ([]Record, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	b := &q{}
	with := b.evidenceScope(v)
	b.add("e.record->>'tool' = 'observation.health'")
	b.add("e.record->>'scope' = s.scope")
	b.add("e.record->>'ts' < " + b.arg(before))
	core := b.arg(evidence.CoreProviderName)
	list := b.arg(scopes)
	pre := "h AS (SELECT t.seq, t.record, t.assurance, " +
		"max(CASE WHEN COALESCE(t.record->'provider'->>'name', '') <> " + core + " AND t.record->'health'->>'state' = 'healthy' " +
		"THEN t.seq END) OVER (PARTITION BY s.scope, COALESCE(t.record->'source'->>'name', '')) AS aseq " +
		"FROM unnest(" + list + "::text[]) AS s(scope) CROSS JOIN LATERAL (SELECT e.seq, e.record, e.assurance FROM clearance_evidence e WHERE " +
		b.sql() + " ORDER BY e.seq DESC LIMIT " + fmt.Sprint(healthTail) + ") t) "
	if with == "" {
		with = "WITH "
	} else {
		with = strings.TrimRight(with, " ") + ", "
	}
	return s.records(ctx, with+pre+"SELECT h.record::text, h.assurance FROM h WHERE h.seq >= COALESCE(h.aseq, -1) ORDER BY h.seq", b.args)
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
