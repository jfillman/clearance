package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

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
	if f.Since != "" {
		b.add("e.record->>'ts' >= " + b.arg(f.Since))
	}
	if f.Until != "" {
		b.add("e.record->>'ts' < " + b.arg(f.Until))
	}
	switch f.Outcomes {
	case OutcomesExclude:
		b.add("NOT (e.record ? 'outcome_of')")
	case OutcomesOnly:
		b.add("e.record ? 'outcome_of'")
	}
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
		v, err := canon.Parse([]byte(text))
		if err != nil {
			return nil, fmt.Errorf("pg: stored record: %w", err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("pg: stored record is not an object")
		}
		m["assurance"] = assurance
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PG) Evidence(ctx context.Context, f EvidenceFilter, v *Viewer, limit int, after *int64) ([]Record, error) {
	b := &q{}
	with := b.evidenceScope(v)
	b.evidenceFilter(f)
	if after != nil {
		b.add("e.seq < " + b.arg(*after))
	}
	return s.records(ctx, with+"SELECT e.record::text, e.assurance FROM clearance_evidence e WHERE "+b.sql()+
		" ORDER BY e.seq DESC LIMIT "+b.arg(limit), b.args)
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

func (s *PG) Counts(ctx context.Context, f EvidenceFilter, v *Viewer, by string) ([]Count, error) {
	if !in(CountBy, by) {
		return nil, fmt.Errorf("api: count by %q", by)
	}
	b := &q{}
	with := b.evidenceScope(v)
	b.evidenceFilter(f)
	col := "e.record->>'" + by + "'"
	return s.counts(ctx, with+"SELECT "+col+", count(*) FROM clearance_evidence e WHERE "+b.sql()+
		" GROUP BY "+col+" ORDER BY count(*) DESC, 1 LIMIT "+b.arg(MaxLimit), b.args)
}

// likeEscape escapes LIKE's wildcards (api.py did not: a repo with "_" matched one character more).
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (s *PG) ByPR(ctx context.Context, tools []string, repo, pr string, v *Viewer) ([]Record, error) {
	b := &q{}
	b.add("e.record->>'tool' = ANY(" + b.arg(tools) + ")")
	match := "(e.record->'effect'->>'repo' = " + b.arg(repo)
	if pr != "" {
		match += " AND e.record->'effect'->>'pr' = " + b.arg(pr) + ") OR e.record->>'target' = " + b.arg(repo+"#"+pr)
	} else {
		match += ") OR e.record->>'target' LIKE " + b.arg(likeEscape(repo)+"#%")
	}
	b.add("(" + match + ")")
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
	if v.All() {
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
		b.add("c.record->>'updated_at' < " + b.arg(after))
	}
	return s.raws(ctx, "SELECT c.record::text FROM clearance_changes c WHERE "+b.sql()+
		" ORDER BY c.record->>'updated_at' DESC LIMIT "+b.arg(limit), b.args)
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
	"env": "c.env", "cleared_by": "c.record->>'cleared_by'"}

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

func in(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
