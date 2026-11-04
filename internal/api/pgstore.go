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
	if f.Installation != "" {
		b.add("e.record->>'principal' = " + b.arg(InstallationPrincipal(f.Installation)))
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
