package api

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store/pg"
)

// planNodes lists every node type and index name in an EXPLAIN (FORMAT JSON) plan.
func planNodes(t *testing.T, plan []byte) (types, indexes []string) {
	t.Helper()
	var top []map[string]any
	if err := json.Unmarshal(plan, &top); err != nil || len(top) == 0 {
		t.Fatalf("plan: %v", err)
	}
	var walk func(n map[string]any)
	walk = func(n map[string]any) {
		if s, ok := n["Node Type"].(string); ok {
			types = append(types, s)
		}
		if s, ok := n["Index Name"].(string); ok {
			indexes = append(indexes, s)
		}
		if kids, ok := n["Plans"].([]any); ok {
			for _, k := range kids {
				walk(k.(map[string]any))
			}
		}
	}
	walk(top[0]["Plan"].(map[string]any))
	return types, indexes
}

// A coverage page is one index range scan of its own rows with no Sort, and the pages are lossless and identical to
// one read of the whole window, with many records sharing a ts (the window's rows tie on ts, never on seq).
func TestCoveragePagesAreIndexRangeScansAndLossless(t *testing.T) {
	dsn := newDB(t)
	st, err := pg.Open(bg, dsn, pg.Options{Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.BuildIndexes(bg); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	// 12000 records: seq mod 4 is observation, assessment, observation (scope b), health; the ts steps once per 6 records, so each
	// ts is shared by about 4 observations and assessments of both scopes. About 3000 of each kind in scope-a, 1500 outside the window.
	if _, err := conn.Exec(bg, `INSERT INTO clearance_evidence (seq, hash, prev_hash, record, written_at)
	  SELECT i, md5(i::text) || md5(i::text), md5((i-1)::text) || md5((i-1)::text),
	    jsonb_build_object('seq', i, 'boundary', 'deployment',
	      'tool', CASE i % 4 WHEN 0 THEN 'observation' WHEN 1 THEN 'assessment' WHEN 2 THEN 'observation' ELSE 'observation.health' END,
	      'scope', CASE WHEN i % 4 = 2 THEN 'scope-b' ELSE 'scope-a' END,
	      'ts', to_char(timestamp '2026-11-01 00:00:00' + (i / 6) * interval '1 second', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	      'detail', repeat(md5(i::text), 60)),
	    timestamp '2026-11-01 00:00:00' + (i / 6) * interval '1 second'
	  FROM generate_series(0, 11999) i`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(bg, "ANALYZE clearance_evidence"); err != nil {
		t.Fatal(err)
	}
	rdr, err := pg.OpenReader(bg, dsn, pg.Options{MaxConns: 2, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer rdr.Close()
	store := &PG{R: rdr}
	aud := &Viewer{Role: RoleAuditor}
	since, until := "2026-11-01T00:08:20Z", "2026-11-01T00:25:00Z" // seq 3000 up to 9000: the middle of the chain

	for kind, index := range map[string]string{evidence.KindObservation: "clearance_evidence_obs_page", evidence.KindAssessment: "clearance_evidence_obs_page",
		evidence.KindHealth: "clearance_evidence_health_page"} {
		f := EvidenceFilter{Scope: "scope-a", Outcomes: OutcomesInclude, Slim: true, Tools: []string{kind}, Since: since, Until: until}
		// every record of the kind in the window, as the raw table says it
		var want []int64
		rows, err := conn.Query(bg, `SELECT seq FROM clearance_evidence WHERE record->>'tool' = $1 AND record->>'scope' = 'scope-a'
		  AND record->>'ts' >= $2 AND record->>'ts' < $3 ORDER BY seq DESC`, kind, since, until)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var n int64
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			want = append(want, n)
		}
		rows.Close()
		if len(want) < 1000 {
			t.Fatalf("%s: only %d records in the window; the test proves nothing", kind, len(want))
		}
		for _, page := range []int{7, 200, 1000, 100000} {
			var got []int64
			var after *int64
			for {
				rs, err := store.Evidence(bg, f, aud, page, after)
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range rs {
					n, _ := seqOf(r)
					got = append(got, n)
				}
				if len(rs) < page {
					break
				}
				n, _ := seqOf(rs[len(rs)-1])
				after = &n
			}
			if !slices.Equal(got, want) {
				t.Fatalf("%s paged by %d: %d records, want %d (lost or repeated or out of order)", kind, page, len(got), len(want))
			}
		}
		// the plan of a middle page and of the first: the new index, no Sort
		mid := want[len(want)/2]
		for _, after := range []*int64{nil, &mid} {
			sql, args := evidenceSQL(f, aud, collectPage, after)
			var plan []byte
			if err := conn.QueryRow(bg, "EXPLAIN (FORMAT JSON) "+sql, args...).Scan(&plan); err != nil {
				t.Fatal(err)
			}
			types, idx := planNodes(t, plan)
			if slices.Contains(types, "Sort") || slices.Contains(types, "Incremental Sort") {
				t.Errorf("%s page: the plan sorts: %s", kind, plan)
			}
			if !slices.Contains(idx, index) {
				t.Errorf("%s page: not read from %s (%v): %s", kind, index, idx, plan)
			}
		}
	}
}

// The tool predicate is a literal for the paged kinds (never request text) and a bind for any other.
func TestToolPredicateLiteralsComeFromThePagedKinds(t *testing.T) {
	b := &q{}
	if got := toolPredicate([]string{"observation"}, b); got != "e.record->>'tool' = 'observation'" || len(b.args) != 0 {
		t.Errorf("one paged kind: %q %v", got, b.args)
	}
	if got := toolPredicate([]string{"observation", "assessment"}, b); !strings.Contains(got, "IN ('observation', 'assessment')") {
		t.Errorf("two paged kinds: %q", got)
	}
	b = &q{}
	if got := toolPredicate([]string{"observation", "x'; DROP TABLE"}, b); strings.Contains(got, "DROP") || len(b.args) != 1 {
		t.Errorf("an unknown tool must be bound: %q %v", got, b.args)
	}
}
