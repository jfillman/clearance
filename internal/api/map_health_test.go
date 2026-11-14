package api

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store/pg"
)

// HealthBeforeScopes reads the newest healthTail health records of each scope and starts at the newest healthy
// collector record among them. A core-written flip (monitoring forced blind) still held when the tail begins is not in
// the tail: that is the one thing the bound loses, and this test pins exactly what it loses (docs/clearance-api.md).
func TestHealthTailBoundAndWhatItLoses(t *testing.T) {
	dsn := newDB(t)
	st, err := pg.Open(bg, dsn, pg.Options{Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	// Per scope: seq 0 the collector healthy, seq 1 the core's blind flip, then n collector records reporting degraded.
	// "short" has 100 of them, "long" has 700 (more than healthTail), so its flip is older than the tail.
	for i, c := range []struct {
		scope string
		n     int
	}{{"short", 100}, {"long", 700}} {
		base := i * 1000
		sql := fmt.Sprintf(`INSERT INTO clearance_evidence (seq, hash, prev_hash, record)
		SELECT %d + i, md5('h%d' || i), md5('p%d' || i), jsonb_build_object('tool','observation.health','scope',%s,'ts','2026-11-10T10:00:00Z','seq',%d + i,
		  'source',jsonb_build_object('name','k8s'),
		  'provider',jsonb_build_object('name', CASE WHEN i = 1 THEN %s ELSE 'observe-k8s' END),
		  'health',jsonb_build_object('state', CASE WHEN i = 0 THEN 'healthy' WHEN i = 1 THEN 'blind' ELSE 'degraded' END))
		FROM generate_series(0, %d) i`, base, i, i, quote(c.scope), base, quote(evidence.CoreProviderName), c.n+1)
		if _, err := conn.Exec(bg, sql); err != nil {
			t.Fatal(err)
		}
	}
	rd := openReader(t, dsn)
	got, err := rd.HealthBeforeScopes(bg, &Viewer{Role: RoleAuditor}, []string{"short", "long"}, "2026-11-11T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	per := map[string][]Record{}
	for _, r := range got {
		per[r["scope"].(string)] = append(per[r["scope"].(string)], r)
	}
	core := func(rs []Record) (n int) {
		for _, r := range rs {
			if sub(r, "provider")["name"] == evidence.CoreProviderName {
				n++
			}
		}
		return n
	}
	// A flip inside the tail is read whole: from the healthy record that precedes it, through the flip, to the newest.
	if s := per["short"]; len(s) != 102 || num(s[0]["seq"]) != 0 || core(s) != 1 {
		t.Errorf("short: %d records, first seq %v, %d from the core: want all 102, from the healthy one, with the flip", len(s), s[0]["seq"], core(s))
	}
	// A flip older than the tail is not: the Map reads the newest healthTail records and none of them is the core's.
	if l := per["long"]; len(l) != healthTail || core(l) != 0 || num(l[len(l)-1]["seq"]) != 1000+701 {
		t.Errorf("long: %d records (want %d), %d from the core (want 0)", len(l), healthTail, core(l))
	}
}

func quote(s string) string { return "'" + s + "'" }
