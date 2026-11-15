package api

import (
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/store/pg"
)

// A health chain per scope, all in the last minute before `before`: seq 0 the collector healthy, seq 1 the core's
// blind flip on source "k8s", then n collector records reporting degraded (on source "k8s", or on "chatty" for the
// scope "sparse", where the flipped source "k8s" reports nothing more).
func healthChain(t *testing.T, conn *pgx.Conn, i int, scope string, n int, chattySource bool) {
	t.Helper()
	src := "'k8s'"
	if chattySource {
		src = "'chatty'"
	}
	sql := fmt.Sprintf(`INSERT INTO clearance_evidence (seq, hash, prev_hash, record)
	SELECT %d + i, md5('h%d' || i), md5('p%d' || i), jsonb_build_object('tool','observation.health','scope','%s','ts','2026-11-10T23:59:30Z','seq',%d + i,
	  'source',jsonb_build_object('name', CASE WHEN i < 2 THEN 'k8s' ELSE %s END),
	  'provider',jsonb_build_object('name', CASE WHEN i = 1 THEN '%s' ELSE 'observe-k8s' END),
	  'health',jsonb_build_object('state', CASE WHEN i = 0 THEN 'healthy' WHEN i = 1 THEN 'blind' ELSE 'degraded' END, 'interval_seconds', 60))
	FROM generate_series(0, %d) i`, i*1000, i, i, scope, i*1000, src, evidence.CoreProviderName, n+1)
	if _, err := conn.Exec(bg, sql); err != nil {
		t.Fatal(err)
	}
}

// The Map never shows a source better than the core's standing declaration. The core forces a source blind; the
// collector goes on reporting degraded; however many health records pass (here far more than healthTail, and in
// "sparse" from another source of the same scope that crowds the flipped source out of the newest records), the Map
// shows blind until the collector reports healthy.
func TestHealthNeverBetterThanTheCoreDeclared(t *testing.T) {
	dsn := newDB(t)
	st, err := pg.Open(bg, dsn, pg.Options{Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BuildIndexes(bg); err != nil {
		t.Fatal(err)
	}
	st.Close()
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	healthChain(t, conn, 0, "short", 100, false)
	healthChain(t, conn, 1, "long", 700, false)
	healthChain(t, conn, 2, "sparse", 700, true)
	// "ended": the collector reports healthy again after the flip, then degraded: the flip is over.
	healthChain(t, conn, 3, "ended", 20, false)
	if _, err := conn.Exec(bg, `UPDATE clearance_evidence SET record = jsonb_set(record, '{health,state}', '"healthy"') WHERE seq = 3010`); err != nil {
		t.Fatal(err)
	}
	rd := openReader(t, dsn)
	before := "2026-11-11T00:00:00Z"
	got, err := rd.HealthBeforeScopes(bg, &Viewer{Role: RoleAuditor}, []string{"short", "long", "sparse", "ended"}, before)
	if err != nil {
		t.Fatal(err)
	}
	per := map[string][]Record{}
	seen := map[any]bool{}
	for _, r := range got {
		if seen[r["seq"]] {
			t.Fatalf("seq %v returned twice", r["seq"])
		}
		seen[r["seq"]] = true
		per[r["scope"].(string)] = append(per[r["scope"].(string)], r)
	}
	if len(per["long"]) > healthTail+1 || len(per["sparse"]) > healthTail+1 {
		t.Errorf("the tail is bounded: long %d, sparse %d records", len(per["long"]), len(per["sparse"]))
	}
	now, _ := time.Parse(time.RFC3339, before)
	for _, c := range []struct{ scope, source, want string }{
		{"short", "k8s", observe.Blind},
		{"long", "k8s", observe.Blind},
		{"sparse", "k8s", observe.Blind}, // its collector has gone quiet: stale is blind too, but the flip is what is declared
		{"sparse", "chatty", observe.Degraded},
		{"ended", "k8s", observe.Degraded},
	} {
		stmt := observe.Build(observe.Input{Scope: c.scope, Window: observe.Window{From: now.Add(-time.Minute), To: now}, Health: per[c.scope]}, now)
		found := false
		for _, sh := range stmt.Health.Sources {
			if sh.Source == c.source {
				found = true
				if sh.Now != c.want {
					t.Errorf("%s/%s reads %s, want %s", c.scope, c.source, sh.Now, c.want)
				}
			}
		}
		if !found {
			t.Errorf("%s/%s: no such source in %v", c.scope, c.source, stmt.Health.Sources)
		}
	}
}
