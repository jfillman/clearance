package api

// The Map's budget: GET /v1/map answers in under a second on a chain of about 25 000 records, and stays there at ten
// times that. The chain is synthetic (the mix of a busy lab: runtime decisions, deployment records, observations,
// assessments and health records over two days), written straight into Postgres with the schema the core migrates.
// The 250 000-record run is CLEARANCE_MAP_PERF=1 (a few seconds more); the 25 000-record one always runs.

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/pg"
	"github.com/jfillman/clearance/internal/targets"
)

func synthChain(t *testing.T, dsn string, n int) {
	t.Helper()
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	end := mapNow.Format("2006-01-02 15:04:05")
	ts := fmt.Sprintf(`to_char((timestamp '%s' - (%d - i) * interval '1 second' * 172800 / %d) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`, end, n, n)
	rec := `CASE i %% 10
	  WHEN 0 THEN jsonb_build_object('tool','github.pr.open','boundary','runtime','decision','allow','policy',jsonb_build_object('ref','x'),'provider',jsonb_build_object('name','gw-'||(i %% 3)),'agent','coding-agent','coverage','authorized-and-verified')
	  WHEN 1 THEN jsonb_build_object('tool','github.pr.open','boundary','runtime','decision','deny','policy',jsonb_build_object('ref','x'),'provider',jsonb_build_object('name','gw-'||(i %% 3)),'agent','coding-agent','coverage','authorized-and-verified')
	  WHEN 2 THEN jsonb_build_object('tool','github.pr.open','boundary','runtime','decision','allow','outcome_of',jsonb_build_object('seq',i-1),'provider',jsonb_build_object('name','gw-0'),'agent','coding-agent')
	  WHEN 3 THEN jsonb_build_object('tool','session.open','boundary','runtime','decision','allow','principal','user:p'||(i %% 40),'task_id','t-'||i,'session','s-'||i)
	  WHEN 4 THEN jsonb_build_object('tool','deploy.request','boundary','deployment','app','app-'||(i %% 100),'decision','','provider',jsonb_build_object('name','clearance'),'change',jsonb_build_object('id','c-'||i,'env','prod','tier',1),'coverage','authorized-and-verified')
	  WHEN 5 THEN jsonb_build_object('tool',CASE WHEN i %% 20 = 5 THEN 'deploy.deny' ELSE 'deploy.clear' END,'boundary','deployment','app','app-'||(i %% 100),'decision',CASE WHEN i %% 20 = 5 THEN 'deny' ELSE 'allow' END,'provider',jsonb_build_object('name','clearance'),'change',jsonb_build_object('id','c-'||(i-1),'env','prod','tier',1),'coverage','authorized-and-verified')
	  WHEN 6 THEN jsonb_build_object('tool','observation','boundary','deployment','scope','scope-'||(i %% 50),'source',jsonb_build_object('name','observe-k8s','event_id','e'||i),'coverage','observed-not-attributed','provider',jsonb_build_object('name','observe-k8s'))
	  WHEN 7 THEN jsonb_build_object('tool','assessment','boundary','deployment','scope','scope-'||(i %% 50),'about',jsonb_build_object('seq',i-1),'coverage',CASE WHEN i %% 30 = 7 THEN 'out-of-band-detected' ELSE 'authorized-and-verified' END,'provider',jsonb_build_object('name','observe-k8s'))
	  WHEN 8 THEN jsonb_build_object('tool','deploy.outcome','boundary','deployment','app','app-'||(i %% 100),'matched',true,'outcome',jsonb_build_object('applied',true),'provider',jsonb_build_object('name','argo-gate'),'change',jsonb_build_object('id','c-'||(i-4),'env','prod'))
	  ELSE jsonb_build_object('tool','observation.health','boundary','deployment','scope','scope-'||(i %% 50),'source',jsonb_build_object('name','observe-k8s'),'health',jsonb_build_object('state','healthy','interval_seconds',60,'checks','[]'::jsonb),'provider',jsonb_build_object('name','observe-k8s'))
	END || jsonb_build_object('ts', ` + ts + `, 'seq', i)`
	sql := fmt.Sprintf(`INSERT INTO clearance_evidence (seq, hash, prev_hash, record, written_at)
	  SELECT i, md5(i::text) || md5(i::text), md5((i-1)::text) || md5((i-1)::text), %s, (timestamp '%s' - (%d - i) * interval '1 second' * 172800 / %d) AT TIME ZONE 'UTC'
	  FROM generate_series(0, %d) i`, strings.ReplaceAll(rec, "%%", "%"), end, n, n, n-1)
	if _, err := conn.Exec(bg, sql); err != nil {
		t.Fatal(err)
	}
	// a change row for every deploy.request, and some holding
	if _, err := conn.Exec(bg, `INSERT INTO clearance_changes (id, app, env, state, repo, pr, head, expires_at, record)
	  SELECT 'c-'||i, 'app-'||(i % 100), 'prod', CASE WHEN i % 40 = 4 THEN 'holding' ELSE 'cleared' END, 'o/r', 1, 'h', now() + interval '7 days',
	    jsonb_build_object('id','c-'||i,'app','app-'||(i % 100),'env','prod','state',CASE WHEN i % 40 = 4 THEN 'holding' ELSE 'cleared' END,'tier',(i % 4),'registered_by','ci-'||(i % 20),'created_at',now()::text,'updated_at',now()::text,'owner','group:default/x')
	  FROM generate_series(0, `+fmt.Sprint(n-1)+`) i WHERE i % 10 = 4`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(bg, "ANALYZE"); err != nil {
		t.Fatal(err)
	}
}

func synthRegistry() store.TargetSet {
	var ts []targets.Target
	for i := 0; i < 100; i++ {
		ts = append(ts, targets.Target{ID: fmt.Sprintf("app-%d-prod", i), Name: fmt.Sprintf("app-%d", i), Kind: "k8s-namespace", Group: fmt.Sprintf("cluster-%d", i%5),
			Env: "prod", App: fmt.Sprintf("app-%d", i), Scope: fmt.Sprintf("scope-%d", i%50),
			Gates:     []targets.Gate{{Type: "glidepath", Instance: fmt.Sprintf("ci-%d", i%20), Mode: "enforce"}, {Type: "g-argo", Instance: "argo-gate", Mode: "flag"}},
			Observers: []targets.Observer{{Provider: "observe-k8s", Source: "observe-k8s"}}})
	}
	return targetSet("perf", ts...)
}

func TestMapStaysUnderABudgetOnALargeChain(t *testing.T) {
	sizes := []int{25000}
	if os.Getenv("CLEARANCE_MAP_PERF") != "" {
		sizes = append(sizes, 250000)
	}
	for _, n := range sizes {
		n := n
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			dsn := newDB(t)
			st, err := pg.Open(bg, dsn, pg.Options{Logger: quiet})
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if err := st.Atomic(bg, func(tx store.Tx) error { return tx.PutTargets(bg, synthRegistry()) }); err != nil {
				t.Fatal(err)
			}
			synthChain(t, dsn, n)
			rd := openReader(t, dsn)
			h := newHarness(t, backend{"perf", func(*testing.T, world) (Store, string) { return rd, dsn }}, world{},
				func(o *Options) { o.Clock = func() time.Time { return mapNow } })
			for _, path := range []string{"/v1/map", "/v1/map?target=app-7-prod", "/v1/map?group=cluster-1&expand=cluster-1",
				"/v1/evidence/counts?by=provider&bucket=1h&since=2026-11-09T12:00:00Z"} {
				best := time.Hour
				var m map[string]any
				for i := 0; i < 3; i++ {
					start := time.Now()
					m = h.ok(path, "audit")
					if d := time.Since(start); d < best {
						best = d
					}
				}
				t.Logf("%d records: GET %s: %s", n, path, best)
				if best > time.Second {
					t.Errorf("GET %s took %s on %d records: the budget is 1s", path, best, n)
				}
				if strings.HasPrefix(path, "/v1/map") && len(sub(m, "nodes")["targets"].([]any)) == 0 {
					t.Fatalf("the synthetic registry produced an empty map: %v", m)
				}
			}
			m := h.ok("/v1/map", "audit")
			gp := pick(t, sub(m, "nodes")["gate_types"], "type", "glidepath")
			if num(sub(gp, "lanes")["requested"]) == 0 || num(gp["decisions"]) == 0 {
				t.Fatalf("no activity counted on the synthetic chain: %v", gp)
			}
		})
	}
}
