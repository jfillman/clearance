package api

// The Map's budget: GET /v1/map answers in under a second on a chain of about 25 000 records, and in under three at ten
// times that (the synthetic chain puts half its records in the window as gate records, which each cost a read). The chain is synthetic (the mix of a busy lab: runtime decisions, deployment records, observations,
// assessments and health records over two days, each about 3 KB, as the real ones are: past the TOAST threshold, so a statement that
// reads a record pays a fetch and a decompress), written straight into Postgres with the schema the core migrates.
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

// synthChain writes n records evenly over span, ending at mapNow.
func synthChain(t *testing.T, dsn string, n int, span time.Duration) {
	t.Helper()
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	end := mapNow.Format("2006-01-02 15:04:05")
	secs := int(span / time.Second)
	ts := fmt.Sprintf(`to_char((timestamp '%s' - (%d - i) * interval '1 second' * %d / %d) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`, end, n, secs, n)
	// Real records are about 3 KB (about 2 KB compressed): past the TOAST threshold, so every field a statement reads
	// detoasts and decompresses the whole record. Records that fit in the page would hide the cost the Map pays; the
	// padding is random hex, which does not compress away.
	pad := `(SELECT string_agg(md5(random()::text || i::text || k::text), '') FROM generate_series(1, 90) k)`
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
	END || jsonb_build_object('ts', ` + ts + `, 'seq', i, 'detail', ` + pad + `)`
	sql := fmt.Sprintf(`INSERT INTO clearance_evidence (seq, hash, prev_hash, record, written_at)
	  SELECT i, md5(i::text) || md5(i::text), md5((i-1)::text) || md5((i-1)::text), %s, (timestamp '%s' - (%d - i) * interval '1 second' * %d / %d) AT TIME ZONE 'UTC'
	  FROM generate_series(0, %d) i`, strings.ReplaceAll(rec, "%%", "%"), end, n, secs, n, n-1)
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
			if err := st.BuildIndexes(bg); err != nil { // the core builds them in the background after it starts
				t.Fatal(err)
			}
			synthChain(t, dsn, n, 48*time.Hour)
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
				budget := time.Second
				if n > 100000 {
					budget = 3 * time.Second // half of these records are gate records inside the window: a read per record
				}
				if best > budget {
					t.Errorf("GET %s took %s on %d records: the budget is %s", path, best, n, budget)
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

// A long chain with a small window: 60 000 records over 30 days, so the Map's 24 hours hold about 3% of them. A Map
// read must come from the partial indexes (the indexes the core builds for it after it starts: store/pg/indexes.go) and never walk the table: a record is
// TOASTed, so a statement that filters a chain row by row pays a fetch and a decompress for every record of every
// day, which on the lab took each statement past the 5 s statement_timeout. The scan counts come from Postgres's own
// statistics, so this holds on any machine, however fast.
func TestMapReadsOnlyTheIndexedRecords(t *testing.T) {
	dsn := newDB(t)
	st, err := pg.Open(bg, dsn, pg.Options{Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Atomic(bg, func(tx store.Tx) error { return tx.PutTargets(bg, synthRegistry()) }); err != nil {
		t.Fatal(err)
	}
	if err := st.BuildIndexes(bg); err != nil {
		t.Fatal(err)
	}
	synthChain(t, dsn, 60000, 30*24*time.Hour)
	rdr, err := pg.OpenReader(bg, dsn, pg.Options{MaxConns: 4, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	rd := &PG{R: rdr}
	h := newHarness(t, backend{"perf", func(*testing.T, world) (Store, string) { return rd, dsn }}, world{},
		func(o *Options) { o.Clock = func() time.Time { return mapNow } })
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	scans := func() (seq int64, idx map[string]int64) {
		idx = map[string]int64{}
		if err := conn.QueryRow(bg, "SELECT seq_scan FROM pg_stat_user_tables WHERE relname = 'clearance_evidence'").Scan(&seq); err != nil {
			t.Fatal(err)
		}
		rows, err := conn.Query(bg, "SELECT indexrelname, idx_scan FROM pg_stat_user_indexes WHERE relname = 'clearance_evidence'")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			var c int64
			if err := rows.Scan(&n, &c); err != nil {
				t.Fatal(err)
			}
			idx[n] = c
		}
		return seq, idx
	}
	st.Close() // a backend reports its scan counts when its session ends: the writer's go before the snapshot, the reader's before the check
	time.Sleep(time.Second)
	seq0, idx0 := scans()
	start := time.Now()
	m := h.ok("/v1/map", "audit")
	t.Logf("GET /v1/map on 60000 records over 30 days: %s", time.Since(start))
	if len(sub(m, "nodes")["targets"].([]any)) == 0 {
		t.Fatalf("the synthetic registry produced an empty map: %v", m)
	}
	rdr.Close()
	want := []string{"clearance_evidence_gate", "clearance_evidence_obs_ts", "clearance_evidence_health_page", "clearance_evidence_health_core"}
	var seq1 int64
	var idx1 map[string]int64
	for i := 0; i < 50; i++ { // the statistics reach the collector a moment after the statements finish
		seq1, idx1 = scans()
		used := true
		for _, n := range want {
			used = used && idx1[n] > idx0[n]
		}
		if used {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, n := range want {
		if idx1[n] <= idx0[n] {
			t.Errorf("the Map did not read from %s", n)
		}
	}
	if seq1 != seq0 {
		t.Errorf("the Map walked clearance_evidence %d times: every statement must come from a partial index", seq1-seq0)
	}
}

// Until clearance_evidence_gate is built (the core builds it in the background after a start that adds it), the gate
// read must not be worse than before the index existed: it reads the chain from the first record written at or
// after `from`, not the whole of it. Postgres's own tuple counts say how many records it read.
func TestGateActivityBeforeItsIndexExists(t *testing.T) {
	dsn := newDB(t)
	st, err := pg.Open(bg, dsn, pg.Options{Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	st.Close() // and with it the background build: the indexes are dropped below, whichever of them it got to
	synthChain(t, dsn, 60000, 30*24*time.Hour)
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	for _, ix := range pg.MapIndexes {
		if _, err := conn.Exec(bg, "DROP INDEX IF EXISTS "+ix.Name); err != nil {
			t.Fatal(err)
		}
	}
	read := func() (n int64) {
		if err := conn.QueryRow(bg, "SELECT seq_tup_read + idx_tup_fetch FROM pg_stat_user_tables WHERE relname = 'clearance_evidence'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	rdr, err := pg.OpenReader(bg, dsn, pg.Options{MaxConns: 2, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	before := read()
	rows, _, err := (&PG{R: rdr}).GateActivity(bg, &Viewer{Role: RoleAuditor}, "2026-11-09T12:00:00Z", "2026-11-10T12:00:00Z")
	if err != nil || len(rows) == 0 {
		t.Fatalf("gate activity: %d rows, %v", len(rows), err)
	}
	rdr.Close() // a backend reports its tuple counts when its session ends
	var after int64
	for i := 0; i < 50; i++ {
		if after = read(); after > before {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	// The window is 1/30 of the chain (2 000 records): reading the chain from its start would read 60 000.
	if n := after - before; n > 10000 {
		t.Errorf("GateActivity read %d records of 60000 with no gate index: it must start at the window", n)
	}
	// A window after the last record written has no gate activity, and the statement does not look: no record written at
	// or after from means none has a ts at or after it (a record's ts is stamped when it is written; a backdated one
	// is the caveat in docs/clearance-api.md, and the gate index, once built, would find it).
	rdr, err = pg.OpenReader(bg, dsn, pg.Options{MaxConns: 2, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	before = read()
	rows, cut, err := (&PG{R: rdr}).GateActivity(bg, &Viewer{Role: RoleAuditor}, "2026-11-10T13:00:00Z", "2026-11-10T14:00:00Z")
	if err != nil || len(rows) != 0 || cut {
		t.Fatalf("a window after the last write: %d rows, cut %v, %v", len(rows), cut, err)
	}
	rdr.Close()
	for i := 0; i < 50; i++ {
		if after = read(); after > before {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if n := after - before; n > 100 {
		t.Errorf("a window after the last write read %d records of 60000: it must not scan the chain", n)
	}
}
