package api

// The unscoped coverage read's scope list (Store.Scopes) and a statement's health before its window (Store.HealthBefore)
// read what they return, not the health history behind it. On a lab's two weeks of health records (about one a minute
// per source, each a TOAST fetch) both read every one and passed the statement timeout: every GET /v1/coverage with no
// scope answered 503. Postgres's own tuple counts say how many records each read.

import (
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/store/pg"
)

func TestCoverageScopeListAndHealthBeforeDoNotReadTheHealthHistory(t *testing.T) {
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
	// 20 000 records a minute apart from 2026-11-01: health of scope-a from two sources (k8s healthy but every 50th degraded,
	// trail healthy until the last 300 minutes, then degraded, with a core flip among them), and every 10th an observation of scope-b.
	if _, err := conn.Exec(bg, `INSERT INTO clearance_evidence (seq, hash, prev_hash, record, written_at)
	  SELECT i, md5(i::text) || md5(i::text), md5((i-1)::text) || md5((i-1)::text),
	    CASE WHEN i % 10 = 0 THEN jsonb_build_object('tool', 'observation', 'scope', 'scope-b', 'source', jsonb_build_object('name', 'trail', 'event_id', 'e'||i))
	    ELSE jsonb_build_object('tool', 'observation.health', 'scope', 'scope-a',
	      'source', jsonb_build_object('name', CASE WHEN i % 2 = 0 THEN 'k8s' ELSE 'trail' END),
	      'provider', jsonb_build_object('name', CASE WHEN i = 19801 THEN 'clearance' ELSE 'collector' END),
	      'health', jsonb_build_object('state', CASE WHEN i % 2 = 0 AND i % 50 <> 0 THEN 'healthy' WHEN i % 2 = 1 AND i < 19700 THEN 'healthy' ELSE 'degraded' END,
	        'interval_seconds', 60, 'checks', '[]'::jsonb))
	    END || jsonb_build_object('seq', i, 'boundary', 'deployment',
	      'ts', to_char(timestamp '2026-11-01 00:00:00' + i * interval '1 minute', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	      'detail', (SELECT string_agg(md5(i::text || k::text), '') FROM generate_series(1, 90) k)),
	    timestamp '2026-11-01 00:00:00' + i * interval '1 minute'
	  FROM generate_series(0, 19999) i`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(bg, "ANALYZE clearance_evidence"); err != nil {
		t.Fatal(err)
	}
	read := func() (n int64) {
		if err := conn.QueryRow(bg, "SELECT seq_tup_read + COALESCE(idx_tup_fetch, 0) FROM pg_stat_user_tables WHERE relname = 'clearance_evidence'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// counted runs fn on its own reader and returns the records Postgres read for it (a backend reports its counts when
	// its session ends).
	counted := func(fn func(rd *PG)) int64 {
		rdr, err := pg.OpenReader(bg, dsn, pg.Options{MaxConns: 1, Logger: quiet})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		before := read()
		fn(&PG{R: rdr})
		rdr.Close()
		after := before
		for i := 0; i < 50; i++ {
			if after = read(); after > before {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		return after - before
	}
	aud := &Viewer{Role: RoleAuditor}
	ts := func(minute int) string {
		return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(minute) * time.Minute).Format(time.RFC3339)
	}

	// The window is the last hour: scope-a has health before its end, scope-b observations in it.
	n := counted(func(rd *PG) {
		got, err := rd.Scopes(bg, aud, ts(19940), ts(20000), 1001)
		if err != nil || !reflect.DeepEqual(got, []string{"scope-a", "scope-b"}) {
			t.Fatalf("scopes %v, %v", got, err)
		}
	})
	if n > 50 {
		t.Errorf("Scopes read %d records of 20000: it must probe each scope, not read the health history", n)
	}

	// Before minute 19940: k8s from its last healthy record (19938), trail from its last (19699) through the flip and
	// its degraded records: 122 records, and the anchors.
	var rs []Record
	n = counted(func(rd *PG) {
		var err error
		if rs, err = rd.HealthBefore(bg, aud, "scope-a", ts(19940)); err != nil {
			t.Fatal(err)
		}
	})
	var seqs []int64
	for _, r := range rs {
		s, _ := seqOf(r)
		seqs = append(seqs, s)
	}
	var want []int64
	for i := int64(19699); i < 19940; i++ {
		if i%10 != 0 && (i%2 == 1 || i >= 19938) {
			want = append(want, i)
		}
	}
	if !reflect.DeepEqual(seqs, want) {
		t.Fatalf("HealthBefore seqs %v,\nwant %v", seqs, want)
	}
	if n > int64(len(want))+50 {
		t.Errorf("HealthBefore read %d records to return %d: it must not read the history before the anchors", n, len(want))
	}

	// Until clearance_evidence_health_src is valid, HealthBefore keeps the one-pass statement (the per-source one would
	// walk the history once per source without it), with the same answer; it switches once the index is valid.
	if _, err := conn.Exec(bg, "DROP INDEX "+HealthSrcIndex); err != nil {
		t.Fatal(err)
	}
	rdr, err := pg.OpenReader(bg, dsn, pg.Options{MaxConns: 1, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer rdr.Close()
	rd := &PG{R: rdr}
	again := func() []int64 {
		rs, err := rd.HealthBefore(bg, aud, "scope-a", ts(19940))
		if err != nil {
			t.Fatal(err)
		}
		var out []int64
		for _, r := range rs {
			s, _ := seqOf(r)
			out = append(out, s)
		}
		return out
	}
	if got := again(); !reflect.DeepEqual(got, want) || rd.healthSrc.Load() {
		t.Fatalf("without the index: seqs %v (per-source chosen %v)", got, rd.healthSrc.Load())
	}
	for _, ix := range pg.MapIndexes {
		if ix.Name == HealthSrcIndex {
			if _, err := conn.Exec(bg, ix.DDL); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := again(); !reflect.DeepEqual(got, want) || !rd.healthSrc.Load() {
		t.Fatalf("with the index: seqs %v (per-source chosen %v)", got, rd.healthSrc.Load())
	}
}
