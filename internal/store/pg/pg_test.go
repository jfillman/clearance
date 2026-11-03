package pg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/storetest"
)

var bg = context.Background()

var dbN atomic.Int64

// newDB creates a scratch database on CLEARANCE_TEST_DSN's server (the advisory lock is per database, so each
// test gets its own) and returns its DSN; it is dropped when the test ends.
func newDB(t *testing.T) string {
	t.Helper()
	admin := os.Getenv("CLEARANCE_TEST_DSN")
	if admin == "" {
		t.Skip("CLEARANCE_TEST_DSN not set")
	}
	conn, err := pgx.Connect(bg, admin)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("clr_test_%d_%d", os.Getpid(), dbN.Add(1))
	if _, err := conn.Exec(bg, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(bg, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		conn.Close(bg)
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

func open(t *testing.T, dsn string) *Store {
	t.Helper()
	s, err := Open(bg, dsn, Options{VerifyBatch: 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// seed writes records as rows directly, the way the Python core left them.
func seed(t *testing.T, dsn string, recs []store.Record) {
	t.Helper()
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	if _, err := conn.Exec(bg, Schema); err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		c, err := canon.Canonical(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(bg, "INSERT INTO clearance_evidence (seq, hash, prev_hash, record) VALUES ($1, $2, $3, $4)",
			r["seq"], r["hash"], r["prev_hash"], string(c)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T, recs []store.Record) store.Store {
		dsn := newDB(t)
		if len(recs) > 0 {
			seed(t, dsn, recs)
		}
		return open(t, dsn)
	})
}

func TestSecondWriterLocked(t *testing.T) {
	dsn := newDB(t)
	s := open(t, dsn)
	if _, err := Open(bg, dsn, Options{}); !errors.Is(err, store.ErrWriterLocked) {
		t.Fatalf("second writer: %v, want ErrWriterLocked", err)
	}
	// A reader is not a writer: it opens beside the writer.
	r, err := OpenReader(bg, dsn, Options{})
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	s.Close()
	s2, err := Open(bg, dsn, Options{})
	if err != nil {
		t.Fatalf("after the first writer closed: %v", err)
	}
	s2.Close()
}

func appendN(t *testing.T, s store.Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := s.Atomic(bg, func(tx store.Tx) error {
			_, err := tx.Append(bg, store.Event{"tool": "t", "i": i, "f": 0.5}, storetest.Writer)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEditedRowStopsOpen(t *testing.T) {
	for name, sql := range map[string]string{
		"edit record":  `UPDATE clearance_evidence SET record = jsonb_set(record, '{i}', '99') WHERE seq = 4`,
		"delete row":   `DELETE FROM clearance_evidence WHERE seq = 4`,
		"hash column":  `UPDATE clearance_evidence SET hash = 'x' WHERE seq = 4`,
		"swap records": `UPDATE clearance_evidence SET record = (SELECT record FROM clearance_evidence WHERE seq = 5) WHERE seq = 4`,
	} {
		t.Run(name, func(t *testing.T) {
			dsn := newDB(t)
			s := open(t, dsn)
			appendN(t, s, 7)
			s.Close()
			conn, err := pgx.Connect(bg, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close(bg)
			if _, err := conn.Exec(bg, sql); err != nil {
				t.Fatal(err)
			}
			_, err = Open(bg, dsn, Options{VerifyBatch: 3})
			var bad *evidence.BadRecord
			if !errors.As(err, &bad) || bad.Seq != 4 {
				t.Fatalf("Open = %v, want a broken chain at 4", err)
			}
			r, err := OpenReader(bg, dsn, Options{VerifyBatch: 2})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := r.Verify(bg, nil); !errors.As(err, &bad) || bad.Seq != 4 {
				t.Fatalf("reader Verify = %v", err)
			}
		})
	}
}

func TestReaderIsReadOnly(t *testing.T) {
	dsn := newDB(t)
	s := open(t, dsn)
	appendN(t, s, 5)
	r, err := OpenReader(bg, dsn, Options{VerifyBatch: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var seen int
	cp, err := r.Verify(bg, func(int64, string) { seen++ })
	if err != nil || cp.Count != 5 || seen != 5 {
		t.Fatalf("Verify = %v %v (seen %d)", cp, err, seen)
	}
	if seq, h, err := r.Head(bg); err != nil || seq != 4 || h != cp.Head {
		t.Fatalf("reader Head = %d %s %v", seq, h, err)
	}
	if _, err := r.pool.Exec(bg, "DELETE FROM clearance_evidence"); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("a write through the reader: %v, want a read-only error", err)
	}
}

// TestWriterReconnects kills the writer's backend (as a Postgres restart would): the next Atomic reconnects,
// retakes the lock, re-verifies from the committed head and goes on.
func TestWriterReconnects(t *testing.T) {
	dsn := newDB(t)
	s := open(t, dsn)
	appendN(t, s, 3)
	pid := s.conn.PgConn().PID()
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	if _, err := conn.Exec(bg, "SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatal(err)
	}
	// The first write may fail on the dead connection; the store must recover on its own.
	var errs int
	for i := 0; i < 3; i++ {
		if err := s.Atomic(bg, func(tx store.Tx) error {
			_, err := tx.Append(bg, store.Event{"tool": "after"}, storetest.Writer)
			return err
		}); err != nil {
			errs++
			continue
		}
		break
	}
	if errs > 1 {
		t.Fatalf("store did not recover from a dropped writer connection (%d failures)", errs)
	}
	if s.conn.PgConn().PID() == pid {
		t.Fatal("writer connection was not replaced")
	}
	// The new connection holds the lock.
	if _, err := Open(bg, dsn, Options{}); !errors.Is(err, store.ErrWriterLocked) {
		t.Fatalf("lock not retaken: %v", err)
	}
	r, _ := OpenReader(bg, dsn, Options{})
	defer r.Close()
	if cp, err := r.Verify(bg, nil); err != nil || cp.Count != 4 {
		t.Fatalf("after reconnect: %v %v", cp, err)
	}
}

// TestStaleHeadAfterCommitFailure: a commit whose outcome is unknown makes the next write re-read the head.
func TestStaleHeadAfterCommitFailure(t *testing.T) {
	dsn := newDB(t)
	s := open(t, dsn)
	appendN(t, s, 2)
	// Simulate: the commit landed but the store did not learn it.
	s.mu.Lock()
	s.stale = true
	s.headMu.Lock()
	s.committed = evidence.Checkpoint{Count: 1, Head: s.committed.Head} // wrong on purpose: behind by one
	s.headMu.Unlock()
	s.mu.Unlock()
	// Resume from a checkpoint that does not match: verification must refuse, not fork.
	err := s.Atomic(bg, func(tx store.Tx) error {
		_, err := tx.Append(bg, store.Event{"tool": "x"}, storetest.Writer)
		return err
	})
	var bad *evidence.BadRecord
	if !errors.As(err, &bad) {
		t.Fatalf("Atomic over a wrong head = %v, want a BadRecord", err)
	}
}

func TestStatementTimeout(t *testing.T) {
	dsn := newDB(t)
	s, err := Open(bg, dsn, Options{StatementTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	start := time.Now()
	err = s.Atomic(bg, func(t2 store.Tx) error {
		_, err := t2.(*tx).tx.Exec(bg, "SELECT pg_sleep(5)")
		return err
	})
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("statement_timeout not applied: %v after %v", err, time.Since(start))
	}
	appendN(t, s, 1) // the store is still usable
}

func TestMigrateIsIdempotentAndLeavesOthers(t *testing.T) {
	dsn := newDB(t)
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	// A table of the gateway's that the Go core does not own.
	if _, err := conn.Exec(bg, "CREATE TABLE clearance_sessions (id text PRIMARY KEY); INSERT INTO clearance_sessions VALUES ('s')"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		s := open(t, dsn)
		appendN(t, s, 1)
		s.Close()
	}
	var n int
	if err := conn.QueryRow(bg, "SELECT count(*) FROM clearance_sessions").Scan(&n); err != nil || n != 1 {
		t.Fatalf("clearance_sessions touched: %d %v", n, err)
	}
	var idx int
	if err := conn.QueryRow(bg, "SELECT count(*) FROM pg_indexes WHERE indexname = 'clearance_evidence_receipt'").Scan(&idx); err != nil || idx != 1 {
		t.Fatalf("receipt index: %d %v", idx, err)
	}
}

// TestReceiptsUseTheIndex checks the planner can answer Receipts from clearance_evidence_receipt.
func TestReceiptsUseTheIndex(t *testing.T) {
	dsn := newDB(t)
	s := open(t, dsn)
	appendN(t, s, 1)
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	if _, err := conn.Exec(bg, "SET enable_seqscan = off"); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.Query(bg, "EXPLAIN SELECT record::text FROM clearance_evidence WHERE record ? 'effect' "+
		"AND (record->'effect'->>'repo') = $1 AND (record->'effect'->>'pr') = $2 AND record->>'tool' = ANY($3) ORDER BY seq",
		"o/r", "7", []string{"repo.pr.open"})
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for rows.Next() {
		var l string
		_ = rows.Scan(&l)
		plan.WriteString(l + "\n")
	}
	if !strings.Contains(plan.String(), "clearance_evidence_receipt") {
		t.Fatalf("Receipts does not use the index:\n%s", plan.String())
	}
}

func BenchmarkAppend(b *testing.B) {
	admin := os.Getenv("CLEARANCE_TEST_DSN")
	if admin == "" {
		b.Skip("CLEARANCE_TEST_DSN not set")
	}
	conn, err := pgx.Connect(bg, admin)
	if err != nil {
		b.Fatal(err)
	}
	name := fmt.Sprintf("clr_bench_%d", os.Getpid())
	_, _ = conn.Exec(bg, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	if _, err := conn.Exec(bg, "CREATE DATABASE "+name); err != nil {
		b.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(bg, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); conn.Close(bg) }()
	u, _ := url.Parse(admin)
	u.Path = "/" + name
	s, err := Open(bg, u.String(), Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	ev := store.Event{"ts": "2026-11-02T00:00:00Z", "tool": "model.call", "agent": "a", "principal": "ns/a",
		"decision": "allow", "rule": nil, "session": "s-1", "task_id": "t-1", "args_sha256": strings.Repeat("a", 64)}
	lat := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st := time.Now()
		if err := s.Atomic(bg, func(tx store.Tx) error { _, err := tx.Append(bg, ev, storetest.Writer); return err }); err != nil {
			b.Fatal(err)
		}
		lat = append(lat, time.Since(st))
	}
	b.StopTimer()
	reportP99(b, lat)
}

func reportP99(b *testing.B, lat []time.Duration) {
	if len(lat) < 100 {
		return
	}
	sorted := append([]time.Duration(nil), lat...)
	for i := 1; i < len(sorted); i++ { // insertion sort is fine for a benchmark's tail
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	b.ReportMetric(float64(sorted[len(sorted)*99/100].Microseconds()), "p99-µs")
	b.ReportMetric(float64(sorted[len(sorted)/2].Microseconds()), "p50-µs")
}

// TestLiveChainDump loads a dump of a live chain (CLEARANCE_LIVE_CHAIN: `psql -Atc "select record::text from
// clearance_evidence order by seq"`) into a scratch database as rows, opens the Go writer on it (which verifies
// it), extends it with storetest.GoEvents and writes the extended chain to CLEARANCE_LIVE_CHAIN_OUT for
// Python's audit.verify. Opt-in: the dump is live data and is never committed.
func TestLiveChainDump(t *testing.T) {
	in, out := os.Getenv("CLEARANCE_LIVE_CHAIN"), os.Getenv("CLEARANCE_LIVE_CHAIN_OUT")
	if in == "" || out == "" {
		t.Skip("CLEARANCE_LIVE_CHAIN / CLEARANCE_LIVE_CHAIN_OUT not set")
	}
	dsn := newDB(t)
	raw, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	if _, err := conn.Exec(bg, Schema); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		v, err := canon.Parse([]byte(l))
		if err != nil {
			t.Fatal(err)
		}
		r := v.(map[string]any)
		if _, err := conn.Exec(bg, "INSERT INTO clearance_evidence (seq, hash, prev_hash, record) VALUES ($1, $2, $3, $4)",
			r["seq"], r["hash"], r["prev_hash"], l); err != nil {
			t.Fatal(err)
		}
		n++
	}
	s := open(t, dsn)
	if seq, _, _ := s.Head(bg); seq != int64(n-1) {
		t.Fatalf("head %d after loading %d", seq, n)
	}
	for _, e := range storetest.GoEvents {
		if err := s.Atomic(bg, func(tx store.Tx) error { _, err := tx.Append(bg, e, storetest.Writer); return err }); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := conn.Query(bg, "SELECT record::text FROM clearance_evidence ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	var dump strings.Builder
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			t.Fatal(err)
		}
		dump.WriteString(l + "\n")
	}
	if err := os.WriteFile(out, []byte(dump.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	seq, h, _ := s.Head(bg)
	t.Logf("loaded %d live records, extended to seq %d head %s", n, seq, h)
}
