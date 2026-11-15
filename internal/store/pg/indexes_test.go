package pg

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/storetest"
)

func indexState(t *testing.T, conn *pgx.Conn, name string) (oid uint32, valid, found bool) {
	t.Helper()
	err := conn.QueryRow(bg, "SELECT i.indexrelid::oid::text::bigint, i.indisvalid FROM pg_index i WHERE i.indexrelid = to_regclass($1)", name).Scan(&oid, &valid)
	if err == pgx.ErrNoRows {
		return 0, false, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return oid, valid, true
}

func waitIndexes(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	for i := 0; i < 150; i++ {
		ok := true
		for _, ix := range MapIndexes {
			if _, v, f := indexState(t, conn, ix.Name); !f || !v {
				ok = false
			}
		}
		if ok {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("the Map's indexes were not built")
}

// The core builds the Map's indexes after it has started, so Open does not wait for them; they are valid soon after.
func TestMapIndexesAreBuiltInTheBackground(t *testing.T) {
	dsn := newDB(t)
	s := open(t, dsn)
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	waitIndexes(t, conn)
	_ = s
}

// An interrupted CREATE INDEX CONCURRENTLY leaves an INVALID index, which IF NOT EXISTS would skip for ever: the next
// build drops it and builds it again.
func TestInvalidMapIndexIsRebuilt(t *testing.T) {
	dsn := newDB(t)
	s := open(t, dsn)
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	waitIndexes(t, conn)
	before, _, _ := indexState(t, conn, "clearance_evidence_gate")
	if _, err := conn.Exec(bg, "UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'clearance_evidence_gate'::regclass"); err != nil {
		t.Fatal(err)
	}
	if _, v, _ := indexState(t, conn, "clearance_evidence_gate"); v {
		t.Fatal("the index was not made invalid")
	}
	if err := s.BuildIndexes(bg); err != nil {
		t.Fatal(err)
	}
	after, valid, found := indexState(t, conn, "clearance_evidence_gate")
	if !found || !valid || after == before {
		t.Fatalf("index after the rebuild: found=%v valid=%v oid %d (was %d): want a new, valid index", found, valid, after, before)
	}
}

// While an index is being built the core serves: a build waits for the transactions that have written to the table, and
// the core's own writes go on meanwhile (CONCURRENTLY takes no lock that stops them). The build is held here by an
// open writer, so the test sees it in progress, not just finished.
func TestCoreWritesWhileAnIndexIsBuilding(t *testing.T) {
	dsn := newDB(t)
	s := open(t, dsn)
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	waitIndexes(t, conn)
	for _, ix := range MapIndexes {
		if _, err := conn.Exec(bg, "DROP INDEX "+ix.Name); err != nil {
			t.Fatal(err)
		}
	}
	blocker, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(bg)
	if _, err := blocker.Exec(bg, "BEGIN; LOCK TABLE clearance_evidence IN ROW EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.BuildIndexes(bg) }()
	building := false
	for i := 0; i < 50 && !building; i++ {
		var n int
		if err := conn.QueryRow(bg, "SELECT count(*) FROM pg_stat_activity WHERE query LIKE 'CREATE INDEX CONCURRENTLY%' AND state = 'active'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		building = n > 0
		time.Sleep(100 * time.Millisecond)
	}
	if !building {
		t.Fatal("no index build in progress")
	}
	start := time.Now()
	if err := s.Atomic(bg, func(tx store.Tx) error {
		_, err := tx.Append(bg, store.Event{"tool": "during-build"}, storetest.Writer)
		return err
	}); err != nil {
		t.Fatalf("the core could not write while an index was building: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("a write took %s during an index build", d)
	}
	select {
	case err := <-done:
		t.Fatalf("the build finished while a writer held the table: %v", err)
	default:
	}
	if _, err := blocker.Exec(bg, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	waitIndexes(t, conn)
}

func dropMapIndexes(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	for _, ix := range MapIndexes {
		if _, err := conn.Exec(bg, "DROP INDEX IF EXISTS "+ix.Name); err != nil {
			t.Fatal(err)
		}
	}
}

func activeBuilds(t *testing.T, conn *pgx.Conn) (n int) {
	t.Helper()
	if err := conn.QueryRow(bg, "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND query LIKE 'CREATE INDEX CONCURRENTLY%' AND state = 'active'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The partial indexes' predicates are proved from literals: the core's provider name is spelled in two of them.
func TestMapIndexesSpellTheCoreProviderName(t *testing.T) {
	n := 0
	for _, ix := range MapIndexes {
		if strings.Contains(ix.DDL, "'"+evidence.CoreProviderName+"'") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d indexes spell the core provider name %q, want 2 (health_core, health_ok)", n, evidence.CoreProviderName)
	}
}

// An INVALID index that a live backend is still building (a killed core's ghost) is not dropped, which would throw the
// work away: the next build waits for it and finds it valid.
func TestLiveBuildOfAnInvalidIndexIsNotDropped(t *testing.T) {
	indexPoll = 100 * time.Millisecond
	t.Cleanup(func() { indexPoll = 5 * time.Second })
	dsn := newDB(t)
	s := open(t, dsn)
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	waitIndexes(t, conn)
	dropMapIndexes(t, conn)
	blocker, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(bg)
	if _, err := blocker.Exec(bg, "BEGIN; LOCK TABLE clearance_evidence IN ROW EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	ghost, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer ghost.Close(bg)
	ghostDone := make(chan error, 1)
	go func() { _, err := ghost.Exec(bg, MapIndexes[0].DDL); ghostDone <- err }()
	waitFor(t, "the ghost build", func() bool {
		_, _, found := indexState(t, conn, "clearance_evidence_gate")
		return found && activeBuilds(t, conn) > 0
	})
	oid, _, _ := indexState(t, conn, "clearance_evidence_gate")
	wait, cancel := context.WithTimeout(bg, time.Second)
	defer cancel()
	if err := s.buildIndex(wait, MapIndexes[0].Name, MapIndexes[0].DDL); err == nil {
		t.Fatal("the build did not wait for the live one")
	}
	if now, _, found := indexState(t, conn, "clearance_evidence_gate"); !found || now != oid {
		t.Fatalf("the index a live backend was building was dropped (oid %d, now %d, found %v)", oid, now, found)
	}
	if _, err := blocker.Exec(bg, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	if err := <-ghostDone; err != nil {
		t.Fatal(err)
	}
	if err := s.buildIndex(bg, MapIndexes[0].Name, MapIndexes[0].DDL); err != nil {
		t.Fatal(err)
	}
	if now, v, _ := indexState(t, conn, "clearance_evidence_gate"); now != oid || !v {
		t.Fatalf("the finished ghost's index is not the one kept: oid %d (was %d) valid %v", now, oid, v)
	}
}

// Close during a build returns at once (bounded), and the build stops on the server too: pgx's context cancel is a
// CancelRequest here, not only a closed socket (a backend waiting on a lock does not notice a closed socket). The
// next start finds the INVALID index and rebuilds it.
func TestCloseDuringABuildIsBounded(t *testing.T) {
	dsn := newDB(t)
	s := open(t, dsn)
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	waitIndexes(t, conn)
	dropMapIndexes(t, conn)
	blocker, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(bg)
	if _, err := blocker.Exec(bg, "BEGIN; LOCK TABLE clearance_evidence IN ROW EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	s.startIndexBuild()
	waitFor(t, "the build", func() bool { return activeBuilds(t, conn) > 0 })
	start := time.Now()
	s.Close()
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("Close took %s during a build", d)
	}
	waitFor(t, "the cancelled build to leave the server", func() bool { return activeBuilds(t, conn) == 0 })
	if _, err := blocker.Exec(bg, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	if _, v, found := indexState(t, conn, "clearance_evidence_gate"); found && v {
		t.Fatal("a cancelled build left a valid index")
	}
	open(t, dsn) // the next start drops the invalid one and builds again
	waitIndexes(t, conn)
}
