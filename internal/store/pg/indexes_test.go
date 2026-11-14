package pg

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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
