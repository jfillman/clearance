package pg

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/storetest"
)

// schemaV0573 is internal/store/pg's Schema as the v0.57.3 core ran it at start (git show v0.57.3:internal/store/pg/pg.go):
// the statements a database created by that release was built with.
//
//go:embed testdata/schema-v0.57.3.sql
var schemaV0573 string

// catalog is the shape of the database's objects: every table, column, index definition and constraint, with the oid of
// each relation (a recreated object has a new one), except clearance_schema itself.
func catalog(t *testing.T, dsn string) []string {
	t.Helper()
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	var out []string
	for _, q := range []string{
		`SELECT 'rel ' || c.oid || ' ' || c.relname || ' ' || c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE n.nspname = 'public' AND c.relname <> 'clearance_schema' AND c.relname NOT LIKE 'clearance_schema\_%'`,
		`SELECT 'col ' || table_name || '.' || column_name || ' ' || data_type || ' ' || is_nullable || ' ' || coalesce(column_default, '')
		  FROM information_schema.columns WHERE table_schema = 'public' AND table_name <> 'clearance_schema'`,
		`SELECT 'idx ' || indexdef FROM pg_indexes WHERE schemaname = 'public' AND tablename <> 'clearance_schema'`,
		`SELECT 'con ' || conrelid::regclass || ' ' || pg_get_constraintdef(oid) FROM pg_constraint
		  WHERE connamespace = 'public'::regnamespace AND conrelid::regclass::text <> 'clearance_schema'`,
	} {
		rows, err := conn.Query(bg, q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		rows.Close()
	}
	return out
}

func diff(a, b []string) []string {
	in := map[string]bool{}
	for _, s := range a {
		in[s] = true
	}
	var d []string
	for _, s := range b {
		if !in[s] {
			d = append(d, "+ "+s)
		}
		delete(in, s)
	}
	for s := range in {
		d = append(d, "- "+s)
	}
	return d
}

func exec(t *testing.T, dsn, sql string) {
	t.Helper()
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	if _, err := conn.Exec(bg, sql); err != nil {
		t.Fatal(err)
	}
}

// A database created by v0.57.3's code adopts migration 1 with no DDL change: no object is created, altered or
// recreated (same oids, same columns, indexes and constraints); only clearance_schema, and its one row, is new.
func TestADatabaseFromV0573AdoptsMigrationOneWithNoDDLChange(t *testing.T) {
	dsn := newDB(t)
	exec(t, dsn, schemaV0573)
	// Records written by that release, so the chain is real.
	before := catalog(t, dsn)
	if len(before) < 40 {
		t.Fatalf("the v0.57.3 schema has only %d catalog entries: the fixture is not the schema", len(before))
	}
	s, err := Open(bg, dsn, Options{VerifyBatch: 3, CoreVersion: "0.58.0"})
	if err != nil {
		t.Fatal(err)
	}
	<-s.build.done
	appendN(t, s, 3)
	info, err := s.SchemaInfo(bg)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if info.Version != 1 || info.MinCore != "0.0.0" || info.NoRollback || len(info.Migrations) != 1 {
		t.Fatalf("schema info: %+v", info)
	}
	if m := info.Migrations[0]; !m.Adopted || m.Name != "baseline" || m.Kind != KindExpand || m.CoreVersion != "0.58.0" {
		t.Fatalf("migration 1 was not adopted: %+v", m)
	}
	// The Map's indexes are built by the core in the background, after start and not by the migration (indexes.go): they
	// are not migration 1's, and they are not DDL of the adoption.
	after := catalog(t, dsn)
	var changed []string
	for _, d := range diff(before, after) {
		if !strings.Contains(d, "clearance_evidence_") || !isMapIndex(d) {
			changed = append(changed, d)
		}
	}
	if len(changed) > 0 {
		t.Fatalf("adopting migration 1 changed the database:\n%s", strings.Join(changed, "\n"))
	}
}

func isMapIndex(line string) bool {
	for _, ix := range MapIndexes {
		if strings.Contains(line, ix.Name) {
			return true
		}
	}
	return false
}

// A database an old release built that lacks an object migration 1 creates is not adopted: migration 1 runs, and the
// missing object appears.
func TestAnIncompleteLegacyDatabaseRunsMigrationOne(t *testing.T) {
	dsn := newDB(t)
	exec(t, dsn, schemaV0573+"; DROP TABLE clearance_packets; ALTER TABLE clearance_signing_keys DROP COLUMN revoked_at")
	s := open(t, dsn)
	info, _ := s.SchemaInfo(bg)
	if len(info.Migrations) != 1 || info.Migrations[0].Adopted {
		t.Fatalf("an incomplete database was adopted without DDL: %+v", info.Migrations)
	}
	exec(t, dsn, "SELECT count(*) FROM clearance_packets; SELECT revoked_at FROM clearance_signing_keys")
}

func TestAFreshDatabaseRunsMigrationOne(t *testing.T) {
	s := open(t, newDB(t))
	info, err := s.SchemaInfo(bg)
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != 1 || info.Migrations[0].Adopted {
		t.Fatalf("%+v", info)
	}
	// A second start applies nothing.
	dsn2 := newDB(t)
	s2 := open(t, dsn2)
	s2.Close()
	s3 := open(t, dsn2)
	if i, _ := s3.SchemaInfo(bg); len(i.Migrations) != 1 {
		t.Fatalf("%+v", i)
	}
}

// -- the upgrade path -------------------------------------------------------------------------------------------------

func expandTwo() Migration {
	return Migration{Version: 2, Name: "add-probe", Kind: KindExpand, Release: "0.59.0", MinCore: "0.0.0",
		DDL: `CREATE TABLE IF NOT EXISTS clearance_probe (id text PRIMARY KEY, note text);`}
}

func contractTwo() Migration {
	return Migration{Version: 2, Name: "drop-signing-revoked-at", Kind: KindContract, Release: "0.59.0", MinCore: "0.59.0",
		Retires: []string{"clearance_signing_keys.revoked_at"}, DDL: `ALTER TABLE clearance_signing_keys DROP COLUMN revoked_at;`}
}

func openAt(t *testing.T, dsn, core string, list ...Migration) (*Store, error) {
	t.Helper()
	s, err := Open(bg, dsn, Options{VerifyBatch: 3, CoreVersion: core, Migrations: list})
	if err == nil {
		t.Cleanup(s.Close)
		<-s.build.done
	}
	return s, err
}

func TestACoreOlderThanTheSchemasMinCoreRefusesToStart(t *testing.T) {
	dsn := newDB(t)
	s, err := openAt(t, dsn, "0.59.0", base(), contractTwo())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err = openAt(t, dsn, "0.58.0", base())
	var se *SchemaError
	if !errors.Is(err, ErrCoreTooOld) || !errors.As(err, &se) || se.Code != CodeCoreTooOld || !strings.HasPrefix(err.Error(), "schema_requires_newer_core:") {
		t.Fatalf("a 0.58.0 core on a schema that needs 0.59.0: %v", err)
	}
	if !strings.Contains(err.Error(), "drop-signing-revoked-at") {
		t.Fatalf("the refusal does not name the migration: %v", err)
	}
	// The reader refuses the same way, when it is told its version.
	if _, err := OpenReader(bg, dsn, Options{CoreVersion: "0.58.0"}); !errors.Is(err, ErrCoreTooOld) {
		t.Fatalf("reader: %v", err)
	}
	// A core that meets min_core (this one, or a later one) starts.
	for _, v := range []string{"0.59.0", "0.59.1", "v0.60.0"} {
		s, err := openAt(t, dsn, v, base(), contractTwo())
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		s.Close()
	}
}

// A newer schema whose min_core the core meets is accepted: what makes a rollback across expand migrations work.
func TestACoreAcceptsANewerSchemaItsVersionMeets(t *testing.T) {
	dsn := newDB(t)
	cand, err := openAt(t, dsn, "0.59.0", base(), expandTwo())
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, cand, 2)
	cand.Close()
	prev, err := openAt(t, dsn, "0.58.0", base()) // knows only migration 1; the schema has 2
	if err != nil {
		t.Fatalf("the previous core on an expand-only schema: %v", err)
	}
	appendN(t, prev, 2)
	if cp, err := prev.Verify(bg, nil); err != nil || cp.Count != 4 {
		t.Fatalf("verify: %+v %v", cp, err)
	}
	if i, _ := prev.SchemaInfo(bg); i.Version != 2 || i.MinCore != "0.0.0" {
		t.Fatalf("%+v", i)
	}
}

func TestAMigrationRunsInOneTransaction(t *testing.T) {
	dsn := newDB(t)
	s, err := openAt(t, dsn, "0.58.0", base())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	bad := Migration{Version: 2, Name: "half", Kind: KindExpand, Release: "0.59.0", MinCore: "0.0.0",
		DDL: `CREATE TABLE IF NOT EXISTS clearance_half (id text); CREATE TABLE clearance_evidence (id text);`}
	if _, err := openAt(t, dsn, "0.59.0", base(), bad); err == nil {
		t.Fatal("a failing migration was applied")
	}
	conn, _ := pgx.Connect(bg, dsn)
	defer conn.Close(bg)
	var exists bool
	var n int
	_ = conn.QueryRow(bg, `SELECT to_regclass('clearance_half') IS NOT NULL`).Scan(&exists)
	_ = conn.QueryRow(bg, `SELECT count(*) FROM clearance_schema`).Scan(&n)
	if exists || n != 1 {
		t.Fatalf("the failed migration left clearance_half=%v and %d schema rows", exists, n)
	}
	// And the database still opens with the sound list.
	if _, err := openAt(t, dsn, "0.59.0", base(), expandTwo()); err != nil {
		t.Fatal(err)
	}
}

func TestAnEditedReleasedMigrationIsRefused(t *testing.T) {
	dsn := newDB(t)
	s, err := openAt(t, dsn, "0.59.0", base(), expandTwo())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	edited := expandTwo()
	edited.DDL += ` CREATE TABLE IF NOT EXISTS clearance_sneaky (id text);`
	_, err = openAt(t, dsn, "0.59.0", base(), edited)
	var se *SchemaError
	if !errors.As(err, &se) || se.Code != CodeMigrationChanged {
		t.Fatalf("%v", err)
	}
}

func TestAGapInTheSchemaHistoryIsRefused(t *testing.T) {
	dsn := newDB(t)
	s, err := openAt(t, dsn, "0.59.0", base(), expandTwo())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	exec(t, dsn, `DELETE FROM clearance_schema WHERE version = 1`)
	_, err = openAt(t, dsn, "0.59.0", base(), expandTwo())
	var se *SchemaError
	if !errors.As(err, &se) || se.Code != CodeSchemaGap {
		t.Fatalf("%v", err)
	}
}

// -- the whole-install upgrade, at the store (N-6f) ----------------------------------------------------------------

// scratchCopy is a physical copy of a database (CREATE DATABASE ... TEMPLATE): the pre-upgrade backup the restore path
// restores. Nothing may be connected to the source.
func scratchCopy(t *testing.T, dsn string) string {
	t.Helper()
	u, _ := url.Parse(dsn)
	src := strings.TrimPrefix(u.Path, "/")
	name := fmt.Sprintf("%s_restored", src)
	u.Path = "/postgres"
	maintenance := u.String() // the cleanup connects here: a database cannot be dropped from a connection to itself
	conn, err := pgx.Connect(bg, maintenance)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	if _, err := conn.Exec(bg, "CREATE DATABASE "+name+" TEMPLATE "+src); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), maintenance)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(context.Background())
		}
	})
	restored, _ := url.Parse(maintenance)
	restored.Path = "/" + name
	return restored.String()
}

// previous release -> candidate -> verify the chain; then either the previous core rolls back onto the upgraded schema
// (expand only), or it refuses it with the named code and the pre-upgrade backup is restored (no-rollback).
func TestUpgradeAndRollBackAcrossExpandMigrations(t *testing.T) {
	dsn := newDB(t)
	prev, err := openAt(t, dsn, "0.58.0", base())
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, prev, 5)
	prev.Close()

	cand, err := openAt(t, dsn, "0.59.0", base(), expandTwo())
	if err != nil {
		t.Fatal(err)
	}
	if cp, err := cand.Verify(bg, nil); err != nil || cp.Count != 5 {
		t.Fatalf("the candidate does not verify the chain the previous core wrote: %+v %v", cp, err)
	}
	appendN(t, cand, 3)
	cand.Close()

	back, err := openAt(t, dsn, "0.58.0", base())
	if err != nil {
		t.Fatalf("rollback to the previous core on the upgraded schema: %v", err)
	}
	appendN(t, back, 2)
	if cp, err := back.Verify(bg, nil); err != nil || cp.Count != 10 {
		t.Fatalf("after the rollback and a write: %+v %v", cp, err)
	}
}

func TestANoRollbackUpgradeIsRefusedByThePreviousCoreAndRestoresFromBackup(t *testing.T) {
	dsn := newDB(t)
	prev, err := openAt(t, dsn, "0.58.0", base())
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, prev, 5)
	prev.Close()
	backup := scratchCopy(t, dsn) // the pre-upgrade backup

	cand, err := openAt(t, dsn, "0.59.0", base(), contractTwo())
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, cand, 4) // records written after the backup
	witnessed, err := cand.Verify(bg, nil)
	if err != nil || witnessed.Count != 9 {
		t.Fatalf("%+v %v", witnessed, err)
	}
	cand.Close()

	if _, err := openAt(t, dsn, "0.58.0", base()); !errors.Is(err, ErrCoreTooOld) {
		t.Fatalf("the previous core on a no-rollback schema: %v, want %s", err, CodeCoreTooOld)
	}

	// The restore path: the backup, the previous core on it, the chain verifies, and the 4 records written after the backup
	// are missing from it: the gap a witness would name. (Recording that gap as an exception is N-11's `clearance restore
	// verify`, not built yet.)
	back, err := openAt(t, backup, "0.58.0", base())
	if err != nil {
		t.Fatalf("the previous core on the restored backup: %v", err)
	}
	cp, err := back.Verify(bg, nil)
	if err != nil || cp.Count != 5 {
		t.Fatalf("restored chain: %+v %v", cp, err)
	}
	if cp.Count >= witnessed.Count {
		t.Fatalf("the restore shows no gap against the last witnessed head (%d vs %d)", cp.Count, witnessed.Count)
	}
	appendN(t, back, 1)
	if _, err := back.Verify(bg, nil); err != nil {
		t.Fatal(err)
	}
}

var _ store.SchemaReporter = (*Store)(nil)
var _ = storetest.Writer

// The guard holds on a reconnect too: a writer that lost its connection (and the lock) while another core applied a
// contract migration refuses to write on the new schema.
func TestTheGuardHoldsAfterTheWriterReconnects(t *testing.T) {
	dsn := newDB(t)
	s, err := openAt(t, dsn, "0.58.0", base())
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 2)
	exec(t, dsn, `INSERT INTO clearance_schema (version, name, kind, release, min_core, checksum, core)
VALUES (2, 'drop-x', 'contract', '0.59.0', '0.59.0', 'x', '0.59.0')`)
	pid := s.conn.PgConn().PID()
	exec(t, dsn, fmt.Sprintf("SELECT pg_terminate_backend(%d)", pid))
	// The first attempts may fail on the dead connection; none may succeed, and the refusal must come.
	var last error
	for i := 0; i < 5; i++ {
		last = s.Atomic(bg, func(tx store.Tx) error {
			_, err := tx.Append(bg, store.Event{"tool": "after"}, storetest.Writer)
			return err
		})
		if last == nil {
			t.Fatal("the old core wrote after the schema moved past it")
		}
		if errors.Is(last, ErrCoreTooOld) {
			return
		}
	}
	t.Fatalf("no refusal with %s after the schema moved: last error %v", CodeCoreTooOld, last)
}
