package pg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/compat"
	"github.com/jfillman/clearance/internal/store"
)

// Migration kinds (N-6e). A release may ship any number of expand migrations, and contract migrations only for shapes that
// a release at least one version earlier already stopped using (Unused).
const (
	// KindExpand is new tables, nullable columns and new indexes: it leaves MinCore alone, so the previous core runs on the
	// expanded schema.
	KindExpand = "expand"
	// KindContract is a drop, a rename, a type change or a new NOT NULL: it raises MinCore to its own release, so an
	// older core refuses to start, and the release is marked no-rollback.
	KindContract = "contract"
)

// The named refusals of this file. Each is the first word of its error's message.
const (
	// CodeCoreTooOld: the core is older than the schema's min_core (N-6b).
	CodeCoreTooOld = "schema_requires_newer_core"
	// CodeMigrationChanged: a migration the database records as applied no longer matches the one this core carries.
	CodeMigrationChanged = "schema_migration_changed"
	// CodeSchemaGap: the database's clearance_schema has a hole, or a row this core cannot account for.
	CodeSchemaGap = "schema_history_invalid"
)

// Migration is one step of the schema, forward only.
type Migration struct {
	Version int
	Name    string
	Kind    string
	// Release is the release (X.Y.Z) that first ships it.
	Release string
	// MinCore is the oldest core that can run on the schema after this migration. An expand migration repeats the one
	// before it; a contract migration's is its own Release.
	MinCore string
	// Retires, for a contract migration, is every shape it drops or changes ("table" or "table.column"). Each must be in
	// Unused, since a release at least one version before Release.
	Retires []string
	// DDL runs in one transaction, under the writer lock.
	DDL string
}

// Unused is a shape that no release uses from Since on: the code stopped reading and writing it in that release. A
// contract migration may retire it in the next release after Since or later.
type Unused struct {
	Shape string
	Since string
}

// unused is every shape retired from use and not yet dropped. Empty today: migration 1 is the baseline.
var unused = []Unused{}

// migrations is the ordered list. Migration 1 is the idempotent DDL every core before N-6 ran at start (Schema), so a
// database built by one of them adopts it with no DDL change. Never edit a released migration (the database records its
// checksum, and a core refuses one that changed): add the next.
var migrations = []Migration{
	{Version: 1, Name: "baseline", Kind: KindExpand, Release: "0.58.0", MinCore: "0.0.0", DDL: Schema},
}

// Migrations is a copy of the migration list.
func Migrations() []Migration { return append([]Migration(nil), migrations...) }

// UnusedShapes is a copy of the retired-from-use list.
func UnusedShapes() []Unused { return append([]Unused(nil), unused...) }

func (m Migration) checksum() string {
	h := sha256.Sum256([]byte(m.DDL))
	return hex.EncodeToString(h[:])
}

// SchemaError is a refusal to run on the database's schema. Code is one of the Code constants.
type SchemaError struct {
	Code string
	Msg  string
}

func (e *SchemaError) Error() string { return e.Code + ": " + e.Msg }

// Is makes errors.Is(err, ErrCoreTooOld) true for the version guard's refusal.
func (e *SchemaError) Is(target error) bool {
	t, ok := target.(*SchemaError)
	return ok && t.Code == e.Code
}

// ErrCoreTooOld matches (errors.Is) the version guard's refusal.
var ErrCoreTooOld = &SchemaError{Code: CodeCoreTooOld}

const schemaTable = `
CREATE TABLE IF NOT EXISTS clearance_schema (
  version     integer     PRIMARY KEY,
  name        text        NOT NULL,
  kind        text        NOT NULL CHECK (kind IN ('expand', 'contract')),
  release     text        NOT NULL,
  min_core    text        NOT NULL,
  checksum    text        NOT NULL,
  core        text        NOT NULL DEFAULT '',
  adopted     boolean     NOT NULL DEFAULT false,
  applied_at  timestamptz NOT NULL DEFAULT now()
)`

// readApplied reads clearance_schema; a database without the table has no migrations.
func readApplied(ctx context.Context, q querier) ([]store.AppliedMigration, map[int]string, error) {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('clearance_schema') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, nil, err
	}
	if !exists {
		return nil, nil, nil
	}
	rows, err := q.Query(ctx, `SELECT version, name, kind, release, min_core, checksum, core, adopted, applied_at
FROM clearance_schema ORDER BY version`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []store.AppliedMigration
	sums := map[int]string{}
	for rows.Next() {
		var a store.AppliedMigration
		var sum string
		if err := rows.Scan(&a.Version, &a.Name, &a.Kind, &a.Release, &a.MinCore, &sum, &a.CoreVersion, &a.Adopted, &a.AppliedAt); err != nil {
			return nil, nil, err
		}
		out = append(out, a)
		sums[a.Version] = sum
	}
	return out, sums, rows.Err()
}

// SummarizeSchema is the SchemaInfo of a list of applied migrations.
func SummarizeSchema(applied []store.AppliedMigration) store.SchemaInfo {
	info := store.SchemaInfo{MinCore: "0.0.0", Migrations: applied}
	if info.Migrations == nil {
		info.Migrations = []store.AppliedMigration{}
	}
	for _, a := range applied {
		if a.Version > info.Version {
			info.Version = a.Version
		}
		if lt, ok := compat.Less(info.MinCore, a.MinCore); ok && lt {
			info.MinCore = a.MinCore
		}
	}
	info.NoRollback = info.MinCore != "0.0.0"
	return info
}

// SchemaInfo reads the database's clearance_schema. A database no versioned core has opened reports version 0.
func (r *Reader) SchemaInfo(ctx context.Context) (store.SchemaInfo, error) {
	ctx, cancel := deadline(ctx, r.opt)
	defer cancel()
	applied, _, err := readApplied(ctx, r.pool)
	if err != nil {
		return store.SchemaInfo{}, fmt.Errorf("pg: reading the schema version: %w", err)
	}
	return SummarizeSchema(applied), nil
}

// Guard is the version guard (N-6b): nil when a core of this version may run on a schema whose applied migrations are
// these, else a *SchemaError. A core version that does not parse (a development build) is not guarded. A schema newer
// than the core's own list is accepted when the core meets its min_core: that is what makes a rollback across expand
// migrations work.
func Guard(coreVersion string, applied []store.AppliedMigration) error {
	if _, ok := compat.Parse3(coreVersion); !ok {
		return nil
	}
	info := SummarizeSchema(applied)
	if lt, ok := compat.Less(coreVersion, info.MinCore); ok && lt {
		by := ""
		for _, a := range applied {
			if a.MinCore == info.MinCore {
				by = fmt.Sprintf(" (migration %d, %s, release %s)", a.Version, a.Name, a.Release)
			}
		}
		return &SchemaError{Code: CodeCoreTooOld, Msg: fmt.Sprintf(
			"this core is %s and the database schema needs a core of at least %s%s; upgrade the core, or restore the pre-upgrade backup",
			strings.TrimPrefix(coreVersion, "v"), info.MinCore, by)}
	}
	return nil
}

// checkHistory refuses a clearance_schema this core cannot account for: a hole in the versions, or a row for a version
// it carries whose migration changed.
func checkHistory(list []Migration, applied []store.AppliedMigration, sums map[int]string) error {
	byVersion := map[int]Migration{}
	for _, m := range list {
		byVersion[m.Version] = m
	}
	for i, a := range applied {
		if a.Version != i+1 {
			return &SchemaError{Code: CodeSchemaGap, Msg: fmt.Sprintf("clearance_schema has version %d where %d is expected: a migration is missing", a.Version, i+1)}
		}
		if m, ok := byVersion[a.Version]; ok && m.checksum() != sums[a.Version] {
			return &SchemaError{Code: CodeMigrationChanged, Msg: fmt.Sprintf(
				"migration %d (%s) is recorded as applied with different DDL than this core carries: a released migration was edited; add a new migration instead", a.Version, m.Name)}
		}
	}
	return nil
}

var (
	createTableRx = regexp.MustCompile(`(?im)^\s*CREATE TABLE IF NOT EXISTS\s+([a-z_0-9]+)`)
	createIndexRx = regexp.MustCompile(`(?im)^\s*CREATE (?:UNIQUE )?INDEX IF NOT EXISTS\s+([a-z_0-9]+)`)
	addColumnRx   = regexp.MustCompile(`(?im)^\s*ALTER TABLE\s+([a-z_0-9]+)\s+ADD COLUMN IF NOT EXISTS\s+([a-z_0-9]+)`)
)

// presentAlready says whether every object migration 1's DDL would create is in the database: the tables, the indexes,
// and the columns it adds. It reads the same DDL text the migration runs, so it cannot drift from it. When it is, the
// database was built by a core before N-6 and the migration is recorded without running (no DDL change).
func presentAlready(ctx context.Context, q querier, m Migration) (bool, error) {
	var tables, indexes []string
	for _, x := range createTableRx.FindAllStringSubmatch(m.DDL, -1) {
		tables = append(tables, x[1])
	}
	for _, x := range createIndexRx.FindAllStringSubmatch(m.DDL, -1) {
		indexes = append(indexes, x[1])
	}
	if len(tables) == 0 {
		return false, nil
	}
	var missing int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM unnest($1::text[]) AS n WHERE to_regclass(quote_ident(n)) IS NULL`,
		append(append([]string(nil), tables...), indexes...)).Scan(&missing); err != nil {
		return false, err
	}
	if missing > 0 {
		return false, nil
	}
	for _, x := range addColumnRx.FindAllStringSubmatch(m.DDL, -1) {
		var n int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`, x[1], x[2]).Scan(&n); err != nil {
			return false, err
		}
		if n == 0 {
			return false, nil
		}
	}
	return true, nil
}

// migrate brings the database to the end of list, on the writer's connection (which holds the advisory lock). It first
// applies the version guard, then runs each pending migration in one transaction with its clearance_schema row.
func (s *Store) migrate(ctx context.Context, list []Migration, coreVersion string) error {
	if _, err := s.conn.Exec(ctx, schemaTable); err != nil {
		return fmt.Errorf("pg: migrate: %w", err)
	}
	applied, sums, err := readApplied(ctx, s.conn)
	if err != nil {
		return fmt.Errorf("pg: migrate: %w", err)
	}
	if err := Guard(coreVersion, applied); err != nil {
		return err
	}
	if err := checkHistory(list, applied, sums); err != nil {
		return err
	}
	if _, ok := compat.Parse3(coreVersion); !ok {
		s.opt.Logger.Warn("clearance store: the core's version is not X.Y.Z, so the schema version guard is off", "version", coreVersion)
	}
	for _, m := range list {
		if m.Version <= len(applied) {
			continue
		}
		if err := s.apply(ctx, m, coreVersion); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) apply(ctx context.Context, m Migration, coreVersion string) error {
	ctx, cancel := context.WithTimeout(ctx, s.opt.MigrateTimeout)
	defer cancel()
	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg: migration %d: %w", m.Version, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = 0"); err != nil {
		return fmt.Errorf("pg: migration %d: %w", m.Version, err)
	}
	adopted := false
	if m.Version == 1 {
		if adopted, err = presentAlready(ctx, tx, m); err != nil {
			return fmt.Errorf("pg: migration %d: %w", m.Version, err)
		}
	}
	if !adopted {
		if _, err := tx.Exec(ctx, m.DDL); err != nil {
			return fmt.Errorf("pg: migration %d (%s): %w", m.Version, m.Name, err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO clearance_schema (version, name, kind, release, min_core, checksum, core, adopted)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, m.Version, m.Name, m.Kind, m.Release, m.MinCore, m.checksum(), strings.TrimPrefix(coreVersion, "v"), adopted); err != nil {
		return fmt.Errorf("pg: migration %d: %w", m.Version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pg: migration %d: %w", m.Version, err)
	}
	s.opt.Logger.Info("clearance schema migrated", "version", m.Version, "name", m.Name, "kind", m.Kind, "adopted_without_ddl", adopted,
		"at", time.Now().UTC().Format(time.RFC3339))
	return nil
}

// ---- the CI rules (N-6e) ------------------------------------------------------------------------------------------

var (
	commentRx = regexp.MustCompile(`--[^\n]*`)
	spaceRx   = regexp.MustCompile(`\s+`)
)

// Statements splits DDL into its statements, comments removed and whitespace collapsed.
func Statements(ddl string) []string {
	var out []string
	for _, st := range strings.Split(commentRx.ReplaceAllString(ddl, ""), ";") {
		if st = strings.TrimSpace(spaceRx.ReplaceAllString(st, " ")); st != "" {
			out = append(out, st)
		}
	}
	return out
}

var (
	alterRx    = regexp.MustCompile(`(?i)^ALTER TABLE (?:IF EXISTS )?(?:ONLY )?(\S+) (.+)$`)
	addColRx   = regexp.MustCompile(`(?i)^ADD COLUMN(?: IF NOT EXISTS)? `)
	contractAc = regexp.MustCompile(`(?i)^(DROP |RENAME |ALTER |ADD CONSTRAINT )`)
	notNullRx  = regexp.MustCompile(`(?i)\bNOT NULL\b|\bPRIMARY KEY\b|\bUNIQUE\b|\bREFERENCES\b|\bGENERATED\b`)
	concurrRx  = regexp.MustCompile(`(?i)\bCONCURRENTLY\b`)
	createRx   = regexp.MustCompile(`(?i)^(CREATE TABLE( IF NOT EXISTS)? |CREATE (UNIQUE )?INDEX( IF NOT EXISTS)? )`)
	dropRx     = regexp.MustCompile(`(?i)^(DROP |TRUNCATE |ALTER INDEX \S+ RENAME )`)
)

// splitActions splits the actions of an ALTER TABLE on the commas outside parentheses.
func splitActions(s string) []string {
	var out []string
	depth, from := 0, 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[from:i]))
				from = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[from:]))
}

// ClassifyStatement says what one DDL statement is: KindExpand (a new table, a new index, a new nullable column),
// KindContract (a drop, a rename, a type change, a new NOT NULL), or "" for anything else: a data change, a function, a
// concurrent index build, or a statement that mixes expand and contract actions (an ALTER TABLE is classified by every
// one of its actions). "" fails CI.
func ClassifyStatement(st string) string {
	switch {
	case concurrRx.MatchString(st):
		return ""
	case dropRx.MatchString(st):
		return KindContract
	case createRx.MatchString(st):
		return KindExpand
	}
	m := alterRx.FindStringSubmatch(st)
	if m == nil {
		return ""
	}
	kind := ""
	for _, a := range splitActions(m[2]) {
		var k string
		switch {
		case addColRx.MatchString(a) && notNullRx.MatchString(a):
			k = KindContract // a new NOT NULL column: the previous release's inserts would fail
		case addColRx.MatchString(a):
			k = KindExpand
		case contractAc.MatchString(a):
			k = KindContract
		default:
			return ""
		}
		if kind != "" && kind != k {
			return ""
		}
		kind = k
	}
	return kind
}

var (
	dropTableRx  = regexp.MustCompile(`(?i)^DROP (?:TABLE|INDEX|VIEW|SEQUENCE)(?: IF EXISTS)? ([^\s,;]+)`)
	truncateRx   = regexp.MustCompile(`(?i)^TRUNCATE (?:TABLE )?(?:ONLY )?([^\s,;]+)`)
	alterColRx   = regexp.MustCompile(`(?i)^(?:DROP COLUMN(?: IF EXISTS)?|ALTER COLUMN|RENAME COLUMN|ADD COLUMN(?: IF NOT EXISTS)?) ([^\s,;]+)`)
	alterIdxName = regexp.MustCompile(`(?i)^ALTER INDEX (?:IF EXISTS )?(\S+) RENAME `)
)

// Shapes are the shapes a contract statement drops or changes: "table" or "table.column" (an index is its own name; a
// statement it cannot read column by column is the table). CheckMigrations requires each to be covered by the migration's
// Retires, so the declaration cannot name one shape while the DDL changes another.
func Shapes(st string) []string {
	if m := dropTableRx.FindStringSubmatch(st); m != nil {
		return []string{m[1]}
	}
	if m := truncateRx.FindStringSubmatch(st); m != nil {
		return []string{m[1]}
	}
	if m := alterIdxName.FindStringSubmatch(st); m != nil {
		return []string{m[1]}
	}
	m := alterRx.FindStringSubmatch(st)
	if m == nil {
		return nil
	}
	var out []string
	for _, a := range splitActions(m[2]) {
		if c := alterColRx.FindStringSubmatch(a); c != nil {
			out = append(out, m[1]+"."+c[1])
		} else {
			out = append(out, m[1]) // RENAME TO, ADD/DROP CONSTRAINT: the table's shape
		}
	}
	return out
}

// covers: a retired shape "t" covers "t.c".
func covers(retired, shape string) bool {
	return retired == shape || strings.HasPrefix(shape, retired+".")
}

// CheckMigrations is N-6e as a function: every violation of the list's rules, empty when it is sound. tab is the
// compatibility table, retired the shapes released as unused.
func CheckMigrations(list []Migration, tab compat.Table, retired []Unused) []string {
	var bad []string
	add := func(f string, a ...any) { bad = append(bad, fmt.Sprintf(f, a...)) }
	minCore, prevRelease := "0.0.0", "0.0.0"
	retiredSince := map[string]string{}
	for _, u := range retired {
		retiredSince[u.Shape] = u.Since
		if _, ok := tab.Exact(u.Since); !ok {
			add("unused shape %s: release %s is not in the compatibility table", u.Shape, u.Since)
		}
	}
	for i, m := range list {
		who := fmt.Sprintf("migration %d (%s)", m.Version, m.Name)
		if m.Version != i+1 {
			add("%s: versions must run 1, 2, 3 in order; this is at position %d", who, i+1)
		}
		if m.Name == "" {
			add("%s: no name", who)
		}
		if _, ok := compat.Parse3(m.Release); !ok {
			add("%s: release %q is not X.Y.Z", who, m.Release)
			continue
		}
		if _, ok := tab.Exact(m.Release); !ok {
			add("%s: release %s is not in the compatibility table", who, m.Release)
		}
		if lt, _ := compat.Less(m.Release, prevRelease); lt {
			add("%s: release %s is before the previous migration's %s", who, m.Release, prevRelease)
		}
		kinds := map[string]int{}
		for _, st := range Statements(m.DDL) {
			k := ClassifyStatement(st)
			if k == "" {
				add("%s: neither expand nor contract: %q", who, abbreviate(st))
			}
			kinds[k]++
		}
		if len(kinds) == 0 {
			add("%s: no DDL", who)
		}
		switch m.Kind {
		case KindExpand:
			if kinds[KindContract] > 0 {
				add("%s: declared expand but has a contract statement; a contract migration stands alone", who)
			}
			if m.MinCore != minCore {
				add("%s: an expand migration leaves min_core at %s, not %s", who, minCore, m.MinCore)
			}
			if len(m.Retires) > 0 {
				add("%s: an expand migration retires nothing", who)
			}
		case KindContract:
			if kinds[KindExpand] > 0 || kinds[""] > 0 {
				add("%s: declared contract but has other statements; a contract migration is only contract statements", who)
			}
			if kinds[KindContract] == 0 {
				add("%s: declared contract but has no contract statement", who)
			}
			if m.MinCore != m.Release {
				add("%s: a contract migration raises min_core to its own release %s, not %s", who, m.Release, m.MinCore)
			}
			if len(m.Retires) == 0 {
				add("%s: a contract migration names the shapes it retires", who)
			}
			for _, st := range Statements(m.DDL) {
				for _, shape := range Shapes(st) {
					covered := false
					for _, r := range m.Retires {
						covered = covered || covers(r, shape)
					}
					if !covered {
						add("%s: the DDL changes %s, which its Retires does not name", who, shape)
					}
				}
			}
			prev, hasPrev := tab.Previous(m.Release)
			if hasPrev && prev.SchemaVersion < 1 {
				add("%s: the previous release (%s) has no version guard, so it would start on a schema it cannot run; a contract migration comes only after a release that carries the guard", who, prev.Core)
			}
			for _, shape := range m.Retires {
				since, ok := retiredSince[shape]
				switch {
				case !ok:
					add("%s: retires %s, which no release has stopped using (it is not in the unused list)", who, shape)
				case !hasPrev:
					add("%s: retires %s but there is no previous release", who, shape)
				default:
					if lt, _ := compat.Less(prev.Core, since); lt {
						add("%s: retires %s, which the previous release (%s) still used: it stopped in %s", who, shape, prev.Core, since)
					}
				}
			}
			if lt, _ := compat.Less(minCore, m.MinCore); !lt {
				add("%s: a contract migration must raise min_core above %s", who, minCore)
			}
		default:
			add("%s: kind %q is neither expand nor contract", who, m.Kind)
		}
		if lt, ok := compat.Less(minCore, m.MinCore); ok && lt {
			minCore = m.MinCore
		}
		prevRelease = m.Release
	}
	// The table says what the migrations do.
	for _, r := range tab.Releases {
		version, rowMin, contract := 0, "0.0.0", false
		for _, m := range list {
			if lt, _ := compat.Less(r.Core, m.Release); lt {
				continue
			}
			version = m.Version
			if lt, ok := compat.Less(rowMin, m.MinCore); ok && lt {
				rowMin = m.MinCore
			}
			if m.Release == r.Core && m.Kind == KindContract {
				contract = true
			}
		}
		if r.SchemaVersion != version {
			add("compat table, release %s: schema_version is %d, the migrations say %d", r.Core, r.SchemaVersion, version)
		}
		if r.MinCore != rowMin {
			add("compat table, release %s: min_core is %s, the migrations say %s", r.Core, r.MinCore, rowMin)
		}
		if r.NoRollback != contract {
			add("compat table, release %s: no_rollback is %v, but the release's contract migrations say %v", r.Core, r.NoRollback, contract)
		}
	}
	sort.Strings(bad)
	return bad
}

func abbreviate(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
