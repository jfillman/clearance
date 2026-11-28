package pg

import (
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/compat"
)

// The shipped list and the shipped table obey N-6e: this is the CI gate a release's migrations pass.
func TestShippedMigrationsObeyTheRules(t *testing.T) {
	if bad := CheckMigrations(Migrations(), compat.Embedded(), UnusedShapes()); len(bad) > 0 {
		t.Fatalf("the migration list breaks the expand/contract rules:\n  %s", strings.Join(bad, "\n  "))
	}
}

func TestMigrationOneIsTheSchemaOfV0573(t *testing.T) {
	if Migrations()[0].DDL != Schema {
		t.Fatal("migration 1 must be Schema")
	}
}

// The tables the negative tests share: 0.58.0 shipped schema 1; 0.59.0 stopped using clearance_changes.legacy;
// 0.60.0 is the release under test.
func rulesTable() compat.Table {
	return compat.Table{Format: 1, Releases: []compat.Release{
		{Core: "0.58.0", SchemaVersion: 1, MinCore: "0.0.0"},
		{Core: "0.59.0", SchemaVersion: 1, MinCore: "0.0.0"},
		{Core: "0.60.0", SchemaVersion: 2, MinCore: "0.60.0", NoRollback: true},
	}}
}

func base() Migration { return Migrations()[0] }

func baseAt058() Migration { m := base(); m.Release = "0.58.0"; return m }

func contract(release string, shapes ...string) Migration {
	return Migration{Version: 2, Name: "drop-legacy", Kind: KindContract, Release: release, MinCore: release,
		Retires: shapes, DDL: `ALTER TABLE clearance_changes DROP COLUMN legacy;`}
}

func has(bad []string, sub string) bool {
	for _, b := range bad {
		if strings.Contains(b, sub) {
			return true
		}
	}
	return false
}

func TestAContractMigrationForAShapeTheLastReleaseStillUsesFailsCI(t *testing.T) {
	// Negative: nothing says clearance_changes.legacy is unused.
	bad := CheckMigrations([]Migration{baseAt058(), contract("0.60.0", "clearance_changes.legacy")}, rulesTable(), nil)
	if !has(bad, "no release has stopped using") {
		t.Fatalf("an unretired shape passed: %v", bad)
	}
	// Negative: the release before this one (0.59.0) still used it; it stopped only in 0.60.0, the migration's own release.
	bad = CheckMigrations([]Migration{baseAt058(), contract("0.60.0", "clearance_changes.legacy")}, rulesTable(),
		[]Unused{{Shape: "clearance_changes.legacy", Since: "0.60.0"}})
	if !has(bad, "still used") {
		t.Fatalf("a shape the previous release used passed: %v", bad)
	}
	// Positive: unused since 0.59.0, dropped in 0.60.0.
	bad = CheckMigrations([]Migration{baseAt058(), contract("0.60.0", "clearance_changes.legacy")}, rulesTable(),
		[]Unused{{Shape: "clearance_changes.legacy", Since: "0.59.0"}})
	if len(bad) > 0 {
		t.Fatalf("a sound contract migration failed: %v", bad)
	}
}

func TestAContractMigrationNeedsAPreviousReleaseWithTheGuard(t *testing.T) {
	rt := rulesTable()
	rt.Releases[1].SchemaVersion = 0 // 0.59.0, the release before 0.60.0, predates the guard
	bad := CheckMigrations([]Migration{baseAt058(), contract("0.60.0", "clearance_changes.legacy")}, rt,
		[]Unused{{Shape: "clearance_changes.legacy", Since: "0.59.0"}})
	if !has(bad, "has no version guard") {
		t.Fatalf("%v", bad)
	}
}

func TestAMigrationThatIsNeitherExpandNorContractFailsCI(t *testing.T) {
	for _, ddl := range []string{
		`UPDATE clearance_changes SET state = 'x';`,
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS i ON clearance_changes (state);`,
		`CREATE FUNCTION f() RETURNS int AS 'select 1' LANGUAGE sql;`,
		`INSERT INTO clearance_changes (id) VALUES ('x');`,
	} {
		m := Migration{Version: 2, Name: "odd", Kind: KindExpand, Release: "0.60.0", MinCore: "0.0.0", DDL: ddl}
		if bad := CheckMigrations([]Migration{baseAt058(), m}, rulesTable(), nil); !has(bad, "neither expand nor contract") {
			t.Errorf("%s: passed: %v", ddl, bad)
		}
	}
}

func TestAnExpandMigrationThatDropsFailsCI(t *testing.T) {
	m := Migration{Version: 2, Name: "sneaky", Kind: KindExpand, Release: "0.60.0", MinCore: "0.0.0",
		DDL: `ALTER TABLE clearance_changes DROP COLUMN legacy;`}
	if bad := CheckMigrations([]Migration{baseAt058(), m}, rulesTable(), nil); !has(bad, "declared expand but has a contract statement") {
		t.Fatalf("an expand that drops passed: %v", bad)
	}
}

func TestAContractMigrationMustRaiseMinCoreToItsOwnRelease(t *testing.T) {
	c := contract("0.60.0", "clearance_changes.legacy")
	c.MinCore = "0.0.0"
	bad := CheckMigrations([]Migration{baseAt058(), c}, rulesTable(), []Unused{{Shape: "clearance_changes.legacy", Since: "0.59.0"}})
	if !has(bad, "raises min_core to its own release") {
		t.Fatalf("a contract migration that kept min_core passed: %v", bad)
	}
}

func TestAnExpandMigrationMustNotRaiseMinCore(t *testing.T) {
	m := Migration{Version: 2, Name: "add", Kind: KindExpand, Release: "0.60.0", MinCore: "0.60.0",
		DDL: `ALTER TABLE clearance_changes ADD COLUMN IF NOT EXISTS note text;`}
	if bad := CheckMigrations([]Migration{baseAt058(), m}, rulesTable(), nil); !has(bad, "leaves min_core") {
		t.Fatalf("an expand that raised min_core passed: %v", bad)
	}
}

func TestANewNotNullColumnIsAContractChange(t *testing.T) {
	if got := ClassifyStatement(`ALTER TABLE t ADD COLUMN IF NOT EXISTS c text NOT NULL DEFAULT ''`); got != KindContract {
		t.Fatalf("NOT NULL column: %q", got)
	}
	if got := ClassifyStatement(`ALTER TABLE t ADD COLUMN IF NOT EXISTS c text`); got != KindExpand {
		t.Fatalf("nullable column: %q", got)
	}
	for _, st := range []string{`ALTER TABLE t ALTER COLUMN c TYPE bigint`, `ALTER TABLE t RENAME COLUMN a TO b`, `DROP TABLE t`, `ALTER TABLE t ALTER COLUMN c SET NOT NULL`} {
		if got := ClassifyStatement(st); got != KindContract {
			t.Errorf("%s: %q", st, got)
		}
	}
}

func TestTheTableMustSayWhatTheMigrationsDo(t *testing.T) {
	list := []Migration{baseAt058(), contract("0.60.0", "clearance_changes.legacy")}
	u := []Unused{{Shape: "clearance_changes.legacy", Since: "0.59.0"}}
	rt := rulesTable()
	rt.Releases[2].NoRollback = false
	if bad := CheckMigrations(list, rt, u); !has(bad, "no_rollback") {
		t.Fatalf("a contract release not marked no-rollback passed: %v", bad)
	}
	rt = rulesTable()
	rt.Releases[2].MinCore = "0.0.0"
	if bad := CheckMigrations(list, rt, u); !has(bad, "min_core") {
		t.Fatalf("a wrong min_core passed: %v", bad)
	}
	rt = rulesTable()
	rt.Releases[2].SchemaVersion = 1
	if bad := CheckMigrations(list, rt, u); !has(bad, "schema_version") {
		t.Fatalf("a wrong schema_version passed: %v", bad)
	}
	if bad := CheckMigrations(list, rulesTable(), u); len(bad) > 0 {
		t.Fatalf("the sound combination failed: %v", bad)
	}
}

func TestAReleasedMigrationMustBeInTheTable(t *testing.T) {
	m := baseAt058()
	m.Release = "0.99.0"
	if bad := CheckMigrations([]Migration{m}, rulesTable(), nil); !has(bad, "not in the compatibility table") {
		t.Fatalf("%v", bad)
	}
}

// An ALTER TABLE is classified by every action in it, so a drop cannot ride behind an add.
func TestAnAlterTableIsClassifiedByEveryAction(t *testing.T) {
	cases := map[string]string{
		`ALTER TABLE t ADD COLUMN a text, ADD COLUMN IF NOT EXISTS b jsonb`: KindExpand,
		`ALTER TABLE t ADD COLUMN a numeric(10,2)`:                          KindExpand,
		`ALTER TABLE t ADD COLUMN a text, DROP COLUMN b`:                    "",
		`ALTER TABLE t DROP COLUMN a, DROP COLUMN b`:                        KindContract,
		`ALTER TABLE t ADD COLUMN a text, ALTER COLUMN b TYPE bigint`:       "",
		`ALTER TABLE t ADD COLUMN a text NOT NULL DEFAULT ''`:               KindContract,
		`ALTER TABLE t ADD COLUMN a text UNIQUE`:                            KindContract,
		`ALTER TABLE t SET SCHEMA other`:                                    "",
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS i ON t (a)`:                "",
		`CREATE UNIQUE INDEX IF NOT EXISTS i ON t (a)`:                      KindExpand,
		`TRUNCATE clearance_evidence`:                                       KindContract,
	}
	for st, want := range cases {
		if got := ClassifyStatement(st); got != want {
			t.Errorf("%s: %q, want %q", st, got, want)
		}
	}
	m := Migration{Version: 2, Name: "sneaky", Kind: KindExpand, Release: "0.60.0", MinCore: "0.0.0",
		DDL: `ALTER TABLE clearance_changes ADD COLUMN note text, DROP COLUMN head;`}
	if bad := CheckMigrations([]Migration{baseAt058(), m}, rulesTable(), nil); !has(bad, "neither expand nor contract") {
		t.Fatalf("an add that carries a drop passed: %v", bad)
	}
}

// The declared Retires must cover what the DDL changes.
func TestRetiresMustCoverWhatTheDDLChanges(t *testing.T) {
	u := []Unused{{Shape: "clearance_changes.legacy", Since: "0.59.0"}}
	c := contract("0.60.0", "clearance_changes.legacy")
	c.DDL = `DROP TABLE clearance_evidence;`
	if bad := CheckMigrations([]Migration{baseAt058(), c}, rulesTable(), u); !has(bad, "changes clearance_evidence, which its Retires does not name") {
		t.Fatalf("a drop of another table passed: %v", bad)
	}
	c.DDL = `ALTER TABLE clearance_changes DROP COLUMN legacy, DROP COLUMN head;`
	if bad := CheckMigrations([]Migration{baseAt058(), c}, rulesTable(), u); !has(bad, "clearance_changes.head") {
		t.Fatalf("a second dropped column passed: %v", bad)
	}
	// A retired table covers its columns.
	c = contract("0.60.0", "clearance_old")
	c.DDL = `DROP TABLE clearance_old;`
	if bad := CheckMigrations([]Migration{baseAt058(), c}, rulesTable(), []Unused{{Shape: "clearance_old", Since: "0.59.0"}}); len(bad) > 0 {
		t.Fatalf("%v", bad)
	}
}
