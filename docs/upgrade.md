# Upgrading, rolling back and version skew

Clearance upgrades are meant to be boring: the schema is versioned, a core that cannot run on a schema refuses to start
with a named code, and every release says whether you can go back. This page is the rules and the commands (work package
N-6). Status: **Built** (the migrations, the guard, the table, `upgrade check`, the CI rules and the upgrade test);
**Unverified live** (adopting migration 1 on a long-lived database, below); `clearance doctor` (N-3) and `clearance restore
verify` (N-11) are **Proposal**.

## The schema

`clearance_schema` has one row per applied migration: `version`, `name`, `kind` (`expand` or `contract`), `release`,
`min_core`, a checksum of the migration's DDL, the core that applied it and when. The core applies the migrations it carries
that the database lacks, in order, **at start, under the writer lock, each in one transaction** with its row: a failed
migration leaves nothing behind. Migrations are forward only. A released migration is never edited (a core refuses a
database whose recorded checksum differs, code `schema_migration_changed`); the next change is the next migration.

**Migration 1 is the idempotent DDL every earlier core ran at start.** A database built by one of them already has every
object it creates, so it is **adopted**: the row is recorded (`adopted = true`) and no DDL runs, apart from creating
`clearance_schema` itself. A database missing something (an old one) is not adopted: migration 1 runs, and the idempotent
statements add what is missing. The Map's indexes are built in the background after start, as before; they are not
migrations.

`GET /v1/version` (and, for tools, `pg.Reader.SchemaInfo`) serves the schema's `version`, its `min_core` (the highest of any
applied migration), `no_rollback`, and the list of migrations. Doctor (N-3) will read the same data.

## The version guard

Each migration records `min_core`, the oldest core that can run on the schema after it. A core refuses to start only when it
is **older than the schema's `min_core`**:

```
schema_requires_newer_core: this core is 0.58.0 and the database schema needs a core of at least 0.60.0 (migration 2, drop-x, release 0.60.0); upgrade the core, or restore the pre-upgrade backup
```

It **accepts a newer schema whose `min_core` it meets**, which is what makes a rollback across expand migrations work. A core
whose own version is not `X.Y.Z` (a development build) is not guarded and logs that. `clearance-api` reads with
`pg.OpenReader` and applies the same check when given its version. Cores before N-6 have no guard: the first release that
carries it is the first that can refuse, so the first contract migration waits until a release after it (CI enforces this).

## Expand, then contract

- **Expand** migrations are new tables, nullable columns and new indexes. They leave `min_core` unchanged, so the previous
  core runs on the expanded schema and **rollback is open**.
- **Contract** migrations are a drop, a rename, a type change or a new NOT NULL. Each may only retire a shape that a release
  at least one version earlier already **stopped using** (the code no longer reads or writes it): the shape is listed in
  `unused` (`internal/store/pg/migrate.go`) with the release that stopped. A contract migration raises `min_core` to its own
  release, so an older core refuses, and its release is marked **no-rollback** in its notes, in `upgrade check` and in the
  compatibility table. A contract migration stands alone (no expand statements in it).

CI fails a list that breaks these (`TestShippedMigrationsObeyTheRules`, and `releasenotes -check-tag` at the tag): a contract
migration for a shape still used by the previous release, a migration that is neither expand nor contract (a data change, a
function, a concurrent index build), an expand migration that raises `min_core`, a contract migration that does not raise it
to its own release, a compatibility-table row that disagrees with the migrations, a contract migration whose previous release
has no guard. The notes of a contract release must say **no-rollback** and name the migration.

## No-rollback releases and the way back

Rollback past a no-rollback release is a **restore of the pre-upgrade backup**, never a downgrade. Take the backup first
(the PostgreSQL chain, the keys and the witness's state). Records written after the backup are lost from the database and
kept in the witnessed ledger; recording that gap as an exception is `clearance restore verify` (N-11, not built yet). Until
then, after a restore, run `clearance chain verify` and compare the head with the last witnessed checkpoint by hand.

## Compatibility as data

`internal/compat/compat.json` is a table, a release asset of every release (`compat.json`) and part of `GET /v1/version`: per
release, its `schema_version`, `min_core`, `no_rollback`, and per provider program the accepted range (`min` inclusive,
`max` exclusive). A core follows the newest row at or below its own version. Providers send `Clearance-Provider:
<program>/<version>`; a version outside the core's range is refused `412`, code `provider_version_unsupported`
([provider protocol](provider-protocol.md#version-skew-n-6c)). **Upgrade a provider that the new core would refuse before the
core**, to a version both accept. Doctor (N-3) will report the skew across the fleet.

## `clearance upgrade check`

```
clearance upgrade check --to v0.60.0 --url https://clearance.example.com --token-file /path/to/token \
  --provider argocd-agent=0.58.0
```

It reads the target's `compat.json` and release notes and the running core's `GET /v1/version`, and lists: the schema change
(`schema 1 -> 2`, which migrations run), whether any release up to the target is no-rollback (and that you need a backup
first), the providers to upgrade first, and the notes' lines about migrations and upgrade steps. Exit 1 when it is blocked.
It does not run doctor (not built); a line says so. See [the CLI](cli.md#clearance-upgrade-check).

## The whole-install upgrade test

`.github/workflows/upgrade.yaml` (`tools/upgrade-test/run.sh`) runs on every change to the store, the table or the chart, and
as a **release gate**: no image is built until it passes. On a fresh kind cluster with a plain Postgres it installs the
previous release's chart and image, runs traffic (`tools/installtest`) and verifies the chain, takes a backup, upgrades to the
candidate (its migrations run), runs traffic and verifies again; then, for an **expand-only** release, rolls back to the
previous core on the upgraded schema, writes and verifies; for a **no-rollback** release, checks the previous core refuses
with `schema_requires_newer_core`, restores the backup, starts the previous core, runs traffic and verifies. Not covered yet:
that the restore's gap is recorded as an exception (N-11). The store-level version of the same sequence, with injected
migrations, is `TestUpgradeAndRollBackAcrossExpandMigrations` and
`TestANoRollbackUpgradeIsRefusedByThePreviousCoreAndRestoresFromBackup` in `internal/store/pg`; the adoption of a v0.57.3
database with no DDL change is `TestADatabaseFromV0573AdoptsMigrationOneWithNoDDLChange` (a catalog snapshot before and
after).

## Adding a migration

1. Append to `migrations` in `internal/store/pg/migrate.go`: the next version, a name, `Kind`, `Release` (the release that
   ships it), `MinCore` (unchanged for expand; `Release` for contract, with `Retires`) and the DDL.
2. Add the release's row to `internal/compat/compat.json` (`schema_version`, `min_core`, `no_rollback`, provider ranges).
3. For a contract migration, make sure the shape is in `unused` with the release that stopped using it, a release before.
4. `go test ./internal/store/pg` runs the rules; a contract release's CHANGELOG section says no-rollback and names the
   migration.
