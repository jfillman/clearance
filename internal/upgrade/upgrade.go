// Package upgrade is `clearance upgrade check` (N-6d): from the running core's version, schema and the target release's
// notes and compatibility table, what the upgrade changes and what must go first. Doctor (N-3) is not built yet; when it
// is, the command runs it and folds its findings in. The data it needs (the schema version and min_core, the table) is
// served at GET /v1/version.
package upgrade

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jfillman/clearance/internal/compat"
	"github.com/jfillman/clearance/internal/store"
)

// Input is what a check reads.
type Input struct {
	// Current is GET /v1/version's answer of the running core: its release and, on Postgres, its schema.
	CurrentCore string
	Schema      *store.SchemaInfo
	// Target is the release to upgrade to, its compatibility table (the release's compat.json) and its notes.
	Target string
	Table  compat.Table
	Notes  string
	// Providers are the versions of the providers running now, program to version.
	Providers map[string]string
}

// Report is the result: Blockers stop the upgrade as planned, Before are what must go first, Changes what the upgrade
// does, Notes the target's own words on it.
type Report struct {
	Blockers []string
	Before   []string
	Changes  []string
	Notes    []string
	// NoRollback is true when the target, or a release between, carries a contract migration.
	NoRollback bool
}

var noteRx = regexp.MustCompile(`(?i)no-rollback|migration|upgrade|before you|must |breaking|requires`)

// Check works out the upgrade.
func Check(in Input) Report {
	var r Report
	target, ok := in.Table.Exact(in.Target)
	if !ok {
		target, ok = in.Table.Row(in.Target)
	}
	if !ok {
		r.Blockers = append(r.Blockers, fmt.Sprintf("the compatibility table has no row for %s or any release before it", in.Target))
		return r
	}
	if lt, known := compat.Less(in.Target, in.CurrentCore); known && lt {
		r.Blockers = append(r.Blockers, fmt.Sprintf("%s is older than the running core %s: that is a rollback, not an upgrade (see the rollback rules in docs/upgrade.md)", in.Target, in.CurrentCore))
	}
	if in.CurrentCore == in.Target {
		r.Changes = append(r.Changes, fmt.Sprintf("the core is already %s", in.Target))
	}

	// The schema.
	cur := 0
	curMin := "0.0.0"
	if in.Schema != nil {
		cur, curMin = in.Schema.Version, in.Schema.MinCore
	} else {
		r.Changes = append(r.Changes, "the running core keeps no versioned schema (in-memory store, or a core before N-6): the schema is not compared")
	}
	switch {
	case in.Schema != nil && target.SchemaVersion > cur:
		r.Changes = append(r.Changes, fmt.Sprintf("schema %d -> %d: the new core applies migrations %d to %d at start, each in one transaction under the writer lock",
			cur, target.SchemaVersion, cur+1, target.SchemaVersion))
	case in.Schema != nil && target.SchemaVersion == cur:
		r.Changes = append(r.Changes, fmt.Sprintf("schema stays at %d: no migration runs", cur))
	case in.Schema != nil && target.SchemaVersion < cur:
		r.Blockers = append(r.Blockers, fmt.Sprintf("the database is at schema %d and %s ships %d: the target is older than the data", cur, in.Target, target.SchemaVersion))
	}
	if lt, ok := compat.Less(in.Target, curMin); ok && lt {
		r.Blockers = append(r.Blockers, fmt.Sprintf("the database schema needs a core of at least %s; %s would refuse to start (code schema_requires_newer_core)", curMin, in.Target))
	}

	// No-rollback: the target, or any release between the running core and it.
	var nr []string
	for _, rel := range in.Table.Releases {
		afterCurrent, known := compat.Less(in.CurrentCore, rel.Core)
		if !known {
			afterCurrent = true // an unknown running version: count every release up to the target
		}
		upToTarget, _ := compat.Less(rel.Core, in.Target)
		if rel.NoRollback && afterCurrent && (upToTarget || rel.Core == in.Target) {
			nr = append(nr, rel.Core)
		}
	}
	if len(nr) > 0 {
		r.NoRollback = true
		r.Before = append(r.Before, fmt.Sprintf("NO ROLLBACK: %s carries a contract migration, so a core older than %s refuses the schema afterwards; take a backup first "+
			"(the restore from it is the only way back, and what was written after it is lost from the database and kept in the witnessed ledger)",
			strings.Join(nr, ", "), nr[0]))
	} else {
		r.Changes = append(r.Changes, "rollback stays open: the schema changes are expand-only, so the previous core runs on the upgraded schema")
	}

	// Providers: one the target's core refuses must be upgraded first.
	progs := make([]string, 0, len(in.Providers))
	for p := range in.Providers {
		progs = append(progs, p)
	}
	sort.Strings(progs)
	for _, p := range progs {
		v := in.Providers[p]
		if ok, why := (compat.Table{Releases: []compat.Release{target}}).Accepts(target.Core, p, v); !ok {
			r.Before = append(r.Before, fmt.Sprintf("provider %s: %s: upgrade it first, to a version both the running core and %s accept", p, why, in.Target))
		}
	}
	if len(in.Providers) == 0 {
		r.Changes = append(r.Changes, "no provider versions were given (--provider program=version): provider skew is not checked")
	}

	for _, line := range strings.Split(in.Notes, "\n") {
		if l := strings.TrimSpace(line); strings.HasPrefix(l, "-") && noteRx.MatchString(l) {
			r.Notes = append(r.Notes, l)
		}
	}
	return r
}
