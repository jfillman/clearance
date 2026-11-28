package upgrade

import (
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/compat"
	"github.com/jfillman/clearance/internal/store"
)

func table() compat.Table {
	return compat.Table{Format: 1, Releases: []compat.Release{
		{Core: "0.57.3", SchemaVersion: 0, MinCore: "0.0.0"},
		{Core: "0.58.0", SchemaVersion: 1, MinCore: "0.0.0", Providers: map[string]compat.Range{"argocd-agent": {Min: "0.57.0"}}},
		{Core: "0.60.0", SchemaVersion: 2, MinCore: "0.60.0", NoRollback: true, Providers: map[string]compat.Range{"argocd-agent": {Min: "0.59.0"}}},
	}}
}

func has(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func TestAnExpandOnlyUpgradeKeepsRollbackOpen(t *testing.T) {
	r := Check(Input{CurrentCore: "0.57.3", Target: "0.58.0", Table: table(), Schema: &store.SchemaInfo{Version: 0, MinCore: "0.0.0"}})
	if len(r.Blockers) > 0 || r.NoRollback || !has(r.Changes, "schema 0 -> 1") || !has(r.Changes, "rollback stays open") {
		t.Fatalf("%+v", r)
	}
}

func TestANoRollbackReleaseSaysSoAndNamesTheBackup(t *testing.T) {
	r := Check(Input{CurrentCore: "0.58.0", Target: "0.60.0", Table: table(), Schema: &store.SchemaInfo{Version: 1, MinCore: "0.0.0"},
		Providers: map[string]string{"argocd-agent": "0.58.0"}})
	if !r.NoRollback || !has(r.Before, "NO ROLLBACK: 0.60.0") || !has(r.Before, "backup") {
		t.Fatalf("%+v", r)
	}
	// A provider the target's core refuses goes first.
	if !has(r.Before, "provider argocd-agent: argocd-agent 0.58.0 is older than 0.59.0") {
		t.Fatalf("%+v", r.Before)
	}
}

func TestAnUpgradeToAnOlderReleaseOrOlderSchemaIsBlocked(t *testing.T) {
	r := Check(Input{CurrentCore: "0.60.0", Target: "0.58.0", Table: table(), Schema: &store.SchemaInfo{Version: 2, MinCore: "0.60.0"}})
	if !has(r.Blockers, "older than the running core") || !has(r.Blockers, "schema needs a core of at least 0.60.0") || !has(r.Blockers, "older than the data") {
		t.Fatalf("%+v", r.Blockers)
	}
}
