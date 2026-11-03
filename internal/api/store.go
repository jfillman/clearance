package api

import (
	"context"
	"encoding/json"

	"github.com/jfillman/clearance/internal/store"
)

// Record is a stored evidence record as read, with "assurance" added beside it (before evidence.Project).
type Record = map[string]any

// Outcome selectors (the `outcomes` query parameter). The Go core writes two records for every allowed call it
// decides: the decision, then the outcome the provider reports (`outcome_of`: the decision's seq and hash), which
// copies the decision's tool, agent, rule and app. Counting both counts every call twice.
const (
	OutcomesInclude = "include" // every record (the list's default)
	OutcomesExclude = "exclude" // records that are not an outcome: one per decision or event (the counts' default)
	OutcomesOnly    = "only"    // outcome records only
)

// EvidenceFilter is the evidence list's and counts' filters; "" is unset.
type EvidenceFilter struct {
	Task, Session, Agent, Tool, Principal, Decision, Rule, App string
	Since, Until                                               string // compared with the record's ts as text, as api.py does
	Outcomes                                                   string // OutcomesInclude (""), OutcomesExclude, OutcomesOnly
}

// ChangeFilter is the deployment gate's list and counts filters; "" and nil are unset.
type ChangeFilter struct {
	App, Env, State, Repo, Since string
	PR, Tier                     *int64
}

// Count is one group of a counts answer: its key (null when the field is absent) and how many.
type Count struct {
	Key   *string `json:"key"`
	Count int64   `json:"count"`
}

// Verified is GET /v1/evidence/verify's answer (api.py verify_chain).
type Verified struct {
	OK     bool   `json:"ok"`
	Count  int64  `json:"count"`
	Head   string `json:"head"`
	BadSeq *int64 `json:"bad_seq"`
}

// Store is what clearance-api reads. Every list is scoped by the viewer in the store (in SQL for Postgres), so a
// person never sees another team's records through a filter.
type Store interface {
	// Evidence is up to limit records the viewer may see matching f, newest first, below seq after (when not nil).
	Evidence(ctx context.Context, f EvidenceFilter, v *Viewer, limit int, after *int64) ([]Record, error)
	// EvidenceOne is one record the viewer may see, or nil.
	EvidenceOne(ctx context.Context, seq int64, v *Viewer) (Record, error)
	// Counts is the records the viewer may see matching f, grouped by the record field by (one of CountBy), the
	// largest first, at most MaxLimit groups.
	Counts(ctx context.Context, f EvidenceFilter, v *Viewer, by string) ([]Count, error)
	// ByPR is the records of one of tools that the viewer may see, whose effect names repo (and pr when not "") or
	// whose target is repo#pr (repo#anything without pr), newest first, at most MaxLimit.
	ByPR(ctx context.Context, tools []string, repo, pr string, v *Viewer) ([]Record, error)
	// Verify checks the whole chain from genesis.
	Verify(ctx context.Context) (Verified, error)
	// Changes is up to limit of the gate's changes the viewer may see, by updated_at newest first, below after.
	Changes(ctx context.Context, f ChangeFilter, v *Viewer, limit int, after string) ([]json.RawMessage, error)
	// Change is one change's stored record (nil when there is none); the caller checks visibility.
	Change(ctx context.Context, id string) (json.RawMessage, error)
	// ChangeCounts is the changes the viewer may see matching f, grouped by one of ChangeCountBy.
	ChangeCounts(ctx context.Context, f ChangeFilter, v *Viewer, by string) ([]Count, error)
	// Definitions are the cluster-pinned definitions the core stored (clearance_definitions).
	Definitions(ctx context.Context) ([]store.Definition, error)
	// Ping answers when the database does.
	Ping(ctx context.Context) error
}
