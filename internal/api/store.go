package api

import (
	"context"
	"encoding/json"
	"time"

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
	// Installation keeps the records of one GitHub App installation (principal app:<id>).
	Installation string
	Since, Until string // compared with the record's ts as text, as api.py does
	Outcomes     string // OutcomesInclude (""), OutcomesExclude, OutcomesOnly
	// Exceptions keeps only the records the packet's exceptions section lists (GET /v1/exceptions): the tools of
	// ExceptionTools, and any record whose coverage is coverage-unavailable. Kind narrows a deploy.exception to
	// its exception.kind.
	Exceptions bool
	Kind       string
}

// ChangeFilter is the deployment gate's list and counts filters; "" and nil are unset.
type ChangeFilter struct {
	App, Env, State, Repo, Since string
	PR, Tier                     *int64
	Cluster                      string
	// LiveAt, when set, keeps only the changes whose token is live at that moment (not revoked, not expired): the
	// grant feed (cluster and state=cleared).
	LiveAt *time.Time
}

// Count is one group of a counts answer: its key (null when the field is absent) and how many.
type Count struct {
	Key   *string `json:"key"`
	Count int64   `json:"count"`
	// Cost is the group's cost (counts by=cost only); count is then its model calls.
	Cost *CostSum `json:"cost,omitempty"`
}

// CostSum is what a group of records cost (AP-C2): the model-call outcomes' usage summed (charged_tokens is what
// the gateway's model proxy charged the sessions' model_tokens budgets, the provider's four kinds of token beside
// it) and the run.finish records' runs and wall-clock seconds (compute).
type CostSum struct {
	ChargedTokens            int64 `json:"charged_tokens"`
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	ModelCalls               int64 `json:"model_calls"`
	Runs                     int64 `json:"runs"`
	WallSeconds              int64 `json:"wall_seconds"`
}

func (c *CostSum) add(o *CostSum) {
	c.ChargedTokens += o.ChargedTokens
	c.InputTokens += o.InputTokens
	c.OutputTokens += o.OutputTokens
	c.CacheCreationInputTokens += o.CacheCreationInputTokens
	c.CacheReadInputTokens += o.CacheReadInputTokens
	c.ModelCalls += o.ModelCalls
	c.Runs += o.Runs
	c.WallSeconds += o.WallSeconds
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
	// Costs is the cost of the records the viewer may see matching f (f.Outcomes is ignored: the model.call outcome
	// records that carry usage and the run.finish records that carry cost), grouped by the record field of per (one
	// of CostPer), the most charged first, at most MaxLimit groups, and the sums over every matching group (not the
	// page). Each group's count is its model calls.
	Costs(ctx context.Context, f EvidenceFilter, v *Viewer, per string) ([]Count, CostSum, error)
	// ByPR is the records of one of tools that the viewer may see, whose effect names repo (and pr when not "") or
	// whose target is repo#pr (repo#anything without pr), newest first, at most MaxLimit. f.Installation, when set,
	// keeps the records of that App installation (Verdicts: recorded by app:<id>) or (receipts) the records on a
	// pull request that installation checked (a provenance.verify by app:<id> targets it).
	ByPR(ctx context.Context, tools []string, f PRFilter, v *Viewer) ([]Record, error)
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
	// Tokens are the live tokens (not revoked, not expired at now) of the changes ids, by change id.
	Tokens(ctx context.Context, ids []string, now time.Time) (map[string]store.Token, error)
	// Attestation is the change's signed attestation (C-2), nil when it has none.
	Attestation(ctx context.Context, changeID string) (*store.Attestation, error)
	// SigningKeys are the token verification keys in use or retired after since (clearance_signing_keys).
	SigningKeys(ctx context.Context, since time.Time) ([]store.SigningKey, error)
	// Ping answers when the database does.
	Ping(ctx context.Context) error

	// Head is the chain's last seq (-1 when empty): the stream's high-water mark.
	Head(ctx context.Context) (int64, error)
	// EvidenceAfter is up to limit records the viewer may see matching f, with seq above after, oldest first.
	EvidenceAfter(ctx context.Context, f EvidenceFilter, v *Viewer, after int64, limit int) ([]Record, error)
	// DeploysAfter is up to limit of the gate's deploy.* records with seq above after, oldest first, each with the
	// change it names as stored now (unscoped: the caller checks visibility).
	DeploysAfter(ctx context.Context, after int64, limit int) ([]DeployEvent, error)
	// Feed is the cluster's signed grant feed (nil when the core has signed none).
	Feed(ctx context.Context, cluster string) (*store.Feed, error)
	// Installations are the GitHub App installations the records name (principal app:<id>), at most MaxLimit.
	Installations(ctx context.Context) ([]Installation, error)
}

// PRFilter is the receipts' and verdicts' filters.
type PRFilter struct {
	Repo, PR     string
	Installation string
	// ByInstaller: Installation keeps the records the installation wrote (verdicts), not the records on the pull
	// requests it checked (receipts).
	ByInstaller bool
}

// DeployEvent is one deploy.* record as the stream sends it: its seq, tool and ts, the change summary it recorded
// (the change's state at that record), and the change as stored now (nil when the row is gone).
type DeployEvent struct {
	Seq     int64
	Tool    string
	TS      string
	Summary json.RawMessage
	Change  json.RawMessage
}

// Installation is one GitHub App installation as the records show it (GET /v1/github/installations).
type Installation struct {
	// ID is the installation id; the records name it as Principal, app:<id>.
	ID        string `json:"id"`
	Principal string `json:"principal"`
	// Account is the GitHub account (organization or user) of its last app.installation record; null when the
	// chain has none (the App was installed before Clearance recorded installations).
	Account *string `json:"account"`
	// Action is that record's action (created, deleted, suspend, unsuspend, new_permissions_accepted, added,
	// removed), and Status what it leaves: active, suspended or removed.
	Action *string `json:"action"`
	Status string  `json:"status"`
	// FirstSeq/LastSeq and FirstTS/LastTS bound the installation's records; Records counts them by tool
	// (provenance.verify, deploy.request, app.installation, ...).
	FirstSeq int64            `json:"first_seq"`
	LastSeq  int64            `json:"last_seq"`
	FirstTS  string           `json:"first_ts"`
	LastTS   string           `json:"last_ts"`
	Records  map[string]int64 `json:"records"`
	// Repos are the repositories its checks ran on (provenance.verify targets), by name, at most MaxLimit.
	Repos []string `json:"repos"`
}
