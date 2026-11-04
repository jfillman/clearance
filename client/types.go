package client

import (
	"encoding/json"
	"time"
)

// The wire types mirror the core's Go types field for field (json name, omitempty, shape); types_test.go walks
// both by reflection and fails on any difference, so they cannot drift from the server. They are declared here
// rather than aliased so a caller links no policy engine or store code. Two deliberate narrowings:
//
//   - the core's exact-at-any-size integers (decide.Int) are int64 here: a caller that holds its budgets in int64
//     sends nothing larger, and a larger value in an answer fails strict decoding (fail closed);
//   - the gate's Python-isoformat timestamps (gate.PyTime) are strings, passed through as the core wrote them.

// Action names (EvaluationRequest.Action.Name).
const (
	ActionToolCall     = "tool.call"
	ActionModelCall    = "model.call"
	ActionSessionOpen  = "session.open"
	ActionSessionSpawn = "session.spawn"
)

// Resource types (EvaluationRequest.Resource.Type).
const (
	ResourceTool  = "tool"
	ResourceModel = "model"
	ResourceAgent = "agent"
)

// RecordKinds are the kinds POST /v1/records takes (server.RecordKinds).
var RecordKinds = []string{"session.open", "run.launch", "run.delete", "run.finish", "human.answer",
	"session.freeze", "session.end", "trigger.hold", "trigger.release", "tool.call", "deploy.outcome",
	"deploy.exception", "deploy.degraded", "federated.decision"}

// CoverageUnavailable is a tool.call record's coverage: a T0 read the provider allowed while the core was
// unreachable (the outage policy), posted once it answers.
const CoverageUnavailable = "coverage-unavailable"

// -- POST /access/v1/evaluation ------------------------------------------------------------------------------------

// EvaluationRequest is an AuthZEN 1.0 Access Evaluation (decide.EvaluationRequest; internal/decide's package doc
// describes every field).
type EvaluationRequest struct {
	Subject  Subject  `json:"subject"`
	Action   Action   `json:"action"`
	Resource Resource `json:"resource"`
	Context  Context  `json:"context"`
}

// Subject is the authenticated caller.
type Subject struct {
	Type       string            `json:"type"`
	ID         string            `json:"id"`
	Properties SubjectProperties `json:"properties"`
}

// SubjectProperties are what the caller's authenticator vouches for.
type SubjectProperties struct {
	Kind        string `json:"kind"`
	TierCeiling int    `json:"tier_ceiling"`
	ActingAs    string `json:"acting_as,omitempty"`
}

// Action is what the caller asks to do.
type Action struct {
	Name       string           `json:"name"`
	Properties ActionProperties `json:"properties"`
}

// ActionProperties are the action's arguments.
type ActionProperties struct {
	Args      json.RawMessage `json:"args,omitempty"`
	EstTokens *int64          `json:"est_tokens,omitempty"`
	Limits    json.RawMessage `json:"limits,omitempty"`
	TaskID    string          `json:"task_id,omitempty"`
	Trigger   string          `json:"trigger,omitempty"`
	// Run marks a session.open for a person's run (no limits, no trigger); Via names the delegate they acted
	// through, recorded as "opened to run via <delegate>".
	Run bool   `json:"run,omitempty"`
	Via string `json:"via,omitempty"`
}

// Resource is what the action is on.
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Context is the state the decision reads; the caller holds it.
type Context struct {
	Now          time.Time     `json:"now"`
	SessionID    string        `json:"session_id,omitempty"`
	Session      *SessionState `json:"session,omitempty"`
	Scope        *Scope        `json:"scope,omitempty"`
	Agent        *AgentDef     `json:"agent,omitempty"`
	NewSessionID string        `json:"new_session_id,omitempty"`
	Hold         *Hold         `json:"hold,omitempty"`
	Live         *SessionState `json:"live,omitempty"`
	Models       *Models       `json:"models,omitempty"`
}

// SessionState is a session as the caller holds it.
type SessionState struct {
	ID        string    `json:"id"`
	Principal string    `json:"principal"`
	Agent     string    `json:"agent"`
	TaskID    string    `json:"task_id"`
	ParentID  *string   `json:"parent_id"`
	Depth     int       `json:"depth"`
	Limits    Limits    `json:"limits"`
	Used      Budgets   `json:"used"`
	Reserved  Budgets   `json:"reserved"`
	ExpiresAt time.Time `json:"expires_at"`
	Closed    bool      `json:"closed"`
	Tripped   bool      `json:"tripped"`
	Denials   int       `json:"denials"`
}

// Limits is a session's limits (limits.Limits.as_dict's shape).
type Limits struct {
	TierCeiling string   `json:"tier_ceiling"`
	TTLMinutes  int64    `json:"ttl_minutes"`
	ToolCalls   int64    `json:"tool_calls"`
	GithubCalls int64    `json:"github_calls"`
	OpenPRs     int64    `json:"open_prs"`
	ModelTokens int64    `json:"model_tokens"`
	Children    int64    `json:"children"`
	Tools       []string `json:"tools"`
	Models      []string `json:"models"`
	Network     string   `json:"network"`
	Compute     string   `json:"compute"`
}

// Budgets are the five budget counters.
type Budgets struct {
	ToolCalls   int64 `json:"tool_calls"`
	GithubCalls int64 `json:"github_calls"`
	OpenPRs     int64 `json:"open_prs"`
	ModelTokens int64 `json:"model_tokens"`
	Children    int64 `json:"children"`
}

// Scope is what a session's definition allows beyond its limits.
type Scope struct {
	AgentKind  string          `json:"agent_kind"`
	DenyPaths  []string        `json:"deny_paths"`
	ReposAllow []string        `json:"repos_allow"`
	APIAllow   []string        `json:"api_allow"`
	FieldDeny  []string        `json:"field_deny"`
	FieldAllow []string        `json:"field_allow"`
	Profile    json.RawMessage `json:"profile,omitempty"`
}

// AgentDef is the part of an agent definition a session.open or session.spawn reads.
type AgentDef struct {
	Name           string  `json:"name"`
	Kind           string  `json:"kind"`
	IdentityType   string  `json:"identity_type"`
	ServiceAccount *string `json:"service_account"`
	Limits         Limits  `json:"limits"`
}

// Hold is an active hold on an agent's triggers.
type Hold struct {
	By     string    `json:"by"`
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
}

// Models is the deployment's model routing.
type Models struct {
	Routes []string `json:"routes"`
}

// EvaluationResult is the evaluation's answer. Decision false is a deny, not an error. DecisionID is nil when the
// core did not record the decision (then no outcome is taken).
type EvaluationResult struct {
	Decision   bool            `json:"decision"`
	Context    DecisionContext `json:"context"`
	DecisionID *string         `json:"decision_id"`
	Record     *RecordRef      `json:"record,omitempty"`
}

// DecisionContext explains the decision and carries the spend the caller must apply.
type DecisionContext struct {
	Rule     string    `json:"rule,omitempty"`
	Name     string    `json:"name,omitempty"`
	Message  string    `json:"message"`
	Hint     string    `json:"hint,omitempty"`
	Tier     *int      `json:"tier"`
	Problems []Problem `json:"problems,omitempty"`
	Spend    Spend     `json:"spend"`
	Grant    *Grant    `json:"grant,omitempty"`
	Policy   PolicyRef `json:"policy"`
}

// Problem is one structured problem behind a decision.
type Problem struct {
	Pointer string `json:"pointer"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

// Spend is what the caller applies to the request's session when it acts on the decision.
type Spend struct {
	ToolCalls   int64    `json:"tool_calls,omitempty"`
	GithubCalls int64    `json:"github_calls,omitempty"`
	OpenPRs     int64    `json:"open_prs,omitempty"`
	Children    int64    `json:"children,omitempty"`
	Reserve     *Budgets `json:"reserve,omitempty"`
	Denial      bool     `json:"denial,omitempty"`
	Trip        string   `json:"trip,omitempty"`
	TripTree    string   `json:"trip_tree,omitempty"`
}

// Grant is the session an allowed session.open or session.spawn creates.
type Grant struct {
	Session   string    `json:"session"`
	TaskID    string    `json:"task_id"`
	Principal string    `json:"principal"`
	Agent     string    `json:"agent"`
	Parent    *string   `json:"parent"`
	Depth     int       `json:"depth"`
	Limits    Limits    `json:"limits"`
	ExpiresAt time.Time `json:"expires_at"`
	Deduped   bool      `json:"deduped,omitempty"`
}

// PolicyRef names the policy that decided: the core and bundle names, the digest over all of it, and each loaded
// policy bundle with its own version.
type PolicyRef struct {
	Bundle  string      `json:"bundle"`
	Version string      `json:"version"`
	Bundles []BundleRef `json:"bundles,omitempty"`
}

// BundleRef is one loaded policy bundle: its declared version, the digest of what was loaded, and the source
// documents it read.
type BundleRef struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Digest  string      `json:"digest"`
	Sources []SourceRef `json:"sources,omitempty"`
	// Status is "loaded", or "unavailable" while a source could not be read (Unavailable names which and why).
	Status      string          `json:"status"`
	Unavailable []SourceFailure `json:"unavailable,omitempty"`
}

// SourceFailure is a source a degraded bundle could not read.
type SourceFailure struct {
	Name  string `json:"name"`
	Error string `json:"error"`
}

// SourceRef is a source document a bundle read at load.
type SourceRef struct {
	Name    string `json:"name"`
	Version int64  `json:"version"`
	Digest  string `json:"digest"`
}

// RecordRef names a stored evidence record.
type RecordRef struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

// -- POST /v1/decisions/{id}/outcome -------------------------------------------------------------------------------

// OutcomeRequest is what the caller saw when it acted on an allowed decision.
type OutcomeRequest struct {
	Result  string         `json:"result"`
	Effect  *Effect        `json:"effect,omitempty"`
	Receipt map[string]any `json:"receipt,omitempty"`
	// Refusal is a refusal the caller's handler made after the core allowed the call.
	Refusal *Refusal `json:"refusal,omitempty"`
}

// Refusal is a handler's refusal: its rule id and message.
type Refusal struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// Effect is a write's receipt (a pull request's repo, pr, commit, branch and paths).
type Effect struct {
	Repo   string   `json:"repo,omitempty"`
	PR     int64    `json:"pr,omitempty"`
	Commit string   `json:"commit,omitempty"`
	Branch string   `json:"branch,omitempty"`
	Paths  []string `json:"paths,omitempty"`
}

// -- POST /v1/records ----------------------------------------------------------------------------------------------

// RecordRequest is a provider's own record. Provider empty is Options.Provider.
type RecordRequest struct {
	Provider string        `json:"provider"`
	Kind     string        `json:"kind"`
	Record   ProviderEvent `json:"record"`
}

// ProviderEvent is the fields a provider may report; every one is claimed.
type ProviderEvent struct {
	TaskID      *string        `json:"task_id,omitempty"`
	Session     *string        `json:"session,omitempty"`
	Parent      *string        `json:"parent,omitempty"`
	Principal   *string        `json:"principal,omitempty"`
	Agent       *string        `json:"agent,omitempty"`
	Tool        *string        `json:"tool,omitempty"` // tool.call records only: the tool that was called
	Target      *string        `json:"target,omitempty"`
	App         *string        `json:"app,omitempty"`
	Decision    *string        `json:"decision,omitempty"`
	Rule        *string        `json:"rule,omitempty"`
	Tier        *int           `json:"tier,omitempty"`
	ArgsSHA256  *string        `json:"args_sha256,omitempty"`
	Result      *string        `json:"result,omitempty"`
	Reason      *string        `json:"reason,omitempty"`
	Intent      *string        `json:"intent,omitempty"`
	Coverage    *string        `json:"coverage,omitempty"`
	Subject     map[string]any `json:"subject,omitempty"`
	Initiator   map[string]any `json:"initiator,omitempty"`
	Source      map[string]any `json:"source,omitempty"`
	Destination map[string]any `json:"destination,omitempty"`
	Change      map[string]any `json:"change,omitempty"`
	Effect      map[string]any `json:"effect,omitempty"`
	Outcome     map[string]any `json:"outcome,omitempty"`
	// Exception is a deploy.exception's {kind, objects, addresses, actor, expected, observed, state, detected_at,
	// detail}; Outage a deploy.degraded's {from, to} (docs/gate.md).
	Exception map[string]any `json:"exception,omitempty"`
	Outage    map[string]any `json:"outage,omitempty"`
}

// String is a pointer to s, for ProviderEvent's optional fields.
func String(s string) *string { return &s }

// -- PUT /v1/definitions -------------------------------------------------------------------------------------------

// DefinitionsRequest is the provider's whole set of cluster-pinned agent definitions. Provider empty is
// Options.Provider. Pins nil is sent as [] (unpin everything).
type DefinitionsRequest struct {
	Provider string             `json:"provider"`
	Pins     []PinnedDefinition `json:"pins"`
	Rejected []RejectedPin      `json:"rejected,omitempty"`
}

// PinnedDefinition is one fetched pin: its source, its Agent XR's spec.owner and the file's document.
type PinnedDefinition struct {
	Source PinSource      `json:"source"`
	Owner  string         `json:"owner"`
	Doc    map[string]any `json:"doc"`
}

// PinSource is where a pin came from.
type PinSource struct {
	Repo      *string `json:"repo,omitempty"`
	Path      *string `json:"path,omitempty"`
	Commit    *string `json:"commit,omitempty"`
	Namespace *string `json:"namespace,omitempty"`
	XR        *string `json:"xr,omitempty"`
	LoadedAt  *string `json:"loaded_at,omitempty"`
}

// RejectedPin is a pin the provider could not load, and why.
type RejectedPin struct {
	Name   string    `json:"name"`
	Source PinSource `json:"source"`
	Reason string    `json:"reason"`
}

// DefinitionsResult is what a publish changed.
type DefinitionsResult struct {
	Added    []string       `json:"added"`
	Changed  []string       `json:"changed"`
	Removed  []string       `json:"removed"`
	Rejected []RejectedView `json:"rejected"`
	Cleared  []RejectedView `json:"cleared"`
	Cluster  int            `json:"cluster"`
}

// RejectedView is a rejection as the core keeps it.
type RejectedView struct {
	Name   string     `json:"name"`
	Source SourceView `json:"source"`
	Reason string     `json:"reason"`
}

// SourceView is a pin's source as the core keeps it, with its one-line pin.
type SourceView struct {
	Kind      string  `json:"kind"`
	Repo      *string `json:"repo,omitempty"`
	Path      *string `json:"path,omitempty"`
	Commit    *string `json:"commit,omitempty"`
	Namespace *string `json:"namespace,omitempty"`
	XR        *string `json:"xr,omitempty"`
	LoadedAt  *string `json:"loaded_at,omitempty"`
	Pin       string  `json:"pin"`
}

// -- the deployment gate -------------------------------------------------------------------------------------------

// ChangeRequest is what a verifier registers (POST /v1/clearances; docs/gate.md). Its keys are the gate's
// camelCase ones; the core refuses an unknown key.
type ChangeRequest struct {
	App          string            `json:"app"`
	Env          string            `json:"env"`
	Cluster      string            `json:"cluster"`
	Repo         string            `json:"repo"`
	PR           int64             `json:"pr"`
	Head         string            `json:"head"`
	Base         string            `json:"base,omitempty"`
	Proposer     string            `json:"proposer"`
	ProposerKind string            `json:"proposerKind,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	Protected    bool              `json:"protected"`
	TreeDigest   string            `json:"treeDigest"`
	Paths        []string          `json:"paths"`
	LinesChanged int64             `json:"linesChanged"`
	Objects      []ObjectChange    `json:"objects"`
	Checks       map[string]string `json:"checks"`
	Policy       map[string]any    `json:"policy,omitempty"`
	PolicyCommit string            `json:"policyCommit,omitempty"`
	Admission    *Admission        `json:"admission,omitempty"`
	Agent        *string           `json:"agent,omitempty"`
	TaskID       *string           `json:"taskId,omitempty"`
	Definition   map[string]any    `json:"definition,omitempty"`
	// Subject is a saved Terraform plan (G-TF-1); with it, Cluster and TreeDigest may be empty and Objects is an
	// empty list (not nil: the core refuses "objects": null).
	Subject *PlanSubject `json:"subject,omitempty"`
}

// PlanSubject is a terraform-plan change's subject as a verifier sends it (schemas/change-request.schema.json):
// the saved plan's digests, its workspace and versions, the summary and every resource change. Digests are sha256
// (bare hex or "sha256:"); a variable's value is never sent, only the variable set's hash.
type PlanSubject struct {
	Kind              string         `json:"kind"` // terraform-plan
	PlanDigest        string         `json:"planDigest"`
	PlanJSONDigest    string         `json:"planJsonDigest"`
	Workspace         PlanWorkspace  `json:"workspace"`
	Versions          PlanVersions   `json:"versions"`
	Summary           PlanSummary    `json:"summary"`
	Targeted          bool           `json:"targeted"`
	VariableSetDigest string         `json:"variableSetDigest"`
	Resources         []PlanResource `json:"resources"`
}

// PlanWorkspace is a Terraform workspace: backend type, state key, workspace name.
type PlanWorkspace struct {
	Backend string `json:"backend"`
	Key     string `json:"key"`
	Name    string `json:"name"`
}

// PlanVersions are Terraform's version and each provider's (source address to version).
type PlanVersions struct {
	Terraform string            `json:"terraform"`
	Providers map[string]string `json:"providers"`
}

// PlanSummary is the plan's counts and the addresses it destroys; the core checks it against the resources.
type PlanSummary struct {
	Create             int64    `json:"create"`
	Update             int64    `json:"update"`
	Replace            int64    `json:"replace"`
	Destroy            int64    `json:"destroy"`
	DestroyedAddresses []string `json:"destroyedAddresses,omitempty"`
}

// PlanResource is one resource change: address, type, actions, the changed attributes' JSON pointers and Terraform's
// action_reason.
type PlanResource struct {
	Address      string   `json:"address"`
	Type         string   `json:"type"`
	Actions      []string `json:"actions"`
	Fields       []string `json:"fields,omitempty"`
	ActionReason string   `json:"actionReason,omitempty"`
}

// ChangeSubject is what a change on record binds to: kind manifest-tree, definition or terraform-plan, its digests
// (sha256, gitCommit; planJson and variableSet for a plan) and, for a plan, the request's subject.
type ChangeSubject struct {
	Kind              string            `json:"kind"`
	Name              string            `json:"name,omitempty"`
	Digests           map[string]string `json:"digests"`
	Flags             []string          `json:"flags,omitempty"`
	PlanDigest        string            `json:"planDigest,omitempty"`
	PlanJSONDigest    string            `json:"planJsonDigest,omitempty"`
	Workspace         *PlanWorkspace    `json:"workspace,omitempty"`
	Versions          *PlanVersions     `json:"versions,omitempty"`
	Summary           *PlanSummary      `json:"summary,omitempty"`
	Targeted          *bool             `json:"targeted,omitempty"`
	VariableSetDigest string            `json:"variableSetDigest,omitempty"`
	Resources         []PlanResource    `json:"resources,omitempty"`
}

// Admission is a verifier's offline admission result for a change's rendered tree (docs/gate.md "The policy in
// the record"): the engine and version (kyverno/1.19.0), the verdict (pass, warn, fail, skipped, error), the rule
// set it ran (<repo>//<path>@<commit>) and the blocking and warning finding counts.
type Admission struct {
	Engine  string `json:"engine"`
	Verdict string `json:"verdict"`
	Bundle  string `json:"bundle,omitempty"`
	Deny    int64  `json:"deny"`
	Warn    int64  `json:"warn"`
}

// ObjectChange is one Kubernetes object a change touches.
type ObjectChange struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Namespace  string   `json:"namespace"`
	Name       string   `json:"name"`
	Op         string   `json:"op"`
	Fields     []string `json:"fields"`
	Images     []string `json:"images"`
	Digest     string   `json:"digest"`
}

// Change is a change on record.
type Change struct {
	ID               string            `json:"id"`
	App              string            `json:"app"`
	Env              string            `json:"env"`
	Cluster          string            `json:"cluster"`
	Repo             string            `json:"repo"`
	PR               int64             `json:"pr"`
	Head             string            `json:"head"`
	Base             string            `json:"base"`
	Proposer         string            `json:"proposer"`
	ProposerKind     string            `json:"proposer_kind"`
	Agent            *string           `json:"agent"`
	TaskID           *string           `json:"task_id"`
	Owner            string            `json:"owner"`
	Protected        bool              `json:"protected"`
	TreeDigest       string            `json:"tree_digest"`
	Subject          *ChangeSubject    `json:"subject"`
	Paths            []string          `json:"paths"`
	LinesChanged     int64             `json:"lines_changed"`
	Objects          []ObjectChange    `json:"objects"`
	Checks           map[string]string `json:"checks"`
	PolicyVersion    string            `json:"policy_version"`
	RepoPolicyDigest *string           `json:"repo_policy_digest"`
	PolicyRef        string            `json:"policy_ref,omitempty"`
	Admission        *Admission        `json:"admission,omitempty"`
	Tier             int               `json:"tier"`
	Reasons          []Reason          `json:"reasons"`
	Requirement      *Requirement      `json:"requirement"`
	State            string            `json:"state"`
	CreatedAt        string            `json:"created_at"`
	UpdatedAt        string            `json:"updated_at"`
	ExpiresAt        string            `json:"expires_at"`
	RegisteredBy     string            `json:"registered_by"`
	Approvals        []Approval        `json:"approvals"`
	ClearedBy        *string           `json:"cleared_by"`
	DecidedAt        *string           `json:"decided_at"`
	DenyReason       *string           `json:"deny_reason"`
	DeniedBy         *string           `json:"denied_by"`
	SupersededBy     *string           `json:"superseded_by"`
	Deployments      []Deployment      `json:"deployments"`
	Outcome          *ChangeOutcome    `json:"outcome,omitempty"`
	Target           string            `json:"target"`
	ObjectsCount     int               `json:"objects_count"`
	PathsCount       int               `json:"paths_count"`
	// Outage is allow-and-record or hold: what a provider does with the change while the core is unreachable.
	Outage string `json:"outage,omitempty"`
	// Ended is the record that moved the change to degraded or exception.
	Ended *Ended `json:"ended,omitempty"`
}

// Ended names the provider record that took a change out of the main path.
type Ended struct {
	Seq  int64  `json:"seq"`
	Tool string `json:"tool"`
	Kind string `json:"kind,omitempty"`
}

// Reason is one classification reason of a change.
type Reason struct {
	Subject string `json:"subject"`
	Rule    string `json:"rule"`
	Tier    int    `json:"tier"`
}

// Requirement is who must clear a change.
type Requirement struct {
	Owner         int      `json:"owner"`
	Outside       int      `json:"outside"`
	OwnerGroup    string   `json:"ownerGroup"`
	OutsideGroups []string `json:"outsideGroups"`
}

// Approval is one person's clearance.
type Approval struct {
	Person string  `json:"person"`
	Via    *string `json:"via"`
	Role   string  `json:"role"`
	At     string  `json:"at"`
	// Sub and Iss name the person at their identity provider ("delegate:<delegate>" as Iss through a delegate).
	Sub string `json:"sub,omitempty"`
	Iss string `json:"iss,omitempty"`
}

// Deployment is a GitHub Actions deployment waiting on a change.
type Deployment struct {
	RunID        int64   `json:"run_id"`
	Environment  string  `json:"environment"`
	Installation string  `json:"installation"`
	CallbackURL  string  `json:"callback_url"`
	RequestedAt  string  `json:"requested_at"`
	Answer       *string `json:"answer"`
	AnsweredAt   *string `json:"answered_at"`
	Delivered    bool    `json:"delivered"`
	DeliveredAt  *string `json:"delivered_at"`
}

// Decided is a clear's or a deny's answer: the change and the seq of the record that recorded the person's act.
type Decided struct {
	Change
	AuditSeq int64 `json:"audit_seq"`
}

// -- POST /v1/clearances/{change_id}/outcome ----------------------------------------------------------------------

// AppliedChange is one resource a Terraform apply acted on, from its JSON log (gate.AppliedChange): the address, the
// action (gate.ApplyActions) and, when the log says, complete or errored.
type AppliedChange struct {
	Address string `json:"address"`
	Action  string `json:"action"`
	Status  string `json:"status,omitempty"`
}

// ChangeOutcomeRequest is what a terraform-plan change's apply did (gate.OutcomeRequest): whether it ran, the sha256
// of the saved plan file applied, the resources from the apply's JSON log, when it started and finished (RFC 3339),
// and its error.
type ChangeOutcomeRequest struct {
	Applied    *bool           `json:"applied"`
	PlanDigest string          `json:"planDigest"`
	Changes    []AppliedChange `json:"changes"`
	StartedAt  string          `json:"startedAt"`
	FinishedAt string          `json:"finishedAt"`
	Error      string          `json:"error,omitempty"`
}

// ChangeOutcome is a change's recorded outcome (gate.Outcome): the deploy.outcome's seq, whether the apply ran and
// matched the cleared plan, the digest reported, when it was recorded, and on a mismatch the deploy.exception's seq.
type ChangeOutcome struct {
	Seq        int64  `json:"seq"`
	Applied    bool   `json:"applied"`
	Matched    bool   `json:"matched"`
	PlanDigest string `json:"plan_digest"`
	At         string `json:"at"`
	Exception  *int64 `json:"exception,omitempty"`
}

// ChangeOutcomeResult is the outcome route's answer (gate.OutcomeResult).
type ChangeOutcomeResult struct {
	Change       *Change `json:"change"`
	Matched      bool    `json:"matched"`
	AuditSeq     int64   `json:"audit_seq"`
	ExceptionSeq *int64  `json:"exception_seq"`
}

// -- POST /v1/provenance -------------------------------------------------------------------------------------------

// ProvenanceRequest asks for a pull request's agent-identity and agent-scope verdicts.
type ProvenanceRequest struct {
	Repo     string            `json:"repo"`
	PR       int64             `json:"pr"`
	Head     string            `json:"head"`
	Paths    []string          `json:"paths"`
	Author   string            `json:"author,omitempty"`
	Trailers map[string]string `json:"trailers,omitempty"`
}

// Verdict is provenance's answer.
type Verdict struct {
	AgentPR  bool           `json:"agent_pr"`
	Identity Check          `json:"identity"`
	Scope    Check          `json:"scope"`
	Record   *RecordSummary `json:"record"`
	AuditSeq *int64         `json:"audit_seq,omitempty"`
}

// Check is one verdict.
type Check struct {
	OK         bool         `json:"ok"`
	Status     string       `json:"status"`
	Rule       *string      `json:"rule"`
	Message    string       `json:"message"`
	Hint       string       `json:"hint"`
	Violations *[]Violation `json:"violations,omitempty"`
}

// Violation is one path an agent's pull request may not touch.
type Violation struct {
	Path    string `json:"path"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// RecordSummary is the receipt record a verdict rests on; its values are the stored record's, any JSON type.
type RecordSummary struct {
	Seq       any `json:"seq"`
	Hash      any `json:"hash"`
	TS        any `json:"ts"`
	TaskID    any `json:"task_id"`
	Session   any `json:"session"`
	Agent     any `json:"agent"`
	Principal any `json:"principal"`
	Tool      any `json:"tool"`
}

// -- operational ---------------------------------------------------------------------------------------------------

// Health is GET /healthz's answer.
type Health struct {
	OK bool `json:"ok"`
}

// Ready is GET /readyz's answer: the policy bundle and the chain's head seq (-1 empty).
type Ready struct {
	OK     bool      `json:"ok"`
	Error  string    `json:"error,omitempty"`
	Policy PolicyRef `json:"policy"`
	Head   int64     `json:"head"`
	// Degraded names the policy bundles whose sources could not be read (the core stays ready).
	Degraded []string `json:"degraded,omitempty"`
}

// errorBody is every refusal's body: {"error"} and, from the gate, rule and hint.
type errorBody struct {
	Error string `json:"error"`
	Rule  string `json:"rule"`
	Hint  string `json:"hint"`
}

// -- GET /v1/clearances/{change_id}, GET /v1/keys --------------------------------------------------------------

// ClearanceAnswer is a change's state and its live clearance token (gate.ClearanceAnswer).
type ClearanceAnswer struct {
	ID         string     `json:"id"`
	State      string     `json:"state"`
	App        string     `json:"app"`
	Env        string     `json:"env"`
	Cluster    string     `json:"cluster"`
	Repo       string     `json:"repo"`
	PR         int64      `json:"pr"`
	Head       string     `json:"head"`
	TreeDigest string     `json:"tree_digest"`
	Tier       int        `json:"tier"`
	ClearedBy  *string    `json:"cleared_by"`
	TaskID     *string    `json:"task_id"`
	ExpiresAt  string     `json:"expires_at"`
	Token      *TokenView `json:"token"`
}

// WaitAnswer is the wait route's answer (server.WaitAnswer): the change and its token, and whether its state
// changed (false: the wait timed out).
type WaitAnswer struct {
	ClearanceAnswer
	Changed bool `json:"changed"`
}

// TokenView is a clearance token: the DSSE envelope, its JWT projection, the nonce, the key and the validity
// (gate.TokenView). Verify it with internal/token (or any DSSE / JWS ES256 verifier) against Keys.
type TokenView struct {
	Nonce     string   `json:"nonce"`
	KeyID     string   `json:"key_id"`
	IssuedAt  string   `json:"issued_at"`
	ExpiresAt string   `json:"expires_at"`
	DSSE      Envelope `json:"dsse"`
	JWT       string   `json:"jwt"`
}

// Envelope is a DSSE envelope (token.Envelope).
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// JWKS is the token verification keys (token.JWKS).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is one EC P-256 verification key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}
