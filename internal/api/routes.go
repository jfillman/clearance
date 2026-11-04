package api

import (
	"encoding/json"
	"net/http"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/token"
)

// Route is one operation of the route table: what the mux serves and what the contract says (api.py ROUTES, the
// operations clearance-api kept after R-3).
type Route struct {
	OperationID, Method, Path string
	Roles                     []string
	Params                    []string // the query parameters it takes; any other is refused (400)
	Summary                   string
	Response                  any   // a value of the 200 answer's Go type, for the contract's schema
	Errors                    []int // the other statuses it answers
	serve                     func(*Server, http.ResponseWriter, *http.Request, *Viewer)
}

// Routes is the route table in contract order. The slice is shared: do not modify it.
func Routes() []Route { return routeTable }

// The answers' Go types (the contract's schemas).

// EvidencePage is a page of evidence records: next is the last item's seq when the page is full, else null.
type EvidencePage struct {
	Items []Record `json:"items"`
	Next  *int64   `json:"next"`
}

// RecordList is the records of a PR (receipts, verdicts).
type RecordList struct {
	Items []Record `json:"items"`
}

// Counts is a counts answer: the groups and their sum. Outcomes says which records were counted (evidence counts
// only).
type Counts struct {
	By       string  `json:"by"`
	Items    []Count `json:"items"`
	Total    int64   `json:"total"`
	Outcomes string  `json:"outcomes,omitempty"`
}

// ChangePage is a page of the gate's changes: next is the last item's updated_at when the page is full.
type ChangePage struct {
	Items []json.RawMessage `json:"items"`
	Next  *string           `json:"next"`
}

// ClearanceView is one change with its live clearance token beside it (null when it has none).
type ClearanceView struct {
	gate.Change
	Token *gate.TokenView `json:"token"`
}

// ListedChange is a list item: the stored change, and its token in the grant feed (cluster and state=cleared).
type ListedChange struct {
	gate.Change
	Token *gate.TokenView `json:"token,omitempty"`
}

// ErrorBody is every refusal.
type ErrorBody struct {
	Error string `json:"error"`
}

// Health is /healthz's answer; Ready is /readyz's.
type Health struct {
	OK bool `json:"ok"`
}

// Ready is /readyz's answer: the database answers.
type Ready struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Degraded names the policy bundles whose sources could not be read (the api stays ready).
	Degraded []string `json:"degraded,omitempty"`
}

var routeTable = []Route{
	{OperationID: "listEvidence", Method: "GET", Path: "/v1/evidence", Roles: PersonRoles,
		Params: []string{"task", "session", "agent", "tool", "principal", "decision", "rule", "app", "since", "until",
			"limit", "after", "outcomes"},
		Summary: "Evidence records you may see, newest first; the cursor is seq. outcomes=include (default), exclude " +
			"or only: the outcome records the core writes beside each allowed decision (outcome_of)",
		Response: EvidencePage{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listEvidence},
	{OperationID: "listExceptions", Method: "GET", Path: "/v1/exceptions", Roles: PersonRoles,
		Params: []string{"tool", "kind", "app", "since", "until", "limit", "after"},
		Summary: "The packet's exceptions, newest first; the cursor is seq: every deploy.exception (kind=out-of-band, " +
			"drift, untraced-apply or digest-mismatch), every provider's degraded-mode report (deploy.degraded: what " +
			"it did while the core was unreachable, with the outage policy it was held to), every break-glass window " +
			"(breakglass.open, breakglass.close with what changed in it) and every runtime read allowed during an " +
			"outage (tool.call, coverage-unavailable). tool narrows to one of those",
		Response: EvidencePage{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listExceptions},
	{OperationID: "getEvidence", Method: "GET", Path: "/v1/evidence/{seq}", Roles: PersonRoles, Params: []string{},
		Summary:  "One evidence record with its hash",
		Response: Record{}, Errors: []int{400, 401, 403, 404, 503}, serve: (*Server).getEvidence},
	{OperationID: "verifyEvidence", Method: "GET", Path: "/v1/evidence/verify", Roles: []string{RoleAuditor},
		Params:   []string{},
		Summary:  "The whole chain checked from genesis: ok, count, head, the first bad seq",
		Response: Verified{}, Errors: []int{401, 403, 503}, serve: (*Server).verifyEvidence},
	{OperationID: "countEvidence", Method: "GET", Path: "/v1/evidence/counts", Roles: PersonRoles,
		Params: []string{"by", "task", "session", "agent", "tool", "principal", "decision", "rule", "app", "since",
			"until", "outcomes"},
		Summary: "Records you may see, counted by rule, tool, agent, app or decision (`by`), with the same filters as " +
			"the list. outcomes=exclude (default) counts each decision once; include or only count the outcome records too",
		Response: Counts{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).countEvidence},
	{OperationID: "getPolicy", Method: "GET", Path: "/v1/policy", Roles: PersonRoles, Params: []string{},
		Summary: "The policy in force: the deny rules in evaluation order (id, name, CEL expression, message, hint, " +
			"bundle, `pack`), the tool registry with tiers, \"core\" and the loaded bundles (`packs`)",
		Response: PolicyDoc{}, Errors: []int{401, 403, 404}, serve: (*Server).getPolicy},
	{OperationID: "explainPolicy", Method: "GET", Path: "/v1/policy/explain", Roles: PersonRoles,
		Params: []string{"agent", "tool", "args"},
		Summary: "Would this be allowed? A dry run of the real policy for an agent, a tool and its args (JSON) on a " +
			"fresh session: the decision and each rule's verdict in order. Records nothing",
		Response: Explanation{}, Errors: []int{400, 401, 403, 404}, serve: (*Server).explainPolicy},
	{OperationID: "listReceipts", Method: "GET", Path: "/v1/receipts", Roles: PersonRoles,
		Params:   []string{"repo", "pr"},
		Summary:  "PR receipts: what Clearance's agents opened on a repo (and PR), the commit, the paths",
		Response: RecordList{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listReceipts},
	{OperationID: "listProvenance", Method: "GET", Path: "/v1/provenance", Roles: PersonRoles,
		Params:   []string{"repo", "pr"},
		Summary:  "The agent-gate verdicts recorded for a PR (provenance.verify)",
		Response: RecordList{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listProvenance},
	{OperationID: "listClearances", Method: "GET", Path: "/v1/clearances", Roles: FeedRoles,
		Params: []string{"app", "env", "state", "repo", "pr", "tier", "since", "limit", "after", "cluster"},
		Summary: "The deployment gate's changes, newest first: tier and why, state (holding, cleared, denied, " +
			"expired, superseded, degraded, exception), the requirement and the approvals so far, what the grant binds to. A person sees " +
			"their apps' changes and the ones their groups may clear; the cursor is updated_at. cluster=<c>&state=" +
			"cleared is the grant feed: the cluster's cleared changes whose clearance token is live, each with its " +
			"token; a feed reader (CLEARANCE_API_FEED_READERS) may read only that, for its own clusters",
		Response: ChangePage{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listClearances},
	{OperationID: "countClearances", Method: "GET", Path: "/v1/clearances/counts", Roles: PersonRoles,
		Params: []string{"app", "env", "state", "since", "by"},
		Summary: "Changes counted by state, tier, app, env or cleared_by (the C1 stats: holding, cleared by policy " +
			"and by people, denied)",
		Response: Counts{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).countClearances},
	{OperationID: "getClearance", Method: "GET", Path: "/v1/clearances/{id}", Roles: FeedRoles, Params: []string{},
		Summary: "One change: the objects and paths it touches, every reason for its tier, the requirement, the " +
			"approvals, the checks as last reported, and its live clearance token (null when it has none)",
		Response: ClearanceView{}, Errors: []int{401, 403, 404, 503}, serve: (*Server).getClearance},
	{OperationID: "getClearancePolicy", Method: "GET", Path: "/v1/clearance-policy", Roles: PersonRoles,
		Params: []string{},
		Summary: "The deployment gate's baseline policy: the tier table, the people each tier needs, the outside " +
			"groups, the TTL, the outage policy by tier (allow-and-record or hold). A repo's clearance.yaml can only " +
			"tighten it",
		Response: gate.PolicyView{}, Errors: []int{401, 403, 404}, serve: (*Server).getClearancePolicy},
	{OperationID: "listDefinitions", Method: "GET", Path: "/v1/definitions", Roles: PersonRoles,
		Params: []string{"full"},
		Summary: "The agent definitions Clearance decides with: the bundled set and the cluster pins the core " +
			"stored, each with its source; rejected pins with the reason. full=1 (auditors) adds instructions",
		Response: DefinitionList{}, Errors: []int{400, 401, 403}, serve: (*Server).listDefinitions},
	{OperationID: "getKeys", Method: "GET", Path: "/v1/keys", Roles: []string{RoleAny}, Params: []string{},
		Summary: "The clearance token verification keys, a JWKS (EC P-256, ES256, kid = the RFC 7638 thumbprint): " +
			"the key the core signs with and keys retired within the last 24 hours. Public",
		Response: token.JWKS{}, Errors: []int{503}, serve: (*Server).getKeys},
	{OperationID: "getContract", Method: "GET", Path: "/v1/contract", Roles: []string{RoleAny}, Params: []string{},
		Summary:  "This contract",
		Response: map[string]any{}}, // served by getContract (New), which reads this table
}
