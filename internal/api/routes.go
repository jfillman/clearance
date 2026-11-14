package api

import (
	"encoding/json"
	"net/http"

	"github.com/jfillman/clearance/internal/attest"
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
	// AlsoResponse is a second Go type the 200 answer may be (a query switch): the contract then says oneOf Response, AlsoResponse.
	AlsoResponse any
	// Stream is a route that answers text/event-stream (Response is one event's data): no handler deadline, its own
	// write deadlines, and a portal's buffered proxy does not forward it.
	Stream bool
	serve  func(*Server, http.ResponseWriter, *http.Request, *Viewer)
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
	// Bucket is the bucket width of a bucketed count; each item then carries its bucket's start.
	Bucket string `json:"bucket,omitempty"`
	// Per is what by=cost grouped by (task, session, agent or principal); Cost is the groups' cost summed.
	Per  string   `json:"per,omitempty"`
	Cost *CostSum `json:"cost,omitempty"`
}

// ChangePage is a page of the gate's changes: next is the last item's updated_at when the page is full.
type ChangePage struct {
	Items []json.RawMessage `json:"items"`
	Next  *string           `json:"next"`
}

// ClearanceView is one change with its live clearance token beside it (null when it has none) and its signed
// attestation (C-2; null until a deploy reports an applied outcome).
type ClearanceView struct {
	gate.Change
	Token       *gate.TokenView  `json:"token"`
	Attestation *AttestationView `json:"attestation"`
	// Request is the change's first deploy.request record (its seq and hash on the chain); null when it has none.
	Request *RecordRef `json:"request"`
}

// AttestationView is the reference to a change's attestation: the envelope's digest (the one the deploy.attestation
// record carries), where Rekor logged it, and the records it ties together. The bundle itself is GET
// /v1/clearances/{id}/attestation.
type AttestationView struct {
	Digest        string `json:"digest"`
	Backend       string `json:"backend"` // keyless | static
	KeyID         string `json:"key_id,omitempty"`
	RekorLogIndex *int64 `json:"rekor_log_index"`
	RekorUUID     string `json:"rekor_uuid,omitempty"`
	OutcomeSeq    int64  `json:"outcome_seq"`
	RecordSeq     int64  `json:"record_seq"`
	CreatedAt     string `json:"created_at"`
	// Verification is this replica's last check of the bundle (GET /v1/clearances/{id}/attestation/verify); null
	// when it has not checked it. Only a verification with verified true says the attestation is verified.
	Verification *VerificationBrief `json:"verification"`
}

// ListedChange is a list item: the stored change, and its token in the grant feed (cluster and state=cleared).
type ListedChange struct {
	gate.Change
	Token *gate.TokenView `json:"token,omitempty"`
	// Attested and Attestation are on every list but the grant feed: whether the change has a signed attestation,
	// and its reference (as getClearance serves it).
	Attested    *bool            `json:"attested,omitempty"`
	Attestation *AttestationView `json:"attestation,omitempty"`
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
			"limit", "after", "outcomes", "installation", "coverage"},
		Summary: "Evidence records you may see, newest first; the cursor is seq. outcomes=include (default), exclude " +
			"or only: the outcome records the core writes beside each allowed decision (outcome_of). installation=<id> " +
			"keeps one GitHub App installation's records (principal app:<id>). coverage=<state>[,<state>...] keeps the records in " +
			"those coverage states (authorized-and-verified, observed-not-attributed, out-of-band-detected, coverage-unavailable, break-glass, attempted-refused)",
		Response: EvidencePage{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listEvidence},
	{OperationID: "listExceptions", Method: "GET", Path: "/v1/exceptions", Roles: ObservationRoles,
		Params: []string{"tool", "kind", "app", "since", "until", "limit", "after"},
		Summary: "The packet's exceptions, newest first; the cursor is seq: every deploy.exception (kind=out-of-band, " +
			"drift, untraced-apply, digest-mismatch, attempted-refused or monitoring-protection), every provider's degraded-mode report (deploy.degraded: what " +
			"it did while the core was unreachable, with the outage policy it was held to), every break-glass window " +
			"(breakglass.open, breakglass.close with what changed in it) and every runtime read allowed during an " +
			"outage (tool.call, coverage-unavailable). tool narrows to one of those. Any signed-in person, a delegate for one, an auditor or a configured observation reader reads every exception (O-5); secret-bearing keys in a record's state_change and exception are redacted for all but an auditor",
		Response: EvidencePage{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listExceptions},
	{OperationID: "listObservations", Method: "GET", Path: "/v1/observations", Roles: ObservationRoles,
		Params: []string{"scope", "source", "kind", "since", "until", "limit", "after"},
		Summary: "The observation records (clearance.evidence/v1.1) of one scope, newest first; the cursor is seq. " +
			"kind=observation (default), assessment, resolution (every edit of a resolution is a record of its own: the history) or " +
			"observation.verification (a feed's later proof an observation was delivered unaltered). scope is required: the account, cluster or workspace " +
			"observed; source narrows to one feed. Any signed-in person, a delegate for one, an auditor or a configured observation reader (O-5): the whole scope; secret-bearing keys in a record's state_change are redacted for all but an auditor",
		Response: EvidencePage{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listObservations},
	{OperationID: "listObservationHealth", Method: "GET", Path: "/v1/observations/health", Roles: ObservationRoles,
		Params: []string{"scope", "source", "since", "until", "limit", "after"},
		Summary: "The health of the feeds behind a scope's observations, newest first: observation.health records " +
			"(healthy, degraded or blind per source, with the checks that produced it) and the observation.audit-gap " +
			"records written when a feed dropped. scope is required. Any signed-in person, a delegate for one, an auditor or a configured observation reader (O-5): the whole scope; secret-bearing keys in a record's state_change are redacted for all but an auditor",
		Response: EvidencePage{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listObservationHealth},
	{OperationID: "getCoverage", Method: "GET", Path: "/v1/coverage", Roles: ObservationRoles,
		Params: []string{"scope", "from", "to", "names"},
		Summary: "With no scope, the statements of every scope observed in the window ({from, to, scopes: [statement...], truncated}; " +
			"at most 100 scopes). With no scope and names=only, just the scope list ({from, to, scopes: [{scope}...], truncated, " +
			"names_only: true}; at most 1000 names, no statements built: one cheap read); names is only, and takes no scope (400). The coverage statement for a scope and window (from and to, RFC 3339; default the last 24 hours): " +
			"what was cleared and verified, what was seen and not cleared (by coverage state, with how each ended), " +
			"what could not be seen (the stretches a feed was blind or degraded, and the audit gaps), and the health " +
			"of each feed, with each item's newest resolution (state, cause, who set it and when) and how many of the window's " +
			"observations had their source verified (source_integrity). clean is true only when nothing was seen uncleared and every feed was healthy for the " +
			"whole window: a window with no healthy health record, or whose last record has gone stale, is blind and " +
			"never clean. Any signed-in person, a delegate for one, an auditor or a configured observation reader (O-5): the whole scope; secret-bearing keys in a record's state_change are redacted for all but an auditor",
		Response: ScopeStatements{}, AlsoResponse: ScopeNames{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).getCoverage},
	{OperationID: "getEvidence", Method: "GET", Path: "/v1/evidence/{seq}", Roles: PersonRoles, Params: []string{},
		Summary:  "One evidence record with its hash",
		Response: Record{}, Errors: []int{400, 401, 403, 404, 503}, serve: (*Server).getEvidence},
	{OperationID: "verifyEvidence", Method: "GET", Path: "/v1/evidence/verify", Roles: []string{RoleAuditor},
		Params:   []string{},
		Summary:  "The whole chain checked from genesis: ok, count, head, the first bad seq",
		Response: Verified{}, Errors: []int{401, 403, 503}, serve: (*Server).verifyEvidence},
	{OperationID: "countEvidence", Method: "GET", Path: "/v1/evidence/counts", Roles: PersonRoles,
		Params: []string{"by", "per", "task", "session", "agent", "tool", "principal", "decision", "rule", "app", "since",
			"until", "outcomes", "installation", "coverage", "scope", "bucket"},
		Summary: "Records you may see, counted by rule, tool, agent, app, decision, coverage, provider (the registered " +
			"provider or gate that wrote it) or boundary (`by`), with the same filters as the list, and scope=<scope> " +
			"for one observed scope's records. bucket=1m|5m|15m|1h|6h|1d cuts the window (since is required, until " +
			"defaults to now, at most 1500 buckets) into epoch-aligned time buckets: each item is then a bucket (its start) " +
			"and a key, in time order, at most 10000. outcomes=exclude (default) counts each decision once; include or only count the outcome records too. " +
			"by=cost sums what runs cost instead, per task (default: the task tree), session (one run), agent or " +
			"principal (`per`): the model-call outcomes' usage (charged_tokens is what the model proxy charged the " +
			"session budgets) and the run.finish records' runs and wall seconds; each item's count is its model calls",
		Response: Counts{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).countEvidence},
	{OperationID: "listTargets", Method: "GET", Path: "/v1/targets", Roles: ObservationRoles,
		Params: []string{"source", "group", "kind", "env", "app"},
		Summary: "The declared target registry: what each publishing source (a cluster's gitops render, an account's " +
			"bootstrap) declares should be protected, the union of every source's set (PUT /v1/targets/{source} on the " +
			"core). A target has an id, name, kind (k8s-namespace, k8s-cluster, aws-account, github-environment, other), " +
			"group (the cluster or account), env, app, owner, registry tier (a name), the coverage scope its " +
			"observations arrive under, its gates (type, instance, mode enforce or flag) and its observers (provider, " +
			"source); sources lists each set's digest (the one its targets.load record carries). A declaration, not " +
			"evidence: GET /v1/map reconciles it with the records",
		Response: TargetList{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listTargets},
	{OperationID: "getMap", Method: "GET", Path: "/v1/map", Roles: ObservationRoles,
		Params: []string{"from", "to", "target", "group", "expand"},
		Summary: "The coverage map in one read (from and to, RFC 3339; default the last 24 hours). The declared registry " +
			"joined with the records, computed in a fixed number of aggregate queries: nodes (gate types with their " +
			"instances, mode mix and what they decided; target groups and their targets with coverage mix, observer health " +
			"and lanes; observers), edges (a gate type or observer to a group, or, with expand=<group>[,<group>], to each " +
			"of its targets: volume is decisions, status the worst state), the needs-attention list (targets with no gate, " +
			"blind or degraded observers, gates in flag mode, changes holding, declared gates that decided nothing and " +
			"decisions from gates nobody declared) and `partial`: what the records cannot yet say. target=<id> is the " +
			"one-target detail (also the changes moving through it, its exceptions and recent evidence); group=<g> narrows " +
			"to one cluster or account. Observation facts are whole-scope for every reader (O-5); gate decisions, " +
			"exceptions and evidence are the records the viewer may see",
		Response: MapResponse{}, Errors: []int{400, 401, 403, 404, 503}, serve: (*Server).getMap},
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
		Params: []string{"repo", "pr", "installation"},
		Summary: "PR receipts: what Clearance's agents opened on a repo (and PR), the commit, the paths. " +
			"installation=<id> keeps the receipts of pull requests that GitHub App installation checked",
		Response: RecordList{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listReceipts},
	{OperationID: "listProvenance", Method: "GET", Path: "/v1/provenance", Roles: PersonRoles,
		Params: []string{"repo", "pr", "installation"},
		Summary: "The agent-gate verdicts recorded for a PR (provenance.verify). installation=<id> keeps the " +
			"verdicts that GitHub App installation recorded",
		Response: RecordList{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listProvenance},
	{OperationID: "listClearances", Method: "GET", Path: "/v1/clearances", Roles: NotifierChangeRoles,
		Params: []string{"app", "env", "state", "repo", "pr", "tier", "since", "limit", "after", "cluster", "awaiting"},
		Summary: "The deployment gate's changes, newest first: tier and why, state (holding, cleared, denied, " +
			"expired, superseded, degraded, exception), the requirement and the approvals so far, what the grant binds to. A person sees " +
			"their apps' changes and the ones their groups may clear; the order is updated_at then id, and the cursor (next, pass it back as after) is \"<updated_at>,<id>\", so changes sharing a second are never dropped between pages; a bare updated_at from an older client still means strictly older. cluster=<c>&state=" +
			"cleared is the grant feed: the cluster's cleared changes whose clearance token is live, each with its " +
			"token; a feed reader (CLEARANCE_API_FEED_READERS) may read only that, for its own clusters. awaiting=me keeps the holding " +
			"changes the caller may clear now (the gate's own rule: in the owner group or an unfilled outside group, not the proposer, " +
			"not already an approver); a person's token or a delegate naming one",
		Response: ChangePage{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listClearances},
	{OperationID: "countClearances", Method: "GET", Path: "/v1/clearances/counts", Roles: NotifierCountRoles,
		Params: []string{"app", "env", "state", "since", "by"},
		Summary: "Changes counted by state, tier, app, env, cleared_by or attestation (the C1 stats: holding, cleared by policy " +
			"and by people, denied). by=attestation: attested (a signed attestation is stored), pending (the deploy " +
			"reported an applied outcome and none is stored yet: the signer is waiting or retrying) and none (no applied outcome)",
		Response: Counts{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).countClearances},
	{OperationID: "getClearance", Method: "GET", Path: "/v1/clearances/{id}", Roles: FeedRoles, Params: []string{},
		Summary: "One change: the objects and paths it touches, every reason for its tier, the requirement, the " +
			"approvals, the checks as last reported, and its live clearance token (null when it has none)",
		Response: ClearanceView{}, Errors: []int{401, 403, 404, 503}, serve: (*Server).getClearance},
	{OperationID: "getClearanceAttestation", Method: "GET", Path: "/v1/clearances/{id}/attestation", Roles: FeedRoles,
		Params: []string{},
		Summary: "The change's signed attestation (C-2) as a Sigstore bundle: the DSSE envelope of an in-toto statement " +
			"(predicate " + attest.PredicateType + ") and the certificate and Rekor entry that verify it. " +
			"`clearance attest verify` checks it offline. 404 until a deploy reports an applied outcome",
		Response: attest.Bundle{}, Errors: []int{401, 403, 404, 503}, serve: (*Server).getAttestation},
	{OperationID: "verifyClearanceAttestation", Method: "GET", Path: "/v1/clearances/{id}/attestation/verify", Roles: FeedRoles,
		Params: []string{},
		Summary: "The stored attestation verified server-side exactly as `clearance attest verify` does: its signature " +
			"against the configured trust (a static key, or a keyless trust root with the core's identity and issuer), the " +
			"Rekor entry, and that the statement names the change's cleared digest (tree, or terraform plan) and this " +
			"change. {verified, checked_at, subject, key_id, rekor{log_index, integrated_time, verified}, errors}. Answers " +
			"200 with verified false and the reasons for a bundle that fails; 404 when the change has no attestation or " +
			"this deployment has no trust configured. The answer is remembered per attestation digest until the replica " +
			"restarts (`cached`); the lists show it as `verification`",
		Response: VerifyAnswer{}, Errors: []int{401, 403, 404, 503}, serve: (*Server).getAttestationVerify},
	{OperationID: "listChangeRecords", Method: "GET", Path: "/v1/clearances/{id}/records", Roles: FeedRoles,
		Params: []string{"limit", "after"},
		Summary: "One change's history: its deploy.* records (request, clear, answer, outcome, attestation, exception, " +
			"...) in chain order, each with its seq, hash, tool, ts, principal and the record. The cursor is seq. Seen " +
			"by whoever may see the change; secret-bearing keys in a record's state_change are redacted for all but an auditor",
		Response: ChangeRecordPage{}, Errors: []int{400, 401, 403, 404, 503}, serve: (*Server).listChangeRecords},
	{OperationID: "listAttestations", Method: "GET", Path: "/v1/attestations", Roles: PersonRoles,
		Params: []string{"app", "env", "since", "until", "limit", "after"},
		Summary: "The signed change attestations, newest first (the cursor is record_seq, the deploy.attestation record's " +
			"seq): each with its change (app, env, release, tree digest), when it was signed, the envelope digest, " +
			"backend, key id, Rekor log index and uuid, the deploy.outcome it attests and this replica's last " +
			"verification. since and until bound the time signed. A person sees the attestations of the changes they may see. " +
			"For the changes applied and not yet attested, GET /v1/clearances/counts?by=attestation (pending)",
		Response: AttestationPage{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).listAttestations},
	{OperationID: "getAttestationConfig", Method: "GET", Path: "/v1/attestation-config", Roles: PersonRoles,
		Params: []string{},
		Summary: "The non-secret attestation configuration a portal needs: whether this api can verify (verifiable), the " +
			"backends, Rekor's public URL and the link to an entry, the keyless identity and issuer, the static key ids and the " +
			"offline verify command. Public keys only",
		Response: AttestationConfig{}, Errors: []int{401, 403}, serve: (*Server).getAttestationConfig},
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
	{OperationID: "getGrantFeed", Method: "GET", Path: "/v1/grant-feeds/{cluster}", Roles: []string{RoleFeed, RoleAuditor},
		Params: []string{},
		Summary: "The cluster's signed grant feed: a DSSE envelope (application/vnd.clearance.grant-feed.v1+json, the " +
			"token key) over every clearance token live on the cluster when the core signed it, with seq, iat, exp and " +
			"each token's payload digest, and the tokens it lists beside it. The core re-signs it on every token write " +
			"and at least every 2 minutes (exp 5 minutes): verify it whole before acting (docs/gate.md). A feed reader " +
			"reads its own clusters'; auditors any",
		Response: GrantFeed{}, Errors: []int{400, 401, 403, 404, 503}, serve: (*Server).getGrantFeed},
	{OperationID: "listInstallations", Method: "GET", Path: "/v1/github/installations", Roles: PersonRoles,
		Params: []string{},
		Summary: "The Clearance GitHub App's installations as the records name them (app:<id>): the account and last " +
			"action of the last app.installation record, the status it leaves, the records by tool, their seq and ts " +
			"bounds, and the repositories its checks ran on",
		Response: InstallationList{}, Errors: []int{401, 403, 503}, serve: (*Server).listInstallations},
	{OperationID: "streamEvents", Method: "GET", Path: "/v1/stream", Roles: NotifierChangeRoles,
		Params: []string{"types", "after"}, Stream: true,
		Summary: "Server-sent events of new evidence records (event: record, the record as getEvidence serves it) and " +
			"gate state changes (event: clearance: the deploy.* record's seq, tool and ts and the change summary it " +
			"recorded), each with id: <seq>. Resume with Last-Event-ID (or after=<seq>); without either the stream " +
			"starts at the head. types=records,clearances (default both). The same scoping as the reads: a person sees " +
			"the records and changes they may read; a feed reader only clearance events of its clusters. A comment " +
			"every 15 s keeps it open; the server ends it after 10 minutes (reconnect with Last-Event-ID)",
		Response: StreamEvent{}, Errors: []int{400, 401, 403, 503}, serve: (*Server).stream},
	{OperationID: "whoami", Method: "GET", Path: "/v1/whoami", Roles: AnyCaller, Params: []string{},
		Summary: "Who the token is and what the api resolves it to: the principal and kind, every role it holds, the " +
			"viewer's role, the person the reads are as (and the delegate, if one asked), whether that person is an admin " +
			"(CLEARANCE_ADMINS), their groups, owned apps and owned agents, the token's issuer and expiry. No secret",
		Response: WhoAmI{}, Errors: []int{401, 403}, serve: (*Server).whoami},
	{OperationID: "getContract", Method: "GET", Path: "/v1/contract", Roles: []string{RoleAny}, Params: []string{},
		Summary:  "This contract",
		Response: map[string]any{}}, // served by getContract (New), which reads this table
}
