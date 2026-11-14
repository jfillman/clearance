package server

import (
	"net/http"
	"strings"

	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/githubapp"
	"github.com/jfillman/clearance/internal/hcprun"
	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/receipt"
	"github.com/jfillman/clearance/internal/review"
	"github.com/jfillman/clearance/internal/sampling"
	"github.com/jfillman/clearance/internal/token"
)

// How a route authenticates its caller.
const (
	AuthNone      = "none"             // /healthz, /readyz
	AuthBearer    = "bearer"           // any principal the Authenticator accepts; the handler decides who may
	AuthProvider  = "provider"         // a bearer token whose principal is a registered provider
	AuthSignature = "github-signature" // the GitHub App's HMAC (X-Hub-Signature-256), no bearer token
	AuthHCP       = "hcp-signature"    // the HCP Terraform run task's HMAC (X-TFC-Task-Signature), no bearer token
)

// Body caps of this package's routes; the R-1c routes keep their own.
const (
	MaxEvaluationBody = decide.MaxRequestBytes
	MaxOutcomeBody    = 64 << 10
	MaxRecordBody     = 256 << 10
	DefaultMaxBody    = 64 << 10
)

// Response is one documented answer of a route.
type Response struct {
	Status      int
	Description string
	Body        any // a value of the body's Go type; nil = no schema
}

// Route is one entry of the route table: what the mux serves and what the contract says.
type Route struct {
	Method, Path, OperationID, Summary string
	Auth                               string
	MaxBody                            int64
	// Request is a value of the request body's Go type (strictly decoded); nil with RequestNote set is a body the
	// handler parses itself (an R-1c route whose request has no JSON-tagged Go type), documented as an object.
	Request     any
	RequestNote string
	Responses   []Response
	// Query are the query parameters it takes, documented in the contract (the handler checks them).
	Query []QueryParam
	// LongPoll is a route that holds the request open (up to MaxWait): its handler deadline and write deadline are
	// extended past HandlerTimeout and WriteTimeout for it alone.
	LongPoll bool
	serve    func(*Server) http.HandlerFunc // nil: a mounted R-1c handler
}

// QueryParam is one documented query parameter.
type QueryParam struct {
	Name, Description string
	Integer           bool
}

// Pattern is the route's ServeMux pattern.
func (r Route) Pattern() string { return r.Method + " " + r.Path }

// matches reports whether path fits the route's path, a {name} segment matching any one non-empty segment.
func (r Route) matches(path string) bool {
	want, got := strings.Split(r.Path, "/"), strings.Split(path, "/")
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if strings.HasPrefix(want[i], "{") {
			if got[i] == "" {
				return false
			}
		} else if want[i] != got[i] {
			return false
		}
	}
	return true
}

// Routes is the route table, in contract order. The slice is shared: do not modify it.
func Routes() []Route { return routeTable }

var errs = func(codes ...int) []Response {
	text := map[int]string{
		400: "the body is not valid (strict decoding, or a field the route refuses)",
		401: "no bearer token, or one the authenticator refused",
		403: "the caller may not do this",
		404: "no such resource",
		409: "the request conflicts with what is recorded",
		413: "the body is over the route's cap",
		503: "the store could not record it: treat as unreachable (fail closed)",
	}
	out := make([]Response, 0, len(codes))
	for _, c := range codes {
		out = append(out, Response{c, text[c], ErrorResponse{}})
	}
	return out
}

// freshErr is the 401 of a person's write: the token, or (DG-AUTH-NOT-FRESH, with max_age and age) a sign-in older than
// the deployment allows for the action.
var freshErr = Response{401, "no bearer token, one the authenticator refused, or (rule DG-AUTH-NOT-FRESH, with max_age and age) " +
	"a sign-in older than CLEARANCE_FRESH_AUTH_* allows for this action: sign in again", gate.ErrorBody{}}

// personWrite is what every person write's description says about the headers it reads.
const personWrite = " The call may carry X-Clearance-Via (cli, web, slack, api, or a name from CLEARANCE_VIAS_EXTRA) and X-Clearance-Surface-Ref (at most 512 " +
	"bytes of printable text), recorded as claimed `surface` {via, ref}; a bad value is 400 (DG-VIA, DG-SURFACE-REF). " +
	"A delegate naming the person may forward their sign-in time in X-Clearance-Auth-Time (unix seconds), which " +
	"CLEARANCE_FRESH_AUTH_DELEGATES=require demands."

var gateErrs = []Response{
	{400, "a malformed change or reason", ErrorResponse{}},
	freshErr,
	{403, "the caller is not a verifier, or may not decide this change", gate.ErrorBody{}},
	{404, "no such change, or a Clearance that keeps no changes (DG-OFF)", gate.ErrorBody{}},
	{409, "the change is not holding, or the person already approved it", gate.ErrorBody{}},
	{413, "the body is over the route's cap", ErrorResponse{}},
}

var routeTable = []Route{
	{
		Method: "GET", Path: "/healthz", OperationID: "healthz", Auth: AuthNone, MaxBody: DefaultMaxBody,
		Summary:   "The process is up.",
		Responses: []Response{{200, "up", Health{}}},
		serve:     func(s *Server) http.HandlerFunc { return s.healthz },
	},
	{
		Method: "GET", Path: "/readyz", OperationID: "readyz", Auth: AuthNone, MaxBody: DefaultMaxBody,
		Summary:   "The store answers and the policy is loaded.",
		Responses: []Response{{200, "ready", Ready{}}, {503, "not ready", Ready{}}},
		serve:     func(s *Server) http.HandlerFunc { return s.readyz },
	},
	{
		Method: "POST", Path: "/access/v1/evaluation", OperationID: "evaluate", Auth: AuthProvider,
		MaxBody: MaxEvaluationBody,
		Summary: "Decide one AuthZEN access evaluation (tool.call, session.spawn, session.open, model.call) and record " +
			"the decision in the evidence chain, sealed by the core. The answer carries decision_id, the record's seq, " +
			"for the outcome route.",
		Request:   decide.EvaluationRequest{},
		Responses: append([]Response{{200, "the decision", EvaluationResult{}}}, errs(400, 401, 403, 413, 503)...),
		serve:     func(s *Server) http.HandlerFunc { return s.evaluate },
	},
	{
		Method: "POST", Path: "/v1/decisions/{id}/outcome", OperationID: "recordOutcome", Auth: AuthProvider,
		MaxBody: MaxOutcomeBody,
		Summary: "The call's result, effect (a pull request's receipt) and receipt, once, for an allowed decision this " +
			"provider asked for. Recorded as the decision's tool, linked by outcome_of; the identity fields are copied " +
			"from the decision record (verified), what the provider reports is claimed.",
		Request:   OutcomeRequest{},
		Responses: append([]Response{{200, "recorded", RecordRef{}}}, errs(400, 401, 403, 404, 409, 413, 503)...),
		serve:     func(s *Server) http.HandlerFunc { return s.outcome },
	},
	{
		Method: "POST", Path: "/v1/records", OperationID: "appendRecord", Auth: AuthProvider, MaxBody: MaxRecordBody,
		Summary: "A registered provider's own record (one of RecordKinds), sealed with that provider's name and version; " +
			"only provider and ts are verified.",
		Request:   RecordRequest{},
		Responses: append([]Response{{200, "recorded", RecordRef{}}}, errs(400, 401, 403, 413, 503)...),
		serve:     func(s *Server) http.HandlerFunc { return s.records },
	},
	{
		Method: "PUT", Path: "/v1/definitions", OperationID: "publishDefinitions", Auth: AuthProvider,
		MaxBody: MaxDefinitionsBody,
		Summary: "The provider's whole set of cluster-pinned agent definitions (its Agent XR loader's pins and " +
			"rejections) replaces the set the core holds. The core decides each pin itself (schema, name, owner, " +
			"workload identity, not a bundled name) and records each change once as definition.load, " +
			"definition.unload or definition.reject; provenance then reads the pinned definitions. The optional " +
			"bundled list is the definitions that ship with the provider itself (name, build version, document): " +
			"decided with the same schema, held beside the pins (a pin cannot shadow one) and recorded the same " +
			"way; absent keeps the provider's earlier bundled set. Only the provider registered with " +
			"definitions: true.",
		Request:   DefinitionsRequest{},
		Responses: append([]Response{{200, "what changed", DefinitionsResult{}}}, errs(400, 401, 403, 404, 413, 503)...),
		serve:     func(s *Server) http.HandlerFunc { return s.definitions },
	},
	{
		Method: "PUT", Path: "/v1/targets/{source}", OperationID: "publishTargets", Auth: AuthProvider,
		MaxBody: MaxTargetsBody,
		Summary: "The targets one source (a cluster's gitops render, an account's bootstrap) declares: the Map's registry " +
			"of what should be protected. Each target has an id, name, kind, group, environment, app, owner, registry " +
			"tier, the coverage scope its observations arrive under, the gates that guard it (type, instance, mode " +
			"enforce or flag) and the observers that watch it. The list replaces the set the core holds for that " +
			"source (an empty list withdraws it); other sources' are untouched. Validated strictly; a changed set is " +
			"one targets.load record carrying the set's digest, an unchanged one records nothing. Only a provider " +
			"registered with targets naming the source. clearance-api serves the union (GET /v1/targets).",
		Request:   TargetsRequest{},
		Responses: append([]Response{{200, "what was held, and whether it changed", TargetsResult{}}}, errs(400, 401, 403, 413, 503)...),
		serve:     func(s *Server) http.HandlerFunc { return s.publishTargets },
	},
	{
		Method: "POST", Path: "/v1/clearances", OperationID: "registerChange", Auth: AuthBearer,
		MaxBody: gate.MaxRegisterBody,
		Summary: "The clearance-gate check registers (or re-evaluates) a change to a protected environment; the caller " +
			"is a verifier (CLEARANCE_VERIFIERS).",
		RequestNote: "gate.ChangeRequest, schemas/change-request.schema.json (docs/gate.md): app, env, cluster, " +
			"repo, pr, head, base, proposer, proposerKind, owner, protected, treeDigest, paths, linesChanged, objects, " +
			"checks, policy, policyCommit, admission, agent, taskId, definition, subject (a saved Terraform plan: kind " +
			"terraform-plan, planDigest, planJsonDigest, workspace, versions, summary, targeted, variableSetDigest, " +
			"resources); unknown fields are refused. protected: false is refused (DG-PROTECTED): Clearance decides " +
			"protection from CLEARANCE_PROTECTED_ENVIRONMENTS, and clears a change elsewhere at tier 0 (unprotected)",
		Responses: append([]Response{{200, "the change as recorded", gate.Change{}}}, gateErrs...),
	},
	{
		Method: "GET", Path: "/v1/clearances/{change_id}", OperationID: "getClearance", Auth: AuthBearer,
		MaxBody: DefaultMaxBody,
		Summary: "A change's state and its live clearance token (a DSSE envelope and its JWT projection; null when " +
			"the change is not cleared, its token was revoked by a new head, or it lapsed). For a registered provider " +
			"and the verifier that registered the change; people read changes through clearance-api. A token with " +
			"less than half its life left is re-issued (same nonce) before it is returned.",
		Responses: []Response{{200, "the change and its token", gate.ClearanceAnswer{}}, errs(401)[0], errs(403)[0],
			{404, "no such change, or a Clearance that keeps no changes (DG-OFF)", gate.ErrorBody{}}, errs(503)[0]},
		serve: func(s *Server) http.HandlerFunc { return s.getClearance },
	},
	{
		Method: "GET", Path: "/v1/clearances/{change_id}/wait", OperationID: "waitClearance", Auth: AuthBearer,
		MaxBody: DefaultMaxBody, LongPoll: true,
		Summary: "Long-poll a change: the same answer as getClearance, returned as soon as the change's state is not " +
			"`state` (default: its state when the call arrived), or after `timeout` seconds (1 to 60, default 30) " +
			"with changed false. For any subject kind; the same callers as getClearance. The core is the one writer, " +
			"so it wakes the call on the write itself (an in-process notifier), never by polling the database.",
		Query: []QueryParam{
			{Name: "state", Description: "the state the caller last saw: answer at once if the change is in another"},
			{Name: "timeout", Description: "seconds to hold the call, 1 to 60 (default 30)", Integer: true},
		},
		Responses: []Response{{200, "the change, its token, and whether it changed", WaitAnswer{}},
			{400, "a timeout or state that is not valid", ErrorResponse{}}, errs(401)[0], errs(403)[0],
			{404, "no such change, or a Clearance that keeps no changes (DG-OFF)", gate.ErrorBody{}},
			{503, "the store could not be read, or too many calls are waiting", ErrorResponse{}}},
		serve: func(s *Server) http.HandlerFunc { return s.waitClearance },
	},
	{
		Method: "POST", Path: "/v1/clearances/{change_id}/outcome", OperationID: "recordChangeOutcome", Auth: AuthBearer,
		MaxBody: gate.MaxOutcomeBody,
		Summary: "The outcome of a cleared terraform-plan change's apply, once, from the principal that registered " +
			"the change: whether it ran, the sha256 of the plan file applied, the resources from the apply's JSON log, " +
			"when it started and finished, and its error. Recorded as deploy.outcome with matched (verified: the " +
			"applied digest is the cleared one); a mismatch is also a deploy.exception of kind digest-mismatch. A " +
			"second outcome is DG-STATE.",
		Request: gate.OutcomeRequest{},
		Responses: []Response{{200, "the change with its outcome, and the records' seqs", gate.OutcomeResult{}},
			{400, "a malformed body, or a change that is not a terraform-plan (DG-SUBJECT)", gate.ErrorBody{}},
			errs(401)[0], {403, "the caller did not register this change", gate.ErrorBody{}},
			{404, "no such change, or a Clearance that keeps no changes (DG-OFF)", gate.ErrorBody{}},
			{409, "the change is not cleared, or its outcome is already recorded (DG-STATE)", gate.ErrorBody{}},
			errs(413)[0]},
	},
	{
		Method: "POST", Path: "/v1/clearances/{change_id}/clear", OperationID: "clearChange", Auth: AuthBearer,
		MaxBody: gate.MaxPersonBody,
		Summary: "A person (or a delegate naming one in the on-behalf-of header) approves a holding change. The body is " +
			"empty or {\"reason\": string}: a note recorded on deploy.clear as claimed." + personWrite,
		RequestNote: `{"reason"?: string}`,
		Responses:   append([]Response{{200, "the change and the record's seq", gate.Decided{}}}, gateErrs...),
	},
	{
		Method: "POST", Path: "/v1/clearances/{change_id}/deny", OperationID: "denyChange", Auth: AuthBearer,
		MaxBody:     gate.MaxPersonBody,
		Summary:     "A person who could clear a holding change denies it, with a reason." + personWrite,
		RequestNote: `{"reason": string}`,
		Responses:   append([]Response{{200, "the change and the record's seq", gate.Decided{}}}, gateErrs...),
	},
	{
		Method: "POST", Path: "/v1/breakglass", OperationID: "openBreakglass", Auth: AuthBearer,
		MaxBody: gate.MaxBreakglassBody,
		Summary: "An admin (CLEARANCE_ADMINS), or a delegate naming one in the on-behalf-of header, opens a " +
			"break-glass window on one protected environment: a reason, a TTL (a Go duration, at most " +
			"CLEARANCE_BREAKGLASS_MAX_TTL, never over 4h) and the cluster and env. Recorded as breakglass.open and " +
			"committed before the answer, so the record precedes every change it covers. It clears nothing; " +
			"exceptions inside it carry its id. At the TTL the core reconciles it (breakglass.close)." + personWrite,
		Request: gate.BreakglassRequest{},
		Responses: []Response{{200, "the open window", gate.Breakglass{}},
			{400, "a malformed body, a TTL out of range, or an environment that is not protected", gate.ErrorBody{}},
			freshErr, {403, "not an admin, or a delegate naming no admin", gate.ErrorBody{}},
			{404, "a Clearance that keeps no changes (DG-OFF)", gate.ErrorBody{}},
			{409, "a window is already open on that environment", gate.ErrorBody{}}, errs(413)[0]},
	},
	{
		Method: "POST", Path: "/v1/breakglass/{id}/close", OperationID: "closeBreakglass", Auth: AuthBearer,
		MaxBody: gate.MaxPersonBody,
		Summary: "An admin closes a break-glass window early; it is reconciled at once (breakglass.close lists what " +
			"the record store knows changed in the window)." + personWrite,
		Responses: []Response{{200, "the closed window", gate.Breakglass{}}, freshErr,
			{403, "not an admin", gate.ErrorBody{}}, {404, "no such window", gate.ErrorBody{}},
			{409, "the window is already closed", gate.ErrorBody{}}},
	},
	{
		Method: "POST", Path: "/v1/observations/{seq}/resolution", OperationID: "setObservationResolution", Auth: AuthBearer,
		MaxBody: gate.MaxResolutionBody,
		Summary: "A person (an admin, CLEARANCE_ADMINS, or a delegate naming one in the on-behalf-of header) sets how an " +
			"observed change ended: state (reverted, ratified, declared-break-glass, still-live) and, for reverted, its " +
			"cause (agent-caused, policy-triggered, human-initiated, automated-remediation, requirement-changed, " +
			"external-dependency, unattributed), with an optional note. Recorded as a resolution record about the " +
			"observation, naming the person (principal, initiator, resolution.by). Append-only: an edit is another " +
			"record about the same seq, and the newest wins when it is read; the earlier ones stay in the chain. The seq may " +
			"also be a gate exception (deploy.exception of kind out-of-band, drift, untraced-apply or digest-mismatch), " +
			"resolved in the scope of its destination (cluster, else workspace backend/key#name); attempted-refused and " +
			"monitoring-protection exceptions are not resolved this way." + personWrite,
		Request: gate.ResolutionRequest{},
		Responses: []Response{{200, "the record written, naming the person", gate.ResolutionRecorded{}},
			{400, "a state or cause outside the vocabulary, or a body that is not {state, cause?, note?}", gate.ErrorBody{}},
			freshErr, {403, "not an admin, or a delegate naming none", gate.ErrorBody{}},
			{404, "no such observation (the seq is neither an observation nor a resolvable gate exception), or a Clearance that keeps no changes (DG-OFF)", gate.ErrorBody{}},
			errs(413)[0]},
	},
	{
		Method: "POST", Path: "/v1/observations/resolutions", OperationID: "setObservationResolutions", Auth: AuthBearer,
		MaxBody: gate.MaxBulkResolutionBody,
		Summary: "Bulk resolution: a person (an admin, CLEARANCE_ADMINS, or a delegate naming one in the on-behalf-of " +
			"header) resolves up to 200 observations or gate exceptions at once with the same state, cause and note as " +
			"POST /v1/observations/{seq}/resolution. Each item gets a resolution record of its own, exactly as the " +
			"single route writes it (about that seq, naming the person), never one record for many; every record of the " +
			"call carries the same resolution.batch {id, size}. The records are written in one transaction. The answer " +
			"names the batch and, for each item, the record written (recorded), why it was skipped (skipped: not an " +
			"observation or a resolvable exception, a seq named twice, or its newest resolution already has the same " +
			"state, cause and note) or why its record was refused (failed). The same validation as the single route: a " +
			"state or cause outside the vocabulary, or reverted without a cause, refuses the whole call with 400." + personWrite,
		Request: gate.BulkResolutionRequest{},
		Responses: []Response{{200, "the batch id and each item's outcome", gate.BulkResolutionResult{}},
			{400, "no items, more than 200, a state or cause outside the vocabulary, or a body that is not {items, state, cause?, note?}", gate.ErrorBody{}},
			freshErr, {403, "not an admin, or a delegate naming none", gate.ErrorBody{}},
			{404, "a Clearance that keeps no changes (DG-OFF)", gate.ErrorBody{}},
			errs(413)[0]},
	},
	{
		Method: "GET", Path: "/v1/breakglass", OperationID: "listBreakglass", Auth: AuthBearer,
		MaxBody: DefaultMaxBody,
		Summary: "The break-glass windows open now (?cluster= narrows them), for a registered provider that honours " +
			"break-glass and for admins.",
		Responses: []Response{{200, "the open windows", BreakglassList{}}, errs(400)[0], errs(401)[0], errs(403)[0],
			{404, "a Clearance that keeps no changes", ErrorResponse{}}, errs(503)[0]},
		serve: func(s *Server) http.HandlerFunc { return s.listBreakglass },
	},
	{
		Method: "GET", Path: "/v1/keys", OperationID: "getKeys", Auth: AuthNone, MaxBody: DefaultMaxBody,
		Summary: "The clearance token verification keys, a JWKS (EC P-256, ES256, kid = the RFC 7638 thumbprint): the " +
			"key in use and keys retired within the last 24 hours. Public: a verifier checks tokens offline with it.",
		Responses: append([]Response{{200, "the key set", token.JWKS{}}}, errs(503)...),
		serve:     func(s *Server) http.HandlerFunc { return s.keys },
	},
	{
		Method: "POST", Path: "/v1/definitions/review", OperationID: "reviewDefinition", Auth: AuthBearer,
		MaxBody: review.MaxBody,
		Summary: "Would Clearance load this agent definition, and how much more may its agent do than before " +
			"(definition-change tier). Stateless and unrecorded.",
		RequestNote: "{doc, old?, name?, owner?, path?}: the definition, the one it replaces, and its pin",
		Responses:   append([]Response{{200, "the review", review.Result{}}}, errs(400, 401, 403, 413)...),
	},
	{
		Method: "POST", Path: "/v1/provenance", OperationID: "verifyProvenance", Auth: AuthBearer,
		MaxBody: provenance.MaxBody,
		Summary: "The agent-identity and agent-scope verdicts for a pull request, from the receipts Clearance " +
			"recorded; the caller is a verifier. Recorded as provenance.verify.",
		RequestNote: "provenance.Request: {repo, pr, head, paths, author?, trailers?, coauthors?: [{commit, trailer}], merged?, mergedBy?, mergedByBot?}",
		Responses:   append([]Response{{200, "the verdicts", provenance.Verdict{}}}, errs(400, 401, 403, 413)...),
	},
	{
		Method: "POST", Path: "/v1/packets", OperationID: "publishPacket", Auth: AuthBearer, MaxBody: MaxPacketBody,
		Summary: "An admin (CLEARANCE_ADMINS, or a delegate naming one) publishes an evidence packet the packet job wrote, as a " +
			"bundle (the packet directory as one JSON document). The core checks every file against the manifest, that the packet " +
			"was read from this chain (its head is the hash the core holds at that count), and keeps it. The packet's id is " +
			"the content's address (pk- and the first 32 hex digits of the SHA-256 of MANIFEST.json): the same packet again is the " +
			"same id and records nothing; a new one is one packet.publish record.",
		RequestNote: "packet.Bundle: {schema: clearance.packet-bundle/v1, files: {path: base64}} (`clearance packet publish` makes it)",
		Responses: append([]Response{{200, "the packet's id and digest, and whether it was new", PacketPublished{}}},
			errs(400, 401, 403, 404, 409, 413, 503)...),
		serve: func(s *Server) http.HandlerFunc { return s.publishPacket },
	},
	{
		Method: "POST", Path: "/v1/packets/{id}/deliveries", OperationID: "deliverPacket", Auth: AuthBearer, MaxBody: MaxDeliveryBody,
		Summary: "An admin opens a published packet to one registered assurance provider (a recipient) for a window, scoped to " +
			"parts of it (summary, evidence). The delivery is a packet.deliver record naming the person, the recipient, the scope and the " +
			"window; the answer carries the time-boxed credential the recipient presents to GET /v1/packets/{id}: once, never stored. " +
			"The subscriber hands it over; Clearance submits nothing to anyone.",
		Request:   DeliveryRequest{},
		Responses: append([]Response{{200, "the delivery and its credential", Delivery{}}}, errs(400, 401, 403, 404, 413, 503)...),
		serve:     func(s *Server) http.HandlerFunc { return s.deliverPacket },
	},
	{
		Method: "GET", Path: "/v1/packets/{id}", OperationID: "getPacket", Auth: AuthCredential, MaxBody: DefaultMaxBody,
		Summary: "The recipient reads the packet (the bundle) under the credential its delivery returned, in the bearer header. " +
			"No Clearance account. The credential is checked for its signature (anything the core did not sign is a bare 401); " +
			"then every answer is a packet.fetch record, written before the answer: an allowed read before a byte is served, and a " +
			"refusal (PK-EXPIRED, PK-NOT-YET, PK-SCOPE for another packet or a part outside its scope, PK-RECIPIENT, PK-GONE) with its rule.",
		Query: []QueryParam{{Name: "part", Description: "read one part of the packet (summary or evidence); it must be in the credential's scope"}},
		Responses: []Response{{200, "the bundle (cut to the credential's scope)", PacketBundle{}},
			{400, "an unknown query parameter or part", ErrorResponse{}},
			{401, "no credential, one the core did not issue, or an expired one (PK-EXPIRED)", PacketError{}},
			{403, "another packet, a part outside the scope, not yet good, or a recipient no longer registered", PacketError{}},
			{404, "the core does not hold the packet", PacketError{}},
			{429, "this delivery has been refused too often this hour (the refusals past the cap are not recorded)", PacketError{}},
			errs(503)[0]},
		serve: func(s *Server) http.HandlerFunc { return s.getPacket },
	},
	{
		Method: "GET", Path: "/v1/packets/{id}/sample", OperationID: "getPacketSample", Auth: AuthCredential, MaxBody: DefaultMaxBody,
		Summary: "The recipient draws a sample of the packet's cleared changes (P-2) under the same credential as GET /v1/packets/{id}, " +
			"which must carry both parts (summary and evidence). The sample is reproducible: the same packet, seed, n and stratify give " +
			"the same changes, and the response states the rule and the effective seed. Each sampled change comes with its clear record " +
			"and an inclusion proof against the packet's checkpoint; the population (every change of the packet, with why any is not " +
			"eligible) is printed with it, with its SHA-256. Without a seed the core's default is used (a function of the packet alone); " +
			"a supplied seed is the recipient's choice and is recorded. The sampling is a packet.sample record written before the " +
			"answer; asking again for the same sample is served from that record and writes nothing. `clearance verify --sample` checks " +
			"the result offline. A refusal is a packet.sample record with its rule, as a refused read is.",
		Query: []QueryParam{
			{Name: "n", Description: "the sample size, 1 to 100 (default 25); at most the number of eligible changes", Integer: true},
			{Name: "seed", Description: "up to 64 letters, digits, dots, underscores or hyphens; omitted, the default seed is used"},
			{Name: "stratify", Description: "none (uniform, the default) or tier-month (proportional by tier and the month of the change's first record)"}},
		Responses: []Response{{200, "the sample document (clearance.packet-sample/v1)", sampling.Document{}},
			{400, "an unknown, repeated or out-of-range query parameter, or n above the eligible changes", ErrorResponse{}},
			{401, "no credential, one the core did not issue, or an expired one (PK-EXPIRED)", PacketError{}},
			{403, "another packet, a credential without both parts, not yet good, or a recipient no longer registered", PacketError{}},
			{404, "the core does not hold the packet", PacketError{}},
			{409, "the packet stood on no witnessed checkpoint, so nothing in it has an inclusion proof", ErrorResponse{}},
			{429, "the delivery has been read, refused or sampled too often (the caps: reads per hour, refusals per hour, 20 distinct samples); nothing past a cap is recorded", PacketError{}},
			errs(503)[0]},
		serve: func(s *Server) http.HandlerFunc { return s.getSample },
	},
	{
		Method: "POST", Path: "/v1/packets/{id}/receipts", OperationID: "acceptReceipt", Auth: AuthRecipientKey, MaxBody: receipt.MaxEnvelopeBytes,
		Summary: "The recipient's acceptance receipt: a DSSE envelope (application/vnd.clearance.acceptance-receipt.v1+json) signed " +
			"with a key the recipient registered, naming the packet, the delivery, the engagement, the framework and mapping versions, " +
			"the checkpoint, the verdict (accepted, accepted-with-notes, questioned, rejected) and control notes keyed to the mapping's " +
			"rows. The signature is the authentication. The core checks the key, the delivery and that the receipt binds this packet's " +
			"digest, mappings and checkpoint, then records it (packet.receipt). A later packet carries it in its Acceptances section.",
		RequestNote: "a DSSE envelope: {payloadType, payload (base64 of the receipt), signatures: [{keyid, sig}]} (`clearance receipt sign` makes it)",
		Responses:   append([]Response{{200, "the record", ReceiptRecorded{}}}, errs(400, 403, 404, 413, 503)...),
		serve:       func(s *Server) http.HandlerFunc { return s.acceptReceipt },
	},
	{
		Method: "POST", Path: "/v1/github/webhook", OperationID: "githubWebhook", Auth: AuthSignature,
		MaxBody:     githubapp.MaxWebhookBody,
		Summary:     "The Clearance GitHub App's webhook: verified by its signature, queued, answered at once.",
		RequestNote: "a GitHub webhook payload (X-GitHub-Event names it)",
		Responses: []Response{
			{200, "ignored", WebhookAnswer{}}, {202, "queued", WebhookAnswer{}},
			{401, "a bad signature", WebhookAnswer{}}, {404, "this Clearance runs no GitHub App", ErrorResponse{}},
			{413, "the body is over the route's cap", ErrorResponse{}}, {503, "the queue is full", WebhookAnswer{}},
		},
	},
	{
		Method: "POST", Path: hcprun.Path, OperationID: "hcpRunTask", Auth: AuthHCP,
		MaxBody: hcprun.MaxBody,
		Summary: "An HCP Terraform run task (G-TF-6): verified by its HMAC-SHA512 signature (X-TFC-Task-Signature), the " +
			"plan JSON is read with the run's access token, the plan is registered as a terraform-plan change, and the " +
			"run task's result is reported to HCP Terraform (running, then passed or failed). Answered 200 at once.",
		RequestNote: "an HCP Terraform run task payload, payload_version 1 (stage post_plan or pre_apply carries plan_json_api_url)",
		Responses: []Response{
			{200, "accepted (or verified: HCP Terraform's check of the URL)", RunTaskAnswer{}},
			{400, "a payload the adapter refuses, or a URL that is not on the configured HCP Terraform host", RunTaskAnswer{}},
			{401, "a bad signature, or an organization that is not configured", RunTaskAnswer{}},
			{404, "this Clearance runs no HCP Terraform run task", ErrorResponse{}},
			{413, "the body is over the route's cap", ErrorResponse{}},
			{503, "busy, or the HMAC key is unreadable: HCP Terraform retries", RunTaskAnswer{}},
		},
	},
}

// RunTaskAnswer is the run task route's body: {"result": "accepted" | "verified" | ..., "reason"?}.
type RunTaskAnswer = hcprun.Answer

// WebhookAnswer is the webhook's body: {"result": "queued" | "ignored" | ...}.
type WebhookAnswer struct {
	Result string `json:"result"`
}
