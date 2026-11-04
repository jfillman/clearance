package server

import (
	"net/http"
	"strings"

	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/githubapp"
	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/review"
	"github.com/jfillman/clearance/internal/token"
)

// How a route authenticates its caller.
const (
	AuthNone      = "none"             // /healthz, /readyz
	AuthBearer    = "bearer"           // any principal the Authenticator accepts; the handler decides who may
	AuthProvider  = "provider"         // a bearer token whose principal is a registered provider
	AuthSignature = "github-signature" // the GitHub App's HMAC (X-Hub-Signature-256), no bearer token
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

var gateErrs = []Response{
	{400, "a malformed change or reason", ErrorResponse{}},
	{401, "no bearer token, or one the authenticator refused", ErrorResponse{}},
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
			"definition.unload or definition.reject; provenance then reads the pinned definitions. Only the provider " +
			"registered with definitions: true.",
		Request:   DefinitionsRequest{},
		Responses: append([]Response{{200, "what changed", DefinitionsResult{}}}, errs(400, 401, 403, 404, 413, 503)...),
		serve:     func(s *Server) http.HandlerFunc { return s.definitions },
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
			"resources); unknown fields are refused",
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
		Method: "POST", Path: "/v1/clearances/{change_id}/clear", OperationID: "clearChange", Auth: AuthBearer,
		MaxBody:   gate.MaxPersonBody,
		Summary:   "A person (or a delegate naming one in the on-behalf-of header) approves a holding change.",
		Responses: append([]Response{{200, "the change and the record's seq", gate.Decided{}}}, gateErrs...),
	},
	{
		Method: "POST", Path: "/v1/clearances/{change_id}/deny", OperationID: "denyChange", Auth: AuthBearer,
		MaxBody:     gate.MaxPersonBody,
		Summary:     "A person who could clear a holding change denies it, with a reason.",
		RequestNote: `{"reason": string}`,
		Responses:   append([]Response{{200, "the change and the record's seq", gate.Decided{}}}, gateErrs...),
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
		RequestNote: "provenance.Request: {repo, pr, head, paths, author?, trailers?}",
		Responses:   append([]Response{{200, "the verdicts", provenance.Verdict{}}}, errs(400, 401, 403, 413)...),
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
}

// WebhookAnswer is the webhook's body: {"result": "queued" | "ignored" | ...}.
type WebhookAnswer struct {
	Result string `json:"result"`
}
