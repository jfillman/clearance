package decide

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"time"
)

// Action names: the four decisions the gateway asks for.
const (
	ActionToolCall     = "tool.call"     // Gateway.call: policy.build_context + evaluate
	ActionModelCall    = "model.call"    // Gateway.model_authorize: modelproxy.ModelProxy._decide
	ActionSessionOpen  = "session.open"  // Gateway.open_session / open_triggered
	ActionSessionSpawn = "session.spawn" // a run.spawn tool call: the call's rules, then the child (Gateway._spawn)
)

// Resource types.
const (
	ResourceTool  = "tool"
	ResourceModel = "model"
	ResourceAgent = "agent"
)

// EvaluationRequest is an AuthZEN 1.0 Access Evaluation request. Context carries every piece of state the decision
// reads, so the engine holds none.
type EvaluationRequest struct {
	Subject  Subject  `json:"subject"`
	Action   Action   `json:"action"`
	Resource Resource `json:"resource"`
	Context  Context  `json:"context"`

	args parsed // Action.Properties.Args, decoded once
}

// Subject is the authenticated caller.
type Subject struct {
	Type       string            `json:"type"` // "principal"
	ID         string            `json:"id"`   // the principal id records name
	Properties SubjectProperties `json:"properties"`
}

// SubjectProperties are what the authenticator vouches for.
type SubjectProperties struct {
	Kind        string `json:"kind"`                // "user" (a delegated agent's person) or "workload"
	TierCeiling int    `json:"tier_ceiling"`        // 0-3: the principal's own ceiling (Principal.tier_ceiling)
	ActingAs    string `json:"acting_as,omitempty"` // who the caller acts as in the session (a run acts as its session's principal); empty = itself
}

// Action is what the caller asks to do.
type Action struct {
	Name       string           `json:"name"` // one of the Action* constants
	Properties ActionProperties `json:"properties"`
}

// ActionProperties are the action's arguments.
type ActionProperties struct {
	// tool.call and session.spawn: the tool's arguments, a JSON object (hashed into records, never stored).
	Args json.RawMessage `json:"args,omitempty"`
	// model.call: the caller's estimate of the tokens the call will use.
	EstTokens *Int `json:"est_tokens,omitempty"`
	// session.open: the requested limits exactly as sent (absent or null: none).
	Limits json.RawMessage `json:"limits,omitempty"`
	// session.open: the task id asked for.
	TaskID string `json:"task_id,omitempty"`
	// session.open: set when a trigger (schedule, event) opens the session; the subject is then "trigger:<name>".
	Trigger string `json:"trigger,omitempty"`
}

// Resource is what the action is on: a tool (tool.call, session.spawn: run.spawn), a model alias, or an agent
// definition's name (session.open).
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Context is the state the decision reads. The gateway holds it; the engine reads only this.
type Context struct {
	// Now is the decision's clock; the engine never reads one.
	Now time.Time `json:"now"`
	// SessionID is the session the caller named (tool.call, model.call, session.spawn).
	SessionID string `json:"session_id,omitempty"`
	// Session is that session's state (for session.spawn, the parent's). Absent: no such session.
	Session *SessionState `json:"session,omitempty"`
	// Scope is what the session's definition allows (tool.call, session.spawn).
	Scope *Scope `json:"scope,omitempty"`
	// Agent is the definition asked for: session.open's, or session.spawn's child. Absent: no such definition.
	Agent *AgentDef `json:"agent,omitempty"`
	// NewSessionID is the id the caller gives the session this opens (session.open, session.spawn).
	NewSessionID string `json:"new_session_id,omitempty"`
	// Hold is the active hold on the agent's triggers (a triggered session.open).
	Hold *Hold `json:"hold,omitempty"`
	// Live is the live top-level session of this agent and task id, which a triggered session.open dedupes onto.
	Live *SessionState `json:"live,omitempty"`
	// Models is the deployment's model routing (model.call). Absent: the deployment has no model routes.
	Models *Models `json:"models,omitempty"`
}

// SessionState is a session as the gateway holds it (session.Session.to_record's fields that decisions read).
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

// Limits is limits.Limits in its as_dict shape.
type Limits struct {
	TierCeiling string   `json:"tier_ceiling"` // T0-T3
	TTLMinutes  Int      `json:"ttl_minutes"`
	ToolCalls   Int      `json:"tool_calls"`
	GithubCalls Int      `json:"github_calls"`
	OpenPRs     Int      `json:"open_prs"`
	ModelTokens Int      `json:"model_tokens"`
	Children    Int      `json:"children"`
	Tools       []string `json:"tools"`
	Models      []string `json:"models"`
	Network     string   `json:"network"` // none, clearance, clearance+model, allowlist
	Compute     string   `json:"compute"` // small, medium, large, gpu
}

// Budgets are the five budget counters (limits.BUDGET_FIELDS).
type Budgets struct {
	ToolCalls   Int `json:"tool_calls"`
	GithubCalls Int `json:"github_calls"`
	OpenPRs     Int `json:"open_prs"`
	ModelTokens Int `json:"model_tokens"`
	Children    Int `json:"children"`
}

// Scope is what a session's definition allows, beyond its limits.
type Scope struct {
	AgentKind  string   `json:"agent_kind"` // task, team, session, scheduled, event, service
	DenyPaths  []string `json:"deny_paths"`
	ReposAllow []string `json:"repos_allow"`
	APIAllow   []string `json:"api_allow"`
	FieldDeny  []string `json:"field_deny"`
	FieldAllow []string `json:"field_allow"`
	// Profile is the definition's profile as written; a pack reads its own sections (hangar: glidepath.apps,
	// airframe.apps).
	Profile json.RawMessage `json:"profile,omitempty"`
}

// AgentDef is the part of an agent definition a session.open or session.spawn reads.
type AgentDef struct {
	Name           string  `json:"name"`
	Kind           string  `json:"kind"`
	IdentityType   string  `json:"identity_type"` // delegated or workload
	ServiceAccount *string `json:"service_account"`
	Limits         Limits  `json:"limits"`
}

// Hold is an active hold on an agent's triggers (control.Hold).
type Hold struct {
	By     string    `json:"by"`
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
}

// Models is the deployment's model routing.
type Models struct {
	Routes []string `json:"routes"` // the model aliases with a route
}

// EvaluationResponse is the AuthZEN response: the decision, and in context what the caller must know and do.
type EvaluationResponse struct {
	Decision bool            `json:"decision"`
	Context  DecisionContext `json:"context"`
}

// DecisionContext explains the decision.
type DecisionContext struct {
	Rule     string    `json:"rule,omitempty"` // empty on an allow
	Name     string    `json:"name,omitempty"`
	Message  string    `json:"message"`
	Hint     string    `json:"hint,omitempty"`
	Tier     *int      `json:"tier"` // the tool's tier; null for a model call, a session open, an unknown session
	Problems []Problem `json:"problems,omitempty"`
	Spend    Spend     `json:"spend"`
	Grant    *Grant    `json:"grant,omitempty"` // session.open / session.spawn allowed: the session to create
	Policy   PolicyRef `json:"policy"`
}

// Problem is one structured problem behind a decision (GP-SCOPE findings for R021).
type Problem struct {
	Pointer string `json:"pointer"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

// Spend is what the caller must apply to the session named in the request when it acts on this decision.
type Spend struct {
	ToolCalls   int64 `json:"tool_calls,omitempty"`
	GithubCalls int64 `json:"github_calls,omitempty"`
	OpenPRs     int64 `json:"open_prs,omitempty"`
	Children    int64 `json:"children,omitempty"`
	// Reserve is session.spawn's reservation on the parent: the child's budgets (all but children).
	Reserve *Budgets `json:"reserve,omitempty"`
	// Denial: count one denied call (session.denials += 1).
	Denial bool `json:"denial,omitempty"`
	// Trip: trip the session's breaker with this reason (it is not tripped yet).
	Trip string `json:"trip,omitempty"`
	// TripTree: trip the session's descendants with "parent tripped: <TripTree>" (a tripwire call).
	TripTree string `json:"trip_tree,omitempty"`
}

// Grant is the session a session.open or session.spawn creates.
type Grant struct {
	Session   string    `json:"session"`
	TaskID    string    `json:"task_id"`
	Principal string    `json:"principal"`
	Agent     string    `json:"agent"`
	Parent    *string   `json:"parent"`
	Depth     int       `json:"depth"`
	Limits    Limits    `json:"limits"`
	ExpiresAt time.Time `json:"expires_at"`
	Deduped   bool      `json:"deduped,omitempty"` // a triggered open landed on the live session; nothing is created
}

// PolicyRef names the bundle that decided.
type PolicyRef struct {
	Bundle  string `json:"bundle"`
	Version string `json:"version"`
}

// Int is a JSON integer of any size, as Python's int is. Values outside int64 are rare (a budget nobody bounded)
// and kept exactly, so the engine fails closed on them the way the Python engine does.
type Int struct {
	n int64
	b *big.Int // set only when the value is outside int64
}

// I is an Int.
func I(n int64) Int { return Int{n: n} }

// Small is the value and whether it fits int64.
func (i Int) Small() (int64, bool) { return i.n, i.b == nil }

// Big is the value as a *big.Int (a new one).
func (i Int) Big() *big.Int {
	if i.b != nil {
		return new(big.Int).Set(i.b)
	}
	return big.NewInt(i.n)
}

// Value is the value as a pyval integer (int64 or *big.Int).
func (i Int) Value() any {
	if i.b != nil {
		return i.b
	}
	return i.n
}

// Cmp compares two Ints.
func (i Int) Cmp(j Int) int {
	if i.b == nil && j.b == nil {
		switch {
		case i.n < j.n:
			return -1
		case i.n > j.n:
			return 1
		}
		return 0
	}
	return i.Big().Cmp(j.Big())
}

func intFromBig(b *big.Int) Int {
	if b.IsInt64() {
		return Int{n: b.Int64()}
	}
	return Int{b: b}
}

// Sub is i - j exactly.
func (i Int) Sub(j Int) Int {
	if i.b == nil && j.b == nil {
		d := i.n - j.n
		if (i.n >= 0) == (j.n >= 0) || (d >= 0) == (i.n >= 0) {
			return Int{n: d}
		}
	}
	return intFromBig(new(big.Int).Sub(i.Big(), j.Big()))
}

// Add is i + j exactly.
func (i Int) Add(j Int) Int {
	if i.b == nil && j.b == nil {
		s := i.n + j.n
		if (i.n >= 0) != (j.n >= 0) || (s >= 0) == (i.n >= 0) {
			return Int{n: s}
		}
	}
	return intFromBig(new(big.Int).Add(i.Big(), j.Big()))
}

// String is the decimal text.
func (i Int) String() string {
	if i.b != nil {
		return i.b.String()
	}
	return strconv.FormatInt(i.n, 10)
}

var errNotInt = errors.New("decide: not an integer")

// UnmarshalJSON accepts an integer literal only: no fraction, no exponent, not null.
func (i *Int) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || len(data) > 400 {
		return errNotInt
	}
	for k, c := range data {
		if !(c >= '0' && c <= '9' || (k == 0 && c == '-')) {
			return errNotInt
		}
	}
	if n, err := strconv.ParseInt(string(data), 10, 64); err == nil {
		*i = Int{n: n}
		return nil
	}
	b, ok := new(big.Int).SetString(string(data), 10)
	if !ok {
		return errNotInt
	}
	*i = intFromBig(b)
	return nil
}

// MarshalJSON writes the integer.
func (i Int) MarshalJSON() ([]byte, error) { return []byte(i.String()), nil }

// field returns the budget counter named f (a limits.BUDGET_FIELDS name).
func (b *Budgets) field(f string) *Int {
	switch f {
	case "tool_calls":
		return &b.ToolCalls
	case "github_calls":
		return &b.GithubCalls
	case "open_prs":
		return &b.OpenPRs
	case "model_tokens":
		return &b.ModelTokens
	case "children":
		return &b.Children
	}
	return nil
}

func (l *Limits) budget(f string) *Int {
	switch f {
	case "tool_calls":
		return &l.ToolCalls
	case "github_calls":
		return &l.GithubCalls
	case "open_prs":
		return &l.OpenPRs
	case "model_tokens":
		return &l.ModelTokens
	case "children":
		return &l.Children
	}
	return nil
}

// budgetFields is limits.BUDGET_FIELDS, in order.
var budgetFields = [...]string{"tool_calls", "github_calls", "open_prs", "model_tokens", "children"}

// remaining is Session.remaining(f).
func (s *SessionState) remaining(f string) Int {
	return s.Limits.budget(f).Sub(*s.Used.field(f)).Sub(*s.Reserved.field(f))
}

// expired is Session.expired(now).
func (s *SessionState) expired(now time.Time) bool { return s.Closed || !now.Before(s.ExpiresAt) }
