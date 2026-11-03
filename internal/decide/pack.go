package decide

import (
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/scope"
)

// Pack is the policy for a family of tools not every deployment has (pack.py): tools, rules placed among the core
// rules by Order, and the context those rules read. A pack holds policy only; what a tool does is the gateway's.
// Packs are passed to New explicitly; nothing registers itself.
type Pack interface {
	Name() string
	Tools() []ToolSpec
	Rules() []Rule
	// Vars are the ctx.<name> variables Context fills, in order.
	Vars() []Var
	// Data is anything else the pack decides by (vendored contracts); it goes into the bundle version.
	Data() any
	// Context computes the pack's variables for one call, aligned with Vars (bool or int64 each), the bad-argument
	// count it adds to ctx.missing_args (R008), and state its Decide reads. An error fails the call closed (R000).
	Context(in *CallInput) (PackContext, error)
	// Decide turns a matched rule into a structured decision; ok false leaves the rule's own.
	Decide(rule *Rule, in *CallInput, state any) (d Decision, ok bool)
	// AppOf is the application a call acts on, recorded as `app`; "" when it names none.
	AppOf(tool string, args *pycompat.Map) string
}

// PackContext is what a pack's Context returns.
type PackContext struct {
	Values []any
	Bad    int
	State  any
}

// CallInput is what a pack sees of one tool call.
type CallInput struct {
	Tool    string
	Spec    *ToolSpec // nil: not a registered tool
	Args    *pycompat.Map
	Session *SessionState
	Scope   *Scope
	Profile any // Scope.Profile decoded (a *pycompat.Map), nil when absent
	Globs   *scope.Globs
}

// Decision is a rule's verdict, before the engine adds spend and policy.
type Decision struct {
	Allow    bool
	Rule     string
	Name     string
	Message  string
	Hint     string
	Tier     *int
	Problems []Problem
}
