package decide

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"

	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/pyyaml"
	"github.com/jfillman/clearance/internal/scope"
)

// Engine decides. It is built once per bundle version (New) and is safe for concurrent use; Decide is a pure
// function of its request.
type Engine struct {
	b     *bundle
	globs *scope.Globs
}

// New compiles the core rules and the deployment's policy bundles into an Engine. A rule or context expression that
// does not compile or type-check, whose result is not of its type, or a rule whose worst-case cost is over
// MaxRuleCost fails the load, as does a tool, rule, context key or bundle registered twice.
func New(opt Options) (*Engine, error) {
	core, err := Core()
	if err != nil {
		return nil, err
	}
	return NewFromData(core, opt)
}

// NewFromData is New with a core rule set other than the embedded one (tests of the load's failure modes).
func NewFromData(core BundleData, opt Options) (*Engine, error) {
	b, err := compileBundle(core, opt)
	if err != nil {
		return nil, err
	}
	return &Engine{b: b, globs: &scope.Globs{}}, nil
}

// Policy names what decides: the core and every bundle, the digest over all of it, and each bundle's own version.
func (e *Engine) Policy() PolicyRef {
	return PolicyRef{Bundle: e.b.name, Version: e.b.version, Bundles: append([]BundleRef(nil), e.b.refs...)}
}

// RuleBundle is the name of the bundle a rule came from, "" for a core rule.
func (e *Engine) RuleBundle(id string) string { return e.b.ruleBundle[id] }

// BundleNames are the loaded bundles' names, in load order.
func (e *Engine) BundleNames() []string {
	out := make([]string, len(e.b.refs))
	for i, r := range e.b.refs {
		out[i] = r.Name
	}
	return out
}

// PRTools are the tools whose receipt is a pull request: the core's and every bundle's.
func (e *Engine) PRTools() []string { return append([]string(nil), e.b.prToolList...) }

// ProfileSections are the definition profile sections whose `apps` list scopes an agent, from the bundles.
func (e *Engine) ProfileSections() []string { return append([]string(nil), e.b.sections...) }

// Tripwires are the T3 tool names no definition may grant.
func (e *Engine) Tripwires() []string {
	out := make([]string, 0, len(e.b.tripwires))
	for t := range e.b.tripwires {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Tools is the registry, core tools then each pack's, in registration order.
func (e *Engine) Tools() []ToolSpec { return append([]ToolSpec(nil), e.b.toolList...) }

// Rules are the compiled rules in evaluation order.
func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.b.rules))
	for i, r := range e.b.rules {
		out[i] = r.Rule
	}
	return out
}

// Tool is a registered tool's spec, or nil.
func (e *Engine) Tool(name string) *ToolSpec { return e.b.tools[name] }

// Globs is the engine's compiled-glob cache.
func (e *Engine) Globs() *scope.Globs { return e.globs }

// R000: anything that fails while deciding is a deny.
const (
	errorRuleID   = "R000"
	errorRuleName = "policy-error"
	errorMessage  = "the policy could not be evaluated"
	errorHint     = "This is a platform fault, not something to retry around. It fails closed."
)

// Error classes in R000's message. The Python engine writes type(e).__name__; the Go engine writes the name of
// the Python exception the same failure raises there, so the evidence reads the same whichever engine decided.
const (
	ErrClassCEL   = "CELEvalError" // a rule failed to evaluate (a wrong type, the cost limit)
	ErrClassValue = "ValueError"   // a value the policy cannot hold (an integer outside int64, a bad YAML timestamp)
)

// EvalError is an evaluation failure, named by its Python class.
type EvalError struct {
	Class string
	Err   error
}

func (e *EvalError) Error() string { return e.Class + ": " + e.Err.Error() }
func (e *EvalError) Unwrap() error { return e.Err }

func classOf(err error) string {
	var ee *EvalError
	if errors.As(err, &ee) {
		return ee.Class
	}
	var ve *pyyaml.ValueError
	if errors.As(err, &ve) {
		return ErrClassValue
	}
	return ErrClassCEL
}

func failClosed(err error) Decision {
	return Decision{Rule: errorRuleID, Name: errorRuleName, Message: errorMessage + ": " + classOf(err), Hint: errorHint}
}

func intp(n int) *int { return &n }

// Decide is the decision for one evaluation. It never fails: an invalid request or an evaluation error is a deny
// (R000), so a caller that acts on the response fails closed.
func (e *Engine) Decide(ctx context.Context, req *EvaluationRequest) *EvaluationResponse {
	var d Decision
	var sp Spend
	var g *Grant
	if err := req.validate(); err != nil {
		d = failClosed(&EvalError{Class: ErrClassValue, Err: err})
	} else {
		switch req.Action.Name {
		case ActionToolCall:
			d, sp = e.toolCall(ctx, req)
		case ActionSessionSpawn:
			d, sp, g = e.spawn(ctx, req)
		case ActionSessionOpen:
			d, g = e.open(req)
		case ActionModelCall:
			d, sp = e.model(req)
		}
	}
	return &EvaluationResponse{Decision: d.Allow, Context: DecisionContext{
		Rule: d.Rule, Name: d.Name, Message: d.Message, Hint: d.Hint, Tier: d.Tier, Problems: d.Problems,
		Spend: sp, Grant: g, Policy: e.Policy(),
	}}
}

// denialSpend is Session.record_denial (and, for a tripwire, store.trip) as spend.
func denialSpend(s *SessionState, rule, tool string) Spend {
	sp := Spend{Denial: true}
	if n := s.Denials + 1; n >= denialTrip && !s.Tripped {
		sp.Trip = fmt.Sprintf("%d denied calls", n)
	}
	if rule == "R002" {
		sp.TripTree = "tripwire: " + tool
		if sp.Trip == "" && !s.Tripped {
			sp.Trip = sp.TripTree
		}
	}
	return sp
}

// denialTrip is session.DENIAL_TRIP.
const denialTrip = 5

// toolCall is Gateway.call's decision: Policy.build_context then Policy.evaluate.
func (e *Engine) toolCall(ctx context.Context, req *EvaluationRequest) (Decision, Spend) {
	tool := req.Resource.ID
	s := req.Context.Session
	if s == nil {
		return Decision{Rule: "R004", Name: "session-expired", Message: "no such session", Hint: "Open a new session."}, Spend{}
	}
	args, err := req.argsMap()
	if err != nil {
		return failClosed(err), denialSpend(s, errorRuleID, tool)
	}
	d, spec := e.evaluateCall(ctx, req, args)
	if !d.Allow {
		return d, denialSpend(s, d.Rule, tool)
	}
	return d, e.callSpend(tool, spec)
}

func (e *Engine) callSpend(tool string, spec *ToolSpec) Spend {
	sp := Spend{ToolCalls: 1, GithubCalls: spec.GithubCost}
	if e.b.prTools[tool] {
		sp.OpenPRs = 1
	}
	return sp
}

// activation is a call's CEL variables, by slot.
type activation struct {
	slots map[string]int
	vals  []ref.Val
}

func (a *activation) ResolveName(name string) (any, bool) {
	i, ok := a.slots[name]
	if !ok || a.vals[i] == nil {
		return nil, false
	}
	return a.vals[i], true
}

func (a *activation) Parent() interpreter.Activation { return nil }

// evaluateCall builds the context and runs the rules.
func (e *Engine) evaluateCall(ctx context.Context, req *EvaluationRequest, args *pycompat.Map) (Decision, *ToolSpec) {
	act, in, states, err := e.buildContext(req, args)
	if err != nil {
		return failClosed(err), in.Spec
	}
	return e.run(ctx, act, in, states), in.Spec
}

func (e *Engine) run(ctx context.Context, act *activation, in *CallInput, states [][][]Problem) Decision {
	tier := 0
	if t, ok := act.vals[vToolTier].(types.Int); ok {
		tier = int(t)
	}
	for i := range e.b.rules {
		r := &e.b.rules[i]
		out, _, err := r.prg.ContextEval(ctx, act)
		if err != nil {
			return failClosed(&EvalError{Class: ErrClassCEL, Err: err})
		}
		hit, ok := out.(types.Bool)
		if !ok {
			return failClosed(&EvalError{Class: ErrClassCEL, Err: fmt.Errorf("rule %s returned %s", r.ID, out.Type())})
		}
		if !hit {
			continue
		}
		if ref, ok := e.b.problemsOf[r.ID]; ok && in != nil && states != nil {
			if probs := states[ref.bundle][ref.doc]; len(probs) > 0 {
				msgs := make([]string, len(probs))
				for i, q := range probs {
					msgs[i] = q.Message
				}
				return Decision{Rule: probs[0].Rule, Name: r.Name, Message: strings.Join(msgs, "; "),
					Hint: probs[0].Hint, Tier: intp(tier), Problems: probs}
			}
		}
		return Decision{Rule: r.ID, Name: r.Name, Message: r.Message, Hint: r.Hint, Tier: intp(tier)}
	}
	return Decision{Allow: true, Message: "allowed", Tier: intp(tier)}
}

// EvaluateActivation runs the rules over a raw activation shaped like the Python one ({"tool": {...},
// "effective": {...}, "session": {...}, "cost": {...}, "ctx": {...}}), with no context building. It is the
// diagnostic replay of a context the Python tests built or altered by hand; bundle documents' findings do not
// apply. Values are pycompat dict-model values (pycompat.DecodeJSON).
func (e *Engine) EvaluateActivation(ctx context.Context, raw *pycompat.Map) Decision {
	act := &activation{slots: e.b.slots, vals: make([]ref.Val, len(e.b.slots))}
	for i := range raw.Len() {
		k, v := raw.At(i)
		group, ok1 := k.(string)
		m, ok2 := v.(*pycompat.Map)
		if !ok1 || !ok2 {
			continue
		}
		for j := range m.Len() {
			fk, fv := m.At(j)
			name, ok := fk.(string)
			if !ok {
				continue
			}
			slot, ok := e.b.slots[group+"."+name]
			if !ok {
				continue
			}
			cv, err := celValue(fv)
			if err != nil {
				return failClosed(err)
			}
			act.vals[slot] = cv
		}
	}
	d := e.run(ctx, act, nil, nil)
	if !d.Allow && d.Rule != errorRuleID {
		if t, ok := act.vals[vToolTier].(types.Int); ok {
			d.Tier = intp(int(t))
		} else {
			d.Tier = nil
		}
	}
	return d
}

// celValue is celpy.json_to_cel for one value: an integer outside int64 is a ValueError.
func celValue(v any) (ref.Val, error) {
	switch x := v.(type) {
	case nil:
		return types.NullValue, nil
	case bool:
		return types.Bool(x), nil
	case int64:
		return types.Int(x), nil
	case float64:
		return types.Double(x), nil
	case string:
		return types.String(x), nil
	case []any:
		out := make([]ref.Val, len(x))
		for i, e := range x {
			cv, err := celValue(e)
			if err != nil {
				return nil, err
			}
			out[i] = cv
		}
		return types.NewRefValList(types.DefaultTypeAdapter, out), nil
	case *pycompat.Map:
		out := make(map[ref.Val]ref.Val, x.Len())
		for i := range x.Len() {
			k, e := x.At(i)
			ck, err := celValue(k)
			if err != nil {
				return nil, err
			}
			cv, err := celValue(e)
			if err != nil {
				return nil, err
			}
			out[ck] = cv
		}
		return types.NewRefValMap(types.DefaultTypeAdapter, out), nil
	}
	return nil, &EvalError{Class: ErrClassValue, Err: errors.New("overflow")}
}

// envTierOf is policy.env_tier_of: which environment tier the arguments point at, by the deployment's naming.
func (e *Engine) envTierOf(spec *ToolSpec, args *pycompat.Map) string {
	if spec.Target == "none" {
		return "none"
	}
	env := &e.b.env
	if v, ok := args.GetStr("project"); ok {
		if p, ok := v.(string); ok {
			for _, suf := range env.LowerProjectSuffixes {
				if strings.HasSuffix(p, suf) {
					return "lower"
				}
			}
			return "upper"
		}
	}
	if v, ok := args.GetStr("env"); ok {
		if name, ok := v.(string); ok {
			if slices.Contains(env.LowerNames, name) {
				return "lower"
			}
			for _, pre := range env.LowerPrefixes {
				if strings.HasPrefix(name, pre) {
					return "lower"
				}
			}
			return "upper"
		}
	}
	if v, ok := args.GetStr("repo"); ok {
		if repo, ok := v.(string); ok {
			parts := strings.Split(repo, "/")
			for _, pre := range env.UpperRepoPrefixes {
				if strings.HasPrefix(parts[len(parts)-1], pre) {
					return "upper"
				}
			}
			return "lower"
		}
	}
	return spec.Target
}
