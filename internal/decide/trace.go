package decide

import (
	"context"

	"github.com/google/cel-go/common/types"
)

// RuleVerdict is one rule's verdict on a call (policy.py Policy.trace): whether its expression matched, or failed to
// evaluate (Error, Matched nil; Decide denies on that, R000).
type RuleVerdict struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Order   int    `json:"order"`
	Matched *bool  `json:"matched"`
	Error   bool   `json:"error"`
}

// Trace is Policy.trace: every rule's verdict on a tool.call evaluation, in evaluation order, the path a call takes
// through the policy. The decision is still Decide's (the first match wins, and a pack may turn a matched rule into
// its own decision); Trace shows which other rules would have matched too. It records nothing and spends nothing:
// clearance-api's dry-run explainer (GET /v1/policy/explain) calls it beside Decide.
//
// A request that is not a valid tool.call, or whose context cannot be built (an argument the policy cannot hold),
// is reported as every rule erroring, as Decide fails such a request closed.
func (e *engine) Trace(ctx context.Context, req *EvaluationRequest) []RuleVerdict {
	out := make([]RuleVerdict, len(e.b.rules))
	for i := range e.b.rules {
		r := &e.b.rules[i]
		out[i] = RuleVerdict{ID: r.ID, Name: r.Name, Order: r.Order, Error: true}
	}
	if req.validate() != nil || req.Action.Name != ActionToolCall || req.Context.Session == nil {
		return out
	}
	args, err := req.argsMap()
	if err != nil {
		return out
	}
	act, _, _, err := e.buildContext(req, args)
	if err != nil {
		return out
	}
	for i := range e.b.rules {
		res, _, err := e.b.rules[i].prg.ContextEval(ctx, act)
		if err != nil {
			continue
		}
		hit, ok := res.(types.Bool)
		if !ok {
			continue
		}
		m := bool(hit)
		out[i].Matched, out[i].Error = &m, false
	}
	return out
}
