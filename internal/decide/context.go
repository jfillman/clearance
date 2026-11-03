package decide

import (
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

var errOverflow = &EvalError{Class: ErrClassValue, Err: errors.New("overflow")}

func celInt(i Int) (ref.Val, error) {
	n, ok := i.Small()
	if !ok {
		return nil, errOverflow // celpy.json_to_cel: ValueError('overflow')
	}
	return types.Int(n), nil
}

// noneOrEmpty is Python's `v in (None, "", [])`.
func noneOrEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	}
	return false
}

func asString(v any, ok bool) (string, bool) {
	if !ok {
		return "", false
	}
	s, isStr := v.(string)
	return s, isStr
}

// tierOf parses a Tier name (T0-T3).
func tierOf(name string) (int, bool) {
	switch name {
	case "T0":
		return 0, true
	case "T1":
		return 1, true
	case "T2":
		return 2, true
	case "T3":
		return 3, true
	}
	return 0, false
}

// buildContext is Policy.build_context: the CEL activation for one tool call, and each bundle's document findings.
func (e *Engine) buildContext(req *EvaluationRequest, args *pycompat.Map) (*activation, *CallInput, [][][]Problem, error) {
	tool := req.Resource.ID
	s := req.Context.Session
	sc := req.Context.Scope
	if sc == nil {
		sc = &Scope{AgentKind: "task"}
	}
	spec := e.b.tools[tool]
	in := &CallInput{Tool: tool, Spec: spec, Args: args, Session: s, Scope: sc, Globs: e.globs}
	if len(sc.Profile) > 0 {
		p, err := pycompat.DecodeJSON(sc.Profile)
		if err != nil {
			return nil, in, nil, &EvalError{Class: ErrClassValue, Err: err}
		}
		in.Profile = p
	}

	var files []any
	if v, ok := args.GetStr("files"); ok {
		if l, isList := v.([]any); isList {
			files = l
		}
	}
	var paths []any
	for _, f := range files {
		if fm, ok := f.(*pycompat.Map); ok {
			p, found := fm.GetStr("path")
			if !found {
				p = ""
			}
			paths = append(paths, p)
		}
	}
	repo, hasRepoStr := asString(args.GetStr("repo"))
	missing := 0
	if spec != nil {
		for _, a := range spec.RequiredArgs {
			if v, ok := args.GetStr(a); !ok || noneOrEmpty(v) {
				missing++
			}
		}
		if spec.WritesFiles && len(paths) == 0 {
			missing++
		}
	}
	service, hasService := asString(args.GetStr("service"))
	rawPath, pathPresent := args.GetStr("path")
	apiPath, hasAPIPath := asString(rawPath, pathPresent)
	if tool == "repo.file.get" {
		if (pathPresent && !hasAPIPath) || (hasAPIPath && (strings.HasPrefix(apiPath, "/") ||
			slices.Contains(strings.Split(apiPath, "/"), "..") || strings.Contains(apiPath, "\\"))) {
			missing++
		}
	}
	if tool == "app.api.get" && (!hasAPIPath || !strings.HasPrefix(apiPath, "/") || strings.Contains(apiPath, "..") ||
		strings.ContainsAny(apiPath, "?#\\")) {
		missing++
	}

	ceiling, ok := tierOf(s.Limits.TierCeiling)
	if !ok {
		return nil, in, nil, &EvalError{Class: ErrClassValue, Err: errors.New("bad tier ceiling")}
	}
	effTier := min(ceiling, req.Subject.Properties.TierCeiling)
	tierVal := 0
	if spec != nil {
		tierVal = spec.Tier
	}
	acting := req.Subject.ID
	if req.Subject.Properties.ActingAs != "" {
		acting = req.Subject.Properties.ActingAs
	}

	pathViolations, fieldViolations := 0, 0
	if len(paths) > 0 {
		pathViolations = e.globs.PathViolations(paths, sc.DenyPaths)
	}
	if len(files) > 0 {
		n, err := e.fileFieldViolations(files, sc.FieldDeny, sc.FieldAllow)
		if err != nil {
			return nil, in, nil, err
		}
		fieldViolations = n
	}
	artifactBytes := 0
	if tool == "artifact.put" {
		if c, ok := asString(args.GetStr("content")); ok {
			artifactBytes = pycompat.Len(c)
		}
	}

	act := &activation{slots: e.b.slots, vals: make([]ref.Val, len(e.b.slots))}
	v := act.vals
	v[vToolName] = types.String(tool)
	v[vToolTier] = types.Int(tierVal)
	v[vToolProposeOnly] = types.Bool(spec != nil && spec.ProposeOnly)
	tools := append([]string(nil), s.Limits.Tools...)
	sort.Strings(tools)
	v[vEffTools] = types.NewStringList(types.DefaultTypeAdapter, tools)
	v[vEffTier] = types.Int(effTier)
	v[vSessExpired] = types.Bool(s.expired(req.Context.Now))
	v[vSessTripped] = types.Bool(s.Tripped)
	var err error
	for _, b := range [...]struct {
		slot  int
		field string
	}{{vSessToolCallsLeft, "tool_calls"}, {vSessGithubLeft, "github_calls"}, {vSessPRsLeft, "open_prs"}} {
		if v[b.slot], err = celInt(s.remaining(b.field)); err != nil {
			return nil, in, nil, err
		}
	}
	cost := int64(0)
	if spec != nil {
		cost = spec.GithubCost
	}
	v[vCostGithub] = types.Int(cost)
	prs := 0
	if e.b.prTools[tool] {
		prs = 1
	}
	v[vCostPRs] = types.Int(prs)
	v[vOwnsSession] = types.Bool(s.Principal == acting)
	v[vTripwire] = types.Bool(e.b.tripwires[tool])
	v[vKnown] = types.Bool(spec != nil)
	v[vTargetMismatch] = types.Bool(spec != nil && spec.Target == "lower" && e.envTierOf(spec, args) == "upper")
	v[vHasRepo] = types.Bool(hasRepoStr && spec != nil && (spec.WritesFiles || spec.ReadsRepo))
	v[vRepoOK] = types.Bool(repo == "" || e.globs.RepoAllowed(repo, sc.ReposAllow))
	v[vPathViolations] = types.Int(pathViolations)
	v[vFieldViolations] = types.Int(fieldViolations)
	v[vHasService] = types.Bool(tool == "app.api.get" && hasService)
	v[vServiceOK] = types.Bool(service == "" || slices.Contains(sc.APIAllow, service))
	v[vIsChat] = types.Bool(tool == "chat.recv" || tool == "chat.send")
	v[vArtifactBytes] = types.Int(artifactBytes)
	v[vSessionKind] = types.Bool(sc.AgentKind == "session")

	states := make([][][]Problem, len(e.b.bundles))
	for i, cb := range e.b.bundles {
		bad, probs, err := e.bundleContext(cb, in, files, v)
		if err != nil {
			return nil, in, nil, err
		}
		missing += bad
		states[i] = probs
	}
	v[vMissingArgs] = types.Int(missing)
	return act, in, states, nil
}

// fileFieldViolations is policy._file_field_violations (AF-9a).
func (e *Engine) fileFieldViolations(files []any, deny, allow []string) (int, error) {
	if len(deny) == 0 && len(allow) == 0 {
		return 0, nil
	}
	total := 0
	for _, f := range files {
		fm, ok := f.(*pycompat.Map)
		if !ok {
			continue
		}
		before, ok1 := asString(fm.GetStr("before"))
		content, ok2 := asString(fm.GetStr("content"))
		if !ok1 || !ok2 {
			continue
		}
		b, err := pyyaml.SafeLoad(before)
		if err == nil {
			var a any
			a, err = pyyaml.SafeLoad(content)
			if err == nil {
				if !container(b) || !container(a) {
					continue
				}
				ptrs := scope.DiffPointers(b, a)
				total += e.globs.FieldViolations(ptrs, deny) + e.globs.FieldOutsideAllow(ptrs, allow)
				continue
			}
		}
		var ye *pyyaml.Error
		if errors.As(err, &ye) {
			continue // a file that does not parse is not one field scope reasons about
		}
		return 0, err
	}
	return total, nil
}

func container(v any) bool {
	switch v.(type) {
	case *pycompat.Map, []any:
		return true
	}
	return false
}

// CallInput is what a bundle's context sees of one tool call.
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

// ctxActivation is the context expressions' variables for one call.
type ctxActivation struct{ vals []ref.Val }

var ctxSlotOf = func() map[string]int {
	m := map[string]int{}
	for i, n := range ctxVarNames {
		m[n] = i
	}
	return m
}()

func (a *ctxActivation) ResolveName(name string) (any, bool) {
	i, ok := ctxSlotOf[name]
	if !ok {
		return nil, false
	}
	return a.vals[i], true
}

func (a *ctxActivation) Parent() interpreter.Activation { return nil }

// varActivation adds a bundle's computed vars (ctx.<name>) to the call's.
type varActivation struct {
	base  *ctxActivation
	names map[string]int
	vals  []ref.Val
}

func (a *varActivation) ResolveName(name string) (any, bool) {
	if i, ok := a.names[name]; ok && a.vals[i] != nil {
		return a.vals[i], true
	}
	return a.base.ResolveName(name)
}

func (a *varActivation) Parent() interpreter.Activation { return nil }

func evalCtx(p *ctxProgram, act interpreter.Activation) (ref.Val, error) {
	out, _, err := p.prg.Eval(act)
	if err != nil {
		return nil, &EvalError{Class: ErrClassCEL, Err: err}
	}
	if types.IsError(out) {
		return nil, &EvalError{Class: ErrClassCEL, Err: fmt.Errorf("%v", out)}
	}
	return out, nil
}

// callActivation is the context expressions' view of a call.
func callActivation(in *CallInput) *ctxActivation {
	vals := make([]ref.Val, nCtx)
	vals[cvToolName] = types.String(in.Tool)
	vals[cvToolKnown] = types.Bool(in.Spec != nil)
	tier, wf, rr := 0, false, false
	if in.Spec != nil {
		tier, wf, rr = in.Spec.Tier, in.Spec.WritesFiles, in.Spec.ReadsRepo
	}
	vals[cvToolTier] = types.Int(tier)
	vals[cvToolWritesFiles] = types.Bool(wf)
	vals[cvToolReadsRepo] = types.Bool(rr)
	vals[cvArgs] = toCEL(in.Args)
	vals[cvProfile] = toCEL(in.Profile)
	return &ctxActivation{vals: vals}
}

// bundleContext computes one bundle's vars (into the rules' activation), its bad-argument count and its
// documents' findings for a call.
func (e *Engine) bundleContext(cb *compiledBundle, in *CallInput, files []any, v []ref.Val) (int, [][]Problem, error) {
	base := callActivation(in)
	act := &varActivation{base: base, names: map[string]int{}, vals: make([]ref.Val, len(cb.vars))}
	for i, p := range cb.vars {
		out, err := evalCtx(p, act)
		if err != nil {
			return 0, nil, err
		}
		act.vals[i] = out
		act.names["ctx."+cb.b.Spec.Vars[i].Name] = i
		v[cb.varSlots[i]] = out
	}
	bad := 0
	for _, g := range cb.argChecks {
		w, err := evalCtx(g.when, act)
		if err != nil {
			return 0, nil, err
		}
		if w != types.True {
			continue
		}
		for _, c := range g.checks {
			out, err := evalCtx(c, act)
			if err != nil {
				return 0, nil, err
			}
			if out == types.True {
				bad++
			}
		}
	}
	probs := make([][]Problem, len(cb.b.docs))
	for i, d := range cb.b.docs {
		if len(files) > 0 && in.Spec != nil && in.Spec.WritesFiles {
			found, err := d.Problems(files)
			if err != nil {
				return 0, nil, err
			}
			for _, q := range found {
				probs[i] = append(probs[i], Problem{Pointer: q.Pointer, Rule: q.Rule, Message: q.Message, Hint: q.Hint})
			}
		}
		v[cb.docSlots[i]] = types.Int(len(probs[i]))
	}
	return bad, probs, nil
}

// appOf is the application a call acts on, from the first bundle whose app expression names one.
func (e *Engine) appOf(tool string, args *pycompat.Map) string {
	in := &CallInput{Tool: tool, Spec: e.b.tools[tool], Args: args}
	for _, cb := range e.b.bundles {
		if cb.app == nil {
			continue
		}
		out, err := evalCtx(cb.app, callActivation(in))
		if err != nil {
			continue
		}
		if s, ok := out.(types.String); ok && s != "" {
			return string(s)
		}
	}
	return ""
}
