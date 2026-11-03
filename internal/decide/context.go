package decide

import (
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/jfillman/clearance/internal/decide/pyval"
	"github.com/jfillman/clearance/internal/decide/pyyaml"
	"github.com/jfillman/clearance/internal/decide/scope"
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

// buildContext is Policy.build_context: the CEL activation for one tool call, and what packs need to decide.
func (e *Engine) buildContext(req *EvaluationRequest, args *pyval.Map) (*activation, *CallInput, []any, error) {
	tool := req.Resource.ID
	s := req.Context.Session
	sc := req.Context.Scope
	if sc == nil {
		sc = &Scope{AgentKind: "task"}
	}
	spec := e.b.tools[tool]
	in := &CallInput{Tool: tool, Spec: spec, Args: args, Session: s, Scope: sc, Globs: e.globs}
	if len(sc.Profile) > 0 {
		p, err := pyval.DecodeJSON(sc.Profile)
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
		if fm, ok := f.(*pyval.Map); ok {
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
			artifactBytes = pyval.Len(c)
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

	states := make([]any, len(e.b.packs))
	for i, p := range e.b.packs {
		pc, err := p.Context(in)
		if err != nil {
			return nil, in, nil, err
		}
		vars := p.Vars()
		if len(pc.Values) != len(vars) {
			return nil, in, nil, &EvalError{Class: ErrClassValue, Err: errors.New("pack context does not match its variables")}
		}
		base := e.b.packBase[i]
		for j, val := range pc.Values {
			switch x := val.(type) {
			case bool:
				v[base+j] = types.Bool(x)
			case int64:
				v[base+j] = types.Int(x)
			case int:
				v[base+j] = types.Int(x)
			default:
				return nil, in, nil, &EvalError{Class: ErrClassValue, Err: errors.New("pack context value is not a bool or int")}
			}
		}
		missing += pc.Bad
		states[i] = pc.State
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
		fm, ok := f.(*pyval.Map)
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
	case *pyval.Map, []any:
		return true
	}
	return false
}
