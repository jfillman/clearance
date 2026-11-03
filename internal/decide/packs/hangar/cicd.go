package hangar

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"path"
	"strings"

	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/decide/pyval"
	"github.com/jfillman/clearance/internal/decide/pyyaml"
	"github.com/jfillman/clearance/internal/decide/scope"
)

// This file is packs/hangar/cicd.py and its vendored vendor/cicd_scope.py (Glidepath's GP-SCOPE rules), ported:
// the same diff, the same rule lookup, the same messages. The scope data (vendor/glidepath-scope.json) is the
// vendored file byte for byte.

// missing is cicd_scope.MISSING.
type missingT struct{}

var missing = missingT{}

// pyErr is a Python exception the scope check raises; cicd_scope_problems turns it into a whole-file problem
// naming its class.
type pyErr struct{ class string }

func (e *pyErr) Error() string { return e.class }

var (
	errAttr     = &pyErr{"AttributeError"}
	errType     = &pyErr{"TypeError"}
	errOverflow = &pyErr{"OverflowError"}
)

type scopeRule struct {
	Pattern    string `json:"pattern"`
	AgentScope string `json:"agentScope"`
	Why        string `json:"why,omitempty"`
	Order      any    `json:"-"`
	Default    any    `json:"-"`
	hasDefault bool
	segs       []string
}

func mergePatch(target, patch any) any {
	pm, ok := patch.(*pyval.Map)
	if !ok {
		return patch // values are never mutated, so sharing is a deep copy's equal
	}
	var out *pyval.Map
	if tm, ok := target.(*pyval.Map); ok {
		out = tm.Copy()
	} else {
		out = pyval.NewMap(pm.Len())
	}
	for i := range pm.Len() {
		k, v := pm.At(i)
		if v == nil {
			out.Delete(k)
			continue
		}
		cur, _ := out.Get(k)
		out.Set(k, mergePatch(cur, v))
	}
	return out
}

func isCicdYAML(p any) bool {
	n, err := scope.NormalizeAny(p)
	return err == nil && path.Base(n) == "cicd.yaml"
}

func wholeFile(p string, why string) decide.Problem {
	return decide.Problem{Pointer: "", Rule: "GP-SCOPE-001", Message: p + ": " + why,
		Hint: "Send cicd.yaml as YAML (a mapping), with `before` set to its current content, so Clearance can tell which fields change."}
}

// loadIfStr is `yaml.safe_load(x) if isinstance(x, str) else x`.
func loadIfStr(v any) (any, error) {
	if s, ok := v.(string); ok {
		return pyyaml.SafeLoad(s)
	}
	return v, nil
}

// cicdScopeProblems is cicd.cicd_scope_problems. A non-YAML error from the loader (a PyYAML ValueError) is
// returned: the Python raises it uncaught, the Go engine fails closed (R000).
func (p *Pack) cicdScopeProblems(files []any) ([]decide.Problem, error) {
	var problems []decide.Problem
	for _, f := range files {
		fm, ok := f.(*pyval.Map)
		if !ok {
			continue
		}
		pv, _ := fm.GetStr("path")
		if !isCicdYAML(pv) {
			continue
		}
		fp := pv.(string)
		before, _ := fm.GetStr("before")
		content, _ := fm.GetStr("content")
		base, err := loadIfStr(before)
		var head any
		if err == nil {
			head, err = loadIfStr(content)
		}
		if err != nil {
			var ye *pyyaml.Error
			if errors.As(err, &ye) {
				problems = append(problems, wholeFile(fp, "does not parse as YAML"))
				continue
			}
			return nil, err
		}
		if _, isMap := base.(*pyval.Map); base != nil && !isMap {
			problems = append(problems, wholeFile(fp, "the current content (`before`) is not a YAML mapping"))
			continue
		}
		if op, _ := fm.GetStr("op"); op == "merge-patch" {
			if _, isMap := head.(*pyval.Map); !isMap {
				problems = append(problems, wholeFile(fp, "a merge-patch must be a mapping"))
				continue
			}
			b := base
			if !pyval.Truthy(b) {
				b = pyval.NewMap(0)
			}
			head = mergePatch(b, head)
		}
		hm, isMap := head.(*pyval.Map)
		if !isMap {
			problems = append(problems, wholeFile(fp, "the new content is not a YAML mapping"))
			continue
		}
		found, err := p.scopeProblems(base, hm)
		if err != nil {
			var pe *pyErr
			if errors.As(err, &pe) {
				problems = append(problems, wholeFile(fp, fmt.Sprintf("the scope check could not be evaluated (%s)", pe.class)))
				continue
			}
			return nil, err
		}
		for _, q := range found {
			q.Message = fp + ": " + q.Message
			problems = append(problems, q)
		}
	}
	return problems, nil
}

// --- JSON pointers ---------------------------------------------------------------------------

func esc(k any) string {
	return strings.ReplaceAll(strings.ReplaceAll(pyval.Str(k), "~", "~0"), "/", "~1")
}

func segments(pointer string) []string {
	if pointer == "" || pointer == "/" {
		return nil
	}
	parts := strings.Split(strings.TrimLeft(pointer, "/"), "/")
	for i, s := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
	}
	return parts
}

func pointerMatches(pat, ptr []string) bool {
	var gofn func(i, j int) bool
	gofn = func(i, j int) bool {
		if i == len(pat) {
			return true
		}
		if pat[i] == "**" {
			for k := j; k <= len(ptr); k++ {
				if gofn(i+1, k) {
					return true
				}
			}
			return false
		}
		if j == len(ptr) {
			return false
		}
		return (pat[i] == "*" || pat[i] == ptr[j]) && gofn(i+1, j+1)
	}
	return gofn(0, 0)
}

func (p *Pack) ruleFor(pointer string) *scopeRule {
	segs := segments(pointer)
	for i := range p.scope {
		if pointerMatches(p.scope[i].segs, segs) {
			return &p.scope[i]
		}
	}
	return nil
}

// --- the diff --------------------------------------------------------------------------------

type change struct {
	ptr  string
	b, h any
}

// get is `d.get(k, MISSING)` on a value known to be a dict.
func get(m *pyval.Map, k any) any {
	if v, ok := m.Get(k); ok {
		return v
	}
	return missing
}

// eqTop is Python ==, with MISSING equal only to itself.
func eqTop(a, b any) bool {
	_, am := a.(missingT)
	_, bm := b.(missingT)
	if am || bm {
		return am && bm
	}
	return pyval.Eq(a, b)
}

func eqIn(a, b any) bool {
	_, am := a.(missingT)
	_, bm := b.(missingT)
	if am || bm {
		return am && bm
	}
	return pyval.EqIn(a, b)
}

func named(items []any) bool {
	seen := map[string]bool{}
	for _, it := range items {
		m, ok := it.(*pyval.Map)
		if !ok {
			return false
		}
		n, ok := m.GetStr("name")
		s, isStr := n.(string)
		if !ok || !isStr || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

type pair struct {
	seg  string
	b, h any
}

func pairList(base, head []any) []pair {
	if named(base) && named(head) {
		b, h := pyval.NewMap(len(base)), pyval.NewMap(len(head))
		keys := pyval.NewMap(len(base) + len(head))
		for _, it := range base {
			n, _ := it.(*pyval.Map).GetStr("name")
			b.Set(n, it)
			keys.Set(n, nil)
		}
		for _, it := range head {
			n, _ := it.(*pyval.Map).GetStr("name")
			h.Set(n, it)
			keys.Set(n, nil)
		}
		var out []pair
		for _, k := range keys.Keys() {
			out = append(out, pair{k.(string), get(b, k), get(h, k)})
		}
		return out
	}
	used := map[int]bool{}
	type iv struct {
		i int
		v any
	}
	var rest []iv
	for hi, hv := range head {
		found := -1
		for i, bv := range base {
			if !used[i] && pyval.Eq(bv, hv) {
				found = i
				break
			}
		}
		if found < 0 {
			rest = append(rest, iv{hi, hv})
		} else {
			used[found] = true
		}
	}
	var left []iv
	for i, bv := range base {
		if !used[i] {
			left = append(left, iv{i, bv})
		}
	}
	var out []pair
	for n, r := range rest {
		var b any = missing
		if n < len(left) {
			b = left[n].v
		}
		out = append(out, pair{itoa(r.i), b, r.v})
	}
	if len(rest) < len(left) {
		for _, l := range left[len(rest):] {
			out = append(out, pair{"-" + itoa(l.i), l.v, missing})
		}
	}
	return out
}

func itoa(i int) string { return fmt.Sprint(i) }

func changes(base, head any, pointer string, depth int) ([]change, error) {
	if depth > 512 {
		return nil, &pyErr{"RecursionError"}
	}
	if eqTop(base, head) {
		return nil, nil
	}
	bm, bIsMap := base.(*pyval.Map)
	hm, hIsMap := head.(*pyval.Map)
	if bIsMap && hIsMap {
		keys := pyval.NewMap(bm.Len() + hm.Len())
		for _, k := range bm.Keys() {
			keys.Set(k, nil)
		}
		for _, k := range hm.Keys() {
			keys.Set(k, nil)
		}
		var out []change
		for _, k := range keys.Keys() {
			c, err := changes(get(bm, k), get(hm, k), pointer+"/"+esc(k), depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, c...)
		}
		return out, nil
	}
	bl, bIsList := base.([]any)
	hl, hIsList := head.([]any)
	if bIsList && hIsList {
		var out []change
		for _, pr := range pairList(bl, hl) {
			c, err := changes(pr.b, pr.h, pointer+"/"+esc(pr.seg), depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, c...)
		}
		return out, nil
	}
	_, hMissing := head.(missingT)
	_, bMissing := base.(missingT)
	if (bIsMap || bIsList) && hMissing {
		var empty any = pyval.NewMap(0)
		if bIsList {
			empty = []any{}
		}
		sub, err := changes(base, empty, pointer, depth+1)
		if err != nil {
			return nil, err
		}
		if len(sub) == 0 {
			return []change{{pointer, base, missing}}, nil
		}
		out := make([]change, len(sub))
		for i, c := range sub {
			out[i] = change{c.ptr, c.b, missing}
		}
		return out, nil
	}
	if (hIsMap || hIsList) && bMissing {
		var empty any = pyval.NewMap(0)
		if hIsList {
			empty = []any{}
		}
		sub, err := changes(empty, head, pointer, depth+1)
		if err != nil {
			return nil, err
		}
		if len(sub) == 0 {
			return []change{{pointer, missing, head}}, nil
		}
		out := make([]change, len(sub))
		for i, c := range sub {
			out[i] = change{c.ptr, missing, c.h}
		}
		return out, nil
	}
	return []change{{pointer, base, head}}, nil
}

// --- tighten-only comparison -----------------------------------------------------------------

// rank is _rank: where a value sits on the rule's order, loosest lowest; ok false when it is not on it.
func rank(order, value any) (float64, bool, error) {
	switch o := order.(type) {
	case string:
		switch o {
		case "bool":
			b, ok := value.(bool)
			if !ok {
				return 0, false, nil
			}
			if b {
				return 1, true, nil
			}
			return 0, true, nil
		case "int":
			switch x := value.(type) {
			case int64:
				return float64(x), true, nil
			case *big.Int:
				f, _ := new(big.Float).SetInt(x).Float64()
				if math.IsInf(f, 0) {
					return 0, false, errOverflow // float(int) past 1e308
				}
				return f, true, nil
			}
		}
		return 0, false, nil
	case []any:
		if _, isMissing := value.(missingT); isMissing {
			return 0, false, nil
		}
		for i, e := range o {
			if pyval.EqIn(e, value) {
				return float64(i), true, nil
			}
		}
	}
	return 0, false, nil
}

func loosened(r *scopeRule, before, after any) (bool, error) {
	b, a := before, after
	if _, m := b.(missingT); m && r.hasDefault {
		b = r.Default
	}
	if _, m := a.(missingT); m && r.hasDefault {
		a = r.Default
	}
	rb, okB, err := rank(r.Order, b)
	if err != nil {
		return false, err
	}
	ra, okA, err := rank(r.Order, a)
	if err != nil {
		return false, err
	}
	if !okA {
		return okB, nil
	}
	return okB && ra < rb, nil
}

func show(v any, r *scopeRule) string {
	if _, m := v.(missingT); m {
		if !r.hasDefault {
			return "unset"
		}
		return "unset = " + pyval.Repr(r.Default)
	}
	return pyval.Repr(v)
}

// --- structural rules ------------------------------------------------------------------------

// dget is `(x or {}).get(k)` for a value that must be a dict when truthy (AttributeError otherwise).
func dget(x any, k string) (any, error) {
	if !pyval.Truthy(x) {
		return nil, nil
	}
	m, ok := x.(*pyval.Map)
	if !ok {
		return nil, errAttr
	}
	v, _ := m.GetStr(k)
	return v, nil
}

func envs(doc any) (*pyval.Map, error) {
	dep, err := dget(doc, "deploy")
	if err != nil {
		return nil, err
	}
	e, err := dget(dep, "environments")
	if err != nil {
		return nil, err
	}
	l, ok := e.([]any)
	if !ok {
		def := pyval.NewMap(2)
		def.Set("name", "dev")
		def.Set("tier", "ground")
		l = []any{def}
	}
	out := pyval.NewMap(len(l))
	for _, it := range l {
		m, ok := it.(*pyval.Map)
		if !ok {
			continue
		}
		if n, _ := m.GetStr("name"); n != nil {
			if s, isStr := n.(string); isStr {
				out.Set(s, m)
			}
		}
	}
	return out, nil
}

// iterate is Python `for s in (x or [])` for _steps: a dict yields its keys, a str its characters.
func iterate(x any) ([]any, error) {
	if !pyval.Truthy(x) {
		return nil, nil
	}
	switch v := x.(type) {
	case []any:
		return v, nil
	case *pyval.Map:
		return v.Keys(), nil
	case string:
		return nil, nil // characters, none of them a dict
	}
	return nil, errType
}

func steps(flow any) ([]*pyval.Map, error) {
	var s any = flow
	if m, ok := flow.(*pyval.Map); ok {
		s, _ = m.GetStr("steps")
	}
	items, err := iterate(s)
	if err != nil {
		return nil, err
	}
	var out []*pyval.Map
	for _, it := range items {
		if m, ok := it.(*pyval.Map); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

type gates struct{ rides, tests int }

func gateCounts(doc any) (*pyval.Map, []gates, error) {
	pl, err := dget(doc, "pipelines")
	if err != nil {
		return nil, nil, err
	}
	if !pyval.Truthy(pl) {
		return pyval.NewMap(0), nil, nil
	}
	pm, ok := pl.(*pyval.Map)
	if !ok {
		return nil, nil, errAttr // .items() on a non-dict
	}
	out := pyval.NewMap(pm.Len())
	var counts []gates
	for i := range pm.Len() {
		name, flow := pm.At(i)
		ss, err := steps(flow)
		if err != nil {
			return nil, nil, err
		}
		var g gates
		for _, s := range ss {
			st, _ := s.GetStr("stage")
			if !pyval.Truthy(st) {
				st, _ = s.GetStr("task")
			}
			if !pyval.Eq(st, "test") {
				continue
			}
			if role, _ := s.GetStr("role"); pyval.Eq(role, "check-ride") {
				g.rides++
			} else if req, ok := s.GetStr("required"); !ok || req != false {
				g.tests++
			}
		}
		out.Set(name, len(counts))
		counts = append(counts, g)
	}
	return out, counts, nil
}

func prob(ptr, rule, msg, hint string) decide.Problem {
	return decide.Problem{Pointer: ptr, Rule: rule, Message: msg, Hint: hint}
}

func structural(base, head any) ([]decide.Problem, error) {
	var out []decide.Problem
	bE, err := envs(base)
	if err != nil {
		return nil, err
	}
	hE, err := envs(head)
	if err != nil {
		return nil, err
	}
	keys := pyval.NewMap(bE.Len() + hE.Len())
	for _, k := range bE.Keys() {
		keys.Set(k, nil)
	}
	for _, k := range hE.Keys() {
		keys.Set(k, nil)
	}
	for _, k := range keys.Keys() {
		name := k.(string)
		bv, bok := bE.Get(k)
		hv, hok := hE.Get(k)
		ptr := "/deploy/environments/" + esc(name)
		var bt, ht any
		if bok {
			bt, _ = bv.(*pyval.Map).GetStr("tier")
		}
		if hok {
			ht, _ = hv.(*pyval.Map).GetStr("tier")
		}
		// `b and h`: a dict here is truthy when it has a key, and every environment has its name.
		if bok && hok && !pyval.Eq(bt, ht) {
			out = append(out, prob(ptr+"/tier", "GP-SCOPE-003",
				fmt.Sprintf("environment '%s' changed tier from %s to %s", name, pyval.Str(bt), pyval.Str(ht)),
				"Moving an environment between Ground and Flight changes which gates guard it. A human makes that change."))
		} else if (pyval.EqIn("flight", bt) || pyval.EqIn("flight", ht)) && !(bok && hok && pyval.Eq(bv, hv)) {
			what := "changed"
			if !bok {
				what = "added"
			} else if !hok {
				what = "removed"
			}
			out = append(out, prob(ptr, "GP-SCOPE-003", fmt.Sprintf("Flight environment '%s' %s", name, what),
				"Flight environments are changed by a human. An agent may add or change Ground environments."))
		}
	}
	bN, bG, err := gateCounts(base)
	if err != nil {
		return nil, err
	}
	hN, hG, err := gateCounts(head)
	if err != nil {
		return nil, err
	}
	for i := range bN.Len() {
		flow, idx := bN.At(i)
		b := bG[idx.(int)]
		var h gates
		if j, ok := hN.Get(flow); ok {
			h = hG[j.(int)]
		}
		ptr := "/pipelines/" + esc(flow)
		if h.rides < b.rides {
			out = append(out, prob(ptr, "GP-SCOPE-002", fmt.Sprintf("flow '%s' lost its check-ride step", pyval.Str(flow)),
				"The check ride is what the qa gate reads. Removing it is a human's change."))
		}
		if h.tests < b.tests {
			out = append(out, prob(ptr, "GP-SCOPE-002",
				fmt.Sprintf("flow '%s' has fewer required test steps (%d -> %d)", pyval.Str(flow), b.tests, h.tests),
				"Removing a required test, or setting required: false on one, loosens the flow. A human makes that change."))
		}
	}
	return out, nil
}

// scopeProblems is cicd_scope.scope_problems.
func (p *Pack) scopeProblems(base any, head *pyval.Map) ([]decide.Problem, error) {
	var b any = base
	if base == nil {
		b = pyval.NewMap(0)
	}
	chs, err := changes(b, head, "", 0)
	if err != nil {
		return nil, err
	}
	var problems []decide.Problem
	for _, c := range chs {
		r := p.ruleFor(c.ptr)
		what := "changed"
		if _, m := c.h.(missingT); m {
			what = "removed"
		} else if _, m := c.b.(missingT); m {
			what = "added"
		}
		if r == nil || r.AgentScope == "human" {
			msg := c.ptr + " " + what + ": a human-only field"
			hint := "Ask a human to make this change, or leave the field as it was."
			if r == nil {
				msg += " (no rule covers it)"
			} else if r.Why != "" {
				hint = r.Why
			}
			problems = append(problems, prob(c.ptr, "GP-SCOPE-001", msg, hint))
		} else if r.AgentScope == "tighten" {
			l, err := loosened(r, c.b, c.h)
			if err != nil {
				return nil, err
			}
			if l {
				problems = append(problems, prob(c.ptr, "GP-SCOPE-002",
					fmt.Sprintf("%s loosened (%s -> %s)", c.ptr, show(c.b, r), show(c.h, r)),
					"An agent may turn a gate on or make it stricter, never the other way."))
			}
		}
	}
	seen := map[[2]string]bool{}
	for _, q := range problems {
		seen[[2]string{q.Pointer, q.Rule}] = true
	}
	st, err := structural(base, head)
	if err != nil {
		return nil, err
	}
	for _, q := range st {
		if !seen[[2]string{q.Pointer, q.Rule}] {
			problems = append(problems, q)
		}
	}
	return problems, nil
}
