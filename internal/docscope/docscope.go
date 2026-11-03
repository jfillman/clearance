// Package docscope is field scope over a structured document an agent changes: which JSON pointers of a YAML file
// an agent may change (open), may only tighten (tighten, along an order), or may never change (human), plus
// structural invariants over keyed collections and counted items that a pointer diff alone cannot see.
//
// It is generic: the file it applies to, the pointer rules, the invariants, every rule id and hint are a policy
// bundle's data (internal/decide's bundle format, "documents"), and the pointer rules are typically read from the
// owning system's published contract at load time. The diff, the rule lookup and the messages reproduce a Python
// reference implementation exactly (dict order, ==, repr and str of values, PyYAML's safe_load), so a deployment
// that moves a check from Python into a bundle decides identically.
package docscope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"path"
	"strings"

	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/pyyaml"
	"github.com/jfillman/clearance/internal/scope"
)

// Problem is one finding: the pointer it is about ("" for the whole file), the rule id, the message and the hint.
type Problem struct {
	Pointer string `json:"pointer"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

// Finding is the rule id and hint a class of problem is reported under.
type Finding struct {
	Rule string `json:"rule"`
	Hint string `json:"hint"`
}

// Template is a structural problem's message and hint. Message may name {key} (the item's key), {before} and
// {after} (the values compared) and {what} (added, removed or changed).
type Template struct {
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

// Keyed is a keyed-collection invariant: the list at At, its items keyed by Key (items that are not mappings, or
// whose key is not a string, are not in it). When At is not a list the collection is Default. An item whose
// Attribute changes between two present items is a problem (Changed); an item whose Attribute is, before or after,
// one of Protected, and that is added, removed or changed at all, is a problem (ProtectedChange).
type Keyed struct {
	Rule            string          `json:"rule"`
	At              string          `json:"at"`
	Key             string          `json:"key"`
	Default         json.RawMessage `json:"default,omitempty"`
	Attribute       string          `json:"attribute"`
	Changed         Template        `json:"changed"`
	Protected       []any           `json:"protected,omitempty"`
	ProtectedChange Template        `json:"protected_change"`

	def any
}

// Counted is a counted-items invariant: the mapping at At, each entry's items (the entry's Items key when the entry
// is a mapping, else the entry itself), each item counted under the first Counter whose conditions all hold. A
// counter that counts fewer items after the change than before, for an entry present before, is a problem.
type Counted struct {
	Rule     string    `json:"rule"`
	At       string    `json:"at"`
	Items    string    `json:"items"`
	Counters []Counter `json:"counters"`
}

// Counter is one count of a Counted invariant.
type Counter struct {
	Name  string      `json:"name"`
	When  []Condition `json:"when"`
	Fewer Template    `json:"fewer"`
}

// Condition is a test on one item: the first of Field's keys whose value is truthy (the last one's value when none
// is, as Python's `a or b`), compared with Equals (==) or IsNot (not identical; a missing key is not anything).
type Condition struct {
	Field  []string `json:"field"`
	Equals any      `json:"equals,omitempty"`
	IsNot  any      `json:"is_not,omitempty"`
}

// Config is one document check.
type Config struct {
	// File is the file name (base name) the check applies to; any other file is not its business.
	File string
	// Rules are the pointer rules, first match wins.
	Rules []Rule
	// WholeFile is reported when the file cannot be reasoned about (it does not parse, is not a mapping, the check
	// cannot be evaluated); Human for a human-only or uncovered field (the rule's own `why` is the hint when it has
	// one); Loosened for a tighten-only field moved the other way.
	WholeFile, Human, Loosened Finding
	Keyed                      []Keyed
	Counted                    []Counted
}

// Rule is one pointer rule: a JSON-pointer pattern (`*` one segment, `**` any number), its scope (human, open or
// tighten), why it is human-only, and for tighten its order ("bool", "int", or a list loosest first) and the value
// an unset field has.
type Rule struct {
	Pattern    string
	AgentScope string
	Why        string
	Order      any
	Default    any
	hasDefault bool
	segs       []string
}

// ParseRules decodes a list of pointer rules ({pattern, agentScope, why?, order?, default?}); an unknown key, an
// empty pattern or an unknown agentScope is an error.
func ParseRules(data []byte) ([]Rule, error) {
	var raw []map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("docscope: rules: %w", err)
	}
	var out []Rule
	for i, r := range raw {
		var sr Rule
		var err error
		for k, v := range r {
			switch k {
			case "pattern":
				err = json.Unmarshal(v, &sr.Pattern)
			case "agentScope":
				err = json.Unmarshal(v, &sr.AgentScope)
			case "why":
				err = json.Unmarshal(v, &sr.Why)
			case "order":
				sr.Order, err = pycompat.DecodeJSON(v)
			case "default":
				sr.Default, err = pycompat.DecodeJSON(v)
				sr.hasDefault = true
			default:
				err = fmt.Errorf("unknown key %q", k)
			}
			if err != nil {
				return nil, fmt.Errorf("docscope: rule %d: %w", i, err)
			}
		}
		if sr.Pattern == "" || (sr.AgentScope != "human" && sr.AgentScope != "open" && sr.AgentScope != "tighten") {
			return nil, fmt.Errorf("docscope: rule %d: bad pattern or agentScope", i)
		}
		sr.segs = segments(sr.Pattern)
		out = append(out, sr)
	}
	return out, nil
}

// Prepare checks the invariants and decodes their defaults; call it once before Problems.
func (c *Config) Prepare() error {
	if c.File == "" {
		return errors.New("docscope: file is required")
	}
	for _, f := range []Finding{c.WholeFile, c.Human, c.Loosened} {
		if f.Rule == "" || f.Hint == "" {
			return errors.New("docscope: whole_file, human and loosened each need a rule and a hint")
		}
	}
	for i := range c.Keyed {
		k := &c.Keyed[i]
		if k.Rule == "" || k.At == "" || k.Key == "" || k.Attribute == "" || k.Changed.Message == "" ||
			(len(k.Protected) > 0 && k.ProtectedChange.Message == "") {
			return fmt.Errorf("docscope: keyed invariant %d: rule, at, key, attribute and messages are required", i)
		}
		if len(k.Default) > 0 {
			d, err := pycompat.DecodeJSON(k.Default)
			if err != nil {
				return fmt.Errorf("docscope: keyed invariant %d: default: %w", i, err)
			}
			if _, ok := d.([]any); !ok {
				return fmt.Errorf("docscope: keyed invariant %d: default must be a list", i)
			}
			k.def = d
		}
		for j, p := range k.Protected {
			k.Protected[j] = fromJSON(p)
		}
	}
	for i := range c.Counted {
		ci := &c.Counted[i]
		if ci.Rule == "" || ci.At == "" || len(ci.Counters) == 0 {
			return fmt.Errorf("docscope: counted invariant %d: rule, at and counters are required", i)
		}
		for j := range ci.Counters {
			ct := &ci.Counters[j]
			if ct.Fewer.Message == "" {
				return fmt.Errorf("docscope: counted invariant %d counter %d: a message is required", i, j)
			}
			for k := range ct.When {
				cd := &ct.When[k]
				if len(cd.Field) == 0 || (cd.Equals == nil) == (cd.IsNot == nil) {
					return fmt.Errorf("docscope: counted invariant %d counter %d: a condition names a field and exactly one of equals, is_not", i, j)
				}
				cd.Equals, cd.IsNot = fromJSON(cd.Equals), fromJSON(cd.IsNot)
			}
		}
	}
	return nil
}

// fromJSON is a value encoding/json decoded, as a pycompat value (numbers: an int when integral).
func fromJSON(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	out, err := pycompat.DecodeJSON(b)
	if err != nil {
		return v
	}
	return out
}

// missing is cicd_scope.MISSING.
type missingT struct{}

var missing = missingT{}

// pyErr is a Python exception the scope check raises; Problems turns it into a whole-file problem naming its
// class.
type pyErr struct{ class string }

func (e *pyErr) Error() string { return e.class }

var (
	errAttr     = &pyErr{"AttributeError"}
	errType     = &pyErr{"TypeError"}
	errOverflow = &pyErr{"OverflowError"}
)

func mergePatch(target, patch any) any {
	pm, ok := patch.(*pycompat.Map)
	if !ok {
		return patch // values are never mutated, so sharing is a deep copy's equal
	}
	var out *pycompat.Map
	if tm, ok := target.(*pycompat.Map); ok {
		out = tm.Copy()
	} else {
		out = pycompat.NewMap(pm.Len())
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

// Applies says whether a file path is this check's file.
func (c *Config) Applies(p any) bool {
	n, err := scope.NormalizeAny(p)
	return err == nil && path.Base(n) == c.File
}

func (c *Config) wholeFile(p string, why string) Problem {
	return Problem{Pointer: "", Rule: c.WholeFile.Rule, Message: p + ": " + why, Hint: c.WholeFile.Hint}
}

// loadIfStr is `yaml.safe_load(x) if isinstance(x, str) else x`.
func loadIfStr(v any) (any, error) {
	if s, ok := v.(string); ok {
		return pyyaml.SafeLoad(s)
	}
	return v, nil
}

// Problems checks every file of a call ({path, content, before?, op?}) that is this check's file. A non-YAML error
// from the loader (a PyYAML ValueError) is returned: the caller fails closed.
func (c *Config) Problems(files []any) ([]Problem, error) {
	var problems []Problem
	for _, f := range files {
		fm, ok := f.(*pycompat.Map)
		if !ok {
			continue
		}
		pv, _ := fm.GetStr("path")
		if !c.Applies(pv) {
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
				problems = append(problems, c.wholeFile(fp, "does not parse as YAML"))
				continue
			}
			return nil, err
		}
		if _, isMap := base.(*pycompat.Map); base != nil && !isMap {
			problems = append(problems, c.wholeFile(fp, "the current content (`before`) is not a YAML mapping"))
			continue
		}
		if op, _ := fm.GetStr("op"); op == "merge-patch" {
			if _, isMap := head.(*pycompat.Map); !isMap {
				problems = append(problems, c.wholeFile(fp, "a merge-patch must be a mapping"))
				continue
			}
			b := base
			if !pycompat.Truthy(b) {
				b = pycompat.NewMap(0)
			}
			head = mergePatch(b, head)
		}
		hm, isMap := head.(*pycompat.Map)
		if !isMap {
			problems = append(problems, c.wholeFile(fp, "the new content is not a YAML mapping"))
			continue
		}
		found, err := c.scopeProblems(base, hm)
		if err != nil {
			var pe *pyErr
			if errors.As(err, &pe) {
				problems = append(problems, c.wholeFile(fp, fmt.Sprintf("the scope check could not be evaluated (%s)", pe.class)))
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
	return strings.ReplaceAll(strings.ReplaceAll(pycompat.Str(k), "~", "~0"), "/", "~1")
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

func (c *Config) ruleFor(pointer string) *Rule {
	segs := segments(pointer)
	for i := range c.Rules {
		if pointerMatches(c.Rules[i].segs, segs) {
			return &c.Rules[i]
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
func get(m *pycompat.Map, k any) any {
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
	return pycompat.Equal(a, b)
}

func named(items []any) bool {
	seen := map[string]bool{}
	for _, it := range items {
		m, ok := it.(*pycompat.Map)
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
		b, h := pycompat.NewMap(len(base)), pycompat.NewMap(len(head))
		keys := pycompat.NewMap(len(base) + len(head))
		for _, it := range base {
			n, _ := it.(*pycompat.Map).GetStr("name")
			b.Set(n, it)
			keys.Set(n, nil)
		}
		for _, it := range head {
			n, _ := it.(*pycompat.Map).GetStr("name")
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
			if !used[i] && pycompat.Equal(bv, hv) {
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
	bm, bIsMap := base.(*pycompat.Map)
	hm, hIsMap := head.(*pycompat.Map)
	if bIsMap && hIsMap {
		keys := pycompat.NewMap(bm.Len() + hm.Len())
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
		var empty any = pycompat.NewMap(0)
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
		var empty any = pycompat.NewMap(0)
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
			if pycompat.EqualIn(e, value) {
				return float64(i), true, nil
			}
		}
	}
	return 0, false, nil
}

func loosened(r *Rule, before, after any) (bool, error) {
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

func show(v any, r *Rule) string {
	if _, m := v.(missingT); m {
		if !r.hasDefault {
			return "unset"
		}
		return "unset = " + pycompat.Repr(r.Default)
	}
	return pycompat.Repr(v)
}

// --- structural invariants -------------------------------------------------------------------

// dget is `(x or {}).get(k)` for a value that must be a dict when truthy (AttributeError otherwise).
func dget(x any, k string) (any, error) {
	if !pycompat.Truthy(x) {
		return nil, nil
	}
	m, ok := x.(*pycompat.Map)
	if !ok {
		return nil, errAttr
	}
	v, _ := m.GetStr(k)
	return v, nil
}

// at follows a pointer with dget at each segment.
func at(doc any, pointer string) (any, error) {
	v := doc
	for _, s := range segments(pointer) {
		var err error
		if v, err = dget(v, s); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func (k *Keyed) items(doc any) (*pycompat.Map, error) {
	e, err := at(doc, k.At)
	if err != nil {
		return nil, err
	}
	l, ok := e.([]any)
	if !ok {
		l, _ = k.def.([]any)
	}
	out := pycompat.NewMap(len(l))
	for _, it := range l {
		m, ok := it.(*pycompat.Map)
		if !ok {
			continue
		}
		if n, _ := m.GetStr(k.Key); n != nil {
			if s, isStr := n.(string); isStr {
				out.Set(s, m)
			}
		}
	}
	return out, nil
}

// iterate is Python `for s in (x or [])`: a dict yields its keys, a str its characters.
func iterate(x any) ([]any, error) {
	if !pycompat.Truthy(x) {
		return nil, nil
	}
	switch v := x.(type) {
	case []any:
		return v, nil
	case *pycompat.Map:
		return v.Keys(), nil
	case string:
		return nil, nil // characters, none of them a dict
	}
	return nil, errType
}

func (c *Counted) entryItems(entry any) ([]*pycompat.Map, error) {
	var s any = entry
	if m, ok := entry.(*pycompat.Map); ok {
		s, _ = m.GetStr(c.Items)
	}
	items, err := iterate(s)
	if err != nil {
		return nil, err
	}
	var out []*pycompat.Map
	for _, it := range items {
		if m, ok := it.(*pycompat.Map); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

func (cd *Condition) holds(item *pycompat.Map) bool {
	var v any
	present := false
	for _, f := range cd.Field {
		v, present = item.GetStr(f)
		if pycompat.Truthy(v) {
			break
		}
	}
	if cd.IsNot != nil {
		return !present || v != cd.IsNot
	}
	return pycompat.Equal(v, cd.Equals)
}

// counts is, per entry of the mapping at At, how many items each counter counts.
func (c *Counted) counts(doc any) (*pycompat.Map, [][]int, error) {
	pl, err := at(doc, c.At)
	if err != nil {
		return nil, nil, err
	}
	if !pycompat.Truthy(pl) {
		return pycompat.NewMap(0), nil, nil
	}
	pm, ok := pl.(*pycompat.Map)
	if !ok {
		return nil, nil, errAttr // .items() on a non-dict
	}
	out := pycompat.NewMap(pm.Len())
	var counts [][]int
	for i := range pm.Len() {
		name, entry := pm.At(i)
		items, err := c.entryItems(entry)
		if err != nil {
			return nil, nil, err
		}
		n := make([]int, len(c.Counters))
		for _, it := range items {
		counters:
			for j := range c.Counters {
				for k := range c.Counters[j].When {
					if !c.Counters[j].When[k].holds(it) {
						continue counters
					}
				}
				n[j]++
				break
			}
		}
		out.Set(name, len(counts))
		counts = append(counts, n)
	}
	return out, counts, nil
}

func fill(t Template, key, before, after, what string) string {
	return strings.NewReplacer("{key}", key, "{before}", before, "{after}", after, "{what}", what).Replace(t.Message)
}

func union(a, b *pycompat.Map) *pycompat.Map {
	keys := pycompat.NewMap(a.Len() + b.Len())
	for _, k := range a.Keys() {
		keys.Set(k, nil)
	}
	for _, k := range b.Keys() {
		keys.Set(k, nil)
	}
	return keys
}

func (k *Keyed) problems(base, head any) ([]Problem, error) {
	bE, err := k.items(base)
	if err != nil {
		return nil, err
	}
	hE, err := k.items(head)
	if err != nil {
		return nil, err
	}
	var out []Problem
	for _, key := range union(bE, hE).Keys() {
		name := key.(string)
		bv, bok := bE.Get(key)
		hv, hok := hE.Get(key)
		ptr := k.At + "/" + esc(name)
		var bt, ht any
		if bok {
			bt, _ = bv.(*pycompat.Map).GetStr(k.Attribute)
		}
		if hok {
			ht, _ = hv.(*pycompat.Map).GetStr(k.Attribute)
		}
		protected := false
		for _, p := range k.Protected {
			if pycompat.EqualIn(p, bt) || pycompat.EqualIn(p, ht) {
				protected = true
				break
			}
		}
		// `b and h`: a dict here is truthy when it has a key, and every item has its key.
		if bok && hok && !pycompat.Equal(bt, ht) {
			out = append(out, Problem{ptr + "/" + esc(k.Attribute), k.Rule,
				fill(k.Changed, name, pycompat.Str(bt), pycompat.Str(ht), "changed"), k.Changed.Hint})
		} else if protected && !(bok && hok && pycompat.Equal(bv, hv)) {
			what := "changed"
			if !bok {
				what = "added"
			} else if !hok {
				what = "removed"
			}
			out = append(out, Problem{ptr, k.Rule, fill(k.ProtectedChange, name, pycompat.Str(bt), pycompat.Str(ht), what),
				k.ProtectedChange.Hint})
		}
	}
	return out, nil
}

func (c *Counted) problems(base, head any) ([]Problem, error) {
	bN, bC, err := c.counts(base)
	if err != nil {
		return nil, err
	}
	hN, hC, err := c.counts(head)
	if err != nil {
		return nil, err
	}
	var out []Problem
	for i := range bN.Len() {
		entry, idx := bN.At(i)
		b := bC[idx.(int)]
		h := make([]int, len(c.Counters))
		if j, ok := hN.Get(entry); ok {
			h = hC[j.(int)]
		}
		ptr := c.At + "/" + esc(entry)
		for j, ct := range c.Counters {
			if h[j] < b[j] {
				out = append(out, Problem{ptr, c.Rule, fill(ct.Fewer, pycompat.Str(entry), itoa(b[j]), itoa(h[j]), "removed"),
					ct.Fewer.Hint})
			}
		}
	}
	return out, nil
}

func (c *Config) structural(base, head any) ([]Problem, error) {
	var out []Problem
	for i := range c.Keyed {
		p, err := c.Keyed[i].problems(base, head)
		if err != nil {
			return nil, err
		}
		out = append(out, p...)
	}
	for i := range c.Counted {
		p, err := c.Counted[i].problems(base, head)
		if err != nil {
			return nil, err
		}
		out = append(out, p...)
	}
	return out, nil
}

// scopeProblems is cicd_scope.scope_problems.
func (c *Config) scopeProblems(base any, head *pycompat.Map) ([]Problem, error) {
	var b any = base
	if base == nil {
		b = pycompat.NewMap(0)
	}
	chs, err := changes(b, head, "", 0)
	if err != nil {
		return nil, err
	}
	var problems []Problem
	for _, ch := range chs {
		r := c.ruleFor(ch.ptr)
		what := "changed"
		if _, m := ch.h.(missingT); m {
			what = "removed"
		} else if _, m := ch.b.(missingT); m {
			what = "added"
		}
		if r == nil || r.AgentScope == "human" {
			msg := ch.ptr + " " + what + ": a human-only field"
			hint := c.Human.Hint
			if r == nil {
				msg += " (no rule covers it)"
			} else if r.Why != "" {
				hint = r.Why
			}
			problems = append(problems, Problem{ch.ptr, c.Human.Rule, msg, hint})
		} else if r.AgentScope == "tighten" {
			l, err := loosened(r, ch.b, ch.h)
			if err != nil {
				return nil, err
			}
			if l {
				problems = append(problems, Problem{ch.ptr, c.Loosened.Rule,
					fmt.Sprintf("%s loosened (%s -> %s)", ch.ptr, show(ch.b, r), show(ch.h, r)), c.Loosened.Hint})
			}
		}
	}
	seen := map[[2]string]bool{}
	for _, q := range problems {
		seen[[2]string{q.Pointer, q.Rule}] = true
	}
	st, err := c.structural(base, head)
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
