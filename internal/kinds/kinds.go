// Package kinds is clearance.kind/v1 (SDK-1, schemas/kind.schema.json): a subject kind as data. A kind names its
// item types, the schema of its facts, its root function, its default tier, and the CEL rules that tier its items
// and its whole change and check that a description is consistent. A kind is a schema and CEL, never an executable.
//
// SDK-1 defines the format, parses it strictly, checks what can be checked without CEL (Parse), and binds a
// description to a kind (Bind): an item type the kind does not list, or an op that is not create, update, delete
// or replace, is refused DG-UNBOUND, never given the default tier. Loading packs from a signed policy bundle,
// compiling and running the CEL rules, and the trust rules are SDK-2; the CEL library is SDK-9. Not built yet.
//
// The built-in kinds, manifest-tree and terraform-plan, are embedded first-party kinds (builtin/*.json). Their tiers
// are still the core's Go (internal/gate), which the kind says with "builtin": true; SDK-6 moves Terraform's into
// rules.
package kinds

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/describe"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/schemas"
)

// APIVersion is the kind format's version.
const APIVersion = "clearance.kind/v1"

// FirstPartyPrefix is the reverse-DNS prefix reserved for first-party kinds (refinement 2): the reversed form of the
// product domain. It is a PLACEHOLDER until the owner decides the domain (N-Q2, Y-55); it is set in schemas/naming.go,
// beside the schema base URL, so the switch is one edit.
const FirstPartyPrefix = schemas.FirstPartyPrefix

// The built-in kinds: named before kinds were data, so their names are not reverse-DNS, and reserved.
const (
	ManifestTree  = "manifest-tree"
	TerraformPlan = "terraform-plan"
)

// BuiltinNames are the built-in kinds' names, and the root function each declares.
var BuiltinNames = map[string]string{ManifestTree: describe.RootTree1, TerraformPlan: describe.RootPlan1}

// IsFirstParty says whether a kind name is first-party: a built-in kind, or under FirstPartyPrefix.
func IsFirstParty(name string) bool {
	_, builtin := BuiltinNames[name]
	return builtin || strings.HasPrefix(name, FirstPartyPrefix)
}

// Kind is one clearance.kind/v1 document.
type Kind struct {
	APIVersion  string `json:"apiVersion"`
	Name        string `json:"name"`
	Version     int    `json:"version"`
	Description string `json:"description,omitempty"`
	// Root is the kind's root function (internal/describe): merkle/1 for every kind but the built-ins.
	Root string `json:"root"`
	// Builtin says the kind's tiers are the core's own Go code, not rules: only a built-in kind may say so, and then
	// it has no rules.
	Builtin bool `json:"builtin,omitempty"`
	// ItemTypes are the types an item may have (fnmatch globs allowed). "*" is allowed only with a defaultTier of at
	// least 2, so an unexpected type is never cleared by policy.
	ItemTypes []ItemType `json:"itemTypes"`
	// SubjectSchema is the JSON Schema (2020-12) of subject.facts: an object schema with additionalProperties false,
	// so an undeclared fact is refused.
	SubjectSchema map[string]any `json:"subjectSchema,omitempty"`
	// DefaultTier is the tier of a known item no item rule fires on: 1 to 3, never 0.
	DefaultTier int          `json:"defaultTier"`
	ItemRules   []ItemRule   `json:"itemRules,omitempty"`
	ChangeRules []ChangeRule `json:"changeRules,omitempty"`
	Consistency []Check      `json:"consistency,omitempty"`
	// Tests are the kind's fixture tests (SDK-9): a description and the tier and rules it must give.
	Tests []Test `json:"tests,omitempty"`
}

// ItemType is one type (or a glob of types) the kind accepts, the ops it may have, and the JSON Schema (2020-12) of
// its attrs: an object schema with additionalProperties false, so an undeclared attribute is refused (refinement 9).
// No attrs schema: the type takes no attrs.
type ItemType struct {
	Type        string         `json:"type"`
	Description string         `json:"description,omitempty"`
	Ops         []string       `json:"ops,omitempty"` // empty: all four
	Attrs       map[string]any `json:"attrs,omitempty"`
}

// ItemRule tiers one item: when its CEL (over item and change) is true, the item is at least tier. An item's tier
// is the highest firing rule's, or defaultTier when none fires. Types limits the rule to item types (globs).
type ItemRule struct {
	Name   string   `json:"name"`
	Types  []string `json:"types,omitempty"`
	When   string   `json:"when"`
	Tier   *int     `json:"tier"` // required: a pointer, so an absent tier is refused rather than read as 0
	Class  []string `json:"class,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

// ChangeRule tiers the whole change, after the item maximum, and can only raise it: a rule with tier makes the change
// at least that tier; the firing raise rules then lift it by their largest raise, to at least their largest floor,
// at most 3. The core invariants run after.
type ChangeRule struct {
	Name   string   `json:"name"`
	When   string   `json:"when"`
	Tier   *int     `json:"tier,omitempty"`
	Raise  *int     `json:"raise,omitempty"`
	Floor  *int     `json:"floor,omitempty"`
	Class  []string `json:"class,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

// Check is a consistency rule: CEL over the change that must hold, or the description is refused with message.
type Check struct {
	Name    string `json:"name"`
	Expr    string `json:"expr"`
	Message string `json:"message"`
}

// Test is a fixture test: a description (the kind's own) and what it must give.
type Test struct {
	Name        string         `json:"name"`
	Description map[string]any `json:"description"`
	Expect      TestExpect     `json:"expect"`
}

// TestExpect is a fixture's expected tier and the rules that must fire (or, with Refused, the refusal's code).
type TestExpect struct {
	Tier    *int     `json:"tier,omitempty"`
	Rules   []string `json:"rules,omitempty"`
	Refused string   `json:"refused,omitempty"`
}

// Error is a kind that does not load, or a description a kind refuses. Code is the refusal's rule: DG-KIND for a
// malformed kind, DG-UNBOUND for a description the kind cannot bind.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func malformed(format string, a ...any) error { return &Error{"DG-KIND", fmt.Sprintf(format, a...)} }
func unbound(format string, a ...any) error   { return &Error{"DG-UNBOUND", fmt.Sprintf(format, a...)} }

var (
	nameRx     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+\z`)
	ruleNameRx = regexp.MustCompile(`^[a-z0-9][a-z0-9:._/-]{0,63}\z`)
	classRx    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}\z`)
	refusalRx  = regexp.MustCompile(`^DG-[A-Z0-9-]+\z`)
	// catchAllRx is a glob made only of wildcards (*, ?, bracket sets), with no literal character: it can match a type
	// the kind's author never saw, so it needs a defaultTier of at least 2. The schema holds the same pattern.
	catchAllRx = regexp.MustCompile(`^([*?]|\[[^\]]*\])*\z`)
)

// MaxCEL bounds one CEL expression's length in characters (code points, as the schema's maxLength counts); SDK-2
// bounds its cost.
const MaxCEL = 4096

// Compiled is a parsed kind with its JSON Schemas compiled.
type Compiled struct {
	Kind
	facts *jsonschema.Schema
	attrs []*jsonschema.Schema // per ItemTypes entry; nil: no attrs
}

// Parse decodes a clearance.kind/v1 document strictly (unknown fields refused) and checks it: the name, the root
// function, the item types and their globs, the schemas, the tiers, and the shape of every rule. CEL is not
// compiled here (SDK-2).
func Parse(raw []byte) (*Compiled, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var k Kind
	if err := dec.Decode(&k); err != nil {
		return nil, malformed("the kind does not decode: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, malformed("the kind is one JSON document, with nothing after it")
	}
	// A null decodes as an absent member (an "ops": null would allow every op), so a null is refused wherever the
	// format itself is, as the schema refuses it. The JSON Schemas a kind carries, and its fixtures, may hold nulls.
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, malformed("the kind does not decode: %v", err)
	}
	if where := nullAt(doc, "", false); where != "" {
		return nil, malformed("%s is null: leave it out instead", where)
	}
	return compile(k)
}

// nullAt is the path of the first null in the kind's own members, skipping the schemas and fixture descriptions.
func nullAt(v any, path string, inTests bool) string {
	switch x := v.(type) {
	case nil:
		return path
	case []any:
		for i, e := range x {
			if p := nullAt(e, fmt.Sprintf("%s[%d]", path, i), inTests); p != "" {
				return p
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "subjectSchema" || k == "attrs" || (inTests && k == "description") {
				if x[k] == nil {
					return strings.TrimPrefix(path+"."+k, ".")
				}
				continue
			}
			if p := nullAt(x[k], strings.TrimPrefix(path+"."+k, "."), inTests || k == "tests"); p != "" {
				return p
			}
		}
	}
	return ""
}

func compile(k Kind) (*Compiled, error) {
	if k.APIVersion != APIVersion {
		return nil, malformed("apiVersion is %s", APIVersion)
	}
	wantRoot, builtin := BuiltinNames[k.Name]
	if !builtin && (!nameRx.MatchString(k.Name) || len(k.Name) > 253) {
		return nil, malformed("name %s is reverse-DNS (io.acme.db-migration)", pycompat.Repr(k.Name))
	}
	if k.Version < 1 || k.Version > describe.MaxVersion {
		return nil, malformed("version is 1 to %d", describe.MaxVersion)
	}
	switch {
	case builtin && k.Version == 1 && k.Root != wantRoot:
		return nil, malformed("%s version 1 declares %s: a built-in kind is never re-rooted in place", k.Name, wantRoot)
	case !builtin && k.Root != describe.RootMerkle1:
		return nil, malformed("root is %s (tree/1 and plan/1 are the built-in kinds')", describe.RootMerkle1)
	case !slices.Contains(describe.RootFns, k.Root):
		return nil, malformed("root is one of %s", strings.Join(describe.RootFns, ", "))
	}
	if k.Builtin && !builtin {
		return nil, malformed("only a built-in kind (%s, %s) is builtin", ManifestTree, TerraformPlan)
	}
	if k.Builtin && (len(k.ItemRules) > 0 || len(k.ChangeRules) > 0 || len(k.Consistency) > 0) {
		return nil, malformed("a builtin kind's tiers are the core's code: it has no rules")
	}
	if k.DefaultTier < 1 || k.DefaultTier > 3 {
		return nil, malformed("defaultTier is 1, 2 or 3 (never 0: an unruled item is never cleared as nothing)")
	}
	if len(k.ItemTypes) == 0 || len(k.ItemTypes) > 1000 {
		return nil, malformed("itemTypes lists 1 to 1000 item types")
	}
	c := &Compiled{Kind: k, attrs: make([]*jsonschema.Schema, len(k.ItemTypes))}
	seen := map[string]bool{}
	for i, it := range k.ItemTypes {
		where := fmt.Sprintf("itemTypes[%d]", i)
		if it.Type == "" || pycompat.Len(it.Type) > describe.MaxTypeLen || strings.ContainsAny(it.Type, " \t\r\n") {
			return nil, malformed("%s.type is a type or a glob", where)
		}
		if seen[it.Type] {
			return nil, malformed("%s: %s is listed twice", where, it.Type)
		}
		seen[it.Type] = true
		if catchAllRx.MatchString(it.Type) && k.DefaultTier < 2 { // "*", "**", "?*", "[!x]*": no literal, so any type
			return nil, malformed(`%s: "*" needs a defaultTier of at least 2, so an unexpected type is never cleared by policy`, where)
		}
		for _, op := range it.Ops {
			if !slices.Contains(describe.Ops, op) {
				return nil, malformed("%s.ops are create, update, delete, replace", where)
			}
		}
		if it.Attrs != nil {
			s, err := objectSchema(it.Attrs, where+".attrs")
			if err != nil {
				return nil, err
			}
			c.attrs[i] = s
		}
	}
	if k.SubjectSchema != nil {
		s, err := objectSchema(k.SubjectSchema, "subjectSchema")
		if err != nil {
			return nil, err
		}
		c.facts = s
	}
	names := map[string]bool{}
	name := func(n, where string) error {
		if !ruleNameRx.MatchString(n) {
			return malformed("%s.name %s is a rule name", where, pycompat.Repr(n))
		}
		if names[n] {
			return malformed("%s: the rule name %s is used twice", where, n)
		}
		names[n] = true
		return nil
	}
	cel := func(e, where string) error {
		if strings.TrimSpace(e) == "" || pycompat.Len(e) > MaxCEL {
			return malformed("%s is a CEL expression of at most %d characters", where, MaxCEL)
		}
		return nil
	}
	classes := func(cs []string, where string) error {
		for _, cl := range cs {
			if !classRx.MatchString(cl) {
				return malformed("%s.class names operational classes (I-1)", where)
			}
		}
		return nil
	}
	for i, r := range k.ItemRules {
		where := fmt.Sprintf("itemRules[%d]", i)
		if err := name(r.Name, where); err != nil {
			return nil, err
		}
		if err := cel(r.When, where+".when"); err != nil {
			return nil, err
		}
		if r.Tier == nil || *r.Tier < 0 || *r.Tier > 3 {
			return nil, malformed("%s.tier is 0 to 3", where)
		}
		if err := classes(r.Class, where); err != nil {
			return nil, err
		}
		for _, g := range r.Types {
			if g == "" || pycompat.Len(g) > describe.MaxTypeLen {
				return nil, malformed("%s.types are item types or globs", where)
			}
		}
	}
	for i, r := range k.ChangeRules {
		where := fmt.Sprintf("changeRules[%d]", i)
		if err := name(r.Name, where); err != nil {
			return nil, err
		}
		if err := cel(r.When, where+".when"); err != nil {
			return nil, err
		}
		switch {
		case (r.Tier == nil) == (r.Raise == nil):
			return nil, malformed("%s sets a tier or a raise, one of them", where)
		case r.Tier != nil && (*r.Tier < 1 || *r.Tier > 3):
			return nil, malformed("%s.tier is 1 to 3 (a change rule only raises)", where)
		case r.Tier != nil && r.Floor != nil:
			return nil, malformed("%s.floor goes with raise", where)
		case r.Raise != nil && (*r.Raise < 1 || *r.Raise > 3):
			return nil, malformed("%s.raise is 1 to 3", where)
		case r.Floor != nil && (*r.Floor < 1 || *r.Floor > 3):
			return nil, malformed("%s.floor is 1 to 3", where)
		}
		if err := classes(r.Class, where); err != nil {
			return nil, err
		}
	}
	for i, ch := range k.Consistency {
		where := fmt.Sprintf("consistency[%d]", i)
		if err := name(ch.Name, where); err != nil {
			return nil, err
		}
		if err := cel(ch.Expr, where+".expr"); err != nil {
			return nil, err
		}
		if strings.TrimSpace(ch.Message) == "" {
			return nil, malformed("%s.message says what is inconsistent", where)
		}
	}
	for i, t := range k.Tests {
		where := fmt.Sprintf("tests[%d]", i)
		if t.Name == "" || t.Description == nil {
			return nil, malformed("%s is {name, description, expect}", where)
		}
		if (t.Expect.Tier == nil) == (t.Expect.Refused == "") {
			return nil, malformed("%s.expect is a tier (and rules) or a refusal", where)
		}
		if t.Expect.Refused != "" && !refusalRx.MatchString(t.Expect.Refused) {
			return nil, malformed("%s.expect.refused is a refusal's code (DG-UNBOUND)", where)
		}
		for _, r := range t.Expect.Rules {
			if !ruleNameRx.MatchString(r) {
				return nil, malformed("%s.expect.rules are rule names", where)
			}
		}
		if t.Expect.Tier != nil && (*t.Expect.Tier < 0 || *t.Expect.Tier > 3) {
			return nil, malformed("%s.expect.tier is 0 to 3", where)
		}
	}
	return c, nil
}

// objectSchema compiles a JSON Schema (2020-12) that must describe an object and refuse undeclared members. It may
// not reference anything outside itself.
func objectSchema(s map[string]any, where string) (*jsonschema.Schema, error) {
	if s["type"] != "object" || s["additionalProperties"] != false {
		return nil, malformed(`%s is an object schema with "additionalProperties": false (an undeclared member is refused)`, where)
	}
	// Draft 2020-12 only, one resource: another dialect can ignore the closure beside a $ref, and an embedded $id
	// is another resource with its own dialect.
	if bad := dialectKey(s); bad != "" {
		return nil, malformed("%s: %s (a kind's schemas are draft 2020-12 and one resource)", where, bad)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, malformed("%s: %v", where, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, malformed("%s: %v", where, err)
	}
	comp := jsonschema.NewCompiler()
	comp.DefaultDraft(jsonschema.Draft2020)
	comp.UseLoader(noLoader{})
	const url = "urn:clearance:kind:schema"
	if err := comp.AddResource(url, doc); err != nil {
		return nil, malformed("%s: %v", where, err)
	}
	sch, err := comp.Compile(url)
	if err != nil {
		return nil, malformed("%s does not compile: %v", where, err)
	}
	return sch, nil
}

const draft2020 = "https://json-schema.org/draft/2020-12/schema"

// dialectKey names the first $schema other than draft 2020-12, or $id, in a schema or any of its subschemas. It walks
// schema positions only: a property named "$id", or "$id" inside const, default or enum data, declares nothing.
func dialectKey(v any) string {
	x, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	if d, ok := x["$schema"]; ok && d != draft2020 {
		return fmt.Sprintf("$schema %v", d)
	}
	if _, ok := x["$id"]; ok {
		return "$id"
	}
	for k, sub := range x {
		switch k {
		case "properties", "patternProperties", "$defs", "definitions", "dependentSchemas":
			if m, ok := sub.(map[string]any); ok {
				for _, e := range m {
					if b := dialectKey(e); b != "" {
						return b
					}
				}
			}
		case "allOf", "anyOf", "oneOf", "prefixItems":
			if l, ok := sub.([]any); ok {
				for _, e := range l {
					if b := dialectKey(e); b != "" {
						return b
					}
				}
			}
		case "items", "additionalProperties", "additionalItems", "not", "if", "then", "else", "contains",
			"propertyNames", "unevaluatedItems", "unevaluatedProperties", "contentSchema":
			if l, ok := sub.([]any); ok { // items as a list, before 2020-12
				for _, e := range l {
					if b := dialectKey(e); b != "" {
						return b
					}
				}
			} else if b := dialectKey(sub); b != "" {
				return b
			}
		}
	}
	return ""
}

type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("a kind's schema references only itself (not %s)", url)
}

// ItemType is the kind's entry for an item type: the first entry whose type (or glob) matches, an exact type
// before a glob.
func (c *Compiled) ItemType(typ string) (int, bool) {
	for i, it := range c.ItemTypes {
		if it.Type == typ {
			return i, true
		}
	}
	for i, it := range c.ItemTypes {
		if strings.ContainsAny(it.Type, "*?[") && pycompat.Match(typ, it.Type) {
			return i, true
		}
	}
	return 0, false
}

// Bind checks a description against the kind: the subject names this kind, version and root function; the facts
// are what subjectSchema declares; and every item has a type the kind lists, an op that type allows, and only the
// attrs its schema declares. Anything else is DG-UNBOUND, never the default tier: a mapping bug cannot under-tier
// a change.
func (c *Compiled) Bind(d *describe.Description) error {
	if d.Subject.Kind != c.Name || d.Subject.Version != c.Version {
		return unbound("the description is %s version %d, the kind is %s version %d", d.Subject.Kind, d.Subject.Version, c.Name, c.Version)
	}
	if d.Subject.RootFn != c.Root {
		return unbound("subject.rootFn is %s; %s version %d declares %s", d.Subject.RootFn, c.Name, c.Version, c.Root)
	}
	facts := d.Subject.Facts
	if facts == nil {
		facts = map[string]any{}
	}
	if c.facts != nil {
		if err := validate(c.facts, facts); err != nil {
			return unbound("subject.facts are not what %s declares: %v", c.Name, err)
		}
	} else if len(facts) > 0 {
		return unbound("%s declares no facts", c.Name)
	}
	for i, it := range d.Items {
		if !slices.Contains(describe.Ops, it.Op) {
			return unbound("items[%d].op %s is not create, update, delete or replace", i, pycompat.Repr(it.Op))
		}
		j, ok := c.ItemType(it.Type)
		if !ok {
			return unbound("items[%d]: %s is not an item type %s lists", i, pycompat.Repr(it.Type), c.Name)
		}
		t := c.ItemTypes[j]
		if len(t.Ops) > 0 && !slices.Contains(t.Ops, it.Op) {
			return unbound("items[%d]: a %s is never %s", i, it.Type, it.Op)
		}
		switch {
		case c.attrs[j] != nil:
			attrs := it.Attrs
			if attrs == nil {
				attrs = map[string]any{}
			}
			if err := validate(c.attrs[j], attrs); err != nil {
				return unbound("items[%d].attrs are not what %s declares for %s: %v", i, c.Name, t.Type, err)
			}
		case len(it.Attrs) > 0:
			keys := make([]string, 0, len(it.Attrs))
			for k := range it.Attrs {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			return unbound("items[%d]: %s declares no attrs for %s (%s sent)", i, c.Name, t.Type, keys[0])
		}
	}
	return nil
}

// validate runs a schema over a value, normalized to what the validator takes (numbers as json.Number).
func validate(s *jsonschema.Schema, v any) error {
	b, err := canon.Canonical(v)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return err
	}
	return s.Validate(inst)
}

//go:embed builtin/*.json
var builtinFS embed.FS

// Builtin is the embedded first-party kind of a built-in kind's name.
func Builtin(name string) (*Compiled, error) {
	if _, ok := BuiltinNames[name]; !ok {
		return nil, fmt.Errorf("kinds: %s is not a built-in kind", name)
	}
	raw, err := builtinFS.ReadFile("builtin/" + name + ".json")
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}
