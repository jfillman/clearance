package decide

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common/types"

	"github.com/jfillman/clearance/internal/scope"
)

// Rule is one deny-if rule: when Expr is true the call is denied with this id, message and hint. Rules run in
// Order, first match wins, so the order is part of what a rule means.
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Expr    string `json:"expr"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
	Order   int    `json:"order"`
	// Problems names one of the bundle's documents: when the rule matches and that document has findings, the
	// decision is the first finding's rule id and hint, every finding's message joined, all of them as problems.
	Problems string `json:"problems,omitempty"`
}

// ToolSpec is a registered tool (tiers.ToolSpec).
type ToolSpec struct {
	Name         string   `json:"name"`
	Tier         int      `json:"tier"`
	Description  string   `json:"description"`
	RequiredArgs []string `json:"required_args"`
	GithubCost   int64    `json:"github_cost"`
	Target       string   `json:"target"` // none, lower, upper
	ProposeOnly  bool     `json:"propose_only"`
	WritesFiles  bool     `json:"writes_files"`
	ReadsRepo    bool     `json:"reads_repo"`
	Receipt      []string `json:"receipt"`
}

// BundleData is the core rule set as data (core.json).
type BundleData struct {
	Name      string     `json:"name"`
	Rules     []Rule     `json:"rules"`
	Tools     []ToolSpec `json:"tools"`
	Tripwires []string   `json:"tripwires,omitempty"`
	PRTools   []string   `json:"pr_tools,omitempty"`
}

//go:embed core.json
var coreJSON []byte

// Core is the embedded core bundle: Clearance's own rules and tools.
func Core() (BundleData, error) { return ParseBundle(coreJSON) }

// ParseBundle strictly decodes a bundle file.
func ParseBundle(data []byte) (BundleData, error) {
	var b BundleData
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return BundleData{}, fmt.Errorf("decide: bundle: %w", err)
	}
	return b, nil
}

// The CEL variables of the core context. Every rule reads only these and its bundles' vars and documents.
var coreVars = []struct {
	name string
	typ  *cel.Type
}{
	{"tool.name", cel.StringType}, {"tool.tier", cel.IntType}, {"tool.propose_only", cel.BoolType},
	{"effective.tools", cel.ListType(cel.StringType)}, {"effective.tier", cel.IntType},
	{"session.expired", cel.BoolType}, {"session.tripped", cel.BoolType},
	{"session.tool_calls_left", cel.IntType}, {"session.github_left", cel.IntType}, {"session.prs_left", cel.IntType},
	{"cost.github", cel.IntType}, {"cost.prs", cel.IntType},
	{"ctx.owns_session", cel.BoolType}, {"ctx.tripwire", cel.BoolType}, {"ctx.known", cel.BoolType},
	{"ctx.missing_args", cel.IntType}, {"ctx.target_mismatch", cel.BoolType}, {"ctx.has_repo", cel.BoolType},
	{"ctx.repo_ok", cel.BoolType}, {"ctx.path_violations", cel.IntType}, {"ctx.field_violations", cel.IntType},
	{"ctx.has_service", cel.BoolType}, {"ctx.service_ok", cel.BoolType}, {"ctx.is_chat", cel.BoolType},
	{"ctx.artifact_bytes", cel.IntType}, {"ctx.session_kind", cel.BoolType},
}

// slot indexes of the core variables in an activation.
const (
	vToolName = iota
	vToolTier
	vToolProposeOnly
	vEffTools
	vEffTier
	vSessExpired
	vSessTripped
	vSessToolCallsLeft
	vSessGithubLeft
	vSessPRsLeft
	vCostGithub
	vCostPRs
	vOwnsSession
	vTripwire
	vKnown
	vMissingArgs
	vTargetMismatch
	vHasRepo
	vRepoOK
	vPathViolations
	vFieldViolations
	vHasService
	vServiceOK
	vIsChat
	vArtifactBytes
	vSessionKind
	nCore
)

// Cost limits. A rule's estimated worst case, with lists and strings at the sizes below, must fit MaxRuleCost at
// load; at run time each evaluation is cut off at the same limit (and denied, R000).
const (
	MaxRuleCost   = 100_000
	maxListSize   = 10_000
	maxStringSize = 1 << 20
)

// compiled is one rule ready to run.
type compiled struct {
	Rule
	prg cel.Program
}

// bundle is the compiled policy: the core rules plus the loaded policy bundles, rules in order.
type bundle struct {
	name, version string
	rules         []compiled
	tools         map[string]*ToolSpec
	toolList      []ToolSpec
	tripwires     map[string]bool
	prTools       map[string]bool
	prToolList    []string
	sections      []string
	env           Environments
	slots         map[string]int // CEL variable name -> activation slot
	bundles       []*compiledBundle
	refs          []BundleRef
	problemsOf    map[string]docRef          // rule id -> the document whose findings decide it
	owner         map[string]*compiledBundle // tool name -> the bundle that registered it
	ruleBundle    map[string]string          // rule id -> the bundle that brought it
}

// docRef is one bundle's document check.
type docRef struct{ bundle, doc int }

// compiledBundle is a loaded bundle's context, compiled.
type compiledBundle struct {
	b         *Bundle
	vars      []*ctxProgram
	varSlots  []int // rule-activation slot of each var
	argChecks []compiledArgCheck
	docSlots  []int
	app       *ctxProgram
}

type compiledArgCheck struct {
	when   *ctxProgram
	checks []*ctxProgram
}

// Options are what New builds an engine from besides the core rules.
type Options struct {
	// Bundles are the deployment's policy bundles (LoadBundle), in the order the deployment lists them.
	Bundles []*Bundle
	// Environments is how arguments name an environment tier; nil is DefaultEnvironments.
	Environments *Environments
}

// Environments says which environment a call's arguments point at, for tools whose target is lower (R012): a
// `project` ending in one of LowerProjectSuffixes is lower (any other project is upper); else an `env` in
// LowerNames or starting with one of LowerPrefixes is lower (any other env is upper); else a `repo` whose name
// starts with one of UpperRepoPrefixes is upper (any other repo is lower). A deployment passes its own naming
// (CLEARANCE_ENV_*); the default knows only the common lower names.
type Environments struct {
	LowerNames           []string `json:"lower_names"`
	LowerPrefixes        []string `json:"lower_prefixes"`
	LowerProjectSuffixes []string `json:"lower_project_suffixes"`
	UpperRepoPrefixes    []string `json:"upper_repo_prefixes"`
}

// DefaultEnvironments is the environment naming a deployment that sets none gets.
func DefaultEnvironments() Environments {
	return Environments{LowerNames: []string{"dev", "development", "sandbox", "scratch"},
		LowerPrefixes: []string{}, LowerProjectSuffixes: []string{}, UpperRepoPrefixes: []string{}}
}

type sizeEstimator struct{}

func (sizeEstimator) EstimateSize(element checker.AstNode) *checker.SizeEstimate {
	if element.Type() == nil {
		return nil
	}
	switch element.Type().Kind() {
	case types.ListKind:
		return &checker.SizeEstimate{Min: 0, Max: maxListSize}
	case types.StringKind:
		return &checker.SizeEstimate{Min: 0, Max: maxStringSize}
	}
	return nil
}

func (sizeEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	return nil
}

func compileBundle(core BundleData, opt Options) (*bundle, error) {
	env := DefaultEnvironments()
	if opt.Environments != nil {
		env = *opt.Environments
	}
	b := &bundle{
		tools: map[string]*ToolSpec{}, tripwires: map[string]bool{}, prTools: map[string]bool{},
		slots: map[string]int{}, env: env, problemsOf: map[string]docRef{}, ruleBundle: map[string]string{},
		owner: map[string]*compiledBundle{},
	}
	for _, t := range core.Tripwires {
		b.tripwires[t] = true
	}
	addPR := func(t string) {
		if !b.prTools[t] {
			b.prTools[t] = true
			b.prToolList = append(b.prToolList, t)
		}
	}
	for _, t := range core.PRTools {
		addPR(t)
	}
	names := []string{core.Name}
	tools := append([]ToolSpec(nil), core.Tools...)
	rules := append([]Rule(nil), core.Rules...)
	var opts []cel.EnvOption
	for i, v := range coreVars {
		b.slots[v.name] = i
		opts = append(opts, cel.Variable(v.name, v.typ))
	}
	next := nCore
	newSlot := func(bundleName, name string, typ *cel.Type) (int, error) {
		full := "ctx." + name
		if _, dup := b.slots[full]; dup {
			return 0, fmt.Errorf("decide: policy bundle %q redefines context keys [%q]", bundleName, name)
		}
		b.slots[full] = next
		next++
		opts = append(opts, cel.Variable(full, typ))
		return next - 1, nil
	}
	seenBundles := map[string]bool{}
	for bi, lb := range opt.Bundles {
		spec := &lb.Spec
		if seenBundles[spec.Name] {
			return nil, fmt.Errorf("decide: policy bundle %q is loaded twice", spec.Name)
		}
		seenBundles[spec.Name] = true
		names = append(names, spec.Name)
		tools = append(tools, spec.Tools...)
		rules = append(rules, spec.Rules...)
		for _, r := range spec.Rules {
			b.ruleBundle[r.ID] = spec.Name
		}
		for _, t := range spec.PRTools {
			addPR(t)
		}
		for _, s := range spec.ProfileSections {
			if !slices.Contains(b.sections, s) {
				b.sections = append(b.sections, s)
			}
		}
		cb := &compiledBundle{b: lb}
		// The context environment grows as the vars are compiled: each may read the ones before it.
		var ctxNames []string
		var ctxTypes []*cel.Type
		globs := &scope.Globs{}
		for _, v := range spec.Vars {
			var typ *cel.Type
			switch v.Type {
			case "bool":
				typ = cel.BoolType
			case "int":
				typ = cel.IntType
			default:
				return nil, fmt.Errorf("decide: policy bundle %s: var %s: type %q is not bool or int", spec.Name, v.Name, v.Type)
			}
			if v.Name == "" || strings.ContainsAny(v.Name, ". ") {
				return nil, fmt.Errorf("decide: policy bundle %s: bad var name %q", spec.Name, v.Name)
			}
			cenv, err := ctxEnv(globs, ctxNames, ctxTypes)
			if err != nil {
				return nil, err
			}
			prg, err := compileCtx(cenv, v.Expr, typ, fmt.Sprintf("policy bundle %s: var %s", spec.Name, v.Name))
			if err != nil {
				return nil, err
			}
			slot, err := newSlot(spec.Name, v.Name, typ)
			if err != nil {
				return nil, err
			}
			cb.vars = append(cb.vars, prg)
			cb.varSlots = append(cb.varSlots, slot)
			ctxNames = append(ctxNames, "ctx."+v.Name)
			ctxTypes = append(ctxTypes, typ)
		}
		cenv, err := ctxEnv(globs, ctxNames, ctxTypes)
		if err != nil {
			return nil, err
		}
		for gi, ac := range spec.ArgChecks {
			what := fmt.Sprintf("policy bundle %s: arg_checks[%d]", spec.Name, gi)
			when, err := compileCtx(cenv, ac.When, cel.BoolType, what+".when")
			if err != nil {
				return nil, err
			}
			c := compiledArgCheck{when: when}
			for ci, ex := range ac.Checks {
				prg, err := compileCtx(cenv, ex, cel.BoolType, fmt.Sprintf("%s.checks[%d]", what, ci))
				if err != nil {
					return nil, err
				}
				c.checks = append(c.checks, prg)
			}
			cb.argChecks = append(cb.argChecks, c)
		}
		for di, d := range spec.Documents {
			slot, err := newSlot(spec.Name, d.Name, cel.IntType)
			if err != nil {
				return nil, err
			}
			cb.docSlots = append(cb.docSlots, slot)
			for _, r := range spec.Rules {
				if r.Problems == d.Name {
					b.problemsOf[r.ID] = docRef{bi, di}
				}
			}
		}
		for _, r := range spec.Rules {
			if r.Problems != "" {
				if _, ok := b.problemsOf[r.ID]; !ok {
					return nil, fmt.Errorf("decide: policy bundle %s: rule %s takes its problems from %q, which is not one of its documents",
						spec.Name, r.ID, r.Problems)
				}
			}
		}
		if spec.App != "" {
			// The app is computed for the record from the call alone: it may not read ctx.* (an expression that
			// does fails the load here, rather than recording no app).
			aenv, err := ctxEnv(globs, nil, nil)
			if err != nil {
				return nil, err
			}
			if cb.app, err = compileCtx(aenv, spec.App, cel.StringType, "policy bundle "+spec.Name+": app"); err != nil {
				return nil, err
			}
		}
		for _, t := range spec.Tools {
			b.owner[t.Name] = cb
		}
		b.bundles = append(b.bundles, cb)
		b.refs = append(b.refs, lb.ref())
	}
	for i := range tools {
		t := &tools[i]
		if _, dup := b.tools[t.Name]; dup {
			return nil, fmt.Errorf("decide: tool %q is registered twice", t.Name)
		}
		if b.tripwires[t.Name] {
			return nil, fmt.Errorf("decide: tool %q is a T3 tripwire and can never be registered", t.Name)
		}
		if t.Tier < 0 || t.Tier > 3 || (t.Target != "none" && t.Target != "lower" && t.Target != "upper") {
			return nil, fmt.Errorf("decide: tool %q: bad tier or target", t.Name)
		}
		b.tools[t.Name] = t
	}
	b.toolList = tools
	for _, attr := range []string{"id", "order"} {
		seen := map[string]int{}
		for _, r := range rules {
			k := r.ID
			if attr == "order" {
				k = fmt.Sprint(r.Order)
			}
			seen[k]++
		}
		var dup []string
		for k, n := range seen {
			if n > 1 {
				dup = append(dup, k)
			}
		}
		if len(dup) > 0 {
			sort.Strings(dup)
			return nil, fmt.Errorf("decide: rule %s registered twice: %v", attr, dup)
		}
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Order < rules[j].Order })
	env2, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("decide: CEL environment: %w", err)
	}
	for _, r := range rules {
		if r.ID == "" || r.Name == "" || r.Message == "" || r.Hint == "" {
			return nil, fmt.Errorf("decide: rule %q: id, name, message and hint are all required", r.ID)
		}
		ast, iss := env2.Compile(r.Expr)
		if iss.Err() != nil {
			return nil, fmt.Errorf("decide: rule %s does not compile: %w", r.ID, iss.Err())
		}
		if !ast.OutputType().IsExactType(cel.BoolType) {
			return nil, fmt.Errorf("decide: rule %s: expression is %s, not bool", r.ID, ast.OutputType())
		}
		est, err := env2.EstimateCost(ast, sizeEstimator{})
		if err != nil {
			return nil, fmt.Errorf("decide: rule %s: cost: %w", r.ID, err)
		}
		if est.Max > MaxRuleCost {
			return nil, fmt.Errorf("decide: rule %s: worst-case cost %d is over the limit %d", r.ID, est.Max, MaxRuleCost)
		}
		prg, err := env2.Program(ast, cel.CostLimit(MaxRuleCost), cel.EvalOptions(cel.OptOptimize))
		if err != nil {
			return nil, fmt.Errorf("decide: rule %s: %w", r.ID, err)
		}
		b.rules = append(b.rules, compiled{Rule: r, prg: prg})
	}
	b.name = strings.Join(names, "+")
	sum := sha256.New()
	enc := json.NewEncoder(sum)
	for _, part := range []any{names, rules, tools, core.Tripwires, b.prToolList, b.sections, env} {
		if err := enc.Encode(part); err != nil {
			return nil, err
		}
	}
	for _, lb := range opt.Bundles {
		if err := enc.Encode(lb.Digest); err != nil {
			return nil, err
		}
	}
	b.version = hex.EncodeToString(sum.Sum(nil))[:16]
	return b, nil
}
