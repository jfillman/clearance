package decide

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common/types"
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

// BundleData is a bundle as data: core.json, or a pack's own file.
type BundleData struct {
	Name      string     `json:"name"`
	Rules     []Rule     `json:"rules"`
	Tools     []ToolSpec `json:"tools"`
	Tripwires []string   `json:"tripwires,omitempty"`
	PRTools   []string   `json:"pr_tools,omitempty"`
	LowerEnvs []string   `json:"lower_envs,omitempty"`
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

// Var is a context variable a pack's rules read, as ctx.<Name>.
type Var struct {
	Name string
	Type *cel.Type // cel.BoolType or cel.IntType
}

// The CEL variables of the core context. Every rule reads only these and its packs' Vars.
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

// bundle is the compiled policy: core plus packs, rules in order.
type bundle struct {
	name, version string
	rules         []compiled
	tools         map[string]*ToolSpec
	toolList      []ToolSpec
	tripwires     map[string]bool
	prTools       map[string]bool
	lowerEnvs     map[string]bool
	slots         map[string]int // CEL variable name -> activation slot
	packs         []Pack
	packBase      []int // first slot of each pack's variables
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

func compileBundle(core BundleData, packs []Pack) (*bundle, error) {
	b := &bundle{
		tools: map[string]*ToolSpec{}, tripwires: map[string]bool{}, prTools: map[string]bool{},
		lowerEnvs: map[string]bool{}, slots: map[string]int{}, packs: packs,
	}
	for _, t := range core.Tripwires {
		b.tripwires[t] = true
	}
	for _, t := range core.PRTools {
		b.prTools[t] = true
	}
	for _, e := range core.LowerEnvs {
		b.lowerEnvs[e] = true
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
	for _, p := range packs {
		names = append(names, p.Name())
		tools = append(tools, p.Tools()...)
		rules = append(rules, p.Rules()...)
		b.packBase = append(b.packBase, next)
		for _, v := range p.Vars() {
			name := "ctx." + v.Name
			if _, dup := b.slots[name]; dup {
				return nil, fmt.Errorf("decide: pack %q redefines context keys [%q]", p.Name(), v.Name)
			}
			b.slots[name] = next
			next++
			opts = append(opts, cel.Variable(name, v.Type))
		}
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
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("decide: CEL environment: %w", err)
	}
	for _, r := range rules {
		if r.ID == "" || r.Name == "" || r.Message == "" || r.Hint == "" {
			return nil, fmt.Errorf("decide: rule %q: id, name, message and hint are all required", r.ID)
		}
		ast, iss := env.Compile(r.Expr)
		if iss.Err() != nil {
			return nil, fmt.Errorf("decide: rule %s does not compile: %w", r.ID, iss.Err())
		}
		if !ast.OutputType().IsExactType(cel.BoolType) {
			return nil, fmt.Errorf("decide: rule %s: expression is %s, not bool", r.ID, ast.OutputType())
		}
		est, err := env.EstimateCost(ast, sizeEstimator{})
		if err != nil {
			return nil, fmt.Errorf("decide: rule %s: cost: %w", r.ID, err)
		}
		if est.Max > MaxRuleCost {
			return nil, fmt.Errorf("decide: rule %s: worst-case cost %d is over the limit %d", r.ID, est.Max, MaxRuleCost)
		}
		prg, err := env.Program(ast, cel.CostLimit(MaxRuleCost), cel.EvalOptions(cel.OptOptimize))
		if err != nil {
			return nil, fmt.Errorf("decide: rule %s: %w", r.ID, err)
		}
		b.rules = append(b.rules, compiled{Rule: r, prg: prg})
	}
	b.name = strings.Join(names, "+")
	sum := sha256.New()
	enc := json.NewEncoder(sum)
	for _, part := range []any{names, rules, tools, core.Tripwires, core.PRTools, core.LowerEnvs} {
		if err := enc.Encode(part); err != nil {
			return nil, err
		}
	}
	for _, p := range packs {
		if err := enc.Encode(p.Data()); err != nil {
			return nil, err
		}
	}
	b.version = hex.EncodeToString(sum.Sum(nil))[:16]
	return b, nil
}
