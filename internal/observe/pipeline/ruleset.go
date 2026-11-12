package pipeline

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"go.yaml.in/yaml/v3"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/pycompat"
)

// Schema names the rule-set bundle's document shape.
const Schema = "clearance.observe-rules/v1"

// DefaultCostLimit bounds one rule: both the cost cel-go estimates for it at load (an expression whose worst case is
// above it does not load) and the cost its evaluation may spend (an evaluation over it is cut off). A rule cannot be
// slow, and a bundle with one that could be does not load.
const DefaultCostLimit uint64 = 10_000

// Provider names.
const (
	Kubernetes = "kubernetes"
	AWS        = "aws"
)

// Outcomes an attribution rule may give. Classify maps each to a coverage state and a tier.
const (
	OutcomeCleared       = "cleared"
	OutcomeOutOfBand     = "out-of-band"
	OutcomeNotAttributed = "observed-not-attributed"
	OutcomeBreakGlass    = "break-glass"
	OutcomeRefused       = "attempted-refused"
	OutcomeMonitoring    = "monitoring-protection"
)

// Outcomes lists them.
var Outcomes = []string{OutcomeCleared, OutcomeOutOfBand, OutcomeNotAttributed, OutcomeBreakGlass, OutcomeRefused, OutcomeMonitoring}

// Severities, lowest first.
var Severities = []string{"info", "low", "medium", "high", "critical"}

//go:embed default.yaml
var defaultRules []byte

// DefaultRules is the bundle the build ships: the attribution orders of the O-3 and O-4 cards and the noise rules
// the card names, for the documentation-style scopes it lists. A deployment supplies its own (same schema), naming
// its clusters, accounts and the identities of its controllers.
func DefaultRules() []byte { return slices.Clone(defaultRules) }

// ---- the document -----------------------------------------------------------------------------------------------

type doc struct {
	Schema      string              `yaml:"schema"`
	Name        string              `yaml:"name"`
	Version     string              `yaml:"version"`
	CostLimit   uint64              `yaml:"cost_limit"`
	Identities  Identities          `yaml:"identities"`
	Annotations AnnotationNames     `yaml:"annotations"`
	Scope       scopeDoc            `yaml:"scope"`
	Noise       []noiseDoc          `yaml:"noise"`
	Monitoring  MonitoringOps       `yaml:"monitoring"`
	Attribute   map[string][]sigDoc `yaml:"attribute"`
	Classify    map[string]ClassDoc `yaml:"classify"`
	Correlate   correlateDoc        `yaml:"correlate"`
}

// Identities are the named sets the attribution facts are built from.
type Identities struct {
	ArgoController   []string `yaml:"argo_controller"`   // Kubernetes subjects of Argo CD's controller (the gated instance: its writes are cleared by grants)
	PlatformGitops   []string `yaml:"platform_gitops"`   // Kubernetes subjects of the application controllers of Argo CD instances that sync the cluster repo (G-ARGO-10a)
	FederatedPrefix  []string `yaml:"federated_prefix"`  // Kubernetes subject prefixes of federated identities
	ApplyRoles       []string `yaml:"apply_roles"`       // AWS session-issuer ARNs of the apply role(s)
	SSOAdminRoles    []string `yaml:"sso_admin_roles"`   // AWS session-issuer ARN globs of the SSO admin role(s)
	TaskIDExtraKey   string   `yaml:"task_id_extra_key"` // the user.extra key a federated identity's task id is under
	KubectlUserAgent string   `yaml:"kubectl_user_agent"`
}

// AnnotationNames are the gate's annotations on rendered objects.
type AnnotationNames struct {
	Grant    string   `yaml:"grant"`
	Rendered string   `yaml:"rendered"`
	Strip    []string `yaml:"strip"` // other annotations hashing ignores (the gate's tree and release, Argo's tracking id)
	// TrackingID is the annotation Argo CD puts on every object it applies, naming the Application (default
	// argocd.argoproj.io/tracking-id; the "annotation" and "annotation+label" tracking methods write it).
	TrackingID string `yaml:"tracking_id"`
	// ControllerOwned are the annotations a controller keeps on an object it manages (an entry ending in "/" is a prefix),
	// and ControllerLabels the labels: hashing ignores them, so a controller's bookkeeping on a granted object does not
	// make the object differ from what the grant rendered. Never the fields a grant renders.
	ControllerOwned  []string `yaml:"controller_owned"`
	ControllerLabels []string `yaml:"controller_labels"`
}

type scopeDoc struct {
	Governed []Governed `yaml:"governed"`
}

// Governed is one place whose writes the pipeline keeps. Empty lists mean any.
type Governed struct {
	Provider   string   `yaml:"provider"`
	Scopes     []string `yaml:"scopes"` // cluster names, account ids (fnmatch globs)
	Namespaces []string `yaml:"namespaces"`
	Kinds      []string `yaml:"kinds"`
	When       string   `yaml:"when"`
}

type noiseDoc struct {
	Name     string   `yaml:"name"`
	Provider string   `yaml:"provider"`
	Why      string   `yaml:"why"`
	Identity identDoc `yaml:"identity"`
	Shape    shapeDoc `yaml:"shape"`
}

type identDoc struct {
	Subject string `yaml:"subject"` // exact; never a pattern
	Issuer  string `yaml:"issuer"`  // AWS: the exact session-issuer ARN
}

type shapeDoc struct {
	Kinds        []string `yaml:"kinds"` // Kubernetes kinds / AWS event sources, exact
	Verbs        []string `yaml:"verbs"` // Kubernetes verbs / AWS event names, exact
	Namespaces   []string `yaml:"namespaces"`
	Subresources []string `yaml:"subresources"`
	When         string   `yaml:"when"`
}

// MonitoringOps are the operations that protect monitoring, per provider, beside the vocabulary's globs.
type MonitoringOps struct {
	AWS        []string `yaml:"aws"`        // event names (fnmatch globs)
	Azure      []string `yaml:"azure"`      // operation names
	Google     []string `yaml:"google"`     // method names
	Kubernetes []string `yaml:"kubernetes"` // kinds whose change is a change to the audit/webhook controls
	ConfigMaps []string `yaml:"kubernetes_configmaps"`
	// KubernetesExempt are the named carve-outs from Kubernetes monitoring-protection: a controller that maintains
	// its own webhook configurations. See validateExempt.
	KubernetesExempt []ExemptDoc `yaml:"kubernetes_exempt"`
}

// ExemptDoc is one named exception: a succeeded write by exactly this subject, with one of these verbs, to a webhook
// configuration of one of these kinds whose name matches one of these globs, is routine noise, not monitoring-protection.
type ExemptDoc struct {
	Name    string   `yaml:"name"`
	Why     string   `yaml:"why"`
	Subject string   `yaml:"subject"` // exact; never a pattern
	Verbs   []string `yaml:"verbs"`   // exact
	Kinds   []string `yaml:"kinds"`   // the webhook configuration kinds only
	Names   []string `yaml:"names"`   // fnmatch globs on the object name ("*" is any)
}

type sigDoc struct {
	Signal     string `yaml:"signal"`
	When       string `yaml:"when"`
	Outcome    string `yaml:"outcome"`
	Severity   string `yaml:"severity"`
	Confidence string `yaml:"confidence"`
	Detail     string `yaml:"detail"`
}

// ClassDoc maps an outcome to a coverage state and a tier.
type ClassDoc struct {
	Coverage string `yaml:"coverage"`
	Tier     int    `yaml:"tier"`
}

type correlateDoc struct {
	Window       string `yaml:"window"`
	RevertWindow string `yaml:"revert_window"`
}

// ---- the compiled rule set --------------------------------------------------------------------------------------

// RuleSetRef names the rule set in force; every assessment carries it.
type RuleSetRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"` // sha256 of the bundle's bytes
}

type noiseRule struct {
	name, why, provider string
	subject, issuer     string
	kinds, verbs, ns    []string
	subresources        []string
	when                cel.Program
}

type governed struct {
	Governed
	when cel.Program
}

type signal struct {
	name, outcome, severity, confidence, detail string
	when                                        cel.Program
}

// RuleSet is a bundle compiled once. It is read-only after Load and safe to share.
type RuleSet struct {
	Ref        RuleSetRef
	CostLimit  uint64
	ids        Identities
	ann        AnnotationNames
	governed   []governed
	noise      []noiseRule
	noiseBySub map[string][]int
	monitoring MonitoringOps
	attribute  map[string][]signal
	classify   map[string]ClassDoc
	window     time.Duration
	revert     time.Duration
	// Costs is each rule's estimated worst-case cost, by rule name, for the documentation and the tests.
	Costs map[string]uint64
}

// Default loads DefaultRules.
func Default() (*RuleSet, error) { return Load(defaultRules) }

var (
	celEnv  *cel.Env
	envOnce error
)

func init() {
	celEnv, envOnce = cel.NewEnv(
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("facts", cel.MapType(cel.StringType, cel.DynType)),
		cel.Function("glob",
			cel.Overload("glob_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(a, b ref.Val) ref.Val {
					s, ok1 := a.Value().(string)
					g, ok2 := b.Value().(string)
					if !ok1 || !ok2 {
						return types.False
					}
					return types.Bool(pycompat.Match(s, g))
				}))),
	)
}

// estimator gives every variable-length value of an event a worst-case size, so cel-go can bound a rule's cost.
type estimator struct{}

func (estimator) EstimateSize(checker.AstNode) *checker.SizeEstimate {
	return &checker.SizeEstimate{Min: 0, Max: 64}
}
func (estimator) EstimateCallCost(string, string, *checker.AstNode, []checker.AstNode) *checker.CallEstimate {
	return nil
}

// Load compiles a bundle. A rule that does not compile, whose output is not a boolean, whose estimated cost is over
// the cost limit, or that the validators refuse (a noise rule that is not an identity paired with an exact shape, an
// attribution list with no catch-all) fails the whole load: there is no partial rule set.
func Load(b []byte) (*RuleSet, error) {
	if envOnce != nil {
		return nil, envOnce
	}
	var d doc
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("observe rules: %w", err)
	}
	if d.Schema != Schema {
		return nil, fmt.Errorf("observe rules: schema is %q, want %q", d.Schema, Schema)
	}
	if d.Name == "" || d.Version == "" {
		return nil, errors.New("observe rules: name and version are required (every assessment names the rule set it was made under)")
	}
	sum := sha256.Sum256(b)
	rs := &RuleSet{Ref: RuleSetRef{d.Name, d.Version, hex.EncodeToString(sum[:])}, CostLimit: d.CostLimit,
		ids: d.Identities, ann: d.Annotations, monitoring: d.Monitoring, classify: d.Classify,
		noiseBySub: map[string][]int{}, attribute: map[string][]signal{}, Costs: map[string]uint64{}}
	if rs.CostLimit == 0 {
		rs.CostLimit = DefaultCostLimit
	}
	if rs.ann.Grant == "" || rs.ann.Rendered == "" {
		return nil, errors.New("observe rules: annotations.grant and annotations.rendered name the gate's annotations")
	}
	if rs.ann.TrackingID == "" {
		rs.ann.TrackingID = DefaultTrackingID
	}
	if err := validatePlatformGitops(rs.ids); err != nil {
		return nil, err
	}
	if rs.ids.KubectlUserAgent == "" {
		rs.ids.KubectlUserAgent = "kubectl"
	}
	var err error
	if rs.window, err = duration(d.Correlate.Window, 30*time.Second); err != nil {
		return nil, fmt.Errorf("observe rules: correlate.window: %w", err)
	}
	if rs.revert, err = duration(d.Correlate.RevertWindow, time.Hour); err != nil {
		return nil, fmt.Errorf("observe rules: correlate.revert_window: %w", err)
	}
	if err := rs.loadScope(d); err != nil {
		return nil, err
	}
	if err := rs.loadNoise(d); err != nil {
		return nil, err
	}
	if err := rs.loadExempt(); err != nil {
		return nil, err
	}
	if err := rs.loadAttribute(d); err != nil {
		return nil, err
	}
	return rs, rs.loadClassify()
}

// DefaultTrackingID is Argo CD's resource-tracking annotation.
const DefaultTrackingID = "argocd.argoproj.io/tracking-id"

// validatePlatformGitops refuses an identity list that is not exact subjects, or that names a subject the gated
// instance also uses: one controller cannot be both "its writes are cleared by grants" and "its writes are GitOps".
func validatePlatformGitops(ids Identities) error {
	for _, s := range ids.PlatformGitops {
		switch {
		case s == "" || strings.ContainsAny(s, "*?[]"):
			return fmt.Errorf("observe rules: identities.platform_gitops %q: a subject is exact, never a pattern", s)
		case strings.HasPrefix(s, "system:serviceaccounts") || s == "system:serviceaccount" || s == "system:authenticated" ||
			s == "system:unauthenticated" || strings.HasPrefix(s, "system:masters"):
			return fmt.Errorf("observe rules: identities.platform_gitops %q is a group, not an identity", s)
		case !strings.HasPrefix(s, "system:serviceaccount:") || len(strings.Split(s, ":")) != 4:
			return fmt.Errorf("observe rules: identities.platform_gitops %q is not one service account (system:serviceaccount:<namespace>:<name>)", s)
		case slices.Contains(ids.ArgoController, s):
			return fmt.Errorf("observe rules: identities.platform_gitops %q is also in identities.argo_controller: the gated instance's writes are cleared by grants, not by GitOps", s)
		}
	}
	return nil
}

func duration(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%q is not a positive duration", s)
	}
	return d, nil
}

// compile compiles expr (a boolean) under the cost limit; "" is no expression (nil program).
func (rs *RuleSet) compile(rule, expr string) (cel.Program, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, nil
	}
	ast, iss := celEnv.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("observe rules: %s: %w", rule, iss.Err())
	}
	// A field of event or facts is dyn; the evaluation refuses a result that is not a bool (evalBool).
	if t := ast.OutputType(); t != cel.BoolType && t != cel.DynType {
		return nil, fmt.Errorf("observe rules: %s: the expression is %s, not a bool", rule, t)
	}
	est, err := celEnv.EstimateCost(ast, estimator{})
	if err != nil {
		return nil, fmt.Errorf("observe rules: %s: cost: %w", rule, err)
	}
	if est.Max > rs.CostLimit {
		return nil, fmt.Errorf("observe rules: %s: worst-case cost %d is over the cost limit %d", rule, est.Max, rs.CostLimit)
	}
	rs.Costs[rule] = est.Max
	prg, err := celEnv.Program(ast, cel.CostLimit(rs.CostLimit))
	if err != nil {
		return nil, fmt.Errorf("observe rules: %s: %w", rule, err)
	}
	return prg, nil
}

func (rs *RuleSet) loadScope(d doc) error {
	if len(d.Scope.Governed) == 0 {
		return errors.New("observe rules: scope.governed names no cluster or account: a rule set that governs nothing is a mistake, not a policy")
	}
	for i, g := range d.Scope.Governed {
		if g.Provider != Kubernetes && g.Provider != AWS {
			return fmt.Errorf("observe rules: scope.governed[%d].provider is %q or %q", i, Kubernetes, AWS)
		}
		if len(g.Scopes) == 0 {
			return fmt.Errorf("observe rules: scope.governed[%d].scopes names the clusters or accounts governed", i)
		}
		p, err := rs.compile(fmt.Sprintf("scope.governed[%d]", i), g.When)
		if err != nil {
			return err
		}
		rs.governed = append(rs.governed, governed{g, p})
	}
	return nil
}

// ErrBlanketNoise is what the noise validator returns for a rule that is not an identity paired with an exact shape.
var ErrBlanketNoise = errors.New("a noise rule pairs one exact identity with the exact shape it may touch")

func (rs *RuleSet) loadNoise(d doc) error {
	seen := map[string]bool{}
	for i, n := range d.Noise {
		where := fmt.Sprintf("noise[%d]", i)
		if n.Name != "" {
			where = "noise." + n.Name
		}
		if err := validateNoise(n); err != nil {
			return fmt.Errorf("observe rules: %s: %w", where, err)
		}
		if seen[n.Name] {
			return fmt.Errorf("observe rules: %s: duplicate rule name", where)
		}
		seen[n.Name] = true
		p, err := rs.compile(where, n.Shape.When)
		if err != nil {
			return err
		}
		r := noiseRule{name: n.Name, why: n.Why, provider: n.Provider, subject: n.Identity.Subject, issuer: n.Identity.Issuer,
			kinds: n.Shape.Kinds, verbs: n.Shape.Verbs, ns: n.Shape.Namespaces, subresources: n.Shape.Subresources, when: p}
		key := n.Provider + "\x00" + n.Identity.Subject + "\x00" + n.Identity.Issuer
		rs.noiseBySub[key] = append(rs.noiseBySub[key], len(rs.noise))
		rs.noise = append(rs.noise, r)
	}
	return nil
}

// webhookKinds are the only kinds a monitoring exemption may name.
var webhookKinds = []string{"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}

func (rs *RuleSet) loadExempt() error {
	seen := map[string]bool{}
	for i, x := range rs.monitoring.KubernetesExempt {
		if err := validateExempt(x); err != nil {
			return fmt.Errorf("observe rules: monitoring.kubernetes_exempt[%d]: %w", i, err)
		}
		if seen[x.Name] { // the name is the filtered-count key: two entries would share one line of the health record
			return fmt.Errorf("observe rules: monitoring.kubernetes_exempt[%d]: name %q is used twice", i, x.Name)
		}
		seen[x.Name] = true
	}
	return nil
}

// validateExempt refuses an exemption that is not one exact subject, with exact verbs, restricted to the webhook
// configuration kinds and to named objects.
func validateExempt(x ExemptDoc) error {
	if x.Name == "" || x.Why == "" {
		return errors.New("name it and say why")
	}
	s := x.Subject
	switch {
	case s == "":
		return errors.New("subject is the one subject the exemption is for")
	case strings.ContainsAny(s, "*?[]"):
		return fmt.Errorf("subject %q is a pattern: an identity is exact", s)
	case strings.HasPrefix(s, "system:serviceaccounts") || s == "system:serviceaccount" || s == "system:authenticated" ||
		s == "system:unauthenticated" || strings.HasPrefix(s, "system:masters"):
		return fmt.Errorf("subject %q is a group, not an identity", s)
	case strings.HasPrefix(s, "system:serviceaccount:"):
		if p := strings.Split(s, ":"); len(p) != 4 || p[2] == "" || p[3] == "" {
			return fmt.Errorf("subject %q is not one service account", s)
		}
	}
	if len(x.Verbs) == 0 {
		return errors.New("verbs name how the subject may write")
	}
	for _, v := range x.Verbs {
		if v == "" || strings.ContainsAny(v, "*?[]") {
			return fmt.Errorf("verbs are exact (%q)", v)
		}
	}
	if len(x.Kinds) == 0 {
		return errors.New("kinds must name the webhook configuration kinds the subject may write")
	}
	for _, k := range x.Kinds {
		if !slices.Contains(webhookKinds, k) {
			return fmt.Errorf("kinds names %q: an exemption covers only %v", k, webhookKinds)
		}
	}
	if len(x.Names) == 0 {
		return errors.New("names are globs on the object name (\"*\" for any)")
	}
	for _, n := range x.Names {
		if n == "" {
			return errors.New("names has an empty entry")
		}
	}
	return nil
}

// monitoringKinds are the kinds a noise rule may never name: dropping a change to them would hide an operation on
// monitoring. (The pipeline never drops a monitoring operation either way; the validator says so at load.)
var monitoringKinds = []string{"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration", "ValidatingAdmissionPolicy",
	"ValidatingAdmissionPolicyBinding", "MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding"}

// validateNoise refuses every noise rule that is not an identity paired with the exact shape it may touch. "Anything
// from a service account" is refused here, at load, not by convention: an identity is one exact subject (no pattern,
// no group, no namespace-wide service account), and a shape names its kinds and its verbs, exactly.
func validateNoise(n noiseDoc) error {
	wrap := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrBlanketNoise}, a...)...)
	}
	if n.Name == "" || n.Why == "" {
		return wrap("name it and say why (why: the controller's job this write is)")
	}
	if n.Provider != Kubernetes && n.Provider != AWS {
		return wrap("provider is %q or %q", Kubernetes, AWS)
	}
	s := n.Identity.Subject
	switch {
	case s == "":
		return wrap("identity.subject is the one subject the rule is for")
	case strings.ContainsAny(s, "*?[]"):
		return wrap("identity.subject %q is a pattern: an identity is exact", s)
	case strings.HasPrefix(s, "system:serviceaccounts"):
		return wrap("identity.subject %q is a service-account group: anything from a service account is not a rule", s)
	case strings.HasPrefix(s, "system:serviceaccount:"):
		p := strings.Split(s, ":")
		if len(p) != 4 || p[2] == "" || p[3] == "" {
			return wrap("identity.subject %q is not one service account (system:serviceaccount:<namespace>:<name>)", s)
		}
	case s == "system:serviceaccount" || s == "system:authenticated" || s == "system:unauthenticated" || strings.HasPrefix(s, "system:masters"):
		return wrap("identity.subject %q is a group, not an identity", s)
	}
	if strings.ContainsAny(n.Identity.Issuer, "*?[]") {
		return wrap("identity.issuer is exact")
	}
	if len(n.Shape.Kinds) == 0 || len(n.Shape.Verbs) == 0 {
		return wrap("shape.kinds and shape.verbs name what the identity may touch and how")
	}
	for _, list := range [][]string{n.Shape.Kinds, n.Shape.Verbs, n.Shape.Namespaces, n.Shape.Subresources} {
		for _, x := range list {
			if x == "" || strings.ContainsAny(x, "*?[]") {
				return wrap("shape entries are exact names, not patterns (%q)", x)
			}
		}
	}
	for _, k := range n.Shape.Kinds {
		if slices.Contains(monitoringKinds, k) {
			return wrap("shape.kinds names %s: a change to monitoring is never noise", k)
		}
	}
	if w := strings.TrimSpace(n.Shape.When); w == "true" {
		return wrap("shape.when is unconditional")
	}
	return nil
}

func (rs *RuleSet) loadAttribute(d doc) error {
	for _, prov := range []string{Kubernetes, AWS} {
		list := d.Attribute[prov]
		if len(list) == 0 {
			return fmt.Errorf("observe rules: attribute.%s: no signals", prov)
		}
		for i, s := range list {
			where := fmt.Sprintf("attribute.%s[%d](%s)", prov, i, s.Signal)
			if s.Signal == "" || s.Detail == "" {
				return fmt.Errorf("observe rules: %s: signal and detail are required", where)
			}
			if !slices.Contains(Outcomes, s.Outcome) || s.Outcome == OutcomeMonitoring {
				return fmt.Errorf("observe rules: %s: outcome is one of %v (monitoring-protection is the pipeline's, not a rule's)", where, Outcomes[:5])
			}
			if !slices.Contains(Severities, s.Severity) {
				return fmt.Errorf("observe rules: %s: severity is one of %v", where, Severities)
			}
			if strings.TrimSpace(s.When) == "" {
				return fmt.Errorf("observe rules: %s: when is required", where)
			}
			p, err := rs.compile(where, s.When)
			if err != nil {
				return err
			}
			rs.attribute[prov] = append(rs.attribute[prov], signal{s.Signal, s.Outcome, s.Severity, s.Confidence, s.Detail, p})
			if i == len(list)-1 && strings.TrimSpace(s.When) != "true" {
				return fmt.Errorf("observe rules: %s: the last signal is the catch-all (when: \"true\"): every surviving event gets an assessment", where)
			}
		}
	}
	for p := range d.Attribute {
		if p != Kubernetes && p != AWS {
			return fmt.Errorf("observe rules: attribute.%s: no such provider", p)
		}
	}
	return nil
}

func (rs *RuleSet) loadClassify() error {
	for _, o := range Outcomes {
		c, ok := rs.classify[o]
		if !ok {
			return fmt.Errorf("observe rules: classify.%s is missing: every outcome maps to a coverage state and a tier", o)
		}
		if !slices.Contains(evidence.Coverage, c.Coverage) || c.Tier < 0 || c.Tier > 3 {
			return fmt.Errorf("observe rules: classify.%s: coverage is one of %v and tier 0 to 3", o, evidence.Coverage)
		}
	}
	if rs.classify[OutcomeMonitoring].Tier != 3 {
		return errors.New("observe rules: classify.monitoring-protection is tier 3: an operation on monitoring is tier 3 whether or not it succeeded")
	}
	for o := range rs.classify {
		if !slices.Contains(Outcomes, o) {
			return fmt.Errorf("observe rules: classify.%s: no such outcome", o)
		}
	}
	return nil
}
