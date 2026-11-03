// Package review answers two questions a CI check asks about an agent definition before it is live, ported from
// review.py: would Clearance load it and could its agent use what it lists (Validate, DF-* rules), and how much
// more or less may the agent do after a change (Classify, tiers 0-3, every reason naming the field and the change).
package review

import (
	"fmt"
	"github.com/jfillman/clearance/internal/vocab"
	"math/big"
	"regexp"
	"sort"
	"strings"

	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/pycompat"
)

var (
	digestRx      = regexp.MustCompile(`@sha256:[0-9a-f]{64}\z`)
	placeholderRx = regexp.MustCompile(`@sha256:0{64}\z`) // profile.PLACEHOLDER_DIGEST
	tierOf        = map[string]int{"T0": 0, "T1": 1, "T2": 2, "T3": 3}
	limitKeys     = []string{"ttlMinutes", "toolCalls", "githubCalls", "openPrs", "modelTokens", "children"}
)

// ToolSpec is what review reads of a registered tool (tiers.ToolSpec).
type ToolSpec struct {
	Tier        int
	ProposeOnly bool
	WritesFiles bool
	ReadsRepo   bool
}

// Registry is the deployment's tool registry (core plus its policy bundles') and the T3 tripwire names.
type Registry struct {
	Tools     map[string]ToolSpec
	Tripwires map[string]bool
}

// Problem is one reason a definition would not load or could not be used.
type Problem struct {
	Rule    string `json:"rule"`
	Path    string `json:"path"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

// Change is one reason for a definition change's tier.
type Change struct {
	Field  string `json:"field"`
	Change string `json:"change"`
	Tier   int    `json:"tier"`
}

// Options are validate()'s keyword arguments. Name, Owner and Path are checked when set; Models nil means the
// deployment's model routes are not checked; ImageAllow empty means any digest-pinned image.
type Options struct {
	Name, Owner, Path *string
	Models            []string
	ImageAllow        []string
}

// Validate is review.validate: every problem with the document, empty when Clearance would load it and its agent
// could use every tool it lists.
func Validate(doc any, reg Registry, parse definitions.Parser, o Options) []Problem {
	m, ok := doc.(map[string]any)
	if !ok {
		return []Problem{{"DF-SCHEMA", "", "the file is not a YAML mapping (an agent definition)", ""}}
	}
	if desc, ok := m["description"].(string); !ok || strings.TrimSpace(desc) == "" {
		return []Problem{{"DF-DESCRIPTION", "description", "the definition has no description",
			"Add one line saying what the agent is for: `description: Explains why a CI run failed.`"}}
	}
	if rt, ok := m["runtime"].(map[string]any); ok {
		if img, ok := rt["image"].(string); ok && placeholderRx.MatchString(img) {
			return []Problem{{"DF-IMAGE", "runtime.image", img + " is a placeholder digest",
				"Pick a runtime from the catalog (GET /v1/runtimes), or leave runtime.image out: the agent then runs in a person's MCP client."}}
		}
	}
	d, err := parse(m)
	if err != nil {
		return []Problem{{"DF-SCHEMA", "", err.Error(), "Fix the field the message names (clearance schemas/agent-definition.schema.json)."}}
	}
	var out []Problem
	if o.Path != nil && *o.Path != "" {
		p := *o.Path
		stem := p[strings.LastIndex(p, "/")+1:]
		if i := strings.LastIndex(stem, "."); i >= 0 {
			stem = stem[:i]
		}
		if stem != d.Name {
			out = append(out, Problem{"DF-NAME", "name", fmt.Sprintf("the file is %s but the agent is named %s", p, pycompat.Repr(d.Name)),
				fmt.Sprintf("Name the file %s.yaml.", d.Name)})
		}
	}
	if o.Name != nil && d.Name != *o.Name {
		out = append(out, Problem{"DF-NAME", "name", fmt.Sprintf("the pin is named %s but the file's name is %s", pycompat.Repr(*o.Name), pycompat.Repr(d.Name)), ""})
	}
	if o.Owner != nil && (!d.HasOwner || d.Owner != *o.Owner) {
		fileOwner := "None"
		if d.HasOwner {
			fileOwner = pycompat.Repr(d.Owner)
		}
		out = append(out, Problem{"DF-OWNER", "owner", fmt.Sprintf("the pin's owner is %s but the file's is %s", pycompat.Repr(*o.Owner), fileOwner), "They must agree."})
	}
	if d.IdentityType == "workload" && d.ServiceAccount != vocab.Get().RunIdentityNamespace+"/"+d.Name {
		sa := "None"
		if d.ServiceAccount != "" {
			sa = pycompat.Repr(d.ServiceAccount)
		}
		out = append(out, Problem{"DF-IDENTITY", "identity.serviceAccount", fmt.Sprintf("a workload agent runs as %s/%s, not %s", vocab.Get().RunIdentityNamespace, d.Name, sa), ""})
	}
	ceiling := d.TierCeiling
	var repoTools []string
	for _, t := range sortedStrings(get(m, "profile", "tools")) {
		if reg.Tripwires[t] {
			out = append(out, Problem{"DF-TRIPWIRE", "profile.tools", t + " is a tripwire: calling it trips the session's breaker", "Remove it."})
			continue
		}
		spec, ok := reg.Tools[t]
		if !ok {
			out = append(out, Problem{"DF-TOOL", "profile.tools", t + " is not a tool this Clearance registers", "Pick a tool from GET /v1/policy."})
			continue
		}
		if spec.Tier > ceiling && !(spec.ProposeOnly && ceiling >= 1) {
			out = append(out, Problem{"DF-CEILING", "profile.tools", fmt.Sprintf("%s is %s above the ceiling %s (R007: every call would be denied)", t, tierName(spec.Tier), tierName(ceiling)),
				fmt.Sprintf("Raise tierCeiling to %s, or drop the tool.", tierName(spec.Tier))})
		}
		if spec.WritesFiles || spec.ReadsRepo {
			repoTools = append(repoTools, t)
		}
	}
	if len(repoTools) > 0 && len(d.ReposAllow) == 0 {
		out = append(out, Problem{"DF-REPOS", "profile.repos.allow", strings.Join(repoTools, ", ") + " name a repo, and repos.allow is empty (R014: every call would be denied)",
			"List the repos the agent may use."})
	}
	if o.Models != nil {
		routed := map[string]bool{}
		for _, x := range o.Models {
			routed[x] = true
		}
		sortedRoutes := append([]string(nil), o.Models...)
		sort.Strings(sortedRoutes)
		use := strings.Join(sortedRoutes, ", ")
		if use == "" {
			use = "none"
		}
		var missing []string
		for _, x := range uniq(d.Models) {
			if !routed[x] {
				missing = append(missing, x)
			}
		}
		sort.Strings(missing)
		for _, x := range missing {
			out = append(out, Problem{"DF-MODEL", "profile.models", x + " is not a model this deployment routes", "Use one of: " + use + "."})
		}
	}
	if img := d.Image; img != "" {
		if !digestRx.MatchString(img) {
			out = append(out, Problem{"DF-IMAGE", "runtime.image", img + " is not pinned by digest", "Pin it: <registry>/<repo>@sha256:<64 hex>."})
		} else if len(o.ImageAllow) > 0 && !pycompat.MatchAny(img, o.ImageAllow) {
			out = append(out, Problem{"DF-IMAGE", "runtime.image", img + " is not from an allowed runtime source",
				"Use an image from the runtime catalog, or one your CI built for this agent's own repository."})
		}
	}
	return out
}

func tierName(t int) string {
	if t >= 0 && t < len(definitions.TierNames) {
		return definitions.TierNames[t]
	}
	return fmt.Sprintf("T%d", t)
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func sortedStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			out = append(out, pycompat.Str(x))
		}
	}
	sort.Strings(out)
	return out
}

// get is review._get: walk mapping keys; a missing key, a non-mapping or None gives nil.
func get(doc any, keys ...string) any {
	cur := doc
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

func getOr(doc any, def any, keys ...string) any {
	if v := get(doc, keys...); v != nil {
		return v
	}
	return def
}

// set is review._set: a mapping's "k=v" items, else the list's items (as str).
func set(doc any, keys ...string) map[string]bool {
	out := map[string]bool{}
	switch x := get(doc, keys...).(type) {
	case map[string]any:
		for k, v := range x {
			out[k+"="+pycompat.Str(v)] = true
		}
	case []any:
		for _, v := range x {
			out[pycompat.Str(v)] = true
		}
	case string:
		for _, r := range x { // set("abc"): Python iterates the characters
			out[string(r)] = true
		}
	}
	return out
}

func minus(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func listOf(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

func (r Registry) tierOf(t string) int {
	if s, ok := r.Tools[t]; ok {
		return s.Tier
	}
	return 3
}

// Classify is review.classify: the tier of going from old to new (either may be nil: a new agent, a removed one)
// and every reason. Both documents are assumed valid.
func Classify(old, new map[string]any, reg Registry) (int, []Change) {
	var changes []Change
	add := func(f, c string, t int) { changes = append(changes, Change{f, c, t}) }
	if new == nil {
		add("agent", "removed", 1)
		return 1, changes
	}
	if old == nil {
		var writers []string
		for _, t := range sortedStrings(get(new, "profile", "tools")) {
			if reg.tierOf(t) >= 1 {
				writers = append(writers, t)
			}
		}
		if len(writers) > 0 {
			add("agent", "new agent with writing tools "+strings.Join(writers, ", "), 3)
		} else {
			add("agent", "new agent (read tools only)", 2)
		}
		return maxTier(changes), changes
	}
	str := func(v any) string { return pycompat.Str(v) }
	if !pycompat.Equal(get(old, "identity"), get(new, "identity")) {
		add("identity", str(get(old, "identity"))+" -> "+str(get(new, "identity")), 3)
	}
	if !pycompat.Equal(get(old, "owner"), get(new, "owner")) {
		add("owner", str(get(old, "owner"))+" -> "+str(get(new, "owner")), 3)
	}
	if !pycompat.Equal(get(old, "kind"), get(new, "kind")) {
		add("kind", str(get(old, "kind"))+" -> "+str(get(new, "kind")), 2)
	}
	oc, nc := ceilingOf(old), ceilingOf(new)
	if nc > oc {
		add("profile.tierCeiling", fmt.Sprintf("T%d -> T%d", oc, nc), 3)
	} else if nc < oc {
		add("profile.tierCeiling", fmt.Sprintf("T%d -> T%d", oc, nc), 1)
	}
	ot, nt := set(old, "profile", "tools"), set(new, "profile", "tools")
	for _, t := range minus(nt, ot) {
		tier := reg.tierOf(t)
		w := 2
		if tier >= 1 {
			w = 3
		}
		add("profile.tools", fmt.Sprintf("added %s (T%d)", t, tier), w)
	}
	for _, t := range minus(ot, nt) {
		add("profile.tools", "removed "+t, 1)
	}
	os, ns := scopeSets(old), scopeSets(new)
	for _, f := range scopeFields() {
		for _, v := range minus(ns[f], os[f]) {
			add(f, "added "+v, 3)
		}
		for _, v := range minus(os[f], ns[f]) {
			add(f, "removed "+v, 1)
		}
	}
	for _, f := range []string{"denyPaths", "fieldDeny"} {
		o, n := set(old, "profile", "repos", f), set(new, "profile", "repos", f)
		for _, v := range minus(o, n) {
			add("profile.repos."+f, "removed "+v, 3)
		}
		for _, v := range minus(n, o) {
			add("profile.repos."+f, "added "+v, 1)
		}
	}
	o, n := set(old, "profile", "repos", "fieldAllow"), set(new, "profile", "repos", "fieldAllow")
	for _, v := range minus(n, o) {
		add("profile.repos.fieldAllow", "added "+v, 3)
	}
	for _, v := range minus(o, n) {
		add("profile.repos.fieldAllow", "removed "+v, 1)
	}
	om, nm := set(old, "profile", "models"), set(new, "profile", "models")
	for _, v := range minus(nm, om) {
		add("profile.models", "added "+v, 2)
	}
	for _, v := range minus(om, nm) {
		add("profile.models", "removed "+v, 1)
	}
	if on, ok1 := parseEnum(getOr(old, "clearance", "profile", "network"), networks); ok1 {
		if nn, ok2 := parseEnum(getOr(new, "clearance", "profile", "network"), networks); ok2 {
			if nn > on {
				add("profile.network", networkNames[on]+" -> "+networkNames[nn], 3)
			} else if nn < on {
				add("profile.network", networkNames[on]+" -> "+networkNames[nn], 1)
			}
		}
	}
	if oc2, ok1 := parseEnum(getOr(old, "small", "profile", "compute"), computes); ok1 {
		if nc2, ok2 := parseEnum(getOr(new, "small", "profile", "compute"), computes); ok2 {
			if nc2 > oc2 {
				add("profile.compute", computeNames[oc2]+" -> "+computeNames[nc2], 2)
			} else if nc2 < oc2 {
				add("profile.compute", computeNames[oc2]+" -> "+computeNames[nc2], 1)
			}
		}
	}
	for _, k := range limitKeys {
		a, b := get(old, "profile", "limits", k), get(new, "profile", "limits", k)
		if a != nil && b != nil && !pycompat.Equal(a, b) {
			fa, okA := pycompat.Number(a)
			fb, okB := pycompat.Number(b)
			w := 1
			if okA && okB && fb.Cmp(fa) > 0 {
				w = 2
			}
			add("profile.limits."+k, str(a)+" -> "+str(b), w)
		}
	}
	if !pycompat.Equal(get(old, "runtime", "image"), get(new, "runtime", "image")) {
		add("runtime.image", str(get(old, "runtime", "image"))+" -> "+str(get(new, "runtime", "image")), 2)
	}
	osb, nsb := getOr(old, "standard", "runtime", "sandbox"), getOr(new, "standard", "runtime", "sandbox")
	if !pycompat.Equal(osb, nsb) {
		w := 3
		if pycompat.Equal(get(new, "runtime", "sandbox"), "hardened") {
			w = 1
		}
		add("runtime.sandbox", str(osb)+" -> "+str(nsb), w)
	}
	osc, nsc := listOf(get(old, "runtime", "sidecars")), listOf(get(new, "runtime", "sidecars"))
	if !pycompat.Equal(anyList(osc), anyList(nsc)) {
		w := 1
		for _, s := range nsc {
			if !inList(s, osc) {
				w = 3
				break
			}
		}
		add("runtime.sidecars", fmt.Sprintf("%d -> %d", len(osc), len(nsc)), w)
	}
	if !pycompat.Equal(get(old, "runtime", "instructions"), get(new, "runtime", "instructions")) {
		add("runtime.instructions", "changed", 0)
	}
	if !pycompat.Equal(get(old, "runtime", "framework"), get(new, "runtime", "framework")) {
		add("runtime.framework", str(get(old, "runtime", "framework"))+" -> "+str(get(new, "runtime", "framework")), 0)
	}
	ot2, nt2 := triggers(old), triggers(new)
	for _, k := range keysMinus(nt2, ot2) {
		add("triggers", "added "+k, 2)
	}
	for _, k := range keysMinus(ot2, nt2) {
		add("triggers", "removed "+k, 1)
	}
	var both []string
	for k := range nt2 {
		if _, ok := ot2[k]; ok {
			both = append(both, k)
		}
	}
	sort.Strings(both)
	for _, k := range both {
		a, b := ot2[k]["maxPerHour"], nt2[k]["maxPerHour"]
		if !pycompat.Equal(a, b) {
			w := 1
			if b == nil || numOr0(b).Cmp(numOr0(a)) > 0 {
				w = 2
			}
			add("triggers", fmt.Sprintf("%s maxPerHour %s -> %s", k, str(a), str(b)), w)
		}
	}
	if len(changes) == 0 {
		add("definition", "no change in authority", 0)
	}
	return maxTier(changes), changes
}

func anyList(l []any) any {
	if l == nil {
		return []any{}
	}
	return l
}

func inList(x any, l []any) bool {
	for _, y := range l {
		if pycompat.Equal(x, y) {
			return true
		}
	}
	return false
}

func maxTier(cs []Change) int {
	m := 0
	for _, c := range cs {
		if c.Tier > m {
			m = c.Tier
		}
	}
	return m
}

func ceilingOf(doc map[string]any) int {
	if s, ok := getOr(doc, "T0", "profile", "tierCeiling").(string); ok {
		return tierOf[s]
	}
	return 0
}

func scopeSets(doc map[string]any) map[string]map[string]bool {
	p := getOr(doc, map[string]any{}, "profile")
	list := func(keys ...string) map[string]bool {
		out := map[string]bool{}
		for _, v := range listOf(get(p, keys...)) {
			out[pycompat.Str(v)] = true
		}
		return out
	}
	out := map[string]map[string]bool{"profile.repos.allow": list("repos", "allow"), "profile.apis.allow": list("apis", "allow")}
	for _, k := range vocab.Get().ProfileSections {
		out["profile."+k+".apps"] = list(k, "apps")
	}
	return out
}

func scopeFields() []string {
	f := []string{"profile.repos.allow", "profile.apis.allow"}
	for _, k := range vocab.Get().ProfileSections {
		f = append(f, "profile."+k+".apps")
	}
	return f
}

// triggerKey is review._trigger_key: every field but maxPerHour, sorted, "k=v" joined by "|".
func triggerKey(t map[string]any) string {
	keys := make([]string, 0, len(t))
	for k := range t {
		if k != "maxPerHour" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + pycompat.Str(t[k])
	}
	return strings.Join(parts, "|")
}

func triggers(doc map[string]any) map[string]map[string]any {
	raw := get(doc, "triggers")
	var list []any
	if raw == nil {
		list = []any{map[string]any{"type": "manual"}}
	} else {
		list = listOf(raw)
	}
	out := map[string]map[string]any{}
	for _, t := range list {
		if m, ok := t.(map[string]any); ok {
			out[triggerKey(m)] = m
		}
	}
	return out
}

func keysMinus(a, b map[string]map[string]any) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func numOr0(v any) *big.Float {
	if f, ok := pycompat.Number(v); ok {
		return f
	}
	return new(big.Float)
}

// -- limits.Network and limits.ComputeClass, ordered by reach ---------------------------------------------------------

var (
	networks     = map[string]int{"NONE": 0, "CLEARANCE": 1, "CLEARANCE_MODEL": 2, "ALLOWLIST": 3}
	networkNames = []string{"none", "clearance", "clearance_model", "allowlist"}
	computes     = map[string]int{"SMALL": 0, "MEDIUM": 1, "LARGE": 2, "GPU": 3}
	computeNames = []string{"small", "medium", "large", "gpu"}
)

// parseEnum is Network.parse (upper-cased, "+" and "-" read as "_") and ComputeClass.parse (upper-cased).
func parseEnum(v any, table map[string]int) (int, bool) {
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	s = strings.ToUpper(s)
	if _, isNetwork := table["CLEARANCE_MODEL"]; isNetwork {
		s = strings.NewReplacer("+", "_", "-", "_").Replace(s)
	}
	n, ok := table[s]
	return n, ok
}
