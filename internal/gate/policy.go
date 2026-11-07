// Package gate is the deployment gate (Clearances), phase 1, ported from gate.py and the gate half of dispatch.py:
// may this change land in a protected environment? docs/gate.md is the design.
//
// A change is a commit to a gitops repo that Argo CD would sync to a protected environment, described by the CI
// check that registers it. It gets a tier, 0 to 3, the maximum over everything it touches, from a baseline (Policy)
// that a repo's clearance.yaml may only tighten. Tiers 0 and 1 are cleared by policy at once; tier 2 waits for one
// person from the app's owner group, tier 3 for one from the owner group and one from an outside group, neither the
// proposer, never the same person twice. A change not cleared within its TTL expires; a new head on the same PR
// supersedes it. Each step is an evidence record in the deployment boundary: deploy.request, deploy.clear,
// deploy.deny, deploy.expire (and deploy.answer for a GitHub deployment).
package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/jfillman/clearance/internal/vocab"
	"regexp"
	"sort"
	"strings"

	"github.com/jfillman/clearance/internal/pycompat"
)

// Limits and patterns (gate.py constants).
const (
	DefaultTTLDays = 7
	MaxTTLDays     = 30
	MaxObjects     = 2000
	MaxPaths       = 4000
	MaxFields      = 400
	MaxReason      = 500
	MaxLinesTier1  = 400
)

var (
	shaRx       = regexp.MustCompile(`^[0-9a-f]{40}\z`)
	repoRx      = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z`)
	nameRx      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z`)
	groupRx     = regexp.MustCompile(`^group:[a-z0-9-]+/[a-z0-9._-]+\z`)
	principalRx = regexp.MustCompile(`^[A-Za-z0-9:/_.@\[\]-]{1,200}\z`)
	treeRx      = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}\z`)
	taskRx      = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}\z`)
	imageField  = regexp.MustCompile(`^/spec/(template/spec/|jobTemplate/spec/template/spec/)?(init)?[cC]ontainers/\d+/image\z`)
)

// States, proposer kinds and object ops.
var (
	States        = []string{StateHolding, StateCleared, StateDenied, StateExpired, StateSuperseded, StateDegraded, StateException}
	ProposerKinds = []string{"person", "agent", "unknown"}
	ops           = []string{"added", "changed", "removed", "unchanged"} // unchanged: in the rendered tree, not in the diff
	metadataOnly  = []string{"/metadata/labels", "/metadata/annotations"}
	// checksOK is what each check must say for policy to clear a tier-1 change, in gate.py's order. provenance
	// "unattested" (agent work outside Clearance, provenance.Unattested) clears as not-agent does: the verdict is a
	// warning and changes no tier (user decision 2026-11-04, docs/provenance-app.md).
	checksOK = []struct {
		name string
		ok   []string
	}{{"ci", []string{"pass"}}, {"provenance", []string{"confirmed", "not-agent", "unattested"}}, {"render", []string{"ok"}}}
)

// Error is gate.GateError: a refusal with a DG-* rule, a message, a hint and the HTTP status.
type Error struct {
	Rule, Message, Hint string
	Status              int
}

func (e *Error) Error() string { return e.Message }

func gerr(rule, msg, hint string, status int) *Error { return &Error{rule, msg, hint, status} }

// BadChange is gate.BadChange: the verifier's description of a change is malformed (400).
type BadChange struct{ Message string }

func (e *BadChange) Error() string { return e.Message }

func bad(format string, a ...any) *BadChange { return &BadChange{fmt.Sprintf(format, a...)} }

// Approvers is how many people each role must supply.
type Approvers struct {
	Owner   int `json:"owner"`
	Outside int `json:"outside"`
}

// Policy is gate.GatePolicy: the platform's tier table and approval rule.
type Policy struct {
	Version           string
	Tier3Kinds        map[string]bool
	Tier3Fields       []string
	Tier3Paths        []string
	NonruntimePaths   []string
	TrustedRegistries []string // image prefixes a tier-1 bump may come from; empty = any registry
	MaxLinesTier1     int
	OutsideGroups     []string
	TTLDays           int
	Approvers         map[int]Approvers
	RepoPolicyDigest  *string // set by Tightened: the clearance.yaml that shaped this policy
	Tier2Paths        []string
	// Outage is what a provider does with each tier while the core is unreachable (OutageFor; "" is the baseline,
	// DefaultOutage).
	Outage [4]string
	// The Terraform baseline (G-TF-1): tier-3 resource types by category (clearance.yaml's workspaces.tiers.3.types
	// are added as category "clearance.yaml"), the attributes of a tag-only update, the types clearance.yaml keeps
	// out of tier 1, and the workspaces it protects (globs on the state key or the workspace name).
	TFTier3Types        []TypeRule
	TFTagFields         []string
	TFTier2Types        []string
	ProtectedWorkspaces []string
	// PlanTTLDays is the hold TTL of a terraform-plan change: the shorter of it and TTLDays (a clearance.yaml
	// ttlDays still shortens it).
	PlanTTLDays int
}

// DefaultPolicy is GatePolicy(): the baseline of 2026-10-31.
func DefaultPolicy() Policy {
	kinds := map[string]bool{}
	for _, k := range []string{"Secret", "ExternalSecret", "SecretStore", "ClusterSecretStore", "ClusterExternalSecret", "PushSecret",
		"ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "AppProject",
		"Job", "CronJob", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "ValidatingPolicy",
		"ClusterPolicy", "Policy", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"} {
		kinds[k] = true
	}
	return Policy{
		Version:    "baseline-2026-10-31",
		Tier3Kinds: kinds,
		Tier3Fields: []string{"secretKeyRef", "secretRef", "envFrom", "imagePullSecrets", "serviceAccountName",
			"serviceAccount", "securityContext", "hostNetwork", "hostPID", "hostIPC",
			"privileged", "capabilities", "/secret/", "automountServiceAccountToken"},
		Tier3Paths:      []string{"clearance.yaml", "**/clearance.yaml", "**/appproject*.yaml", "**/AppProject*.yaml"},
		NonruntimePaths: []string{"docs/**", "**/*.md", "*.md", "LICENSE", ".gitignore", "tests/**", "**/tests/**", ".github/**", "CODEOWNERS"},
		MaxLinesTier1:   MaxLinesTier1,
		OutsideGroups:   append([]string{}, vocab.Get().OutsideGroups...),
		TTLDays:         DefaultTTLDays,
		Approvers:       map[int]Approvers{2: {1, 0}, 3: {1, 1}},
		Outage:          DefaultOutage,
		TFTier3Types:    DefaultTerraformTier3(),
		TFTagFields:     append([]string(nil), DefaultTagFields...),
		PlanTTLDays:     DefaultPlanTTLDays,
	}
}

// PolicyView is GatePolicy.view(), the shape GET /v1/clearance-policy serves.
type PolicyView struct {
	Version           string               `json:"version"`
	Tiers             PolicyTiers          `json:"tiers"`
	TrustedRegistries []string             `json:"trustedRegistries"`
	MaxLinesTier1     int                  `json:"maxLinesTier1"`
	OutsideGroups     []string             `json:"outsideGroups"`
	TTLDays           int                  `json:"ttlDays"`
	Approvers         map[string]Approvers `json:"approvers"`
	RepoPolicy        *string              `json:"repoPolicy"`
	// Outage is the outage policy by tier: allow-and-record or hold (C-6).
	Outage    map[string]string `json:"outage"`
	Terraform PolicyTerraform   `json:"terraform"`
}

// PolicyTerraform is the view's Terraform baseline: tier-3 types by category, the tag-only attributes, and what a
// clearance.yaml added (tier-2 types, protected workspaces).
type PolicyTerraform struct {
	Tier3Types          map[string][]string `json:"tier3Types"`
	TagOnlyFields       []string            `json:"tagOnlyFields"`
	Tier2Types          []string            `json:"tier2Types"`
	ProtectedWorkspaces []string            `json:"protectedWorkspaces"`
	// TTLHours is how long a plan holds before it expires (deploy.expire): 24 hours unless clearance.yaml's ttlDays
	// is shorter still.
	TTLHours int `json:"ttlHours"`
}

// PolicyTiers is the view's tier table: "3" then "0", as gate.py writes it.
type PolicyTiers struct {
	T3 struct {
		Kinds  []string `json:"kinds"`
		Fields []string `json:"fields"`
		Paths  []string `json:"paths"`
	} `json:"3"`
	T0 struct {
		Paths []string `json:"paths"`
	} `json:"0"`
}

// View is GatePolicy.view().
func (p Policy) View() PolicyView {
	kinds := make([]string, 0, len(p.Tier3Kinds))
	for k := range p.Tier3Kinds {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	appr := map[string]Approvers{}
	for t, a := range p.Approvers {
		appr[fmt.Sprint(t)] = a
	}
	var tiers PolicyTiers
	tiers.T3.Kinds, tiers.T3.Fields, tiers.T3.Paths = kinds, nonNil(p.Tier3Fields), nonNil(p.Tier3Paths)
	tiers.T0.Paths = nonNil(p.NonruntimePaths)
	tf := PolicyTerraform{Tier3Types: map[string][]string{}, TagOnlyFields: nonNil(p.TFTagFields),
		Tier2Types: nonNil(p.TFTier2Types), ProtectedWorkspaces: nonNil(p.ProtectedWorkspaces), TTLHours: 24 * p.planTTLDays()}
	for _, r := range p.TFTier3Types {
		tf.Tier3Types[r.Category] = append(tf.Tier3Types[r.Category], r.Types...)
	}
	return PolicyView{
		Version: p.Version, Tiers: tiers,
		TrustedRegistries: nonNil(p.TrustedRegistries), MaxLinesTier1: p.MaxLinesTier1,
		OutsideGroups: nonNil(p.OutsideGroups), TTLDays: p.TTLDays, Approvers: appr, RepoPolicy: p.RepoPolicyDigest,
		Outage:    p.OutageView(),
		Terraform: tf,
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return append([]string(nil), s...)
}

// Tightened applies a repo's clearance.yaml. Allowed: tiers.3.{kinds,paths,fields} (add), tiers.2.{kinds,paths}
// (add), approvers.{2,3}.{owner,outside} (raise), ttlDays (shorten), outage.{0..3} (allow-and-record to hold), and
// for Terraform workspaces.protected (add protected workspaces) and workspaces.tiers.{2,3}.types (add resource
// types). Anything that loosens, or an unknown key, is refused (DG-POLICY).
func (p Policy) Tightened(repoPolicy any) (Policy, error) {
	if repoPolicy == nil {
		return p, nil
	}
	rp, ok := repoPolicy.(map[string]any)
	if !ok {
		return p, gerr("DG-POLICY", "clearance.yaml is a mapping", "", 400)
	}
	digest, err := repoPolicyDigest(rp)
	if err != nil {
		return p, gerr("DG-POLICY", "clearance.yaml is a mapping", "", 400)
	}
	var unknown []string
	for k := range rp {
		if k != "tiers" && k != "approvers" && k != "ttlDays" && k != "outage" && k != "workspaces" {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return p, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: unknown key %s", pycompat.Repr(unknown[0])),
			"Allowed: tiers.{2,3}.{kinds,paths,fields}, approvers.{2,3}.{owner,outside}, ttlDays, outage.{0,1,2,3}, workspaces.{protected,tiers}.", 400)
	}
	t3k := map[string]bool{}
	for k := range p.Tier3Kinds {
		t3k[k] = true
	}
	t3f, t3p := append([]string(nil), p.Tier3Fields...), append([]string(nil), p.Tier3Paths...)
	var tiers map[string]any
	if v := rp["tiers"]; pycompat.Truthy(v) {
		m, ok := v.(map[string]any)
		if !ok {
			return p, gerr("DG-POLICY", "clearance.yaml: tiers names 2 and 3 only (tiers 0 and 1 cannot be widened)", "", 400)
		}
		tiers = m
	}
	for k := range tiers {
		if k != "2" && k != "3" {
			return p, gerr("DG-POLICY", "clearance.yaml: tiers names 2 and 3 only (tiers 0 and 1 cannot be widened)", "", 400)
		}
	}
	// gate.py walks tiers in the mapping's order; the first refusal found is reported. Go maps keep no order, so
	// "2" is checked before "3" (sorted); the refusal's rule is the same either way, only which message comes first.
	tkeys := sortedKeys(tiers)
	var t2p []string
	for _, t := range tkeys {
		spec, ok := tiers[t].(map[string]any)
		if !ok {
			return p, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: tiers.%s takes kinds, paths, fields", t), "", 400)
		}
		for k := range spec {
			if k != "kinds" && k != "paths" && k != "fields" {
				return p, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: tiers.%s takes kinds, paths, fields", t), "", 400)
			}
		}
		lists := map[string][]string{}
		for _, k := range []string{"kinds", "paths", "fields"} {
			v, present := spec[k]
			if !present {
				continue
			}
			l, ok := v.([]any)
			if !ok {
				return p, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: tiers.%s.%s is a list of strings", t, k), "", 400)
			}
			for _, x := range l {
				s, ok := x.(string)
				if !ok || s == "" {
					return p, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: tiers.%s.%s is a list of strings", t, k), "", 400)
				}
				lists[k] = append(lists[k], s)
			}
		}
		if t == "3" {
			for _, k := range lists["kinds"] {
				t3k[k] = true
			}
			t3f = append(t3f, lists["fields"]...)
			t3p = append(t3p, lists["paths"]...)
		} else {
			t2p = lists["paths"]
		}
	}
	appr := map[int]Approvers{}
	for t, a := range p.Approvers {
		appr[t] = a
	}
	if v := rp["approvers"]; pycompat.Truthy(v) {
		m, ok := v.(map[string]any)
		if !ok {
			return p, gerr("DG-POLICY", "clearance.yaml: approvers.{2,3}.{owner,outside} only", "", 400)
		}
		for _, t := range sortedKeys(m) {
			spec, ok := m[t].(map[string]any)
			if (t != "2" && t != "3") || !ok {
				return p, gerr("DG-POLICY", "clearance.yaml: approvers.{2,3}.{owner,outside} only", "", 400)
			}
			for role := range spec {
				if role != "owner" && role != "outside" {
					return p, gerr("DG-POLICY", "clearance.yaml: approvers.{2,3}.{owner,outside} only", "", 400)
				}
			}
			ti := int(t[0] - '0')
			a := appr[ti]
			for _, role := range sortedKeys(spec) {
				cur := a.Owner
				if role == "outside" {
					cur = a.Outside
				}
				n, isInt := pycompat.AsInt(spec[role])
				if !isInt || n < int64(cur) {
					return p, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: approvers.%s.%s may only be raised above %d", t, role, cur), "", 400)
				}
				if role == "owner" {
					a.Owner = int(n)
				} else {
					a.Outside = int(n)
				}
			}
			appr[ti] = a
		}
	}
	ttl := int64(p.TTLDays)
	if v, present := rp["ttlDays"]; present {
		n, isInt := pycompat.AsInt(v)
		if !isInt || n < 1 || n > int64(p.TTLDays) {
			return p, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: ttlDays is 1 to %d (the baseline; it may only be shortened)", p.TTLDays), "", 400)
		}
		ttl = n
	}
	outage := p.Outage
	if v, present := rp["outage"]; present {
		o, err := p.tightenOutage(v)
		if err != nil {
			return p, err
		}
		outage = o
	}
	ws, err := p.tightenWorkspaces(rp["workspaces"])
	if err != nil {
		return p, err
	}
	out := ws
	out.Outage = outage
	out.Tier3Kinds, out.Tier3Fields, out.Tier3Paths = t3k, t3f, t3p
	out.TTLDays, out.Approvers, out.RepoPolicyDigest, out.Tier2Paths = int(ttl), appr, &digest, t2p
	return out, nil
}

// tightenWorkspaces applies clearance.yaml's workspaces block, tighten-only like the gitops tiers: protected names
// more workspaces protected (globs on the state key or the workspace name; there is no way to unprotect one),
// tiers.3.types adds tier-3 resource types, tiers.2.types keeps types out of tier 1. Tiers 0 and 1 cannot be named.
func (p Policy) tightenWorkspaces(v any) (Policy, error) {
	out := p
	out.TFTier3Types = append([]TypeRule(nil), p.TFTier3Types...)
	out.TFTier2Types = append([]string(nil), p.TFTier2Types...)
	out.ProtectedWorkspaces = append([]string(nil), p.ProtectedWorkspaces...)
	if !pycompat.Truthy(v) {
		return out, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return p, gerr("DG-POLICY", "clearance.yaml: workspaces takes protected and tiers", "", 400)
	}
	for _, k := range sortedKeys(m) {
		if k != "protected" && k != "tiers" {
			return p, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: workspaces takes protected and tiers, not %s", pycompat.Repr(k)),
				"A workspace can be protected, never unprotected; resource types can be raised, never lowered.", 400)
		}
	}
	strList := func(v any, what string) ([]string, error) {
		l, ok := v.([]any)
		if !ok {
			return nil, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: %s is a list of strings", what), "", 400)
		}
		var out []string
		for _, x := range l {
			s, ok := x.(string)
			if !ok || s == "" {
				return nil, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: %s is a list of strings", what), "", 400)
			}
			out = append(out, s)
		}
		return out, nil
	}
	if v, present := m["protected"]; present {
		l, err := strList(v, "workspaces.protected")
		if err != nil {
			return p, err
		}
		out.ProtectedWorkspaces = append(out.ProtectedWorkspaces, l...)
	}
	if v := m["tiers"]; pycompat.Truthy(v) {
		tiers, ok := v.(map[string]any)
		if !ok {
			return p, gerr("DG-POLICY", "clearance.yaml: workspaces.tiers names 2 and 3 only (tiers 0 and 1 cannot be widened)", "", 400)
		}
		for _, t := range sortedKeys(tiers) {
			if t != "2" && t != "3" {
				return p, gerr("DG-POLICY", "clearance.yaml: workspaces.tiers names 2 and 3 only (tiers 0 and 1 cannot be widened)", "", 400)
			}
			spec, ok := tiers[t].(map[string]any)
			if !ok || unknownKey(spec, setOf("types")) != "" {
				return p, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: workspaces.tiers.%s takes types", t), "", 400)
			}
			if _, present := spec["types"]; !present {
				continue
			}
			l, err := strList(spec["types"], "workspaces.tiers."+t+".types")
			if err != nil {
				return p, err
			}
			if t == "3" {
				out.TFTier3Types = append(out.TFTier3Types, TypeRule{"clearance.yaml", l})
			} else {
				out.TFTier2Types = append(out.TFTier2Types, l...)
			}
		}
	}
	return out, nil
}

// repoPolicyDigest is the sha256 of a clearance.yaml as gate.py hashed it: json.dumps(repo_policy, sort_keys=True,
// default=str), ASCII escapes, default separators.
func repoPolicyDigest(rp map[string]any) (string, error) {
	raw, err := pycompat.Dumps(rp, pycompat.Options{ASCII: true, Spaced: true})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// globs is gate._globs: fnmatchcase, and a "**/" glob also matches at the top level.
func globs(path string, gs []string) bool {
	for _, g := range gs {
		if pycompat.Match(path, g) || (strings.HasPrefix(g, "**/") && pycompat.Match(path, g[3:])) {
			return true
		}
	}
	return false
}

// planTTLDays is a terraform-plan change's hold TTL in days: PlanTTLDays, never longer than TTLDays.
func (p Policy) planTTLDays() int {
	d := p.TTLDays
	if p.PlanTTLDays > 0 && p.PlanTTLDays < d {
		d = p.PlanTTLDays
	}
	return d
}
