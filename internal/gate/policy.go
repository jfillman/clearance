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
	States        = []string{"holding", "cleared", "denied", "expired", "superseded"}
	ProposerKinds = []string{"person", "agent", "unknown"}
	ops           = []string{"added", "changed", "removed"}
	metadataOnly  = []string{"/metadata/labels", "/metadata/annotations"}
	// checksOK is what each check must say for policy to clear a tier-1 change, in gate.py's order.
	checksOK = []struct {
		name string
		ok   []string
	}{{"ci", []string{"pass"}}, {"provenance", []string{"confirmed", "not-agent"}}, {"render", []string{"ok"}}}
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
	return PolicyView{
		Version: p.Version, Tiers: tiers,
		TrustedRegistries: nonNil(p.TrustedRegistries), MaxLinesTier1: p.MaxLinesTier1,
		OutsideGroups: nonNil(p.OutsideGroups), TTLDays: p.TTLDays, Approvers: appr, RepoPolicy: p.RepoPolicyDigest,
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return append([]string(nil), s...)
}

// Tightened applies a repo's clearance.yaml. Allowed: tiers.3.{kinds,paths,fields} (add), tiers.2.{kinds,paths}
// (add), approvers.{2,3}.{owner,outside} (raise), ttlDays (shorten). Anything that loosens, or an unknown key, is
// refused (DG-POLICY).
func (p Policy) Tightened(repoPolicy any) (Policy, error) {
	if repoPolicy == nil {
		return p, nil
	}
	rp, ok := repoPolicy.(map[string]any)
	if !ok {
		return p, gerr("DG-POLICY", "clearance.yaml is a mapping", "", 400)
	}
	// json.dumps(repo_policy, sort_keys=True, default=str): ASCII escapes, default separators.
	raw, err := pycompat.Dumps(rp, pycompat.Options{ASCII: true, Spaced: true})
	if err != nil {
		return p, gerr("DG-POLICY", "clearance.yaml is a mapping", "", 400)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	var unknown []string
	for k := range rp {
		if k != "tiers" && k != "approvers" && k != "ttlDays" {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return p, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: unknown key %s", pycompat.Repr(unknown[0])),
			"Allowed: tiers.{2,3}.{kinds,paths,fields}, approvers.{2,3}.{owner,outside}, ttlDays.", 400)
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
	out := p
	out.Tier3Kinds, out.Tier3Fields, out.Tier3Paths = t3k, t3f, t3p
	out.TTLDays, out.Approvers, out.RepoPolicyDigest, out.Tier2Paths = int(ttl), appr, &digest, t2p
	return out, nil
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
