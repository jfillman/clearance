package gate

import (
	"fmt"
	"slices"
	"strings"

	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/review"
)

// Reason is one thing that sets the tier: an object, a path, or the change itself, and the rule that tiered it.
type Reason struct {
	Subject string `json:"subject"`
	Rule    string `json:"rule"`
	Tier    int    `json:"tier"`
}

// Requirement is who must clear a held change.
type Requirement struct {
	Owner         int      `json:"owner"`
	Outside       int      `json:"outside"`
	OwnerGroup    string   `json:"ownerGroup"`
	OutsideGroups []string `json:"outsideGroups"`
}

// Satisfied says whether the approvals so far meet the requirement.
func (q Requirement) Satisfied(approvals []Approval) bool {
	owner, outside := 0, 0
	for _, a := range approvals {
		if !a.Counts() {
			continue
		}
		switch a.Role {
		case "owner":
			owner++
		case "outside":
			outside++
		}
	}
	return owner >= q.Owner && outside >= q.Outside
}

// Words is "1 from group:x and 1 from outside (group:default/admins)", or "nobody".
func (q Requirement) Words() string {
	var parts []string
	if q.Owner != 0 {
		parts = append(parts, fmt.Sprintf("%d from %s", q.Owner, q.OwnerGroup))
	}
	if q.Outside != 0 {
		parts = append(parts, fmt.Sprintf("%d from outside (%s)", q.Outside, strings.Join(q.OutsideGroups, ", ")))
	}
	if len(parts) == 0 {
		return "nobody"
	}
	return strings.Join(parts, " and ")
}

// Classification is the tier, why, and what follows.
type Classification struct {
	Tier        int
	Reasons     []Reason
	Decision    string  // clear | hold | deny
	Rule        *string // the deny rule, when denied
	Why         string
	Requirement *Requirement
	Policy      Policy // the effective (tightened) policy
}

func objectTier(ch ObjectChange, pol Policy) Reason {
	// Only what the release stamps on the object's own metadata: first, because it is no change to the object, however
	// sensitive the kind. A stamp in a pod template restarts the pods, so it never counts as nothing on its own.
	rest := withoutStamps(ch.Fields, pol.ReleaseStamps)
	if ch.Op == "changed" && len(ch.Fields) > 0 && len(rest) == 0 && allMetadata(ch.Fields) {
		return Reason{ch.Subject(), "release-stamp", 0}
	}
	if pol.Tier3Kinds[ch.Kind] {
		return Reason{ch.Subject(), "kind:" + ch.Kind, 3}
	}
	for _, f := range ch.Fields {
		for _, token := range pol.Tier3Fields {
			if strings.Contains(f, token) {
				return Reason{ch.Subject(), "field:" + strings.Trim(token, "/"), 3}
			}
		}
	}
	if ch.Op == "changed" && len(ch.Fields) > 0 {
		if allMetadata(ch.Fields) {
			return Reason{ch.Subject(), "metadata-only", 0}
		}
		image := len(rest) > 0
		for _, f := range rest {
			if !imageField.MatchString(f) {
				image = false
			}
		}
		if image {
			if len(pol.TrustedRegistries) > 0 {
				for _, i := range ch.Images {
					from := false
					for _, r := range pol.TrustedRegistries {
						if strings.HasPrefix(i, r) {
							from = true
							break
						}
					}
					if !from {
						return Reason{ch.Subject(), "image:not-trusted-registry", 2}
					}
				}
			}
			return Reason{ch.Subject(), "image-bump", 1}
		}
	}
	return Reason{ch.Subject(), "kind:" + ch.Kind, 2}
}

func allMetadata(fields []string) bool {
	for _, f := range fields {
		if !strings.HasPrefix(f, metadataOnly[0]) && !strings.HasPrefix(f, metadataOnly[1]) {
			return false
		}
	}
	return true
}

func withoutStamps(fields, stamps []string) []string {
	rest := make([]string, 0, len(fields))
	for _, f := range fields {
		if !slices.Contains(stamps, f) {
			rest = append(rest, f)
		}
	}
	return rest
}

func maxTier(rs []Reason) int {
	m := 0
	for _, r := range rs {
		if r.Tier > m {
			m = r.Tier
		}
	}
	return m
}

func strp(s string) *string { return &s }

// Classify is gate.classify: cleared by policy, held for people, or denied. A clearance.yaml that loosens the
// baseline is an *Error (DG-POLICY). A terraform-plan subject is tiered by classifyPlan (terraform.go), its reasons
// naming the resource addresses that set the tier. An agent definition's release is tiered by review.Classify over the two
// documents; problems (review.Validate's, for the new document) deny it (DG-DEFINITION).
func Classify(req ChangeRequest, baseline Policy, tools review.Registry, problems []review.Problem) (Classification, error) {
	pol, err := baseline.Tightened(anyOrNil(req.Policy))
	if err != nil {
		return Classification{}, err
	}
	var reasons []Reason
	hold := func(tier int) Classification { return holdFor(req, pol, tier, reasons) }
	if req.Kind() != KindTerraformPlan && Unbound(req.TreeDigest) {
		// Flagged, not refused, for one release (CLEARANCE_GATE_UNBOUND_TREE=refuse refuses it): the change binds to
		// its commit only.
		reasons = append(reasons, Reason{"the tree", "tree:unbound", 0})
	}
	if req.Definition != nil {
		name, _ := req.Definition["name"].(string)
		if len(problems) > 0 {
			msgs := make([]string, len(problems))
			for i, p := range problems {
				reasons = append(reasons, Reason{"agent " + name, p.Rule + ":" + p.Path, 3})
				msgs[i] = p.Message
			}
			return Classification{3, reasons, "deny", strp("DG-DEFINITION"),
				"the new definition would not load or could not use what it lists: " + pycompat.Truncate(strings.Join(msgs, "; "), 400), nil, pol}, nil
		}
		old, _ := req.Definition["old"].(map[string]any)
		new, _ := req.Definition["new"].(map[string]any)
		tier, changes := review.Classify(old, new, tools)
		for _, ch := range changes {
			reasons = append(reasons, Reason{fmt.Sprintf("agent %s: %s", name, ch.Field), ch.Change, ch.Tier})
		}
		if req.ProposerKind == "unknown" {
			return unknownProposer(req, pol, tier, reasons, "the PR looks like an agent's but Clearance has no record of opening it"), nil
		}
		if req.ProposerKind == "agent" && tier == 0 {
			reasons = append(reasons, Reason{"the PR", "provenance:agent", 1})
			tier = 1
		}
		if tier <= 1 {
			why := "no change in authority"
			if tier != 0 {
				why = "narrows only"
			}
			return Classification{tier, reasons, "clear", nil, fmt.Sprintf("tier %d: cleared by policy (%s)", tier, why), nil, pol}, nil
		}
		return hold(tier), nil
	}
	for _, p := range req.Paths {
		switch {
		case globs(p, pol.Tier3Paths):
			reasons = append(reasons, Reason{p, "path:" + p[strings.LastIndex(p, "/")+1:], 3})
		case globs(p, pol.Tier2Paths):
			reasons = append(reasons, Reason{p, "path:tier2", 2})
		case globs(p, pol.NonruntimePaths):
			reasons = append(reasons, Reason{p, "non-runtime", 0})
		}
	}
	if req.Kind() == KindTerraformPlan {
		d, err := Describe(req)
		if err != nil {
			return Classification{}, err
		}
		return classifyPlan(req, d, pol, reasons), nil
	}
	// The objects the change touches are the description's items (describe.go). An object listed as unchanged (so a
	// grant covers the whole rendered tree) is not an item: it adds no risk to the diff.
	d, err := Describe(req)
	if err != nil {
		return Classification{}, err
	}
	for _, it := range d.Items {
		reasons = append(reasons, objectTier(itemObject(it), pol))
	}
	tier := maxTier(reasons)
	if tier == 1 && req.LinesChanged > int64(pol.MaxLinesTier1) {
		reasons = append(reasons, Reason{"the diff", fmt.Sprintf("lines>%d", pol.MaxLinesTier1), 2})
		tier = 2
	}
	if req.ProposerKind == "unknown" {
		return unknownProposer(req, pol, tier, reasons,
			"the PR looks like an agent's but Clearance has no record of opening it (the agent gates fail it too)"), nil
	}
	if req.ProposerKind == "agent" && tier == 0 {
		reasons = append(reasons, Reason{"the PR", "provenance:agent", 1})
		tier = 1
	}
	if tier == 1 {
		var missing []string
		for _, c := range checksOK {
			if v, ok := req.Checks[c.name]; !ok || !slices.Contains(c.ok, v) {
				missing = append(missing, c.name)
			}
		}
		if len(missing) > 0 {
			reasons = append(reasons, Reason{"the checks", "checks:" + strings.Join(missing, ","), 2})
			tier = 2
		}
	}
	if tier <= 1 {
		return Classification{tier, reasons, "clear", nil, fmt.Sprintf("tier %d: cleared by policy", tier), nil, pol}, nil
	}
	return hold(tier), nil
}

// unknownProposer is the decision for a change whose proposer is unknown (proposerKind unknown). Only a verifier's
// provenanceReason unvouched-commits holds it: at tier 3 whatever its other reasons say, for at least one person
// from the owner group and one from an outside group (never the people behind it, never one person twice; the
// approval rules of every hold). Any other reason (unrecorded-agent: agent impersonation) and no reason at all deny
// it (DG-PROVENANCE), as before provenanceReason existed: a verifier that does not say why fails closed.
func unknownProposer(req ChangeRequest, pol Policy, tier int, reasons []Reason, denyWhy string) Classification {
	if req.ProvenanceReason != ProvenanceUnvouchedCommits || len(req.UnvouchedCommits) == 0 {
		reasons = append(reasons, Reason{"the PR", "provenance:unknown", 3})
		return Classification{max(tier, 2), reasons, "deny", strp("DG-PROVENANCE"), denyWhy, nil, pol}
	}
	n := len(req.UnvouchedCommits)
	reasons = append(reasons, Reason{unvouchedSubject(req.UnvouchedCommits), "provenance:" + ProvenanceUnvouchedCommits, 3})
	cl := holdFor(req, pol, 3, reasons)
	// Two people, whatever the tier-3 approver table says (the baseline is 1 and 1; clearance.yaml may only raise it).
	cl.Requirement.Owner, cl.Requirement.Outside = max(cl.Requirement.Owner, 1), max(cl.Requirement.Outside, 1)
	cl.Why = fmt.Sprintf("tier 3: holding for %s: %s no merged pull request contains (a direct push or a merge made outside a "+
		"pull request), so no review vouches for %s", cl.Requirement.Words(), plural(n, "commit"), map[bool]string{true: "it", false: "them"}[n == 1])
	return cl
}

// unvouchedSubject names the unvouched commits for the reason a reviewer reads: the count and the first few, short.
func unvouchedSubject(commits []string) string {
	const shown = 8
	short := make([]string, 0, shown)
	for i, c := range commits {
		if i == shown {
			break
		}
		short = append(short, pycompat.Truncate(c, 7))
	}
	s := plural(len(commits), "commit") + " in no merged pull request: " + strings.Join(short, ", ")
	if len(commits) > shown {
		s += fmt.Sprintf(" and %d more", len(commits)-shown)
	}
	return s
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// holdFor is a change held for people at tier: the approvers the policy asks for, from the owner and outside groups.
func holdFor(req ChangeRequest, pol Policy, tier int, reasons []Reason) Classification {
	a, ok := pol.Approvers[tier]
	if !ok {
		a = Approvers{1, 1}
	}
	q := &Requirement{a.Owner, a.Outside, req.Owner, nonNil(pol.OutsideGroups)}
	return Classification{tier, reasons, "hold", nil, fmt.Sprintf("tier %d: holding for %s", tier, q.Words()), q, pol}
}

func anyOrNil(m map[string]any) any {
	if m == nil {
		return nil
	}
	return m
}
