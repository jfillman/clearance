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
		meta, image := true, true
		for _, f := range ch.Fields {
			if !strings.HasPrefix(f, metadataOnly[0]) && !strings.HasPrefix(f, metadataOnly[1]) {
				meta = false
			}
			if !imageField.MatchString(f) {
				image = false
			}
		}
		if meta {
			return Reason{ch.Subject(), "metadata-only", 0}
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
// baseline is an *Error (DG-POLICY). An agent definition's release is tiered by review.Classify over the two
// documents; problems (review.Validate's, for the new document) deny it (DG-DEFINITION).
func Classify(req ChangeRequest, baseline Policy, tools review.Registry, problems []review.Problem) (Classification, error) {
	pol, err := baseline.Tightened(anyOrNil(req.Policy))
	if err != nil {
		return Classification{}, err
	}
	var reasons []Reason
	hold := func(tier int) Classification {
		a, ok := pol.Approvers[tier]
		if !ok {
			a = Approvers{1, 1}
		}
		q := &Requirement{a.Owner, a.Outside, req.Owner, nonNil(pol.OutsideGroups)}
		return Classification{tier, reasons, "hold", nil, fmt.Sprintf("tier %d: holding for %s", tier, q.Words()), q, pol}
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
			reasons = append(reasons, Reason{"the PR", "provenance:unknown", 3})
			return Classification{max(tier, 2), reasons, "deny", strp("DG-PROVENANCE"),
				"the PR looks like an agent's but Clearance has no record of opening it", nil, pol}, nil
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
	for _, ch := range req.Objects {
		reasons = append(reasons, objectTier(ch, pol))
	}
	tier := maxTier(reasons)
	if tier == 1 && req.LinesChanged > int64(pol.MaxLinesTier1) {
		reasons = append(reasons, Reason{"the diff", fmt.Sprintf("lines>%d", pol.MaxLinesTier1), 2})
		tier = 2
	}
	if req.ProposerKind == "unknown" {
		reasons = append(reasons, Reason{"the PR", "provenance:unknown", 3})
		return Classification{max(tier, 2), reasons, "deny", strp("DG-PROVENANCE"),
			"the PR looks like an agent's but Clearance has no record of opening it (the agent gates fail it too)", nil, pol}, nil
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

func anyOrNil(m map[string]any) any {
	if m == nil {
		return nil
	}
	return m
}
