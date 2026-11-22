package gate_test

// A change whose proposer is unknown: the verifier's provenanceReason tells the two cases apart (docs/gate.md,
// Unvouched commits). unvouched-commits (commits no merged pull request contains) holds at tier 3 for two people;
// unrecorded-agent (agent impersonation) and no reason at all deny it (DG-PROVENANCE), fail closed.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/gate"
)

var (
	pushed1 = strings.Repeat("c", 40)
	pushed2 = strings.Repeat("d", 40)
)

func unvouched(over map[string]any, commits ...string) map[string]any {
	b := map[string]any{"proposerKind": "unknown", "provenanceReason": "unvouched-commits", "unvouchedCommits": strs(commits)}
	for k, v := range over {
		b[k] = v
	}
	return change(b)
}

func TestAnUnknownProposerIsHeldOnlyForUnvouchedCommits(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     map[string]any
		decision string
		tier     int
		rule     string // the reason rule it must carry
	}{
		{"unvouched commits, a tier-1 image bump", unvouched(map[string]any{"objects": imageBump}, pushed1), "hold", 3, "provenance:unvouched-commits"},
		{"unvouched commits, a tier-0 docs change", unvouched(map[string]any{"paths": strs([]string{"docs/x.md"})}, pushed1, pushed2), "hold", 3, "provenance:unvouched-commits"},
		{"unvouched commits, a tier-3 Secret", unvouched(map[string]any{"objects": secret}, pushed1), "hold", 3, "provenance:unvouched-commits"},
		{"unrecorded agent", change(map[string]any{"objects": imageBump, "proposerKind": "unknown", "provenanceReason": "unrecorded-agent"}), "deny", 2, "provenance:unknown"},
		{"no reason (a verifier that does not send it)", change(map[string]any{"objects": imageBump, "proposerKind": "unknown"}), "deny", 2, "provenance:unknown"},
		{"a null reason", change(map[string]any{"objects": imageBump, "proposerKind": "unknown", "provenanceReason": "", "unvouchedCommits": []any{}}), "deny", 2, "provenance:unknown"},
		{"unrecorded agent on a definition release", release(nil, map[string]any{"name": "gate-triage"}, map[string]any{"proposerKind": "unknown", "provenanceReason": "unrecorded-agent"}), "deny", 2, "provenance:unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := mustClassify(t, tc.body, baseline)
			if c.Decision != tc.decision || c.Tier < tc.tier || !has(ruleList(c), tc.rule) {
				t.Fatalf("%s tier %d %v", c.Decision, c.Tier, ruleList(c))
			}
			switch tc.decision {
			case "hold":
				q := c.Requirement
				if c.Tier != 3 || q == nil || q.Owner < 1 || q.Outside < 1 || q.OwnerGroup != owner || len(q.OutsideGroups) == 0 {
					t.Fatalf("tier %d requirement %+v", c.Tier, q)
				}
				if c.Rule != nil || !strings.Contains(c.Why, "no merged pull request contains") {
					t.Fatalf("rule %v why %q", c.Rule, c.Why)
				}
			case "deny":
				if c.Rule == nil || *c.Rule != "DG-PROVENANCE" || c.Requirement != nil || has(ruleList(c), "provenance:unvouched-commits") {
					t.Fatalf("%+v", c)
				}
			}
		})
	}
}

// The reason a reviewer reads in Tower names the case and the commits.
func TestTheUnvouchedReasonNamesTheCommits(t *testing.T) {
	c := mustClassify(t, unvouched(map[string]any{"objects": imageBump}, pushed1, pushed2), baseline)
	var subject string
	for _, r := range c.Reasons {
		if r.Rule == "provenance:unvouched-commits" {
			subject = r.Subject
		}
	}
	if subject != "2 commits in no merged pull request: ccccccc, ddddddd" {
		t.Fatal(subject)
	}
	var many []string
	for i := 0; i < 10; i++ {
		many = append(many, strings.Repeat(string("0123456789"[i]), 40))
	}
	c = mustClassify(t, unvouched(nil, many...), baseline)
	if r := c.Reasons[len(c.Reasons)-1]; !strings.HasSuffix(r.Subject, "7777777 and 2 more") || !strings.HasPrefix(r.Subject, "10 commits") {
		t.Fatal(r.Subject)
	}
}

// A repo's clearance.yaml may raise the tier-3 approvers; the hold asks for them.
func TestAnUnvouchedHoldTakesRaisedApprovers(t *testing.T) {
	c := mustClassify(t, unvouched(map[string]any{"objects": imageBump,
		"policy": map[string]any{"approvers": map[string]any{"3": map[string]any{"outside": 2}}}}, pushed1), baseline)
	if c.Decision != "hold" || c.Requirement.Owner != 1 || c.Requirement.Outside != 2 {
		t.Fatalf("%s %+v", c.Decision, c.Requirement)
	}
}

// A saved Terraform plan with unvouched commits holds the same way.
func TestAnUnvouchedPlanIsHeldAtTier3(t *testing.T) {
	body := tfChange(plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")),
		map[string]any{"proposerKind": "unknown", "provenanceReason": "unvouched-commits", "unvouchedCommits": strs([]string{pushed1})})
	c := mustClassify(t, body, baseline)
	if c.Decision != "hold" || c.Tier != 3 || !has(ruleList(c), "provenance:unvouched-commits") {
		t.Fatalf("%s %d %v", c.Decision, c.Tier, ruleList(c))
	}
	body = tfChange(plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), map[string]any{"proposerKind": "unknown"})
	if c := mustClassify(t, body, baseline); c.Decision != "deny" || *c.Rule != "DG-PROVENANCE" {
		t.Fatalf("%+v", c)
	}
}

func TestAMalformedProvenanceReasonIsRefused(t *testing.T) {
	var many []any
	for i := 0; i < gate.MaxUnvouchedCommits+1; i++ {
		many = append(many, fmt.Sprintf("%040x", i))
	}
	for _, tc := range []struct {
		name string
		over map[string]any
		want string
	}{
		{"an unknown reason", map[string]any{"provenanceReason": "trust-me"}, "provenanceReason is unvouched-commits or unrecorded-agent"},
		{"not a string", map[string]any{"provenanceReason": 1}, "provenanceReason is"},
		{"a reason for a person", map[string]any{"proposerKind": "person"}, "only with proposerKind unknown"},
		{"a reason for an agent", map[string]any{"proposerKind": "agent"}, "only with proposerKind unknown"},
		{"no commits", map[string]any{"unvouchedCommits": nil}, "names its commits"},
		{"an empty list", map[string]any{"unvouchedCommits": []any{}}, "names its commits"},
		{"commits for an unrecorded agent", map[string]any{"provenanceReason": "unrecorded-agent"}, "only with provenanceReason unvouched-commits"},
		{"commits with no reason", map[string]any{"provenanceReason": nil}, "only with provenanceReason unvouched-commits"},
		{"a short sha", map[string]any{"unvouchedCommits": strs([]string{"abc1234"})}, "40-hex commits"},
		{"an upper-case sha", map[string]any{"unvouchedCommits": strs([]string{strings.Repeat("C", 40)})}, "40-hex commits"},
		{"not a list", map[string]any{"unvouchedCommits": pushed1}, "40-hex commits"},
		{"a commit twice", map[string]any{"unvouchedCommits": strs([]string{pushed1, pushed1})}, "twice"},
		{"too many", map[string]any{"unvouchedCommits": many}, "at most 250"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := gate.ParseRequest(unvouched(tc.over, pushed1))
			var bc *gate.BadChange
			if err == nil || !errors.As(err, &bc) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v, want %q", err, tc.want)
			}
		})
	}
	if _, err := gate.ParseRequest(unvouched(map[string]any{"unvouchedCommits": many[:gate.MaxUnvouchedCommits]})); err != nil {
		t.Fatal(err)
	}
}

// The approval rule of an unvouched hold is every tier-3 hold's: one from the owner group and one from an outside
// group, never the proposer or a source author or merger, never one person in both seats.
func TestAnUnvouchedHoldNeedsTwoDistinctPeopleNotBehindIt(t *testing.T) {
	f := newGate(t)
	body := unvouched(map[string]any{"objects": imageBump, "source": map[string]any{"authors": strs([]string{"user:erin"})}}, pushed1)
	c := f.register(t, "ci", body)
	if c.State != "holding" || c.Tier != 3 || c.Requirement == nil || c.Requirement.Owner != 1 || c.Requirement.Outside != 1 {
		t.Fatalf("%s tier %d %+v", c.State, c.Tier, c.Requirement)
	}
	if !has(ruleOfReasons(c.Reasons), "provenance:unvouched-commits") {
		t.Fatal(c.Reasons)
	}
	recs := f.records(t, "deploy.request")
	if res, _ := recs[len(recs)-1]["result"].(string); !strings.Contains(res, "1 commit no merged pull request contains") {
		t.Fatal(res)
	}
	cid := c.ID
	// dana proposed it, erin authored a source PR: neither may clear it.
	for who, want := range map[string]string{"dana": "DG-PROPOSER", "erin": "DG-PROPOSER", "sam": "DG-FORBIDDEN", "ci": "DG-APPROVER-AUTOMATION"} {
		if _, err := f.svc.Clear(f.ctx, principals[who], cid, ""); func() string { r, _ := ruleOf(err); return r }() != want {
			t.Fatal(who, err)
		}
	}
	// fay is in the owner group and an outside group: she fills one seat, never both.
	out, err := f.svc.Clear(f.ctx, principals["fay"], cid, "")
	if err != nil || out.State != "holding" || len(out.Approvals) != 1 {
		t.Fatal(out, err)
	}
	if _, err := f.svc.Clear(f.ctx, principals["fay"], cid, ""); func() string { r, _ := ruleOf(err); return r }() != "DG-TWICE" {
		t.Fatal(err)
	}
	if got := f.get(t, cid); got.State != "holding" {
		t.Fatal(got.State)
	}
	out, err = f.svc.Clear(f.ctx, principals["root"], cid, "")
	if err != nil || out.State != "cleared" || len(out.Approvals) != 2 || out.Approvals[0].Person == out.Approvals[1].Person {
		t.Fatal(out, err)
	}
}

// A change denied for an unrecorded agent stays denied: no person can clear it.
func TestAnUnrecordedAgentCannotBeCleared(t *testing.T) {
	f := newGate(t)
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump, "proposerKind": "unknown", "provenanceReason": "unrecorded-agent"}))
	if c.State != "denied" || *c.DeniedBy != "policy" {
		t.Fatal(c.State)
	}
	if _, err := f.svc.Clear(f.ctx, principals["erin"], c.ID, ""); func() string { r, _ := ruleOf(err); return r }() != "DG-STATE" {
		t.Fatal(err)
	}
}

func ruleOfReasons(rs []gate.Reason) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Rule)
	}
	return out
}
