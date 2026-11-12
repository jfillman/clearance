package docscope

import (
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/pycompat"
)

// rules is the shape of a Glidepath contract's scope.rules at contract version 2: a new Flight environment's cluster is
// propose (only when added), an existing one's is human, the rest of an environment entry is open.
const rules = `[
 {"pattern":"/secrets","agentScope":"human"},
 {"pattern":"/deploy/environments/*/cluster","agentScope":"propose","proposeOn":["added"]},
 {"pattern":"/deploy/environments/*/production","agentScope":"propose","proposeOn":["added"],"why":"w"},
 {"pattern":"/deploy/environments/*/chart","agentScope":"human"},
 {"pattern":"/deploy/environments","agentScope":"open"},
 {"pattern":"/build","agentScope":"open"}
]`

func config(t *testing.T, ruleJSON string, propose Finding) *Config {
	t.Helper()
	pr, err := ParseRules([]byte(ruleJSON))
	if err != nil {
		t.Fatal(err)
	}
	c := &Config{File: "cicd.yaml", Rules: pr,
		WholeFile: Finding{"GP-SCOPE-001", "send yaml"}, Human: Finding{"GP-SCOPE-001", "ask a human"},
		Loosened: Finding{"GP-SCOPE-002", "tighter"}, Propose: propose}
	if err := c.Prepare(); err != nil {
		t.Fatal(err)
	}
	return c
}

func file(before, content string) []any {
	m := pycompat.NewMap(3)
	m.Set("path", "cicd.yaml")
	m.Set("before", before)
	m.Set("content", content)
	return []any{m}
}

var proposeFinding = Finding{"GP-SCOPE-004", "use glidepath.cicd.propose, which marks the PR for a person to merge"}

const base = "deploy:\n  environments:\n    - {name: dev, tier: ground}\n    - {name: prod, tier: flight, cluster: hangar-prod, production: true}\n"

func rulesOf(t *testing.T, c *Config, before, content string) []string {
	t.Helper()
	ps, err := c.Problems(file(before, content))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range ps {
		out = append(out, p.Rule+" "+p.Pointer)
	}
	return out
}

func TestAProposeFieldOnANewEnvironmentIsRefusedHereWithItsOwnRule(t *testing.T) {
	c := config(t, rules, proposeFinding)
	head := base + "    - {name: staging, tier: flight, cluster: hangar-prod}\n"
	got := rulesOf(t, c, base, head)
	if strings.Join(got, ";") != "GP-SCOPE-004 /deploy/environments/staging/cluster" {
		t.Fatalf("%v", got)
	}
	ps, _ := c.Problems(file(base, head))
	if !strings.Contains(ps[0].Message, "a propose field, which needs a person to merge") || ps[0].Hint != proposeFinding.Hint {
		t.Fatalf("%+v", ps[0])
	}
}

func TestProposeOnAddedLeavesAChangedOrRemovedFieldHuman(t *testing.T) {
	c := config(t, rules, proposeFinding)
	changed := strings.Replace(base, "cluster: hangar-prod", "cluster: other", 1)
	if got := rulesOf(t, c, base, changed); strings.Join(got, ";") != "GP-SCOPE-001 /deploy/environments/prod/cluster" {
		t.Fatalf("changed cluster: %v", got)
	}
	removed := strings.Replace(base, ", production: true", "", 1)
	if got := rulesOf(t, c, base, removed); strings.Join(got, ";") != "GP-SCOPE-001 /deploy/environments/prod/production" {
		t.Fatalf("removed production: %v", got)
	}
}

func TestAProposeRuleWithoutProposeOnCoversEveryKind(t *testing.T) {
	c := config(t, `[{"pattern":"/x","agentScope":"propose"},{"pattern":"/y","agentScope":"open"}]`, proposeFinding)
	for _, tc := range []struct{ before, after string }{{"y: 1\n", "y: 1\nx: 1\n"}, {"x: 1\n", "x: 2\n"}, {"x: 1\n", "y: 1\n"}} {
		got := rulesOf(t, c, tc.before, tc.after)
		if len(got) < 1 || !strings.HasPrefix(got[0], "GP-SCOPE-004 /x") {
			t.Fatalf("%q -> %q: %v", tc.before, tc.after, got)
		}
	}
}

func TestOpenAndHumanFieldsAreUnchangedByTheNewClass(t *testing.T) {
	c := config(t, rules, proposeFinding)
	if got := rulesOf(t, c, base, strings.Replace(base, "{name: dev, tier: ground}", "{name: dev, tier: ground}\n    - {name: qa, tier: ground}", 1)); len(got) != 0 {
		t.Fatalf("a Ground environment is open: %v", got)
	}
	if got := rulesOf(t, c, "build: {a: 1}\n", "build: {a: 1}\nsecrets: [{name: x}]\n"); len(got) != 1 || !strings.HasPrefix(got[0], "GP-SCOPE-001 /secrets") {
		t.Fatalf("%v", got)
	}
}

func TestAProposeRuleNeedsTheDocumentsProposeFinding(t *testing.T) {
	pr, err := ParseRules([]byte(rules))
	if err != nil {
		t.Fatal(err)
	}
	c := &Config{File: "cicd.yaml", Rules: pr, WholeFile: Finding{"A", "h"}, Human: Finding{"A", "h"}, Loosened: Finding{"B", "h"}}
	if err := c.Prepare(); err == nil || !strings.Contains(err.Error(), "propose finding") {
		t.Fatalf("%v", err)
	}
}

func TestParseRulesRefusesWhatItDoesNotKnow(t *testing.T) {
	for _, bad := range []string{
		`[{"pattern":"/x","agentScope":"propse"}]`,
		`[{"pattern":"/x","agentScope":"propose","proposeOn":["created"]}]`,
		`[{"pattern":"/x","agentScope":"open","proposeOn":["added"]}]`,
	} {
		if _, err := ParseRules([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
