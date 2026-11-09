package vocab_test

import (
	"testing"

	"github.com/jfillman/clearance/internal/vocab"
)

func TestWildMatchIsLiteralExceptStar(t *testing.T) {
	for p, c := range map[string]map[string]bool{
		"*[bot]":   {"cicd-pac[bot]": true, "CICD-PAC[BOT]": true, "bot": false, "cicd-pac[bot]x": false},
		"agent:*":  {"agent:triage": true, "xagent:triage": false},
		"*id-jag*": {"https://id-jag.example/x": true, "https://dex.example": false},
		"a*b*c":    {"abc": true, "aXbYc": true, "ac": false},
		"exact":    {"exact": true, "exactly": false},
	} {
		for n, want := range c {
			if got := vocab.WildMatch(p, n); got != want {
				t.Errorf("WildMatch(%q, %q) = %v", p, n, got)
			}
		}
	}
}

func TestAutomationEnv(t *testing.T) {
	v, err := vocab.FromEnv(func(k string) string {
		return map[string]string{"CLEARANCE_AUTOMATION_SUBJECTS": "none", "CLEARANCE_AUTOMATION_ISSUERS": "https://agents.acme.dev*",
			"CLEARANCE_APPROVER_ALIASES": "user:a = a@acme.dev;x=y=z"}[k]
	})
	if err != nil || len(v.AutomationSubjects) != 0 || len(v.AutomationIssuers) != 1 || len(v.ApproverAliases) != 2 || v.ApproverAliases[0][1] != "a@acme.dev" {
		t.Fatal(v, err)
	}
	if _, err := vocab.FromEnv(func(k string) string { return map[string]string{"CLEARANCE_APPROVER_ALIASES": "lonely"}[k] }); err == nil {
		t.Fatal("one name is not an alias group")
	}
	d := vocab.Default()
	if len(d.AutomationSubjects) == 0 || len(d.AutomationIssuers) == 0 || len(d.ApproverAliases) != 0 {
		t.Fatal(d)
	}
}
