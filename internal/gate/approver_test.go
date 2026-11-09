package gate_test

import (
	"testing"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/vocab"
)

func idp(id, sub, iss, sid string) authn.Principal {
	c := map[string]any{"sub": sub, "iss": iss}
	if sid != "" {
		c["sid"] = sid
	}
	return authn.Principal{ID: id, Kind: authn.KindPerson, Claims: c}
}

func ruleName(err error) string { r, _ := ruleOf(err); return r }

// GATE-APPROVER-001: automation cannot approve.
func TestAutomationCannotApprove(t *testing.T) {
	f := newGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": secret})).ID
	for name, c := range map[string]struct {
		p  authn.Principal
		on string
	}{
		"a TokenReview service account":    {principals["ci"], ""},
		"GitHub Actions":                   {authn.Principal{ID: "github:acme/app", Kind: authn.KindGitHubActions}, ""},
		"a bot account signed in":          {idp("user:cicd-pac[bot]", "cicd-pac[bot]", "https://idp.example", ""), ""},
		"the agents' App":                  {idp("user:acme-agents[bot]", "12345", "https://idp.example", ""), ""},
		"an ID-JAG agent identity":         {idp("user:triage", "agent:triage-7", "https://idjag.example/issuer", ""), ""},
		"an ID-JAG issuer, plain subject":  {idp("user:triage", "u-1", "https://id-jag.example", ""), ""},
		"a delegate naming a bot":          {principals["tower"], "user:cicd-pac[bot]"},
		"a delegate naming an agent":       {principals["tower"], "user:agent:triage-7"},
		"a delegate naming a service acct": {principals["tower"], "user:system:serviceaccount:ns:runner"},
	} {
		if _, err := f.svc.Clear(f.ctx, c.p, cid, c.on); ruleName(err) != "DG-APPROVER-AUTOMATION" {
			t.Fatal(name, err)
		}
	}
	// nothing was approved by the refused ones
	if out, err := f.svc.Clear(f.ctx, principals["tower"], cid, "user:erin"); err != nil || len(out.Approvals) != 1 {
		t.Fatal(out, err)
	}
}

func TestDelegateIsNotAutomationButThePersonItNamesIs(t *testing.T) {
	f := newGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": secret})).ID
	out, err := f.svc.Clear(f.ctx, principals["tower"], cid, "user:erin")
	if err != nil || out.Approvals[0].Kind != "person" || out.Approvals[0].Iss != "delegate:"+tower {
		t.Fatal(out, err)
	}
}

func TestAutomationPatternsAreConfiguration(t *testing.T) {
	v := vocab.Get()
	t.Cleanup(func() { vocab.Set(v) })
	n := v
	n.AutomationSubjects = []string{"fay"}
	vocab.Set(n)
	f := newGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": secret})).ID
	if _, err := f.svc.Clear(f.ctx, principals["fay"], cid, ""); ruleName(err) != "DG-APPROVER-AUTOMATION" {
		t.Fatal(err)
	}
}

func TestTwoApprovalsOfOneSubjectAreRefused(t *testing.T) {
	const iss = "https://idp.example"
	for name, c := range map[string]struct {
		first, second authn.Principal
		alias         [][]string
		on            string
	}{
		"one subject under two names":  {idp("user:erin", "sub-1", iss, ""), idp("user:fay", "sub-1", iss, ""), nil, ""},
		"one session":                  {idp("user:erin", "sub-1", iss, "s-9"), idp("user:fay", "sub-2", iss, "s-9"), nil, ""},
		"an alias, direct":             {idp("user:erin", "sub-1", iss, ""), idp("user:fay", "sub-2", iss, ""), [][]string{{"user:erin", "user:fay"}}, ""},
		"an alias, through a delegate": {idp("user:erin", "sub-1", iss, ""), principals["tower"], [][]string{{"sub-1", "user:fay"}}, "user:fay"},
	} {
		v := vocab.Get()
		n := v
		n.ApproverAliases = c.alias
		vocab.Set(n)
		f := newGate(t)
		cid := f.register(t, "ci", change(map[string]any{"objects": secret})).ID
		if _, err := f.svc.Clear(f.ctx, c.first, cid, ""); err != nil {
			vocab.Set(v)
			t.Fatal(name, err)
		}
		_, err := f.svc.Clear(f.ctx, c.second, cid, c.on)
		vocab.Set(v)
		if r, s := ruleOf(err); r != "DG-APPROVER-SAME" || s != 409 {
			t.Fatal(name, err)
		}
	}
}

func TestTwoPeopleClearTier3WithKindPerson(t *testing.T) {
	f := newGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": secret})).ID
	if _, err := f.svc.Clear(f.ctx, idp("user:erin", "sub-1", "https://idp.example", "s-1"), cid, ""); err != nil {
		t.Fatal(err)
	}
	out, err := f.svc.Clear(f.ctx, idp("user:root", "sub-2", "https://idp.example", "s-2"), cid, "")
	if err != nil || out.State != "cleared" || len(out.Approvals) != 2 || out.Approvals[0].Kind != "person" || out.Approvals[1].Kind != "person" {
		t.Fatal(out, err)
	}
}
