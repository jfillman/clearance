package token_test

import (
	"testing"

	"github.com/jfillman/clearance/internal/token"
)

func TestApproversStatementNeedsVerifiedDistinctPeople(t *testing.T) {
	a := token.Approval{Sub: "s1", Iss: "i", Kind: "person"}
	b := token.Approval{Sub: "s2", Iss: "i", Kind: "person"}
	for name, c := range map[string]struct {
		in   []token.Approval
		want string
	}{
		"two people":      {[]token.Approval{a, b}, "approvers: distinct subjects, none automation"},
		"none":            {nil, ""},
		"same subject":    {[]token.Approval{a, a}, ""},
		"unrecorded kind": {[]token.Approval{a, {Sub: "s2", Iss: "i"}}, ""},
	} {
		if got := token.ApproversStatement(c.in); got != c.want {
			t.Errorf("%s: %q", name, got)
		}
	}
}
