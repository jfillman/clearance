package slack

import (
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/gate"
)

// An approval set aside is history, not a seat filled: Slack shows the seat open and says so.
func TestASetAsideApprovalIsNotASeatFilled(t *testing.T) {
	c := &gate.Change{State: gate.StateHolding, Tier: 3,
		Requirement: &gate.Requirement{Owner: 1, Outside: 1, OwnerGroup: "group:default/payments", OutsideGroups: []string{"group:default/admins"}},
		Approvals:   []gate.Approval{{Person: "user:ann", Role: "owner", SetAside: "user:ann is a source author of this change since they approved"}}}
	if outsideWaiting(c) {
		t.Error("the owner seat is open again: nobody outside is waited for yet")
	}
	if got := approvers(c); !strings.HasPrefix(got, "none yet") || !strings.Contains(got, "1 set aside") {
		t.Errorf("approvers: %q", got)
	}
	if stateKey(c) != "holding|0" {
		t.Errorf("stateKey %q", stateKey(c))
	}
	// the thread says the seat reopened when a counted approval is set aside
	if note := threadNote(c, "holding|1"); !strings.Contains(note, "set aside") || strings.Contains(note, "user:ann approved") {
		t.Errorf("note: %q", note)
	}
	// and a counted approval still reads as before
	c.Approvals = append(c.Approvals, gate.Approval{Person: "user:bob", Role: "owner"})
	if !outsideWaiting(c) || !strings.Contains(approvers(c), "user:bob") || strings.Contains(approvers(c), "user:ann (") {
		t.Errorf("counted: %v %q", outsideWaiting(c), approvers(c))
	}
	if note := threadNote(c, "holding|0"); !strings.Contains(note, "user:bob approved (owner)") {
		t.Errorf("note: %q", note)
	}
}
