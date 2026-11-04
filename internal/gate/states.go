package gate

import (
	"fmt"
	"slices"
)

// The clearance state machine (C-6). A change is registered into one of the first three states; holding is the
// only state that moves on its own (people, the TTL, a new head); cleared moves only when something takes the
// clearance away (a new head, an exception); the rest are final. "held" in the design is the state holding: a
// provider that held a change during an outage (deploy.degraded, decision deny) leaves the state as it was.
const (
	StateHolding    = "holding"    // held for people: tier 2 or 3, or a tier-1 change whose checks are not green yet
	StateCleared    = "cleared"    // cleared by policy (tier 0, 1, or an unprotected environment) or by people
	StateDenied     = "denied"     // denied by policy (DG-PROVENANCE, DG-POLICY, DG-DEFINITION) or by a person
	StateExpired    = "expired"    // not cleared within its TTL
	StateSuperseded = "superseded" // a new head on the same pull request (or app, env and cluster for a push)
	StateDegraded   = "degraded"   // a provider let it land while the core was unreachable, before it was cleared
	StateException  = "exception"  // an exception names it: it landed outside its clearance (deploy.exception)
)

// Transition is one edge of the state machine: from ("" for a change being registered) to, and what moves it.
type Transition struct {
	From, To, By string
}

// Transitions is the whole state machine. Moving a change along any other edge is a bug, and the gate refuses to
// write it (Service operations fail, nothing commits). A clearance token is live only while its change is cleared:
// every edge out of cleared revokes it in the same transaction (deploy.revoke), and an edge into cleared issues one.
var Transitions = []Transition{
	{"", StateHolding, "register: tier 2 or 3, or tier 1 waiting on its checks"},
	{"", StateCleared, "register: tier 0 or 1 cleared by policy, or an environment that is not protected"},
	{"", StateDenied, "register: denied by policy"},
	{StateHolding, StateCleared, "the requirement is met by people, or a re-registration clears by policy"},
	{StateHolding, StateDenied, "a person (or an admin) denies it, or a re-registration denies by policy"},
	{StateHolding, StateExpired, "its TTL passes"},
	{StateHolding, StateSuperseded, "a new head registers"},
	{StateHolding, StateDegraded, "a provider reports it let the change land during an outage (deploy.degraded, allow)"},
	{StateHolding, StateException, "an exception names it (deploy.exception)"},
	{StateCleared, StateSuperseded, "a new head registers (the token is revoked)"},
	{StateCleared, StateException, "an exception names it: drift, a digest mismatch, out of band (the token is revoked)"},
}

// FinalStates are the states nothing moves a change out of: a new head registers a new change.
var FinalStates = []string{StateDenied, StateExpired, StateSuperseded, StateDegraded, StateException}

// CanMove says whether the state machine has the edge from -> to.
func CanMove(from, to string) bool {
	for _, t := range Transitions {
		if t.From == from && t.To == to {
			return true
		}
	}
	return false
}

// ErrTransition is a move the state machine does not have: a bug in the gate, never a caller's error.
type ErrTransition struct{ From, To string }

func (e *ErrTransition) Error() string {
	return fmt.Sprintf("gate: no transition from %q to %q", e.From, e.To)
}

// move sets c's state to `to` along an edge of the machine, revoking its token when it leaves cleared (why is the
// deploy.revoke record's reason, extra its fields). It does not write c; the caller does (w.put).
func (w *writer) move(c *Change, to, why string, extra map[string]any) {
	if w.err != nil {
		return
	}
	from := c.State
	if !CanMove(from, to) {
		w.err = &ErrTransition{from, to}
		return
	}
	c.State = to
	if from == StateCleared {
		w.revoke(c, why, extra)
	}
}

// opened is a new change's first state, checked against the machine.
func (w *writer) opened(c *Change, to string) {
	if w.err == nil && !CanMove("", to) {
		w.err = &ErrTransition{"", to}
		return
	}
	c.State = to
}

// final reports whether state is one nothing moves out of.
func final(state string) bool { return slices.Contains(FinalStates, state) }
