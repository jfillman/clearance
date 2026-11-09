package fakes

import (
	"context"
	"net/http"

	"github.com/jfillman/clearance/internal/conformance"
)

// Adapter is the conformance control interface in front of a real provider's code: the provider's own tests
// build one with the flow that runs its normal path once against the core and the target an ApplyRequest names, and
// run conformance.Run against its Handler. It is the test-only switch the protocol asks for: nothing in a provider's
// binary serves it.
type Adapter struct {
	*control
}

// Progress is how a flow reports where it is with one apply.
type Progress struct {
	set func(func(*conformance.Status))
}

// ChangeID names the change the core answered.
func (p Progress) ChangeID(id string) { p.set(func(s *conformance.Status) { s.ChangeID = id }) }

// Holding says the change holds and nothing was applied.
func (p Progress) Holding() {
	p.set(func(s *conformance.Status) { s.State = conformance.StateHolding })
}

// Refused ends the apply: the provider deliberately did not act.
func (p Progress) Refused(reason string) {
	p.set(func(s *conformance.Status) { s.State, s.Reason = conformance.StateRefused, reason })
}

// Failed ends the apply: the provider tried to act and could not.
func (p Progress) Failed(reason string) {
	p.set(func(s *conformance.Status) { s.State, s.Reason = conformance.StateFailed, reason })
}

// Applied ends the apply: the provider acted. outcome is the record it wrote, when it knows it.
func (p Progress) Applied(outcome *conformance.RecordRef) {
	p.set(func(s *conformance.Status) { s.State, s.Outcome = conformance.StateApplied, outcome })
}

// NewAdapter is a deployment provider named info.Name at info.Version whose flow is run for each apply.
func NewAdapter(info conformance.Info, flow func(ctx context.Context, a conformance.ApplyRequest, p Progress)) *Adapter {
	info.Roles = []string{conformance.RoleDeployment}
	ad := &Adapter{control: newControl(info, conformance.RoleDeployment)}
	ad.flow = func(ctx context.Context, a conformance.ApplyRequest, set func(func(*conformance.Status))) {
		flow(ctx, a, Progress{set})
	}
	return ad
}

// Handler serves the conformance control interface.
func (a *Adapter) Handler() http.Handler { return a.handler() }

// ApplyTarget acts on the target: the content a provider's apply step produced.
func (a *Adapter) ApplyTarget(ctx context.Context, ar conformance.ApplyRequest, content string) (conformance.TargetReceipt, error) {
	return a.applyTarget(ctx, ar, content)
}
