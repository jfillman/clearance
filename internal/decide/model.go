package decide

import (
	"slices"

	"github.com/jfillman/clearance/internal/pycompat"
)

// model is Gateway.model_authorize and ModelProxy._decide.
func (e *Engine) model(req *EvaluationRequest) (Decision, Spend) {
	c := &req.Context
	if c.Models == nil {
		return Decision{Rule: "M006", Message: "this deployment has no model routes"}, Spend{}
	}
	s := c.Session
	model := req.Resource.ID
	deny := func(rule, msg string) (Decision, Spend) {
		var sp Spend
		if s != nil {
			sp = denialSpend(s, rule, "model.call")
		}
		return Decision{Rule: rule, Message: msg}, sp
	}
	acting := req.Subject.ID
	if req.Subject.Properties.ActingAs != "" {
		acting = req.Subject.Properties.ActingAs
	}
	switch {
	case s == nil || s.expired(c.Now):
		return deny("M001", "no live session")
	case s.Principal != acting:
		return deny("M002", "not this session's principal")
	case s.Tripped:
		return deny("M003", "session breaker is tripped")
	case networks[s.Limits.Network] < networks["clearance+model"]:
		return deny("M004", "this run's network mode does not include the model proxy")
	case !slices.Contains(s.Limits.Models, model):
		return deny("M005", "model "+pycompat.StrRepr(model)+" is not on this session's allowlist")
	case !slices.Contains(c.Models.Routes, model):
		return deny("M006", "no route for model "+pycompat.StrRepr(model))
	}
	est := *req.Action.Properties.EstTokens
	if est.Cmp(I(0)) < 0 || est.Cmp(s.remaining("model_tokens")) > 0 {
		return deny("M007", "model-token budget would be exceeded")
	}
	return Decision{Allow: true, Message: "allowed"}, Spend{}
}
