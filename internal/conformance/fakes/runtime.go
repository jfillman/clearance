package fakes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/jfillman/clearance/internal/conformance"
	"github.com/jfillman/clearance/internal/decide"
)

// Runtime is a fake runtime provider, the Autopilot gateway's shape: for each call it asks the core, applies the
// decision's spend to the session it holds, acts on the target only on allow, reports the outcome against the
// decision, and fails closed when the core does not answer.
type Runtime struct {
	// ActOnDeny is the broken variant: it acts on whatever the core answered, allow or deny.
	ActOnDeny bool

	*control
	mu    sync.Mutex
	spent map[string]decide.Spend // per session: the spend applied so far
}

// NewRuntime is a runtime provider named name at version.
func NewRuntime(name, version string) *Runtime {
	p := &Runtime{spent: map[string]decide.Spend{}}
	p.control = newControl(conformance.Info{Name: name, Version: version, Roles: []string{conformance.RoleRuntime}},
		conformance.RoleRuntime)
	p.flow = p.call
	return p
}

// Handler serves the conformance control interface.
func (p *Runtime) Handler() http.Handler { return p.handler() }

// evaluation is the part of the core's answer the provider reads.
type evaluation struct {
	Decision bool `json:"decision"`
	Context  struct {
		Rule    string          `json:"rule"`
		Message string          `json:"message"`
		Spend   json.RawMessage `json:"spend"`
	} `json:"context"`
	DecisionID *string                `json:"decision_id"`
	Record     *conformance.RecordRef `json:"record"`
}

func (p *Runtime) call(ctx context.Context, a conformance.ApplyRequest, set func(func(*conformance.Status))) {
	var req struct {
		Action struct {
			Properties struct {
				Args json.RawMessage `json:"args"`
			} `json:"properties"`
		} `json:"action"`
		Context struct {
			SessionID string `json:"session_id"`
		} `json:"context"`
	}
	if err := json.Unmarshal(a.Evaluation, &req); err != nil {
		set(func(s *conformance.Status) {
			s.State, s.Reason = conformance.StateFailed, "bad evaluation: "+err.Error()
		})
		return
	}

	// 1. Ask the core. No answer (or a 5xx) is the outage policy: fail closed, never act.
	var ans evaluation
	if _, err := p.post(ctx, a.Core.URL+"/access/v1/evaluation", a.Core.Bearer, a.Evaluation, &ans); err != nil {
		reason := "refused: " + err.Error()
		if errors.Is(err, errUnavailable) {
			reason = "core-unavailable: failed closed: " + err.Error()
		}
		set(func(s *conformance.Status) { s.State, s.Reason = conformance.StateRefused, reason })
		return
	}
	id := ""
	if ans.DecisionID != nil {
		id = *ans.DecisionID
	}

	// 2. Apply the spend the decision carries to the session, allow or deny (a deny counts a denial).
	var spend decide.Spend
	if len(ans.Context.Spend) > 0 {
		if err := json.Unmarshal(ans.Context.Spend, &spend); err != nil {
			set(func(s *conformance.Status) { s.State, s.Reason = conformance.StateFailed, "bad spend: "+err.Error() })
			return
		}
	}
	p.applySpend(req.Context.SessionID, spend)
	applied, _ := json.Marshal(spend)
	set(func(s *conformance.Status) { s.DecisionID, s.Spend = id, applied })

	// 3. Act only on allow.
	if !ans.Decision && !p.ActOnDeny {
		set(func(s *conformance.Status) {
			s.State, s.Reason = conformance.StateRefused, "denied "+ans.Context.Rule+": "+ans.Context.Message
		})
		return
	}
	rc, err := p.applyTarget(ctx, a, string(req.Action.Properties.Args))
	result := "ok"
	if err != nil {
		result = "error:TargetError"
	}

	// 4. Report the outcome against the decision (also for a failed call: the result says so).
	var ref conformance.RecordRef
	body := map[string]any{"result": result, "receipt": map[string]any{"conformance_id": a.ID,
		"target_seq": strconv.FormatInt(rc.Seq, 10)}}
	_, oerr := p.post(ctx, a.Core.URL+"/v1/decisions/"+id+"/outcome", a.Core.Bearer, body, &ref)
	set(func(s *conformance.Status) {
		switch {
		case err != nil:
			s.State, s.Reason = conformance.StateFailed, "the target refused: "+err.Error()
		default:
			s.State = conformance.StateApplied
		}
		if oerr == nil {
			s.Outcome = &ref
		} else {
			s.Reason = fmt.Sprintf("%s (outcome not recorded: %v)", s.Reason, oerr)
		}
	})
}

func (p *Runtime) applySpend(session string, sp decide.Spend) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.spent[session]
	t.ToolCalls += sp.ToolCalls
	t.GithubCalls += sp.GithubCalls
	t.OpenPRs += sp.OpenPRs
	t.Children += sp.Children
	t.Denial = t.Denial || sp.Denial
	p.spent[session] = t
}

// Spent is the spend applied to a session so far.
func (p *Runtime) Spent(session string) decide.Spend {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.spent[session]
}
