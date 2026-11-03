package decide

import (
	"encoding/json"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
)

// RecordFields are the evidence-record fields the Python gateway writes for this decision (dispatch.py _audit,
// _deny_open, the unknown-session record; modelproxy.py authorize), before the envelope (store.Tx.Append adds
// seq, schema, boundary, coverage, verified, claimed, prev_hash, hash). nil means the decision is not recorded
// (a model call to a deployment without model routes).
//
// For an allowed tool call the result is "ok": the call's outcome (a backend error, a handler's refusal, a PR's
// receipt as `effect`) is the caller's to record once the call has run. Arguments are only ever hashed
// (args_sha256, canonical JSON), never stored.
func (e *Engine) RecordFields(req *EvaluationRequest, resp *EvaluationResponse) store.Event {
	c := &req.Context
	dc := &resp.Context
	decision := "deny"
	if resp.Decision {
		decision = "allow"
	}
	var rule any
	if dc.Rule != "" {
		rule = dc.Rule
	}
	ts := iso(c.Now)
	switch req.Action.Name {
	case ActionModelCall:
		if c.Models == nil {
			return nil
		}
		est := int64(0)
		var estV any = est
		if req.Action.Properties.EstTokens != nil {
			estV = req.Action.Properties.EstTokens.Value()
		}
		m := pycompat.NewMap(2)
		m.Set("model", req.Resource.ID)
		m.Set("est", estV)
		ev := store.Event{"ts": ts, "task_id": nil, "session": c.SessionID, "parent": nil, "principal": req.Subject.ID,
			"agent": nil, "tool": "model.call", "tier": nil, "decision": decision, "rule": rule, "target": req.Resource.ID,
			"args_sha256": digest(m), "result": "ok"}
		if !resp.Decision {
			ev["result"] = dc.Message
		}
		if s := c.Session; s != nil {
			ev["task_id"], ev["parent"], ev["agent"] = s.TaskID, strp(s.ParentID), s.Agent
		}
		return ev
	case ActionSessionOpen:
		p := req.Action.Properties
		if !resp.Decision {
			return store.Event{"ts": ts, "session": nil, "task_id": nil, "principal": req.Subject.ID,
				"agent": req.Resource.ID, "tool": "session.open", "tier": nil, "decision": "deny", "rule": rule,
				"target": nil, "args_sha256": digest(pycompat.NewMap(0)), "result": dc.Message}
		}
		g := dc.Grant
		args := pycompat.NewMap(2)
		result := "opened"
		if p.Trigger != "" {
			args.Set("trigger", p.Trigger)
			if g.Deduped {
				args.Set("deduped", true)
				result = "deduped"
			}
		} else {
			raw, _ := decodeRaw(p.Limits)
			if !pycompat.Truthy(raw) {
				raw = pycompat.NewMap(0)
			}
			args.Set("limits", raw)
		}
		return store.Event{"ts": ts, "task_id": g.TaskID, "session": g.Session, "parent": strp(g.Parent),
			"principal": g.Principal, "agent": g.Agent, "tool": "session.open", "tier": nil, "decision": "allow",
			"rule": nil, "target": nil, "args_sha256": digest(args), "result": result}
	}
	// tool.call, session.spawn
	tool := req.Resource.ID
	args, err := req.argsMap()
	if err != nil {
		args = pycompat.NewMap(0)
	}
	s := c.Session
	if s == nil {
		return store.Event{"ts": ts, "session": c.SessionID, "task_id": nil, "principal": req.Subject.ID,
			"agent": nil, "tool": tool, "tier": nil, "decision": "deny", "rule": rule, "target": nil,
			"args_sha256": digest(args), "result": dc.Message}
	}
	var tier, target any
	if dc.Tier != nil {
		tier = json.Number(itoa(*dc.Tier))
	}
	if spec := e.b.tools[tool]; spec != nil {
		target = e.envTierOf(spec, args)
	}
	result := "ok"
	if !resp.Decision {
		result = dc.Message
	}
	ev := store.Event{"ts": ts, "task_id": s.TaskID, "session": s.ID, "parent": strp(s.ParentID),
		"principal": req.Subject.ID, "agent": s.Agent, "tool": tool, "tier": tier, "decision": decision, "rule": rule,
		"target": target, "args_sha256": digest(args), "result": result}
	for _, p := range e.b.packs {
		if app := p.AppOf(tool, args); app != "" {
			ev["app"] = pycompat.Truncate(pycompat.Lower(app), 100)
			break
		}
	}
	return ev
}

func strp(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func itoa(n int) string { return I(int64(n)).String() }

// digest is audit.args_digest over a pyval value.
func digest(v any) string {
	d, err := canon.ArgsDigest(pycompat.ToJSON(v))
	if err != nil {
		return ""
	}
	return d
}
