package decide

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/pycompat"
)

// maxDepth is session.MAX_DEPTH.
const maxDepth = 3

// limitRequest is limits.LimitRequest: every field optional.
type limitRequest struct {
	tier                  *int
	ttl                   *Int
	budgets               [5]*Int // budgetFields order
	tools, models         []string
	hasTools, hasModels   bool
	network, compute      *int
	networkSet, computSet bool
}

var limitFields = map[string]bool{"tier_ceiling": true, "ttl_minutes": true, "tool_calls": true, "github_calls": true,
	"open_prs": true, "model_tokens": true, "children": true, "tools": true, "models": true, "network": true,
	"compute": true}

// requestError is a requested-limits problem: R008 (or R007 for a widening).
type requestError struct {
	widen bool
	msg   string
}

func (e *requestError) Error() string { return e.msg }

func intField(name string, v any) (*Int, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case int64:
		i := I(x)
		return &i, nil
	case *big.Int:
		i := intFromBig(x)
		return &i, nil
	}
	// Python compares a bool or a float as a number and fails on anything else; Go refuses all three (R008).
	return nil, &requestError{msg: fmt.Sprintf("requested limits: %s must be an integer", name)}
}

func stringSet(name string, v any) ([]string, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, &requestError{msg: fmt.Sprintf("requested limits: %s must be a list of names", name)}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, e := range l {
		s, ok := e.(string)
		if !ok {
			return nil, &requestError{msg: fmt.Sprintf("requested limits: %s must be a list of names", name)}
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Network.parse and ComputeClass.parse: the enum member named by the text, upper-cased (and, for a network,
// with + and - read as _).
var (
	networkNames = map[string]int{"NONE": 0, "CLEARANCE": 1, "CLEARANCE_MODEL": 2, "ALLOWLIST": 3}
	computeNames = map[string]int{"SMALL": 0, "MEDIUM": 1, "LARGE": 2, "GPU": 3}
)

func parseEnum(v any, what string) (*int, error) {
	s, ok := v.(string)
	if !ok {
		return nil, &requestError{msg: fmt.Sprintf("requested limits: %s must be a string", what)}
	}
	var n int
	var found bool
	if what == "network" {
		n, found = networkNames[strings.NewReplacer("+", "_", "-", "_").Replace(strings.ToUpper(s))]
		if !found {
			return nil, &requestError{msg: "unknown network mode " + pycompat.StrRepr(s)}
		}
	} else {
		n, found = computeNames[strings.ToUpper(s)]
		if !found {
			return nil, &requestError{msg: "unknown compute class " + pycompat.StrRepr(s)}
		}
	}
	return &n, nil
}

// parseLimitRequest is LimitRequest.from_dict.
func parseLimitRequest(v any) (*limitRequest, error) {
	if !pycompat.Truthy(v) {
		return &limitRequest{}, nil
	}
	d, ok := v.(*pycompat.Map)
	if !ok {
		return nil, &requestError{msg: "requested limits must be an object"}
	}
	var unknown []string
	for _, k := range d.Keys() {
		ks, _ := k.(string)
		if !limitFields[ks] {
			unknown = append(unknown, ks)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		l := make([]any, len(unknown))
		for i, u := range unknown {
			l[i] = u
		}
		return nil, &requestError{msg: "unknown limit fields: " + pycompat.Repr(l)}
	}
	r := &limitRequest{}
	if t, _ := d.GetStr("tier_ceiling"); pycompat.Truthy(t) {
		s, _ := t.(string)
		n, ok := tierOf(s)
		if !ok {
			return nil, &requestError{msg: "unknown tier ceiling " + pycompat.Repr(t)}
		}
		r.tier = &n
	}
	var err error
	if t, _ := d.GetStr("ttl_minutes"); t != nil {
		if r.ttl, err = intField("ttl_minutes", t); err != nil {
			return nil, err
		}
	}
	for i, f := range budgetFields {
		if b, _ := d.GetStr(f); b != nil {
			if r.budgets[i], err = intField(f, b); err != nil {
				return nil, err
			}
		}
	}
	if t, _ := d.GetStr("tools"); t != nil {
		if r.tools, err = stringSet("tools", t); err != nil {
			return nil, err
		}
		r.hasTools = true
	}
	if m, _ := d.GetStr("models"); m != nil {
		if r.models, err = stringSet("models", m); err != nil {
			return nil, err
		}
		r.hasModels = true
	}
	if n, _ := d.GetStr("network"); pycompat.Truthy(n) {
		if r.network, err = parseEnum(n, "network"); err != nil {
			return nil, err
		}
	}
	if c, _ := d.GetStr("compute"); pycompat.Truthy(c) {
		if r.compute, err = parseEnum(c, "compute"); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func minus(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func intersect(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	out := []string{}
	for _, x := range a {
		if in[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func label(table map[string]int, n int) string {
	for k, v := range table {
		if v == n {
			return k
		}
	}
	return ""
}

var tierNames = [...]string{"T0", "T1", "T2", "T3"}

// narrow is limits.narrow: requested limits may only narrow what is inherited.
func narrow(parent Limits, r *limitRequest) (Limits, error) {
	out := parent
	out.Tools = append([]string{}, parent.Tools...)
	out.Models = append([]string{}, parent.Models...)
	var widened []string
	pt, _ := tierOf(parent.TierCeiling)
	if r.tier != nil {
		if *r.tier > pt {
			widened = append(widened, "tier_ceiling")
		} else {
			out.TierCeiling = tierNames[*r.tier]
		}
	}
	if r.ttl != nil {
		if r.ttl.Cmp(parent.TTLMinutes) > 0 {
			widened = append(widened, "ttl_minutes")
		} else {
			out.TTLMinutes = *r.ttl
		}
	}
	for i, f := range budgetFields {
		if q := r.budgets[i]; q != nil {
			if q.Cmp(*parent.budget(f)) > 0 {
				widened = append(widened, f)
			} else {
				*out.budget(f) = *q
			}
		}
	}
	if r.hasTools {
		if extra := minus(r.tools, parent.Tools); len(extra) > 0 {
			widened = append(widened, "tools:"+strings.Join(extra, ","))
		} else {
			out.Tools = r.tools
		}
	}
	if r.hasModels {
		if extra := minus(r.models, parent.Models); len(extra) > 0 {
			widened = append(widened, "models:"+strings.Join(extra, ","))
		} else {
			out.Models = r.models
		}
	}
	if r.network != nil {
		if *r.network > networks[parent.Network] {
			widened = append(widened, "network")
		} else {
			out.Network = label(networks, *r.network)
		}
	}
	if r.compute != nil {
		if *r.compute > computes[parent.Compute] {
			widened = append(widened, "compute")
		} else {
			out.Compute = label(computes, *r.compute)
		}
	}
	if len(widened) > 0 {
		return Limits{}, &requestError{widen: true, msg: "requested limits widen: " + strings.Join(widened, ", ")}
	}
	sort.Strings(out.Tools)
	sort.Strings(out.Models)
	return out, nil
}

func minInt(a, b Int) Int {
	if a.Cmp(b) <= 0 {
		return a
	}
	return b
}

// minutesLeft is Session.minutes_left(now).
func minutesLeft(s *SessionState, now time.Time) Int {
	us := s.ExpiresAt.Sub(now).Microseconds()
	m := us / 60_000_000
	if us%60_000_000 != 0 && us < 0 {
		m--
	}
	return I(max(0, m))
}

// maxTTLMinutes bounds a session's lifetime far above any definition's (the schema caps ttlMinutes at 1440).
const maxTTLMinutes = 100 * 365 * 24 * 60

// addMinutes is now + timedelta(minutes=ttl); false when the ttl is beyond maxTTLMinutes.
func addMinutes(now time.Time, ttl Int) (time.Time, bool) {
	n, ok := ttl.Small()
	if !ok || n > maxTTLMinutes || n < -maxTTLMinutes {
		return time.Time{}, false
	}
	return now.Add(time.Duration(n) * time.Minute), true
}

// open is Gateway.open_session and Gateway.open_triggered.
func (e *engine) open(req *EvaluationRequest) (Decision, *Grant) {
	c := &req.Context
	d := c.Agent
	p := req.Action.Properties
	deny := func(rule, why string) (Decision, *Grant) { return Decision{Rule: rule, Message: why}, nil }
	if p.Trigger != "" {
		if d == nil {
			return deny("R003", "unknown agent definition")
		}
		if d.IdentityType != "workload" || (d.Kind != "scheduled" && d.Kind != "event" && d.Kind != "service") {
			return deny("R001", "only workload agents of kind scheduled, event or service can be triggered")
		}
		if h := c.Hold; h != nil {
			return deny("R024", fmt.Sprintf("triggers held by %s until %s: %s", h.By, iso(h.Until), h.Reason))
		}
		sa := ""
		if d.ServiceAccount != nil {
			sa = *d.ServiceAccount
		}
		if p.TaskID != "" && c.Live != nil {
			l := c.Live
			return Decision{Allow: true}, &Grant{Session: l.ID, TaskID: l.TaskID, Principal: sa, Agent: l.Agent,
				Parent: l.ParentID, Depth: l.Depth, Limits: l.Limits, ExpiresAt: l.ExpiresAt, Deduped: true}
		}
		return e.grant(c, sa, d, &limitRequest{}, p.TaskID, "R008")
	}
	if d == nil {
		return deny("R003", "unknown agent definition")
	}
	if d.IdentityType == "workload" && (d.ServiceAccount == nil || req.Subject.ID != *d.ServiceAccount) {
		return deny("R001", "principal does not match the definition's workload identity")
	}
	if d.IdentityType == "delegated" && req.Subject.Properties.Kind != "user" {
		return deny("R001", "definition is for a delegated agent")
	}
	raw, err := decodeRaw(p.Limits)
	if err != nil {
		return deny("R008", "requested limits: "+err.Error())
	}
	lr, err := parseLimitRequest(raw)
	if err != nil {
		return deny("R008", err.Error())
	}
	return e.grant(c, req.Subject.ID, d, lr, p.TaskID, "R008")
}

func decodeRaw(raw []byte) (any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	return pycompat.DecodeJSON(raw)
}

// grant is SessionStore.open for a top-level session.
func (e *engine) grant(c *Context, principal string, d *AgentDef, lr *limitRequest, taskID, ttlRule string) (Decision, *Grant) {
	lim, err := narrow(d.Limits, lr)
	if err != nil {
		if err.(*requestError).widen {
			return Decision{Rule: "R007", Message: err.Error()}, nil
		}
		return Decision{Rule: "R008", Message: err.Error()}, nil
	}
	if lim.TTLMinutes.Cmp(I(1)) < 0 {
		return Decision{Rule: ttlRule, Message: "no time left to run"}, nil
	}
	exp, ok := addMinutes(c.Now, lim.TTLMinutes)
	if !ok {
		return Decision{Rule: "R008", Message: "requested limits: ttl_minutes is out of range"}, nil
	}
	if taskID == "" {
		taskID = "t-" + strings.TrimPrefix(c.NewSessionID, "s-")
	}
	return Decision{Allow: true}, &Grant{Session: c.NewSessionID, TaskID: taskID, Principal: principal, Agent: d.Name,
		Limits: lim, ExpiresAt: exp}
}

// spawn is a run.spawn call: the call's own rules, then Gateway._spawn's checks on the child.
func (e *engine) spawn(ctx context.Context, req *EvaluationRequest) (Decision, Spend, *Grant) {
	d, sp := e.toolCall(ctx, req)
	if !d.Allow {
		return d, sp, nil
	}
	// The gateway charges the call before its handler runs, so the child is cut from what the parent has left
	// after this call's own spend.
	charged := *req.Context.Session
	charged.Used.ToolCalls = charged.Used.ToolCalls.Add(I(sp.ToolCalls))
	charged.Used.GithubCalls = charged.Used.GithubCalls.Add(I(sp.GithubCalls))
	charged.Used.OpenPRs = charged.Used.OpenPRs.Add(I(sp.OpenPRs))
	parent := &charged
	args, _ := req.argsMap()
	refuse := func(rule, msg, hint string) (Decision, Spend, *Grant) {
		// The call was allowed and charged before the handler refused it, then the refusal counts as a denial.
		den := denialSpend(parent, rule, "run.spawn")
		sp.Denial, sp.Trip = den.Denial, den.Trip
		return Decision{Rule: rule, Name: "refused", Message: msg, Hint: hint, Tier: d.Tier}, sp, nil
	}
	child := req.Context.Agent
	if child == nil {
		return refuse("R003", "unknown agent definition", "Spawn an agent that exists in the catalog.")
	}
	rawLimits, _ := args.GetStr("limits")
	lr, err := parseLimitRequest(rawLimits)
	if err != nil {
		return refuse("R008", err.Error(), "Fix the requested limits; see the tool schema.")
	}
	const r016 = "Spawn fewer or smaller child runs, or finish the ones running."
	now := req.Context.Now
	if parent.expired(now) || parent.Tripped {
		return refuse("R016", "parent is expired or tripped", r016)
	}
	if parent.Depth+1 > maxDepth {
		return refuse("R016", fmt.Sprintf("run tree deeper than %d", maxDepth), r016)
	}
	if parent.remaining("children").Cmp(I(1)) < 0 {
		return refuse("R016", "children budget exhausted", r016)
	}
	base := child.Limits
	pt, _ := tierOf(parent.Limits.TierCeiling)
	bt, _ := tierOf(base.TierCeiling)
	base.TierCeiling = tierNames[min(pt, bt)]
	base.TTLMinutes = minInt(base.TTLMinutes, minutesLeft(parent, now))
	for _, f := range budgetFields {
		*base.budget(f) = minInt(*child.Limits.budget(f), parent.remaining(f))
	}
	base.Tools = intersect(child.Limits.Tools, parent.Limits.Tools)
	base.Models = intersect(child.Limits.Models, parent.Limits.Models)
	base.Network = label(networks, min(networks[base.Network], networks[parent.Limits.Network]))
	base.Compute = label(computes, min(computes[base.Compute], computes[parent.Limits.Compute]))
	lim, err := narrow(base, lr)
	if err != nil {
		if err.(*requestError).widen {
			return refuse("R007", err.Error(), "A child run may only narrow what its parent has left.")
		}
		return refuse("R008", err.Error(), "Fix the requested limits; see the tool schema.")
	}
	if lim.TTLMinutes.Cmp(I(1)) < 0 {
		return refuse("R016", "no time left to run", r016)
	}
	exp, ok := addMinutes(now, lim.TTLMinutes)
	if !ok {
		return refuse("R008", "requested limits: ttl_minutes is out of range", "Fix the requested limits; see the tool schema.")
	}
	if parent.ExpiresAt.Before(exp) {
		exp = parent.ExpiresAt
	}
	pid := parent.ID
	sp.Children = 1
	sp.Reserve = &Budgets{ToolCalls: lim.ToolCalls, GithubCalls: lim.GithubCalls, OpenPRs: lim.OpenPRs,
		ModelTokens: lim.ModelTokens}
	return d, sp, &Grant{Session: req.Context.NewSessionID, TaskID: parent.TaskID, Principal: parent.Principal,
		Agent: child.Name, Parent: &pid, Depth: parent.Depth + 1, Limits: lim, ExpiresAt: exp}
}

// iso is audit.iso: the one timestamp format records use.
func iso(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }
