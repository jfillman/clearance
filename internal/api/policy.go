package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/profile"
	"github.com/jfillman/clearance/internal/pycompat"
)

// PolicyDoc is GET /v1/policy (api.py policy_view): the rules in evaluation order with their pack, the tool
// registry with tiers, and "core" plus the loaded policy bundles (`packs`, the name api.py gave them).
type PolicyDoc struct {
	Rules []PolicyRule `json:"rules"`
	Tools []PolicyTool `json:"tools"`
	Packs []string     `json:"packs"`
}

// PolicyRule is one deny rule as data.
type PolicyRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Expression string `json:"expression"`
	Message    string `json:"message"`
	Hint       string `json:"hint"`
	Order      int    `json:"order"`
	Pack       string `json:"pack"`
}

// PolicyTool is one registered tool.
type PolicyTool struct {
	Name         string   `json:"name"`
	Tier         string   `json:"tier"`
	Summary      string   `json:"summary"`
	RequiredArgs []string `json:"required_args"`
	Target       string   `json:"target"`
	ProposeOnly  bool     `json:"propose_only"`
	WritesFiles  bool     `json:"writes_files"`
	GithubCost   int64    `json:"github_cost"`
}

// ExplainDecision is the decision of a dry run (policy.py Decision.as_dict).
type ExplainDecision struct {
	Allow    bool             `json:"allow"`
	Rule     *string          `json:"rule"`
	Name     *string          `json:"name"`
	Message  string           `json:"message"`
	Hint     string           `json:"hint"`
	Tier     *int             `json:"tier"`
	Problems []decide.Problem `json:"problems,omitempty"`
}

// Explanation is GET /v1/policy/explain (api.py explain): the decision, the rules up to and including the first
// that matched or failed (path), every rule's verdict (all_rules).
type Explanation struct {
	Agent     string               `json:"agent"`
	Tool      string               `json:"tool"`
	KnownTool bool                 `json:"known_tool"`
	Decision  ExplainDecision      `json:"decision"`
	Path      []decide.RuleVerdict `json:"path"`
	AllRules  []decide.RuleVerdict `json:"all_rules"`
	DryRun    bool                 `json:"dry_run"`
}

var tierNames = [...]string{"T0", "T1", "T2", "T3"}

func tierName(t int) string {
	if t >= 0 && t < len(tierNames) {
		return tierNames[t]
	}
	return "T?"
}

// PolicyView is api.py policy_view for the engine: each rule names the bundle it came from ("core" for the core's).
func (s *Server) PolicyView() PolicyDoc {
	e := s.opt.Engine
	doc := PolicyDoc{Rules: []PolicyRule{}, Tools: []PolicyTool{}, Packs: []string{"core"}}
	for _, r := range e.Rules() {
		pack := "core"
		if p := e.RuleBundle(r.ID); p != "" {
			pack = p
		}
		doc.Rules = append(doc.Rules, PolicyRule{ID: r.ID, Name: r.Name, Expression: r.Expr, Message: r.Message,
			Hint: r.Hint, Order: r.Order, Pack: pack})
	}
	tools := e.Tools()
	sort.SliceStable(tools, func(i, j int) bool {
		if tools[i].Tier != tools[j].Tier {
			return tools[i].Tier < tools[j].Tier
		}
		return tools[i].Name < tools[j].Name
	})
	for _, t := range tools {
		req := t.RequiredArgs
		if req == nil {
			req = []string{}
		}
		doc.Tools = append(doc.Tools, PolicyTool{Name: t.Name, Tier: tierName(t.Tier), Summary: t.Description,
			RequiredArgs: req, Target: t.Target, ProposeOnly: t.ProposeOnly, WritesFiles: t.WritesFiles,
			GithubCost: t.GithubCost})
	}
	doc.Packs = append(doc.Packs, e.BundleNames()...)
	return doc
}

func (s *Server) getPolicy(w http.ResponseWriter, _ *http.Request, _ *Viewer) {
	if s.opt.Engine == nil {
		writeError(w, 404, "this deployment serves no policy")
		return
	}
	writeJSON(w, 200, s.PolicyView())
}

func (s *Server) explainPolicy(w http.ResponseWriter, r *http.Request, v *Viewer) {
	if s.opt.Engine == nil {
		writeError(w, 404, "this deployment serves no policy")
		return
	}
	q := query(r)
	var d *profile.AgentDefinition
	if s.opt.Definitions != nil {
		d = s.opt.Definitions.Get(q["agent"])
	}
	if d == nil {
		writeError(w, 404, "no such agent")
		return
	}
	tool := q["tool"]
	if tool == "" {
		writeError(w, 400, "tool is required")
		return
	}
	raw := q["args"]
	if raw == "" {
		raw = "{}"
	}
	if len(raw) > MaxExplainArgs {
		writeError(w, 400, "args too large")
		return
	}
	args, err := pycompat.DecodeJSON([]byte(raw))
	if err != nil {
		writeError(w, 400, "args is a JSON object")
		return
	}
	if _, ok := args.(*pycompat.Map); !ok {
		writeError(w, 400, "args is a JSON object")
		return
	}
	person := v.Person
	if person == "" {
		person = "user:dry-run"
	}
	out, err := Explain(r, s.opt.Engine, d, person, tool, json.RawMessage(raw), s.opt.Clock())
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

// DryRunSession and DryRunTask name the fresh session a dry run decides on (api.py explain).
const (
	DryRunSession = "s-dry-run"
	DryRunTask    = "t-dry-run"
)

// limitsOf is a definition's limits as the decision context carries them (limits.Limits.as_dict).
func limitsOf(l profile.Limits) decide.Limits {
	tools, models := l.Tools, l.Models
	if tools == nil {
		tools = []string{}
	}
	if models == nil {
		models = []string{}
	}
	return decide.Limits{TierCeiling: tierName(l.TierCeiling), TTLMinutes: decide.I(l.TTLMinutes),
		ToolCalls: decide.I(l.ToolCalls), GithubCalls: decide.I(l.GithubCalls), OpenPRs: decide.I(l.OpenPRs),
		ModelTokens: decide.I(l.ModelTokens), Children: decide.I(l.Children), Tools: tools, Models: models,
		Network: l.Network.Label(), Compute: l.Compute.String()}
}

// DryRunRequest is the evaluation a dry run decides: the real policy for `person` (a person's own tier ceiling,
// T1, as api.py explain builds it) on a fresh session of the definition, nothing used, nothing reserved.
func DryRunRequest(d *profile.AgentDefinition, person, tool string, args json.RawMessage, now time.Time) (*decide.EvaluationRequest, error) {
	profileRaw, err := json.Marshal(d.RawProfile)
	if err != nil {
		return nil, err
	}
	if d.RawProfile == nil {
		profileRaw = nil
	}
	now = now.UTC()
	nn := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	return &decide.EvaluationRequest{
		Subject: decide.Subject{Type: "principal", ID: person,
			Properties: decide.SubjectProperties{Kind: "user", TierCeiling: 1}},
		Action:   decide.Action{Name: decide.ActionToolCall, Properties: decide.ActionProperties{Args: args}},
		Resource: decide.Resource{Type: decide.ResourceTool, ID: tool},
		Context: decide.Context{Now: now, SessionID: DryRunSession,
			Session: &decide.SessionState{ID: DryRunSession, Principal: person, Agent: d.Name, TaskID: DryRunTask,
				Limits: limitsOf(d.Limits), ExpiresAt: now.Add(time.Duration(d.Limits.TTLMinutes) * time.Minute)},
			Scope: &decide.Scope{AgentKind: d.Kind, DenyPaths: nn(d.DenyPaths), ReposAllow: nn(d.ReposAllow),
				APIAllow: nn(d.APIAllow), FieldDeny: nn(d.FieldDeny), FieldAllow: nn(d.FieldAllow),
				Profile: profileRaw}},
	}, nil
}

// Explain is api.py explain: Decide and Trace on the dry-run request. Nothing is recorded or spent.
func Explain(r *http.Request, e *decide.Engine, d *profile.AgentDefinition, person, tool string, args json.RawMessage,
	now time.Time) (*Explanation, error) {
	req, err := DryRunRequest(d, person, tool, args, now)
	if err != nil {
		return nil, err
	}
	res := e.Decide(r.Context(), req)
	all := e.Trace(r.Context(), req)
	path := all
	for i, rv := range all {
		if (rv.Matched != nil && *rv.Matched) || rv.Error {
			path = all[:i+1]
			break
		}
	}
	strp := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	c := res.Context
	return &Explanation{Agent: d.Name, Tool: tool, KnownTool: e.Tool(tool) != nil,
		Decision: ExplainDecision{Allow: res.Decision, Rule: strp(c.Rule), Name: strp(c.Name), Message: c.Message,
			Hint: c.Hint, Tier: c.Tier, Problems: c.Problems},
		Path: path, AllRules: all, DryRun: true}, nil
}
