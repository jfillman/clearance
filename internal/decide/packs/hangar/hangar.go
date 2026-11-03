// Package hangar is the Hangar pack (clearance.packs.hangar): the policy for Glidepath and Airframe tools. R021
// is Glidepath's cicd.yaml scope on any file-writing tool, R022 and R023 the per-agent app allowlists
// (profile.glidepath.apps, profile.airframe.apps). Policy only: what the tools do is Autopilot's.
//
// It is a Go pack so the Hangar deployment decides exactly as the Python one does; R-5 turns it into
// configuration. The vendored Glidepath scope (vendor/glidepath-scope.json) is embedded as-is.
package hangar

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"

	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/decide/pyval"
)

//go:embed hangar.json
var hangarJSON []byte

//go:embed vendor/glidepath-scope.json
var scopeJSON []byte

// Pack is the Hangar pack. Build it with New.
type Pack struct {
	data  decide.BundleData
	scope []scopeRule
	raw   any
}

// New loads the pack's embedded tools, rules and Glidepath scope.
func New() (*Pack, error) {
	d, err := decide.ParseBundle(hangarJSON)
	if err != nil {
		return nil, err
	}
	p := &Pack{data: d}
	if err := p.loadScope(scopeJSON); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Pack) loadScope(data []byte) error {
	var doc struct {
		Rules []map[string]json.RawMessage `json:"rules"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("hangar: glidepath scope: %w", err)
	}
	raw, err := pyval.DecodeJSON(data)
	if err != nil {
		return fmt.Errorf("hangar: glidepath scope: %w", err)
	}
	p.raw = raw
	for i, r := range doc.Rules {
		var sr scopeRule
		for k, v := range r {
			switch k {
			case "pattern":
				err = json.Unmarshal(v, &sr.Pattern)
			case "agentScope":
				err = json.Unmarshal(v, &sr.AgentScope)
			case "why":
				err = json.Unmarshal(v, &sr.Why)
			case "order":
				sr.Order, err = pyval.DecodeJSON(v)
			case "default":
				sr.Default, err = pyval.DecodeJSON(v)
				sr.hasDefault = true
			default:
				err = fmt.Errorf("unknown key %q", k)
			}
			if err != nil {
				return fmt.Errorf("hangar: glidepath scope rule %d: %w", i, err)
			}
		}
		if sr.Pattern == "" || (sr.AgentScope != "human" && sr.AgentScope != "open" && sr.AgentScope != "tighten") {
			return fmt.Errorf("hangar: glidepath scope rule %d: bad pattern or agentScope", i)
		}
		sr.segs = segments(sr.Pattern)
		p.scope = append(p.scope, sr)
	}
	return nil
}

// Name is the pack's name.
func (p *Pack) Name() string { return "hangar" }

// Tools are the glidepath.* and airframe.* tools.
func (p *Pack) Tools() []decide.ToolSpec { return p.data.Tools }

// Rules are R021-R023.
func (p *Pack) Rules() []decide.Rule { return p.data.Rules }

// Data is the vendored Glidepath scope.
func (p *Pack) Data() any { return json.RawMessage(scopeJSON) }

// Vars are the ctx.* variables the rules read.
func (p *Pack) Vars() []decide.Var {
	return []decide.Var{
		{Name: "cicd_scope_problems", Type: cel.IntType},
		{Name: "has_glidepath_app", Type: cel.BoolType}, {Name: "glidepath_app_ok", Type: cel.BoolType},
		{Name: "has_airframe_app", Type: cel.BoolType}, {Name: "airframe_app_ok", Type: cel.BoolType},
	}
}

// apps is profile.<section>.apps from the definition's raw profile.
func apps(profile any, section string) []string {
	m, ok := profile.(*pyval.Map)
	if !ok {
		return nil
	}
	sec, _ := m.GetStr(section)
	sm, ok := sec.(*pyval.Map)
	if !ok {
		return nil
	}
	l, _ := sm.GetStr("apps")
	var out []string
	switch x := l.(type) {
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case string:
		for _, r := range x { // list("abc"): its characters
			out = append(out, string(r))
		}
	}
	return out
}

func (p *Pack) appAllowed(in *decide.CallInput, app string, allow []string) bool {
	for _, g := range allow {
		if in.Globs.FnmatchCase(app, g) {
			return true
		}
	}
	return false
}

// Context is packs/hangar context().
func (p *Pack) Context(in *decide.CallInput) (decide.PackContext, error) {
	bad := 0
	a := in.Args
	gp := strings.HasPrefix(in.Tool, "glidepath.")
	af := strings.HasPrefix(in.Tool, "airframe.")
	gpApp, hasGP := "", false
	afApp, hasAF := "", false
	if gp {
		gpApp, hasGP, _ = strOf(a, "app")
		if in.Spec != nil {
			bad += glidepathBadArgs(a)
			if in.Tool == "glidepath.promote" && !glidepathPromoteSourceOK(a) {
				bad++
			}
		}
	}
	if af {
		afApp, hasAF, _ = strOf(a, "app")
		if in.Spec != nil {
			bad += airframeBadArgs(a)
		}
	}
	var files []any
	if v, ok := a.GetStr("files"); ok {
		files, _ = v.([]any)
	}
	var probs []decide.Problem
	if len(files) > 0 && in.Spec != nil && in.Spec.WritesFiles {
		var err error
		if probs, err = p.cicdScopeProblems(files); err != nil {
			return decide.PackContext{}, err
		}
	}
	gpOK, afOK := true, true
	if hasGP && gpApp != "" {
		gpOK = p.appAllowed(in, gpApp, apps(in.Profile, "glidepath"))
	}
	if hasAF && afApp != "" {
		afOK = p.appAllowed(in, afApp, apps(in.Profile, "airframe"))
	}
	return decide.PackContext{
		Values: []any{int64(len(probs)), hasGP, gpOK, hasAF, afOK},
		Bad:    bad,
		State:  probs,
	}, nil
}

// Decide gives R021 the first GP-SCOPE problem's rule id and hint, every problem under problems.
func (p *Pack) Decide(rule *decide.Rule, in *decide.CallInput, state any) (decide.Decision, bool) {
	if rule.ID != "R021" {
		return decide.Decision{}, false
	}
	probs, _ := state.([]decide.Problem)
	if len(probs) == 0 {
		return decide.Decision{}, false
	}
	msgs := make([]string, len(probs))
	for i, q := range probs {
		msgs[i] = q.Message
	}
	tier := 0
	if in.Spec != nil {
		tier = in.Spec.Tier
	}
	return decide.Decision{Rule: probs[0].Rule, Name: rule.Name, Message: strings.Join(msgs, "; "),
		Hint: probs[0].Hint, Tier: &tier, Problems: probs}, true
}

// AppOf is the Hangar app a call acts on.
func (p *Pack) AppOf(tool string, args *pyval.Map) string {
	if strings.HasPrefix(tool, "glidepath.") || strings.HasPrefix(tool, "airframe.") || tool == "xr.request" {
		s, _, _ := strOf(args, "app")
		return s
	}
	repo, isStr, _ := strOf(args, "repo")
	if strings.HasPrefix(tool, "repo.") && isStr && strings.Contains(repo, "/") {
		name := repo[strings.LastIndex(repo, "/")+1:]
		for _, prefix := range []string{"gitops-infra-", "gitops-"} {
			if strings.HasPrefix(name, prefix) {
				return name[len(prefix):]
			}
		}
		return name
	}
	return ""
}
