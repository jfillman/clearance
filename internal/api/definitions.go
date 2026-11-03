package api

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jfillman/clearance/internal/vocab"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/profile"
)

// Definitions is the live set clearance-api reads (autopilot api_serve.py's Definitions plus its
// DefinitionsRefresher): the bundled definitions (CLEARANCE_AGENTS_DIR) and the cluster pins the core stored in
// clearance_definitions, refreshed from the store. This process fetches nothing and decides nothing about a pin:
// a stored row that no longer parses is shown as rejected.
type Definitions struct {
	reg     *definitions.Registry
	bundled map[string]profile.AgentDefinition

	mu     sync.Mutex
	ver    int
	parsed map[string]*profile.AgentDefinition
}

// NewDefinitions holds the bundled definitions.
func NewDefinitions(bundled map[string]profile.AgentDefinition) *Definitions {
	b := map[string]definitions.Definition{}
	for n, d := range bundled {
		b[n] = d.Definition()
	}
	if bundled == nil {
		bundled = map[string]profile.AgentDefinition{}
	}
	return &Definitions{reg: definitions.NewRegistry(b), bundled: bundled, ver: -1}
}

// Refresh replaces the cluster set with the store's rows.
func (d *Definitions) Refresh(ctx context.Context, st Store) (definitions.Changes, error) {
	rows, err := st.Definitions(ctx)
	if err != nil {
		return definitions.Changes{}, err
	}
	maps := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(r.Record))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
			continue // not an object: nothing to show
		}
		maps = append(maps, m)
	}
	return d.reg.ApplyRecords(maps, profile.Parser()), nil
}

// Run refreshes every interval until ctx ends; a failed refresh keeps the set it has.
func (d *Definitions) Run(ctx context.Context, st Store, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rctx, cancel := context.WithTimeout(ctx, every)
			ch, err := d.Refresh(rctx, st)
			cancel()
			if err != nil {
				log.WarnContext(ctx, "definitions: refresh failed", "error", err.Error())
			} else if ch.Any() {
				log.InfoContext(ctx, "definitions: refreshed", "added", ch.Added, "changed", ch.Changed,
					"removed", ch.Removed, "live", d.reg.Len())
			}
		}
	}
}

// Names are the live definitions' names, sorted.
func (d *Definitions) Names() []string {
	set := map[string]bool{}
	for n := range d.bundled {
		set[n] = true
	}
	for _, r := range d.reg.Records() {
		if r.State == "loaded" {
			set[r.Name] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Get is the live definition by name (a bundled one always wins), or nil.
func (d *Definitions) Get(name string) *profile.AgentDefinition {
	if name == "" {
		return nil
	}
	if b, ok := d.bundled[name]; ok {
		return &b
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if v := d.reg.Version(); v != d.ver {
		d.ver, d.parsed = v, map[string]*profile.AgentDefinition{}
	}
	if p, ok := d.parsed[name]; ok {
		return p
	}
	def, ok := d.reg.Get(name)
	if !ok {
		return nil
	}
	pd, err := profile.Parse(def.Raw)
	if err != nil {
		return nil // FromRecords already shows a row that does not parse as rejected
	}
	d.parsed[name] = &pd
	return &pd
}

// Owners is each live definition's owner group, by name.
func (d *Definitions) Owners() map[string]string {
	out := map[string]string{}
	for _, n := range d.Names() {
		if def := d.Get(n); def != nil && def.HasOwner {
			out[n] = def.Owner
		}
	}
	return out
}

// DefinitionView is one definition as served (api.py _definition_view, without the gateway's hold): what it is
// for, where it runs, its identity, owner, tier ceiling, tools, limits, scope, triggers and runtime, and its source.
type DefinitionView struct {
	Name         string                  `json:"name"`
	Description  *string                 `json:"description"`
	Kind         string                  `json:"kind"`
	RunsIn       string                  `json:"runsIn"`
	Owner        *string                 `json:"owner"`
	Identity     DefinitionIdentity      `json:"identity"`
	TierCeiling  string                  `json:"tierCeiling"`
	Tools        []string                `json:"tools"`
	Models       []string                `json:"models"`
	Limits       DefinitionLimits        `json:"limits"`
	Network      string                  `json:"network"`
	Compute      string                  `json:"compute"`
	Repos        DefinitionRepos         `json:"repos"`
	Triggers     []map[string]any        `json:"triggers"`
	Runtime      DefinitionRuntime       `json:"runtime"`
	Scopes       map[string]any          `json:"scopes"`
	Source       *definitions.SourceView `json:"source"`
	Instructions any                     `json:"instructions,omitempty"` // auditors with full=1: the text, or null
}

// DefinitionIdentity is a definition's identity.
type DefinitionIdentity struct {
	Type           string  `json:"type"`
	ServiceAccount *string `json:"serviceAccount"`
}

// DefinitionLimits are a definition's budgets.
type DefinitionLimits struct {
	TTLMinutes  int64 `json:"ttl_minutes"`
	ToolCalls   int64 `json:"tool_calls"`
	GithubCalls int64 `json:"github_calls"`
	OpenPRs     int64 `json:"open_prs"`
	ModelTokens int64 `json:"model_tokens"`
	Children    int64 `json:"children"`
}

// DefinitionRepos is a definition's repo allowlist.
type DefinitionRepos struct {
	Allow []string `json:"allow"`
}

// DefinitionRuntime is how an in-cluster run of it runs (image null: a person's client runs it).
type DefinitionRuntime struct {
	Framework string  `json:"framework"`
	Sandbox   string  `json:"sandbox"`
	Image     *string `json:"image"`
}

// DefinitionList is GET /v1/definitions: the live definitions and the pins that did not load.
type DefinitionList struct {
	Items    []DefinitionView           `json:"items"`
	Rejected []definitions.RejectedView `json:"rejected"`
}

func optional(s string, set bool) *string {
	if !set || s == "" {
		return nil
	}
	return &s
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// View is the definition named, as served.
func (d *Definitions) View(name string, full bool) (DefinitionView, bool) {
	def := d.Get(name)
	if def == nil {
		return DefinitionView{}, false
	}
	l := def.Limits
	v := DefinitionView{Name: def.Name, Description: optional(def.Description, true), Kind: def.Kind,
		RunsIn: def.RunsIn(), Owner: optional(def.Owner, def.HasOwner),
		Identity:    DefinitionIdentity{Type: def.IdentityType, ServiceAccount: optional(def.ServiceAccount, true)},
		TierCeiling: tierName(l.TierCeiling), Tools: nonNilStrings(l.Tools), Models: nonNilStrings(l.Models),
		Limits: DefinitionLimits{TTLMinutes: l.TTLMinutes, ToolCalls: l.ToolCalls, GithubCalls: l.GithubCalls,
			OpenPRs: l.OpenPRs, ModelTokens: l.ModelTokens, Children: l.Children},
		Network: l.Network.Label(), Compute: l.Compute.String(),
		Repos:    DefinitionRepos{Allow: nonNilStrings(def.ReposAllow)},
		Triggers: def.Triggers,
		Runtime:  DefinitionRuntime{Framework: def.Framework, Sandbox: def.Sandbox, Image: optional(def.Image, true)},
		Scopes:   map[string]any{},
	}
	if v.Triggers == nil {
		v.Triggers = []map[string]any{}
	}
	for _, k := range vocab.Get().ProfileSections {
		if s, ok := def.RawProfile[k]; ok {
			v.Scopes[k] = s
		}
	}
	if src, ok := d.reg.Source(name); ok {
		sv := src.View()
		v.Source = &sv
	}
	if full {
		v.Instructions = json.RawMessage("null")
		if def.HasInstructions {
			v.Instructions = def.Instructions
		}
	}
	return v, true
}

func (s *Server) listDefinitions(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	full := v.All() && q["full"] == "1"
	out := DefinitionList{Items: []DefinitionView{}, Rejected: []definitions.RejectedView{}}
	if d := s.opt.Definitions; d != nil {
		for _, n := range d.Names() {
			if dv, ok := d.View(n, full); ok {
				out.Items = append(out.Items, dv)
			}
		}
		for _, rj := range d.reg.Rejected() {
			out.Rejected = append(out.Rejected, rj.View())
		}
	}
	writeJSON(w, 200, out)
}
