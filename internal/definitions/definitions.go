// Package definitions is the live set of agent definitions (Autopilot M4): the platform's bundled definitions plus
// the ones pinned on the cluster by an Agent XR, ported from definitions.py.
//
// A pin becomes a definition only if its file's name is the XR's name, its owner the XR's spec.owner, a workload
// identity is autopilot-runs/<name>, and the name is not a bundled one (FromPin). The Registry swaps the whole
// cluster set at once and says what changed, so the core records definition.load / definition.unload /
// definition.reject once per change, never once per poll (Service.Apply).
//
// Parsing a document (profile.parse: the agent-definition JSON schema, then the typed fields) is not this
// package's: a Parser is injected (R-1a ports profile.py with the policy engine).
package definitions

import (
	"errors"
	"fmt"
	"github.com/jfillman/clearance/internal/vocab"
	"slices"
	"sort"
	"sync"

	"github.com/jfillman/clearance/internal/pycompat"
)

// RunIdentityNamespace is where a workload agent's service account lives (definitions.RUN_IDENTITY_NAMESPACE): the
// deployment's (vocab, CLEARANCE_RUN_IDENTITY_NAMESPACE).
func RunIdentityNamespace() string { return vocab.Get().RunIdentityNamespace }

// Tier names, T0..T3, as tiers.Tier.name.
var TierNames = [...]string{"T0", "T1", "T2", "T3"}

// Definition is a parsed agent definition: the fields of profile.AgentDefinition the gate, review and provenance
// read. Raw is the document it was parsed from.
type Definition struct {
	Name         string
	Description  string
	Kind         string
	Owner        string
	HasOwner     bool // the document names an owner (Python's owner is not None)
	IdentityType string
	// ServiceAccount is "<ns>/<name>" for a workload identity ("" when none).
	ServiceAccount string
	TierCeiling    int
	// Tools are the granted tools (profile.tools, plus human.request.get with human.request).
	Tools []string
	// Models are profile.models.
	Models     []string
	ReposAllow []string
	// DenyPaths are the baseline denies plus the definition's own (profile.BASELINE_DENY_PATHS + repos.denyPaths).
	DenyPaths []string
	Image     string
	Raw       map[string]any
}

// Parser is profile.parse: schema-validate a document and read it. The error's text is what DF-SCHEMA and a
// rejected pin's reason ("schema: ...") show.
type Parser func(doc map[string]any) (Definition, error)

// Source is where a definition came from: "bundled" (the core's own CLEARANCE_AGENTS_DIR), "cluster" (an Agent XR's
// pin) or "provider" (a definition the provider enforces that ships with it, published by name and version: the
// gateway image's agents/ directory; there is no repository pin to name).
type Source struct {
	Kind      string
	Repo      *string
	Path      *string
	Commit    *string
	Namespace *string
	XR        *string
	LoadedAt  *string
	// Provider and Version name the publishing provider and the build its definition ships in (kind provider).
	Provider *string
	Version  *string
}

// Str is a convenience for a Source's optional fields.
func Str(s string) *string { return &s }

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func eqp(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// Equal is the dataclass equality of two sources.
func (s Source) Equal(o Source) bool {
	return s.Kind == o.Kind && eqp(s.Repo, o.Repo) && eqp(s.Path, o.Path) && eqp(s.Commit, o.Commit) &&
		eqp(s.Namespace, o.Namespace) && eqp(s.XR, o.XR) && eqp(s.LoadedAt, o.LoadedAt) &&
		eqp(s.Provider, o.Provider) && eqp(s.Version, o.Version)
}

// Pin is one line: "repo@short path", "provider:<name>@<version>", or "bundled".
func (s Source) Pin() string {
	switch s.Kind {
	case "provider":
		return fmt.Sprintf("provider:%s@%s", deref(s.Provider), deref(s.Version))
	case "cluster":
	default:
		return "bundled"
	}
	return fmt.Sprintf("%s@%s %s", pycompat.Str(strOrNone(s.Repo)), pycompat.Truncate(deref(s.Commit), 7), pycompat.Str(strOrNone(s.Path)))
}

func strOrNone(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// SourceView is Source.view(): kind, the fields that are set, and the pin, in that order.
type SourceView struct {
	Kind      string  `json:"kind"`
	Repo      *string `json:"repo,omitempty"`
	Path      *string `json:"path,omitempty"`
	Commit    *string `json:"commit,omitempty"`
	Namespace *string `json:"namespace,omitempty"`
	XR        *string `json:"xr,omitempty"`
	LoadedAt  *string `json:"loaded_at,omitempty"`
	Provider  *string `json:"provider,omitempty"`
	Version   *string `json:"version,omitempty"`
	Pin       string  `json:"pin"`
}

// View is Source.view().
func (s Source) View() SourceView {
	return SourceView{s.Kind, s.Repo, s.Path, s.Commit, s.Namespace, s.XR, s.LoadedAt, s.Provider, s.Version, s.Pin()}
}

// SourceFromView is Source.from_view (kind defaults to "cluster").
func SourceFromView(v map[string]any) Source {
	get := func(k string) *string {
		if s, ok := v[k].(string); ok {
			return &s
		}
		return nil
	}
	kind := "cluster"
	if k, ok := v["kind"].(string); ok {
		kind = k
	}
	return Source{Kind: kind, Repo: get("repo"), Path: get("path"), Commit: get("commit"), Namespace: get("namespace"),
		XR: get("xr"), LoadedAt: get("loaded_at"), Provider: get("provider"), Version: get("version")}
}

// Loaded is a pin that became a definition, with the document it was parsed from (kept for the read API).
type Loaded struct {
	Definition Definition
	Source     Source
	Doc        map[string]any
}

// Name is the definition's name.
func (l Loaded) Name() string { return l.Definition.Name }

// Rejected is a pin that did not become a definition, and why.
type Rejected struct {
	Name   string
	Source Source
	Reason string
}

// Equal is the dataclass equality.
func (r Rejected) Equal(o Rejected) bool {
	return r.Name == o.Name && r.Reason == o.Reason && r.Source.Equal(o.Source)
}

// RejectedView is Rejected.view().
type RejectedView struct {
	Name   string     `json:"name"`
	Source SourceView `json:"source"`
	Reason string     `json:"reason"`
}

// View is Rejected.view().
func (r Rejected) View() RejectedView { return RejectedView{r.Name, r.Source.View(), r.Reason} }

// Changes is what one ReplaceCluster changed. Empty means the poll found the same set as before.
type Changes struct {
	Added, Changed, Removed []string
	Rejected                []Rejected // rejections that were not there before
	Cleared                 []Rejected // rejections that are gone
	Sources                 map[string]Source
}

// Any is bool(Changes).
func (c Changes) Any() bool {
	return len(c.Added)+len(c.Changed)+len(c.Removed)+len(c.Rejected)+len(c.Cleared) > 0
}

// FromPin decides one pin. doc is the fetched file parsed as YAML; source.XR is the XR's name; owner its
// spec.owner; reserved says whether a name is a bundled definition's. Never fails: a bad pin is a Rejected.
func FromPin(doc any, source Source, owner string, reserved func(string) bool, parse Parser) (*Loaded, *Rejected) {
	name := "?"
	if source.XR != nil {
		name = *source.XR
	}
	if name == "" {
		name = "?"
	}
	m, ok := doc.(map[string]any)
	if !ok {
		return nil, &Rejected{name, source, "the pinned file is not a YAML mapping (an agent definition)"}
	}
	d, err := parse(m)
	if err != nil {
		return nil, &Rejected{name, source, "schema: " + err.Error()}
	}
	if d.Name != name {
		return nil, &Rejected{name, source, fmt.Sprintf("the file's name is %s; a pin named %s must pin a definition named %s",
			pycompat.Repr(d.Name), pycompat.Repr(name), pycompat.Repr(name))}
	}
	if !d.HasOwner || d.Owner != owner {
		return nil, &Rejected{name, source, fmt.Sprintf("the file's owner is %s; the pin's owner is %s: they must agree",
			ownerRepr(d), pycompat.Repr(owner))}
	}
	if d.IdentityType == "workload" && d.ServiceAccount != RunIdentityNamespace()+"/"+d.Name {
		return nil, &Rejected{name, source, fmt.Sprintf("a pinned agent's workload identity is %s/%s, not %s",
			RunIdentityNamespace(), d.Name, saRepr(d))}
	}
	if reserved != nil && reserved(name) {
		return nil, &Rejected{name, source, fmt.Sprintf("%s is a bundled platform definition; a pin cannot replace it", pycompat.Repr(name))}
	}
	return &Loaded{d, source, m}, nil
}

// FromProvided decides one definition the provider publishes as shipping with it (Source kind provider, name and
// version). The same schema as a pin's, and the file's name is the one published; there is no XR, so no owner or
// identity rule beyond the schema: the provider enforces its own definitions, the core only needs to know them.
// Never fails: a bad one is a Rejected.
func FromProvided(doc any, name string, source Source, parse Parser) (*Loaded, *Rejected) {
	m, ok := doc.(map[string]any)
	if !ok {
		return nil, &Rejected{name, source, "the definition is not a mapping"}
	}
	d, err := parse(m)
	if err != nil {
		return nil, &Rejected{name, source, "schema: " + err.Error()}
	}
	if d.Name != name {
		return nil, &Rejected{name, source, fmt.Sprintf("the document's name is %s; it is published as %s",
			pycompat.Repr(d.Name), pycompat.Repr(name))}
	}
	return &Loaded{d, source, m}, nil
}

func ownerRepr(d Definition) string {
	if !d.HasOwner {
		return "None"
	}
	return pycompat.Repr(d.Owner)
}

func saRepr(d Definition) string {
	if d.ServiceAccount == "" {
		return "None"
	}
	return pycompat.Repr(d.ServiceAccount)
}

// Registry is the live set: bundled definitions, then cluster definitions, by name (definitions.Definitions).
// Reads take a read lock on the current snapshot; ReplaceCluster swaps it whole.
type Registry struct {
	mu       sync.RWMutex
	bundled  map[string]Definition
	cluster  []Loaded // sorted by insertion, as Python's dict
	rejected []Rejected
	version  int
}

// NewRegistry holds the bundled definitions.
func NewRegistry(bundled map[string]Definition) *Registry {
	b := make(map[string]Definition, len(bundled))
	for k, v := range bundled {
		b[k] = v
	}
	return &Registry{bundled: b}
}

// Get is the definition by name: a bundled one always wins.
func (r *Registry) Get(name string) (Definition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if d, ok := r.bundled[name]; ok {
		return d, true
	}
	for _, l := range r.cluster {
		if l.Name() == name {
			return l.Definition, true
		}
	}
	return Definition{}, false
}

// Bundled reports whether name is a bundled definition.
func (r *Registry) Bundled(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.bundled[name]
	return ok
}

// Len is the number of live definitions.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := len(r.bundled)
	for _, l := range r.cluster {
		if _, ok := r.bundled[l.Name()]; !ok {
			n++
		}
	}
	return n
}

// Version bumps on every change.
func (r *Registry) Version() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version
}

// keepProvided adds the provider-kind definitions and rejections the registry holds to a publish that did not
// carry its provider set (an older provider), so that publish does not unload them. r.mu is held.
func (r *Registry) keepProvided(loaded []Loaded, rejected []Rejected) ([]Loaded, []Rejected) {
	loaded, rejected = append([]Loaded(nil), loaded...), append([]Rejected(nil), rejected...)
	for _, l := range r.cluster {
		if l.Source.Kind == "provider" {
			loaded = append(loaded, l)
		}
	}
	for _, x := range r.rejected {
		if x.Source.Kind == "provider" {
			rejected = append(rejected, x)
		}
	}
	return loaded, rejected
}

// Rejected is the current rejections.
func (r *Registry) Rejected() []Rejected {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Rejected(nil), r.rejected...)
}

// Source is where a live definition came from, if it is live.
func (r *Registry) Source(name string) (Source, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, l := range r.cluster {
		if l.Name() == name {
			return l.Source, true
		}
	}
	if _, ok := r.bundled[name]; ok {
		return Source{Kind: "bundled"}, true
	}
	return Source{}, false
}

// Row is one store row (Definitions.records()).
type Row struct {
	Name   string         `json:"name"`
	State  string         `json:"state"`
	Source SourceView     `json:"source"`
	Doc    map[string]any `json:"doc,omitempty"`
	Reason *string        `json:"reason,omitempty"`
}

// Records is the cluster set as rows for the store: loaded ones (by name) with their document, then rejected ones.
func (r *Registry) Records() []Row {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return records(r.cluster, r.rejected)
}

func records(cluster []Loaded, rejected []Rejected) []Row {
	ls := append([]Loaded(nil), cluster...)
	sort.SliceStable(ls, func(i, j int) bool { return ls[i].Name() < ls[j].Name() })
	out := make([]Row, 0, len(ls)+len(rejected))
	for _, l := range ls {
		doc := l.Doc
		if doc == nil {
			doc = map[string]any{}
		}
		out = append(out, Row{Name: l.Name(), State: "loaded", Source: l.Source.View(), Doc: doc})
	}
	for _, j := range rejected {
		reason := j.Reason
		out = append(out, Row{Name: j.Name, State: "rejected", Source: j.Source.View(), Reason: &reason})
	}
	return out
}

// plan is a computed swap: the next cluster set and what it changes.
type plan struct {
	cluster  []Loaded
	rejected []Rejected
	changes  Changes
}

func (r *Registry) plan(loaded []Loaded, rejected []Rejected) plan {
	// A provider's own definition is never shadowed by a pin: the pin is rejected, the provider's loads.
	provided := map[string]Source{}
	for _, l := range loaded {
		if l.Source.Kind == "provider" {
			provided[l.Name()] = l.Source
		}
	}
	rejected = append([]Rejected(nil), rejected...)
	if len(provided) > 0 {
		kept := make([]Loaded, 0, len(loaded))
		for _, l := range loaded {
			if ps, ok := provided[l.Name()]; ok && l.Source.Kind != "provider" {
				rejected = append(rejected, Rejected{l.Name(), l.Source, fmt.Sprintf("%s is a definition provided by %s; a pin cannot replace it",
					pycompat.Repr(l.Name()), deref(ps.Provider))})
				continue
			}
			kept = append(kept, l)
		}
		loaded = kept
	}
	byName := map[string]Loaded{}
	var order []string
	dupes := map[string]bool{}
	for _, l := range loaded {
		if _, ok := byName[l.Name()]; ok {
			dupes[l.Name()] = true
		} else {
			order = append(order, l.Name())
		}
		byName[l.Name()] = l
	}
	rej := append([]Rejected(nil), rejected...)
	for _, l := range loaded {
		if dupes[l.Name()] {
			rej = append(rej, Rejected{l.Name(), l.Source, fmt.Sprintf("two pins name the agent %s; neither is loaded", pycompat.Repr(l.Name()))})
		}
	}
	var next []Loaded
	for _, n := range order {
		if dupes[n] {
			continue
		}
		if _, ok := r.bundled[n]; ok {
			rej = append(rej, Rejected{n, byName[n].Source, fmt.Sprintf("%s is a bundled platform definition; a pin cannot replace it", pycompat.Repr(n))})
			continue
		}
		next = append(next, byName[n])
	}
	// dict.fromkeys(rej): drop exact duplicates keeping the first, then sort by (name, reason).
	var uniq []Rejected
	for _, x := range rej {
		seen := false
		for _, y := range uniq {
			if x.Equal(y) {
				seen = true
				break
			}
		}
		if !seen {
			uniq = append(uniq, x)
		}
	}
	sort.SliceStable(uniq, func(i, j int) bool {
		if uniq[i].Name != uniq[j].Name {
			return uniq[i].Name < uniq[j].Name
		}
		return uniq[i].Reason < uniq[j].Reason
	})
	ch := Changes{Sources: map[string]Source{}}
	old := map[string]Loaded{}
	for _, l := range r.cluster {
		old[l.Name()] = l
	}
	nextNames := map[string]bool{}
	for _, l := range next {
		nextNames[l.Name()] = true
		o, ok := old[l.Name()]
		switch {
		case !ok:
			ch.Added = append(ch.Added, l.Name())
		case deref(o.Source.Commit) != deref(l.Source.Commit) || (o.Source.Commit == nil) != (l.Source.Commit == nil) ||
			deref(o.Source.Version) != deref(l.Source.Version) || o.Source.Kind != l.Source.Kind ||
			!pycompat.Equal(anyDoc(o.Doc), anyDoc(l.Doc)):
			ch.Changed = append(ch.Changed, l.Name())
		}
	}
	for _, l := range r.cluster {
		if !nextNames[l.Name()] {
			ch.Removed = append(ch.Removed, l.Name())
			ch.Sources[l.Name()] = l.Source
		}
	}
	for _, x := range uniq {
		if !containsRejected(r.rejected, x) {
			ch.Rejected = append(ch.Rejected, x)
		}
	}
	for _, x := range r.rejected {
		if !containsRejected(uniq, x) {
			ch.Cleared = append(ch.Cleared, x)
		}
	}
	for _, l := range next {
		if slices.Contains(ch.Added, l.Name()) || slices.Contains(ch.Changed, l.Name()) {
			ch.Sources[l.Name()] = l.Source
		}
	}
	return plan{next, uniq, ch}
}

func anyDoc(m map[string]any) any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func containsRejected(list []Rejected, x Rejected) bool {
	for _, y := range list {
		if x.Equal(y) {
			return true
		}
	}
	return false
}

func (r *Registry) commit(p plan) {
	r.cluster, r.rejected = p.cluster, p.rejected
	r.version++
}

// ReplaceCluster makes loaded + rejected the cluster set. A name that appears twice in loaded is a rejection of
// both. Returns what changed.
func (r *Registry) ReplaceCluster(loaded []Loaded, rejected []Rejected) Changes {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.plan(loaded, rejected)
	if p.changes.Any() {
		r.commit(p)
	}
	return p.changes
}

// ApplyRecords rebuilds the cluster set from the store's rows (the read API's side). A row whose document no longer
// parses is shown as rejected, not dropped.
func (r *Registry) ApplyRecords(rows []map[string]any, parse Parser) Changes {
	loaded, rejected := FromRecords(rows, parse)
	return r.ReplaceCluster(loaded, rejected)
}

// FromRecords reads store rows into loaded and rejected pins.
func FromRecords(rows []map[string]any, parse Parser) ([]Loaded, []Rejected) {
	var loaded []Loaded
	var rejected []Rejected
	for _, row := range rows {
		srcView, _ := row["source"].(map[string]any)
		src := SourceFromView(srcView)
		name := "?"
		if n, ok := row["name"].(string); ok {
			name = n
		}
		if row["state"] == "loaded" {
			raw, present := row["doc"]
			doc, isMap := raw.(map[string]any)
			switch {
			case !present:
				rejected = append(rejected, Rejected{name, src, "stored definition no longer parses: 'doc'"})
			case !isMap:
				rejected = append(rejected, Rejected{name, src, "stored definition no longer parses: the document is not a mapping"})
			default:
				d, err := parse(doc)
				if err != nil {
					rejected = append(rejected, Rejected{name, src, "stored definition no longer parses: " + err.Error()})
				} else {
					loaded = append(loaded, Loaded{d, src, doc})
				}
			}
			continue
		}
		reason := "rejected"
		if v, ok := row["reason"]; ok {
			reason = pycompat.Str(v)
		}
		rejected = append(rejected, Rejected{name, src, reason})
	}
	return loaded, rejected
}

// ErrNotRegistry is apply_cluster_definitions' TypeError: the core holds no Registry.
var ErrNotRegistry = errors.New("cluster definitions need a definitions.Registry")
