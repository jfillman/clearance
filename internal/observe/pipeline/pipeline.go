// Package pipeline is the observation pipeline (O-2): raw events from a collector in, assessments, change
// transactions and exceptions out, in six stages.
//
//	Normalize  flatten the event, canonicalize the stored object                  (event.go)
//	Scope      keep writes in governed clusters, namespaces, accounts, kinds; count the rest
//	Noise      drop legitimate controller writes: one exact identity paired with the exact shape it may touch
//	Attribute  tie what survives to an authorization, strongest signal first, per provider
//	Classify   map the outcome to a coverage state and a tier
//	Correlate  collapse bursts into one change transaction; fold an apply-and-revert into one exception
//
// Every stage but Normalize and Correlate is a rule set compiled once at bundle load (ruleset.go) with a cost limit:
// the rules are CEL, and the bundle that carries them is versioned and named in every assessment. The pipeline reads
// no cluster and calls no API: what it knows about grants, break-glass, attestations and plans it asks a Lookups,
// which the collectors (O-3, O-4) back with the record store. docs/observe-pipeline.md is the contract.
package pipeline

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/jfillman/clearance/internal/gate/render"
	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/vocab"
)

// Assessment is what the pipeline made of one event that survived scope and noise.
type Assessment struct {
	EventID    string     `json:"event_id"`
	Provider   string     `json:"provider"`
	Scope      string     `json:"scope"`
	Time       time.Time  `json:"time"`
	Resource   string     `json:"resource"`
	Verb       string     `json:"verb"`
	Succeeded  bool       `json:"succeeded"`
	Actor      string     `json:"actor"`
	ActorQuote string     `json:"actor_quoted,omitempty"` // the actor the record quotes (AWS sourceIdentity)
	Outcome    string     `json:"outcome"`
	Coverage   string     `json:"coverage"`
	Tier       int        `json:"tier"`
	Severity   string     `json:"severity"`
	Signal     string     `json:"signal"`
	Confidence string     `json:"confidence,omitempty"`
	Detail     string     `json:"detail"`
	Grant      string     `json:"grant,omitempty"`
	Monitoring bool       `json:"monitoring,omitempty"`
	Diff       []string   `json:"diff,omitempty"`
	BeforeHash string     `json:"before_hash,omitempty"`
	AfterHash  string     `json:"after_hash,omitempty"`
	RuleSet    RuleSetRef `json:"rule_set"`

	ev *Event
}

// Disposition says what became of one event.
type Disposition string

const (
	Assessed   Disposition = "assessed"
	Filtered   Disposition = "filtered"
	OutOfScope Disposition = "out-of-scope"
	NotWrite   Disposition = "not-a-write"
)

// Alert is what a tier 3 observation raises the moment it is seen: the operation on monitoring, and the health the
// scope's feed flips to. A sink must not block.
type Alert struct {
	Scope      string      `json:"scope"`
	Assessment *Assessment `json:"assessment"`
	Health     string      `json:"health"` // blind when the operation succeeded, degraded when it was refused
	Check      string      `json:"check"`
	Detail     string      `json:"detail"`
}

// Stats are the counters the packet's "filtered: N events under rule X" and the coverage population are built from.
type Stats struct {
	Events     int            `json:"events"`
	Assessed   int            `json:"assessed"`
	NotWrites  int            `json:"not_writes"`
	Filtered   map[string]int `json:"filtered"`     // by noise rule
	OutOfScope map[string]int `json:"out_of_scope"` // by scope (cluster or account)
}

// FilteredCount is one noise rule's count, as the packet prints it.
type FilteredCount struct {
	Rule    string `json:"rule"`
	Count   int    `json:"count"`
	RuleSet string `json:"rule_set"` // "<name>@<version>"
	Why     string `json:"why,omitempty"`
}

// Pipeline is the stages bound to a rule set and to the lookups that back attribution. Safe for concurrent use.
type Pipeline struct {
	rs    *RuleSet
	lk    Lookups
	vocab vocab.Vocabulary

	// OnAlert is called, under the pipeline's lock and before Process returns, for each operation on monitoring.
	OnAlert func(Alert)

	mu     sync.Mutex
	stats  Stats
	health map[string]string
	corr   *Correlator
}

// New binds a rule set. lk may be nil: nothing is then known to the pipeline, so nothing is cleared.
func New(rs *RuleSet, lk Lookups, v vocab.Vocabulary) *Pipeline {
	if lk == nil {
		lk = StaticLookups{}
	}
	return &Pipeline{rs: rs, lk: lk, vocab: v, health: map[string]string{}, corr: newCorrelator(rs),
		stats: Stats{Filtered: map[string]int{}, OutOfScope: map[string]int{}}}
}

// RuleSet is the rule set in force.
func (p *Pipeline) RuleSet() RuleSetRef { return p.rs.Ref }

// Process runs one raw event through the stages. The returned assessment is nil unless the disposition is Assessed;
// for Filtered, detail is the noise rule's name.
func (p *Pipeline) Process(raw RawEvent) (*Assessment, Disposition, string, error) {
	ev, err := p.rs.Normalize(raw)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats.Events++
	if err == ErrSkip {
		p.stats.NotWrites++
		return nil, NotWrite, "", nil
	}
	if err != nil {
		return nil, "", "", err
	}
	ev.Monitoring = p.monitoring(ev)
	if !p.inScope(ev) {
		p.stats.OutOfScope[ev.Scope]++
		return nil, OutOfScope, ev.Scope, nil
	}
	if !ev.Monitoring {
		if rule := p.noise(ev); rule != "" {
			p.stats.Filtered[rule]++
			return nil, Filtered, rule, nil
		}
	}
	a, err := p.attribute(ev)
	if err != nil {
		return nil, "", "", err
	}
	p.stats.Assessed++
	p.corr.Add(a)
	if a.Monitoring {
		p.flip(a)
	}
	return a, Assessed, "", nil
}

// Stats is a copy of the counters.
func (p *Pipeline) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stats
	s.Filtered, s.OutOfScope = cloneMap(p.stats.Filtered), cloneMap(p.stats.OutOfScope)
	return s
}

func cloneMap(m map[string]int) map[string]int {
	o := make(map[string]int, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

// FilteredCounts are the per-rule filtered counts, most filtered first, each with the rule set it was under.
func (p *Pipeline) FilteredCounts() []FilteredCount {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.filteredCounts()
}

func (p *Pipeline) filteredCounts() []FilteredCount {
	var out []FilteredCount
	why := map[string]string{}
	for _, r := range p.rs.noise {
		why[r.name] = r.why
	}
	for rule, n := range p.stats.Filtered {
		out = append(out, FilteredCount{rule, n, p.rs.Ref.Name + "@" + p.rs.Ref.Version, why[rule]})
	}
	slices.SortFunc(out, func(a, b FilteredCount) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.Rule, b.Rule)
	})
	return out
}

// FilteredLine is the line the packet prints for one rule: "filtered: N events under rule X".
func (f FilteredCount) Line() string {
	return fmt.Sprintf("filtered: %d events under rule %s (%s)", f.Count, f.Rule, f.RuleSet)
}

// Health is a scope's feed health as the pipeline's own observations have left it (healthy until an operation on
// monitoring flips it). Only Healthy, the provider's own next healthy record, clears a flip.
func (p *Pipeline) Health(scope string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h, ok := p.health[scope]; ok {
		return h
	}
	return observe.Healthy
}

// Healthy records the provider's next healthy health record for the scope.
func (p *Pipeline) Healthy(scope string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.health, scope)
}

func (p *Pipeline) flip(a *Assessment) {
	state := observe.Degraded
	if a.Succeeded {
		state = observe.Blind
	}
	if observe.Rank(state) > observe.Rank(p.health[a.Scope]) || p.health[a.Scope] == "" {
		p.health[a.Scope] = state
	}
	if p.OnAlert != nil {
		p.OnAlert(Alert{Scope: a.Scope, Assessment: a, Health: state, Check: "monitoring-protection",
			Detail: fmt.Sprintf("%s %s by %s (succeeded: %t)", a.Verb, a.Resource, a.Actor, a.Succeeded)})
	}
}

// Flush finishes the correlation of everything seen and returns the transactions and exceptions.
func (p *Pipeline) Flush() ([]Transaction, []Exception) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.corr.Flush()
}

// ---- monitoring --------------------------------------------------------------------------------------------------

func (p *Pipeline) monitoring(e *Event) bool {
	if observe.Monitoring(p.vocab, e.Provider, e.API) {
		return true
	}
	m := p.rs.monitoring
	if e.Provider == Kubernetes {
		if slices.Contains(m.Kubernetes, e.Kind) {
			return true
		}
		return e.Kind == "ConfigMap" && slices.Contains(m.ConfigMaps, e.Namespace+"/"+e.Name)
	}
	// A cloud's operation name (AWS event name, Azure operation, Google method); the Azure and Google lists are for the
	// normalizers those providers get later.
	return pycompat.MatchAny(e.API, m.AWS) || pycompat.MatchAny(e.API, m.Azure) || pycompat.MatchAny(e.API, m.Google)
}

// ---- scope ------------------------------------------------------------------------------------------------------

func (p *Pipeline) inScope(e *Event) bool {
	for _, g := range p.rs.governed {
		if g.Provider != e.Provider || !pycompat.MatchAny(e.Scope, g.Scopes) {
			continue
		}
		if len(g.Namespaces) > 0 && !pycompat.MatchAny(e.Namespace, g.Namespaces) {
			continue
		}
		if len(g.Kinds) > 0 && !slices.Contains(g.Kinds, e.Kind) {
			continue
		}
		if g.when != nil {
			if ok, err := evalBool(g.when, e, nil); err != nil || !ok {
				continue
			}
		}
		return true
	}
	return false
}

// ---- noise ------------------------------------------------------------------------------------------------------

// noise returns the name of the rule that drops e, or "". A refused attempt is never noise (nothing a controller does
// legitimately is refused, and a refusal is what a coverage statement should show), and neither is monitoring.
func (p *Pipeline) noise(e *Event) string {
	if !e.Succeeded {
		return ""
	}
	issuer := ""
	if e.Provider == AWS {
		issuer = e.Issuer
	}
	idx := p.rs.noiseBySub[e.Provider+"\x00"+e.Subject+"\x00"+issuer]
	for _, i := range idx {
		r := &p.rs.noise[i]
		if !slices.Contains(r.kinds, e.Kind) || !slices.Contains(r.verbs, e.Verb) {
			continue
		}
		if len(r.ns) > 0 && !slices.Contains(r.ns, e.Namespace) {
			continue
		}
		if len(r.subresources) > 0 && !slices.Contains(r.subresources, e.Subresource) {
			continue
		}
		if r.when != nil {
			if ok, err := evalBool(r.when, e, nil); err != nil || !ok {
				continue
			}
		}
		return r.name
	}
	return ""
}

// ---- CEL activation ---------------------------------------------------------------------------------------------

func evalBool(prg cel.Program, e *Event, facts map[string]any) (bool, error) {
	if facts == nil {
		facts = map[string]any{}
	}
	out, _, err := prg.Eval(map[string]any{"event": e.celMap(), "facts": facts})
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("the rule's result is %s, not a bool", out.Type().TypeName())
	}
	return b, nil
}

func nz(m map[string]string) map[string]any {
	o := make(map[string]any, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

func (e *Event) celMap() map[string]any {
	owners := make([]any, len(e.Owners))
	for i, o := range e.Owners {
		owners[i] = map[string]any{"kind": o.Kind, "name": o.Name}
	}
	groups := make([]any, len(e.Groups))
	for i, g := range e.Groups {
		groups[i] = g
	}
	return map[string]any{
		"provider": e.Provider, "scope": e.Scope, "namespace": e.Namespace, "kind": e.Kind, "name": e.Name,
		"subresource": e.Subresource, "verb": e.Verb, "api": e.API, "succeeded": e.Succeeded, "code": int64(e.Code),
		"error_code": e.ErrorCode, "resource_id": e.ResourceID, "region": e.Region, "monitoring": e.Monitoring,
		"annotations": nz(e.AuditAnnotations), "obj_annotations": nz(e.ObjAnnotations), "labels": nz(e.Labels), "owners": owners,
		"actor": map[string]any{"subject": e.Subject, "type": e.Type, "issuer": e.Issuer, "source_identity": e.SourceIdentity,
			"session_name": e.SessionName, "user_agent": e.UserAgent, "groups": groups, "impersonated": e.Impersonated, "task_id": e.TaskID},
	}
}

// ---- attribute and classify -------------------------------------------------------------------------------------

func (p *Pipeline) attribute(e *Event) (*Assessment, error) {
	a := &Assessment{EventID: e.ID, Provider: e.Provider, Scope: e.Scope, Time: e.Time, Resource: e.Key(), Verb: e.API,
		Succeeded: e.Succeeded, Actor: e.Subject, BeforeHash: e.BeforeHash, AfterHash: e.AfterHash, Monitoring: e.Monitoring,
		RuleSet: p.rs.Ref, ev: e}
	if e.SourceIdentity != "" {
		a.ActorQuote = e.SourceIdentity
	}
	f := p.facts(e)
	var sig *signal
	for i := range p.rs.attribute[e.Provider] {
		s := &p.rs.attribute[e.Provider][i]
		ok, err := evalBool(s.when, e, f.m)
		if err != nil {
			return nil, fmt.Errorf("attribute %s %s: %w", e.Provider, s.name, err) // a rule over its cost is an error, never a pass
		}
		if ok {
			sig = s
			break
		}
	}
	a.Signal, a.Outcome, a.Severity, a.Confidence, a.Detail = sig.name, sig.outcome, sig.severity, sig.confidence, sig.detail
	a.Grant = f.grant
	if a.Outcome == OutcomeOutOfBand || a.Outcome == OutcomeNotAttributed {
		a.Diff = diff(e)
	}
	if e.Monitoring {
		// An operation on monitoring is tier 3 whether or not it succeeded, whatever signal explains it: the signal
		// is kept (who did it, under which grant), the outcome is not up to a rule.
		a.Outcome, a.Severity = OutcomeMonitoring, "critical"
		a.Detail = "operation on the controls that watch the environment: " + a.Detail
	}
	c := p.rs.classify[a.Outcome]
	a.Coverage, a.Tier = c.Coverage, c.Tier
	return a, nil
}

func diff(e *Event) []string {
	switch {
	case e.After == nil && e.Before == nil:
		return nil
	case e.Before == nil:
		return []string{"created"}
	case e.After == nil:
		return []string{"deleted"}
	}
	d := render.DiffPointers(e.Before, e.After, "")
	if len(d) > 20 {
		d = append(d[:20], fmt.Sprintf("... and %d more", len(d)-20))
	}
	return d
}
