package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/targets"
)

// GET /v1/map: the coverage map in one read. The declared registry (GET /v1/targets) says what should be protected and
// by which gates; the records say what happened. The Map joins them on the server, in a fixed number of aggregate
// queries, so the client makes one call however many gates and targets there are. A mismatch between the two (a
// declared gate that never decided anything, a gate that decided without being declared, a target with no gate) is an
// attention item, never an error.

// Status of a node, an edge or an attention item.
const (
	StatusOK        = "ok"
	StatusAttention = "attention"
	StatusDown      = "down"
)

// MapLimits.
const (
	MaxMapScopes       = 1000
	MaxMapAttention    = 200
	MaxAttentionTarget = 20
	MaxMapChanges      = 20
	MaxMapEvidence     = 10
	healthWindow       = time.Minute
)

const (
	covOutOfBand   = "out-of-band-detected"
	covUnavailable = "coverage-unavailable"
)

// coverageKeys are the six coverage states plus unassessed (an observation no assessment is about yet), in the order
// the Map reports them.
var coverageKeys = append(append([]string{}, evidence.Coverage...), "unassessed")

// Lanes are the stage counts of the change flow, Requested to Verified. Requested, Tiered, Decided and Applied are
// distinct changes counted from the deploy.* records; Observed and Verified are the observations of the scope and the
// ones assessed authorized-and-verified (an observation's coverage), see MapResponse.Partial.
type Lanes struct {
	Requested int64 `json:"requested"`
	Tiered    int64 `json:"tiered"`
	Decided   int64 `json:"decided"`
	Applied   int64 `json:"applied"`
	// AppliedMatched are the applied outcomes whose digest matched what was cleared (deploy.outcome matched).
	AppliedMatched int64 `json:"applied_matched"`
	Observed       int64 `json:"observed"`
	Verified       int64 `json:"verified"`
}

// Tally is what the gate records of a window say of a gate, a gate type, a target or an edge.
type Tally struct {
	// Decisions are the decisions made: the deployment gate's clear, deny and expire, and each runtime decision.
	Decisions int64 `json:"decisions"`
	Refused   int64 `json:"refused"`
	// Exceptions are the deploy.exception and deploy.degraded records (what a gate or observer reported out of band).
	Exceptions int64 `json:"exceptions"`
	// Holding are the changes holding now (not windowed).
	Holding  int64            `json:"holding"`
	Coverage map[string]int64 `json:"coverage"`
	Lanes    Lanes            `json:"lanes"`
}

// Mix is how many of a node's gates are in each mode, and how many were silent (declared, and no record of the window
// names them).
type Mix struct {
	Enforce int `json:"enforce"`
	Flag    int `json:"flag"`
	Silent  int `json:"silent"`
}

// GateTypeNode is a gate type: its declared instances, their modes and what they decided.
type GateTypeNode struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Instances int    `json:"instances"`
	Targets   int    `json:"targets"`
	Mix       Mix    `json:"mix"`
	Status    string `json:"status"`
	Tally
}

// GateRef is a gate that guards a target, with what its records say of the target (Attributed is false when the target
// declares no app: decisions are attributed to a target by app and environment).
type GateRef struct {
	Type       string `json:"type"`
	Instance   string `json:"instance"`
	Mode       string `json:"mode"`
	Attributed bool   `json:"attributed"`
	// Silent: no record of the window names the instance at all.
	Silent bool `json:"silent"`
	Tally
}

// ObserverRef is an observer that watches a target, with the health of its feed in the scope as of the end of the
// window (observe's health logic: the newest record, blind once stale). State is healthy, degraded, blind, or unknown
// (the target declares no scope to read it by).
type ObserverRef struct {
	Provider string   `json:"provider"`
	Source   string   `json:"source"`
	State    string   `json:"state"`
	LastTS   *string  `json:"last_ts"`
	Stale    bool     `json:"stale"`
	Failed   []string `json:"failed_checks"`
}

// TargetNode is a declared target with its metrics.
type TargetNode struct {
	ID        string           `json:"id"`
	Source    string           `json:"source"`
	Name      string           `json:"name"`
	Kind      string           `json:"kind"`
	Group     string           `json:"group"`
	Env       string           `json:"env,omitempty"`
	App       string           `json:"app,omitempty"`
	Owner     string           `json:"owner,omitempty"`
	Registry  string           `json:"registry,omitempty"`
	Scope     string           `json:"scope,omitempty"`
	Status    string           `json:"status"`
	Gates     []GateRef        `json:"gates"`
	Observers []ObserverRef    `json:"observers"`
	Coverage  map[string]int64 `json:"coverage"`
	// VerifiedPct is authorized-and-verified over the assessed observations (null when there are none).
	VerifiedPct *float64 `json:"verified_pct"`
	Lanes       Lanes    `json:"lanes"`
	Holding     int64    `json:"holding"`
}

// GroupNode is the targets of one cluster or account, rolled up; its coverage counts each of its scopes once.
type GroupNode struct {
	ID          string           `json:"id"`
	Group       string           `json:"group"`
	Targets     int              `json:"targets"`
	Kinds       map[string]int   `json:"kinds"`
	Status      string           `json:"status"`
	Mix         Mix              `json:"mix"`
	Coverage    map[string]int64 `json:"coverage"`
	VerifiedPct *float64         `json:"verified_pct"`
	Holding     int64            `json:"holding"`
	Observers   map[string]int   `json:"observers"`
	NoGate      int              `json:"no_gate"`
}

// ObserverNode is an observer (a provider's source) rolled up over the targets it watches.
type ObserverNode struct {
	ID       string         `json:"id"`
	Provider string         `json:"provider"`
	Source   string         `json:"source"`
	Targets  int            `json:"targets"`
	States   map[string]int `json:"states"`
	Status   string         `json:"status"`
}

// MapNodes are the Map's nodes.
type MapNodes struct {
	GateTypes []GateTypeNode `json:"gate_types"`
	Groups    []GroupNode    `json:"groups"`
	Targets   []TargetNode   `json:"targets"`
	Observers []ObserverNode `json:"observers"`
}

// MapEdge joins a gate type (or an observer) to a group of targets (or, when expanded, to one target). Volume is the
// edge's decisions (a watches edge has none), Status its worst state: down for out-of-band or coverage-unavailable
// records or a blind observer, attention for a holding change or a gate in flag mode, else ok.
type MapEdge struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Kind    string `json:"kind"` // guards | watches
	Targets int    `json:"targets"`
	Volume  int64  `json:"volume"`
	Refused int64  `json:"refused"`
	Holding int64  `json:"holding"`
	Status  string `json:"status"`
}

// Attention kinds.
const (
	AttnNoGate     = "no-gate"
	AttnBlind      = "blind-observer"
	AttnDegraded   = "degraded-observer"
	AttnFlag       = "flag-mode"
	AttnHolding    = "holding"
	AttnSilent     = "gate-silent"
	AttnUndeclared = "undeclared-gate"
)

// Attention is one thing the Map says needs a person's eye.
type Attention struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"` // down | attention | info
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Count    int64  `json:"count"`
	// Targets are the targets it is about (at most 20).
	Targets  []string `json:"targets"`
	GateType string   `json:"gate_type,omitempty"`
	Instance string   `json:"instance,omitempty"`
}

// Partial says what the Map could not derive and why: a stage not linked in the records yet, a target the records
// cannot be attributed to.
type Partial struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// MapChange is a change moving through a target (the C10 detail).
type MapChange struct {
	ID         string `json:"id"`
	Tier       int64  `json:"tier"`
	State      string `json:"state"`
	Repo       string `json:"repo"`
	PR         int64  `json:"pr"`
	Owner      string `json:"owner,omitempty"`
	ClearedBy  string `json:"cleared_by,omitempty"`
	UpdatedAt  string `json:"updated_at"`
	AgeSeconds int64  `json:"age_seconds"`
}

// TargetDetail is the C10 detail of one target: who guards it, who watches it, its coverage and lanes (on the node), the
// changes moving through it, its open exceptions and its recent evidence.
type TargetDetail struct {
	Changes    []MapChange `json:"changes"`
	Exceptions []Record    `json:"exceptions"`
	Evidence   []Record    `json:"evidence"`
}

// MapRegistry says what the Map read the declared registry from.
type MapRegistry struct {
	Sources   []TargetSource `json:"sources"`
	Conflicts []string       `json:"conflicts"`
	Targets   int            `json:"targets"`
}

// MapResponse is GET /v1/map.
type MapResponse struct {
	From      string        `json:"from"`
	To        string        `json:"to"`
	Registry  MapRegistry   `json:"registry"`
	Nodes     MapNodes      `json:"nodes"`
	Edges     []MapEdge     `json:"edges"`
	Attention []Attention   `json:"attention"`
	Partial   []Partial     `json:"partial"`
	Truncated bool          `json:"truncated"`
	Target    *TargetDetail `json:"target,omitempty"`
}

func newTally() Tally {
	c := map[string]int64{}
	for _, k := range evidence.Coverage {
		c[k] = 0
	}
	return Tally{Coverage: c}
}

// windowOf is the window of a statement-like read: to (default now, never later), from (default 24 hours before),
// at most 92 days.
func windowOf(q map[string]string, now time.Time) (from, to time.Time, aerr *apiError) {
	var err error
	to = now
	if x := q["to"]; x != "" {
		if to, err = time.Parse(time.RFC3339, x); err != nil {
			return from, to, errorf(400, "to is an RFC 3339 time")
		}
	}
	if x := q["from"]; x != "" {
		if from, err = time.Parse(time.RFC3339, x); err != nil {
			return from, to, errorf(400, "from is an RFC 3339 time")
		}
	} else {
		from = to.Add(-DefaultCoverageWindow)
	}
	to, from = to.UTC(), from.UTC()
	if to.After(now) {
		to = now
	}
	switch {
	case !from.Before(to):
		return from, to, errorf(400, "from is before to (and before now)")
	case to.Sub(from) > MaxCoverageWindow:
		return from, to, errorf(400, "the window is at most 92 days")
	}
	return from, to, nil
}

// mapBuild is one request's working state.
type mapBuild struct {
	rows    []GateRow
	byInst  map[string][]int // instance name -> the rows that name it (as provider or registrant)
	scopes  map[string]scopeTally
	health  map[string]map[string]observe.SourceHealth // scope -> source -> health
	holding []HoldRow
}

type scopeTally struct {
	observed int64
	mix      map[string]int64 // coverage -> assessed observations
}

func (b *mapBuild) instanceRows(inst string) []int { return b.byInst[inst] }

// rowTally adds the records of the rows chosen (once each) to t.
func (b *mapBuild) add(t *Tally, idx []int, seen map[int]bool) {
	for _, i := range idx {
		if seen != nil {
			if seen[i] {
				continue
			}
			seen[i] = true
		}
		g := b.rows[i]
		t.Coverage[g.Coverage] += g.Count
		switch g.Tool {
		case "deploy.request":
			t.Lanes.Requested += g.Changes
			t.Lanes.Tiered += g.Changes // the tier is decided at registration: every request carries one
		case "deploy.clear", "deploy.deny", "deploy.expire":
			t.Lanes.Decided += g.Changes
			t.Decisions += g.Count
		case "deploy.outcome":
			if g.Applied != "false" {
				t.Lanes.Applied += g.Changes
				if g.Matched == "true" {
					t.Lanes.AppliedMatched += g.Changes
				}
			}
		case "deploy.exception", "deploy.degraded":
			t.Exceptions += g.Count
		default:
			if g.Boundary == "runtime" {
				t.Decisions += g.Count
			}
		}
		if (g.Decision == "deny" && g.Tool != "deploy.expire") || g.Coverage == evidence.CoverageAttemptedRefused {
			t.Refused += g.Count
		}
	}
}

// attributable says whether a gate row is about the target: its application and, when both name one, its environment.
func attributable(g GateRow, t *targets.Target) bool {
	if t.App == "" || g.Boundary != "deployment" || g.App != t.App {
		return false
	}
	return t.Env == "" || g.Env == "" || g.Env == t.Env
}

func (s *Server) getMap(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	now := s.opt.Clock().UTC()
	from, to, aerr := windowOf(q, now)
	if aerr != nil {
		aerr.write(w)
		return
	}
	ctx := r.Context()
	reg, err := s.registry(ctx)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	declared := reg.Items
	var one *DeclaredTarget
	if id := q["target"]; id != "" {
		for i := range declared {
			if declared[i].ID == id {
				one = &declared[i]
			}
		}
		if one == nil {
			writeError(w, 404, "no such target")
			return
		}
		declared = []DeclaredTarget{*one}
	}
	if g := q["group"]; g != "" {
		var keep []DeclaredTarget
		for _, t := range declared {
			if t.Group == g {
				keep = append(keep, t)
			}
		}
		declared = keep
	}
	expand := map[string]bool{}
	for _, g := range strings.Split(q["expand"], ",") {
		if g = strings.TrimSpace(g); g != "" {
			expand[g] = true
		}
	}

	b, cut, err := s.mapRead(ctx, v, reg.Items, declared, from, to, now)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	out := assembleMap(b, reg, declared, from, to, expand, one != nil || q["group"] != "")
	out.Truncated = cut
	if one != nil {
		d, err := s.targetDetail(ctx, v, &declared[0].Target, from)
		if err != nil {
			s.readFailed(w, r, err)
			return
		}
		out.Target = d
		if one.App == "" {
			out.Partial = append(out.Partial, Partial{"target.changes", "the target declares no app: its changes, exceptions and evidence are attributed by app"})
		}
	}
	writeJSON(w, 200, out)
}

// mapRead runs the Map's aggregate reads: the gate records of the window, the observations of every declared scope, the
// feeds' health at the window's end and the changes holding. The scopes are those of the targets asked about; the gate
// records are the whole window's (an undeclared gate is found in them), so they are read once.
func (s *Server) mapRead(ctx context.Context, v *Viewer, all, asked []DeclaredTarget, from, to, now time.Time) (*mapBuild, bool, error) {
	st := s.opt.Store
	b := &mapBuild{byInst: map[string][]int{}, scopes: map[string]scopeTally{}, health: map[string]map[string]observe.SourceHealth{}}
	var cut bool
	var err error
	if b.rows, cut, err = st.GateActivity(ctx, v, evidence.ISO(from), evidence.ISO(to)); err != nil {
		return nil, false, err
	}
	for i, g := range b.rows {
		if g.Provider != "" {
			b.byInst[g.Provider] = append(b.byInst[g.Provider], i)
		}
		if g.RegisteredBy != "" && g.RegisteredBy != g.Provider {
			b.byInst[g.RegisteredBy] = append(b.byInst[g.RegisteredBy], i)
		}
	}
	seen := map[string]bool{}
	var scopes []string
	for _, t := range asked {
		if t.Scope != "" && !seen[t.Scope] && len(scopes) < MaxMapScopes {
			seen[t.Scope] = true
			scopes = append(scopes, t.Scope)
		}
	}
	sort.Strings(scopes)
	rd := readerOf(v)
	rows, err := st.ScopeCoverage(ctx, rd, scopes, evidence.ISO(from), evidence.ISO(to))
	if err != nil {
		return nil, false, err
	}
	for _, sc := range scopes {
		b.scopes[sc] = scopeTally{mix: map[string]int64{}}
	}
	for _, r := range rows {
		t := b.scopes[r.Scope]
		switch r.Tool {
		case "observation":
			t.observed += r.Count
		case "assessment":
			t.mix[r.Coverage] += r.Count
		}
		b.scopes[r.Scope] = t
	}
	hs, err := st.HealthBeforeScopes(ctx, rd, scopes, evidence.ISO(to))
	if err != nil {
		return nil, false, err
	}
	per := map[string][]Record{}
	for _, h := range hs {
		sc, _ := h["scope"].(string)
		per[sc] = append(per[sc], h)
	}
	end := to
	if end.After(now) {
		end = now
	}
	for sc, recs := range per {
		stmt := observe.Build(observe.Input{Scope: sc, Window: observe.Window{From: end.Add(-healthWindow), To: end}, Health: recs}, now)
		m := map[string]observe.SourceHealth{}
		for _, sh := range stmt.Health.Sources {
			m[sh.Source] = sh
		}
		b.health[sc] = m
	}
	if b.holding, err = st.Holding(ctx, v); err != nil {
		return nil, false, err
	}
	return b, cut, nil
}

func worseStatus(a, b string) string {
	rank := map[string]int{StatusOK: 0, StatusAttention: 1, StatusDown: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func pct(mix map[string]int64) *float64 {
	var total int64
	for k, n := range mix {
		if k != "unassessed" {
			total += n
		}
	}
	if total == 0 {
		return nil
	}
	p := float64(mix[evidence.CoverageAuthorizedAndVerified]) * 1000 / float64(total)
	p = float64(int64(p+0.5)) / 10
	return &p
}

func mixOf(sc scopeTally) map[string]int64 {
	out := map[string]int64{}
	var assessed int64
	for _, k := range evidence.Coverage {
		out[k] = sc.mix[k]
		assessed += sc.mix[k]
	}
	out["unassessed"] = max(0, sc.observed-assessed)
	return out
}

func holdingOf(b *mapBuild, match func(HoldRow) bool) int64 {
	var n int64
	for _, h := range b.holding {
		if match(h) {
			n += h.Count
		}
	}
	return n
}

// assembleMap joins the registry with what was read. filtered says the request narrowed the registry (a target or a
// group), so the whole-fleet reconciliation (silent and undeclared gates) is left out.
func assembleMap(b *mapBuild, reg TargetList, declared []DeclaredTarget, from, to time.Time, expand map[string]bool, filtered bool) *MapResponse {
	out := &MapResponse{From: evidence.ISO(from), To: evidence.ISO(to), Edges: []MapEdge{}, Attention: []Attention{}, Partial: []Partial{},
		Registry: MapRegistry{Sources: reg.Sources, Conflicts: reg.Conflicts, Targets: len(reg.Items)}}
	out.Nodes = MapNodes{GateTypes: []GateTypeNode{}, Groups: []GroupNode{}, Targets: []TargetNode{}, Observers: []ObserverNode{}}

	// -- gate instances: the declared (type, instance) pairs, their mode (flag when any target declares flag), activity.
	type inst struct {
		typ, name string
		flag      bool
		targets   map[string]bool
	}
	instances := map[[2]string]*inst{}
	typeTargets := map[string]map[string]bool{}
	for _, t := range declared {
		for _, g := range t.Gates {
			k := [2]string{g.Type, g.Instance}
			in := instances[k]
			if in == nil {
				in = &inst{typ: g.Type, name: g.Instance, targets: map[string]bool{}}
				instances[k] = in
			}
			in.flag = in.flag || g.Mode == targets.ModeFlag
			in.targets[t.ID] = true
			if typeTargets[g.Type] == nil {
				typeTargets[g.Type] = map[string]bool{}
			}
			typeTargets[g.Type][t.ID] = true
		}
	}
	instKeys := make([][2]string, 0, len(instances))
	for k := range instances {
		instKeys = append(instKeys, k)
	}
	sort.Slice(instKeys, func(i, j int) bool {
		if instKeys[i][0] != instKeys[j][0] {
			return instKeys[i][0] < instKeys[j][0]
		}
		return instKeys[i][1] < instKeys[j][1]
	})

	// -- gate type nodes
	typeSeen := map[string]map[int]bool{}
	typeNodes := map[string]*GateTypeNode{}
	var typeOrder []string
	scopesOfType := map[string]map[string]bool{}
	for _, k := range instKeys {
		in := instances[k]
		n := typeNodes[in.typ]
		if n == nil {
			n = &GateTypeNode{ID: "gate:" + in.typ, Type: in.typ, Status: StatusOK, Tally: newTally()}
			typeNodes[in.typ] = n
			typeOrder = append(typeOrder, in.typ)
			typeSeen[in.typ] = map[int]bool{}
			scopesOfType[in.typ] = map[string]bool{}
		}
		n.Instances++
		idx := b.instanceRows(in.name)
		switch {
		case in.flag:
			n.Mix.Flag++
		default:
			n.Mix.Enforce++
		}
		if len(idx) == 0 {
			n.Mix.Silent++
		}
		b.add(&n.Tally, idx, typeSeen[in.typ])
		n.Holding += holdingOf(b, func(h HoldRow) bool { return h.RegisteredBy == in.name })
	}
	for _, t := range declared {
		for _, g := range t.Gates {
			if t.Scope != "" {
				scopesOfType[g.Type][t.Scope] = true
			}
		}
	}
	for _, typ := range typeOrder {
		n := typeNodes[typ]
		n.Targets = len(typeTargets[typ])
		for sc := range scopesOfType[typ] {
			n.Lanes.Observed += b.scopes[sc].observed
			n.Lanes.Verified += b.scopes[sc].mix[evidence.CoverageAuthorizedAndVerified]
		}
		n.Status = StatusOK
		if n.Mix.Flag > 0 || n.Holding > 0 {
			n.Status = StatusAttention
		}
		if n.Coverage[covOutOfBand] > 0 || n.Coverage[covUnavailable] > 0 {
			n.Status = StatusDown
		}
		out.Nodes.GateTypes = append(out.Nodes.GateTypes, *n)
	}

	// -- targets
	groupOf := map[string]*GroupNode{}
	var groupOrder []string
	groupScopes := map[string]map[string]bool{}
	obsNodes := map[string]*ObserverNode{}
	var obsOrder []string
	noScope, noApp := 0, 0
	targetStatus := map[string]string{}
	for _, dt := range declared {
		t := dt.Target
		node := TargetNode{ID: t.ID, Source: dt.Source, Name: t.Name, Kind: t.Kind, Group: t.Group, Env: t.Env, App: t.App,
			Owner: t.Owner, Registry: t.Registry, Scope: t.Scope, Status: StatusOK, Gates: []GateRef{}, Observers: []ObserverRef{}}
		sc := b.scopes[t.Scope]
		if sc.mix == nil {
			sc.mix = map[string]int64{}
		}
		node.Coverage = mixOf(sc)
		node.VerifiedPct = pct(node.Coverage)
		node.Lanes.Observed, node.Lanes.Verified = sc.observed, sc.mix[evidence.CoverageAuthorizedAndVerified]
		if t.Scope == "" {
			noScope++
		}
		if t.App == "" {
			noApp++
		}
		match := func(g GateRow) bool { return attributable(g, &t) }
		// the target's own lanes: every gate's records about its app and environment
		all := newTally()
		var idx []int
		if t.App != "" {
			for i, g := range b.rows {
				if match(g) {
					idx = append(idx, i)
				}
			}
		}
		b.add(&all, idx, map[int]bool{})
		node.Lanes.Requested, node.Lanes.Tiered, node.Lanes.Decided = all.Lanes.Requested, all.Lanes.Tiered, all.Lanes.Decided
		node.Lanes.Applied, node.Lanes.AppliedMatched = all.Lanes.Applied, all.Lanes.AppliedMatched
		if t.App != "" {
			node.Holding = holdingOf(b, func(h HoldRow) bool { return h.App == t.App && (t.Env == "" || h.Env == t.Env) })
		}
		for _, g := range t.Gates {
			ref := GateRef{Type: g.Type, Instance: g.Instance, Mode: g.Mode, Attributed: t.App != "", Tally: newTally()}
			irows := b.instanceRows(g.Instance)
			ref.Silent = len(irows) == 0
			var mine []int
			for _, i := range irows {
				if match(b.rows[i]) {
					mine = append(mine, i)
				}
			}
			b.add(&ref.Tally, mine, map[int]bool{})
			ref.Holding = holdingOf(b, func(h HoldRow) bool {
				return h.RegisteredBy == g.Instance && t.App != "" && h.App == t.App && (t.Env == "" || h.Env == t.Env)
			})
			ref.Lanes.Observed, ref.Lanes.Verified = sc.observed, sc.mix[evidence.CoverageAuthorizedAndVerified]
			node.Gates = append(node.Gates, ref)
		}
		blind, degraded := false, false
		for _, o := range t.Observers {
			ref := ObserverRef{Provider: o.Provider, Source: o.Source, State: "unknown", Failed: []string{}}
			if t.Scope != "" {
				ref.State = observe.Blind // a declared feed with no health record is never seen
				if sh, ok := b.health[t.Scope][o.Source]; ok {
					ref.State, ref.LastTS, ref.Stale = sh.Now, sh.LastTS, sh.Stale
					if sh.Failed != nil {
						ref.Failed = sh.Failed
					}
				}
			}
			blind = blind || ref.State == observe.Blind
			degraded = degraded || ref.State == observe.Degraded
			node.Observers = append(node.Observers, ref)
			id := "observer:" + o.Provider + "/" + o.Source
			on := obsNodes[id]
			if on == nil {
				on = &ObserverNode{ID: id, Provider: o.Provider, Source: o.Source, States: map[string]int{}}
				obsNodes[id] = on
				obsOrder = append(obsOrder, id)
			}
			on.Targets++
			on.States[ref.State]++
		}
		flag := false
		for _, g := range node.Gates {
			flag = flag || g.Mode == targets.ModeFlag
		}
		switch {
		case blind || node.Coverage[covOutOfBand] > 0 || node.Coverage[covUnavailable] > 0:
			node.Status = StatusDown
		case len(t.Gates) == 0 || flag || node.Holding > 0 || degraded || node.Coverage[evidence.CoverageObservedNotAttributed] > 0 ||
			node.Coverage[evidence.CoverageBreakGlass] > 0:
			node.Status = StatusAttention
		}
		targetStatus[t.ID] = node.Status
		out.Nodes.Targets = append(out.Nodes.Targets, node)

		gn := groupOf[t.Group]
		if gn == nil {
			gn = &GroupNode{ID: "group:" + t.Group, Group: t.Group, Kinds: map[string]int{}, Status: StatusOK, Coverage: map[string]int64{},
				Observers: map[string]int{}}
			for _, k := range coverageKeys {
				gn.Coverage[k] = 0
			}
			groupOf[t.Group] = gn
			groupOrder = append(groupOrder, t.Group)
			groupScopes[t.Group] = map[string]bool{}
		}
		gn.Targets++
		gn.Kinds[t.Kind]++
		gn.Holding += node.Holding
		gn.Status = worseStatus(gn.Status, node.Status)
		if len(t.Gates) == 0 {
			gn.NoGate++
		}
		for _, g := range t.Gates {
			if g.Mode == targets.ModeFlag {
				gn.Mix.Flag++
			} else {
				gn.Mix.Enforce++
			}
		}
		for _, o := range node.Observers {
			gn.Observers[o.State]++
		}
		if t.Scope != "" && !groupScopes[t.Group][t.Scope] {
			groupScopes[t.Group][t.Scope] = true
			for k, n := range node.Coverage {
				gn.Coverage[k] += n
			}
		}
	}
	sort.Strings(groupOrder)
	for _, g := range groupOrder {
		gn := groupOf[g]
		gn.VerifiedPct = pct(gn.Coverage)
		out.Nodes.Groups = append(out.Nodes.Groups, *gn)
	}
	sort.Strings(obsOrder)
	for _, id := range obsOrder {
		on := obsNodes[id]
		on.Status = StatusOK
		if on.States[observe.Degraded] > 0 || on.States["unknown"] > 0 {
			on.Status = StatusAttention
		}
		if on.States[observe.Blind] > 0 {
			on.Status = StatusDown
		}
		out.Nodes.Observers = append(out.Nodes.Observers, *on)
	}

	out.Edges = buildEdges(b, out, declared, expand)
	out.Attention = buildAttention(b, out, declared, instKeys, filtered)

	if len(out.Nodes.GateTypes) > 0 || len(declared) > 0 {
		out.Partial = append(out.Partial, Partial{"lanes.observed,lanes.verified", "counted from the observations of the target's scope in the window " +
			"(observed: observations; verified: assessed authorized-and-verified), not joined to each change: a deploy.outcome " +
			"does not yet name the observation that matched it (G-ARGO-3)"})
		out.Partial = append(out.Partial, Partial{"lanes.requested..applied", "a change that is cleared and later expires counts as decided under each; " +
			"a gate's lanes are summed over its instances' records, each record once"})
	}
	if noApp > 0 {
		out.Partial = append(out.Partial, Partial{"targets.attribution", fmt.Sprintf("%d targets declare no app: decisions, holds and lanes are attributed to a target by app and environment, so they show none", noApp)})
	}
	if noScope > 0 {
		out.Partial = append(out.Partial, Partial{"targets.coverage", fmt.Sprintf("%d targets declare no coverage scope: their coverage mix and observer health are unavailable", noScope)})
	}
	return out
}

func buildEdges(b *mapBuild, out *MapResponse, declared []DeclaredTarget, expand map[string]bool) []MapEdge {
	edges := []MapEdge{}
	type key struct{ typ, to string }
	type acc struct {
		e     MapEdge
		insts map[string]bool
		seen  map[int]bool
		t     Tally
	}
	byEdge := map[key]*acc{}
	var order []key
	nodeOf := map[string]TargetNode{}
	for _, n := range out.Nodes.Targets {
		nodeOf[n.ID] = n
	}
	add := func(typ, to string, t *DeclaredTarget, g targets.Gate) {
		k := key{typ, to}
		a := byEdge[k]
		if a == nil {
			a = &acc{e: MapEdge{From: "gate:" + typ, To: to, Kind: "guards", Status: StatusOK}, insts: map[string]bool{}, seen: map[int]bool{}, t: newTally()}
			byEdge[k] = a
			order = append(order, k)
		}
		a.e.Targets++
		if g.Mode == targets.ModeFlag {
			a.e.Status = worseStatus(a.e.Status, StatusAttention)
		}
		if !a.insts[g.Instance+"|"+t.ID] {
			a.insts[g.Instance+"|"+t.ID] = true
			var mine []int
			for _, i := range b.instanceRows(g.Instance) {
				if attributable(b.rows[i], &t.Target) {
					mine = append(mine, i)
				}
			}
			b.add(&a.t, mine, a.seen)
			a.e.Holding += holdingOf(b, func(h HoldRow) bool {
				return h.RegisteredBy == g.Instance && t.App != "" && h.App == t.App && (t.Env == "" || h.Env == t.Env)
			})
		}
		if nodeOf[t.ID].Status == StatusDown {
			a.e.Status = worseStatus(a.e.Status, StatusDown)
		}
	}
	for i := range declared {
		t := &declared[i]
		for _, g := range t.Gates {
			add(g.Type, "group:"+t.Group, t, g)
			if expand[t.Group] || len(declared) == 1 {
				add(g.Type, "target:"+t.ID, t, g)
			}
		}
	}
	for _, k := range order {
		a := byEdge[k]
		a.e.Volume, a.e.Refused = a.t.Decisions, a.t.Refused
		if a.e.Holding > 0 {
			a.e.Status = worseStatus(a.e.Status, StatusAttention)
		}
		if a.t.Coverage[covOutOfBand] > 0 || a.t.Coverage[covUnavailable] > 0 {
			a.e.Status = worseStatus(a.e.Status, StatusDown)
		}
		edges = append(edges, a.e)
	}
	// observers watch groups (and targets, expanded)
	type wk struct{ obs, to string }
	watch := map[wk]*MapEdge{}
	var worder []wk
	for _, n := range out.Nodes.Targets {
		for _, o := range n.Observers {
			id := "observer:" + o.Provider + "/" + o.Source
			for _, to := range []string{"group:" + n.Group, "target:" + n.ID} {
				if strings.HasPrefix(to, "target:") && !expand[n.Group] && len(declared) != 1 {
					continue
				}
				k := wk{id, to}
				e := watch[k]
				if e == nil {
					e = &MapEdge{From: id, To: to, Kind: "watches", Status: StatusOK}
					watch[k] = e
					worder = append(worder, k)
				}
				e.Targets++
				switch o.State {
				case observe.Blind:
					e.Status = worseStatus(e.Status, StatusDown)
				case observe.Degraded, "unknown":
					e.Status = worseStatus(e.Status, StatusAttention)
				}
			}
		}
	}
	for _, k := range worder {
		edges = append(edges, *watch[k])
	}
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].Kind != edges[j].Kind {
			return edges[i].Kind < edges[j].Kind
		}
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})
	return edges
}

func capIDs(ids []string) []string {
	sort.Strings(ids)
	if len(ids) > MaxAttentionTarget {
		ids = ids[:MaxAttentionTarget]
	}
	if ids == nil {
		ids = []string{}
	}
	return ids
}

func buildAttention(b *mapBuild, out *MapResponse, declared []DeclaredTarget, instKeys [][2]string, filtered bool) []Attention {
	var items []Attention
	var noGate []string
	for _, n := range out.Nodes.Targets {
		if len(n.Gates) == 0 {
			noGate = append(noGate, n.ID)
		}
		for _, o := range n.Observers {
			switch o.State {
			case observe.Blind:
				d := "no signed health record in time"
				if o.LastTS != nil {
					d = "last health record " + *o.LastTS
				}
				if len(o.Failed) > 0 {
					d += "; failed checks: " + strings.Join(o.Failed, ", ")
				}
				items = append(items, Attention{Kind: AttnBlind, Severity: StatusDown, Title: o.Provider + "/" + o.Source + " is blind on " + n.Name,
					Detail: d + ". Applies in the window cannot be verified: they show as could not see, never clean.", Count: 1, Targets: []string{n.ID}})
			case observe.Degraded:
				items = append(items, Attention{Kind: AttnDegraded, Severity: StatusAttention, Title: o.Provider + "/" + o.Source + " is degraded on " + n.Name,
					Detail: strings.Join(o.Failed, ", "), Count: 1, Targets: []string{n.ID}})
			}
		}
	}
	if len(noGate) > 0 {
		items = append(items, Attention{Kind: AttnNoGate, Severity: StatusAttention, Title: fmt.Sprintf("%d targets with no gate", len(noGate)),
			Detail: "declared targets no gate is declared to guard", Count: int64(len(noGate)), Targets: capIDs(noGate)})
	}
	for _, n := range out.Nodes.GateTypes {
		if n.Mix.Flag > 0 {
			var ids []string
			for _, t := range out.Nodes.Targets {
				for _, g := range t.Gates {
					if g.Type == n.Type && g.Mode == targets.ModeFlag {
						ids = append(ids, t.ID)
						break
					}
				}
			}
			items = append(items, Attention{Kind: AttnFlag, Severity: StatusAttention, GateType: n.Type,
				Title:  fmt.Sprintf("%s: %d of %d instances in flag mode", n.Type, n.Mix.Flag, n.Instances),
				Detail: "refusals are recorded, not enforced", Count: int64(n.Mix.Flag), Targets: capIDs(ids)})
		}
	}
	// changes holding now (the declared targets' apps when the view is narrowed, else all)
	var holdN int64
	var tiers []string
	var holdTargets []string
	if filtered {
		for _, t := range out.Nodes.Targets {
			if t.Holding > 0 {
				holdN += t.Holding
				holdTargets = append(holdTargets, t.ID)
			}
		}
		if holdN > 0 {
			tiers = append(tiers, "see the target's changes")
		}
	} else {
		byTier := map[int]int64{}
		for _, h := range b.holding {
			holdN += h.Count
			byTier[h.Tier] += h.Count
		}
		var ts []int
		for t := range byTier {
			ts = append(ts, t)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(ts)))
		for _, t := range ts {
			tiers = append(tiers, fmt.Sprintf("%d at tier %d", byTier[t], t))
		}
		for _, n := range out.Nodes.Targets {
			if n.Holding > 0 {
				holdTargets = append(holdTargets, n.ID)
			}
		}
	}
	if holdN > 0 {
		items = append(items, Attention{Kind: AttnHolding, Severity: StatusAttention, Title: fmt.Sprintf("%d changes waiting on a person", holdN),
			Detail: strings.Join(tiers, ", "), Count: holdN, Targets: capIDs(holdTargets)})
	}
	if !filtered {
		known := map[string]bool{}
		for _, k := range instKeys {
			known[k[1]] = true
			if len(b.instanceRows(k[1])) == 0 {
				items = append(items, Attention{Kind: AttnSilent, Severity: "info", GateType: k[0], Instance: k[1],
					Title: k[0] + "/" + k[1] + " decided nothing in the window", Detail: "declared, but no record of the window names it: quiet, or not wired", Count: 0, Targets: []string{}})
			}
		}
		und := map[string]int64{}
		for _, g := range b.rows {
			name := g.Provider
			if name == "" {
				name = g.RegisteredBy
			}
			if name == "" || known[g.Provider] || known[g.RegisteredBy] {
				continue
			}
			und[name] += g.Count
		}
		var names []string
		for n := range und {
			names = append(names, n)
		}
		sort.Slice(names, func(i, j int) bool {
			if und[names[i]] != und[names[j]] {
				return und[names[i]] > und[names[j]]
			}
			return names[i] < names[j]
		})
		for _, n := range names {
			items = append(items, Attention{Kind: AttnUndeclared, Severity: "info", Instance: n, Title: n + " wrote records but no target declares it",
				Detail: "decisions from a gate instance the registry does not list", Count: und[n], Targets: []string{}})
		}
	}
	rank := map[string]int{StatusDown: 0, StatusAttention: 1, "info": 2}
	sort.SliceStable(items, func(i, j int) bool {
		if rank[items[i].Severity] != rank[items[j].Severity] {
			return rank[items[i].Severity] < rank[items[j].Severity]
		}
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Title < items[j].Title
	})
	if len(items) > MaxMapAttention {
		items = items[:MaxMapAttention]
	}
	if items == nil {
		items = []Attention{}
	}
	return items
}

// targetDetail is the C10 page's lists for one target: the changes moving through it, its exceptions and its recent
// evidence, the records the viewer may see for the target's app.
func (s *Server) targetDetail(ctx context.Context, v *Viewer, t *targets.Target, from time.Time) (*TargetDetail, error) {
	d := &TargetDetail{Changes: []MapChange{}, Exceptions: []Record{}, Evidence: []Record{}}
	if t.App == "" {
		return d, nil
	}
	rows, err := s.opt.Store.Changes(ctx, ChangeFilter{App: t.App, Env: t.Env, Since: evidence.ISO(from)}, v, MaxMapChanges, "")
	if err != nil {
		return nil, err
	}
	now := s.opt.Clock().UTC()
	for _, raw := range rows {
		var c struct {
			ID, State, Repo, Owner string
			PR, Tier               int64
			ClearedBy              *string `json:"cleared_by"`
			UpdatedAt              string  `json:"updated_at"`
		}
		c.ID = ""
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		get := func(k string, into any) { _ = json.Unmarshal(m[k], into) }
		get("id", &c.ID)
		get("state", &c.State)
		get("repo", &c.Repo)
		get("owner", &c.Owner)
		get("pr", &c.PR)
		get("tier", &c.Tier)
		get("cleared_by", &c.ClearedBy)
		get("updated_at", &c.UpdatedAt)
		mc := MapChange{ID: c.ID, Tier: c.Tier, State: c.State, Repo: c.Repo, PR: c.PR, Owner: c.Owner, UpdatedAt: c.UpdatedAt}
		if c.ClearedBy != nil {
			mc.ClearedBy = *c.ClearedBy
		}
		if at, ok := parseISO(c.UpdatedAt); ok {
			mc.AgeSeconds = int64(now.Sub(at).Seconds())
		}
		d.Changes = append(d.Changes, mc)
	}
	redact := !v.All()
	ex := EvidenceFilter{App: t.App, Exceptions: true, Outcomes: OutcomesInclude, Since: evidence.ISO(from)}
	if recs, err := s.opt.Store.Evidence(ctx, ex, readerOf(v), MaxMapEvidence, nil); err != nil {
		return nil, err
	} else {
		d.Exceptions = prepared(recs, redact)
	}
	ev := EvidenceFilter{App: t.App, Outcomes: OutcomesExclude, Since: evidence.ISO(from), Tools: []string{"deploy.request", "deploy.clear", "deploy.deny", "deploy.expire", "deploy.outcome", "deploy.exception"}}
	if recs, err := s.opt.Store.Evidence(ctx, ev, v, MaxMapEvidence, nil); err != nil {
		return nil, err
	} else {
		d.Evidence = prepared(recs, redact)
	}
	return d, nil
}

func prepared(rs []Record, redact bool) []Record {
	if redact {
		for i := range rs {
			rs[i] = redactForPerson(rs[i])
		}
	}
	return projectAll(rs)
}
