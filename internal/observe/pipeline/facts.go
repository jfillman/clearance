package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/gate/render"
	"github.com/jfillman/clearance/internal/pycompat"
)

// Grant is a clearance as the record store knows it: its id and the digests of the objects it rendered.
type Grant struct {
	ID     string
	Hashes []string // render.ObjectDigest of each rendered object
}

// PlanChange is one resource change of a cleared Terraform plan: the resource and the API calls the change makes.
type PlanChange struct {
	Resource string
	APIs     []string
}

// Plan is a cleared plan. Changes may be empty (a digest-only record), which makes only the digest evidence.
type Plan struct {
	Grant   string
	Digest  string
	Changes []PlanChange
}

// Lookups is what attribution asks the record store. Every answer is the store's, never the event's: an event only
// supplies the key. The collectors (O-3, O-4) implement it over the evidence chain and the grant records.
type Lookups interface {
	Grant(id string) (Grant, bool)
	// BreakGlass is the id of the break-glass window open for the scope at t.
	BreakGlass(scope string, t time.Time) (string, bool)
	// Attestation is the grant of a signed execution attestation whose subject includes the event (by its id).
	Attestation(eventID string) (string, bool)
	// Run is the grant of a verified pipeline identity and run (the run id the actor's source identity or session
	// name carries).
	Run(runID string) (string, bool)
	// Session is the grant an apply role's session was issued under.
	Session(issuerARN, session string) (string, bool)
	// Plan is the cleared plan with this digest.
	Plan(digest string) (Plan, bool)
	// Window is the grant whose apply window is open in the scope at t.
	Window(scope string, t time.Time) (string, bool)
}

// facts are what the attribution rules read besides the event.
type facts struct {
	m     map[string]any
	grant string
}

func (p *Pipeline) facts(e *Event) facts {
	if e.Provider == Kubernetes {
		return p.kubeFacts(e)
	}
	return p.awsFacts(e)
}

func contains(list []string, s string) bool { return slices.Contains(list, s) }

func (p *Pipeline) kubeFacts(e *Event) facts {
	ids := p.rs.ids
	f := map[string]any{}
	grant := e.ObjAnnotations[p.rs.ann.Grant]
	f["grant"] = grant
	f["stamped_hash"] = e.ObjAnnotations[p.rs.ann.Rendered]
	known, match := false, false
	if grant != "" {
		var g Grant
		if g, known = p.lk.Grant(grant); known && e.AfterHash != "" {
			// The live object's own hash against the hashes the grant lists. The stamp annotation is the tenant's to
			// write, so it is only a claim: it is never what matches.
			match = contains(g.Hashes, e.AfterHash)
		}
	}
	f["grant_known"] = known
	f["hash_match"] = match
	f["hash_differs"] = grant != "" && known && !match
	webhook, vap := false, false
	for k := range e.AuditAnnotations {
		if strings.HasPrefix(k, "patch.webhook.admission.k8s.io/") || strings.HasPrefix(k, "mutation.webhook.admission.k8s.io/") {
			webhook = true
		}
		if strings.HasPrefix(k, "validation.policy.admission.k8s.io/") {
			vap = true
		}
	}
	f["mutating_webhook"] = webhook
	f["vap_denial"] = vap && !e.Succeeded
	f["refused"] = !e.Succeeded
	f["argo_controller"] = contains(ids.ArgoController, e.Subject)
	fed := false
	for _, pre := range ids.FederatedPrefix {
		if pre != "" && strings.HasPrefix(e.Subject, pre) {
			fed = true
		}
	}
	f["federated"] = fed
	f["has_task_id"] = e.TaskID != ""
	f["impersonated"] = e.Impersonated != ""
	f["kubectl"] = strings.HasPrefix(e.UserAgent, ids.KubectlUserAgent)
	f["service_account"] = e.Type == "serviceaccount"
	bg, live := p.lk.BreakGlass(e.Scope, e.Time)
	f["break_glass"] = live
	f["break_glass_id"] = bg
	return facts{f, grant}
}

func (p *Pipeline) awsFacts(e *Event) facts {
	ids := p.rs.ids
	f := map[string]any{}
	f["root"] = e.Type == "Root"
	f["refused"] = e.ErrorCode != ""
	applyRole := e.Issuer != "" && contains(ids.ApplyRoles, e.Issuer)
	f["apply_role"] = applyRole
	f["sso_admin"] = e.Issuer != "" && pycompat.MatchAny(e.Issuer, ids.SSOAdminRoles)
	f["source_identity"] = e.SourceIdentity
	f["claim_grant"], f["claim_plan"] = e.ClaimGrant, e.ClaimPlan
	f["user_type"] = e.Type
	var grant string
	// 1. a signed execution attestation naming this event
	g, ok := p.lk.Attestation(e.ID)
	f["corr_attestation"] = ok
	if ok {
		grant = g
	}
	// 2. a verified pipeline identity and run: the run id the source identity carries ("run=<id>" or "<name>/<id>")
	g, ok = "", false
	if run := runID(e.SourceIdentity); run != "" {
		g, ok = p.lk.Run(run)
	}
	f["corr_pipeline"] = ok
	if ok && grant == "" {
		grant = g
	}
	// 3. the apply role and its session
	g, ok = "", false
	if applyRole && e.SessionName != "" {
		g, ok = p.lk.Session(e.Issuer, e.SessionName)
	}
	f["corr_session"] = ok
	if ok && grant == "" {
		grant = g
	}
	// 4./5. the cleared plan, found by the digest the runner put in the user agent
	var plan Plan
	planKnown := false
	if applyRole && e.ClaimPlan != "" {
		plan, planKnown = p.lk.Plan(e.ClaimPlan)
		// the claim names a grant too; a plan whose grant differs is not the plan this run claims
		if planKnown && e.ClaimGrant != "" && plan.Grant != e.ClaimGrant {
			planKnown = false
		}
	}
	inSet := false
	if planKnown {
		for _, c := range plan.Changes {
			if c.Resource == e.ResourceID && (len(c.APIs) == 0 || contains(c.APIs, e.API)) {
				inSet = true
			}
		}
	}
	f["corr_plan_change"] = planKnown && inSet
	f["outside_plan"] = planKnown && len(plan.Changes) > 0 && !inSet
	f["corr_plan_digest"] = planKnown && len(plan.Changes) == 0
	if planKnown && grant == "" && (inSet || len(plan.Changes) == 0) {
		grant = plan.Grant
	}
	// 6. the apply window, last
	g, ok = "", false
	if applyRole {
		g, ok = p.lk.Window(e.Scope, e.Time)
	}
	f["corr_window"] = ok
	if ok && grant == "" {
		grant = g
	}
	f["grant"] = grant
	return facts{f, grant}
}

// runID is the pipeline run a source identity quotes: "clearance-run/<id>" or "run=<id>".
func runID(s string) string {
	if s == "" {
		return ""
	}
	if _, after, ok := strings.Cut(s, "run="); ok {
		return after
	}
	if _, after, ok := strings.Cut(s, "/"); ok {
		return after
	}
	return ""
}

// ---- StaticLookups -------------------------------------------------------------------------------------------------

// StaticLookups is a Lookups held in memory: what `clearance observe replay --lookups` loads, and what the tests use.
// Its JSON form:
//
//	{"grants": [{"id": "clr_1", "objects": [ <rendered manifest>, ... ]}],
//	 "break_glass": [{"id": "bg_1", "scope": "prod-1", "from": "...", "to": "..."}],
//	 "attestations": {"<event id>": "clr_1"}, "runs": {"<run id>": "clr_1"},
//	 "sessions": [{"issuer": "arn:...", "session": "tf-1", "grant": "clr_1"}],
//	 "plans": [{"digest": "sha256:...", "grant": "clr_1", "changes": [{"resource": "web", "apis": ["PutBucketPolicy"]}]}],
//	 "windows": [{"scope": "111122223333", "grant": "clr_1", "from": "...", "to": "..."}]}
//
// A grant's objects are the rendered manifests; their digests are computed here the way the gate computes them.
type StaticLookups struct {
	Grants       map[string]Grant
	BreakGlassW  []span
	Attestations map[string]string
	Runs         map[string]string
	Sessions     map[[2]string]string
	Plans        map[string]Plan
	Windows      []span
}

type span struct {
	ID, Scope string
	From, To  time.Time
}

func (s StaticLookups) Grant(id string) (Grant, bool) { g, ok := s.Grants[id]; return g, ok }
func (s StaticLookups) BreakGlass(scope string, t time.Time) (string, bool) {
	return open(s.BreakGlassW, scope, t)
}
func (s StaticLookups) Attestation(id string) (string, bool) {
	g, ok := s.Attestations[id]
	return g, ok
}
func (s StaticLookups) Run(id string) (string, bool) { g, ok := s.Runs[id]; return g, ok }
func (s StaticLookups) Session(issuer, session string) (string, bool) {
	g, ok := s.Sessions[[2]string{issuer, session}]
	return g, ok
}
func (s StaticLookups) Plan(d string) (Plan, bool) { p, ok := s.Plans[d]; return p, ok }
func (s StaticLookups) Window(scope string, t time.Time) (string, bool) {
	return open(s.Windows, scope, t)
}

func open(w []span, scope string, t time.Time) (string, bool) {
	for _, x := range w {
		if x.Scope == scope && !t.Before(x.From) && !t.After(x.To) {
			return x.ID, true
		}
	}
	return "", false
}

type lookupsDoc struct {
	Grants []struct {
		ID      string           `json:"id"`
		Objects []map[string]any `json:"objects"`
	} `json:"grants"`
	BreakGlass []struct {
		ID, Scope string
		From, To  time.Time
	} `json:"break_glass"`
	Attestations map[string]string                         `json:"attestations"`
	Runs         map[string]string                         `json:"runs"`
	Sessions     []struct{ Issuer, Session, Grant string } `json:"sessions"`
	Plans        []struct {
		Digest, Grant string
		Changes       []struct {
			Resource string
			APIs     []string
		}
	} `json:"plans"`
	Windows []struct {
		Scope, Grant string
		From, To     time.Time
	} `json:"windows"`
}

// LoadLookups reads StaticLookups' JSON form. rs supplies the canonicalization a grant's objects are hashed under.
func LoadLookups(b []byte, rs *RuleSet) (StaticLookups, error) {
	var d lookupsDoc
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return StaticLookups{}, fmt.Errorf("lookups: %w", err)
	}
	s := StaticLookups{Grants: map[string]Grant{}, Attestations: d.Attestations, Runs: d.Runs,
		Sessions: map[[2]string]string{}, Plans: map[string]Plan{}}
	for _, g := range d.Grants {
		gr := Grant{ID: g.ID}
		for _, o := range g.Objects {
			gr.Hashes = append(gr.Hashes, render.ObjectDigest(render.Doc{Value: rs.canonicalObject(o)}))
		}
		s.Grants[g.ID] = gr
	}
	for _, b := range d.BreakGlass {
		s.BreakGlassW = append(s.BreakGlassW, span{b.ID, b.Scope, b.From, b.To})
	}
	for _, x := range d.Sessions {
		s.Sessions[[2]string{x.Issuer, x.Session}] = x.Grant
	}
	for _, p := range d.Plans {
		pl := Plan{Grant: p.Grant, Digest: p.Digest}
		for _, c := range p.Changes {
			pl.Changes = append(pl.Changes, PlanChange{c.Resource, c.APIs})
		}
		s.Plans[p.Digest] = pl
	}
	for _, w := range d.Windows {
		s.Windows = append(s.Windows, span{w.Grant, w.Scope, w.From, w.To})
	}
	return s, nil
}
