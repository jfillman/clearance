package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/vocab"
)

// RecordKinds are the records a registered provider writes itself (POST /v1/records): the runtime's session and
// run lifecycle and people's answers and controls (the Autopilot gateway), a T0 read the gateway allowed while the
// core was unreachable (tool.call, coverage-unavailable: the outage policy's outbox replay), and the deployment
// boundary's outcome, exceptions and outage reports (a deployment-gate provider such as the Argo sync).
// deploy.exception and deploy.degraded are the gate's to check and act on (gate.Service.Report, C-6): their shape
// is in internal/gate/exception.go and docs/gate.md. A decision another gateway's own policy decision point made
// is federated.decision: a federated runtime source such as the Traefik Hub adapter (internal/federate/traefikhub).
//
// definition.load, definition.unload and definition.reject are not among them: the core writes those itself when a
// provider publishes its pinned definitions (PUT /v1/definitions, definitions.Service.Apply), so there is one
// writer of each.
var RecordKinds = []string{"session.open", "run.launch", "run.delete", "run.finish", "human.answer",
	"session.freeze", "session.end", "trigger.hold", "trigger.release", "tool.call", "deploy.outcome",
	"deploy.exception", "deploy.degraded", FederatedKind,
	evidence.KindObservation, evidence.KindAssessment, evidence.KindResolution, evidence.KindHealth, evidence.KindVerification,
	KindGRCPush, KindGRCReport}

// The GRC push's records (P-4, internal/grc, docs/grc-push.md): what clearance-grc did with a change or a report it
// sent to a GRC hub. Written only by a provider that names them in its kinds (like the observation kinds), claimed
// but for provider and ts: they say what the pusher reports it sent, never that the hub holds it.
const (
	KindGRCPush   = "grc.push"
	KindGRCReport = "grc.report"
)

// isGRCKind is a kind only a provider that names it may write.
func isGRCKind(k string) bool { return k == KindGRCPush || k == KindGRCReport }

// OutageKind is the record of a T0 read the provider allowed while the core was unreachable. Its tool is the tool
// that was called (record.tool), its coverage is CoverageUnavailable, and everything in it is claimed: the core
// decided nothing.
const (
	OutageKind          = "tool.call"
	CoverageUnavailable = "coverage-unavailable"
)

// FederatedKind is a decision a federated runtime source observed at another gateway (its own PDP decided; the
// core decided nothing). Everything in it is claimed, a correlated task_id included, so its coverage is always
// CoverageObserved: another PDP authorized the call, not Clearance. It carries no Clearance rule, tier, effect,
// outcome or change.
const (
	FederatedKind    = "federated.decision"
	CoverageObserved = "observed-not-attributed"
)

// kindSpec is what each kind must carry, and its boundary.
type kindSpec struct {
	required []string
	boundary string
}

var recordKinds = map[string]kindSpec{
	"session.open":    {[]string{"session", "task_id", "principal", "agent", "result"}, "runtime"},
	"run.launch":      {[]string{"session", "principal", "agent", "result"}, "runtime"},
	"run.delete":      {[]string{"session", "principal", "agent", "result"}, "runtime"},
	"run.finish":      {[]string{"session", "task_id", "principal", "agent", "args_sha256", "result"}, "runtime"},
	"human.answer":    {[]string{"principal", "target", "result"}, "runtime"},
	"session.freeze":  {[]string{"session", "principal", "agent", "result"}, "runtime"},
	"session.end":     {[]string{"session", "principal", "agent", "target", "result"}, "runtime"},
	"trigger.hold":    {[]string{"principal", "agent", "target", "result"}, "runtime"},
	"trigger.release": {[]string{"principal", "agent", "target", "result"}, "runtime"},
	OutageKind: {[]string{"session", "task_id", "principal", "agent", "tool", "tier", "args_sha256", "result",
		"coverage"}, "runtime"},
	"deploy.outcome":   {[]string{"app", "target", "outcome"}, "deployment"},
	"deploy.exception": {[]string{"principal", "target", "result", "exception", "destination"}, "deployment"},
	"deploy.degraded": {[]string{"principal", "target", "app", "result", "decision", "coverage", "outage",
		"destination"}, "deployment"},
	FederatedKind: {[]string{"decision", "result", "coverage"}, "runtime"},
	// The observation kinds (O-1); observe.Check holds each to its shape.
	evidence.KindObservation:  {[]string{"scope", "source", "resource", "actor", "action", "integrity", "times"}, "deployment"},
	evidence.KindAssessment:   {[]string{"scope", "about", "coverage", "tier", "rule_set", "attribution"}, "deployment"},
	evidence.KindResolution:   {[]string{"scope", "about", "resolution"}, "deployment"},
	evidence.KindHealth:       {[]string{"scope", "source", "health"}, "deployment"},
	evidence.KindVerification: {[]string{"scope", "source", "about", "verification"}, "deployment"},
	// P-4: target is the hub ("vanta"), result is pushed or failed.
	KindGRCPush:   {[]string{"target", "result"}, "deployment"},
	KindGRCReport: {[]string{"target", "result"}, "deployment"},
}

// RecordRequest is POST /v1/records's body. provider must be the provider the caller authenticates as; kind is the
// record's tool.
type RecordRequest struct {
	Provider string        `json:"provider" contract:"required"`
	Kind     string        `json:"kind" contract:"required"`
	Record   ProviderEvent `json:"record" contract:"required"`
}

// ProviderEvent is the fields a provider may report (docs/evidence.md field groups). Every one is claimed: the core
// verifies only who sent it (provider) and when it arrived (ts). The envelope (seq, schema, boundary, verified,
// claimed, prev_hash, hash, provider) is the core's.
type ProviderEvent struct {
	TaskID    *string `json:"task_id,omitempty"`
	Session   *string `json:"session,omitempty"`
	Parent    *string `json:"parent,omitempty"`
	Principal *string `json:"principal,omitempty"`
	Agent     *string `json:"agent,omitempty"`
	// Tool is the tool that was called: kind tool.call only (a T0 tool the core knows); every other kind's tool is
	// the kind.
	Tool       *string `json:"tool,omitempty"`
	Target     *string `json:"target,omitempty"`
	App        *string `json:"app,omitempty"`
	Decision   *string `json:"decision,omitempty"`
	Rule       *string `json:"rule,omitempty"`
	Tier       *int    `json:"tier,omitempty"`
	ArgsSHA256 *string `json:"args_sha256,omitempty"`
	Result     *string `json:"result,omitempty"`
	Reason     *string `json:"reason,omitempty"`
	// Intent is free text an agent or a person gave as the reason; stored as its digest unless the provider's
	// intent_capture is full.
	Intent      *string        `json:"intent,omitempty"`
	Coverage    *string        `json:"coverage,omitempty"`
	Subject     map[string]any `json:"subject,omitempty"`
	Initiator   map[string]any `json:"initiator,omitempty"`
	Source      map[string]any `json:"source,omitempty"`
	Destination map[string]any `json:"destination,omitempty"`
	Change      map[string]any `json:"change,omitempty"`
	// Release is {id}: the release a deploy.outcome belongs to (G-ARGO-6), the record's one place for it. A provider
	// that sent change.release.id (the Argo CD agent before this) is read the same way. Claimed, like the rest.
	Release map[string]any `json:"release,omitempty"`
	Effect  map[string]any `json:"effect,omitempty"`
	Outcome map[string]any `json:"outcome,omitempty"`
	// Exception is a deploy.exception's {kind, objects, addresses, actor, expected, observed, state, detected_at,
	// detail} (gate.ExceptionKinds; docs/gate.md, Exceptions).
	Exception map[string]any `json:"exception,omitempty"`
	// Outage is a deploy.degraded's {from, to}: when the provider could not reach the core.
	Outage map[string]any `json:"outage,omitempty"`
	// ModelVersion is the pinned model version the run runs on (AP-C1): the definition's model through the
	// provider's route. A run's records only (RunRecordKinds).
	ModelVersion *string `json:"model_version,omitempty"`
	// Preflight is the Preflight result of the run's definition (AP-C1). A run's records only.
	Preflight *Preflight `json:"preflight,omitempty"`
	// Cost is the run's usage summary when it ends (AP-C2). run.finish only.
	Cost *Cost `json:"cost,omitempty"`

	// The observation kinds' fields (O-1, internal/observe): scope is the account, cluster or workspace observed. An
	// observation carries resource, actor {subject, chain, issuer, client, attributes}, action {verb, api, succeeded,
	// refused_reason}, state_change {before, after}, correlation {grant, plan, task_id, run_id, operation_id}, integrity
	// {sourceVerified, completenessClaimed} and times {requested, observed, delivered}, and names its source as source
	// {name, event_id}. An assessment or a resolution names the record it is about as about {seq}; an assessment carries
	// coverage, tier, rule_set {version} and attribution {signal}; a resolution carries resolution {state, cause}. A
	// health record carries source {name} and health {state, checks, interval_seconds}. Every one is claimed.
	Scope       *string        `json:"scope,omitempty"`
	Resource    map[string]any `json:"resource,omitempty"`
	Actor       map[string]any `json:"actor,omitempty"`
	Action      map[string]any `json:"action,omitempty"`
	StateChange map[string]any `json:"state_change,omitempty"`
	Correlation map[string]any `json:"correlation,omitempty"`
	Integrity   map[string]any `json:"integrity,omitempty"`
	Times       map[string]any `json:"times,omitempty"`
	Health      map[string]any `json:"health,omitempty"`
	About       map[string]any `json:"about,omitempty"`
	RuleSet     map[string]any `json:"rule_set,omitempty"`
	Attribution map[string]any `json:"attribution,omitempty"`
	Resolution  map[string]any `json:"resolution,omitempty"`
	// Verification is an observation.verification's {method, verified, reference?} (O-5).
	Verification map[string]any `json:"verification,omitempty"`
}

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}\z`)

// MaxFieldText caps each string field of a provider record.
const MaxFieldText = 4 << 10

// event is the record's fields, every Python record key present (null when unset), and what it must carry checked.
func (e *ProviderEvent) event(kind string, spec kindSpec, ts string) (store.Event, error) {
	ev := store.Event{"ts": ts, "tool": kind, "boundary": spec.boundary}
	strs := []struct {
		k string
		v *string
	}{{"task_id", e.TaskID}, {"session", e.Session}, {"parent", e.Parent}, {"principal", e.Principal},
		{"agent", e.Agent}, {"target", e.Target}, {"decision", e.Decision}, {"rule", e.Rule},
		{"args_sha256", e.ArgsSHA256}, {"result", e.Result}}
	for _, f := range strs {
		ev[f.k] = nil
		if f.v != nil {
			if err := text(f.k, *f.v); err != nil {
				return nil, err
			}
			ev[f.k] = *f.v
		}
	}
	ev["tier"] = nil
	if e.Tier != nil {
		if *e.Tier < 0 || *e.Tier > 3 {
			return nil, errors.New("tier is 0 to 3")
		}
		ev["tier"] = json.Number(strconv.Itoa(*e.Tier))
	}
	if e.Decision != nil && *e.Decision != "allow" && *e.Decision != "deny" {
		return nil, errors.New("decision is allow or deny")
	}
	if e.ArgsSHA256 != nil && !hexDigest.MatchString(*e.ArgsSHA256) {
		return nil, errors.New("args_sha256 is 64 lowercase hex")
	}
	for _, f := range []struct {
		k string
		v *string
	}{{"app", e.App}, {"reason", e.Reason}, {"coverage", e.Coverage}, {"scope", e.Scope}} {
		if f.v != nil {
			if err := text(f.k, *f.v); err != nil {
				return nil, err
			}
			ev[f.k] = *f.v
		}
	}
	if e.Tool != nil {
		if kind != OutageKind {
			return nil, fmt.Errorf("tool is set on a %s record only (a %s record's tool is its kind)", OutageKind, kind)
		}
		if err := text("tool", *e.Tool); err != nil {
			return nil, err
		}
		ev["tool"] = *e.Tool
	} else if kind == OutageKind {
		ev["tool"] = nil
	}
	if e.Intent != nil {
		ev["intent"] = *e.Intent // evidence.Seal caps and redacts it
	}
	for _, f := range []struct {
		k string
		v map[string]any
	}{{"subject", e.Subject}, {"initiator", e.Initiator}, {"source", e.Source}, {"destination", e.Destination},
		{"change", e.Change}, {"release", e.Release}, {"effect", e.Effect}, {"outcome", e.Outcome}, {"exception", e.Exception},
		{"outage", e.Outage}, {"resource", e.Resource}, {"actor", e.Actor}, {"action", e.Action},
		{"state_change", e.StateChange}, {"correlation", e.Correlation}, {"integrity", e.Integrity}, {"times", e.Times},
		{"health", e.Health}, {"about", e.About}, {"rule_set", e.RuleSet}, {"attribution", e.Attribution},
		{"resolution", e.Resolution}, {"verification", e.Verification}} {
		if f.v != nil {
			ev[f.k] = f.v
		}
	}
	if err := normalizeRelease(kind, ev); err != nil {
		return nil, err
	}
	if err := e.recorderFields(kind, ev); err != nil {
		return nil, err
	}
	for _, k := range spec.required {
		switch v := ev[k].(type) {
		case nil:
			return nil, fmt.Errorf("a %s record carries %s", kind, k)
		case string:
			if v == "" {
				return nil, fmt.Errorf("a %s record carries %s", kind, k)
			}
		}
	}
	if (e.Exception != nil && kind != gate.KindException) || (e.Outage != nil && kind != gate.KindDegraded) {
		return nil, fmt.Errorf("exception is a %s field and outage a %s field", gate.KindException, gate.KindDegraded)
	}
	return ev, nil
}

// normalizeRelease makes release {id} the one place a deploy.outcome names its release (G-ARGO-6). A provider that
// sent change.release.id (the Argo CD agent before this) is accepted: the id is copied to release, and the record
// carries both, as sent. release is a deploy.outcome field, {id} only, and the id a bounded, non-empty string.
func normalizeRelease(kind string, ev store.Event) error {
	rel, _ := ev["release"].(map[string]any)
	if rel == nil {
		if ch, _ := ev["change"].(map[string]any); ch != nil {
			if old, _ := ch["release"].(map[string]any); old != nil && kind == "deploy.outcome" {
				rel = map[string]any{"id": old["id"]}
				ev["release"] = rel
			}
		}
	}
	if rel == nil {
		return nil
	}
	if kind != "deploy.outcome" {
		return errors.New("release is a deploy.outcome field")
	}
	id, ok := rel["id"].(string)
	if !ok || id == "" || len(rel) != 1 {
		return errors.New("release is {id}: the id a non-empty string")
	}
	return text("release.id", id)
}

// checkOutageRead holds a tool.call record to what the outage policy allows a provider to run without the core: a
// T0 tool the core knows, allowed, coverage-unavailable, and nothing that would read as the core's decision (a
// rule) or as a write (an effect, an outcome, a change). The record's subject is derived from tool and args_sha256
// (a tool-call digest) and is claimed, like every field but provider and ts.
func (s *Server) checkOutageRead(e *ProviderEvent) error {
	if *e.Coverage != CoverageUnavailable {
		return fmt.Errorf("a %s record is an outage read: coverage is %s", OutageKind, CoverageUnavailable)
	}
	spec := s.opt.Engine.Tool(*e.Tool)
	switch {
	case spec == nil:
		return fmt.Errorf("%s is not a tool the core knows", *e.Tool)
	case spec.Tier != 0:
		return fmt.Errorf("%s is a T%d tool: only a T0 read may run without the core's decision", *e.Tool, spec.Tier)
	case *e.Tier != 0:
		return fmt.Errorf("a %s record's tier is 0 (an outage read is a T0 read)", OutageKind)
	case e.Decision != nil && *e.Decision != "allow":
		return fmt.Errorf("a %s record is a read that ran: decision is allow", OutageKind)
	case e.Rule != nil:
		return fmt.Errorf("a %s record carries no rule: the core decided nothing", OutageKind)
	case e.Subject != nil:
		return fmt.Errorf("a %s record's subject is the core's to derive (tool and args_sha256)", OutageKind)
	case e.Effect != nil || e.Outcome != nil || e.Change != nil:
		return fmt.Errorf("a %s record is a read: no effect, outcome or change", OutageKind)
	}
	return nil
}

// checkFederated holds a federated.decision to what an observer can say: another PDP's verdict, always
// observed-not-attributed (a task_id it correlated is a claim; authorized-and-verified would say Clearance knows the
// call was authorized), and nothing that would read as the core's decision (a rule or tier) or as a write (an
// effect, an outcome, a change). A tool is refused before this, by event (only tool.call carries one).
func checkFederated(e *ProviderEvent) error {
	switch {
	case *e.Coverage != CoverageObserved:
		return fmt.Errorf("a %s record's coverage is %s, want %s: another PDP decided, and its correlation is "+
			"claimed", FederatedKind, *e.Coverage, CoverageObserved)
	case e.Rule != nil || e.Tier != nil:
		return fmt.Errorf("a %s record carries no rule or tier: the core decided nothing", FederatedKind)
	case e.Effect != nil || e.Outcome != nil || e.Change != nil:
		return fmt.Errorf("a %s record is a decision: no effect, outcome or change", FederatedKind)
	}
	return nil
}

func text(k, v string) error {
	if len(v) > MaxFieldText || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
		return fmt.Errorf("%s is a string of at most %d bytes", k, MaxFieldText)
	}
	return nil
}

func (s *Server) records(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.caller(w, r)
	if !ok {
		return
	}
	var body RecordRequest
	if err := strictDecode(r.Body, &body); err != nil {
		bodyError(w, err)
		return
	}
	var prov *Provider
	for i := range s.opt.Providers {
		if s.opt.Providers[i].Name == body.Provider {
			prov = &s.opt.Providers[i]
		}
	}
	if prov == nil || !prov.matches(p.ID) {
		writeError(w, http.StatusForbidden, fmt.Sprintf("%s is not the registered provider %q", p.ID, body.Provider))
		return
	}
	spec, known := recordKinds[body.Kind]
	if !known {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("kind %q is not one of %v", body.Kind, RecordKinds))
		return
	}
	if !prov.mayWrite(body.Kind) {
		writeError(w, http.StatusForbidden, fmt.Sprintf("provider %q may not write %s records", prov.Name, body.Kind))
		return
	}
	ev, err := body.Record.event(body.Kind, spec, evidence.ISO(s.opt.Clock()))
	if err == nil && body.Kind == OutageKind {
		err = s.checkOutageRead(&body.Record)
	}
	if err == nil && body.Kind == FederatedKind {
		err = checkFederated(&body.Record)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := observe.Check(body.Kind, ev, vocab.Get())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	wr := prov.Writer()
	wr.Verified = recordVerified
	var rec store.Record
	if source, id, keyed := eventKey(ev); keyed {
		// The provider's own event id: de-duplicate (O-1, closes R-9). The lock makes the check and the write one step.
		s.eventMu.Lock()
		defer s.eventMu.Unlock()
		prior, err := s.opt.Store.EventRecord(r.Context(), prov.Name, body.Kind, source, id)
		switch {
		case err == nil:
			ref := refOf(prior)
			ref.Duplicate = true
			writeJSON(w, http.StatusOK, ref)
			return
		case !errors.Is(err, store.ErrNotFound):
			s.log.ErrorContext(r.Context(), "records: reading the event failed", "error", err.Error())
			writeError(w, http.StatusServiceUnavailable, "the record could not be recorded")
			return
		}
	}
	if observe.Is(body.Kind) {
		err = s.opt.Store.Atomic(r.Context(), func(tx store.Tx) error {
			var err error
			rec, err = s.appendObserved(r.Context(), tx, body.Kind, ev, wr, res)
			return err
		})
	} else if gate.IsReport(body.Kind) {
		// An exception or an outage report: the gate checks it, records it and acts on the change it names in one
		// transaction (gate.Service.Report). A core without the gate still checks its shape.
		if s.opt.Gate != nil {
			rec, err = s.opt.Gate.Report(r.Context(), ev, wr)
		} else if err = gate.CheckReport(ev, s.opt.Clock()); err == nil {
			err = s.opt.Store.Atomic(r.Context(), func(tx store.Tx) error {
				var err error
				rec, err = tx.Append(r.Context(), ev, wr)
				return err
			})
		}
	} else if body.Kind == "deploy.outcome" && s.opt.Gate != nil {
		// The gate appends it and sets the outcome of the change it names (the clearance view shows it).
		rec, err = s.opt.Gate.RecordOutcome(r.Context(), ev, wr)
	} else {
		err = s.opt.Store.Atomic(r.Context(), func(tx store.Tx) error {
			var err error
			rec, err = tx.Append(r.Context(), ev, wr)
			return err
		})
	}
	var br *gate.BadReport
	switch {
	case errors.As(err, &br):
		writeError(w, http.StatusBadRequest, br.Message)
		return
	case errors.Is(err, evidence.ErrInvalid), errors.Is(err, evidence.ErrNotStorable), errors.Is(err, evidence.ErrEnvelopeField):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "records: recording failed", "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the record could not be recorded")
		return
	}
	if body.Kind == "deploy.outcome" && s.opt.OnOutcome != nil {
		s.opt.OnOutcome(rec)
	}
	writeJSON(w, http.StatusOK, refOf(rec))
}

// recordVerified: provider (the caller authenticated as it) and ts (the core's clock). Everything else is claimed.
var recordVerified = union(evidence.ProviderVerified, "ts")
