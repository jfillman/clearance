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
	"github.com/jfillman/clearance/internal/store"
)

// RecordKinds are the records a registered provider writes itself (POST /v1/records): the runtime's session and
// run lifecycle and people's answers and controls (the Autopilot gateway), a T0 read the gateway allowed while the
// core was unreachable (tool.call, coverage-unavailable: the outage policy's outbox replay), and the deployment
// boundary's outcome and exceptions (a deployment-gate provider such as the Argo sync), and a decision another
// gateway's own policy decision point made (federated.decision: a federated runtime source such as the Traefik Hub
// adapter, internal/federate/traefikhub).
//
// definition.load, definition.unload and definition.reject are not among them: the core writes those itself when a
// provider publishes its pinned definitions (PUT /v1/definitions, definitions.Service.Apply), so there is one
// writer of each.
var RecordKinds = []string{"session.open", "run.launch", "run.delete", "run.finish", "human.answer",
	"session.freeze", "session.end", "trigger.hold", "trigger.release", "tool.call", "deploy.outcome",
	"deploy.exception", FederatedKind}

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
	"deploy.exception": {[]string{"principal", "target", "result"}, "deployment"},
	FederatedKind:      {[]string{"decision", "result", "coverage"}, "runtime"},
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
	Effect      map[string]any `json:"effect,omitempty"`
	Outcome     map[string]any `json:"outcome,omitempty"`
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
	}{{"app", e.App}, {"reason", e.Reason}, {"coverage", e.Coverage}} {
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
		{"change", e.Change}, {"effect", e.Effect}, {"outcome", e.Outcome}} {
		if f.v != nil {
			ev[f.k] = f.v
		}
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
	return ev, nil
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
		return fmt.Errorf("a %s record's coverage is %s: another PDP decided, and its correlation is claimed",
			FederatedKind, CoverageObserved)
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
	wr := prov.Writer()
	wr.Verified = recordVerified
	var rec store.Record
	err = s.opt.Store.Atomic(r.Context(), func(tx store.Tx) error {
		var err error
		rec, err = tx.Append(r.Context(), ev, wr)
		return err
	})
	switch {
	case errors.Is(err, evidence.ErrInvalid), errors.Is(err, evidence.ErrNotStorable), errors.Is(err, evidence.ErrEnvelopeField):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "records: recording failed", "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the record could not be recorded")
		return
	}
	writeJSON(w, http.StatusOK, refOf(rec))
}

// recordVerified: provider (the caller authenticated as it) and ts (the core's clock). Everything else is claimed.
var recordVerified = union(evidence.ProviderVerified, "ts")
