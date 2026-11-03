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
// run lifecycle and people's answers and controls (the Autopilot gateway), and the deployment boundary's outcome
// and exceptions (a deployment-gate provider such as the Argo sync).
var RecordKinds = []string{"session.open", "run.launch", "run.delete", "human.answer", "session.freeze",
	"trigger.hold", "deploy.outcome", "deploy.exception"}

// kindSpec is what each kind must carry, and its boundary.
type kindSpec struct {
	required []string
	boundary string
}

var recordKinds = map[string]kindSpec{
	"session.open":     {[]string{"session", "task_id", "principal", "agent", "result"}, "runtime"},
	"run.launch":       {[]string{"session", "principal", "agent", "result"}, "runtime"},
	"run.delete":       {[]string{"session", "principal", "agent", "result"}, "runtime"},
	"human.answer":     {[]string{"principal", "target", "result"}, "runtime"},
	"session.freeze":   {[]string{"session", "principal", "agent", "result"}, "runtime"},
	"trigger.hold":     {[]string{"principal", "agent", "target", "result"}, "runtime"},
	"deploy.outcome":   {[]string{"app", "target", "outcome"}, "deployment"},
	"deploy.exception": {[]string{"principal", "target", "result"}, "deployment"},
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
	TaskID     *string `json:"task_id,omitempty"`
	Session    *string `json:"session,omitempty"`
	Parent     *string `json:"parent,omitempty"`
	Principal  *string `json:"principal,omitempty"`
	Agent      *string `json:"agent,omitempty"`
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
