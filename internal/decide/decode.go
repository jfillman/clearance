package decide

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/jfillman/clearance/internal/pycompat"
)

// MaxRequestBytes caps an evaluation request. The largest legitimate one is an airframe.validate call (20
// documents of 256 KiB) or an over-size artifact.put the policy must see to deny (R019 is over 1 MiB).
const MaxRequestBytes = 8 << 20

// ErrTooLarge is returned for a request over MaxRequestBytes.
var ErrTooLarge = errors.New("decide: evaluation request is too large")

// parsed is a request's decoded arguments.
type parsed struct {
	done bool
	m    *pycompat.Map
	err  error
}

// DecodeEvaluation reads one evaluation request: at most MaxRequestBytes, strictly (an unknown field, a second
// value, or a wrong type is an error), then validated. Every error is the caller's (HTTP 400).
func DecodeEvaluation(r io.Reader) (*EvaluationRequest, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxRequestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("decide: read: %w", err)
	}
	if len(data) > MaxRequestBytes {
		return nil, ErrTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	req := &EvaluationRequest{}
	if err := dec.Decode(req); err != nil {
		return nil, fmt.Errorf("decide: decode: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("decide: trailing data after the request")
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	m, err := parseArgs(req.Action.Properties.Args)
	if err != nil {
		return nil, err
	}
	req.args = parsed{done: true, m: m}
	return req, nil
}

func parseArgs(raw json.RawMessage) (*pycompat.Map, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return pycompat.NewMap(0), nil
	}
	v, err := pycompat.DecodeJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("decide: args: %w", err)
	}
	m, ok := v.(*pycompat.Map)
	if !ok {
		return nil, errors.New("decide: args must be a JSON object")
	}
	return m, nil
}

// argsMap is the request's arguments, decoded (once by DecodeEvaluation, or here for a request built in Go).
func (r *EvaluationRequest) argsMap() (*pycompat.Map, error) {
	if r.args.done {
		return r.args.m, r.args.err
	}
	m, err := parseArgs(r.Action.Properties.Args)
	if err != nil {
		return nil, &EvalError{Class: ErrClassValue, Err: err}
	}
	return m, nil
}

var (
	networks = map[string]int{"none": 0, "clearance": 1, "clearance+model": 2, "allowlist": 3}
	computes = map[string]int{"small": 0, "medium": 1, "large": 2, "gpu": 3}
)

func (l *Limits) validate() error {
	if _, ok := tierOf(l.TierCeiling); !ok {
		return fmt.Errorf("limits: bad tier_ceiling %q", l.TierCeiling)
	}
	if _, ok := networks[l.Network]; !ok {
		return fmt.Errorf("limits: bad network %q", l.Network)
	}
	if _, ok := computes[l.Compute]; !ok {
		return fmt.Errorf("limits: bad compute %q", l.Compute)
	}
	return nil
}

func (s *SessionState) validate() error {
	if s.ID == "" || s.Principal == "" || s.ExpiresAt.IsZero() {
		return errors.New("session: id, principal and expires_at are required")
	}
	return s.Limits.validate()
}

// validate checks what strict decoding cannot: the action, resource and subject agree, and the state an action
// reads is there.
func (r *EvaluationRequest) validate() error {
	if r.Subject.Type != "principal" || r.Subject.ID == "" {
		return errors.New("decide: subject must be a principal with an id")
	}
	if k := r.Subject.Properties.Kind; k != "user" && k != "workload" {
		return fmt.Errorf("decide: subject kind %q", k)
	}
	if t := r.Subject.Properties.TierCeiling; t < 0 || t > 3 {
		return errors.New("decide: subject tier_ceiling must be 0-3")
	}
	if r.Context.Now.IsZero() {
		return errors.New("decide: context.now is required")
	}
	want := map[string]string{ActionToolCall: ResourceTool, ActionSessionSpawn: ResourceTool,
		ActionModelCall: ResourceModel, ActionSessionOpen: ResourceAgent}[r.Action.Name]
	if want == "" {
		return fmt.Errorf("decide: unknown action %q", r.Action.Name)
	}
	if r.Resource.Type != want || r.Resource.ID == "" {
		return fmt.Errorf("decide: %s needs a %s resource", r.Action.Name, want)
	}
	if r.Action.Name == ActionSessionSpawn && r.Resource.ID != "run.spawn" {
		return errors.New("decide: session.spawn is a run.spawn call")
	}
	if r.Action.Name == ActionModelCall && r.Action.Properties.EstTokens == nil {
		return errors.New("decide: model.call needs est_tokens")
	}
	for _, s := range []*SessionState{r.Context.Session, r.Context.Live} {
		if s != nil {
			if err := s.validate(); err != nil {
				return fmt.Errorf("decide: %w", err)
			}
		}
	}
	if a := r.Context.Agent; a != nil {
		if err := a.Limits.validate(); err != nil {
			return fmt.Errorf("decide: agent: %w", err)
		}
	}
	if r.Action.Name == ActionSessionSpawn && r.Context.Session != nil && r.Context.NewSessionID == "" {
		return errors.New("decide: session.spawn needs new_session_id")
	}
	return nil
}
