// Package targets is the declared target registry (the Map's "what should be protected"): each source (a cluster's
// gitops render, an account's bootstrap) publishes the targets it declares with PUT /v1/targets/{source}, and GET
// /v1/targets on clearance-api serves the union. A target says what it is (kind, group, environment, owner), which
// coverage scope its observations arrive under, which gates guard it (type, instance, mode) and which observers
// watch it. The registry is a declaration, never evidence: the Map reconciles it with what the records show and
// reports a mismatch as an attention item, not an error.
package targets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"unicode/utf8"
)

// Limits of a published set.
const (
	MaxBody      = 4 << 20
	MaxTargets   = 2000 // per source
	MaxGates     = 32   // per target
	MaxObservers = 16   // per target
	MaxText      = 256  // any one text field, in bytes
)

// Kinds are a target's kinds.
var Kinds = []string{"k8s-namespace", "k8s-cluster", "aws-account", "github-environment", "other"}

// Gate modes: enforce refuses what it denies; flag records the refusal and lets it through.
const (
	ModeEnforce = "enforce"
	ModeFlag    = "flag"
)

// Modes are a gate's modes.
var Modes = []string{ModeEnforce, ModeFlag}

var (
	// SourceRx is a source name: the publisher (a cluster, an account), lower case.
	SourceRx   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	tierRx     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	idRx       = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,126}$`)
	typeRx     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	providerRx = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	printable  = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)
)

// Gate is one gate that guards a target: its type (the kind of gate: glidepath, g-argo, g-tf, agent, ...), its
// instance (the name its records carry: the registered provider's name, or the verifier principal that registers its
// changes) and its mode.
type Gate struct {
	Type     string `json:"type" contract:"required"`
	Instance string `json:"instance" contract:"required"`
	Mode     string `json:"mode" contract:"required"`
}

// Observer is one observer that watches a target: the registered provider that observes it and the source name its
// health records carry (observation.health's source.name).
type Observer struct {
	Provider string `json:"provider" contract:"required"`
	Source   string `json:"source" contract:"required"`
}

// Target is one declared target.
type Target struct {
	ID   string `json:"id" contract:"required"`
	Name string `json:"name" contract:"required"`
	Kind string `json:"kind" contract:"required"`
	// Group is the cluster or account the target belongs to; the Map groups by it.
	Group string `json:"group" contract:"required"`
	Env   string `json:"env,omitempty"`
	// App is the application the target runs (the `app` of the gate's records, which attributes decisions to the
	// target); Owner is the owning group.
	App   string `json:"app,omitempty"`
	Owner string `json:"owner,omitempty"`
	// Registry is the target's registry tier, a lower-case name the platform defines (its registries' tiers).
	Registry string `json:"registry,omitempty"`
	// Scope is the coverage scope the target's observations arrive under (GET /v1/coverage?scope=).
	Scope     string     `json:"scope,omitempty"`
	Gates     []Gate     `json:"gates" contract:"required"`
	Observers []Observer `json:"observers" contract:"required"`
}

// Set is a source's declared targets as stored: the sorted list and its digest.
type Set struct {
	Source    string   `json:"source"`
	Digest    string   `json:"digest"`
	Targets   []Target `json:"targets"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

func text(what, v string, required bool) error {
	if v == "" {
		if required {
			return fmt.Errorf("%s is required", what)
		}
		return nil
	}
	if len(v) > MaxText || !utf8.ValidString(v) {
		return fmt.Errorf("%s is a string of at most %d bytes", what, MaxText)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s has a control character", what)
		}
	}
	return nil
}

func in(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Validate checks a target strictly; the error names the field.
func (t *Target) Validate() error {
	switch {
	case !idRx.MatchString(t.ID):
		return fmt.Errorf("id is a lower-case name of at most 127 characters (%s)", idRx)
	case !in(Kinds, t.Kind):
		return fmt.Errorf("kind is one of %v", Kinds)
	case t.Registry != "" && !tierRx.MatchString(t.Registry):
		return fmt.Errorf("registry is a lower-case tier name (%s)", tierRx)
	case t.Scope != "" && !printable.MatchString(t.Scope):
		return errors.New("scope is the coverage scope: 1 to 256 printable ASCII characters, no spaces")
	case t.Gates == nil || t.Observers == nil:
		return errors.New("gates and observers are lists (empty when there are none)")
	case len(t.Gates) > MaxGates:
		return fmt.Errorf("at most %d gates", MaxGates)
	case len(t.Observers) > MaxObservers:
		return fmt.Errorf("at most %d observers", MaxObservers)
	}
	for _, f := range []struct {
		k, v string
		req  bool
	}{{"name", t.Name, true}, {"group", t.Group, true}, {"env", t.Env, false}, {"app", t.App, false},
		{"owner", t.Owner, false}} {
		if err := text(f.k, f.v, f.req); err != nil {
			return err
		}
	}
	seen := map[[2]string]bool{}
	for i, g := range t.Gates {
		switch {
		case !typeRx.MatchString(g.Type):
			return fmt.Errorf("gates[%d].type is a lower-case name (%s)", i, typeRx)
		case !printable.MatchString(g.Instance):
			return fmt.Errorf("gates[%d].instance is the name the gate's records carry: 1 to 256 printable ASCII characters", i)
		case !in(Modes, g.Mode):
			return fmt.Errorf("gates[%d].mode is one of %v", i, Modes)
		case seen[[2]string{g.Type, g.Instance}]:
			return fmt.Errorf("gates[%d]: %s/%s is listed twice", i, g.Type, g.Instance)
		}
		seen[[2]string{g.Type, g.Instance}] = true
	}
	seenObs := map[[2]string]bool{}
	for i, o := range t.Observers {
		switch {
		case !providerRx.MatchString(o.Provider):
			return fmt.Errorf("observers[%d].provider is a provider name (%s)", i, providerRx)
		case !SourceRx.MatchString(o.Source):
			return fmt.Errorf("observers[%d].source is a lower-case source name (%s)", i, SourceRx)
		case seenObs[[2]string{o.Provider, o.Source}]:
			return fmt.Errorf("observers[%d]: %s/%s is listed twice", i, o.Provider, o.Source)
		}
		seenObs[[2]string{o.Provider, o.Source}] = true
	}
	return nil
}

// Normalize validates the targets of one source, rejects a duplicate id and returns them sorted by id (the stored
// and digested order).
func Normalize(ts []Target) ([]Target, error) {
	if ts == nil {
		return nil, errors.New("targets is required (an empty list withdraws everything the source declared)")
	}
	if len(ts) > MaxTargets {
		return nil, fmt.Errorf("at most %d targets per source", MaxTargets)
	}
	out := make([]Target, len(ts))
	copy(out, ts)
	seen := map[string]bool{}
	for i := range out {
		if err := out[i].Validate(); err != nil {
			return nil, fmt.Errorf("targets[%d]: %w", i, err)
		}
		if seen[out[i].ID] {
			return nil, fmt.Errorf("targets[%d]: id %q is listed twice", i, out[i].ID)
		}
		seen[out[i].ID] = true
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Digest is the content address of a normalized set: sha256 of its canonical JSON (Go's encoding of the structs
// above, sorted by id, which is deterministic), as hex.
func Digest(ts []Target) string {
	b, _ := json.Marshal(ts)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
