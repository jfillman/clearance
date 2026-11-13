package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/pycompat"
)

// Provider is one entry of CLEARANCE_PROVIDERS: a registered provider, the principals it authenticates as, and
// which of its own records it may write.
//
//	CLEARANCE_PROVIDERS='[{"name": "autopilot-gateway", "version": "0.3.27",
//	                       "principals": ["autopilot-system/clearance"]},
//	                      {"name": "argo-gate", "version": "0.1.0", "principals": ["hangar-prod/argocd/clearance-sync"],
//	                       "kinds": ["deploy.outcome", "deploy.exception"]}]'
//
// name is the record's provider.name (the schema's pattern; never "clearance", the core's own); version is
// provider.version. principals are fnmatch globs on the authenticated principal id; a caller is the first provider
// whose globs match it. kinds narrows which POST /v1/records kinds the provider may write (default: every kind of
// RecordKinds but the observation kinds, which a provider writes only when its kinds name them: a registered
// observed provider, O-1). intent_capture is "redacted" (default) or "full" for its records' intent text. definitions lets the
// provider publish its cluster-pinned agent definitions (PUT /v1/definitions; default false). At most one provider
// has it: a publish replaces the whole pinned set, so two publishers would undo each other. conformance is the
// conformance suite the provider passed, as `clearance conformance` reports it, with the date
// ("clearance-conformance/v1@2026-11-03"): stamped on every record it writes as provider.conformance.
type Provider struct {
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Conformance   string   `json:"conformance,omitempty"`
	Principals    []string `json:"principals"`
	Kinds         []string `json:"kinds,omitempty"`
	IntentCapture string   `json:"intent_capture,omitempty"`
	Definitions   bool     `json:"definitions,omitempty"`
	// Targets are the source names (globs) whose declared targets the provider may publish (PUT /v1/targets/{source},
	// the Map's registry): ["hangar-prod"], or ["*"]. A publish replaces only its own source's set, so several
	// providers may publish (each its own sources); a source belongs to the first provider that lists it.
	Targets []string `json:"targets,omitempty"`
}

var providerName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// MaxProvidersBytes caps CLEARANCE_PROVIDERS.
const MaxProvidersBytes = 64 << 10

// ParseProviders reads CLEARANCE_PROVIDERS: a JSON array of Provider, strictly decoded. "" is no providers (then
// no caller may evaluate or record).
func ParseProviders(v string) ([]Provider, error) {
	if v == "" {
		return nil, nil
	}
	if len(v) > MaxProvidersBytes {
		return nil, errors.New("CLEARANCE_PROVIDERS is too long")
	}
	var ps []Provider
	if err := strictDecode(bytes.NewReader([]byte(v)), &ps); err != nil {
		return nil, fmt.Errorf("CLEARANCE_PROVIDERS: %w", err)
	}
	seen := map[string]bool{}
	publisher := ""
	for i := range ps {
		p := &ps[i]
		switch {
		case !providerName.MatchString(p.Name):
			return nil, fmt.Errorf("CLEARANCE_PROVIDERS[%d]: name %q is not a provider name (%s)", i, p.Name, providerName)
		case p.Name == evidence.CoreProviderName:
			return nil, fmt.Errorf("CLEARANCE_PROVIDERS[%d]: %q is the core's own provider name", i, p.Name)
		case seen[p.Name]:
			return nil, fmt.Errorf("CLEARANCE_PROVIDERS: %q is listed twice", p.Name)
		case p.Version == "" || len(p.Version) > 64:
			return nil, fmt.Errorf("CLEARANCE_PROVIDERS[%d]: version is 1 to 64 characters", i)
		case len(p.Principals) == 0:
			return nil, fmt.Errorf("CLEARANCE_PROVIDERS[%d]: principals names no principal glob", i)
		case p.IntentCapture != "" && !slices.Contains(evidence.IntentCapture, p.IntentCapture):
			return nil, fmt.Errorf("CLEARANCE_PROVIDERS[%d]: intent_capture is one of %v", i, evidence.IntentCapture)
		case p.Conformance != "" && !evidence.ConformanceRx.MatchString(p.Conformance):
			return nil, fmt.Errorf("CLEARANCE_PROVIDERS[%d]: conformance %q is <suite>/v<n>[@YYYY-MM-DD], e.g. clearance-conformance/v1@2026-11-03",
				i, p.Conformance)
		}
		for _, g := range p.Principals {
			if g == "" {
				return nil, fmt.Errorf("CLEARANCE_PROVIDERS[%d]: an empty principal glob", i)
			}
		}
		for _, k := range p.Kinds {
			if _, ok := recordKinds[k]; !ok {
				return nil, fmt.Errorf("CLEARANCE_PROVIDERS[%d]: kind %q is not one of %v", i, k, RecordKinds)
			}
		}
		if p.Definitions {
			if publisher != "" {
				return nil, fmt.Errorf("CLEARANCE_PROVIDERS: %q and %q both have definitions: at most one provider "+
					"publishes the pinned definitions", publisher, p.Name)
			}
			publisher = p.Name
		}
		for _, g := range p.Targets {
			if g == "" || len(g) > 64 {
				return nil, fmt.Errorf("CLEARANCE_PROVIDERS[%d]: targets names source globs of 1 to 64 characters", i)
			}
		}
		seen[p.Name] = true
	}
	return ps, nil
}

// Writer is how this provider's own records are sealed: its name and version, and only provider verified.
func (p *Provider) Writer() evidence.Writer {
	return evidence.Writer{Provider: p.provider(), IntentCapture: p.IntentCapture, Verified: evidence.ProviderVerified}
}

func (p *Provider) provider() evidence.Provider {
	return evidence.Provider{Name: p.Name, Version: p.Version, Conformance: p.Conformance}
}

// mayPublishTargets says whether the provider may publish the source's declared targets.
func (p *Provider) mayPublishTargets(source string) bool { return pycompat.MatchAny(source, p.Targets) }

func (p *Provider) matches(principal string) bool { return pycompat.MatchAny(principal, p.Principals) }

func (p *Provider) mayWrite(kind string) bool {
	if len(p.Kinds) == 0 {
		return !observe.Is(kind)
	}
	return slices.Contains(p.Kinds, kind)
}

// ProviderFor is the registered provider a principal is (the first whose globs match), as the evidence record
// names it. The gate uses it for the records the core writes on a provider's behalf.
func ProviderFor(ps []Provider, principal string) (evidence.Provider, bool) {
	if p := providerFor(ps, principal); p != nil {
		return p.provider(), true
	}
	return evidence.Provider{}, false
}

// providerFor is the first provider whose globs match principal, or nil.
func providerFor(ps []Provider, principal string) *Provider {
	for i := range ps {
		if ps[i].matches(principal) {
			return &ps[i]
		}
	}
	return nil
}

// strictDecode decodes exactly one JSON value into v: unknown fields, trailing data and wrong types are errors;
// numbers in an `any` stay json.Number.
func strictDecode(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}
