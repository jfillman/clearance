package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/evidence"
)

// Limits of PUT /v1/definitions.
const (
	MaxDefinitionsBody = 4 << 20
	MaxPins            = 256
	MaxPinText         = 1 << 10
)

// DefinitionsRequest is PUT /v1/definitions's body: the provider's whole set of cluster-pinned agent definitions,
// as its Agent XR loader found them (autopilot agent_xrs.py, the hand-off to apply_cluster_definitions). It
// replaces the set the core holds. provider must be the provider the caller authenticates as, registered with
// definitions: true.
type DefinitionsRequest struct {
	Provider string `json:"provider" contract:"required"`
	// Pins are the pins the provider fetched: each pinned file's document, where it came from, and its Agent XR's
	// spec.owner. The core decides each one itself (definitions.FromPin: the agent-definition schema, the name, the
	// owner, the workload identity, not a bundled name); one it refuses is a rejection.
	Pins []PinnedDefinition `json:"pins" contract:"required"`
	// Rejected are the pins the provider could not load itself (an incomplete spec.source, a file the broker
	// refused), each with its reason.
	Rejected []RejectedPin `json:"rejected,omitempty"`
}

// PinnedDefinition is one fetched pin.
type PinnedDefinition struct {
	Source PinSource `json:"source" contract:"required"`
	// Owner is the Agent XR's spec.owner; the document's owner must be the same.
	Owner string         `json:"owner" contract:"required"`
	Doc   map[string]any `json:"doc" contract:"required"`
}

// PinSource is where a pin came from (definitions.Source, kind cluster): the XR's namespace and name, and the
// repository, path and commit it pins. loaded_at is when the provider fetched it.
type PinSource struct {
	Repo      *string `json:"repo,omitempty"`
	Path      *string `json:"path,omitempty"`
	Commit    *string `json:"commit,omitempty"`
	Namespace *string `json:"namespace,omitempty"`
	XR        *string `json:"xr,omitempty"`
	LoadedAt  *string `json:"loaded_at,omitempty"`
}

// RejectedPin is a pin the provider could not load, and why.
type RejectedPin struct {
	Name   string    `json:"name" contract:"required"`
	Source PinSource `json:"source" contract:"required"`
	Reason string    `json:"reason" contract:"required"`
}

// DefinitionsResult is what the publish changed (definitions.Changes): names added, re-pinned and removed, the
// rejections that are new and the ones that cleared, and how many cluster definitions are now live. Each change is
// one definition.load, definition.unload or definition.reject record; a publish that changes nothing records
// nothing.
type DefinitionsResult struct {
	Added    []string                   `json:"added"`
	Changed  []string                   `json:"changed"`
	Removed  []string                   `json:"removed"`
	Rejected []definitions.RejectedView `json:"rejected"`
	Cleared  []definitions.RejectedView `json:"cleared"`
	Cluster  int                        `json:"cluster"`
}

var k8sName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?\z`)

// definitionVerified: what the core establishes on a definition record. It authenticated the caller (provider,
// caller), set ts, and chose the record (tool, decision, rule). The pin's own fields (principal, agent, target,
// args_sha256: its XR, repository, path and commit) and the result line built from them are the provider's
// claim: the core never fetched the file.
var definitionVerified = union(evidence.ProviderVerified, "ts", "caller", "tool", "tier", "decision", "rule",
	"task_id", "session", "parent")

func (s *Server) definitions(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.caller(w, r)
	if !ok {
		return
	}
	if s.opt.Definitions == nil || s.opt.ParseDefinition == nil {
		writeError(w, http.StatusNotFound, "this core keeps no published definitions")
		return
	}
	var body DefinitionsRequest
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
	if !prov.Definitions {
		writeError(w, http.StatusForbidden, fmt.Sprintf("provider %q may not publish definitions", prov.Name))
		return
	}
	loaded, rejected, err := s.decidePins(&body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	wr := s.coreWriter(definitionVerified)
	ch, err := s.opt.Definitions.ApplyWith(r.Context(), loaded, rejected, wr,
		map[string]any{"caller": callerField(prov, p)})
	if err != nil {
		s.log.ErrorContext(r.Context(), "definitions: publishing failed", "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the definitions could not be recorded")
		return
	}
	out := DefinitionsResult{Added: nonNil(ch.Added), Changed: nonNil(ch.Changed), Removed: nonNil(ch.Removed),
		Rejected: views(ch.Rejected), Cleared: views(ch.Cleared)}
	for _, row := range s.opt.Definitions.Registry.Records() {
		if row.State == "loaded" {
			out.Cluster++
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// decidePins checks the body's shape and decides every pin (definitions.FromPin, the core's own parser): a pin the
// core refuses becomes a rejection with the core's reason.
func (s *Server) decidePins(b *DefinitionsRequest) ([]definitions.Loaded, []definitions.Rejected, error) {
	if b.Pins == nil {
		return nil, nil, errors.New("pins is required (an empty list unpins everything)")
	}
	if len(b.Pins) > MaxPins || len(b.Rejected) > MaxPins {
		return nil, nil, fmt.Errorf("at most %d pins and %d rejections", MaxPins, MaxPins)
	}
	reg := s.opt.Definitions.Registry
	var loaded []definitions.Loaded
	var rejected []definitions.Rejected
	for i, pin := range b.Pins {
		src, err := pin.Source.source(true)
		if err != nil {
			return nil, nil, fmt.Errorf("pins[%d].source: %w", i, err)
		}
		if err := text("owner", pin.Owner); err != nil {
			return nil, nil, fmt.Errorf("pins[%d]: %w", i, err)
		}
		if pin.Doc == nil {
			return nil, nil, fmt.Errorf("pins[%d]: doc is the pinned file's document", i)
		}
		l, rej := definitions.FromPin(pin.Doc, src, pin.Owner, reg.Bundled, s.opt.ParseDefinition)
		if rej != nil {
			rejected = append(rejected, *rej)
		} else {
			loaded = append(loaded, *l)
		}
	}
	for i, rj := range b.Rejected {
		src, err := rj.Source.source(false)
		if err != nil {
			return nil, nil, fmt.Errorf("rejected[%d].source: %w", i, err)
		}
		if rj.Name == "" || len(rj.Name) > MaxPinText {
			return nil, nil, fmt.Errorf("rejected[%d]: name is 1 to %d bytes", i, MaxPinText)
		}
		if err := text("name", rj.Name); err != nil {
			return nil, nil, fmt.Errorf("rejected[%d]: %w", i, err)
		}
		if rj.Reason == "" {
			return nil, nil, fmt.Errorf("rejected[%d]: reason says why the pin did not load", i)
		}
		if err := text("reason", rj.Reason); err != nil {
			return nil, nil, fmt.Errorf("rejected[%d]: %w", i, err)
		}
		rejected = append(rejected, definitions.Rejected{Name: rj.Name, Source: src, Reason: rj.Reason})
	}
	return loaded, rejected, nil
}

// source is the pin's definitions.Source (kind cluster). A fetched pin (complete) names its XR, namespace,
// repository (owner/name), path and commit (hex); a rejected one may be missing any of them, which may be why it
// was rejected.
func (ps PinSource) source(complete bool) (definitions.Source, error) {
	fields := []struct {
		k string
		v *string
	}{{"repo", ps.Repo}, {"path", ps.Path}, {"commit", ps.Commit}, {"namespace", ps.Namespace}, {"xr", ps.XR},
		{"loaded_at", ps.LoadedAt}}
	for _, f := range fields {
		if f.v == nil {
			if complete && f.k != "loaded_at" {
				return definitions.Source{}, fmt.Errorf("%s is required", f.k)
			}
			continue
		}
		if len(*f.v) > MaxPinText {
			return definitions.Source{}, fmt.Errorf("%s is at most %d bytes", f.k, MaxPinText)
		}
		if err := text(f.k, *f.v); err != nil {
			return definitions.Source{}, err
		}
	}
	if complete {
		switch {
		case !repoRx.MatchString(*ps.Repo):
			return definitions.Source{}, errors.New("repo is owner/name")
		case *ps.Path == "":
			return definitions.Source{}, errors.New("path is the definition file's path")
		case !commitRx.MatchString(*ps.Commit):
			return definitions.Source{}, errors.New("commit is a hex commit sha")
		case !k8sName.MatchString(*ps.Namespace):
			return definitions.Source{}, errors.New("namespace is the Agent XR's namespace")
		case !k8sName.MatchString(*ps.XR):
			return definitions.Source{}, errors.New("xr is the Agent XR's name")
		}
	}
	return definitions.Source{Kind: "cluster", Repo: ps.Repo, Path: ps.Path, Commit: ps.Commit,
		Namespace: ps.Namespace, XR: ps.XR, LoadedAt: ps.LoadedAt}, nil
}

func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

func views(rs []definitions.Rejected) []definitions.RejectedView {
	out := make([]definitions.RejectedView, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.View())
	}
	return out
}
