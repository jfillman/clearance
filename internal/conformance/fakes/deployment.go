package fakes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/conformance"
)

// Deployment is a fake deployment provider, a deployment gate's shape (the Argo CD gate, the Terraform gate):
// it registers the change with its subject digest, holds while the change holds (polling, as the core serves no
// wait route yet), applies once on clear and only the cleared digest, refuses on deny, expiry or supersession, and
// reports a deploy.outcome with the digest it applied.
type Deployment struct {
	// ApplyBeforeClear is the broken variant: it applies as soon as it has registered the change.
	ApplyBeforeClear bool

	*control
}

// NewDeployment is a deployment provider named name at version.
func NewDeployment(name, version string) *Deployment {
	p := &Deployment{}
	p.control = newControl(conformance.Info{Name: name, Version: version, Roles: []string{conformance.RoleDeployment}},
		conformance.RoleDeployment)
	p.flow = p.deploy
	return p
}

// Handler serves the conformance control interface.
func (p *Deployment) Handler() http.Handler { return p.handler() }

// change is the part of the core's change view the provider reads.
type change struct {
	ID         string `json:"id"`
	App        string `json:"app"`
	Env        string `json:"env"`
	Cluster    string `json:"cluster"`
	Head       string `json:"head"`
	TreeDigest string `json:"tree_digest"`
	Target     string `json:"target"`
	State      string `json:"state"`
	Tier       int    `json:"tier"`
}

func (p *Deployment) deploy(ctx context.Context, a conformance.ApplyRequest, set func(func(*conformance.Status))) {
	poll := time.Duration(a.PollIntervalMS) * time.Millisecond
	if poll <= 0 {
		poll = time.Second
	}
	register := func() (change, error) {
		var c change
		_, err := p.post(ctx, a.Core.URL+"/v1/clearances", a.Core.Bearer, a.Change, &c)
		return c, err
	}
	fail := func(state, reason string) {
		set(func(s *conformance.Status) { s.State, s.Reason = state, reason })
	}

	c, err := register()
	if err != nil {
		// Unregistered is uncleared: fail closed.
		fail(conformance.StateRefused, "not registered: "+err.Error())
		return
	}
	set(func(s *conformance.Status) { s.ChangeID = c.ID })
	applied := false
	if p.ApplyBeforeClear {
		if _, err := p.applyTarget(ctx, a, a.Manifest); err == nil {
			applied = true
		}
	}

	// Hold: re-registering is idempotent by repo, PR and head and answers the change as it stands.
	for c.State == "holding" {
		set(func(s *conformance.Status) { s.State = conformance.StateHolding })
		select {
		case <-ctx.Done():
			fail(conformance.StateRefused, "gave up waiting: "+ctx.Err().Error())
			return
		case <-time.After(poll):
		}
		next, err := register()
		if err != nil {
			continue // a core that does not answer leaves the change held; keep waiting, never apply
		}
		c = next
	}
	if c.State != "cleared" {
		fail(conformance.StateRefused, "the change is "+c.State)
		return
	}

	// Release: only the content whose digest is the cleared subject, once.
	sum := sha256.Sum256([]byte(a.Manifest))
	digest := hex.EncodeToString(sum[:])
	if digest != strings.TrimPrefix(c.TreeDigest, "sha256:") {
		fail(conformance.StateRefused, "the rendered tree "+digest+" is not the cleared "+c.TreeDigest)
		return
	}
	if !applied {
		rc, err := p.applyTarget(ctx, a, a.Manifest)
		if err != nil {
			fail(conformance.StateFailed, "the target refused: "+err.Error())
			return
		}
		digest = rc.SHA256
	}

	// Outcome: deploy.outcome with the applied digest, bound to the change.
	ev := map[string]any{
		"app": c.App, "target": c.Target, "result": "applied",
		"change":      map[string]any{"id": c.ID, "tree": c.TreeDigest, "head": c.Head},
		"subject":     map[string]any{"kind": "manifest-tree", "name": c.App + "/" + c.Env, "digests": map[string]any{"sha256": digest, "gitCommit": c.Head}},
		"destination": map[string]any{"cluster": c.Cluster, "environment": c.Env, "application": c.App},
		"outcome":     map[string]any{"applied": true, "observed_revision": c.Head, "digests": map[string]any{"sha256": digest}},
	}
	body := map[string]any{"provider": a.Provider, "kind": "deploy.outcome", "record": ev}
	var ref conformance.RecordRef
	if _, err := p.post(ctx, a.Core.URL+"/v1/records", a.Core.Bearer, body, &ref); err != nil {
		fail(conformance.StateApplied, "applied; the outcome was not recorded: "+err.Error())
		return
	}
	set(func(s *conformance.Status) { s.State, s.Outcome = conformance.StateApplied, &ref })
}
