package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/client"
)

// The installed ClearanceGrant CRD must carry the fields the opt-in writes. An API server prunes what the schema lacks, so
// with an older CRD the merged grant silently loses `app` (the incumbent of every key) and `expiresAt` (each object's own
// expiry): contested keys would be dropped for both Applications, and the stored spec would never equal the desired one.
// So the agent reads the CRD's schema at its first opt-in pass, and again when a held merged grant looks pruned; if a field
// is missing it does not run the opt-in at all (per-change grants go on as before), logs an error, and reports it once.

// requiredGrantFields are the schema fields the opt-in needs.
var requiredGrantFields = []string{"objects.app", "objects.expiresAt", "carried.app"}

const schemaRecheck = 5 * time.Minute

type schemaState struct {
	checked bool
	ok      bool
	at      time.Time
}

// optInSchemaOK says whether the opt-in may run. force reads the CRD again now.
func (a *Agent) optInSchemaOK(ctx context.Context, force bool) bool {
	a.schemaMu.Lock()
	defer a.schemaMu.Unlock()
	st := a.schema
	if st.checked && !force && (st.ok || a.now().Sub(st.at) < schemaRecheck) {
		return st.ok
	}
	fields, err := a.kube.GrantSchemaFields(ctx)
	var missing []string
	if err == nil {
		for _, f := range requiredGrantFields {
			if !fields[f] {
				missing = append(missing, f)
			}
		}
	}
	a.schema = schemaState{checked: true, ok: err == nil && len(missing) == 0, at: a.now()}
	const fp = "schema"
	switch {
	case a.schema.ok:
		a.forgetOnce(ctx, fp)
	default:
		why := "the ClearanceGrant CRD lacks the fields the opt-in writes: " + strings.Join(missing, ", ") +
			" (apply the CRD first, then the agent, then optIn.enabled; docs/gate.md)"
		if err != nil {
			why = "the ClearanceGrant CRD cannot be read, so the opt-in is not run: " + truncate(err.Error(), 200)
		}
		a.log.Error("the opt-in is not running", "why", why)
		if rerr := a.reportOnce(ctx, fp+"|"+strings.Join(missing, ","), "ClearanceGrant CRD missing opt-in fields", why,
			[]map[string]any{{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "name": a.cfg.GrantCRDName()}}); rerr != nil {
			a.log.Warn("the CRD problem could not be reported", "err", rerr)
		}
	}
	return a.schema.ok
}

// GrantCRDName is the CRD's name, for the report.
func (c *Config) GrantCRDName() string { return "clearancegrants.clearance.hangar.io" }

// suspectPruned says whether a held merged grant looks pruned: it has objects and none names an owner, which the agent
// always writes.
func suspectPruned(have []Grant) bool {
	for _, g := range have {
		if g.Name != MergedGrantName || len(g.Spec.Objects) == 0 {
			continue
		}
		named := false
		for _, o := range g.Spec.Objects {
			if o.App != "" {
				named = true
			}
		}
		if !named {
			return true
		}
	}
	return false
}

// reportOnce posts a deploy.exception (out-of-band, the existing path) for a condition the opt-in found, once: the
// fingerprint is kept in the state until forgetOnce says the condition has gone.
func (a *Agent) reportOnce(ctx context.Context, fp, result, detail string, objs []map[string]any) error {
	a.mu.Lock()
	_, done := a.st.Once[fp]
	a.mu.Unlock()
	if done {
		return nil
	}
	if len(objs) == 0 {
		return fmt.Errorf("agent: an exception names an object")
	}
	req := &client.RecordRequest{Kind: "deploy.exception", Record: client.ProviderEvent{
		Principal:   client.String("argocd-agent (opt-in)"),
		Target:      client.String(truncate(result, 200)),
		App:         client.String("clearance-argocd-agent"),
		Result:      client.String(truncate(result, 200)),
		Destination: map[string]any{"cluster": a.cfg.Cluster, "environment": a.cfg.Environment},
		Source:      map[string]any{"provider": a.Provider()},
		Exception: map[string]any{"kind": "out-of-band", "objects": objs, "detected_at": a.now().UTC().Format(time.RFC3339),
			"detail": truncate(detail, 1000)}}}
	if _, err := a.core.Record(ctx, req); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st.Once[fp] = a.now().UTC().Format(time.RFC3339)
	return a.saveLocked(ctx)
}

// forgetOnce forgets every once-reported condition whose fingerprint starts with prefix (the condition has gone).
func (a *Agent) forgetOnce(ctx context.Context, prefix string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var drop []string
	for k := range a.st.Once {
		if strings.HasPrefix(k, prefix) {
			drop = append(drop, k)
		}
	}
	sort.Strings(drop)
	for _, k := range drop {
		delete(a.st.Once, k)
	}
	if len(drop) > 0 {
		_ = a.saveLocked(ctx)
	}
}
