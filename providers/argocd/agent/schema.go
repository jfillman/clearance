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

const (
	schemaRecheck = 5 * time.Minute // when the schema was read and lacks fields
	// schemaFailedFor is how long the check must fail continuously before it is reported, and schemaReportEvery how often the
	// same condition is reported again.
	schemaFailedFor    = 5 * time.Minute
	schemaReportEvery  = 24 * time.Hour
	schemaBackoffLimit = 5 * time.Minute
)

type schemaState struct {
	checked  bool
	ok       bool      // the opt-in may run
	lastGood bool      // this process has read a schema that has every field
	nextTry  time.Time // not before, while not ok
	fails    int       // consecutive failed reads
	badSince time.Time // when the check began failing, continuously
}

// optInSchemaOK says whether the opt-in may run. force reads the CRD again now.
//
// A schema that IS missing fields is an answer: the opt-in is off and the CRD is read again in five minutes. A read that
// FAILED (forbidden, a timeout, the API briefly down) is not an answer about the schema: with a good answer already in this
// process the opt-in keeps running on it; with none, the opt-in is off and the read is retried at the ordinary pass interval
// with a backoff up to five minutes (not five minutes after the first failure).
func (a *Agent) optInSchemaOK(ctx context.Context, force bool) bool {
	a.schemaMu.Lock()
	defer a.schemaMu.Unlock()
	st := a.schema
	if st.checked && !force && (st.ok || a.now().Before(st.nextTry)) {
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
	st.checked = true
	switch {
	case err == nil && len(missing) == 0:
		st = schemaState{checked: true, ok: true, lastGood: true}
	case err != nil:
		st.fails++
		back := a.cfg.GrantInterval << min(st.fails-1, 4)
		if back > schemaBackoffLimit {
			back = schemaBackoffLimit
		}
		st.nextTry = a.now().Add(back)
		if st.lastGood { // the last good answer stands for this process
			a.log.Warn("the ClearanceGrant CRD cannot be read; the last good answer stands", "err", err)
			a.schema = st
			return true
		}
		st.ok = false
	default:
		st.ok, st.lastGood, st.fails = false, false, 0
		st.nextTry = a.now().Add(schemaRecheck)
	}
	if !st.ok && st.badSince.IsZero() {
		st.badSince = a.now()
	}
	a.schema = st
	if st.ok {
		return true
	}
	why := "the ClearanceGrant CRD lacks the fields the opt-in writes: " + strings.Join(missing, ", ") +
		" (apply the CRD first, then the agent, then optIn.enabled; docs/gate.md)"
	fp := "schema|" + strings.Join(missing, ",")
	if err != nil {
		why = "the ClearanceGrant CRD cannot be read, so the opt-in is not run: " + truncate(err.Error(), 200)
		fp = "schema|unreadable"
	}
	a.log.Error("the opt-in is not running", "why", why)
	// Reported only once it has failed for five minutes without a good read between, and at most once a day for the same
	// condition (a flapping API does not post one per flap).
	if a.now().Sub(st.badSince) >= schemaFailedFor {
		if rerr := a.reportEvery(ctx, fp, schemaReportEvery, "ClearanceGrant CRD missing opt-in fields", why,
			[]map[string]any{{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "name": a.cfg.GrantCRD}}); rerr != nil {
			a.log.Warn("the CRD problem could not be reported", "err", rerr)
		}
	}
	return false
}

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

// reportEvery is reportOnce with a repeat: the exception is posted again when it was last posted more than every ago.
func (a *Agent) reportEvery(ctx context.Context, fp string, every time.Duration, result, detail string, objs []map[string]any) error {
	a.mu.Lock()
	last, ok := a.st.Once[fp]
	a.mu.Unlock()
	if ok {
		if t, err := time.Parse(time.RFC3339, last); err == nil && a.now().Sub(t) < every {
			return nil
		}
		a.mu.Lock()
		delete(a.st.Once, fp)
		a.mu.Unlock()
	}
	return a.reportOnce(ctx, fp, result, detail, objs)
}
