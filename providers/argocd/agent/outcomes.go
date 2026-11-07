package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jfillman/clearance/client"
)

func (a *Agent) protectedProject(p string) bool {
	return slices.Contains(a.cfg.Projects, "*") || slices.Contains(a.cfg.Projects, p)
}

// RunOutcomes lists the Applications, handles each, and watches them from the list's resourceVersion. A watch ends
// at ResyncEvery, on a break or when its version is gone; the loop lists again, so a restarted agent (or a post that
// failed) catches up from state, and nothing waits for a notification that was lost (docs/gate.md, "The outcome
// source").
func (a *Agent) RunOutcomes(ctx context.Context) {
	first := true
	for ctx.Err() == nil {
		apps, rv, err := a.kube.ListApplications(ctx)
		if err != nil {
			a.log.Warn("listing the Applications failed", "err", err)
			sleep(ctx, 5*time.Second)
			continue
		}
		for _, app := range apps {
			a.handleApp(ctx, app, first && a.cfg.RepostOnStart)
		}
		first = false
		wctx, cancel := context.WithTimeout(ctx, a.cfg.ResyncEvery)
		err = a.kube.WatchApplications(wctx, rv, func(app Application) { a.handleApp(ctx, app, false) })
		cancel()
		if err != nil && ctx.Err() == nil && !errors.Is(err, ErrWatchGone) && !errors.Is(err, context.DeadlineExceeded) {
			a.log.Warn("the Application watch ended", "err", err)
			sleep(ctx, 2*time.Second)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// OperationKey names one operation of one Application: its UID and the operation's start time.
func OperationKey(app Application) string {
	if app.Op == nil {
		return ""
	}
	return app.UID + "@" + app.Op.StartedAt
}

// HandleApplication is handleApp for a caller that drives the agent step by step (the conformance test).
func (a *Agent) HandleApplication(ctx context.Context, app Application) error {
	return a.handleApp(ctx, app, false)
}

func (a *Agent) handleApp(ctx context.Context, app Application, force bool) error {
	if !a.protectedProject(app.Project) || app.Op == nil || !Terminal(app.Op.Phase) || app.Op.StartedAt == "" {
		return nil
	}
	appKey, opKey := app.Namespace+"/"+app.Name, OperationKey(app)
	a.mu.Lock()
	done := a.st.Outcomes[appKey] == opKey
	a.mu.Unlock()
	var errs []error
	if !done || force {
		if err := a.postOutcome(ctx, app, appKey, opKey); err != nil {
			a.log.Warn("outcome not posted (retried on the next list)", "app", appKey, "err", err)
			errs = append(errs, err)
		}
	}
	if err := a.reportRefusedSync(ctx, app, opKey); err != nil {
		a.log.Warn("refused sync not reported (retried on the next list)", "app", appKey, "err", err)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// tracked are the live objects Argo CD tracks to app in its destination namespace.
func (a *Agent) tracked(ctx context.Context, app Application) ([]ObjectDetail, error) {
	var out []ObjectDetail
	for _, r := range a.cfg.Resources {
		objs, err := a.kube.ListObjects(ctx, r, app.DestNS)
		if err != nil {
			return nil, fmt.Errorf("listing %s in %s: %w", r.Plural, app.DestNS, err)
		}
		for _, o := range objs {
			if strings.HasPrefix(o.Annotations[AnnTracking], app.Name+":") {
				out = append(out, o)
			}
		}
	}
	return out, nil
}

// stampOf is what the stamped annotations of objs agree on: the one value every stamped object carries, or "" when
// none carries one or they disagree (mixed is then true).
func stampOf(objs []ObjectDetail, ann string) (v string, mixed bool) {
	for _, o := range objs {
		x := o.Annotations[ann]
		if x == "" {
			continue
		}
		if v != "" && v != x {
			return "", true
		}
		v = x
	}
	return v, false
}

// releaseOf is the release id every stamped object agrees on; mixed when two objects name different ones (no id is
// then reported: the objects are not one release).
func releaseOf(objs []ObjectDetail) (id string, mixed bool) {
	for _, o := range objs {
		v := o.Annotations[AnnRelease]
		if v == "" {
			v = o.Labels[AnnRelease]
		}
		if v == "" {
			continue
		}
		if id != "" && id != v {
			return "", true
		}
		id = v
	}
	return id, false
}

func trimSHA(s string) string { return strings.TrimPrefix(s, "sha256:") }

func firstRevision(r []string) string {
	if len(r) == 0 {
		return ""
	}
	return r[0]
}

// OutcomeRecord is the deploy.outcome for a finished operation, with what the live objects' stamps say was applied.
// It is exported for the tests.
func (a *Agent) OutcomeRecord(ctx context.Context, app Application) (*client.RecordRequest, error) {
	objs, err := a.tracked(ctx, app)
	if err != nil {
		return nil, err
	}
	op := app.Op
	tree, mixed := stampOf(objs, AnnTree)
	change, mixedChange := stampOf(objs, AnnGrant)
	rev := firstRevision(op.Revisions)
	if rev == "" {
		rev = firstRevision(app.Revisions)
	}
	applied := op.Phase == "Succeeded"
	result := "applied"
	if !applied {
		result = "failed"
	}
	out := map[string]any{"applied": applied, "phase": op.Phase, "observed_revision": rev,
		"revisions": op.Revisions, "sync_status": app.SyncState, "health": app.Health,
		"started_at": op.StartedAt, "finished_at": op.FinishedAt, "objects": len(objs)}
	if op.Message != "" {
		out["message"] = truncate(op.Message, 1000)
	}
	if tree != "" {
		out["digests"] = map[string]any{"sha256": trimSHA(tree)}
	}
	if mixed || mixedChange {
		out["mixed_stamps"] = true // the tracked objects carry different trees or grants: not one clearance
	}
	change_ := map[string]any{}
	if change != "" {
		change_["id"] = change
	}
	if tree != "" {
		change_["tree"] = "sha256:" + trimSHA(tree)
	}
	rel, mixedRel := releaseOf(objs)
	if mixedRel {
		out["mixed_stamps"] = true
	}
	if rel != "" {
		change_["release"] = map[string]any{"id": rel}
	}
	src := map[string]any{"provider": a.Provider(), "operation": OperationKey(app), "application": app.Namespace + "/" + app.Name}
	req := &client.RecordRequest{Kind: "deploy.outcome", Record: client.ProviderEvent{
		App:    client.String(app.Name),
		Target: client.String(fmt.Sprintf("%s/%s@%s", app.DestNS, app.Name, rev)),
		Result: client.String(result),
		Destination: map[string]any{"cluster": a.cfg.Cluster, "environment": a.environment(ctx, app.DestNS),
			"application": app.Name, "namespace": app.DestNS},
		Outcome: out, Source: src}}
	if len(change_) > 0 {
		req.Record.Change = change_
	}
	if tree != "" {
		req.Record.Subject = map[string]any{"kind": "manifest-tree", "name": app.Name,
			"digests": map[string]any{"sha256": trimSHA(tree)}}
	}
	return req, nil
}

func (a *Agent) environment(ctx context.Context, ns string) string {
	if p, err := a.kube.ProtectedNamespaces(ctx); err == nil {
		if e := p[ns][LabelEnvironment]; e != "" {
			return e
		}
	}
	return a.cfg.Environment
}

func (a *Agent) postOutcome(ctx context.Context, app Application, appKey, opKey string) error {
	req, err := a.OutcomeRecord(ctx, app)
	if err != nil {
		return err
	}
	ref, err := a.core.Record(ctx, req)
	if err != nil {
		return fmt.Errorf("posting deploy.outcome: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st.Outcomes[appKey] = opKey
	a.log.Info("outcome posted", "app", appKey, "operation", opKey, "phase", app.Op.Phase, "seq", ref.Seq)
	return a.saveLocked(ctx)
}
