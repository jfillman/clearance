package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/observe"
)

// Check names, as they appear in the health record.
const (
	CheckWebhook  = "webhook-delivering"
	CheckPolicy   = "audit-policy-live"
	CheckMirror   = "audit-policy-mirror"
	CheckSecrets  = "secrets-metadata-only"
	CheckQueue    = "queue-draining"
	CheckPosting  = "records-posting"
	CheckWatch    = "watch-current"
	CheckGap      = "audit-gap"
	CheckLookups  = "lookups-fresh"
	CheckFiltered = "noise-filtered"
	heartbeatAnn  = "observe-k8s.clearance.hangar.io/beat"
	lookupsMaxAge = 5 // health intervals
	fallbackQuiet = 5 // health intervals a webhook with no heartbeat may be silent
)

// DeletedHistoryTTL is how long the history of a deleted object is kept for its delete's audit event. That event trails
// the watch by the webhook's batch wait and the queue's lag (the queue-draining check allows 5 minutes, a managed source's
// latency a few more), so an hour outlasts any lag the health check would not already be reporting, and the history of a
// delete is small.
const DeletedHistoryTTL = time.Hour

// HealthOnce is one pass of the health loop: it reports the gaps that expired, refreshes the lookups, works out what
// the collector can and cannot vouch for, and posts the observation.health record the core reads coverage from. The
// state is blind when the collector cannot show that the audit path delivers (no heartbeat through the live policy),
// degraded for the other failures, and healthy only with every check passing. A healthy record also clears a flip the
// pipeline made after an operation on monitoring (Pipeline.Healthy): the checks include a heartbeat that must have
// arrived after that operation.
func (c *Collector) HealthOnce(ctx context.Context) error {
	now := c.cfg.Now()
	var errs []error
	if len(c.cfg.Watches) > 0 {
		errs = append(errs, c.reportGaps(ctx, now))
	}
	if c.d.Lookups != nil {
		err := c.d.Lookups.Refresh(ctx)
		c.mu.Lock()
		c.lkErr = err
		c.mu.Unlock()
		if err != nil {
			c.cfg.Log.Warn("grants or break-glass windows not read; the last snapshot is used", "err", err)
		}
	}
	c.cache.Prune(now, DeletedHistoryTTL)
	checks := c.checks(ctx, now)
	state := observe.Healthy
	for _, ch := range checks {
		if ch.OK {
			continue
		}
		state = observe.Degraded
		if ch.Name == CheckWebhook || ch.Name == CheckPolicy {
			state = observe.Blind
			break
		}
	}
	snap := c.Counters()
	if !snap.empty() {
		checks = append(checks, HealthCheck{CheckFiltered, true, c.filteredDetail(snap, now)})
	}
	if _, err := c.d.Core.Record(ctx, healthRecord(c.cfg.Cluster, c.cfg.Source, state, checks, c.cfg.HealthInterval)); err != nil {
		return errors.Join(append(errs, fmt.Errorf("posting the health record: %w", err))...)
	}
	if state == observe.Healthy {
		c.pipe.Healthy(c.cfg.Cluster)
	}
	if !snap.empty() {
		errs = append(errs, c.clearReported(snap, now))
	}
	return errors.Join(errs...)
}

// filteredDetail is the counters as the packet reads them: per rule, with the rule set they were under, and the
// population the coverage statement counts. The window is [since, until).
func (c *Collector) filteredDetail(s Counters, now time.Time) string {
	type rule struct {
		Rule  string `json:"rule"`
		Count int    `json:"count"`
		Why   string `json:"why,omitempty"`
	}
	var rules []rule
	for r, n := range s.Filtered {
		rules = append(rules, rule{r, n, c.pipe.NoiseWhy(r)})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Rule < rules[j].Rule })
	ref := c.pipe.RuleSet()
	doc := map[string]any{"schema": FilteredSchema, "since": ts(s.Since), "until": ts(now), "rule_set": ref.Name + "@" + ref.Version,
		"filtered": rules, "events": s.Events, "assessed": s.Assessed, "not_writes": s.NotWrites, "out_of_scope": s.OutOfScope,
		"collector_own_events": s.Taps, "malformed": s.Malformed}
	b, _ := json.Marshal(doc)
	if len(b) > 3800 { // the check detail is at most 4 KiB; the rule list is what is cut
		doc["filtered"] = rules[:min(len(rules), 20)]
		doc["truncated"] = true
		b, _ = json.Marshal(doc)
	}
	return string(b)
}

// FilteredSchema names the detail of the noise-filtered check; the packet reads it (observe.ParseFiltered).
const FilteredSchema = observe.FilteredSchema

// clearReported takes what a health record reported off the counters, and commits that with the cursor.
func (c *Collector) clearReported(s Counters, now time.Time) error {
	c.commitMu.Lock()
	defer c.commitMu.Unlock()
	c.mu.Lock()
	next := c.meta
	cc := &next.Counters
	cc.Filtered, cc.OutOfScope = copyMap(cc.Filtered), copyMap(cc.OutOfScope)
	cc.Events -= s.Events
	cc.Assessed -= s.Assessed
	cc.NotWrites -= s.NotWrites
	cc.Malformed -= s.Malformed
	cc.Taps -= s.Taps
	for k, v := range s.Filtered {
		if cc.Filtered[k] -= v; cc.Filtered[k] <= 0 {
			delete(cc.Filtered, k)
		}
	}
	for k, v := range s.OutOfScope {
		if cc.OutOfScope[k] -= v; cc.OutOfScope[k] <= 0 {
			delete(cc.OutOfScope, k)
		}
	}
	cc.Since = now.UTC()
	m, _ := json.Marshal(next)
	c.mu.Unlock()
	// applied to the live counters only after the commit: a failed commit leaves them to be reported again
	if err := c.d.Queue.Commit(c.d.Queue.Cursor(), m); err != nil {
		return err
	}
	c.mu.Lock()
	c.meta = next
	c.mu.Unlock()
	return nil
}

func ago(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return now.Sub(t).Round(time.Second).String() + " ago"
}

func (c *Collector) checks(ctx context.Context, now time.Time) []HealthCheck {
	cfg := c.cfg
	c.mu.Lock()
	hb, lastAlert, lastGap, lastBody := c.hb, c.lastAlert, c.lastGap, c.lastBody
	postErrs, lastPost, hbErr, lkErr := c.postErrs, c.lastPost, c.hbErr, c.lkErr
	watchOK, want := copyTimes(c.watchOK), c.watchWant
	c.mu.Unlock()
	var out []HealthCheck
	add := func(name string, ok bool, detail string) { out = append(out, HealthCheck{name, ok, detail}) }

	if cfg.Webhook {
		heartbeat := c.d.Kube != nil && cfg.HeartbeatCM != "" && cfg.Namespace != ""
		fresh := 3 * cfg.HeartbeatInterval
		if heartbeat {
			ok := !hb.seen.IsZero() && now.Sub(hb.seen) <= fresh && hb.seen.After(lastAlert)
			d := "the collector's heartbeat write reached it through the API server's audit webhook " + ago(now, hb.seen)
			if hbErr != nil {
				d = "the heartbeat write failed: " + hbErr.Error()
			} else if !ok {
				d = "no heartbeat write has come back through the audit webhook (last " + ago(now, hb.seen) + "; it must be newer than " + fresh.String() + " and than any operation on monitoring): the policy, the webhook configuration or the path to the collector is broken"
			}
			add(CheckWebhook, ok, d)
			add(CheckPolicy, ok, "the live audit policy recorded the heartbeat write at level "+levelOr(hb.level)+" (the policy file itself is not readable from a pod; this is the strongest check the pod can make)")
		} else {
			var last time.Time
			if c.d.Delivery != nil {
				last = c.d.Delivery()
			}
			quiet := fallbackQuiet * cfg.HealthInterval
			ok := !last.IsZero() && now.Sub(last) <= quiet
			add(CheckWebhook, ok, "no heartbeat is configured, so only batch arrival is checked: the last accepted batch was "+ago(now, last)+
				"; a quiet cluster looks the same as a broken webhook")
		}
		if cfg.PolicyCM != "" && c.d.Kube != nil && c.d.Policy != nil {
			ok, d := c.mirrorOK(ctx)
			add(CheckMirror, ok, d)
		}
		secretsOK := lastBody.IsZero() || now.Sub(lastBody) > cfg.SecretHold
		d := "no Secret event has been recorded above Metadata"
		if !secretsOK {
			d = "a Secret event came with a body (" + ago(now, lastBody) + "): the live audit policy records Secrets above Metadata; the receiver cut the body, nothing was stored"
		}
		if cfg.CanarySecret != "" && heartbeat {
			if hb.canarySeen.IsZero() || now.Sub(hb.canarySeen) > fresh {
				secretsOK = false
				d = "the canary Secret write has not come back through the audit webhook (last " + ago(now, hb.canarySeen) + "): the Secret rule of the live policy cannot be shown"
			} else if hb.canaryBody {
				secretsOK = false
				d = "the canary Secret write came with a body: the live audit policy records Secrets above Metadata"
			} else {
				d += "; the canary Secret write was recorded at level " + levelOr(hb.canaryLevel)
			}
		}
		add(CheckSecrets, secretsOK, d)
	}
	st := c.d.Queue.Stats()
	add(CheckQueue, st.OldestAge <= cfg.MaxQueueAge,
		fmt.Sprintf("%d events waiting, the oldest %s (the most allowed is %s)", st.Pending, st.OldestAge.Round(time.Second), cfg.MaxQueueAge))
	postOK := postErrs == 0 || (!lastPost.IsZero() && now.Sub(lastPost) < 2*cfg.HealthInterval && postErrs < 3)
	add(CheckPosting, postOK, fmt.Sprintf("%d consecutive failures posting records to the core; the last success %s", postErrs, ago(now, lastPost)))
	if len(cfg.Watches) > 0 {
		stale := 0
		for _, t := range watchOK {
			if now.Sub(t) > 3*time.Minute {
				stale++
			}
		}
		ok := len(watchOK) >= want && stale == 0
		add(CheckWatch, ok, fmt.Sprintf("%d of %d watches current", len(watchOK)-stale, want))
		gapOK := lastGap.IsZero() || now.Sub(lastGap) > cfg.GapHold
		m, r, p := c.gaps.Counts()
		add(CheckGap, gapOK, fmt.Sprintf("%d watch changes matched to audit events, %d reported as gaps (the last %s), %d waiting", m, r, ago(now, lastGap), p))
	}
	if c.d.Lookups != nil {
		age := c.d.Lookups.Age()
		ok := lkErr == nil && age <= lookupsMaxAge*cfg.HealthInterval
		d := fmt.Sprintf("grants and break-glass windows read %s ago", age.Round(time.Second))
		if lkErr != nil {
			d = "not read: " + lkErr.Error()
		}
		add(CheckLookups, ok, d)
	}
	return out
}

func copyTimes(m map[string]time.Time) map[string]time.Time {
	o := make(map[string]time.Time, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

// mirrorOK reads the audit policy mirror (a ConfigMap the operator keeps equal to the policy on the nodes) and runs the
// Secret check on it. It says nothing about the policy file on a node, which a pod cannot read.
func (c *Collector) mirrorOK(ctx context.Context) (bool, string) {
	ns, name, ok := strings.Cut(c.cfg.PolicyCM, "/")
	if !ok {
		return false, "the policy ConfigMap is namespace/name"
	}
	cm, err := c.d.Kube.Get(ctx, "/api/v1/namespaces/"+ns+"/configmaps/"+name)
	if err != nil {
		return false, "the policy mirror " + c.cfg.PolicyCM + " is not readable: " + err.Error()
	}
	data, _ := cm["data"].(map[string]any)
	var raw string
	for _, k := range []string{"audit-policy.yaml", "policy.yaml"} {
		if s, ok := data[k].(string); ok {
			raw = s
		}
	}
	if raw == "" {
		return false, "the policy mirror has no audit-policy.yaml"
	}
	vs, err := c.d.Policy([]byte(raw))
	if err != nil {
		return false, "the policy mirror does not parse: " + err.Error()
	}
	if len(vs) > 0 {
		return false, "the policy mirror records a Secret body: " + vs[0]
	}
	return true, "the policy mirror " + c.cfg.PolicyCM + " never records a Secret body (a mirror, not the node's file)"
}

// reportGaps posts an observation and a not-attributed assessment for each watch change the audit feed never reported.
func (c *Collector) reportGaps(ctx context.Context, now time.Time) error {
	lag := c.d.Queue.Stats().OldestAge
	var errs []error
	for _, ch := range c.gaps.Expired(now, lag) {
		ref, err := c.d.Core.Record(ctx, gapObservation(c.cfg.Cluster, c.cfg.Source, ch, c.pipe.CanonicalHash, now))
		if err == nil {
			_, err = c.d.Core.Record(ctx, gapAssessment(c.cfg.Cluster, ref.Seq, ch, c.pipe.RuleSet(), c.cfg.GapGrace))
		}
		if err != nil {
			c.gaps.Requeue(ch)
			errs = append(errs, err)
			continue
		}
		c.mu.Lock()
		c.lastGap = now
		c.mu.Unlock()
		c.cfg.Log.Warn("audit gap: a change was seen on the watch stream and never audited", "kind", ch.Kind, "namespace", ch.Namespace, "name", ch.Name)
	}
	return errors.Join(errs...)
}

// RunHealth runs HealthOnce every HealthInterval.
func (c *Collector) RunHealth(ctx context.Context) {
	t := time.NewTicker(c.cfg.HealthInterval)
	defer t.Stop()
	for {
		if err := c.HealthOnce(ctx); err != nil && ctx.Err() == nil {
			c.cfg.Log.Error("health", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---- heartbeat and watches -------------------------------------------------------------------------------------

// BeatOnce patches the heartbeat ConfigMap (and the canary Secret, if there is one) with a new nonce: a write the
// audit policy must record at Metadata at least, that comes back through the webhook. Whether it did is the
// webhook-delivering check.
func (c *Collector) BeatOnce(ctx context.Context) error {
	if c.d.Kube == nil || c.cfg.HeartbeatCM == "" {
		return nil
	}
	now := c.cfg.Now()
	body := map[string]any{"metadata": map[string]any{"annotations": map[string]string{heartbeatAnn: ts(now)}}}
	err := c.d.Kube.Patch(ctx, "/api/v1/namespaces/"+c.cfg.Namespace+"/configmaps/"+c.cfg.HeartbeatCM, body)
	if err == nil && c.cfg.CanarySecret != "" {
		err = c.d.Kube.Patch(ctx, "/api/v1/namespaces/"+c.cfg.Namespace+"/secrets/"+c.cfg.CanarySecret, body)
	}
	c.mu.Lock()
	c.hbErr = err
	if err == nil {
		c.hb.sent = now
	}
	c.mu.Unlock()
	return err
}

// RunHeartbeat beats every HeartbeatInterval.
func (c *Collector) RunHeartbeat(ctx context.Context) {
	t := time.NewTicker(c.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		if err := c.BeatOnce(ctx); err != nil && ctx.Err() == nil {
			c.cfg.Log.Warn("heartbeat write failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunWatches lists and watches every configured resource: a namespaced one in each of WatchNS, a cluster-scoped one
// once. Each loop keeps the Cache current and feeds the gap tracker; a loop that cannot list or watch is stale in the
// watch-current check until it can.
func (c *Collector) RunWatches(ctx context.Context) {
	if c.d.Kube == nil {
		return
	}
	var wg sync.WaitGroup
	for _, w := range c.cfg.Watches {
		nss := []string{""}
		if w.Namespaced {
			nss = c.cfg.WatchNS
		}
		for _, ns := range nss {
			c.mu.Lock()
			c.watchWant++
			c.mu.Unlock()
			wg.Add(1)
			go func(w WatchSpec, ns string) {
				defer wg.Done()
				c.watchLoop(ctx, w, ns)
			}(w, ns)
		}
	}
	wg.Wait()
}

// noteApplication feeds the lookups' Argo CD Application index (platform-gitops attribution) from the Application watch.
func (c *Collector) noteApplication(kind, typ string, o map[string]any) {
	if kind == "Application" && c.d.Lookups != nil {
		c.d.Lookups.PutApplication(typ, o)
	}
}

func (c *Collector) watchLoop(ctx context.Context, w WatchSpec, ns string) {
	key := w.Resource + "/" + ns
	path := w.path(ns)
	for ctx.Err() == nil {
		items, rv, err := c.d.Kube.List(ctx, path)
		if err != nil {
			c.cfg.Log.Warn("listing for the watch cache", "path", path, "err", err)
			if !sleep(ctx, 10*time.Second) {
				return
			}
			continue
		}
		for _, o := range items {
			c.cache.Put(w.Kind, "ADDED", o, c.cfg.Now(), true)
			c.noteApplication(w.Kind, "ADDED", o)
		}
		c.mu.Lock()
		c.watchOK[key] = c.cfg.Now()
		c.mu.Unlock()
		for ctx.Err() == nil {
			err := c.d.Kube.Watch(ctx, path, rv, func(typ string, o map[string]any) {
				_, _, nrv := metaOf(o)
				if nrv != "" {
					rv = nrv
				}
				c.mu.Lock()
				c.watchOK[key] = c.cfg.Now()
				c.mu.Unlock()
				if typ == "BOOKMARK" {
					return
				}
				c.noteApplication(w.Kind, typ, o)
				if ch, ok := c.cache.Put(w.Kind, typ, o, c.cfg.Now(), false); ok {
					c.gaps.Watched(ch)
				}
			})
			if errors.Is(err, ErrGone) {
				break // list again
			}
			if err != nil && ctx.Err() == nil {
				c.cfg.Log.Warn("watch ended", "path", path, "err", err)
				if !sleep(ctx, 5*time.Second) {
					return
				}
			}
		}
	}
}
