// Package collector is the Kubernetes audit collector's engine (O-3). One Collector is one audit source for one
// cluster: it drains a durable queue of audit events, normalizes and attributes each through the observation pipeline
// (internal/observe/pipeline), posts the observation and its assessment to the core, keeps the health record the core
// reads coverage from, and finds what the audit feed missed.
//
// The pieces, each testable alone: the queue and the receiver (sibling packages) make sure nothing the API server was
// told arrived is lost; Lookups backs attribution with the cluster's grants and the core's break-glass windows; Cache
// and Gaps are the watch stream, which supplies the object before a change and notices a change with no audit event;
// health.go is what the collector claims about its own feed.
package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/providers/observe-k8s/queue"
)

// Core is the part of the core's client the collector uses.
type Core interface {
	Record(ctx context.Context, req *client.RecordRequest) (*client.RecordRef, error)
}

// Config is one collector's settings.
type Config struct {
	Cluster string // the scope of every record: the cluster's name (the Argo CD agent's CLEARANCE_CLUSTER)
	Source  string // source.name; the health record is per (scope, source). Default k8s-audit-webhook
	// Webhook: the source is the API server's webhook backend, which has a heartbeat, a canary and a receiver to
	// check. A managed-cluster reader sets it false.
	Webhook bool
	// CompletenessClaimed is what each observation says about its feed (the core still checks it against health).
	CompletenessClaimed bool

	Namespace      string // the collector's own namespace
	ServiceAccount string // the collector's own service account name (its heartbeat writes are recognised by it)
	HeartbeatCM    string // the ConfigMap the collector patches to prove the audit path end to end
	CanarySecret   string // optional: a Secret the collector patches to prove Secrets are recorded at Metadata
	PolicyCM       string // optional namespace/name of a mirror of the live audit policy the pod may read

	HealthInterval    time.Duration // default 60s
	HeartbeatInterval time.Duration // default 30s
	GapGrace          time.Duration // default 3m
	GapHold           time.Duration // how long a gap keeps the feed degraded; default 15m
	SecretHold        time.Duration // how long a Secret body keeps the feed degraded; default 15m
	FlushInterval     time.Duration // default 20m
	MaxQueueAge       time.Duration // the queue is not draining past this; default 5m
	BatchSize         int           // default 200
	// Latency is how far behind the source this reader is by design (CloudWatch, Log Analytics): a watch change waits
	// this much longer for its audit event. Webhook: 0.
	Latency time.Duration

	Watches []WatchSpec
	WatchNS []string // namespaces the namespaced watches cover
	Log     *slog.Logger
	Now     func() time.Time
}

func (c *Config) defaults() {
	if c.Source == "" {
		c.Source = "k8s-audit-webhook"
	}
	for _, d := range []struct {
		v *time.Duration
		d time.Duration
	}{{&c.HealthInterval, time.Minute}, {&c.HeartbeatInterval, 30 * time.Second}, {&c.GapGrace, 3 * time.Minute},
		{&c.GapHold, 15 * time.Minute}, {&c.SecretHold, 15 * time.Minute}, {&c.FlushInterval, 20 * time.Minute},
		{&c.MaxQueueAge, 5 * time.Minute}} {
		if *d.v <= 0 {
			*d.v = d.d
		}
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 200
	}
	if c.Log == nil {
		c.Log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// Deps are what the collector reads and writes.
type Deps struct {
	Queue    *queue.Queue
	Pipeline *pipeline.Pipeline
	Core     Core
	Lookups  *Lookups // optional (nil: nothing is known, nothing is cleared; used by tests)
	Kube     Kube     // optional: the heartbeat, the watches and the policy mirror need it
	// Delivery is the receiver's status (the time of the last accepted batch), for the check a heartbeat cannot make.
	Delivery func() (lastBatch time.Time)
	// Policy checks a mirror of the live audit policy (auditpolicy parse and check); nil: no such check.
	Policy func(raw []byte) (violations []string, err error)
}

// Counters are the pipeline's per-rule counts the packet prints ("filtered: N events under rule X") and the
// coverage population is built from. They are committed to the queue's cursor file with the cursor, so a batch is
// counted once however many times it is retried, and they are reported (in the health record) and cleared together.
type Counters struct {
	Events     int            `json:"events"`
	Assessed   int            `json:"assessed"`
	NotWrites  int            `json:"not_writes"`
	Malformed  int            `json:"malformed"`
	Taps       int            `json:"collector_own_events"`
	Filtered   map[string]int `json:"filtered,omitempty"`
	OutOfScope map[string]int `json:"out_of_scope,omitempty"`
	Since      time.Time      `json:"since"`
}

func (c *Counters) empty() bool {
	return c.Events == 0 && c.Malformed == 0
}

type meta struct {
	Counters Counters `json:"counters"`
}

// Collector is one source's engine.
type Collector struct {
	cfg  Config
	d    Deps
	pipe *pipeline.Pipeline

	cache *Cache
	gaps  *Gaps

	commitMu  sync.Mutex // serializes meta + cursor writes (the processor's and the health loop's)
	mu        sync.Mutex
	meta      meta
	inflight  *batch
	seqs      map[string]int64 // event id -> the observation's seq (for resolutions)
	hb        heartbeatState
	lastAlert time.Time
	lastGap   time.Time
	lastBody  time.Time // the last time an event showed a Secret recorded above Metadata
	postErrs  int
	lastPost  time.Time
	watchOK   map[string]time.Time
	watchWant int
	hbErr     error
	lkErr     error
}

type heartbeatState struct {
	seen, canarySeen   time.Time
	level, canaryLevel string
	sent, canarySent   time.Time
	canaryBody         bool
}

// New builds a Collector and loads the counters the queue's cursor file holds.
func New(cfg Config, d Deps) (*Collector, error) {
	cfg.defaults()
	if cfg.Cluster == "" || d.Queue == nil || d.Pipeline == nil || d.Core == nil {
		return nil, errors.New("collector: a cluster, a queue, a pipeline and a core are required")
	}
	c := &Collector{cfg: cfg, d: d, pipe: d.Pipeline, cache: NewCache(d.Pipeline.CanonicalHash),
		gaps: NewGaps(cfg.GapGrace + cfg.Latency), seqs: map[string]int64{}, watchOK: map[string]time.Time{}}
	if m := d.Queue.Meta(); len(m) > 0 {
		if err := json.Unmarshal(m, &c.meta); err != nil {
			return nil, fmt.Errorf("collector: the queue's meta: %w", err)
		}
	}
	if c.meta.Counters.Since.IsZero() {
		c.meta.Counters.Since = cfg.Now().UTC()
	}
	d.Pipeline.OnAlert = func(a pipeline.Alert) {
		c.mu.Lock()
		c.lastAlert = cfg.Now()
		c.mu.Unlock()
		cfg.Log.Error("operation on the controls that watch this cluster", "scope", a.Scope, "health", a.Health, "detail", a.Detail)
	}
	return c, nil
}

// auditEvent is the slice of an audit event the collector reads before the pipeline.
type auditEvent struct {
	AuditID        string `json:"auditID"`
	Level          string `json:"level"`
	Stage          string `json:"stage"`
	Verb           string `json:"verb"`
	StageTimestamp string `json:"stageTimestamp"`
	User           struct {
		Username string `json:"username"`
	} `json:"user"`
	ObjectRef struct {
		Resource    string `json:"resource"`
		Subresource string `json:"subresource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
	} `json:"objectRef"`
	Annotations    map[string]string `json:"annotations"`
	ResponseObject struct {
		Kind     string `json:"kind"`
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	} `json:"responseObject"`
}

func (e *auditEvent) time(def time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, e.StageTimestamp); err == nil {
		return t.UTC()
	}
	return def
}

func (e *auditEvent) write() bool {
	switch e.Verb {
	case "create", "update", "patch", "delete", "deletecollection":
		return e.Stage == "" || e.Stage == "ResponseComplete"
	}
	return false
}

// batch is a batch whose events have been through the pipeline and whose records are to be posted.
type batch struct {
	upTo  uint64
	items []item
	delta Counters
}

type item struct {
	a     *pipeline.Assessment
	level string
}

// ProcessOnce reads one batch from the queue, runs it through the pipeline, posts its records and commits. It returns
// how many events it handled. A batch whose posting failed is kept and posted again on the next call, without going
// through the pipeline twice; nothing is committed (so nothing is lost) until every record is posted.
func (c *Collector) ProcessOnce(ctx context.Context) (int, error) {
	if c.inflight == nil {
		es, err := c.d.Queue.Next(c.cfg.BatchSize)
		if err != nil {
			return 0, err
		}
		if len(es) == 0 {
			return 0, nil
		}
		b := &batch{upTo: es[len(es)-1].Seq + 1}
		b.delta.Filtered, b.delta.OutOfScope = map[string]int{}, map[string]int{}
		for _, e := range es {
			c.handle(e.Payload, e.At, b)
		}
		c.inflight = b
	}
	b := c.inflight
	if err := c.post(ctx, b); err != nil {
		c.mu.Lock()
		c.postErrs++
		c.mu.Unlock()
		return 0, err
	}
	c.commitMu.Lock()
	c.mu.Lock()
	c.postErrs = 0
	c.lastPost = c.cfg.Now()
	// The counters are committed with the cursor: marshal a copy with the batch applied, and apply it to the live
	// meta only once the commit succeeded, so a failed commit retried from inflight counts the batch once.
	next := c.meta
	next.Counters.Filtered, next.Counters.OutOfScope = copyMap(c.meta.Counters.Filtered), copyMap(c.meta.Counters.OutOfScope)
	merge(&next.Counters, b.delta)
	m, _ := json.Marshal(next)
	c.mu.Unlock()
	err := c.d.Queue.Commit(b.upTo, m)
	if err == nil {
		c.mu.Lock()
		c.meta = next
		c.mu.Unlock()
	}
	c.commitMu.Unlock()
	if err != nil {
		return 0, err
	}
	c.inflight = nil
	return int(b.delta.Events), nil
}

func merge(dst *Counters, s Counters) {
	dst.Events += s.Events
	dst.Assessed += s.Assessed
	dst.NotWrites += s.NotWrites
	dst.Malformed += s.Malformed
	dst.Taps += s.Taps
	for k, v := range s.Filtered {
		if dst.Filtered == nil {
			dst.Filtered = map[string]int{}
		}
		dst.Filtered[k] += v
	}
	for k, v := range s.OutOfScope {
		if dst.OutOfScope == nil {
			dst.OutOfScope = map[string]int{}
		}
		dst.OutOfScope[k] += v
	}
}

// handle runs one queued event. A payload the pipeline cannot read is counted (malformed) and skipped: one bad event
// must not hold the whole queue.
func (c *Collector) handle(payload []byte, at time.Time, b *batch) {
	b.delta.Events++
	var ev auditEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		b.delta.Malformed++
		c.cfg.Log.Warn("an audit event is not JSON; skipped", "err", err)
		return
	}
	when := ev.time(at)
	if c.tap(&ev, when) {
		b.delta.Taps++
		return
	}
	c.noteCredentialLevel(&ev, when)
	kind := ""
	if ev.write() && ev.ObjectRef.Resource != "" {
		kind = c.kindOf(ev.ObjectRef.Resource)
		c.gaps.Audited(kind, ev.ObjectRef.Namespace, ev.ObjectRef.Name, ev.ResponseObject.Metadata.ResourceVersion, when, c.cfg.Now())
	}
	raw := pipeline.RawEvent{Provider: pipeline.Kubernetes, Scope: c.cfg.Cluster, Raw: payload}
	if kind != "" && ev.ObjectRef.Resource != "secrets" {
		deleted := ev.Verb == "delete"
		raw.Before = JSON(c.cache.Before(kind, ev.ObjectRef.Namespace, ev.ObjectRef.Name, ev.ResponseObject.Metadata.ResourceVersion, when, deleted))
	}
	a, disp, detail, err := c.pipe.Process(raw)
	if err != nil {
		b.delta.Malformed++
		c.cfg.Log.Warn("an audit event could not be normalized; skipped", "audit_id", ev.AuditID, "err", err)
		return
	}
	switch disp {
	case pipeline.Assessed:
		b.delta.Assessed++
		b.items = append(b.items, item{a, levelOf(map[string]any{"level": ev.Level})})
	case pipeline.Filtered:
		b.delta.Filtered[detail]++
	case pipeline.OutOfScope:
		b.delta.OutOfScope[detail]++
	case pipeline.NotWrite:
		b.delta.NotWrites++
	}
}

// kindOf is the Kind of a resource the watches know (so the cache key matches), else the pipeline's own guess is used
// downstream and the cache simply has nothing for it.
func (c *Collector) kindOf(resource string) string {
	for _, w := range c.cfg.Watches {
		if w.Resource == resource {
			return w.Kind
		}
	}
	return ""
}

// tap recognises the collector's own heartbeat and canary writes, by its exact identity and the exact objects, takes
// what they prove (the audit path works, at which level) and keeps them out of the pipeline: they are not changes to
// anything. The count of them is in the health record, so nothing is hidden.
func (c *Collector) tap(ev *auditEvent, when time.Time) bool {
	if !c.cfg.Webhook || c.cfg.ServiceAccount == "" || c.cfg.Namespace == "" {
		return false
	}
	self := "system:serviceaccount:" + c.cfg.Namespace + ":" + c.cfg.ServiceAccount
	if ev.User.Username != self || ev.ObjectRef.Namespace != c.cfg.Namespace || (ev.Verb != "patch" && ev.Verb != "update") {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case ev.ObjectRef.Resource == "configmaps" && c.cfg.HeartbeatCM != "" && ev.ObjectRef.Name == c.cfg.HeartbeatCM:
		if when.After(c.hb.seen) {
			c.hb.seen, c.hb.level = when, levelOr(ev.Level)
		}
		return true
	case ev.ObjectRef.Resource == "secrets" && c.cfg.CanarySecret != "" && ev.ObjectRef.Name == c.cfg.CanarySecret:
		if when.After(c.hb.canarySeen) {
			c.hb.canarySeen, c.hb.canaryLevel = when, levelOr(ev.Level)
			c.hb.canaryBody = ev.Annotations["observe-k8s.clearance.hangar.io/body-stripped"] != ""
		}
		if c.hb.canaryBody || ev.Level == "Request" || ev.Level == "RequestResponse" {
			c.lastBody = when
		}
		return true
	}
	return false
}

func levelOr(l string) string {
	if l == "" {
		return "Metadata"
	}
	return l
}

// noteCredentialLevel: a Secret (or token) event the receiver had to cut, or one at a level above Metadata, means the
// live audit policy records Secret bodies. The receiver already dropped them; this is the signal that it happened.
func (c *Collector) noteCredentialLevel(ev *auditEvent, when time.Time) {
	about := ev.ObjectRef.Resource == "secrets" || (ev.ObjectRef.Resource == "serviceaccounts" && ev.ObjectRef.Subresource == "token")
	if !about {
		return
	}
	if ev.Annotations["observe-k8s.clearance.hangar.io/body-stripped"] != "" || ev.Level == "Request" || ev.Level == "RequestResponse" {
		c.mu.Lock()
		c.lastBody = when
		c.mu.Unlock()
	}
}

// post writes each item's observation and assessment. The core de-duplicates the observation on source.event_id, so a
// retry (or a replay of a queue after a crash) does not write it twice; a repeated assessment is harmless (the latest
// wins), and it is always posted so a crash between the two never leaves an observation unassessed.
func (c *Collector) post(ctx context.Context, b *batch) error {
	for i := range b.items {
		it := &b.items[i]
		e := it.a.Event()
		ref, err := c.d.Core.Record(ctx, observation(c.cfg.Source, it.level, c.cfg.CompletenessClaimed, it.a, c.cfg.Now()))
		if err != nil {
			return fmt.Errorf("posting the observation of %s: %w", e.ID, err)
		}
		if _, err := c.d.Core.Record(ctx, assessment(it.a, ref.Seq)); err != nil {
			return fmt.Errorf("posting the assessment of %s: %w", e.ID, err)
		}
		c.mu.Lock()
		if len(c.seqs) > 50000 {
			c.seqs = map[string]int64{}
		}
		c.seqs[e.ID] = ref.Seq
		c.mu.Unlock()
	}
	return nil
}

// Flush closes the pipeline's open transactions: each apply-and-revert it folded into one exception gets a `reverted`
// resolution on the observation of the change that was undone, and each observation of any other change that landed gets
// `still-live` (a person can set a later one). Called on a timer and at shutdown.
func (c *Collector) Flush(ctx context.Context) error {
	txs, excs := c.pipe.Flush()
	var errs []error
	for _, x := range excs {
		c.cfg.Log.Info("exception", "id", x.ID, "kind", x.Kind, "actor", x.Actor, "resources", x.Resources, "severity", x.Severity, "resolution", x.Resolution)
		if len(x.Events) == 0 {
			continue
		}
		if x.Reverted {
			seq, ok := c.seqOf(x.Events[0])
			if !ok {
				continue // not posted in this run (a restart in between): no resolution is recorded, the cautious answer
			}
			if _, err := c.d.Core.Record(ctx, resolutionReverted(x.Scope, seq, fmt.Sprintf("applied and put back within the revert window (events %s)", strings.Join(x.Events, ", ")))); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if !landedChange(x.Kind) {
			continue
		}
		for _, ev := range x.Events {
			seq, ok := c.seqOf(ev)
			if !ok {
				continue
			}
			if _, err := c.d.Core.Record(ctx, resolutionStillLive(x.Scope, seq)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	c.cfg.Log.Info("transactions closed", "count", len(txs), "exceptions", len(excs))
	return errors.Join(errs...)
}

// seqOf is the core's seq of the observation posted for an audit event, if this run posted it.
func (c *Collector) seqOf(event string) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seq, ok := c.seqs[event]
	return seq, ok
}

// landedChange says an exception of this kind is a change that took effect and was not put back: a refused attempt
// landed nothing, and a break-glass window has its own record.
func landedChange(kind string) bool {
	return kind == "out-of-band" || kind == "monitoring-protection" || kind == "drift"
}

// Run drains the queue until ctx ends: it waits for an append, processes batches, and backs off on an error. The
// health, flush, heartbeat and watch loops are separate (RunHealth, RunHeartbeat, RunWatches, RunFlush).
func (c *Collector) Run(ctx context.Context) {
	if c.d.Lookups != nil { // attribute against the grants as they are now, not an empty snapshot
		if err := c.d.Lookups.Refresh(ctx); err != nil {
			c.cfg.Log.Warn("grants or break-glass windows not read at start", "err", err)
		}
	}
	backoff := time.Second
	for ctx.Err() == nil {
		n, err := c.ProcessOnce(ctx)
		switch {
		case err != nil:
			c.cfg.Log.Error("processing the audit queue", "err", err, "retry_in", backoff)
			if !sleep(ctx, backoff) {
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		case n == 0:
			backoff = time.Second
			select {
			case <-ctx.Done():
				return
			case <-c.d.Queue.Wait():
			case <-time.After(5 * time.Second):
			}
		default:
			backoff = time.Second
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// RunFlush flushes on a timer, and once more when ctx ends.
func (c *Collector) RunFlush(ctx context.Context) {
	t := time.NewTicker(c.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.Flush(fctx); err != nil {
				c.cfg.Log.Error("flush at shutdown", "err", err)
			}
			return
		case <-t.C:
			if err := c.Flush(ctx); err != nil {
				c.cfg.Log.Error("flush", "err", err)
			}
		}
	}
}

// Counters is a copy of the counters not yet reported.
func (c *Collector) Counters() Counters {
	c.mu.Lock()
	defer c.mu.Unlock()
	cc := c.meta.Counters
	cc.Filtered, cc.OutOfScope = copyMap(cc.Filtered), copyMap(cc.OutOfScope)
	return cc
}

func copyMap(m map[string]int) map[string]int {
	if m == nil {
		return nil
	}
	o := make(map[string]int, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}
