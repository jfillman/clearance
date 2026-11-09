package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/internal/vocab"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
	"github.com/jfillman/clearance/providers/observe-k8s/queue"
)

const cluster = "prod-1"

var t0 = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

// fakeCore is the core as far as the collector sees it: it holds every record the way the chain would (seq, ts, tool),
// holds each one to observe.Check (what the real core does before it seals a record) and de-duplicates observations on
// source.event_id.
type fakeCore struct {
	mu    sync.Mutex
	t     *testing.T
	now   func() time.Time
	recs  []observe.Record
	ids   map[string]int64
	fail  error
	vocab vocab.Vocabulary
}

func newCore(t *testing.T, now func() time.Time) *fakeCore {
	return &fakeCore{t: t, now: now, ids: map[string]int64{}, vocab: vocab.Default()}
}

func (f *fakeCore) Record(_ context.Context, req *client.RecordRequest) (*client.RecordRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	b, err := json.Marshal(req.Record)
	if err != nil {
		f.t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var ev map[string]any
	if err := dec.Decode(&ev); err != nil {
		f.t.Fatal(err)
	}
	if _, err := observe.Check(req.Kind, ev, f.vocab); err != nil {
		f.t.Fatalf("the core would refuse this %s record: %v\n%s", req.Kind, err, b)
	}
	if src, _ := ev["source"].(map[string]any); src != nil {
		if id, _ := src["event_id"].(string); id != "" {
			key := req.Kind + "|" + fmt.Sprint(src["name"]) + "|" + id
			if seq, dup := f.ids[key]; dup {
				return &client.RecordRef{Seq: seq, Duplicate: true}, nil
			}
			defer func() { f.ids[key] = int64(len(f.recs) - 1) }()
		}
	}
	seq := int64(len(f.recs))
	ev["seq"] = json.Number(fmt.Sprint(seq))
	ev["tool"] = req.Kind
	ev["ts"] = f.now().UTC().Format(time.RFC3339)
	f.recs = append(f.recs, ev)
	return &client.RecordRef{Seq: seq}, nil
}

func (f *fakeCore) kind(k string) []observe.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []observe.Record
	for _, r := range f.recs {
		if r["tool"] == k {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeCore) all() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(f.recs)
	return b
}

func sub(m map[string]any, k string) map[string]any { v, _ := m[k].(map[string]any); return v }

type fakeGrants struct{ gs []agent.Grant }

func (f fakeGrants) ListGrants(context.Context) ([]agent.Grant, error) { return f.gs, nil }

type fakeBG struct{ ws []agent.Window }

func (f fakeBG) Breakglass(context.Context, string) ([]agent.Window, error) { return f.ws, nil }

type rig struct {
	t      *testing.T
	c      *Collector
	core   *fakeCore
	q      *queue.Queue
	dir    string
	pipe   *pipeline.Pipeline
	clock  *time.Time
	grants *fakeGrants
}

type rigOpt func(*Config, *Deps)

func newRig(t *testing.T, opts ...rigOpt) *rig {
	t.Helper()
	return newRigIn(t, t.TempDir(), opts...)
}

func newRigIn(t *testing.T, dir string, opts ...rigOpt) *rig {
	t.Helper()
	clock := t0
	now := func() time.Time { return clock }
	rs, err := pipeline.Default()
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGrants{}
	lk := &Lookups{Cluster: cluster, Grants: g, BG: fakeBG{}, Now: now}
	if err := lk.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	pipe := pipeline.New(rs, lk, vocab.Default())
	q, err := queue.Open(dir, queue.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	core := newCore(t, now)
	cfg := Config{Cluster: cluster, Webhook: true, CompletenessClaimed: true, Now: now,
		Watches: []WatchSpec{{Group: "", Version: "v1", Resource: "configmaps", Kind: "ConfigMap", Namespaced: true},
			{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Namespaced: true}}}
	d := Deps{Queue: q, Pipeline: pipe, Core: core, Lookups: lk}
	for _, o := range opts {
		o(&cfg, &d)
	}
	c, err := New(cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, c: c, core: core, q: q, dir: dir, pipe: pipe, clock: &clock, grants: g}
}

// push appends audit events to the queue.
func (r *rig) push(evs ...map[string]any) {
	r.t.Helper()
	for _, e := range evs {
		b, _ := json.Marshal(e)
		if err := r.q.Append(b); err != nil {
			r.t.Fatal(err)
		}
	}
}

func (r *rig) drain() int {
	r.t.Helper()
	total := 0
	for {
		n, err := r.c.ProcessOnce(context.Background())
		if err != nil {
			r.t.Fatal(err)
		}
		if n == 0 {
			return total
		}
		total += n
	}
}

func (r *rig) advance(d time.Duration) { *r.clock = r.clock.Add(d) }

var seqN int

// auditEvent is an audit.k8s.io/v1 Event, ResponseComplete.
func auditEv(user, ua, verb, resource, ns, name string, code int, extra map[string]any) map[string]any {
	seqN++
	e := map[string]any{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse", "stage": "ResponseComplete",
		"auditID": fmt.Sprintf("a-%04d", seqN), "verb": verb, "user": map[string]any{"username": user, "groups": []any{"system:authenticated"}},
		"userAgent": ua, "stageTimestamp": t0.Format(time.RFC3339Nano),
		"objectRef":      map[string]any{"resource": resource, "namespace": ns, "name": name},
		"responseStatus": map[string]any{"code": code}}
	for k, v := range extra {
		e[k] = v
	}
	return e
}

func configMap(ns, name, rv string, data map[string]any) map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": name, "namespace": ns, "resourceVersion": rv, "uid": "u-" + name}, "data": data}
}

var errBoom = errors.New("core unavailable")
