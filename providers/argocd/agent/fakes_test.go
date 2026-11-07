package agent_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

var t0 = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

// clock is the test's time, moved by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeKube is the protected cluster and its Argo CD: namespaces, grants, Applications and live objects, in memory.
// It fails a test the moment a namespace holds two active grants (the admission policy needs exactly one).
type fakeKube struct {
	t        *testing.T
	mu       sync.Mutex
	ns       map[string]map[string]string
	grants   map[string]agent.Grant
	apps     []agent.Application
	objs     map[string][]agent.ObjectDetail // by namespace
	data     map[string]map[string]string
	grantOps int
	workOps  int // anything that would touch a workload: must stay 0
	failList bool
}

func newKube(t *testing.T) *fakeKube {
	return &fakeKube{t: t, ns: map[string]map[string]string{}, grants: map[string]agent.Grant{},
		objs: map[string][]agent.ObjectDetail{}, data: map[string]map[string]string{}}
}

func (k *fakeKube) protect(ns string, labels map[string]string) {
	l := map[string]string{agent.LabelProtected: "true"}
	for a, b := range labels {
		l[a] = b
	}
	k.ns[ns] = l
}

func cp(g agent.Grant) agent.Grant {
	b, _ := json.Marshal(g)
	var out agent.Grant
	_ = json.Unmarshal(b, &out)
	out.Namespace, out.Name, out.Valid = g.Namespace, g.Name, g.Valid
	out.Labels = map[string]string{}
	for a, b := range g.Labels {
		out.Labels[a] = b
	}
	return out
}

func (k *fakeKube) checkActive() {
	active := map[string]int{}
	for _, g := range k.grants {
		if g.Active() {
			active[g.Namespace]++
		}
	}
	for ns, n := range active {
		if n > 1 {
			k.t.Errorf("namespace %s holds %d active grants", ns, n)
		}
	}
}

func (k *fakeKube) ProtectedNamespaces(context.Context) (map[string]map[string]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.ns, nil
}
func (k *fakeKube) ListGrants(context.Context) ([]agent.Grant, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []agent.Grant
	for _, g := range k.grants {
		out = append(out, cp(g))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (k *fakeKube) ApplyGrant(_ context.Context, g agent.Grant) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.grantOps++
	key := g.Namespace + "/" + g.Name
	n := cp(g)
	if old, ok := k.grants[key]; ok {
		n.Valid = old.Valid // spec and labels are replaced; status is not touched
	}
	k.grants[key] = n
	k.checkActive()
	return nil
}
func (k *fakeKube) SetGrantValid(_ context.Context, ns, name string, v bool) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.grantOps++
	g := k.grants[ns+"/"+name]
	g.Valid = &v
	k.grants[ns+"/"+name] = g
	return nil
}
func (k *fakeKube) DeleteGrant(_ context.Context, ns, name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.grantOps++
	delete(k.grants, ns+"/"+name)
	return nil
}
func (k *fakeKube) ListApplications(context.Context) ([]agent.Application, string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]agent.Application(nil), k.apps...), "1", nil
}
func (k *fakeKube) WatchApplications(ctx context.Context, _ string, _ func(agent.Application)) error {
	<-ctx.Done()
	return nil
}
func (k *fakeKube) ListObjects(_ context.Context, r agent.Resource, ns string) ([]agent.ObjectDetail, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failList {
		return nil, errors.New("apiserver unreachable")
	}
	var out []agent.ObjectDetail
	for _, o := range k.objs[ns] {
		if strings.ToLower(o.Kind)+"s" == r.Plural {
			out = append(out, o)
		}
	}
	return out, nil
}
func (k *fakeKube) GetData(_ context.Context, ns, name string) (map[string]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.data[ns+"/"+name], nil
}
func (k *fakeKube) PutData(_ context.Context, ns, name string, d map[string]string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.data[ns+"/"+name] = d
	return nil
}

// fakeCore records what the agent posts, and holds each record to what the real core requires.
type fakeCore struct {
	t       *testing.T
	mu      sync.Mutex
	records []client.RecordRequest
	down    bool
	windows []agent.Window
}

func (c *fakeCore) Record(_ context.Context, req *client.RecordRequest) (*client.RecordRef, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		return nil, errors.New("core unreachable")
	}
	raw, _ := json.Marshal(req)
	var strict server.RecordRequest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&strict); err != nil {
		c.t.Errorf("the core would refuse the body: %v\n%s", err, raw)
	}
	var ev map[string]any
	_ = json.Unmarshal(raw, &ev)
	rec := ev["record"].(map[string]any)
	required := map[string][]string{
		"deploy.outcome":   {"app", "target", "outcome"},
		"deploy.exception": {"principal", "target", "result", "exception", "destination"},
	}[req.Kind]
	if required == nil {
		c.t.Errorf("kind %s is not the agent's", req.Kind)
	}
	for _, f := range required {
		if rec[f] == nil || rec[f] == "" {
			c.t.Errorf("a %s record carries %s: %s", req.Kind, f, raw)
		}
	}
	if src, _ := rec["source"].(map[string]any); !strings.HasPrefix(fmt.Sprint(src["provider"]), "argocd-agent/") {
		c.t.Errorf("a record without the provider identity: %s", raw)
	}
	if req.Kind == "deploy.exception" {
		rec["tool"] = req.Kind
		if err := gate.CheckReport(store.Event(rec), t0); err != nil {
			c.t.Errorf("the core's report check refuses it: %v\n%s", err, raw)
		}
	}
	c.records = append(c.records, *req)
	return &client.RecordRef{Seq: int64(len(c.records) - 1), Hash: strings.Repeat("0", 64)}, nil
}
func (c *fakeCore) Breakglass(context.Context, string) ([]agent.Window, error) {
	return c.windows, nil
}
func (c *fakeCore) of(kind string) []client.RecordRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []client.RecordRequest
	for _, r := range c.records {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

// fakeFeeds is clearance-api: it signs feeds with a throwaway key, and can go down.
type fakeFeeds struct {
	t       *testing.T
	signer  *token.KeySigner
	cluster string
	epoch   string
	seq     int64
	clock   *clock
	down    bool
	claims  []token.Claims
	// raw overrides the body (a tampered or odd feed).
	raw []byte
}

func newFeeds(t *testing.T, c *clock) *fakeFeeds {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.NewKeySigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeFeeds{t: t, signer: s, cluster: "hangar-prod", epoch: "epoch-one", clock: c}
}

func (f *fakeFeeds) Keys(context.Context) ([]byte, error) {
	if f.down {
		return nil, errors.New("clearance-api unreachable")
	}
	j, err := token.PublicJWK(f.signer.Public())
	if err != nil {
		f.t.Fatal(err)
	}
	return json.Marshal(token.JWKS{Keys: []token.JWK{j}})
}

// publish signs the feed of the current claims at the next seq.
func (f *fakeFeeds) publish() []byte {
	f.seq++
	return f.publishAt(f.epoch, f.seq, f.cluster, f.signer)
}

func (f *fakeFeeds) publishAt(epoch string, seq int64, cluster string, s *token.KeySigner) []byte {
	now := f.clock.now()
	feed := token.Feed{Type: token.FeedType, Issuer: "clearance", Cluster: cluster, Epoch: epoch, Seq: seq,
		IssuedAt: now.Unix(), Expires: now.Add(5 * time.Minute).Unix(), RecordsSeq: 10}
	var toks []map[string]any
	for _, c := range f.claims {
		tk, err := token.Issue(context.Background(), s, c)
		if err != nil {
			f.t.Fatal(err)
		}
		d, _ := token.PayloadDigest(tk.Envelope)
		feed.Entries = append(feed.Entries, token.FeedEntry{ChangeID: c.Subject, Nonce: c.Nonce, Expires: c.Expires, PayloadSHA256: d})
		toks = append(toks, map[string]any{"change_id": c.Subject, "dsse": tk.Envelope})
	}
	env, err := token.SignFeed(context.Background(), s, feed)
	if err != nil {
		f.t.Fatal(err)
	}
	if toks == nil {
		toks = []map[string]any{}
	}
	body, _ := json.Marshal(map[string]any{"cluster": cluster, "seq": seq, "feed": env, "tokens": toks})
	f.raw = body
	return body
}

func (f *fakeFeeds) Feed(context.Context, string) ([]byte, error) {
	if f.down {
		return nil, errors.New("clearance-api unreachable")
	}
	return f.raw, nil
}

// claim is a cleared change's token claims: objects in ns, decided at decided.
func claim(f *fakeFeeds, id, ns string, decided time.Time, objs ...token.Object) token.Claims {
	for i := range objs {
		objs[i].Namespace = ns
	}
	return token.Claims{Type: token.Type, Issuer: "clearance", Subject: id, IssuedAt: decided.Unix(),
		Expires: decided.Add(15 * time.Minute).Unix(), Nonce: "n-" + id,
		Clearance: token.Clearance{ID: id, ClearedBy: "people", DecidedAt: decided.Format(time.RFC3339)},
		Subjects:  token.Subjects{Kind: "manifest-tree", Repo: "acme/gitops", PR: 7, Commit: strings.Repeat("a", 40), TreeRoot: strings.Repeat("c", 64)},
		Objects:   objs, Target: token.Target{Cluster: f.cluster, Env: "prod", App: "web"}, Tier: 1}
}

func deploy(name, rendered string) token.Object {
	return token.Object{APIVersion: "apps/v1", Kind: "Deployment", Name: name, Rendered: rendered, Changed: true, Op: "changed"}
}
func cmap(name, rendered string) token.Object {
	return token.Object{APIVersion: "v1", Kind: "ConfigMap", Name: name, Rendered: rendered, Op: "changed"}
}

func hex(c string) string { return strings.Repeat(c, 64) }

type world struct {
	t     *testing.T
	clock *clock
	kube  *fakeKube
	feeds *fakeFeeds
	core  *fakeCore
	a     *agent.Agent
}

func newWorld(t *testing.T) *world {
	c := &clock{t: t0}
	w := &world{t: t, clock: c, kube: newKube(t), feeds: newFeeds(t, c), core: &fakeCore{t: t}}
	w.a = w.agent()
	return w
}

// agent builds an agent over the world's cluster, as a restart does: state is read from the ConfigMap.
func (w *world) agent() *agent.Agent {
	a, err := agent.New(agent.Config{Cluster: "hangar-prod", Environment: "prod", Version: "0.0.0-test",
		ArgoNamespace: "argocd-apps", Projects: []string{"tenants"}, StateNS: "clearance-system"},
		w.kube, w.feeds, w.core, w.clock.now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		w.t.Fatal(err)
	}
	if err := a.Load(context.Background()); err != nil {
		w.t.Fatal(err)
	}
	return a
}

func (w *world) sync() error { return w.a.SyncGrants(context.Background()) }

func newSignerFor(t *testing.T) (*token.KeySigner, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return token.NewKeySigner(k)
}
