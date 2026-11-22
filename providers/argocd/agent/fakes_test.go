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
	"slices"
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
	t             *testing.T
	mu            sync.Mutex
	ns            map[string]map[string]string
	nsLists       int
	grants        map[string]agent.Grant
	apps          []agent.Application
	objs          map[string][]agent.ObjectDetail // by namespace
	data          map[string]map[string]string
	putErr        func(d map[string]string) error // a refusal of some ConfigMap writes
	grantOps      int
	workOps       int // anything that would touch a workload: must stay 0
	failList      bool
	log           []string        // grant operations, in order
	failName      map[string]bool // writes of these grant names fail
	verbs         map[string]int  // create, update, delete, valid, put, app, ns: the writes the agent made
	appsets       map[string]agent.AppSet
	scopes        map[string]bool
	scopeErr      error
	rv            int              // the Applications' resourceVersion counter
	failApp       map[string]error // UpdateApplicationSource of these Applications fails
	failNS        map[string]error // SetNamespaceProtected of these namespaces fails
	listAppErr    error
	nsReadErr     map[string]error // GetNamespaceLabels of these namespaces fails
	reads         map[string]int
	schemaMissing []string // CRD schema fields that are not installed
	schemaErr     error
	liveExempt    map[string]bool
	pruning       bool // the fake API server prunes fields the schema lacks
	strict        bool
	everActive    map[string]bool
	// live: the key=hash pairs of namespace ns that the verified feed lists now (nil: not checked)
	live func(ns string) map[string]bool
}

func newKube(t *testing.T) *fakeKube {
	return &fakeKube{t: t, ns: map[string]map[string]string{}, grants: map[string]agent.Grant{},
		verbs: map[string]int{}, objs: map[string][]agent.ObjectDetail{}, data: map[string]map[string]string{},
		appsets: map[string]agent.AppSet{}, scopes: map[string]bool{"Namespace": true, "Deployment": false}, failApp: map[string]error{},
		failNS: map[string]error{}, nsReadErr: map[string]error{}, reads: map[string]int{}, everActive: map[string]bool{}}
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
	out.Namespace, out.Name, out.Valid, out.CheckedAt = g.Namespace, g.Name, g.Valid, g.CheckedAt
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
		// Two active grants are allowed in one case: a flip to or from a merged grant activates the new one first, and
		// the policy then needs an object to pass both (never more than either lists).
		merged := 0
		for _, g := range k.grants {
			if g.Namespace == ns && g.Active() && g.Labels[agent.LabelMerged] == "true" {
				merged++
			}
		}
		if n > 2 || (n == 2 && merged == 0) {
			k.t.Errorf("namespace %s holds %d active grants", ns, n)
		}
	}
	k.checkLabelled("a grant write")
	k.checkFeed("a grant write")
}

func (k *fakeKube) ProtectedNamespaces(context.Context) (map[string]map[string]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.nsLists++
	out := map[string]map[string]string{}
	for ns, l := range k.ns {
		if l[agent.LabelProtected] == "true" { // the API's label selector
			out[ns] = l
		}
	}
	return out, nil
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
func (k *fakeKube) CreateGrant(_ context.Context, g agent.Grant) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.grantOps++
	k.verbs["create"]++
	if k.failName[g.Name] {
		return errors.New("apply refused")
	}
	key := g.Namespace + "/" + g.Name
	if _, ok := k.grants[key]; ok {
		k.t.Errorf("create of grant %s that exists: the API server refuses it (and the audit log records it)", key)
		return errors.New("already exists")
	}
	k.log = append(k.log, fmt.Sprintf("create %s/%s active=%v", g.Namespace, g.Name, g.Active()))
	k.grants[key] = k.prune(cp(g))
	k.checkActive()
	return nil
}
func (k *fakeKube) UpdateGrant(_ context.Context, g, _ agent.Grant) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.grantOps++
	k.verbs["update"]++
	if k.failName[g.Name] {
		return errors.New("apply refused")
	}
	key := g.Namespace + "/" + g.Name
	old, ok := k.grants[key]
	if !ok {
		k.t.Errorf("update of grant %s that does not exist", key)
		return errors.New("not found")
	}
	k.log = append(k.log, fmt.Sprintf("update %s/%s active=%v", g.Namespace, g.Name, g.Active()))
	n := k.prune(cp(g))
	n.Valid = old.Valid // spec and labels are replaced; status is not touched
	n.CheckedAt = old.CheckedAt
	k.grants[key] = n
	k.checkActive()
	return nil
}
func (k *fakeKube) SetGrantValid(_ context.Context, ns, name string, v bool, _ string, at time.Time) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.grantOps++
	k.verbs["valid"]++
	k.log = append(k.log, fmt.Sprintf("valid %s/%s %v", ns, name, v))
	g, ok := k.grants[ns+"/"+name]
	if !ok {
		return errors.New("not found") // the API server has no such grant to patch the status of
	}
	g.Valid = &v
	g.CheckedAt = at.UTC().Format(time.RFC3339)
	k.grants[ns+"/"+name] = g
	k.checkLabelled("a status write")
	k.checkFeed("a status write")
	return nil
}
func (k *fakeKube) DeleteGrant(_ context.Context, ns, name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.grantOps++
	k.verbs["delete"]++
	delete(k.grants, ns+"/"+name)
	k.log = append(k.log, "delete "+ns+"/"+name)
	k.checkLabelled("a grant delete")
	k.checkFeed("a grant delete")
	return nil
}
func (k *fakeKube) ListApplications(context.Context) ([]agent.Application, string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.listAppErr != nil {
		return nil, "", k.listAppErr
	}
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
	k.verbs["put"]++
	if k.putErr != nil {
		if err := k.putErr(d); err != nil {
			return err
		}
	}
	cur := map[string]string{}
	for a, b := range k.data[ns+"/"+name] { // a merge patch of data: other keys stay
		cur[a] = b
	}
	for a, b := range d {
		cur[a] = b
	}
	k.data[ns+"/"+name] = cur
	return nil
}

// fakeCore records what the agent posts, and holds each record to what the real core requires.
type fakeCore struct {
	t       *testing.T
	mu      sync.Mutex
	records []client.RecordRequest
	down    bool
	windows []agent.Window
	// protection: what ReportProtection saw (every call), the set held, and what the "core" says about static pairs.
	reports    []client.ProtectionRequest
	held       []client.ProtectedPair
	static     map[string]bool // app/env pairs CLEARANCE_PROTECTED_ENVIRONMENTS protects (named in static_removed)
	reportDown bool
	heldSeq    int64                                     // the number of the last report the "core" took
	refuse     func(req *client.ProtectionRequest) error // a refusal for some reports (a 4xx)
	// exempt decides a gate-exemption record as the core would (W-42): nil takes it; an *client.APIError refuses it.
	exempt func(state, env string) error
	// loseReport commits the next protection report and then answers with an error, as a lost answer (W-42).
	loseReport bool
}

func (c *fakeCore) ProtectionSeq(context.Context, string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reportDown || c.down {
		return 0, errors.New("core unreachable")
	}
	return c.heldSeq, nil
}

func (c *fakeCore) ReportProtection(_ context.Context, cluster string, req *client.ProtectionRequest) (*client.ProtectionResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reportDown || c.down {
		return nil, errors.New("core unreachable")
	}
	if c.refuse != nil {
		if err := c.refuse(req); err != nil {
			return nil, err
		}
	}
	if cluster != "hangar-prod" {
		c.t.Errorf("a report for cluster %s: the agent reports its own", cluster)
	}
	pairs := make([]gate.ProtectedPair, 0, len(req.Pairs))
	for _, p := range req.Pairs {
		pairs = append(pairs, gate.ProtectedPair{App: p.App, Env: p.Env})
	}
	if _, err := gate.NormalizePairs(pairs); err != nil {
		c.t.Errorf("the core would refuse the report: %v", err)
	}
	if len(req.Reason) > 500 {
		c.t.Errorf("reason over the core's 500 bytes: %d", len(req.Reason))
	}
	if req.Seq <= c.heldSeq && req.Seq != 0 && c.held != nil && !slices.Equal(c.held, req.Pairs) {
		return nil, &client.APIError{Op: "reportProtection", Status: 409, Message: "not above the held report"}
	}
	if req.Seq > c.heldSeq {
		c.heldSeq = req.Seq
	}
	c.reports = append(c.reports, *req)
	res := &client.ProtectionResult{Cluster: cluster, Pairs: len(req.Pairs), HeldSeq: c.heldSeq}
	for _, n := range req.Pairs {
		if !slices.Contains(c.held, n) {
			res.Added, res.Changed = append(res.Added, n), true
		}
	}
	for _, o := range c.held {
		if !slices.Contains(req.Pairs, o) {
			res.Removed, res.Changed = append(res.Removed, o), true
			if c.static[o.App+"/"+o.Env] {
				res.StaticRemoved = append(res.StaticRemoved, o)
			}
		}
	}
	c.held = append([]client.ProtectedPair(nil), req.Pairs...)
	if c.loseReport {
		c.loseReport = false
		return nil, errors.New("the answer was lost")
	}
	return res, nil
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
		if x, _ := rec["exception"].(map[string]any); x["kind"] == gate.KindGateExemption && c.exempt != nil {
			st, _ := x["exemption"].(map[string]any)["state"].(string)
			env, _ := rec["destination"].(map[string]any)["environment"].(string)
			if err := c.exempt(st, env); err != nil {
				return nil, err
			}
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
	// published: the claims of the feed as last signed: what the agent has verified and may grant from.
	published []token.Claims
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
	f.published = append([]token.Claims(nil), f.claims...)
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
		Wait:          agent.TestWaitPin,
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
