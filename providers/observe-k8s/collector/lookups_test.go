package collector

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

func grant(ns, name, id string, valid bool, expires time.Time, objs map[string]agent.GrantObject) agent.Grant {
	g := agent.Grant{Namespace: ns, Name: name, Valid: &valid, Spec: agent.GrantSpec{ExpiresAt: expires.Format(time.RFC3339), Objects: objs}}
	g.Spec.Clearance.ID = id
	return g
}

// ObjectGrant answers only from active grants (valid and unexpired), by the grant's own namespace, kind and name; Grant
// answers from every grant's hashes, carried trees included.
func TestLookupsObjectGrantIsActiveGrantsOnly(t *testing.T) {
	now := t0
	carried := grant("shop", "shop-active", "clr_new", true, now.Add(time.Hour), map[string]agent.GrantObject{"/ConfigMap/cfg": {Rendered: "sha256:cc"}})
	carried.Spec.Carried = []agent.CarriedTree{{Change: "clr_old", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		Objects: map[string]agent.GrantObject{"/Secret/old-creds": {Rendered: "sha256:dd"}}}}
	g := &fakeGrants{gs: []agent.Grant{
		carried,
		grant("shop", "shop-expired", "clr_exp", true, now.Add(-time.Hour), map[string]agent.GrantObject{"/Secret/expired": {Rendered: "sha256:ee"}}),
		grant("shop", "shop-invalid", "clr_inv", false, now.Add(time.Hour), map[string]agent.GrantObject{"/Secret/invalid": {Rendered: "sha256:ff"}}),
		grant("payments", "p", "clr_pay", true, now.Add(time.Hour), map[string]agent.GrantObject{"/Secret/cfg": {Rendered: "sha256:11"}}),
	}}
	lk := &Lookups{Cluster: cluster, Grants: g, BG: fakeBG{ws: []agent.Window{{ID: "bg_1", Cluster: cluster}}}, Now: func() time.Time { return now }}
	if err := lk.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ns, kind, name string
		want           string
	}{
		{"shop", "ConfigMap", "cfg", "clr_new"}, {"shop", "Secret", "old-creds", "clr_old"}, {"payments", "Secret", "cfg", "clr_pay"},
		{"shop", "Secret", "expired", ""}, {"shop", "Secret", "invalid", ""}, {"payments", "ConfigMap", "cfg", ""}, {"shop", "Secret", "cfg", ""},
	} {
		got, ok := lk.ObjectGrant(cluster, c.ns, c.kind, c.name)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%s/%s/%s: %q %v, want %q", c.ns, c.kind, c.name, got, ok, c.want)
		}
	}
	if _, ok := lk.ObjectGrant("another-cluster", "shop", "ConfigMap", "cfg"); ok {
		t.Error("another cluster's scope")
	}
	if gr, ok := lk.Grant("clr_exp"); !ok || len(gr.Hashes) != 1 || gr.Hashes[0] != "ee" {
		t.Errorf("an expired grant's hashes are still the ones it listed (an older stamp may still be live): %+v %v", gr, ok)
	}
	if _, ok := lk.Grant("clr_unknown"); ok {
		t.Error("unknown grant")
	}
	if id, ok := lk.BreakGlass(cluster, now); !ok || id != "bg_1" {
		t.Errorf("break-glass %q %v", id, ok)
	}
	if _, ok := lk.BreakGlass("other", now); ok {
		t.Error("another cluster's window")
	}
}

type failGrants struct{}

func (failGrants) ListGrants(context.Context) ([]agent.Grant, error) {
	return nil, errors.New("api down")
}

// A failed refresh keeps the last snapshot, and the age says how stale it is.
func TestLookupsKeepTheLastSnapshotOnAFailedRefresh(t *testing.T) {
	now := t0
	g := &fakeGrants{gs: []agent.Grant{grant("shop", "a", "clr_1", true, now.Add(time.Hour), map[string]agent.GrantObject{"/Secret/s": {Rendered: "sha256:aa"}})}}
	lk := &Lookups{Cluster: cluster, Grants: g, Now: func() time.Time { return now }}
	if lk.Age() < 24*time.Hour {
		t.Fatal("an unread lookups is infinitely stale")
	}
	if err := lk.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	lk.Grants = failGrants{}
	now = now.Add(10 * time.Minute)
	if err := lk.Refresh(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if _, ok := lk.ObjectGrant(cluster, "shop", "Secret", "s"); !ok || lk.Age() != 10*time.Minute {
		t.Fatalf("the snapshot was dropped (age %v)", lk.Age())
	}
}

func TestParseWatch(t *testing.T) {
	w, err := ParseWatch("apps/v1/deployments=Deployment")
	if err != nil || w.Group != "apps" || w.Resource != "deployments" || !w.Namespaced || w.path("shop") != "/apis/apps/v1/namespaces/shop/deployments" {
		t.Fatalf("%+v %v %s", w, err, w.path("shop"))
	}
	w, err = ParseWatch("v1/configmaps=ConfigMap")
	if err != nil || w.Group != "" || w.path("shop") != "/api/v1/namespaces/shop/configmaps" {
		t.Fatalf("%+v %v", w, err)
	}
	w, err = ParseWatch("rbac.authorization.k8s.io/v1/clusterroles=ClusterRole,cluster")
	if err != nil || w.Namespaced || w.path("") != "/apis/rbac.authorization.k8s.io/v1/clusterroles" {
		t.Fatalf("%+v %v", w, err)
	}
	for _, bad := range []string{"", "v1/secrets=Secret", "v1/pods", "v1/Secrets=Pod", "a/b/c/d=X", "v1/pods=Pod,nonsense"} {
		if _, err := ParseWatch(bad); err == nil {
			t.Errorf("%q was accepted: the collector never watches Secrets", bad)
		}
	}
}

type fakeWatchKube struct {
	noKube
	mu     sync.Mutex
	lists  map[string][]map[string]any
	events chan func(fn func(string, map[string]any))
	paths  []string
}

func (f *fakeWatchKube) List(_ context.Context, path string) ([]map[string]any, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, path)
	return f.lists[path], "100", nil
}

func (f *fakeWatchKube) Watch(ctx context.Context, _, _ string, fn func(string, map[string]any)) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-f.events:
			e(fn)
		}
	}
}

// The watch loop fills the cache from the list and keeps it current, and a desired-state change on the stream that no
// audit event reports is a gap.
func TestWatchLoopFeedsTheCacheAndTheGapTracker(t *testing.T) {
	r := newRig(t)
	r.c.cfg.WatchNS = []string{"shop"}
	r.c.cfg.Watches = []WatchSpec{{Version: "v1", Resource: "configmaps", Kind: "ConfigMap", Namespaced: true}}
	fk := &fakeWatchKube{lists: map[string][]map[string]any{"/api/v1/namespaces/shop/configmaps": {configMap("shop", "web-config", "10", map[string]any{"v": "1"})}},
		events: make(chan func(fn func(string, map[string]any)), 4)}
	r.c.d.Kube = fk
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.c.RunWatches(ctx); close(done) }()
	fk.events <- func(fn func(string, map[string]any)) {
		fn("MODIFIED", configMap("shop", "web-config", "11", map[string]any{"v": "2"}))
	}
	fk.events <- func(fn func(string, map[string]any)) {
		fn("BOOKMARK", map[string]any{"metadata": map[string]any{"resourceVersion": "12"}})
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, p := r.c.gaps.Counts(); p == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the watch change never reached the gap tracker")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if b := r.c.cache.Before("ConfigMap", "shop", "web-config", "11", t0, false); b == nil || b["data"].(map[string]any)["v"] != "1" {
		t.Fatalf("the list result is the version before the change: %v", b)
	}
	cancel()
	<-done
}

// A grant cleared after the last read is found on the miss, not attributed as unknown until the next scheduled refresh.
func TestLookupsRefreshOnAMiss(t *testing.T) {
	now := t0
	g := &fakeGrants{}
	lk := &Lookups{Cluster: cluster, Grants: g, Now: func() time.Time { return now }}
	if err := lk.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	g.gs = []agent.Grant{grant("shop", "a", "clr_new", true, now.Add(time.Hour), map[string]agent.GrantObject{"/Secret/s": {Rendered: "sha256:aa"}})}
	if _, ok := lk.Grant("clr_new"); ok {
		t.Fatal("a snapshot read a moment ago is not re-read")
	}
	now = now.Add(6 * time.Second)
	if _, ok := lk.Grant("clr_new"); !ok {
		t.Fatal("a miss on a snapshot older than MissRefresh must re-read the grants")
	}
	g.gs = append(g.gs, grant("shop", "b", "clr_b", true, now.Add(time.Hour), map[string]agent.GrantObject{"/Secret/t": {Rendered: "sha256:bb"}}))
	now = now.Add(6 * time.Second)
	if _, ok := lk.ObjectGrant(cluster, "shop", "Secret", "t"); !ok {
		t.Fatal("ObjectGrant refreshes on a miss too")
	}
}
