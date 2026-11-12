package collector

import (
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/observe/pipeline"
)

func appObj(ns, name, rev string, resources ...[3]string) map[string]any {
	var rs []any
	for _, r := range resources {
		rs = append(rs, map[string]any{"kind": r[0], "namespace": r[1], "name": r[2]})
	}
	return map[string]any{"metadata": map[string]any{"namespace": ns, "name": name},
		"status": map[string]any{"sync": map[string]any{"revision": rev}, "resources": rs}}
}

// The Application index answers platform-gitops attribution: by name, with the revision, and by the resources an
// Application lists (one claimant only), per Application namespace; a delete and another cluster answer nothing.
func TestLookupsKnowTheWatchedArgoApplications(t *testing.T) {
	l := &Lookups{Cluster: "prod-1"}
	l.PutApplication("ADDED", appObj("argocd", "rbac", "abc123", [3]string{"Secret", "shop", "db"}, [3]string{"ClusterRole", "", "reader"}))
	l.PutApplication("ADDED", appObj("argocd", "other", "def456", [3]string{"Secret", "shop", "shared"}))
	l.PutApplication("ADDED", appObj("argocd", "other2", "", [3]string{"Secret", "shop", "shared"}))
	l.PutApplication("ADDED", appObj("argocd-apps", "gated", "999", [3]string{"Secret", "shop", "gated-only"}))

	if a, ok := l.Application("prod-1", "argocd", "rbac"); !ok || a.Revision != "abc123" {
		t.Fatalf("%+v %v", a, ok)
	}
	if _, ok := l.Application("prod-2", "argocd", "rbac"); ok {
		t.Fatal("another cluster")
	}
	if _, ok := l.Application("prod-1", "argocd-apps", "rbac"); ok {
		t.Fatal("another namespace")
	}
	if a, ok := l.ManagedBy("prod-1", "argocd", "shop", "secret", "db"); !ok || a.Name != "rbac" {
		t.Fatalf("a Metadata-level event spells the kind from the resource: %+v %v", a, ok)
	}
	if a, ok := l.ManagedBy("prod-1", "argocd", "", "ClusterRole", "reader"); !ok || a.Name != "rbac" {
		t.Fatalf("%+v %v", a, ok)
	}
	if _, ok := l.ManagedBy("prod-1", "argocd", "shop", "Secret", "shared"); ok {
		t.Fatal("two Applications claim it: no answer")
	}
	if _, ok := l.ManagedBy("prod-1", "argocd", "shop", "Secret", "gated-only"); ok {
		t.Fatal("an Application of another instance's namespace is not the platform's")
	}
	l.PutApplication("MODIFIED", appObj("argocd", "rbac", "newrev", [3]string{"Secret", "shop", "db"}))
	if a, _ := l.Application("prod-1", "argocd", "rbac"); a.Revision != "newrev" {
		t.Fatalf("%+v", a)
	}
	l.PutApplication("DELETED", appObj("argocd", "rbac", "newrev"))
	if _, ok := l.Application("prod-1", "argocd", "rbac"); ok {
		t.Fatal("deleted")
	}
	// a multi-source Application: its revisions, joined
	o := appObj("argocd", "multi", "")
	o["status"].(map[string]any)["sync"] = map[string]any{"revisions": []any{"aaa", "bbb"}}
	l.PutApplication("ADDED", o)
	if a, _ := l.Application("prod-1", "argocd", "multi"); a.Revision != "aaa,bbb" {
		t.Fatalf("%+v", a)
	}
}

// The index carries the hooks of an Application's current or last operation (status.operationState.syncResult.resources
// entries with a hookType), with that operation's revision; a plain resource of the sync result is not a hook; two claimants,
// another namespace or another cluster answer nothing; the next operation replaces the list.
func TestLookupsKnowSyncHooks(t *testing.T) {
	l := &Lookups{Cluster: "prod-1"}
	withOp := func(o map[string]any, rev string, rs ...map[string]any) map[string]any {
		var list []any
		for _, r := range rs {
			list = append(list, r)
		}
		o["status"].(map[string]any)["operationState"] = map[string]any{"syncResult": map[string]any{"revision": rev, "resources": list}}
		return o
	}
	hook := map[string]any{"group": "batch", "kind": "Job", "namespace": "argocd-apps", "name": "redis-secret-init", "hookType": "PreSync"}
	plain := map[string]any{"group": "batch", "kind": "Job", "namespace": "argocd-apps", "name": "not-a-hook"}
	l.PutApplication("ADDED", withOp(appObj("argocd", "install", "synced111"), "oprev222", hook, plain))
	if a, ok := l.HookOf("prod-1", "argocd", "argocd-apps", "job", "redis-secret-init"); !ok || a.Name != "install" || a.Revision != "oprev222" {
		t.Fatalf("%+v %v", a, ok)
	}
	if _, ok := l.HookOf("prod-1", "argocd", "argocd-apps", "Job", "not-a-hook"); ok {
		t.Fatal("no hookType: not a hook")
	}
	if _, ok := l.HookOf("prod-2", "argocd", "argocd-apps", "Job", "redis-secret-init"); ok {
		t.Fatal("another cluster")
	}
	if _, ok := l.HookOf("prod-1", "argocd-apps", "argocd-apps", "Job", "redis-secret-init"); ok {
		t.Fatal("another namespace")
	}
	l.PutApplication("ADDED", withOp(appObj("argocd", "second", "x"), "y", hook))
	if _, ok := l.HookOf("prod-1", "argocd", "argocd-apps", "Job", "redis-secret-init"); ok {
		t.Fatal("two Applications list it: no answer")
	}
	l.PutApplication("MODIFIED", withOp(appObj("argocd", "second", "x"), "y"))
	l.PutApplication("MODIFIED", appObj("argocd", "install", "synced333")) // a new operation clears the list
	if _, ok := l.HookOf("prod-1", "argocd", "argocd-apps", "Job", "redis-secret-init"); ok {
		t.Fatal("no operation state: no hooks")
	}
	// no syncResult revision: the Application's own
	l.PutApplication("MODIFIED", withOp(appObj("argocd", "install", "synced111"), "", hook))
	if a, ok := l.HookOf("prod-1", "argocd", "argocd-apps", "Job", "redis-secret-init"); !ok || a.Revision != "synced111" {
		t.Fatalf("%+v %v", a, ok)
	}
}

// HookOfRecent also counts the previous operation's hooks for the window after the current operation replaced them (a TTL delete
// arrives minutes after the sync), with that operation's revision; the current operation wins; past the window, or for a hook
// the previous operation never listed, nothing; two claimants answer nothing.
func TestLookupsRememberReplacedHooks(t *testing.T) {
	now := time.Date(2026, 11, 12, 14, 0, 0, 0, time.UTC)
	l := &Lookups{Cluster: "prod-1", Now: func() time.Time { return now }}
	withOp := func(o map[string]any, rev string, rs ...map[string]any) map[string]any {
		var list []any
		for _, r := range rs {
			list = append(list, r)
		}
		o["status"].(map[string]any)["operationState"] = map[string]any{"syncResult": map[string]any{"revision": rev, "resources": list}}
		return o
	}
	hook := map[string]any{"group": "batch", "kind": "Job", "namespace": "argocd-apps", "name": "redis-secret-init", "hookType": "PreSync"}
	other := map[string]any{"group": "batch", "kind": "Job", "namespace": "argocd-apps", "name": "other-hook", "hookType": "PostSync"}
	recent := func(name string, at time.Time) (string, bool) {
		a, ok := l.HookOfRecent("prod-1", "argocd", "argocd-apps", "Job", name, at)
		return a.Revision, ok
	}
	l.PutApplication("ADDED", withOp(appObj("argocd", "install", "s1"), "op1", hook))
	now = now.Add(time.Minute)
	l.PutApplication("MODIFIED", withOp(appObj("argocd", "install", "s2"), "op2", other)) // a later operation, other hooks
	if rev, ok := recent("redis-secret-init", now); !ok || rev != "op1" {
		t.Fatalf("previous operation's hook, within the window: %q %v", rev, ok)
	}
	if _, ok := l.HookOf("prod-1", "argocd", "argocd-apps", "Job", "redis-secret-init"); ok {
		t.Fatal("HookOf stays the current operation only")
	}
	if rev, ok := recent("other-hook", now); !ok || rev != "op2" {
		t.Fatalf("current operation: %q %v", rev, ok)
	}
	if _, ok := recent("redis-secret-init", now.Add(pipeline.HookCleanupWindow+time.Second)); ok {
		t.Fatal("past the window")
	}
	if _, ok := recent("never-listed", now); ok {
		t.Fatal("never a hook")
	}
	// a status-only update (same operation) keeps the remembered list and its replacement time
	l.PutApplication("MODIFIED", withOp(appObj("argocd", "install", "s2"), "op2", other))
	if rev, ok := recent("redis-secret-init", now); !ok || rev != "op1" {
		t.Fatalf("same operation re-delivered: %q %v", rev, ok)
	}
	// a second Application claiming it, in either operation, is no answer
	l.PutApplication("ADDED", withOp(appObj("argocd", "second", "x"), "y", hook))
	if _, ok := recent("redis-secret-init", now); ok {
		t.Fatal("two claimants")
	}
	if _, ok := l.HookOfRecent("prod-2", "argocd", "argocd-apps", "Job", "other-hook", now); ok {
		t.Fatal("another cluster")
	}
}
