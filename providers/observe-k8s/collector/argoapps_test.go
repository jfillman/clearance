package collector

import "testing"

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
