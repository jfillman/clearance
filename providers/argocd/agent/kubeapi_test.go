package agent_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// The REST implementation against a stand-in API server: the paths, verbs, bodies and decoding the agent relies on.
func TestKubeAPI(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		bodies = append(bodies, string(b))
		if r.Header.Get("Authorization") != "Bearer sa-token" {
			t.Errorf("auth %q", r.Header.Get("Authorization"))
		}
		p := r.URL.Path
		switch {
		case r.Method == "POST" && strings.HasSuffix(p, "/clearancegrants"):
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"reason":"AlreadyExists"}`))
		case r.Method == "PATCH":
			_, _ = w.Write([]byte(`{}`))
		case strings.HasSuffix(p, "/namespaces"):
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"app-a","labels":{"clearance.hangar.io/protected":"true"}}}]}`))
		case strings.HasSuffix(p, "/deployments"):
			_, _ = w.Write([]byte(`{"kind":"DeploymentList","items":[{"metadata":{"name":"web","uid":"u","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}"},` +
				`"ownerReferences":[{"controller":true}],"managedFields":[{"manager":"old","time":"2026-01-01T00:00:00Z"},{"manager":"kubectl","time":"2026-02-01T00:00:00Z"}]}}]}`))
		case strings.HasSuffix(p, "/rollouts"):
			w.WriteHeader(404)
		case r.URL.Query().Get("watch") == "true":
			_, _ = w.Write([]byte(`{"type":"BOOKMARK","object":{}}` + "\n" +
				`{"type":"MODIFIED","object":{"metadata":{"namespace":"argocd-apps","name":"web","uid":"U"},"spec":{"project":"tenants","destination":{"namespace":"app-a"}},` +
				`"status":{"sync":{"status":"Synced","revisions":["r1","r2"]},"health":{"status":"Healthy"},"operationState":{"phase":"Succeeded","startedAt":"s","syncResult":{"revision":"r1","resources":[{"kind":"ConfigMap","name":"c","status":"Synced"}]}}}}}` + "\n" +
				`{"type":"ERROR","object":{"code":410}}` + "\n"))
		case strings.HasSuffix(p, "/configmaps/state"):
			w.WriteHeader(404)
		default:
			t.Errorf("unexpected %s", r.URL.RequestURI())
		}
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tok, []byte("sa-token\n"), 0o600)
	k := &agent.API{Base: srv.URL, TokenFile: tok, Client: srv.Client(), Grants: agent.DefaultGrantAPI, ArgoNS: "argocd-apps"}

	ns, err := k.ProtectedNamespaces(bg)
	if err != nil || ns["app-a"][agent.LabelProtected] != "true" {
		t.Fatalf("namespaces: %v %v", ns, err)
	}
	g := agent.Grant{Namespace: "app-a", Name: ch2, Labels: map[string]string{agent.LabelManagedBy: agent.ManagedBy}}
	if err := k.ApplyGrant(bg, g); err != nil { // POST conflicts, so it patches; the active label is cleared with null
		t.Fatal(err)
	}
	if !strings.Contains(bodies[len(bodies)-1], `"clearance.hangar.io/active":null`) ||
		!strings.HasPrefix(calls[len(calls)-1], "PATCH /apis/clearance.hangar.io/v1alpha1/namespaces/app-a/clearancegrants/"+ch2) {
		t.Errorf("patch: %v %v", calls, bodies)
	}
	if err := k.SetGrantValid(bg, "app-a", ch2, false); err != nil ||
		!strings.HasSuffix(calls[len(calls)-1], "/clearancegrants/"+ch2+"/status") || !strings.Contains(bodies[len(bodies)-1], `"valid":false`) {
		t.Errorf("status: %v %v", err, calls)
	}
	objs, err := k.ListObjects(bg, agent.Resource{Group: "apps", Version: "v1", Plural: "deployments"}, "app-a")
	if err != nil || len(objs) != 1 || objs[0].Kind != "Deployment" || objs[0].APIVersion != "apps/v1" || !objs[0].Owned ||
		objs[0].Manager != "kubectl" || objs[0].LastApplied != "{}" {
		t.Fatalf("objects: %+v %v", objs, err)
	}
	if objs, err := k.ListObjects(bg, agent.Resource{Group: "argoproj.io", Version: "v1alpha1", Plural: "rollouts"}, "app-a"); err != nil || objs != nil {
		t.Errorf("a kind that is not installed is no objects: %v %v", objs, err)
	}
	var seen []agent.Application
	err = k.WatchApplications(bg, "7", func(a agent.Application) { seen = append(seen, a) })
	if !errors.Is(err, agent.ErrWatchGone) || len(seen) != 1 {
		t.Fatalf("watch: %v %v", err, seen)
	}
	a := seen[0]
	if a.Name != "web" || a.Project != "tenants" || a.DestNS != "app-a" || a.Health != "Healthy" || a.Op == nil || a.Op.Phase != "Succeeded" ||
		len(a.Revisions) != 2 || a.Op.Revisions[0] != "r1" || a.Op.Resources[0].Kind != "ConfigMap" {
		t.Errorf("application: %+v %+v", a, a.Op)
	}
	if d, err := k.GetData(bg, "clearance-system", "state"); err != nil || d != nil {
		t.Errorf("no state yet: %v %v", d, err)
	}
}
