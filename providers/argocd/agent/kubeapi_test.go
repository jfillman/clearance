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
	"time"

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
		case r.Method == "GET" && strings.HasSuffix(p, "/clearancegrants/"+ch2):
			_, _ = w.Write([]byte(`{"spec":{"objects":{"apps/Deployment/web":{"rendered":"x"},"/ConfigMap/gone":{"rendered":"y"}}}}`))
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
	g.Spec.Objects = map[string]agent.GrantObject{"apps/Deployment/web": {Rendered: "z"}}
	cur := agent.Grant{Namespace: "app-a", Name: ch2}
	cur.Spec.Objects = map[string]agent.GrantObject{"/ConfigMap/gone": {}, "apps/Deployment/web": {Rendered: "y"}}
	if err := k.UpdateGrant(bg, g, cur); err != nil { // a patch, no create; the active label is cleared with null
		t.Fatal(err)
	}
	if !strings.Contains(bodies[len(bodies)-1], `"/ConfigMap/gone":null`) || strings.Contains(bodies[len(bodies)-1], `"apps/Deployment/web":null`) {
		t.Errorf("an object the update drops is removed with null, one it keeps is not: %s", bodies[len(bodies)-1])
	}
	if !strings.Contains(bodies[len(bodies)-1], `"carried":null`) {
		t.Errorf("a grant with no carried trees clears the list a merge patch would otherwise keep: %s", bodies[len(bodies)-1])
	}
	if !strings.Contains(bodies[len(bodies)-1], `"clearance.hangar.io/active":null`) ||
		!strings.HasPrefix(calls[len(calls)-1], "PATCH /apis/clearance.hangar.io/v1/namespaces/app-a/clearancegrants/"+ch2) {
		t.Errorf("patch: %v %v", calls, bodies)
	}
	if err := k.SetGrantValid(bg, "app-a", ch2, false, "expired", time.Now()); err != nil ||
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

// An update and a state write never send a create the API server would refuse; a create that loses a race (409)
// reads the grant and writes only if it differs.
func TestKubeAPIWritesAreNotRefused(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	stored := `{"metadata":{"labels":{"app.kubernetes.io/managed-by":"clearance-argocd-agent"}},"spec":{"expiresAt":"2026-01-01T00:00:00Z","objects":{"apps/Deployment/web":{"rendered":"x","changed":false}}}}`
	cmExists := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/clearancegrants"):
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"reason":"AlreadyExists"}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/clearancegrants/"):
			_, _ = w.Write([]byte(stored))
		case strings.Contains(r.URL.Path, "/configmaps/state") && !cmExists:
			w.WriteHeader(404)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/configmaps"):
			cmExists = true
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tok, []byte("t"), 0o600)
	k := &agent.API{Base: srv.URL, TokenFile: tok, Client: srv.Client(), Grants: agent.DefaultGrantAPI, ArgoNS: "argocd-apps"}
	reset := func() { calls = nil }

	g := agent.Grant{Namespace: "app-a", Name: ch2, Labels: map[string]string{agent.LabelManagedBy: agent.ManagedBy}}
	g.Spec.ExpiresAt = "2026-01-01T00:00:00Z"
	g.Spec.Objects = map[string]agent.GrantObject{"apps/Deployment/web": {Rendered: "x"}}

	// The race: the create gets 409, the grant is the same: nothing is written.
	if err := k.CreateGrant(bg, g); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ";") != "POST /apis/clearance.hangar.io/v1/namespaces/app-a/clearancegrants;GET /apis/clearance.hangar.io/v1/namespaces/app-a/clearancegrants/"+ch2 {
		t.Errorf("a lost race on an equal grant: %v", calls)
	}
	// The race, the stored grant differs: one patch.
	reset()
	g.Spec.Objects["apps/Deployment/web"] = agent.GrantObject{Rendered: "y"}
	if err := k.CreateGrant(bg, g); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || !strings.HasPrefix(calls[2], "PATCH ") {
		t.Errorf("a lost race on a different grant: %v", calls)
	}
	// An update is a patch only.
	reset()
	if err := k.UpdateGrant(bg, g, g); err != nil || len(calls) != 1 || !strings.HasPrefix(calls[0], "PATCH ") {
		t.Errorf("update: %v %v", err, calls)
	}
	// State: a patch when the ConfigMap is there; a create only after a 404.
	reset()
	if err := k.PutData(bg, "clearance-system", "state", map[string]string{"k": "v"}); err != nil || len(calls) != 1 || !strings.HasPrefix(calls[0], "PATCH ") {
		t.Errorf("state patch: %v %v", err, calls)
	}
	reset()
	cmExists = false
	if err := k.PutData(bg, "clearance-system", "state", map[string]string{"k": "v"}); err != nil || len(calls) != 2 || !strings.HasPrefix(calls[1], "POST ") {
		t.Errorf("state create after 404: %v %v", err, calls)
	}
}
