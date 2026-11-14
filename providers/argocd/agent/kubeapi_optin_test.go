package agent_test

import (
	"encoding/json"
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

// The opt-in's REST calls against a stand-in API server: what is read from an Application, the one JSON patch that
// writes it, the namespace label, the discovery.
func TestKubeAPIOptIn(t *testing.T) {
	var mu sync.Mutex
	type call struct{ method, path, ctype, body string }
	var calls []call
	nsLabels := map[string]map[string]string{"free": {}, "mine": {"clearance.hangar.io/protected": "true", "clearance.hangar.io/protected-by": "optin"},
		"theirs": {"clearance.hangar.io/protected": "true"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, call{r.Method, r.URL.RequestURI(), r.Header.Get("Content-Type"), string(b)})
		p := r.URL.Path
		switch {
		case r.Method == "GET" && strings.HasSuffix(p, "/applications"):
			_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"9"},"items":[{"metadata":{"namespace":"argocd-apps","name":"web","resourceVersion":"41",` +
				`"annotations":{"clearance.hangar.io/protect":"true","argocd.argoproj.io/tracking-id":"root:argoproj.io/Application:argocd-apps/web"},` +
				`"ownerReferences":[{"kind":"ApplicationSet","name":"tenants"}]},` +
				`"spec":{"project":"tenants","destination":{"namespace":"app-web"},"source":{"repoURL":"https://git.example.test/o/r.git","path":"c"},` +
				`"ignoreDifferences":[{"group":"argoproj.io","kind":"Application","jsonPointers":["/spec/source"],"jqPathExpressions":[".spec.sources"]}],` +
				`"syncPolicy":{"syncOptions":["RespectIgnoreDifferences=true"]}}},` +
				`{"metadata":{"name":"multi","resourceVersion":"5"},"spec":{"sources":[{"repoURL":"a"},{"repoURL":"b","ref":"v"}]}}]}`))
		case r.Method == "PATCH" && strings.Contains(p, "/applications/"):
			if strings.Contains(p, "/stale") {
				// What kube-apiserver 1.36.2 answers (measured with envtest) when a JSON patch's `test` fails, and when an op
				// names a path that is not there: the same body for both, no details.
				w.WriteHeader(422)
				_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"the server rejected our request due to an error in our request","reason":"Invalid","details":{},"code":422}`))
				return
			}
			if strings.Contains(p, "/invalid") { // a schema validation refusal: it names its causes
				w.WriteHeader(422)
				_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Application.argoproj.io \"invalid\" is invalid: spec.source: Invalid value","reason":"Invalid","details":{"name":"invalid","group":"argoproj.io","kind":"Application","causes":[{"reason":"FieldValueInvalid","message":"Invalid value","field":"spec.source"}]},"code":422}`))
				return
			}
			_, _ = w.Write([]byte(`{}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/applicationsets/tenants"):
			_, _ = w.Write([]byte(`{"metadata":{"name":"tenants"},"spec":{"ignoreApplicationDifferences":[{"name":"web","jsonPointers":["/spec/source"]}]}}`))
		case r.Method == "GET" && strings.Contains(p, "/applicationsets/"):
			w.WriteHeader(404)
		case r.Method == "GET" && strings.HasPrefix(p, "/api/v1/namespaces/"):
			name := strings.TrimPrefix(p, "/api/v1/namespaces/")
			l, ok := nsLabels[name]
			if !ok {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"labels": l, "resourceVersion": "77"}})
		case r.Method == "PATCH" && strings.HasPrefix(p, "/api/v1/namespaces/"):
			if strings.HasSuffix(p, "/racing") {
				w.WriteHeader(409)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		case p == "/api":
			_, _ = w.Write([]byte(`{"versions":["v1"]}`))
		case p == "/api/v1":
			_, _ = w.Write([]byte(`{"resources":[{"name":"namespaces","kind":"Namespace","namespaced":false},{"name":"pods","kind":"Pod","namespaced":true},{"name":"pods/log","kind":"Pod","namespaced":true},{"name":"nodes","kind":"Node","namespaced":false}]}`))
		case p == "/apis":
			_, _ = w.Write([]byte(`{"groups":[{"versions":[{"groupVersion":"apiextensions.crossplane.io/v1"},{"groupVersion":"postgresql.cnpg.io/v1"},{"groupVersion":"other.example.test/v1"}]}]}`))
		case p == "/apis/apiextensions.crossplane.io/v1":
			_, _ = w.Write([]byte(`{"resources":[{"name":"compositions","kind":"Composition","namespaced":false},{"name":"clusters","kind":"Cluster","namespaced":false}]}`))
		case p == "/apis/postgresql.cnpg.io/v1":
			_, _ = w.Write([]byte(`{"resources":[{"name":"clusters","kind":"Cluster","namespaced":true},{"name":"backups","kind":"Backup","namespaced":true}]}`))
		case p == "/apis/other.example.test/v1":
			_, _ = w.Write([]byte(`{"resources":[{"name":"widgets","kind":"Widget","namespaced":true}]}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tok, []byte("sa-token\n"), 0o600)
	k := &agent.API{Base: srv.URL, TokenFile: tok, Client: srv.Client(), Grants: agent.DefaultGrantAPI, ArgoNS: "argocd-apps"}
	last := func() call { return calls[len(calls)-1] }

	apps, rv, err := k.ListApplications(bg)
	if err != nil || rv != "9" || len(apps) != 2 {
		t.Fatalf("%v %v %v", apps, rv, err)
	}
	a := apps[0]
	if a.ResourceVersion != "41" || a.Annotations[agent.AnnProtect] != "true" || string(a.Source) == "" || a.Sources != nil ||
		len(a.Owners) != 1 || a.Owners[0] != (agent.OwnerRef{Kind: "ApplicationSet", Name: "tenants"}) ||
		len(a.IgnoreDifferences) != 1 || a.IgnoreDifferences[0].JQPathExpressions[0] != ".spec.sources" ||
		len(a.SyncOptions) != 1 || a.SyncOptions[0] != "RespectIgnoreDifferences=true" {
		t.Errorf("an Application's opt-in fields: %+v", a)
	}
	if m := apps[1]; len(m.Source) != 0 || len(m.Sources) != 2 {
		t.Errorf("sources: %+v", m)
	}

	// The patch: a test of the resource version first, then only spec.source, spec.sources and the marker.
	edit := agent.SourceEdit{Sources: []json.RawMessage{json.RawMessage(`{"repoURL":"x","plugin":{"name":"clearance"}}`)}, Switched: "sources"}
	if err := k.UpdateApplicationSource(bg, apps[1], edit); err != nil {
		t.Fatal(err)
	}
	c := last()
	if c.method != "PATCH" || c.path != "/apis/argoproj.io/v1alpha1/namespaces/argocd-apps/applications/multi" || c.ctype != "application/json-patch+json" {
		t.Errorf("%+v", c)
	}
	var ops []map[string]any
	if err := json.Unmarshal([]byte(c.body), &ops); err != nil {
		t.Fatal(err)
	}
	want := []string{"test /metadata/resourceVersion", "add /spec/sources", "add /metadata/annotations", "add /metadata/annotations/clearance.hangar.io~1switched"}
	var got []string
	for _, o := range ops {
		got = append(got, o["op"].(string)+" "+o["path"].(string))
	}
	if strings.Join(got, ";") != strings.Join(want, ";") || ops[0]["value"] != "5" {
		t.Errorf("ops %v, want %v", got, want)
	}
	// Restoring a sources Application whose source is removed: remove what was there, add what was.
	back := agent.SourceEdit{Source: json.RawMessage(`{"repoURL":"o"}`)}
	app := agent.Application{Name: "web", ResourceVersion: "41", Sources: []json.RawMessage{json.RawMessage(`{}`)},
		Annotations: map[string]string{agent.AnnSwitched: "source"}}
	if err := k.UpdateApplicationSource(bg, app, back); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(last().body), &ops)
	got = nil
	for _, o := range ops {
		got = append(got, o["op"].(string)+" "+o["path"].(string))
	}
	if strings.Join(got, ";") != "test /metadata/resourceVersion;add /spec/source;remove /spec/sources;remove /metadata/annotations/clearance.hangar.io~1switched" {
		t.Errorf("restore ops: %v", got)
	}
	// A patch whose version test fails (the server's 422) is a conflict, not a retry loop.
	if err := k.UpdateApplicationSource(bg, agent.Application{Name: "stale", ResourceVersion: "1"}, back); !errors.Is(err, agent.ErrConflict) {
		t.Errorf("%v", err)
	}

	// A validation error is not a stale read: it is reported as invalid, not retried as a conflict.
	if err := k.UpdateApplicationSource(bg, agent.Application{Name: "invalid", ResourceVersion: "1"}, back); !errors.Is(err, agent.ErrInvalid) || errors.Is(err, agent.ErrConflict) {
		t.Errorf("a validation 422: %v", err)
	}

	set, err := k.GetApplicationSet(bg, "tenants")
	if err != nil || len(set.IgnoreApplicationDifferences) != 1 || set.IgnoreApplicationDifferences[0].Name != "web" {
		t.Errorf("%+v %v", set, err)
	}
	if _, err := k.GetApplicationSet(bg, "absent"); !errors.Is(err, agent.ErrNotFound) {
		t.Errorf("%v", err)
	}

	// Namespaces: adding puts the label and the marker in one patch guarded by the version; an operator's label is left
	// alone; removing needs the marker.
	if err := k.SetNamespaceProtected(bg, "free", true); err != nil {
		t.Fatal(err)
	}
	if c := last(); c.method != "PATCH" || c.ctype != "application/merge-patch+json" || !strings.Contains(c.body, `"clearance.hangar.io/protected":"true"`) ||
		!strings.Contains(c.body, `"clearance.hangar.io/protected-by":"optin"`) || !strings.Contains(c.body, `"resourceVersion":"77"`) {
		t.Errorf("label: %+v", c)
	}
	n := len(calls)
	if err := k.SetNamespaceProtected(bg, "theirs", true); err != nil || len(calls) != n+1 || last().method != "GET" {
		t.Errorf("a namespace already protected is not written: %v", calls[n:])
	}
	if err := k.SetNamespaceProtected(bg, "theirs", false); !errors.Is(err, agent.ErrNotOurs) {
		t.Errorf("an operator's label is not removed: %v", err)
	}
	if err := k.SetNamespaceProtected(bg, "mine", false); err != nil {
		t.Fatal(err)
	}
	if b := last().body; !strings.Contains(b, `"clearance.hangar.io/protected":null`) || !strings.Contains(b, `"clearance.hangar.io/protected-by":null`) {
		t.Errorf("unlabel: %s", b)
	}
	if err := k.SetNamespaceProtected(bg, "gone", true); !errors.Is(err, agent.ErrNotFound) {
		t.Errorf("%v", err)
	}

	// Discovery: subresources skipped, a kind served with two scopes dropped (Cluster), the rest as the cluster says.
	sc, err := k.ClusterScopes(bg)
	if err != nil {
		t.Fatal(err)
	}
	if !sc["Namespace"] || !sc["Node"] || sc["Pod"] || !sc["Composition"] || sc["Backup"] || sc["Widget"] {
		t.Errorf("scopes: %v", sc)
	}
	if _, ok := sc["Cluster"]; ok {
		t.Errorf("an ambiguous kind is not guessed: %v", sc)
	}
}
