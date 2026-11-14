package agent_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/token"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// The opt-in's side of the fake cluster: Application writes guarded by resourceVersion, the namespace label with the
// agent's marker, the ApplicationSet, the discovery. It fails the test when a protected namespace the agent labelled is
// ever left without an active, valid grant (the order the doc states).

func (k *fakeKube) UpdateApplicationSource(_ context.Context, app agent.Application, e agent.SourceEdit) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.verbs["app"]++
	if err := k.failApp[app.Name]; err != nil {
		return err
	}
	for i, a := range k.apps {
		if a.Namespace != app.Namespace || a.Name != app.Name {
			continue
		}
		if a.ResourceVersion != app.ResourceVersion {
			return fmt.Errorf("%w: resourceVersion %s is not %s", agent.ErrConflict, app.ResourceVersion, a.ResourceVersion)
		}
		n, _ := strconv.Atoi(a.ResourceVersion)
		a.ResourceVersion = strconv.Itoa(n + 1)
		a.Source, a.Sources = e.Source, e.Sources
		ann := map[string]string{}
		for x, y := range a.Annotations {
			ann[x] = y
		}
		if e.Switched == "" {
			delete(ann, agent.AnnSwitched)
		} else {
			ann[agent.AnnSwitched] = e.Switched
		}
		a.Annotations = ann
		k.apps[i] = a
		k.log = append(k.log, fmt.Sprintf("app %s/%s switched=%q", a.Namespace, a.Name, e.Switched))
		return nil
	}
	return agent.ErrNotFound
}

func (k *fakeKube) GetApplicationSet(_ context.Context, name string) (agent.AppSet, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if s, ok := k.appsets[name]; ok {
		return s, nil
	}
	return agent.AppSet{}, agent.ErrNotFound
}

func (k *fakeKube) ClusterScopes(context.Context) (map[string]bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.verbs["scopes"]++
	if k.scopeErr != nil {
		return nil, k.scopeErr
	}
	out := map[string]bool{}
	for a, b := range k.scopes {
		out[a] = b
	}
	return out, nil
}

// hasActiveValid says whether namespace ns holds an active, valid grant.
func (k *fakeKube) hasActiveValid(ns string) bool {
	for _, g := range k.grants {
		if g.Namespace == ns && g.Active() && g.Valid != nil && *g.Valid {
			return true
		}
	}
	return false
}

// checkLabelled fails the test if a namespace the agent labelled (marker) has no active, valid grant: admission would
// refuse every write there.
func (k *fakeKube) checkLabelled(when string) {
	for ns, l := range k.ns {
		if l[agent.LabelProtectedBy] == agent.ProtectedByOptIn && l[agent.LabelProtected] == "true" && !k.hasActiveValid(ns) {
			k.t.Errorf("after %s: namespace %s is labelled protected and has no active, valid grant", when, ns)
		}
	}
}

func (k *fakeKube) SetNamespaceProtected(_ context.Context, ns string, protected bool) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.verbs["ns"]++
	if err := k.failNS[ns]; err != nil {
		return err
	}
	l, ok := k.ns[ns]
	if !ok {
		l, ok = map[string]string{}, false
	}
	if protected {
		if l[agent.LabelProtected] == "true" {
			k.verbs["ns"]--
			return nil
		}
		if !k.hasActiveValid(ns) {
			k.t.Errorf("namespace %s labelled protected before its grant is active and valid", ns)
		}
		n := map[string]string{}
		for a, b := range l {
			n[a] = b
		}
		n[agent.LabelProtected], n[agent.LabelProtectedBy] = "true", agent.ProtectedByOptIn
		k.ns[ns] = n
		k.log = append(k.log, "label "+ns)
		return nil
	}
	if l[agent.LabelProtected] != "true" && l[agent.LabelProtectedBy] == "" {
		k.verbs["ns"]--
		return nil
	}
	if l[agent.LabelProtectedBy] != agent.ProtectedByOptIn {
		k.verbs["ns"]--
		return agent.ErrNotOurs
	}
	n := map[string]string{}
	for a, b := range l {
		if a != agent.LabelProtected && a != agent.LabelProtectedBy {
			n[a] = b
		}
	}
	k.ns[ns] = n
	k.log = append(k.log, "unlabel "+ns)
	return nil
}

var errBoom = errors.New("boom")

// feedClaims puts one cleared change of app (in env prod, on hangar-prod) with these objects in namespace ns into the
// signed feed, replacing nothing: the world's claims are kept.
func feedClaims(w *optWorld, app, ns, id string, hashes ...string) {
	var objs []token.Object
	for i, h := range hashes {
		objs = append(objs, deploy(fmt.Sprintf("%s-%d", app, i), h))
	}
	c := claim(w.feeds, id, ns, w.clock.now(), objs...)
	c.Target.App = app
	c.Expires = w.clock.now().Add(time.Hour).Unix()
	w.feeds.claims = append(w.feeds.claims, c)
	w.feeds.publish()
}

func newAgentDeny(w *optWorld, deny ...string) (*agent.Agent, error) {
	a, err := agent.New(agent.Config{Cluster: "hangar-prod", Environment: "prod", Version: "0.0.0-test", Wait: agent.TestWaitPin,
		ArgoNamespace: "argocd-apps", Projects: []string{"tenants"}, StateNS: "clearance-system",
		OptIn: agent.OptIn{Enabled: true, DenyApps: deny}},
		w.kube, w.feeds, w.core, w.clock.now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return nil, err
	}
	return a, a.Load(bg)
}

// feedObjs puts one cleared change of app (env prod, hangar-prod) with exactly these objects in ns into the signed feed.
func feedObjs(w *optWorld, app, ns, id string, decided time.Time, objs ...token.Object) {
	c := claim(w.feeds, id, ns, decided, objs...)
	c.Target.App = app
	c.Expires = decided.Add(time.Hour).Unix()
	w.feeds.claims = append(w.feeds.claims, c)
}

func (w *optWorld) publishSync() {
	w.t.Helper()
	w.feeds.publish()
	if err := w.sync(); err != nil {
		w.t.Fatal(err)
	}
}

func (w *optWorld) merged(ns string) (agent.Grant, bool) {
	g, ok := w.kube.grants[ns+"/"+agent.MergedGrantName]
	return g, ok
}

func (w *optWorld) labelled(ns string) bool { return w.kube.ns[ns][agent.LabelProtected] == "true" }

func mustAgent(t *testing.T, w *optWorld, edit func(*agent.Config)) *agent.Agent {
	cfg := agent.Config{Cluster: "hangar-prod", Environment: "prod", Version: "0.0.0-test", Wait: agent.TestWaitPin,
		ArgoNamespace: "argocd-apps", Projects: []string{"tenants"}, StateNS: "clearance-system",
		OptIn: agent.OptIn{Enabled: true, DenyApps: agent.DefaultDenyApps}}
	edit(&cfg)
	a, err := agent.New(cfg, w.kube, w.feeds, w.core, w.clock.now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Load(bg); err != nil {
		t.Fatal(err)
	}
	return a
}
