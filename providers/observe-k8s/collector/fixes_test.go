package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/internal/vocab"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

const platformSA = "system:serviceaccount:platform-cd:argocd-application-controller"

// checkOf is the named check of the latest health record: ok and detail.
func (r *rig) checkOf(name string) (ok bool, detail string, found bool) {
	r.t.Helper()
	if err := r.c.HealthOnce(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	hs := r.core.kind("observation.health")
	for _, c := range sub(hs[len(hs)-1], "health")["checks"].([]any) {
		if m := c.(map[string]any); m["name"] == name {
			return m["ok"].(bool), m["detail"].(string), true
		}
	}
	return false, "", false
}

type errGrants struct{ err error }

func (e errGrants) ListGrants(context.Context) ([]agent.Grant, error) { return nil, e.err }

// A cluster with no gate has no ClearanceGrant CRD: with grants disabled nothing is listed and lookups-fresh is ok, saying so.
// A gated cluster whose list answers 404 (the CRD or the role is gone) stays failing, and the message says what to look at: a real
// 404 must never look healthy.
func TestLookupsFreshOnAClusterWithoutTheGate(t *testing.T) {
	t.Run("grants disabled", func(t *testing.T) {
		r := newRig(t, func(_ *Config, d *Deps) {
			d.Lookups.Grants = nil
			d.Lookups.BG = fakeBG{ws: []agent.Window{{ID: "bg1", Cluster: cluster}}}
		})
		ok, detail, found := r.checkOf(CheckLookups)
		if !found || !ok || !strings.Contains(detail, "no gate on this cluster") || !strings.Contains(detail, "break-glass") {
			t.Fatalf("%v %q", ok, detail)
		}
		if id, live := r.c.d.Lookups.BreakGlass(cluster, t0); !live || id != "bg1" {
			t.Fatal("break-glass windows are still read without grants")
		}
		if _, known := r.c.d.Lookups.Grant("clr_x"); known {
			t.Fatal("no grant is known")
		}
	})
	t.Run("grants enabled and the CRD is not served", func(t *testing.T) {
		r := newRig(t, func(_ *Config, d *Deps) {
			d.Lookups.Grants = errGrants{&agent.StatusError{Code: 404, Body: "404 page not found"}}
		})
		ok, detail, _ := r.checkOf(CheckLookups)
		if ok || !strings.Contains(detail, "404") || !strings.Contains(detail, "grants.enabled=false") {
			t.Fatalf("%v %q", ok, detail)
		}
	})
	t.Run("grants enabled and forbidden", func(t *testing.T) {
		r := newRig(t, func(_ *Config, d *Deps) {
			d.Lookups.Grants = errGrants{&agent.StatusError{Code: 403, Body: "forbidden"}}
		})
		ok, detail, _ := r.checkOf(CheckLookups)
		if ok || strings.Contains(detail, "grants.enabled") {
			t.Fatalf("%v %q", ok, detail)
		}
	})
}

// platformRig is a collector whose rule set names a platform Argo CD controller and whose Application watch is configured.
func platformRig(t *testing.T, opts ...rigOpt) *rig {
	t.Helper()
	opts = append([]rigOpt{func(c *Config, d *Deps) {
		rs, err := pipeline.Load([]byte(strings.Replace(string(pipeline.DefaultRules()), "platform_gitops: []", `platform_gitops: ["`+platformSA+`"]`, 1)))
		if err != nil {
			t.Fatal(err)
		}
		d.Pipeline = pipeline.New(rs, d.Lookups, vocab.Default())
		c.Watches = []WatchSpec{{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications", Kind: "Application", Namespaced: true}}
		c.WatchNS = []string{"platform-cd"}
		d.Kube = noKube{}
		c.HeartbeatCM = "" // no heartbeat in these tests
	}}, opts...)
	return newRig(t, opts...)
}

func platformWrite() map[string]any {
	return auditEv(platformSA, "argocd-application-controller/v3", "patch", "roles", "shop", "reader", 200, map[string]any{"responseObject": map[string]any{
		"kind": "Role", "metadata": map[string]any{"name": "reader", "namespace": "shop",
			"annotations": map[string]any{"argocd.argoproj.io/tracking-id": "platform-rbac:rbac.authorization.k8s.io/Role:shop/reader"}}}})
}

func (r *rig) assessmentSignals() []string {
	var out []string
	for _, a := range r.core.kind("assessment") {
		out = append(out, sub(a, "attribution")["signal"].(string))
	}
	return out
}

// During the collector's own rollout the platform Argo CD is still patching the RBAC that lets the collector watch its
// Applications: the index is empty, and a write decided then is recorded out-of-band for a reason that is not the write's. The
// write waits for the index (every Application watch has listed once), for at most the timeout; past it it is decided as it
// stands and argo-applications-synced says the index never came.
func TestPlatformWritesWaitForTheApplicationIndex(t *testing.T) {
	t.Run("the index syncs in the window", func(t *testing.T) {
		r := platformRig(t)
		r.push(platformWrite())
		r.drain()
		if n := len(r.core.kind("assessment")) + len(r.core.kind("observation")); n != 0 || len(r.c.held) != 1 || r.c.held[0].Reason != heldArgoIndex {
			t.Fatalf("%d records posted, held %+v", n, r.c.held)
		}
		if ok, detail, found := r.checkOf(CheckArgoApps); !found || ok || !strings.Contains(detail, "0 of 1") || !strings.Contains(detail, "1 platform GitOps writes are waiting") {
			t.Fatalf("%v %q %v", ok, detail, found)
		}
		r.advance(time.Minute)
		r.drain()
		if len(r.core.kind("assessment")) != 0 {
			t.Fatal("decided before the index synced")
		}
		// the watch lists: the Application is in the index and the watch is marked synced
		r.c.d.Lookups.PutApplication("ADDED", appObj("platform-cd", "platform-rbac", "4771d88"))
		r.c.mu.Lock()
		r.c.appSynced["applications/platform-cd"] = true
		r.c.mu.Unlock()
		r.drain()
		if sig := r.assessmentSignals(); len(sig) != 1 || sig[0] != "platform-gitops" {
			t.Fatalf("signals %v", sig)
		}
		if len(r.c.held) != 0 || len(r.c.meta.Held) != 0 {
			t.Fatalf("nothing held: %d %d", len(r.c.held), len(r.c.meta.Held))
		}
		if ok, _, _ := r.checkOf(CheckArgoApps); !ok {
			t.Fatal("synced: the check passes")
		}
	})
	t.Run("the index never syncs", func(t *testing.T) {
		r := platformRig(t)
		r.push(platformWrite())
		r.drain()
		r.advance(4 * time.Minute)
		r.drain()
		if len(r.core.kind("assessment")) != 0 {
			t.Fatal("decided before the timeout")
		}
		r.advance(2 * time.Minute)
		r.drain()
		if sig := r.assessmentSignals(); len(sig) != 1 || sig[0] != "service-account.unknown" {
			t.Fatalf("decided as it stands: %v", sig)
		}
		ok, detail, _ := r.checkOf(CheckArgoApps)
		if ok || !strings.Contains(detail, "decided at the timeout") {
			t.Fatalf("%v %q", ok, detail)
		}
	})
	t.Run("a restart in the window loses nothing", func(t *testing.T) {
		dir := t.TempDir()
		r1 := newRigIn(t, dir, func(c *Config, d *Deps) { platformOpt(t, c, d) })
		r1.push(platformWrite())
		r1.drain()
		r1.q.Close()
		r2 := newRigIn(t, dir, func(c *Config, d *Deps) { platformOpt(t, c, d) })
		if len(r2.c.held) != 1 || r2.c.held[0].Reason != heldArgoIndex {
			t.Fatalf("held after the restart: %+v", r2.c.held)
		}
		r2.c.d.Lookups.PutApplication("ADDED", appObj("platform-cd", "platform-rbac", "4771d88"))
		r2.c.mu.Lock()
		r2.c.appSynced["applications/platform-cd"] = true
		r2.c.mu.Unlock()
		r2.drain()
		if sig := r2.assessmentSignals(); len(sig) != 1 || sig[0] != "platform-gitops" {
			t.Fatalf("signals %v", sig)
		}
	})
	t.Run("only a platform controller's write waits", func(t *testing.T) {
		r := platformRig(t)
		r.push(auditEv(human, "kubectl/v1.36.0", "patch", "roles", "shop", "reader", 200, nil))
		r.drain()
		if len(r.c.held) != 0 || len(r.core.kind("assessment")) != 1 {
			t.Fatalf("held %d, assessments %d", len(r.c.held), len(r.core.kind("assessment")))
		}
	})
	t.Run("hold off decides at once", func(t *testing.T) {
		r := platformRig(t, func(c *Config, _ *Deps) { c.ArgoIndexTimeout = -1 })
		r.push(platformWrite())
		r.drain()
		if len(r.c.held) != 0 || len(r.core.kind("assessment")) != 1 {
			t.Fatalf("held %d", len(r.c.held))
		}
	})
	t.Run("without a platform instance the check is absent", func(t *testing.T) {
		r := newRig(t, func(c *Config, d *Deps) {
			c.Watches = []WatchSpec{{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications", Kind: "Application", Namespaced: true}}
			c.WatchNS = []string{"argocd"}
			d.Kube = noKube{}
		})
		if _, _, found := r.checkOf(CheckArgoApps); found {
			t.Fatal("the check is for a cluster that names a platform instance")
		}
	})
}

func platformOpt(t *testing.T, c *Config, d *Deps) {
	rs, err := pipeline.Load([]byte(strings.Replace(string(pipeline.DefaultRules()), "platform_gitops: []", `platform_gitops: ["`+platformSA+`"]`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	d.Pipeline = pipeline.New(rs, d.Lookups, vocab.Default())
	c.Watches = []WatchSpec{{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications", Kind: "Application", Namespaced: true}}
	c.WatchNS = []string{"platform-cd"}
	d.Kube = noKube{}
	c.HeartbeatCM = ""
}

// The Application watch marks the index synced once it has listed; a list that fails (the role the platform Argo CD is still
// patching) does not.
func TestApplicationWatchMarksTheIndexSynced(t *testing.T) {
	path := "/apis/argoproj.io/v1alpha1/namespaces/platform-cd/applications"
	run := func(r *rig, fk Kube) (stop func()) {
		r.c.d.Kube = fk
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { r.c.RunWatches(ctx); close(done) }()
		return func() { cancel(); <-done }
	}
	t.Run("a forbidden list", func(t *testing.T) {
		r := platformRig(t)
		stop := run(r, &deniedListKube{})
		time.Sleep(300 * time.Millisecond)
		synced := r.c.applicationsSynced()
		stop()
		if synced {
			t.Fatal("a list that failed marked the index synced")
		}
	})
	t.Run("a list", func(t *testing.T) {
		r := platformRig(t)
		if r.c.applicationsSynced() {
			t.Fatal("synced before any list")
		}
		fk := &fakeWatchKube{lists: map[string][]map[string]any{path: {appObj("platform-cd", "platform-rbac", "4771d88")}},
			events: make(chan func(fn func(string, map[string]any)), 1)}
		stop := run(r, fk)
		defer stop()
		deadline := time.Now().Add(5 * time.Second)
		for !r.c.applicationsSynced() {
			if time.Now().After(deadline) {
				t.Fatal("the index never synced")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if _, ok := r.c.d.Lookups.Application(cluster, "platform-cd", "platform-rbac"); !ok {
			t.Fatal("the listed Application is in the index")
		}
	})
}

type deniedListKube struct{ fakeWatchKube }

func (*deniedListKube) List(context.Context, string) ([]map[string]any, string, error) {
	return nil, "", errors.New("applications.argoproj.io is forbidden")
}
