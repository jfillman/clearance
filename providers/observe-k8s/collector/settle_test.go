package collector

import (
	"testing"
	"time"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// stampedConfigMap is what Argo CD applies: the ConfigMap with the gate's stamp naming the grant.
func stampedConfigMap(grantID string) map[string]any {
	cm := configMap("shop", "cfg", "7", map[string]any{"k": "v"})
	cm["metadata"].(map[string]any)["annotations"] = map[string]any{"clearance.example.com/grant": grantID}
	return cm
}

func grantOf(t *testing.T, r *rig, id string, obj map[string]any) agent.Grant {
	t.Helper()
	yes := true
	g := agent.Grant{Namespace: "shop", Name: "shop-" + id, Valid: &yes, Labels: map[string]string{agent.LabelActive: "true"},
		Spec: agent.GrantSpec{ExpiresAt: t0.Add(time.Hour).Format(time.RFC3339),
			Objects: map[string]agent.GrantObject{"/ConfigMap/cfg": {Rendered: r.pipe.CanonicalHash(obj)}}}}
	g.Spec.Clearance.ID = id
	return g
}

// A write that names a grant the collector does not know yet is held, not flagged. The grant is cleared a moment before
// Argo CD stamps its objects, and the Argo CD agent writes the ClearanceGrant up to a sync later. When the settle window
// is over the grants are read again, and the write is decided: attributed if the grant is known now, the unknown grant it
// looked like if not. Held events are committed with the cursor, so a restart loses none.
func TestUnknownGrantSettlesBeforeItIsDecided(t *testing.T) {
	obj := stampedConfigMap("clr_late")
	push := func(r *rig) {
		r.push(auditEv(argo, "argocd-application-controller/v3", "patch", "configmaps", "shop", "cfg", 200,
			map[string]any{"responseObject": obj}))
	}
	t.Run("the grant becomes known in the window", func(t *testing.T) {
		r := newRig(t)
		push(r)
		r.drain()
		if n := len(r.core.kind("assessment")) + len(r.core.kind("observation")); n != 0 {
			t.Fatalf("%d records posted while the event waits", n)
		}
		if c := r.c.Counters(); c.Events != 1 || c.Assessed != 0 || len(r.c.held) != 1 {
			t.Fatalf("counters %+v, held %d", c, len(r.c.held))
		}
		r.grants.gs = []agent.Grant{grantOf(t, r, "clr_late", obj)} // the agent's sync lands
		r.advance(time.Minute)
		r.drain()
		if n := len(r.core.kind("assessment")); n != 0 {
			t.Fatalf("decided early: %d assessments", n)
		}
		r.advance(3 * time.Minute)
		r.drain()
		as := r.core.kind("assessment")
		if len(as) != 1 || sub(as[0], "attribution")["signal"] != "grant-annotation+rendered-hash" || as[0]["coverage"] != "authorized-and-verified" {
			t.Fatalf("assessments %v", as)
		}
		if c := r.c.Counters(); c.Events != 1 || c.Assessed != 1 || len(r.c.held) != 0 || len(r.c.meta.Held) != 0 {
			t.Fatalf("counted once, nothing held: %+v held %d", c, len(r.c.held))
		}
	})
	t.Run("the grant never becomes known", func(t *testing.T) {
		r := newRig(t)
		push(r)
		r.drain()
		r.advance(4 * time.Minute)
		r.drain()
		as := r.core.kind("assessment")
		if len(as) != 1 || sub(as[0], "attribution")["signal"] != "grant-annotation.unknown" || as[0]["coverage"] != "out-of-band-detected" {
			t.Fatalf("assessments %v", as)
		}
		// the observation is still of the event as it was: its own time, not the time it was decided
		if o := r.core.kind("observation"); len(o) != 1 || sub(o[0], "times")["observed"] != t0.Format(time.RFC3339Nano) {
			t.Fatalf("observations %v", o)
		}
	})
	t.Run("a restart in the window loses nothing", func(t *testing.T) {
		dir := t.TempDir()
		r := newRigIn(t, dir)
		push(r)
		r.drain()
		r.q.Close()
		r2 := newRigIn(t, dir)
		if len(r2.c.held) != 1 {
			t.Fatalf("held after the restart: %d", len(r2.c.held))
		}
		r2.grants.gs = []agent.Grant{grantOf(t, r2, "clr_late", obj)}
		*r2.clock = t0.Add(4 * time.Minute)
		r2.drain()
		if as := r2.core.kind("assessment"); len(as) != 1 || sub(as[0], "attribution")["signal"] != "grant-annotation+rendered-hash" {
			t.Fatalf("assessments %v", as)
		}
	})
	t.Run("settle off decides at once", func(t *testing.T) {
		r := newRig(t, func(c *Config, _ *Deps) { c.GrantSettle = -1 })
		push(r)
		r.drain()
		if as := r.core.kind("assessment"); len(as) != 1 || sub(as[0], "attribution")["signal"] != "grant-annotation.unknown" {
			t.Fatalf("assessments %v", as)
		}
	})
	t.Run("a full held list decides at once", func(t *testing.T) {
		r := newRig(t, func(c *Config, _ *Deps) { c.MaxHeld = 1 })
		push(r)
		push(r)
		r.drain()
		if as := r.core.kind("assessment"); len(as) != 1 || len(r.c.held) != 1 {
			t.Fatalf("%d assessments, %d held", len(as), len(r.c.held))
		}
	})
}
