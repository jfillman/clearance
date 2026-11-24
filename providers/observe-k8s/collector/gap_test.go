package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/observe"
)

func change(c *Cache, typ, rv string, data map[string]any, at time.Time) Change {
	ch, _ := c.Put("ConfigMap", typ, configMap("shop", "web-config", rv, data), at, false)
	return ch
}

func testCache() *Cache {
	return NewCache(func(o map[string]any) string {
		b, _ := jsonCanon(o)
		return string(b)
	})
}

// jsonCanon hashes what the pipeline hashes, near enough for the cache tests: data only.
func jsonCanon(o map[string]any) ([]byte, error) {
	return JSON(map[string]any{"data": o["data"]}), nil
}

func TestCacheBeforeByResourceVersionAndWithout(t *testing.T) {
	c := testCache()
	c.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "10", map[string]any{"v": "1"}), t0.Add(-time.Hour), true)
	c.Put("ConfigMap", "MODIFIED", configMap("shop", "web-config", "11", map[string]any{"v": "2"}), t0, false)
	c.Put("ConfigMap", "MODIFIED", configMap("shop", "web-config", "12", map[string]any{"v": "3"}), t0.Add(time.Second), false)
	val := func(o map[string]any) any { return o["data"].(map[string]any)["v"] }
	if got := val(c.Before("ConfigMap", "shop", "web-config", "11", t0, false)); got != "1" {
		t.Fatalf("before rv 11 is %v, want 1", got)
	}
	if got := val(c.Before("ConfigMap", "shop", "web-config", "12", t0, false)); got != "2" {
		t.Fatalf("before rv 12 is %v, want 2", got)
	}
	// no resourceVersion (the event came at Metadata): the audit event trails the watch, so before is the second newest
	if got := val(c.Before("ConfigMap", "shop", "web-config", "", t0.Add(time.Second), false)); got != "2" {
		t.Fatalf("before, no rv: %v", got)
	}
	if c.Before("ConfigMap", "shop", "nope", "", t0, false) != nil {
		t.Fatal("an object the cache has never seen has no before")
	}
	// a delete: the cache drops the live entry but keeps the history for the delete's audit event
	c.Put("ConfigMap", "DELETED", configMap("shop", "web-config", "13", map[string]any{"v": "3"}), t0.Add(2*time.Second), false)
	if got := val(c.Before("ConfigMap", "shop", "web-config", "", t0.Add(2*time.Second), true)); got != "3" {
		t.Fatalf("before the delete is %v, want 3", got)
	}
}

func TestWatchChangeKindsAreTold(t *testing.T) {
	c := testCache()
	if ch := change(c, "ADDED", "1", map[string]any{"v": "1"}, t0); !ch.Created || !ch.Desired {
		t.Fatalf("%+v", ch)
	}
	if ch := change(c, "MODIFIED", "2", map[string]any{"v": "1"}, t0); ch.Desired {
		t.Fatal("a change with the same desired state (a status write, a label the hash ignores) is not a desired change")
	}
	if ch := change(c, "MODIFIED", "3", map[string]any{"v": "2"}, t0); !ch.Desired {
		t.Fatal("a data change is desired state")
	}
	if ch := change(c, "DELETED", "4", map[string]any{"v": "2"}, t0); !ch.Deleted || !ch.Desired {
		t.Fatalf("%+v", ch)
	}
}

// A change on the watch with no audit event is a gap; one with an audit event is not, in either arrival order.
func TestGapsBothArrivalOrders(t *testing.T) {
	g := NewGaps(3 * time.Minute)
	c := testCache()
	c.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "1", map[string]any{"v": "0"}), t0, true)

	// watch first, audit after
	g.Watched(change(c, "MODIFIED", "2", map[string]any{"v": "1"}, t0))
	g.Audited("ConfigMap", "shop", "web-config", "2", t0, t0.Add(20*time.Second))
	// audit first, watch after
	g.Audited("ConfigMap", "shop", "web-config", "3", t0.Add(time.Minute), t0.Add(time.Minute))
	g.Watched(change(c, "MODIFIED", "3", map[string]any{"v": "2"}, t0.Add(time.Minute)))
	// no audit at all
	g.Watched(change(c, "MODIFIED", "4", map[string]any{"v": "3"}, t0.Add(2*time.Minute)))
	// a status-only write: not a desired change, never a gap
	g.Watched(change(c, "MODIFIED", "5", map[string]any{"v": "3"}, t0.Add(2*time.Minute)))

	if got := g.Expired(t0.Add(4*time.Minute), 0); len(got) != 0 {
		t.Fatalf("expired too early: %v", got)
	}
	got := g.Expired(t0.Add(6*time.Minute), 0)
	if len(got) != 1 || got[0].RV != "4" {
		t.Fatalf("gaps %+v, want only the change at rv 4", got)
	}
	// a queue that is behind pushes the deadline out: the audit event may be in it
	g.Watched(change(c, "MODIFIED", "6", map[string]any{"v": "4"}, t0.Add(10*time.Minute)))
	if got := g.Expired(t0.Add(14*time.Minute+30*time.Second), 5*time.Minute); len(got) != 0 {
		t.Fatalf("a change whose audit event may still be in the queue is not a gap yet: %v", got)
	}
	if m, r, _ := g.Counts(); m != 2 || r != 1 {
		t.Fatalf("matched %d reported %d", m, r)
	}
}

// A foreground deletion ends when a write (the garbage collector's) removes the last finalizer: the API server then deletes
// the object, and the DELETED event's resourceVersion is the deletion's, which no audit event carries. It is matched to
// the write that ended it by time, in either order; a plain delete is still matched by version only.
func TestFinalizedDeleteIsMatchedToTheWriteThatEndedIt(t *testing.T) {
	marked := func(rv string) map[string]any {
		o := configMap("shop", "web-config", rv, map[string]any{"v": "1"})
		md := o["metadata"].(map[string]any)
		md["deletionTimestamp"], md["finalizers"] = "2026-11-01T00:00:00Z", []any{"foregroundDeletion"}
		return o
	}
	for _, auditFirst := range []bool{false, true} {
		g := NewGaps(3 * time.Minute)
		c := testCache()
		c.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "10", map[string]any{"v": "1"}), t0, true)
		// the delete request marks it (rv 11) and is audited at that version
		g.Audited("ConfigMap", "shop", "web-config", "11", t0, t0.Add(time.Second))
		if ch, ok := c.Put("ConfigMap", "MODIFIED", marked("11"), t0, false); ok {
			g.Watched(ch)
		}
		// the garbage collector's patch removes the finalizer; its audit event reports rv 12, the deletion is rv 13
		del, ok := c.Put("ConfigMap", "DELETED", marked("13"), t0.Add(2*time.Second), false)
		if !ok || !del.Deleted || !del.Finalized {
			t.Fatalf("a delete of a marked object is finalized: %+v", del)
		}
		if auditFirst {
			g.AuditedVerb("ConfigMap", "shop", "web-config", "12", "patch", t0.Add(2*time.Second), t0.Add(2*time.Second))
			g.Watched(del)
		} else {
			g.Watched(del)
			g.AuditedVerb("ConfigMap", "shop", "web-config", "12", "patch", t0.Add(2*time.Second), t0.Add(6*time.Second))
		}
		if got := g.Expired(t0.Add(10*time.Minute), 0); len(got) != 0 {
			t.Fatalf("audit first %v: a finalized delete reported as a gap: %+v", auditFirst, got)
		}
	}

	// a plain delete (no deletionTimestamp) is not finalized and still needs its own version
	g := NewGaps(3 * time.Minute)
	c := testCache()
	c.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "20", map[string]any{"v": "1"}), t0, true)
	del, _ := c.Put("ConfigMap", "DELETED", configMap("shop", "web-config", "21", map[string]any{"v": "1"}), t0, false)
	if del.Finalized {
		t.Fatalf("a plain delete is not finalized: %+v", del)
	}
	g.Watched(del)
	g.Audited("ConfigMap", "shop", "web-config", "99", t0, t0.Add(time.Second)) // a write at another version
	if got := g.Expired(t0.Add(10*time.Minute), 0); len(got) != 1 || got[0].RV != "21" {
		t.Fatalf("a plain delete with no audit event at its version is a gap: %+v", got)
	}
	// and a finalized delete with no audited write near it is still a gap
	g = NewGaps(3 * time.Minute)
	c = testCache()
	c.Put("ConfigMap", "ADDED", marked("30"), t0, true)
	del, _ = c.Put("ConfigMap", "DELETED", marked("31"), t0, false)
	g.Watched(del)
	g.AuditedVerb("ConfigMap", "shop", "web-config", "29", "patch", t0.Add(-5*time.Minute), t0.Add(time.Second)) // long before it
	if got := g.Expired(t0.Add(10*time.Minute), 0); len(got) != 1 || !got[0].Finalized {
		t.Fatalf("a finalized delete with no audited write within Match is a gap: %+v", got)
	}
}

// An Argo CD hook deletes its object (foreground) and creates it again under the same name seconds later. The create's
// audit event may arrive before the finalizer write's: the finalized delete must not take it, in either arrival order.
func TestFinalizedDeleteDoesNotTakeTheRecreatesAudit(t *testing.T) {
	marked := map[string]any{"name": "web-config", "namespace": "shop", "resourceVersion": "13", "uid": "u1",
		"deletionTimestamp": "2026-11-01T00:00:00Z"}
	for _, watchFirst := range []bool{true, false} {
		g := NewGaps(3 * time.Minute)
		c := testCache()
		c.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "10", map[string]any{"v": "1"}), t0, true)
		del, _ := c.Put("ConfigMap", "DELETED", map[string]any{"metadata": marked, "data": map[string]any{"v": "1"}}, t0.Add(time.Second), false)
		add, _ := c.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "14", map[string]any{"v": "1"}), t0.Add(2*time.Second), false)
		if watchFirst {
			g.Watched(del)
			g.Watched(add)
		}
		g.AuditedVerb("ConfigMap", "shop", "web-config", "14", "create", t0.Add(2*time.Second), t0.Add(3*time.Second))
		g.AuditedVerb("ConfigMap", "shop", "web-config", "12", "patch", t0.Add(time.Second), t0.Add(4*time.Second))
		if !watchFirst {
			g.Watched(del)
			g.Watched(add)
		}
		if got := g.Expired(t0.Add(10*time.Minute), 0); len(got) != 0 {
			t.Fatalf("watch first %v: gaps %+v", watchFirst, got)
		}
	}
}

// The collector turns an unaudited change into an observation and a not-attributed audit-gap assessment, and degrades
// the feed (the core writes the observation.audit-gap record from the degraded health record).
func TestUnauditedChangeBecomesAnAuditGapRecord(t *testing.T) {
	r := newRig(t)
	r.c.hb.seen, r.c.hb.level = t0, "Metadata"
	r.c.d.Kube = noKube{}
	r.c.cfg.HeartbeatCM, r.c.cfg.Namespace = "hb", "clearance-system"
	r.c.cache.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "1", map[string]any{"v": "0"}), t0.Add(-time.Hour), true)
	ch, _ := r.c.cache.Put("ConfigMap", "MODIFIED", configMap("shop", "web-config", "2", map[string]any{"v": "1"}), t0, false)
	r.c.gaps.Watched(ch)
	r.advance(10 * time.Minute)
	r.c.hb.seen = r.clock.Add(-time.Second)
	if err := r.c.HealthOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	obs, as := r.core.kind("observation"), r.core.kind("assessment")
	if len(obs) != 1 || len(as) != 1 {
		t.Fatalf("%d observations %d assessments", len(obs), len(as))
	}
	if sub(obs[0], "source")["level"] != "watch" || !strings.Contains(sub(obs[0], "actor")["subject"].(string), "no audit event") || sub(obs[0], "state_change") == nil {
		t.Fatalf("observation %v", obs[0])
	}
	if as[0]["coverage"] != "observed-not-attributed" || sub(as[0], "attribution")["signal"] != "audit-gap" {
		t.Fatalf("assessment %v", as[0])
	}
	h := r.core.kind("observation.health")[0]
	hs := sub(h, "health")
	if hs["state"] != "degraded" {
		t.Fatalf("health state %v: an audit gap degrades the feed", hs["state"])
	}
	failed := ""
	for _, c := range hs["checks"].([]any) {
		if m := c.(map[string]any); m["ok"] == false {
			failed += m["name"].(string) + " "
		}
	}
	if !strings.Contains(failed, CheckGap) {
		t.Fatalf("failed checks %q", failed)
	}
	// the gap holds the feed degraded for GapHold, then it clears
	r.advance(r.c.cfg.GapHold + time.Minute)
	r.c.hb.seen = r.clock.Add(-time.Second)
	if err := r.c.HealthOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	hs = sub(r.core.kind("observation.health")[1], "health")
	if hs["state"] != "healthy" {
		t.Fatalf("after the hold: %v", hs)
	}
	_ = observe.Healthy
}

// Audit events of the watched kinds arrive in the processor and account for their watch change.
func TestAuditEventInTheQueueAccountsForTheWatchChange(t *testing.T) {
	r := newRig(t)
	r.c.cache.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "1", map[string]any{"v": "0"}), t0.Add(-time.Hour), true)
	ch, _ := r.c.cache.Put("ConfigMap", "MODIFIED", configMap("shop", "web-config", "2", map[string]any{"v": "1"}), t0, false)
	r.c.gaps.Watched(ch)
	r.push(auditEv(human, "kubectl/v1.36.0", "update", "configmaps", "shop", "web-config", 200,
		map[string]any{"responseObject": configMap("shop", "web-config", "2", map[string]any{"v": "1"})}))
	r.drain()
	if _, _, pending := r.c.gaps.Counts(); pending != 0 {
		t.Fatalf("%d watch changes still wait for an audit event that was processed", pending)
	}
	if got := r.c.gaps.Expired(t0.Add(time.Hour), 0); len(got) != 0 {
		t.Fatalf("a reported change became a gap: %v", got)
	}
}

// finalizedDelete is a DELETED change of a ConfigMap already marked for deletion, seen at `at`.
func finalizedDelete(c *Cache, rv string, at time.Time) Change {
	o := configMap("shop", "web-config", rv, map[string]any{"v": "1"})
	o["metadata"].(map[string]any)["deletionTimestamp"] = "2026-11-01T00:00:00Z"
	ch, _ := c.Put("ConfigMap", "DELETED", o, at, false)
	return ch
}

// A create recorded at Metadata (no response object, so no resourceVersion) is never what ended a finalized delete:
// it accounts for the recreate, and the delete waits for an update or patch, in either arrival order.
func TestFinalizedDeleteNeverTakesACreateWithoutAVersion(t *testing.T) {
	for _, auditFirst := range []bool{false, true} {
		g := NewGaps(3 * time.Minute)
		c := testCache()
		c.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "10", map[string]any{"v": "1"}), t0, true)
		del := finalizedDelete(c, "13", t0.Add(time.Second))
		add, _ := c.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "14", map[string]any{"v": "1"}), t0.Add(2*time.Second), false)
		if !auditFirst {
			g.Watched(del)
			g.Watched(add)
		}
		g.AuditedVerb("ConfigMap", "shop", "web-config", "", "create", t0.Add(2*time.Second), t0.Add(3*time.Second))
		if auditFirst {
			g.Watched(del)
			g.Watched(add)
		}
		got := g.Expired(t0.Add(10*time.Minute), 0)
		if len(got) != 1 || !got[0].Finalized || got[0].RV != "13" {
			t.Fatalf("audit first %v: want only the finalized delete as a gap (no write ended it), got %+v", auditFirst, got)
		}
	}
}

// A dryRun=All update was never persisted and ended nothing: it does not account for a finalized delete inside its
// window, so the delete stays a gap. A dryRun parameter with no value persists and still counts.
func TestDryRunAllUpdateDoesNotAccountForAFinalizedDelete(t *testing.T) {
	for _, tc := range []struct {
		uri string
		gap bool
	}{
		{"/api/v1/namespaces/shop/configmaps/web-config?dryRun=All", true},
		{"/api/v1/namespaces/shop/configmaps/web-config?fieldManager=x&dryRun=All", true},
		{"/api/v1/namespaces/shop/configmaps/web-config?dryRun", false},
		{"/api/v1/namespaces/shop/configmaps/web-config", false},
	} {
		r := newRig(t)
		r.c.cache.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "10", map[string]any{"v": "1"}), t0.Add(-time.Hour), true)
		r.c.gaps.Watched(finalizedDelete(r.c.cache, "13", t0))
		resp := configMap("shop", "web-config", "12", map[string]any{"v": "1"}) // the write that took the last finalizer off
		resp["metadata"].(map[string]any)["deletionTimestamp"] = "2026-11-01T00:00:00Z"
		r.push(auditEv(human, "kubectl/v1.36.0", "update", "configmaps", "shop", "web-config", 200,
			map[string]any{"requestURI": tc.uri, "responseObject": resp}))
		r.drain()
		got := r.c.gaps.Expired(t0.Add(time.Hour), 0)
		if (len(got) == 1) != tc.gap || len(got) > 1 {
			t.Fatalf("%s: gaps %+v, want a gap: %v", tc.uri, got, tc.gap)
		}
	}
}

// A DELETE can ask for dryRun=All in its DeleteOptions body rather than the query: it persisted nothing either, and does
// not account for a change the watch saw (here a plain delete matched by time, as a Metadata event is).
func TestDryRunAllInADeleteBodyAccountsForNothing(t *testing.T) {
	for _, dry := range []bool{true, false} {
		r := newRig(t)
		r.c.cache.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "10", map[string]any{"v": "1"}), t0.Add(-time.Hour), true)
		del, _ := r.c.cache.Put("ConfigMap", "DELETED", configMap("shop", "web-config", "11", map[string]any{"v": "1"}), t0, false)
		r.c.gaps.Watched(del)
		body := map[string]any{"kind": "DeleteOptions", "apiVersion": "meta.k8s.io/v1"}
		if dry {
			body["dryRun"] = []any{"All"}
		}
		ev := auditEv(human, "kubectl/v1.36.0", "delete", "configmaps", "shop", "web-config", 200,
			map[string]any{"level": "Request", "requestURI": "/api/v1/namespaces/shop/configmaps/web-config", "requestObject": body})
		r.push(ev)
		r.drain()
		if got := r.c.gaps.Expired(t0.Add(time.Hour), 0); (len(got) == 1) != dry {
			t.Fatalf("dryRun body %v: gaps %+v", dry, got)
		}
	}
}

// After a same-name recreate, a write to the new object whose audit event arrives before its watch change is not taken
// by the finalized delete: its response object is not marked for deletion, and it is too late besides. The write that
// ended the delete is matched to it, and the later write to its own change, in every arrival order.
func TestFinalizedDeleteDoesNotTakeALaterWriteToTheRecreate(t *testing.T) {
	no, yes := false, true
	for _, marked := range []*bool{&no, nil} { // RequestResponse (unmarked response) and Metadata (no response)
		g := NewGaps(3 * time.Minute)
		c := testCache()
		c.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "10", map[string]any{"v": "1"}), t0, true)
		g.Watched(finalizedDelete(c, "13", t0.Add(time.Second)))
		add, _ := c.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "14", map[string]any{"v": "1"}), t0.Add(5*time.Second), false)
		g.Watched(add)
		g.AuditedWrite("ConfigMap", "shop", "web-config", "14", "create", &no, t0.Add(5*time.Second), t0.Add(6*time.Second))
		// the new object's update, audited before the watch shows it
		g.AuditedWrite("ConfigMap", "shop", "web-config", "15", "update", marked, t0.Add(8*time.Second), t0.Add(9*time.Second))
		// the garbage collector's patch that ended the delete, read late
		g.AuditedWrite("ConfigMap", "shop", "web-config", "12", "patch", &yes, t0.Add(time.Second), t0.Add(10*time.Second))
		mod, _ := c.Put("ConfigMap", "MODIFIED", configMap("shop", "web-config", "15", map[string]any{"v": "2"}), t0.Add(8*time.Second), false)
		g.Watched(mod)
		if got := g.Expired(t0.Add(10*time.Minute), 0); len(got) != 0 {
			t.Fatalf("marked %v: gaps %+v", marked, got)
		}
	}
}
