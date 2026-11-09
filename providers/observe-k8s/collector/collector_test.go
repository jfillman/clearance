package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/observe"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
	"github.com/jfillman/clearance/providers/observe-k8s/receiver"
)

const (
	argo  = "system:serviceaccount:argocd:argocd-application-controller"
	human = "dana@example.com"
)

// A direct kubectl apply into a protected namespace: an observation with the actor and the diff (before from the watch
// cache, after from the audit event), and an out-of-band assessment. Both would pass the core's own record check.
func TestDirectApplyIsAnExceptionWithActorAndDiff(t *testing.T) {
	r := newRig(t)
	r.c.cache.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "100", map[string]any{"LOG_LEVEL": "info"}), t0.Add(-time.Hour), true)
	r.c.cache.Put("ConfigMap", "MODIFIED", configMap("shop", "web-config", "101", map[string]any{"LOG_LEVEL": "debug"}), t0, false)
	after := configMap("shop", "web-config", "101", map[string]any{"LOG_LEVEL": "debug"})
	r.push(auditEv(human, "kubectl/v1.36.0", "update", "configmaps", "shop", "web-config", 200, map[string]any{"responseObject": after}))
	if n := r.drain(); n != 1 {
		t.Fatalf("handled %d", n)
	}
	obs, as := r.core.kind("observation"), r.core.kind("assessment")
	if len(obs) != 1 || len(as) != 1 {
		t.Fatalf("%d observations, %d assessments", len(obs), len(as))
	}
	o := obs[0]
	if sub(o, "actor")["subject"] != human || sub(o, "resource")["name"] != "web-config" || sub(o, "source")["level"] != "RequestResponse" {
		t.Fatalf("observation %v", o)
	}
	sc := sub(o, "state_change")
	if sub(sc, "before") == nil || sub(sc, "after") == nil {
		t.Fatalf("no state_change: %v", o)
	}
	if got := sub(sub(sc, "before"), "data")["LOG_LEVEL"]; got != "info" {
		t.Fatalf("before is %v: the watch cache's previous version", got)
	}
	a := as[0]
	if a["coverage"] != "out-of-band-detected" || sub(a, "attribution")["signal"] != "kubectl-agent" {
		t.Fatalf("assessment %v", a)
	}
	if d := sub(a, "attribution")["detail"].(string); !strings.Contains(d, "LOG_LEVEL") || !strings.Contains(d, "diff") {
		t.Fatalf("the assessment does not carry the diff: %s", d)
	}
	if about := sub(a, "about")["seq"]; about != json.Number("0") {
		t.Fatalf("about %v", about)
	}
}

// A Secret change names the Secret and its namespace and nothing of its content, at Metadata, even when the live policy
// is wrong and the API server sends the body: the receiver cuts it, the collector never sees a value.
func TestSecretChangeCarriesNoValue(t *testing.T) {
	const value = "c3VwZXItc2VjcmV0LXZhbHVl"
	body := map[string]any{"kind": "Secret", "apiVersion": "v1", "metadata": map[string]any{"name": "db-creds", "namespace": "shop"},
		"data": map[string]any{"password": value}}
	for name, ev := range map[string]map[string]any{
		"policy right (Metadata)": auditEv(human, "kubectl/v1.36.0", "update", "secrets", "shop", "db-creds", 200, map[string]any{"level": "Metadata"}),
		"policy wrong (body sent)": auditEv(human, "kubectl/v1.36.0", "update", "secrets", "shop", "db-creds", 200,
			map[string]any{"requestObject": body, "responseObject": body}),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			batch, _ := json.Marshal(map[string]any{"kind": "EventList", "apiVersion": "audit.k8s.io/v1", "items": []any{ev}})
			items, _, err := receiver.Sanitize(batch) // what the receiver queues
			if err != nil {
				t.Fatal(err)
			}
			if err := r.q.Append(items...); err != nil {
				t.Fatal(err)
			}
			r.drain()
			all := r.core.all()
			if bytes.Contains(all, []byte(value)) || bytes.Contains(all, []byte("password")) || bytes.Contains(all, []byte(`"data"`)) {
				t.Fatalf("a Secret's content is in a record: %s", all)
			}
			o := r.core.kind("observation")
			if len(o) != 1 {
				t.Fatalf("%d observations", len(o))
			}
			res := sub(o[0], "resource")
			if res["kind"] != "Secret" || res["name"] != "db-creds" || res["namespace"] != "shop" || sub(o[0], "source")["level"] != "Metadata" || o[0]["state_change"] != nil {
				t.Fatalf("observation %v", o[0])
			}
			if a := r.core.kind("assessment")[0]; a["coverage"] != "out-of-band-detected" {
				t.Fatalf("a person's write of a Secret is out-of-band: %v", a)
			}
		})
	}
}

// Argo's write of a Secret a grant lists reaches grant-annotation.no-hash (observed, not attributed), as does a prune
// of a listed object; Argo's write of one no grant lists, and a person's write of the listed one, stay out-of-band.
func TestArgoWritesOfGrantListedObjectsAreNotFalseExceptions(t *testing.T) {
	r := newRig(t)
	yes := true
	r.grants.gs = []agent.Grant{{Namespace: "shop", Name: "shop-clr_1", Valid: &yes, Labels: map[string]string{agent.LabelActive: "true"},
		Spec: agent.GrantSpec{ExpiresAt: t0.Add(time.Hour).Format(time.RFC3339), Objects: map[string]agent.GrantObject{
			"/Secret/db-creds": {Rendered: "sha256:aa"}, "apps/Deployment/web": {Rendered: "sha256:bb"}}}}}
	r.grants.gs[0].Spec.Clearance.ID = "clr_1"
	if err := r.c.d.Lookups.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.push(
		auditEv(argo, "argocd-application-controller/v3", "update", "secrets", "shop", "db-creds", 200, map[string]any{"level": "Metadata"}),
		auditEv(argo, "argocd-application-controller/v3", "update", "secrets", "shop", "other", 200, map[string]any{"level": "Metadata"}),
		auditEv(human, "kubectl/v1.36.0", "update", "secrets", "shop", "db-creds", 200, map[string]any{"level": "Metadata"}),
		auditEv(argo, "argocd-application-controller/v3", "delete", "deployments", "shop", "web", 200, nil),
		auditEv(argo, "argocd-application-controller/v3", "delete", "deployments", "shop", "api", 200, nil),
	)
	r.drain()
	want := []struct{ signal, cov string }{
		{"grant-annotation.no-hash", "observed-not-attributed"}, {"argo-controller.no-grant", "out-of-band-detected"},
		{"kubectl-agent", "out-of-band-detected"}, {"grant-annotation.no-hash", "observed-not-attributed"},
		{"argo-controller.no-grant", "out-of-band-detected"}}
	as := r.core.kind("assessment")
	if len(as) != len(want) {
		t.Fatalf("%d assessments", len(as))
	}
	for i, w := range want {
		if got := sub(as[i], "attribution")["signal"]; got != w.signal || as[i]["coverage"] != w.cov {
			t.Errorf("event %d: %v/%v, want %s/%s", i, got, as[i]["coverage"], w.signal, w.cov)
		}
	}
}

// A 403 with a ValidatingAdmissionPolicy denial in the audit annotations is attempted-refused, and the observation says
// why; nothing landed.
func TestAdmissionRefusalIsAttemptedRefused(t *testing.T) {
	r := newRig(t)
	r.push(auditEv(human, "kubectl/v1.36.0", "update", "deployments", "shop", "web", 403, map[string]any{
		"annotations": map[string]any{"validation.policy.admission.k8s.io/validation_failure": `[{"message":"no active clearance grant for shop","policy":"clearance-grant","binding":"b","expressionIndex":0,"validationActions":["Deny"]}]`}}))
	r.drain()
	o, a := r.core.kind("observation")[0], r.core.kind("assessment")[0]
	ac := sub(o, "action")
	if ac["succeeded"] != false || !strings.Contains(ac["refused_reason"].(string), "no active clearance grant") {
		t.Fatalf("action %v", ac)
	}
	if a["coverage"] != "attempted-refused" || sub(a, "attribution")["signal"] != "audit-annotation.vap-denial" {
		t.Fatalf("assessment %v", a)
	}
}

// Nothing is lost when the core is down: the batch stays in the queue, nothing is committed or counted, and the retry
// posts it once.
func TestCoreOutageLosesNothingAndCountsOnce(t *testing.T) {
	r := newRig(t)
	r.push(auditEv(human, "kubectl/v1.36.0", "update", "configmaps", "shop", "x", 200, map[string]any{"responseObject": configMap("shop", "x", "5", nil)}),
		auditEv("system:serviceaccount:kube-system:horizontal-pod-autoscaler", "kube-controller-manager/v1", "update", "deployments", "shop", "web", 200, map[string]any{"objectRef": map[string]any{"resource": "deployments", "namespace": "shop", "name": "web", "subresource": "scale"}}))
	r.core.fail = errBoom
	for i := 0; i < 3; i++ {
		if _, err := r.c.ProcessOnce(context.Background()); err == nil {
			t.Fatal("expected an error")
		}
	}
	if st := r.q.Stats(); st.Pending != 2 {
		t.Fatalf("pending %d: nothing may be acknowledged before it is posted", st.Pending)
	}
	if c := r.c.Counters(); c.Events != 0 {
		t.Fatalf("counted %d events before they were posted", c.Events)
	}
	r.core.fail = nil
	r.drain()
	if len(r.core.kind("observation")) != 1 {
		t.Fatalf("%d observations", len(r.core.kind("observation")))
	}
	c := r.c.Counters()
	if c.Events != 2 || c.Filtered["hpa-scale"] != 1 {
		t.Fatalf("counters %+v: each event counted once, however many retries", c)
	}
}

// A restart mid-flight: the queue holds what was not committed; the pipeline replays it; the core de-duplicates the
// observation on its event id, so the record is not written twice.
func TestRestartReplaysWithoutDuplicates(t *testing.T) {
	dir := t.TempDir()
	r := newRigIn(t, dir)
	r.push(auditEv(human, "kubectl/v1.36.0", "update", "configmaps", "shop", "x", 200, map[string]any{"responseObject": configMap("shop", "x", "5", nil)}))
	// posted, but the process dies before the commit: simulate by posting through the same core and not committing
	b, err := r.q.Next(10)
	if err != nil || len(b) != 1 {
		t.Fatal(err)
	}
	var ba batch
	r.c.handle(b[0].Payload, b[0].At, &ba)
	ba.delta.Filtered, ba.delta.OutOfScope = map[string]int{}, map[string]int{}
	if err := r.c.post(context.Background(), &ba); err != nil {
		t.Fatal(err)
	}
	r.q.Close()
	// restart: a new collector on the same queue directory and the same core
	r2 := newRigIn(t, dir)
	r2.core = r.core
	r2.c.d.Core = r.core
	r2.drain()
	if n := len(r.core.kind("observation")); n != 1 {
		t.Fatalf("%d observations after the replay, want 1 (de-duplicated on event id)", n)
	}
	if n := len(r.core.kind("assessment")); n < 1 {
		t.Fatal("the replay must leave the observation assessed")
	}
}

// The pipeline's counters are persisted with the cursor, survive a restart, are reported in the health record and
// cleared by it.
func TestFilteredCountersArePersistedReportedAndCleared(t *testing.T) {
	dir := t.TempDir()
	r := newRigIn(t, dir)
	hpa := func() map[string]any {
		return auditEv("system:serviceaccount:kube-system:horizontal-pod-autoscaler", "kube-controller-manager/v1", "update", "deployments", "shop", "web", 200,
			map[string]any{"objectRef": map[string]any{"resource": "deployments", "namespace": "shop", "name": "web", "subresource": "scale"}})
	}
	r.push(hpa(), hpa(), hpa(), auditEv(human, "kubectl/v1.36.0", "get", "pods", "shop", "p", 200, nil))
	r.push(auditEv("system:serviceaccount:other:x", "x", "update", "configmaps", "unwatched", "c", 200, nil)) // out of scope
	r.drain()
	r.q.Close()
	r = newRigIn(t, dir) // restart
	if c := r.c.Counters(); c.Filtered["hpa-scale"] != 3 || c.NotWrites != 1 || c.OutOfScope[cluster] != 1 {
		t.Fatalf("after a restart: %+v", c)
	}
	if err := r.c.HealthOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := r.core.kind("observation.health")
	if len(h) != 1 {
		t.Fatalf("%d health records", len(h))
	}
	var detail string
	for _, c := range sub(h[0], "health")["checks"].([]any) {
		if m := c.(map[string]any); m["name"] == CheckFiltered {
			detail = m["detail"].(string)
		}
	}
	var d struct {
		Schema   string
		RuleSet  string `json:"rule_set"`
		Filtered []struct {
			Rule  string
			Count int
		}
	}
	if err := json.Unmarshal([]byte(detail), &d); err != nil || d.Schema != FilteredSchema || len(d.Filtered) != 1 || d.Filtered[0].Rule != "hpa-scale" || d.Filtered[0].Count != 3 || d.RuleSet != "observe-default@2026.11.1" {
		t.Fatalf("detail %s (%v)", detail, err)
	}
	if c := r.c.Counters(); c.Events != 0 || len(c.Filtered) != 0 {
		t.Fatalf("a reported counter must be cleared: %+v", c)
	}
	r.q.Close()
	r = newRigIn(t, dir)
	if c := r.c.Counters(); c.Events != 0 {
		t.Fatalf("the cleared counters came back after a restart: %+v", c)
	}
}

// An apply-and-revert is one exception, and the flush gives it a reverted resolution on the first observation.
func TestRevertGetsAResolution(t *testing.T) {
	r := newRig(t)
	mk := func(rv, v string, off time.Duration) map[string]any {
		return auditEv(human, "kubectl/v1.36.0", "update", "configmaps", "shop", "web-config", 200, map[string]any{
			"stageTimestamp": t0.Add(off).Format(time.RFC3339Nano), "responseObject": configMap("shop", "web-config", rv, map[string]any{"k": v})})
	}
	r.c.cache.Put("ConfigMap", "ADDED", configMap("shop", "web-config", "1", map[string]any{"k": "orig"}), t0.Add(-time.Hour), true)
	r.c.cache.Put("ConfigMap", "MODIFIED", configMap("shop", "web-config", "2", map[string]any{"k": "bad"}), t0, false)
	r.c.cache.Put("ConfigMap", "MODIFIED", configMap("shop", "web-config", "3", map[string]any{"k": "orig"}), t0.Add(time.Minute), false)
	r.push(mk("2", "bad", 0), mk("3", "orig", time.Minute))
	r.drain()
	if err := r.c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	res := r.core.kind("resolution")
	if len(res) != 1 || sub(res[0], "resolution")["state"] != "reverted" || sub(res[0], "about")["seq"] != json.Number("0") {
		t.Fatalf("resolutions %v", res)
	}
}

// The stale-health rule: a collector that stops reporting is blind, not clean, from the core's own statement. The
// record the collector posted is the O-1 health record, and observe.Build (the coverage route and the packet) reads it.
func TestStoppedCollectorIsBlindNotClean(t *testing.T) {
	r := newRig(t, func(c *Config, d *Deps) {
		c.HeartbeatCM, c.Namespace, c.ServiceAccount = "hb", "clearance-system", "clearance-observe-k8s"
	})
	r.c.d.Kube = noKube{}
	// the heartbeat came back through the audit path: a healthy record
	r.c.hb.seen, r.c.hb.level = r.clock.Add(-5*time.Second), "Metadata"
	if err := r.c.HealthOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := r.core.kind("observation.health")
	if len(h) != 1 || sub(h[0], "health")["state"] != "healthy" {
		t.Fatalf("health %v", h)
	}
	in := func(now time.Time) observe.Statement {
		return observe.Build(observe.Input{Scope: cluster, Window: observe.Window{From: t0, To: now}, Health: h}, now)
	}
	if st := in(t0.Add(time.Minute)); st.State != "healthy" || !st.Clean {
		t.Fatalf("one minute after a healthy record: %s clean=%v", st.State, st.Clean)
	}
	// the collector stops: no further record. Past twice its interval the window is blind, and never clean.
	st := in(t0.Add(10 * time.Minute))
	if st.State != "blind" || st.Clean || st.Blind.Seconds == 0 {
		t.Fatalf("ten minutes after the last record: state %s clean=%v blind=%ds; want a blind window", st.State, st.Clean, st.Blind.Seconds)
	}
	if !st.Health.Sources[0].Stale || st.Health.Sources[0].Now != "blind" {
		t.Fatalf("source health %+v", st.Health.Sources[0])
	}
	for _, s := range st.Blind.Segments {
		if s.State == "blind" && s.Reason != "stale" {
			t.Fatalf("segment %+v: the blindness is staleness", s)
		}
	}
}

type noKube struct{ Kube }

func (noKube) Patch(context.Context, string, any) error { return nil }
func (noKube) Get(context.Context, string) (map[string]any, error) {
	return nil, errBoom
}
