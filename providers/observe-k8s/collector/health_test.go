package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/observe/pipeline"
)

func hbRig(t *testing.T, opts ...rigOpt) *rig {
	opts = append([]rigOpt{func(c *Config, d *Deps) {
		c.HeartbeatCM, c.Namespace, c.ServiceAccount = "hb", "clearance-system", "clearance-observe-k8s"
		c.Watches = nil
		d.Kube = noKube{}
	}}, opts...)
	return newRig(t, opts...)
}

func (r *rig) health() (string, map[string]bool) {
	r.t.Helper()
	if err := r.c.HealthOnce(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	hs := r.core.kind("observation.health")
	h := sub(hs[len(hs)-1], "health")
	checks := map[string]bool{}
	for _, c := range h["checks"].([]any) {
		m := c.(map[string]any)
		checks[m["name"].(string)] = m["ok"].(bool)
	}
	return h["state"].(string), checks
}

func heartbeatEvent(at time.Time, level string) map[string]any {
	return auditEv("system:serviceaccount:clearance-system:clearance-observe-k8s", "observe-k8s/1", "patch", "configmaps", "clearance-system", "hb", 200,
		map[string]any{"level": level, "stageTimestamp": at.Format(time.RFC3339Nano)})
}

// The health check the pod can make: the collector writes a heartbeat object and the write must come back through the
// API server's audit webhook, under the live policy. No heartbeat, and the feed is blind.
func TestHeartbeatThroughTheLivePolicyIsWhatMakesTheFeedHealthy(t *testing.T) {
	r := hbRig(t)
	if st, ck := r.health(); st != "blind" || ck[CheckWebhook] || ck[CheckPolicy] {
		t.Fatalf("no heartbeat yet: %s %v", st, ck)
	}
	r.push(heartbeatEvent(t0, "Metadata"))
	r.drain()
	if c := r.c.Counters(); c.Taps != 1 {
		t.Fatalf("the heartbeat is the collector's own and is counted as such: %+v", c)
	}
	if st, ck := r.health(); st != "healthy" || !ck[CheckWebhook] || !ck[CheckPolicy] {
		t.Fatalf("heartbeat came back: %s %v", st, ck)
	}
	if len(r.core.kind("observation")) != 0 {
		t.Fatal("the collector's own heartbeat must not become an observation")
	}
	r.advance(5 * time.Minute) // the webhook (or the policy) stops delivering
	if st, ck := r.health(); st != "blind" || ck[CheckWebhook] {
		t.Fatalf("heartbeat gone: %s %v", st, ck)
	}
}

// Only the collector's own identity writing its own object is the heartbeat: someone else patching the same
// ConfigMap, or the collector writing another, is an ordinary event.
func TestOnlyTheCollectorsOwnWriteIsAHeartbeat(t *testing.T) {
	r := hbRig(t)
	forged := heartbeatEvent(t0, "Metadata")
	forged["user"] = map[string]any{"username": human}
	other := heartbeatEvent(t0, "Metadata")
	other["objectRef"] = map[string]any{"resource": "configmaps", "namespace": "clearance-system", "name": "something-else"}
	r.push(forged, other)
	r.drain()
	if st, _ := r.health(); st != "blind" {
		t.Fatalf("a forged heartbeat made the feed %s", st)
	}
}

// After an operation on monitoring the feed is blind until a heartbeat newer than the operation has come back, then a
// healthy record clears the flip.
func TestMonitoringOperationNeedsAFreshHeartbeatToClear(t *testing.T) {
	r := hbRig(t)
	r.push(heartbeatEvent(t0, "Metadata"))
	r.drain()
	r.advance(10 * time.Second)
	r.push(auditEv(human, "kubectl/v1.36.0", "update", "validatingwebhookconfigurations", "", "clearance-gate", 200,
		map[string]any{"stageTimestamp": r.clock.Format(time.RFC3339Nano)}))
	r.drain()
	if h := r.pipe.Health(cluster); h != "blind" {
		t.Fatalf("pipeline health %s after a successful operation on monitoring", h)
	}
	r.advance(5 * time.Second)
	if st, ck := r.health(); st != "blind" || ck[CheckWebhook] {
		t.Fatalf("the heartbeat before the operation must not vouch for the feed after it: %s %v", st, ck)
	}
	r.advance(5 * time.Second)
	r.push(heartbeatEvent(*r.clock, "Metadata"))
	r.drain()
	if st, _ := r.health(); st != "healthy" {
		t.Fatalf("a fresh heartbeat: %s", st)
	}
	if h := r.pipe.Health(cluster); h != "healthy" {
		t.Fatalf("pipeline health %s: the healthy record clears the flip", h)
	}
	_ = pipeline.Kubernetes
}

// A Secret recorded above Metadata by the live policy (the receiver cut the body) degrades the feed and names the check.
func TestSecretRecordedAboveMetadataDegradesTheFeed(t *testing.T) {
	r := hbRig(t)
	r.push(heartbeatEvent(t0, "Metadata"))
	ev := auditEv(human, "kubectl/v1.36.0", "update", "secrets", "shop", "db", 200, map[string]any{"level": "Metadata",
		"annotations": map[string]any{"observe-k8s.clearance.hangar.io/body-stripped": "true"}})
	r.push(ev)
	r.drain()
	st, ck := r.health()
	if st != "degraded" || ck[CheckSecrets] {
		t.Fatalf("%s %v", st, ck)
	}
	r.advance(r.c.cfg.SecretHold + time.Minute)
	r.push(heartbeatEvent(*r.clock, "Metadata"))
	r.drain()
	if st, _ := r.health(); st != "healthy" {
		t.Fatalf("after the hold: %s", st)
	}
}

// A canary Secret write that comes back with a body shows the live Secret rule is wrong, without any real Secret.
func TestCanarySecretProvesTheSecretRule(t *testing.T) {
	r := hbRig(t, func(c *Config, d *Deps) { c.CanarySecret = "canary" })
	canary := func(at time.Time, extra map[string]any) map[string]any {
		e := auditEv("system:serviceaccount:clearance-system:clearance-observe-k8s", "observe-k8s/1", "patch", "secrets", "clearance-system", "canary", 200,
			map[string]any{"level": "Metadata", "stageTimestamp": at.Format(time.RFC3339Nano)})
		for k, v := range extra {
			e[k] = v
		}
		return e
	}
	r.push(heartbeatEvent(t0, "Metadata"))
	if st, ck := r.health(); ck[CheckSecrets] {
		t.Fatalf("no canary yet: %s %v", st, ck)
	}
	r.push(canary(t0, nil))
	r.drain()
	if st, ck := r.health(); st != "healthy" || !ck[CheckSecrets] {
		t.Fatalf("canary at Metadata: %s %v", st, ck)
	}
	r.advance(time.Minute)
	r.push(heartbeatEvent(*r.clock, "Metadata"), canary(*r.clock, map[string]any{"annotations": map[string]any{"observe-k8s.clearance.hangar.io/body-stripped": "true"}}))
	r.drain()
	if st, ck := r.health(); st != "degraded" || ck[CheckSecrets] {
		t.Fatalf("canary with a body: %s %v", st, ck)
	}
}

// When the pod cannot patch a heartbeat object (no Kube), the check falls back to batch arrival and says so.
func TestWithoutAHeartbeatTheCheckFallsBackToBatchArrival(t *testing.T) {
	last := time.Time{}
	r := newRig(t, func(c *Config, d *Deps) { c.Watches = nil; d.Delivery = func() time.Time { return last } })
	if st, ck := r.health(); st != "blind" || ck[CheckWebhook] {
		t.Fatalf("no batch ever: %s %v", st, ck)
	}
	last = *r.clock
	st, ck := r.health()
	if st != "healthy" || !ck[CheckWebhook] || ck[CheckPolicy] {
		t.Fatalf("%s %v", st, ck)
	}
	if _, has := ck[CheckPolicy]; has {
		t.Fatal("with no heartbeat the live policy is not shown, and the record must not claim it")
	}
	hs := r.core.kind("observation.health")
	for _, c := range sub(hs[len(hs)-1], "health")["checks"].([]any) {
		if m := c.(map[string]any); m["name"] == CheckWebhook && !strings.Contains(m["detail"].(string), "no heartbeat is configured") {
			t.Fatalf("the fallback must name itself: %v", m)
		}
	}
}

func TestPolicyMirrorIsHeldToTheSecretRule(t *testing.T) {
	policy := func(cm string) rigOpt {
		return func(c *Config, d *Deps) {
			c.PolicyCM = "kube-system/audit-policy"
			d.Kube = cmKube{data: cm}
			d.Policy = func(raw []byte) ([]string, error) {
				if strings.Contains(string(raw), "BAD") {
					return []string{"rule 0 records the body of secrets"}, nil
				}
				return nil, nil
			}
		}
	}
	r := hbRig(t, policy("audit-policy.yaml: ok"))
	r.push(heartbeatEvent(t0, "Metadata"))
	r.drain()
	if st, ck := r.health(); st != "healthy" || !ck[CheckMirror] {
		t.Fatalf("%s %v", st, ck)
	}
	r2 := hbRig(t, policy("BAD"))
	r2.push(heartbeatEvent(t0, "Metadata"))
	r2.drain()
	if st, ck := r2.health(); st != "degraded" || ck[CheckMirror] {
		t.Fatalf("%s %v", st, ck)
	}
}

type cmKube struct {
	noKube
	data string
}

func (k cmKube) Get(context.Context, string) (map[string]any, error) {
	d := "ok"
	if strings.Contains(k.data, "BAD") {
		d = "BAD"
	}
	return map[string]any{"data": map[string]any{"audit-policy.yaml": d}}, nil
}

// One event the pipeline cannot read does not hold the queue.
func TestPoisonEventDoesNotWedgeTheQueue(t *testing.T) {
	r := newRig(t)
	if err := r.q.Append([]byte("not json"), []byte(`{"auditID":"x","verb":"create","stage":"ResponseComplete"}`)); err != nil {
		t.Fatal(err)
	}
	r.push(auditEv(human, "kubectl/v1.36.0", "update", "configmaps", "shop", "x", 200, map[string]any{"responseObject": configMap("shop", "x", "5", nil)}))
	r.drain()
	if len(r.core.kind("observation")) != 1 {
		t.Fatal("the good event behind the bad ones was not posted")
	}
	if c := r.c.Counters(); c.Malformed != 2 {
		t.Fatalf("malformed %d", c.Malformed)
	}
}
