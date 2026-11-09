package packet_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
)

var bg = context.Background()

// The lab-shaped window: 30 days, 2026-10-10 to 2026-11-09, made at 2026-11-09 06:00.
const (
	winFrom = "2026-10-10T00:00:00Z"
	winTo   = "2026-11-09T00:00:00Z"
	nowAt   = "2026-11-09T06:00:00Z"
)

var (
	coreW   = evidence.Core("test")
	tfW     = evidence.Writer{Provider: evidence.Provider{Name: "terraform-ci", Version: "1.2.0", Conformance: "clearance-conformance/v1@2026-11-03"}, Verified: evidence.ProviderVerified}
	argoW   = evidence.Writer{Provider: evidence.Provider{Name: "argo-gate", Version: "0.9.0"}, Verified: evidence.ProviderVerified}
	obsW    = evidence.Writer{Provider: evidence.Provider{Name: "audit-observer", Version: "0.3.0"}, Verified: evidence.ProviderVerified}
	obsTier = evidence.Writer{Provider: evidence.Provider{Name: "audit-observer", Version: "0.3.0"}, Verified: func() map[string]bool {
		m := maps.Clone(evidence.ProviderVerified)
		m["tier"] = true
		return m
	}()}
	// a gate writer that also verified the plan comparison, as the core's outcome route does
	coreMatchedW = func() evidence.Writer {
		w := evidence.Core("test")
		w.Verified = maps.Clone(evidence.GatewayVerified)
		w.Verified["matched"] = true
		return w
	}()
)

const (
	chA = "ch-00000000000000a1" // an Argo change, cleared by two people, applied
	chB = "ch-00000000000000b2" // a Terraform change cleared by policy, applied, plan compared by the core
	chC = "ch-00000000000000c3" // an Argo change that failed and was rolled back, approvals before C-14
	chD = "ch-00000000000000d4" // a Terraform change that failed
	chE = "ch-00000000000000e5" // a denied change
)

func hexOf(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

type labber struct {
	t  testing.TB
	st *memory.Store
}

func (l *labber) add(w evidence.Writer, ev store.Event) store.Record {
	l.t.Helper()
	var rec store.Record
	if err := l.st.Atomic(bg, func(tx store.Tx) error {
		var err error
		rec, err = tx.Append(bg, ev, w)
		return err
	}); err != nil {
		l.t.Fatalf("append %v: %v", ev["tool"], err)
	}
	return rec
}

func seqI(r store.Record) int64 {
	n, _ := r["seq"].(json.Number)
	i, _ := n.Int64()
	return i
}

func change(id, app, env, cluster string, tier int, state string) map[string]any {
	return map[string]any{"id": id, "app": app, "env": env, "cluster": cluster, "head": hexOf('a')[:40], "tree": hexOf('b'),
		"tier": json.Number(fmt.Sprint(tier)), "state": state, "objects": json.Number("3")}
}

func manifestSubject(c byte) map[string]any {
	return map[string]any{"kind": "manifest-tree", "name": "gate-api/prod", "digests": map[string]any{"sha256": hexOf(c), "gitCommit": hexOf('a')[:40]}}
}

func planSubject(c byte) map[string]any {
	return map[string]any{"kind": "terraform-plan", "name": "network/prod", "digests": map[string]any{"sha256": hexOf(c), "gitCommit": hexOf('a')[:40], "variableSet": hexOf('e')}}
}

func gate(ts, tool, app, env string, extra map[string]any) store.Event {
	ev := store.Event{"ts": ts, "task_id": nil, "session": nil, "parent": nil, "principal": "policy", "agent": nil, "tool": tool, "tier": nil,
		"decision": "allow", "rule": nil, "target": app + "/" + env, "args_sha256": hexOf('0'), "result": tool, "app": app, "boundary": "deployment"}
	maps.Copy(ev, extra)
	return ev
}

func person(sub string, kind string) map[string]any {
	m := map[string]any{"sub": sub, "iss": "https://idp.example", "person": sub, "role": "approver", "at": "2026-10-12T08:00:00Z"}
	if kind != "" {
		m["kind"] = kind
	}
	return m
}

func observation(ts, scope, api, resource string, extra map[string]any) store.Event {
	ev := store.Event{"ts": ts, "tool": "observation", "boundary": "deployment", "coverage": "observed-not-attributed", "scope": scope,
		"source":   map[string]any{"name": "cloudtrail", "event_id": fmt.Sprintf("%s-%s-%s", scope, api, ts)},
		"resource": map[string]any{"kind": resource, "name": "x"}, "actor": map[string]any{"subject": "arn:aws:iam::111:user/ops"},
		"action": map[string]any{"verb": "write", "api": api, "succeeded": true}, "principal": nil, "agent": nil, "decision": "allow", "args_sha256": hexOf('0'),
		"result": "observed"}
	maps.Copy(ev, extra)
	return ev
}

func health(ts, scope, state string, interval int) store.Event {
	h := map[string]any{"state": state, "interval_seconds": json.Number(fmt.Sprint(interval)),
		"checks": []any{map[string]any{"name": "trail-enabled", "ok": state == "healthy"}}}
	return store.Event{"ts": ts, "tool": "observation.health", "boundary": "deployment", "coverage": "observed-not-attributed", "scope": scope,
		"source": map[string]any{"name": "cloudtrail"}, "health": h, "principal": nil, "agent": nil, "decision": "allow", "args_sha256": hexOf('0'), "result": "health"}
}

func assessment(ts, scope string, about int64, cov string, extra map[string]any) store.Event {
	ev := store.Event{"ts": ts, "tool": "assessment", "boundary": "deployment", "coverage": cov, "scope": scope, "about": map[string]any{"seq": json.Number(fmt.Sprint(about))},
		"attribution": map[string]any{"signal": "grant-lookup"}, "principal": nil, "agent": nil, "decision": "allow", "args_sha256": hexOf('0'), "result": "assessed"}
	maps.Copy(ev, extra)
	return ev
}

func resolution(ts, scope string, about int64, state, cause string) store.Event {
	r := map[string]any{"state": state}
	if cause != "" {
		r["cause"] = cause
	}
	return store.Event{"ts": ts, "tool": "resolution", "boundary": "deployment", "coverage": "observed-not-attributed", "scope": scope, "about": map[string]any{"seq": json.Number(fmt.Sprint(about))},
		"resolution": r, "principal": "user:jfillman", "agent": nil, "decision": "allow", "args_sha256": hexOf('0'), "result": "resolved"}
}

// labChain writes the lab-shaped 30-day chain: failures, a rollback, a deliberate bypass, and every exception class.
func labChain(t testing.TB) (*memory.Store, map[string]int64) {
	st := memory.New()
	t.Cleanup(st.Close)
	l := &labber{t: t, st: st}
	seq := map[string]int64{}
	mark := func(name string, r store.Record) { seq[name] = seqI(r) }

	// Before the window: the feeds' last health records, and a policy.
	l.add(obsW, health("2026-10-09T23:00:00Z", "aws-111", "healthy", 5184000)) // holds past the window
	l.add(obsW, health("2026-10-09T23:00:00Z", "k8s-prod", "healthy", 86400))  // holds two days, then blind
	l.add(coreW, gate("2026-10-09T23:30:00Z", "definition.load", "", "", map[string]any{"app": nil, "boundary": "runtime", "subject": map[string]any{"kind": "definition", "name": "triage-agent", "digests": map[string]any{"sha256": hexOf('d')}}}))

	l.add(coreW, gate("2026-10-11T09:00:00Z", "definition.load", "", "", map[string]any{"app": nil, "boundary": "runtime", "subject": map[string]any{"kind": "definition", "name": "nightly-reviewer", "digests": map[string]any{"sha256": hexOf('e')}}}))

	// Runtime: an agent's calls, a denied one and an outage read.
	for i, ts := range []string{"2026-10-10T08:00:00Z", "2026-10-10T08:01:00Z", "2026-10-10T08:02:00Z"} {
		l.add(coreW, store.Event{"ts": ts, "tool": "repo.pr.open", "boundary": "runtime", "principal": "autopilot-runs/triage", "agent": "triage-agent",
			"session": "s-1", "task_id": "t-1", "decision": "allow", "tier": json.Number("1"), "rule": nil, "target": "jfillman/gate-api", "args_sha256": hexOf(byte('1' + i)), "result": "ok"})
	}
	l.add(coreW, store.Event{"ts": "2026-10-10T08:03:00Z", "tool": "repo.pr.merge", "boundary": "runtime", "principal": "autopilot-runs/triage", "agent": "triage-agent",
		"session": "s-1", "task_id": "t-1", "decision": "deny", "tier": json.Number("2"), "rule": "R006", "target": "jfillman/gate-api", "args_sha256": hexOf('4'), "result": "tool is not permitted"})
	mark("outage-read", l.add(argoW, store.Event{"ts": "2026-10-11T03:00:00Z", "tool": "tool.call", "boundary": "runtime", "coverage": "coverage-unavailable",
		"principal": "autopilot-runs/triage", "agent": "triage-agent", "target": "repo.pr.list", "args_sha256": hexOf('5'), "decision": "allow", "result": "read while the core was unreachable"}))

	// Change A: an Argo change two people cleared and an Argo outcome.
	l.add(coreW, gate("2026-10-12T07:00:00Z", "deploy.request", "gate-api", "prod", map[string]any{"change": change(chA, "gate-api", "prod", "hangar-prod", 2, "holding"), "subject": manifestSubject('b'), "agent": "triage-agent", "operational_class": []any{"availability"},
		"policy": map[string]any{"ref": "clearance.yaml@aaa111", "engine": "none", "version": "gate-1+aaa111"}}))
	l.add(coreW, gate("2026-10-12T08:05:00Z", "deploy.clear", "gate-api", "prod", map[string]any{"change": change(chA, "gate-api", "prod", "hangar-prod", 2, "cleared"), "subject": manifestSubject('b'), "agent": "triage-agent",
		"cleared_by": "approvals", "approvals": []any{person("alice", "person"), person("bob", "person")}, "operational_class": []any{"availability"}}))
	mark("outcomeA", l.add(argoW, gate("2026-10-12T08:20:00Z", "deploy.outcome", "gate-api", "prod", map[string]any{"change": map[string]any{"id": chA, "tree": hexOf('b')},
		"principal": "hangar-prod/argocd/agent", "subject": manifestSubject('b'),
		"outcome": map[string]any{"applied": true, "observed_revision": "r1", "digests": map[string]any{"sha256": hexOf('b')}, "health": "Healthy", "rollback": map[string]any{"available": true, "used": false}}})))
	attBundle, attDigest := labAttestation(t, chA) // a real keyless bundle (C-4 verifies it offline)
	mark("attestA", l.add(coreW, gate("2026-10-12T08:21:00Z", "deploy.attestation", "gate-api", "prod", map[string]any{"change": change(chA, "gate-api", "prod", "hangar-prod", 2, "cleared"),
		"attestation": map[string]any{"digest": attDigest, "backend": "keyless", "outcome_seq": json.Number("0")}})))
	if err := st.Atomic(bg, func(tx store.Tx) error {
		return tx.PutAttestation(bg, store.Attestation{ChangeID: chA, Digest: attDigest, Backend: "keyless", KeyID: "k1", OutcomeSeq: 0,
			RecordSeq: seq["attestA"], Bundle: attBundle})
	}); err != nil {
		t.Fatal(err)
	}

	// Change B: a Terraform plan cleared by policy, the core compared the plan.
	l.add(coreW, gate("2026-10-15T07:00:00Z", "deploy.request", "network", "prod", map[string]any{"change": change(chB, "network", "prod", "", 0, "holding"), "subject": planSubject('c'),
		"destination": map[string]any{"workspace": map[string]any{"backend": "s3", "key": "tf/network", "name": "prod"}}}))
	l.add(coreW, gate("2026-10-15T07:01:00Z", "deploy.clear", "network", "prod", map[string]any{"change": change(chB, "network", "prod", "", 0, "cleared"), "subject": planSubject('c'), "cleared_by": "policy", "approvals": []any{},
		"destination": map[string]any{"workspace": map[string]any{"backend": "s3", "key": "tf/network", "name": "prod"}}}))
	mark("outcomeB", l.add(coreMatchedW, gate("2026-10-15T07:30:00Z", "deploy.outcome", "network", "prod", map[string]any{"change": map[string]any{"id": chB}, "subject": planSubject('c'), "matched": true,
		"destination": map[string]any{"workspace": map[string]any{"backend": "s3", "key": "tf/network", "name": "prod"}},
		"outcome":     map[string]any{"applied": true, "digests": map[string]any{"sha256": hexOf('c')}}})))

	// Change C: failed, then rolled back; its approval was recorded before the person check (no kind).
	l.add(coreW, gate("2026-10-20T07:00:00Z", "deploy.request", "gate-api", "prod", map[string]any{"policy": map[string]any{"ref": "clearance.yaml@bbb222", "engine": "none", "version": "gate-1+bbb222"}, "change": change(chC, "gate-api", "prod", "hangar-prod", 3, "holding"), "subject": manifestSubject('f')}))
	l.add(coreW, gate("2026-10-20T07:30:00Z", "deploy.clear", "gate-api", "prod", map[string]any{"change": change(chC, "gate-api", "prod", "hangar-prod", 3, "cleared"), "subject": manifestSubject('f'),
		"cleared_by": "approvals", "approvals": []any{person("carol", "")}}))
	mark("failC", l.add(argoW, gate("2026-10-20T07:45:00Z", "deploy.outcome", "gate-api", "prod", map[string]any{"change": map[string]any{"id": chC}, "subject": manifestSubject('f'),
		"outcome": map[string]any{"applied": true, "health": "Degraded", "digests": map[string]any{"sha256": hexOf('f')}}})))
	mark("rollbackC", l.add(argoW, gate("2026-10-20T08:10:00Z", "deploy.outcome", "gate-api", "prod", map[string]any{"change": map[string]any{"id": chC}, "subject": manifestSubject('b'),
		"outcome": map[string]any{"applied": true, "health": "Healthy", "digests": map[string]any{"sha256": hexOf('b')}, "rollback": map[string]any{"available": true, "used": true, "to": "r1"}}})))
	mark("revokeC", l.add(coreW, gate("2026-10-20T07:50:00Z", "deploy.revoke", "gate-api", "prod", map[string]any{"change": change(chC, "gate-api", "prod", "hangar-prod", 3, "cleared"),
		"result": "token revoked: the apply failed", "token": "n-1"})))

	// Change D: a Terraform apply that failed, reported by the registered terraform-ci provider.
	l.add(coreW, gate("2026-10-25T07:00:00Z", "deploy.request", "network", "staging", map[string]any{"change": change(chD, "network", "staging", "", 1, "holding"), "subject": planSubject('d')}))
	l.add(coreW, gate("2026-10-25T07:01:00Z", "deploy.clear", "network", "staging", map[string]any{"change": change(chD, "network", "staging", "", 1, "cleared"), "subject": planSubject('d'), "cleared_by": "policy", "approvals": []any{}}))
	mark("failD", l.add(tfW, gate("2026-10-25T07:20:00Z", "deploy.outcome", "network", "staging", map[string]any{"change": map[string]any{"id": chD}, "subject": planSubject('d'),
		"outcome": map[string]any{"applied": false, "error": "apply failed: quota exceeded", "digests": map[string]any{"sha256": hexOf('d')}}})))

	// Change E: denied.
	l.add(coreW, gate("2026-10-26T07:00:00Z", "deploy.request", "gate-api", "prod", map[string]any{"change": change(chE, "gate-api", "prod", "hangar-prod", 3, "holding"), "decision": "deny", "rule": "DG-UNREGISTERED"}))

	// The deliberate bypass: an admin opens break-glass, something lands out of band inside it, the window closes.
	mark("bgOpen", l.add(coreW, gate("2026-11-01T10:00:00Z", "breakglass.open", "gate-api", "prod", map[string]any{"principal": "user:ops", "reason": "the prod rollout is stuck",
		"breakglass":  map[string]any{"id": "bg-1", "cluster": "hangar-prod", "env": "prod", "app": "gate-api", "ttl_seconds": json.Number("3600"), "expires_at": "2026-11-01T11:00:00Z"},
		"destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"}, "target": "hangar-prod/prod"})))
	mark("oob", l.add(argoW, gate("2026-11-01T10:20:00Z", "deploy.exception", "gate-api", "prod", map[string]any{"coverage": "break-glass", "principal": "hangar-prod/argocd/agent",
		"destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"}, "breakglass": map[string]any{"id": "bg-1"},
		"exception": map[string]any{"kind": "out-of-band", "objects": []any{map[string]any{"kind": "Deployment", "namespace": "gate-api", "name": "gate-api"}}, "detail": "image changed by kubectl"}})))
	mark("bgClose", l.add(coreW, gate("2026-11-01T10:59:00Z", "breakglass.close", "gate-api", "prod", map[string]any{"principal": "user:ops", "target": "hangar-prod/prod",
		"breakglass": map[string]any{"id": "bg-1", "closed_by": "admin"}, "window": map[string]any{"from": "2026-11-01T10:00:00Z", "to": "2026-11-01T10:59:00Z"},
		"reported": json.Number("1"), "changes": []any{}, "destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"}})))
	// Out of band with no window: untraced apply and a digest mismatch.
	mark("untraced", l.add(tfW, gate("2026-11-03T02:00:00Z", "deploy.exception", "network", "prod", map[string]any{"coverage": "out-of-band-detected",
		"destination": map[string]any{"workspace": map[string]any{"backend": "s3", "key": "tf/network", "name": "prod"}},
		"exception":   map[string]any{"kind": "untraced-apply", "actor": "arn:aws:iam::111:user/ops", "state": map[string]any{"backend": "s3", "key": "tf/network"}}})))
	mark("refused", l.add(argoW, gate("2026-11-04T02:00:00Z", "deploy.exception", "gate-api", "prod", map[string]any{"coverage": "attempted-refused",
		"destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"},
		"exception":   map[string]any{"kind": "attempted-refused", "actor": "system:serviceaccount:ci:deployer", "detail": "kubectl apply refused by admission"}})))
	mark("monitoring", l.add(argoW, gate("2026-11-05T02:00:00Z", "deploy.exception", "gate-api", "prod", map[string]any{"coverage": "out-of-band-detected",
		"destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"},
		"exception":   map[string]any{"kind": "monitoring-protection", "actor": "arn:aws:iam::111:user/ops", "detail": "audit policy removed"}})))
	mark("degraded", l.add(argoW, gate("2026-11-06T02:00:00Z", "deploy.degraded", "gate-api", "dev", map[string]any{"coverage": "coverage-unavailable",
		"destination": map[string]any{"cluster": "hangar-dev", "environment": "dev"},
		"outage":      map[string]any{"from": "2026-11-06T01:00:00Z", "to": "2026-11-06T01:30:00Z"}, "outage_policy": map[string]any{"action": "allow", "source": "baseline", "conforms": true}})))

	// Observations: a cleared one, an out-of-band one that was reverted, a refused one, a monitoring one, and one whose correlation did not hold.
	o1 := l.add(obsW, observation("2026-10-14T09:00:00Z", "aws-111", "PutBucketPolicy", "Bucket", nil))
	l.add(obsW, assessment("2026-10-14T09:00:05Z", "aws-111", seqI(o1), "authorized-and-verified", nil))
	o2 := l.add(obsW, observation("2026-10-30T09:00:00Z", "aws-111", "AuthorizeSecurityGroupIngress", "SecurityGroup", map[string]any{"state_change": map[string]any{"before": "closed", "after": "open"}}))
	mark("obs2", o2)
	l.add(obsW, assessment("2026-10-30T09:00:05Z", "aws-111", seqI(o2), "out-of-band-detected", nil))
	l.add(obsW, resolution("2026-10-30T12:00:00Z", "aws-111", seqI(o2), "reverted", "human-initiated"))
	o3 := l.add(obsW, observation("2026-11-02T09:00:00Z", "aws-111", "DeleteRole", "Role", map[string]any{"action": map[string]any{"verb": "delete", "api": "DeleteRole", "succeeded": false, "refused_reason": "AccessDenied"}}))
	l.add(obsW, assessment("2026-11-02T09:00:05Z", "aws-111", seqI(o3), "attempted-refused", nil))
	o4 := l.add(obsTier, observation("2026-11-05T01:55:00Z", "aws-111", "StopLogging", "Trail", map[string]any{"tier": json.Number("3")}))
	mark("obs4", o4)
	o5 := l.add(obsW, observation("2026-11-07T09:00:00Z", "aws-111", "UpdateFunctionCode", "Function", map[string]any{"correlation": map[string]any{"grant": "g-1", "run_id": "run-9"}}))
	l.add(obsW, assessment("2026-11-07T09:00:05Z", "aws-111", seqI(o5), "observed-not-attributed", nil))
	// A scope whose feed goes quiet: one observation while healthy, then nothing.
	o6 := l.add(obsW, observation("2026-10-10T08:00:00Z", "k8s-prod", "patch", "Deployment", nil))
	l.add(obsW, assessment("2026-10-10T08:00:05Z", "k8s-prod", seqI(o6), "authorized-and-verified", nil))
	// A ratified change and a declared break-glass: acceptances.
	o7 := l.add(obsW, observation("2026-10-11T08:00:00Z", "k8s-prod", "delete", "Pod", nil))
	l.add(obsW, assessment("2026-10-11T08:00:05Z", "k8s-prod", seqI(o7), "out-of-band-detected", nil))
	l.add(obsW, resolution("2026-10-11T09:00:00Z", "k8s-prod", seqI(o7), "ratified", ""))
	// A federated decision that could not be correlated.
	l.add(evidence.Writer{Provider: evidence.Provider{Name: "traefik-hub", Version: "0.1.0"}, Verified: evidence.ProviderVerified},
		store.Event{"ts": "2026-11-08T05:00:00Z", "tool": "federated.decision", "boundary": "runtime", "coverage": "observed-not-attributed", "principal": "hub",
			"source": map[string]any{"name": "traefik-hub", "event_id": "e-1", "correlated": false}, "target": "mcp/tool", "decision": "allow", "args_sha256": hexOf('7'), "result": "x"})
	return st, seq
}

func itoa(n int) string { return fmt.Sprint(n) }

func fmtSscan(s string, a ...any) (int, error) { return fmt.Sscan(s, a...) }

func bgTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(bg, 10*time.Second)
}
