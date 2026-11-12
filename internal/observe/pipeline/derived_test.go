package pipeline

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jfillman/clearance/internal/vocab"
)

const (
	rolloutsSA = "system:serviceaccount:argo-rollouts:argo-rollouts"
	rsCtlSA    = "system:serviceaccount:kube-system:replicaset-controller"
	gcSA       = "system:serviceaccount:kube-system:generic-garbage-collector"
	stampGrant = "clearance.example.com/grant"
)

// derivedFixture is a granted Rollout (clr_roll) in namespace shop, listed by the grant, as the collector's lookups say.
func derivedFixture(t *testing.T) (*RuleSet, StaticLookups) {
	t.Helper()
	rs := mustRules(t)
	lk, err := LoadLookups([]byte(`{"grants":[{"id":"clr_roll","objects":[`+rolloutJSON(map[string]any{})+`]}]}`), rs)
	if err != nil {
		t.Fatal(err)
	}
	lk.Listed = map[string]string{"prod-1/shop/Rollout/web": "clr_roll"}
	return rs, lk
}

// rolloutJSON is the Rollout the grant renders, with extra metadata annotations and a replica count merged in.
func rolloutJSON(extra map[string]any) string {
	return string(mustJSON(rollout(extra, 2)))
}

func rollout(extraAnn map[string]any, replicas int) map[string]any {
	ann := map[string]any{"hangar.io/release-id": "r1"}
	for k, v := range extraAnn {
		ann[k] = v
	}
	return map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Rollout",
		"metadata": map[string]any{"name": "web", "namespace": "shop", "annotations": ann, "labels": map[string]any{"app": "web"}},
		"spec":     map[string]any{"replicas": replicas, "template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "web", "image": "web:1"}}}}},
		"status":   map[string]any{"readyReplicas": 1}}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

type kev struct {
	id, user, verb, resource, name, sub string
	code                                int
	obj                                 map[string]any
	ua                                  string
}

func (k kev) raw() RawEvent {
	if k.code == 0 {
		k.code = 200
	}
	m := map[string]any{"auditID": k.id, "stage": "ResponseComplete", "verb": k.verb, "stageTimestamp": "2026-11-10T21:12:23Z",
		"user":           map[string]any{"username": k.user},
		"objectRef":      map[string]any{"resource": k.resource, "namespace": "shop", "name": k.name, "subresource": k.sub, "apiGroup": trackedGroup(k.obj)},
		"responseStatus": map[string]any{"code": k.code}, "userAgent": k.ua}
	if k.obj != nil {
		m["level"], m["responseObject"] = "RequestResponse", k.obj
	} else {
		m["level"] = "Metadata"
	}
	return RawEvent{Provider: Kubernetes, Scope: "prod-1", Raw: mustJSON(m)}
}

func owned(objKind, name, ownerKind, owner, stamp string) map[string]any {
	md := map[string]any{"name": name, "namespace": "shop",
		"ownerReferences": []any{map[string]any{"kind": ownerKind, "name": owner, "controller": true}}}
	if stamp != "" {
		md["annotations"] = map[string]any{stampGrant: stamp}
	}
	return map[string]any{"kind": objKind, "metadata": md}
}

// A controller's write to an object a granted object owns is that grant taking effect: attributed to the grant by the
// owner chain (Pod -> ReplicaSet -> Rollout), whether or not the derived object carries a stamp, and whether or not the
// event carries the object. A person, a client, a refusal or a chain that does not reach a listed object is not.
func TestDerivedObjectsAreAttributedToTheirOwnersGrant(t *testing.T) {
	rs, lk := derivedFixture(t)
	p := New(rs, lk, vocab.Default())
	step := func(name string, e kev, signal, outcome, grant string) {
		t.Helper()
		a, disp, _, err := p.Process(e.raw())
		if err != nil || disp != Assessed {
			t.Fatalf("%s: %v %v", name, disp, err)
		}
		if a.Signal != signal || a.Outcome != outcome || a.Grant != grant {
			t.Fatalf("%s: got %s/%s grant %q, want %s/%s grant %q (%s)", name, a.Signal, a.Outcome, a.Grant, signal, outcome, grant, a.Detail)
		}
	}
	// The ReplicaSet argo-rollouts creates: owned by the listed Rollout, stamped with a grant that is NOT the one the
	// ReplicaSet's own hash is in (a ReplicaSet is in no grant). Before: grant-annotation+hash-differs.
	rsObj := owned("ReplicaSet", "web-rs", "Rollout", "web", "clr_roll")
	step("rs created by the rollouts controller", kev{id: "a1", user: rolloutsSA, verb: "create", resource: "replicasets", name: "web-rs", obj: rsObj},
		SignalOwnerGrant, OutcomeCleared, "clr_roll")
	// the ReplicaSet's status (replicaset-controller), with no body at all
	step("rs status at Metadata", kev{id: "a2", user: rsCtlSA, verb: "update", resource: "replicasets", name: "web-rs", sub: "status"},
		SignalOwnerGrant, OutcomeCleared, "clr_roll")
	// a Pod of the ReplicaSet: the chain is two hops, the second learned from the ReplicaSet's own event
	podObj := owned("Pod", "web-rs-x1", "ReplicaSet", "web-rs", "clr_roll")
	step("pod created by the replicaset controller", kev{id: "a3", user: rsCtlSA, verb: "create", resource: "pods", name: "web-rs-x1", obj: podObj},
		SignalOwnerGrant, OutcomeCleared, "clr_roll")
	// a delete has no body: the owners are what the pipeline saw of the Pod
	step("pod deleted with no body", kev{id: "a4", user: gcSA, verb: "delete", resource: "pods", name: "web-rs-x1"},
		SignalOwnerGrant, OutcomeCleared, "clr_roll")
	// a delete whose request body is DeleteOptions is still a Pod
	step("pod deleted, DeleteOptions body", kev{id: "a5", user: rolloutsSA, verb: "delete", resource: "pods", name: "web-rs-x1",
		obj: map[string]any{"kind": "DeleteOptions"}}, SignalOwnerGrant, OutcomeCleared, "clr_roll")

	// still out-of-band: the same objects, written by anyone who is not a controller acting as itself
	step("person edits the rs", kev{id: "b1", user: "dana@example.com", verb: "patch", resource: "replicasets", name: "web-rs", obj: rsObj},
		"grant-annotation+hash-differs", OutcomeOutOfBand, "clr_roll")
	step("kubectl with a service account's token", kev{id: "b2", user: rolloutsSA, verb: "patch", resource: "replicasets", name: "web-rs", obj: rsObj, ua: "kubectl/v1.36"},
		"grant-annotation+hash-differs", OutcomeOutOfBand, "clr_roll")
	step("person deletes the pod", kev{id: "b3", user: "dana@example.com", verb: "delete", resource: "pods", name: "web-rs-x1"},
		"human.no-grant", OutcomeOutOfBand, "")
	// a refused write is a refusal, whoever it is
	step("refused", kev{id: "b4", user: rsCtlSA, verb: "update", resource: "replicasets", name: "web-rs", sub: "status", code: 403},
		"response.refused", OutcomeRefused, "")
	// a chain that does not reach a listed object: unseen ReplicaSet, an owner that no grant lists. The replicaset
	// controller creating the Pod of a ReplicaSet is not a change to desired state (controllerChild): out of scope.
	unseen := owned("Pod", "other-rs-x1", "ReplicaSet", "other-rs", "")
	if _, disp, _, err := p.Process(kev{id: "b5", user: rsCtlSA, verb: "create", resource: "pods", name: "other-rs-x1", obj: unseen}.raw()); err != nil || disp != OutOfScope {
		t.Fatalf("pod of a replicaset never seen: %v %v, want out-of-scope", disp, err)
	}
	// the same Pod written by a service account that is not the controller stays visible
	step("pod of a replicaset created by another service account", kev{id: "b5b", user: "system:serviceaccount:shop:builder", verb: "create", resource: "pods", name: "other-rs-x2",
		obj: owned("Pod", "other-rs-x2", "ReplicaSet", "other-rs", "")}, "service-account.unknown", OutcomeOutOfBand, "")
	lone := owned("ReplicaSet", "lone-rs", "Rollout", "lone", "")
	step("rs of a rollout no grant lists", kev{id: "b6", user: rolloutsSA, verb: "create", resource: "replicasets", name: "lone-rs", obj: lone},
		"service-account.unknown", OutcomeOutOfBand, "")
}

// The stamp comparison covers the rendered fields only: a controller's bookkeeping on the granted object (Argo Rollouts'
// revision, a notification controller's sent-log) and the status leave the hash where the grant put it, and a change to a
// rendered field by anyone, a controller included, does not.
func TestControllerBookkeepingDoesNotChangeTheRenderedHash(t *testing.T) {
	rs, lk := derivedFixture(t)
	stamp := func(o map[string]any) map[string]any {
		o["metadata"].(map[string]any)["annotations"].(map[string]any)[stampGrant] = "clr_roll"
		return o
	}
	cases := []struct {
		name    string
		user    string
		obj     map[string]any
		signal  string
		outcome string
	}{
		{"rollouts revision and sent-log", rolloutsSA, stamp(rollout(map[string]any{"rollout.argoproj.io/revision": "13", "notified.notifications.argoproj.io": `{"x":1}`}, 2)),
			"grant-annotation+rendered-hash", OutcomeCleared},
		{"notification pruner", "system:serviceaccount:argo-rollouts:notification-prune", stamp(rollout(map[string]any{"rollouts.argoproj.io/anything": "y"}, 2)),
			"grant-annotation+rendered-hash", OutcomeCleared},
		{"changed replicas by the controller", rolloutsSA, stamp(rollout(map[string]any{"rollout.argoproj.io/revision": "13"}, 9)),
			"grant-annotation+hash-differs", OutcomeOutOfBand},
		{"changed replicas by a person", "dana@example.com", stamp(rollout(nil, 9)), "grant-annotation+hash-differs", OutcomeOutOfBand},
		{"an annotation nobody rendered, by a person", "dana@example.com", stamp(rollout(map[string]any{"example.com/extra": "z"}, 2)), "grant-annotation+hash-differs", OutcomeOutOfBand},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := kev{id: fmt.Sprintf("h%d", i), user: c.user, verb: "patch", resource: "rollouts", name: "web", obj: c.obj}
			a, disp, _, err := New(rs, lk, vocab.Default()).Process(e.raw())
			if err != nil || disp != Assessed {
				t.Fatal(disp, err)
			}
			if a.Signal != c.signal || a.Outcome != c.outcome {
				t.Fatalf("got %s/%s (%s), want %s/%s", a.Signal, a.Outcome, a.Detail, c.signal, c.outcome)
			}
		})
	}
}

// The status of an object a valid grant lists is not a rendered field, and a controller writing it is not a change; the
// same write by a person, or a body write with no object to hash, is. (A controller's status write to an object no grant
// relates to is not assessed at all: TestStatusAndTokenWritesAreNotChanges.)
func TestStatusOfAListedObjectIsAttributedToItsGrant(t *testing.T) {
	rs, lk := derivedFixture(t)
	for _, c := range []struct {
		name    string
		e       kev
		signal  string
		outcome string
	}{
		{"controller status", kev{id: "s1", user: rolloutsSA, verb: "patch", resource: "rollouts", name: "web", sub: "status"}, SignalListedGrant, OutcomeCleared},
		{"person status", kev{id: "s2", user: "dana@example.com", verb: "patch", resource: "rollouts", name: "web", sub: "status"}, "human.no-grant", OutcomeOutOfBand},
		{"controller body, no object", kev{id: "s3", user: rolloutsSA, verb: "patch", resource: "rollouts", name: "web"}, "service-account.unknown", OutcomeOutOfBand},
		{"person status of an unlisted object", kev{id: "s4", user: "dana@example.com", verb: "patch", resource: "rollouts", name: "other", sub: "status"}, "human.no-grant", OutcomeOutOfBand},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, disp, _, err := New(rs, lk, vocab.Default()).Process(c.e.raw())
			if err != nil || disp != Assessed {
				t.Fatal(disp, err)
			}
			if a.Signal != c.signal || a.Outcome != c.outcome {
				t.Fatalf("got %s/%s, want %s/%s", a.Signal, a.Outcome, c.signal, c.outcome)
			}
			if c.signal == SignalListedGrant && a.Grant != "clr_roll" {
				t.Fatalf("grant %q", a.Grant)
			}
		})
	}
}

// A write that names a grant the lookups do not know is held, not decided, when the pipeline is asked to hold: nothing
// is counted or correlated until it is decided. Decided Final after the grant became known it is attributed normally;
// decided with the grant still unknown it is the unknown grant it looked like. A refusal and an operation on monitoring
// are never held.
func TestUnknownGrantIsHeldThenDecided(t *testing.T) {
	rs, lk := derivedFixture(t)
	p := New(rs, lk, vocab.Default())
	p.HoldUnknownGrants(true)
	obj := rollout(map[string]any{stampGrant: "clr_later"}, 2)
	e := kev{id: "u1", user: "system:serviceaccount:argocd:argocd-application-controller", verb: "patch", resource: "rollouts", name: "web", obj: obj}
	a, disp, detail, err := p.Process(e.raw())
	if err != nil || disp != Held || a != nil || detail != "clr_later" {
		t.Fatalf("%v %v %q %v", disp, a, detail, err)
	}
	if st := p.Stats(); st.Events != 0 || st.Assessed != 0 {
		t.Fatalf("a held event is not counted: %+v", st)
	}
	if txs, _ := p.Flush(); len(txs) != 0 {
		t.Fatalf("a held event is not correlated: %+v", txs)
	}
	// still unknown after the window: decided as it stands
	fin := e.raw()
	fin.Final = true
	a, disp, _, _ = p.Process(fin)
	if disp != Assessed || a.Signal != SignalUnknownGrant || a.Outcome != OutcomeOutOfBand {
		t.Fatalf("%v %+v", disp, a)
	}
	// the grant became known in the window (the lookups' map is the collector's snapshot): the held event clears
	good, err := LoadLookups([]byte(`{"grants":[{"id":"clr_later","objects":[`+rolloutJSON(map[string]any{})+`]}]}`), rs)
	if err != nil {
		t.Fatal(err)
	}
	lk.Grants["clr_later"] = good.Grants["clr_later"]
	a, disp, _, _ = p.Process(fin)
	if disp != Assessed || a.Signal != "grant-annotation+rendered-hash" || a.Outcome != OutcomeCleared || a.Grant != "clr_later" {
		t.Fatalf("%v %+v", disp, a)
	}
	if st := p.Stats(); st.Events != 2 || st.Assessed != 2 {
		t.Fatalf("counted once each when decided: %+v", st)
	}
	// not held: a refusal, and an operation on monitoring
	ref := kev{id: "u2", user: "system:serviceaccount:argocd:argocd-application-controller", verb: "patch", resource: "rollouts", name: "web", obj: obj, code: 403}
	if a, disp, _, _ = New2(rs, lk).Process(ref.raw()); disp != Assessed || a.Outcome != OutcomeRefused {
		t.Fatalf("a refusal is decided at once: %v %+v", disp, a)
	}
	mon := kev{id: "u3", user: "system:serviceaccount:argocd:argocd-application-controller", verb: "update", resource: "validatingwebhookconfigurations", name: "w",
		obj: map[string]any{"kind": "ValidatingWebhookConfiguration", "metadata": map[string]any{"name": "w", "annotations": map[string]any{stampGrant: "clr_never"}}}}
	if a, disp, _, _ = New2(rs, lk).Process(mon.raw()); disp != Assessed || !a.Monitoring || a.Outcome != OutcomeMonitoring {
		t.Fatalf("an operation on monitoring is decided at once: %v %+v", disp, a)
	}
	// a pipeline that was not asked to hold decides at once
	if a, disp, _, _ = New(rs, lk, vocab.Default()).Process(kev{id: "u4", user: e.user, verb: "patch", resource: "rollouts", name: "web",
		obj: rollout(map[string]any{stampGrant: "clr_nobody"}, 2)}.raw()); disp != Assessed || a.Signal != SignalUnknownGrant {
		t.Fatalf("%v %+v", disp, a)
	}
}

// New2 is a pipeline that holds unknown grants.
func New2(rs *RuleSet, lk Lookups) *Pipeline {
	p := New(rs, lk, vocab.Default())
	p.HoldUnknownGrants(true)
	return p
}

// A live Rollout carries fields its render leaves out (a restartAt, CRD defaults), so its own hash never equals the
// grant's and a controller's bookkeeping write to it is judged by what it changed: with the object as it was before known,
// a write that leaves the rendered-hash view of the object as it was is attributed to the grant it names; one that changes
// it, one by a person, and one with no before-state are not.
func TestControllerWriteThatChangesNothingRenderedIsUnchanged(t *testing.T) {
	rs, lk := derivedFixture(t)
	live := func(replicas int, ann map[string]any) map[string]any {
		o := rollout(ann, replicas)
		o["metadata"].(map[string]any)["annotations"].(map[string]any)[stampGrant] = "clr_roll"
		o["spec"].(map[string]any)["restartAt"] = "2026-10-24T05:31:24Z" // not in the render
		return o
	}
	before := mustJSON(live(2, map[string]any{"rollout.argoproj.io/revision": "12"}))
	for _, c := range []struct {
		name, user string
		after      map[string]any
		before     []byte
		signal     string
	}{
		{"bookkeeping only", rolloutsSA, live(2, map[string]any{"rollout.argoproj.io/revision": "13", "notified.notifications.argoproj.io": "{}"}), before, "grant-annotation+unchanged"},
		{"a rendered field changed", rolloutsSA, live(9, nil), before, "grant-annotation+hash-differs"},
		{"person, bookkeeping only", "dana@example.com", live(2, map[string]any{"rollout.argoproj.io/revision": "13"}), before, "grant-annotation+hash-differs"},
		{"no before-state", rolloutsSA, live(2, map[string]any{"rollout.argoproj.io/revision": "13"}), nil, "grant-annotation+hash-differs"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := kev{id: "x-" + c.name, user: c.user, verb: "patch", resource: "rollouts", name: "web", obj: c.after}.raw()
			e.Before = c.before
			a, disp, _, err := New(rs, lk, vocab.Default()).Process(e)
			if err != nil || disp != Assessed || a.Signal != c.signal {
				t.Fatalf("%v %v %+v", disp, err, a)
			}
			if c.signal == "grant-annotation+unchanged" && a.Outcome != OutcomeCleared {
				t.Fatalf("%+v", a)
			}
		})
	}
}
