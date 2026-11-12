package pipeline

import (
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/vocab"
)

// fx is a Kubernetes audit event with the parts the 0.41.1 fixes read: the response status (code, reason, message), the
// audit annotations, the object (RequestResponse) and the collector's before-state.
type fx struct {
	id, user, verb, resource, name, sub string
	ns                                  string
	code                                int
	reason, message                     string
	ann                                 map[string]any
	obj                                 map[string]any // responseObject
	before                              map[string]any
	ua                                  string
}

func (f fx) raw() RawEvent {
	if f.code == 0 {
		f.code = 200
	}
	if f.ns == "" {
		f.ns = "shop"
	}
	st := map[string]any{"code": f.code}
	if f.reason != "" {
		st["reason"] = f.reason
	}
	if f.message != "" {
		st["message"] = f.message
	}
	m := map[string]any{"auditID": f.id, "stage": "ResponseComplete", "verb": f.verb, "stageTimestamp": "2026-11-12T09:00:00Z",
		"user":           map[string]any{"username": f.user},
		"objectRef":      map[string]any{"resource": f.resource, "namespace": f.ns, "name": f.name, "subresource": f.sub},
		"responseStatus": st, "userAgent": f.ua, "level": "Metadata"}
	if f.ann != nil {
		m["annotations"] = f.ann
	}
	if f.obj != nil {
		m["level"], m["responseObject"] = "RequestResponse", f.obj
	}
	r := RawEvent{Provider: Kubernetes, Scope: "prod-1", Raw: mustJSON(m)}
	if f.before != nil {
		r.Before = mustJSON(f.before)
	}
	return r
}

const (
	deployCtlSA = "system:serviceaccount:kube-system:deployment-controller"
	jobCtlSA    = "system:serviceaccount:kube-system:job-controller"
	ttlCtlSA    = "system:serviceaccount:kube-system:ttl-after-finished-controller"
	vapStatusSA = "system:serviceaccount:kube-system:validatingadmissionpolicy-status-controller"
	kcmUser     = "system:kube-controller-manager"
)

func (f fx) run(t *testing.T, p *Pipeline) (*Assessment, Disposition) {
	t.Helper()
	a, disp, _, err := p.Process(f.raw())
	if err != nil {
		t.Fatalf("%s: %v", f.id, err)
	}
	return a, disp
}

// attempted-refused is a security refusal: 401, 403 or an admission denial. A controller's 409 (a lost status update, an
// AlreadyExists create), 404 (a delete or patch of what is gone) and 422 that admission did not deny are not, and are counted
// out of scope; a refusal of a monitoring kind, by a person, kubectl or an impersonated request, or with any other code,
// stays as it was.
func TestRefusalIsASecurityRefusal(t *testing.T) {
	rs := platformRules(t, platformCtl)
	vapAnn := map[string]any{"validation.policy.admission.k8s.io/validation_failure": `[{"message":"no","policy":"pss"}]`}
	cases := []struct {
		name   string
		e      fx
		oos    bool
		signal string // when assessed
	}{
		// the four observed on hangar-dev
		{"deployment-controller status update, 409", fx{id: "r1", user: deployCtlSA, verb: "update", resource: "deployments", name: "web", sub: "status", code: 409, reason: "Conflict"}, true, ""},
		{"redis-secret-init create secret, AlreadyExists", fx{id: "r2", user: "system:serviceaccount:argocd:argocd-apps-redis-secret-init", verb: "create", resource: "secrets", name: "argocd-redis", code: 409, reason: "AlreadyExists"}, true, ""},
		{"controller-manager create serviceaccount token, 404", fx{id: "r3", user: kcmUser, verb: "create", resource: "serviceaccounts", name: "gone", sub: "token", code: 404, reason: "NotFound"}, true, ""},
		{"platform argo patch role, 409", fx{id: "r4", user: platformCtl, verb: "patch", resource: "roles", name: "reader", code: 409, reason: "Conflict"}, true, ""},
		{"platform argo patch role, 404", fx{id: "r5", user: platformCtl, verb: "patch", resource: "roles", name: "reader", code: 404, reason: "NotFound"}, true, ""},
		{"controller, 422 invalid", fx{id: "r6", user: deployCtlSA, verb: "update", resource: "deployments", name: "web", code: 422, reason: "Invalid", message: "Deployment.apps \"web\" is invalid: spec.selector: field is immutable"}, true, ""},
		// security refusals stay
		{"controller, 403", fx{id: "r7", user: platformCtl, verb: "patch", resource: "roles", name: "reader", code: 403, reason: "Forbidden"}, false, "response.refused"},
		{"controller, 401", fx{id: "r8", user: platformCtl, verb: "patch", resource: "roles", name: "reader", code: 401, reason: "Unauthorized"}, false, "response.refused"},
		{"controller, 422 denied by a policy (audit annotation)", fx{id: "r9", user: deployCtlSA, verb: "update", resource: "deployments", name: "web", code: 422, reason: "Invalid", ann: vapAnn}, false, "audit-annotation.vap-denial"},
		{"controller, 422 denied by a webhook (message)", fx{id: "r10", user: deployCtlSA, verb: "update", resource: "deployments", name: "web", code: 422, reason: "Invalid",
			message: `admission webhook "validate.kyverno.svc-fail" denied the request: policy require-labels`}, false, "response.refused"},
		{"controller, 409 carrying a policy denial", fx{id: "r11", user: deployCtlSA, verb: "update", resource: "deployments", name: "web", code: 409, ann: vapAnn}, false, "audit-annotation.vap-denial"},
		{"controller, 500 from a webhook that failed closed", fx{id: "r12", user: deployCtlSA, verb: "create", resource: "replicasets", name: "web-1", code: 500,
			message: `Internal error occurred: failed calling webhook "x.example.com": context deadline exceeded`}, false, "response.refused"},
		{"controller, any other code (500) stays", fx{id: "r13", user: deployCtlSA, verb: "update", resource: "deployments", name: "web", code: 500}, false, "response.refused"},
		// who and what: never a person, never kubectl, never monitoring
		{"person, 409", fx{id: "r14", user: "dana@example.com", verb: "update", resource: "deployments", name: "web", code: 409, reason: "Conflict"}, false, "response.refused"},
		{"person, 404 delete", fx{id: "r15", user: "dana@example.com", verb: "delete", resource: "deployments", name: "web", code: 404}, false, "response.refused"},
		{"kubectl with a service account's token, 409", fx{id: "r16", user: deployCtlSA, verb: "update", resource: "deployments", name: "web", code: 409, ua: "kubectl/v1.36"}, false, "response.refused"},
		{"controller, 409 on a webhook configuration (monitoring)", fx{id: "r17", user: deployCtlSA, verb: "update", resource: "validatingwebhookconfigurations", name: "x", code: 409}, false, "response.refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := New(rs, gitopsLookups(), vocab.Default())
			a, disp := c.e.run(t, p)
			if c.oos {
				if disp != OutOfScope || a != nil || p.Stats().OutOfScope["prod-1"] != 1 || p.Stats().Assessed != 0 {
					t.Fatalf("got %v %+v %+v, want counted out of scope", disp, a, p.Stats())
				}
				return
			}
			if disp != Assessed {
				t.Fatalf("got %v, want assessed", disp)
			}
			if c.name == "controller, 409 on a webhook configuration (monitoring)" {
				if a.Outcome != OutcomeMonitoring {
					t.Fatalf("%s/%s, want monitoring-protection", a.Signal, a.Outcome)
				}
				return
			}
			if a.Outcome != OutcomeRefused || a.Signal != c.signal {
				t.Fatalf("got %s/%s, want %s/attempted-refused", a.Signal, a.Outcome, c.signal)
			}
		})
	}
}

func podOwnedBy(kind, owner string, controller bool) map[string]any {
	return map[string]any{"kind": "Pod", "metadata": map[string]any{"name": "web-abc12", "namespace": "shop",
		"ownerReferences": []any{map[string]any{"kind": kind, "name": owner, "controller": controller}}}}
}

// A kube-system controller managing the objects it created is not a change to desired state. The object must have a
// controller ownerReference where the event shows it; a person or another service account writing the same kind is visible.
func TestControllerChildrenAreOutOfScope(t *testing.T) {
	rs := mustRules(t)
	rsOwned := map[string]any{"kind": "ReplicaSet", "metadata": map[string]any{"name": "web-5d", "namespace": "shop",
		"ownerReferences": []any{map[string]any{"kind": "Deployment", "name": "web", "controller": true}}}}
	jobOwned := map[string]any{"kind": "Job", "metadata": map[string]any{"name": "nightly-1", "namespace": "shop",
		"ownerReferences": []any{map[string]any{"kind": "CronJob", "name": "nightly", "controller": true}}}}
	gcPartial := map[string]any{"kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1", "metadata": map[string]any{"name": "web-abc12",
		"namespace": "shop", "ownerReferences": []any{map[string]any{"kind": "ReplicaSet", "name": "web-5d", "controller": true}}}}
	cases := []struct {
		name   string
		e      fx
		oos    bool
		signal string
	}{
		{"replicaset controller creates a pod (body shows the owner)", fx{id: "c1", user: rsCtlSA, verb: "create", resource: "pods", name: "web-abc12", obj: podOwnedBy("ReplicaSet", "web-5d", true)}, true, ""},
		{"replicaset controller creates a pod (Metadata: nothing shown)", fx{id: "c2", user: rsCtlSA, verb: "create", resource: "pods", name: "web-abc12"}, true, ""},
		{"replicaset controller deletes a pod (Metadata)", fx{id: "c2b", user: rsCtlSA, verb: "delete", resource: "pods", name: "web-abc12"}, true, ""},
		{"deployment controller creates a replicaset", fx{id: "c3", user: deployCtlSA, verb: "create", resource: "replicasets", name: "web-5d", obj: rsOwned}, true, ""},
		{"job controller creates a pod of a job", fx{id: "c4", user: jobCtlSA, verb: "create", resource: "pods", name: "nightly-1-x", obj: podOwnedBy("Job", "nightly-1", true)}, true, ""},
		{"cronjob controller creates a job", fx{id: "c5", user: "system:serviceaccount:kube-system:cronjob-controller", verb: "create", resource: "jobs", name: "nightly-1", obj: jobOwned}, true, ""},
		{"ttl controller deletes a finished job (Metadata)", fx{id: "c6", user: ttlCtlSA, verb: "delete", resource: "jobs", name: "nightly-1"}, true, ""},
		{"garbage collector patches a pod (PartialObjectMetadata)", fx{id: "c7", user: gcSA, verb: "patch", resource: "pods", name: "web-abc12", obj: gcPartial}, true, ""},
		{"garbage collector deletes a replicaset", fx{id: "c8", user: gcSA, verb: "delete", resource: "replicasets", name: "web-5d"}, true, ""},
		{"owner shown only by the before-state", fx{id: "c9", user: gcSA, verb: "patch", resource: "pods", name: "web-abc12",
			obj: map[string]any{"kind": "PartialObjectMetadata", "metadata": map[string]any{"name": "web-abc12", "namespace": "shop"}}, before: podOwnedBy("ReplicaSet", "web-5d", true)}, true, ""},

		{"garbage collector deletes a job", fx{id: "c10", user: gcSA, verb: "delete", resource: "jobs", name: "nightly-1"}, true, ""},
		{"garbage collector deletes a pod", fx{id: "c11", user: gcSA, verb: "delete", resource: "pods", name: "web-abc12"}, true, ""},

		// stays visible
		{"garbage collector deletes a configmap", fx{id: "w1", user: gcSA, verb: "delete", resource: "configmaps", name: "cfg"}, false, "service-account.unknown"},
		{"garbage collector deletes a role", fx{id: "w2", user: gcSA, verb: "delete", resource: "roles", name: "reader"}, false, "service-account.unknown"},
		{"garbage collector deletes a deployment", fx{id: "w3", user: gcSA, verb: "delete", resource: "deployments", name: "web"}, false, "service-account.unknown"},
		{"garbage collector patches a pod with a plain body", fx{id: "w4", user: gcSA, verb: "patch", resource: "pods", name: "web-abc12", obj: podOwnedBy("ReplicaSet", "web-5d", true)}, false, "service-account.unknown"},
		{"garbage collector patches a pod, Metadata (no kind carried)", fx{id: "w5", user: gcSA, verb: "patch", resource: "pods", name: "web-abc12"}, false, "service-account.unknown"},
		{"garbage collector patches a configmap, PartialObjectMetadata", fx{id: "w6", user: gcSA, verb: "patch", resource: "configmaps", name: "cfg",
			obj: map[string]any{"kind": "PartialObjectMetadata", "metadata": map[string]any{"name": "cfg", "namespace": "shop", "ownerReferences": []any{map[string]any{"kind": "X", "name": "y", "controller": true}}}}}, false, "service-account.unknown"},
		{"garbage collector updates a pod, PartialObjectMetadata", fx{id: "w7", user: gcSA, verb: "update", resource: "pods", name: "web-abc12", obj: gcPartial}, false, "service-account.unknown"},
		{"person creates a pod with an ownerReference", fx{id: "v1", user: "dana@example.com", verb: "create", resource: "pods", name: "web-abc12", obj: podOwnedBy("ReplicaSet", "web-5d", true)}, false, "human.no-grant"},
		{"person creates a pod (Metadata)", fx{id: "v2", user: "dana@example.com", verb: "create", resource: "pods", name: "debug"}, false, "human.no-grant"},
		{"another service account creates a pod", fx{id: "v3", user: "system:serviceaccount:shop:builder", verb: "create", resource: "pods", name: "web-abc12", obj: podOwnedBy("ReplicaSet", "web-5d", true)}, false, "service-account.unknown"},
		{"a kube-system controller of another kind of service account (not listed)", fx{id: "v3b", user: "system:serviceaccount:kube-system:somebody", verb: "create", resource: "pods", name: "web-abc12"}, false, "service-account.unknown"},
		{"replicaset controller, pod shown with no owner", fx{id: "v4", user: rsCtlSA, verb: "create", resource: "pods", name: "orphan", obj: map[string]any{"kind": "Pod", "metadata": map[string]any{"name": "orphan", "namespace": "shop"}}}, false, "service-account.unknown"},
		{"replicaset controller, pod shown with a non-controller owner", fx{id: "v5", user: rsCtlSA, verb: "create", resource: "pods", name: "web-abc12", obj: podOwnedBy("ReplicaSet", "web-5d", false)}, false, "service-account.unknown"},
		{"replicaset controller writes a kind that is not its child (a Service)", fx{id: "v6", user: rsCtlSA, verb: "update", resource: "services", name: "web"}, false, "service-account.unknown"},
		{"deployment controller creates a pod (not its kind)", fx{id: "v7", user: deployCtlSA, verb: "create", resource: "pods", name: "web-abc12", obj: podOwnedBy("ReplicaSet", "web-5d", true)}, false, "service-account.unknown"},
		{"kubectl with the controller's token", fx{id: "v8", user: rsCtlSA, verb: "create", resource: "pods", name: "web-abc12", ua: "kubectl/v1.36", obj: podOwnedBy("ReplicaSet", "web-5d", true)}, false, "kubectl-agent"},
		{"garbage collector, shown a body with no controller owner", fx{id: "v9", user: gcSA, verb: "patch", resource: "pods", name: "web-abc12",
			obj: map[string]any{"kind": "PartialObjectMetadata", "metadata": map[string]any{"name": "web-abc12", "namespace": "shop"}}}, false, "service-account.unknown"},
		{"refused (403) is still a refusal", fx{id: "v10", user: rsCtlSA, verb: "create", resource: "pods", name: "web-abc12", code: 403}, false, "response.refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := New(rs, StaticLookups{}, vocab.Default())
			a, disp := c.e.run(t, p)
			if c.oos {
				if disp != OutOfScope || a != nil || p.Stats().OutOfScope["prod-1"] != 1 || p.Stats().Assessed != 0 {
					t.Fatalf("got %v %+v %+v, want counted out of scope", disp, a, p.Stats())
				}
				return
			}
			if disp != Assessed || a.Signal != c.signal {
				t.Fatalf("got %v %+v, want assessed %s", disp, a, c.signal)
			}
		})
	}
}

// A monitoring kind is never counted out, the garbage collector or not; neither is a policy object.
func TestControllerChildrenNeverHideMonitoring(t *testing.T) {
	rs := mustRules(t)
	p := New(rs, StaticLookups{}, vocab.Default())
	a, disp := fx{id: "m1", user: gcSA, verb: "delete", resource: "validatingwebhookconfigurations", name: "x"}.run(t, p)
	if disp != Assessed || a.Outcome != OutcomeMonitoring {
		t.Fatalf("%v %+v", disp, a)
	}
	a, disp = fx{id: "m2", user: gcSA, verb: "delete", resource: "validatingadmissionpolicies", name: "x"}.run(t, p)
	if disp != Assessed {
		t.Fatalf("a ValidatingAdmissionPolicy deleted by the garbage collector was dropped: %v %+v", disp, a)
	}
	// its own controller's status write is a status write (notAChange), not a child
	if _, disp = (fx{id: "m3", user: vapStatusSA, verb: "update", resource: "validatingadmissionpolicies", name: "x", sub: "status"}).run(t, p); disp != OutOfScope {
		t.Fatalf("validatingadmissionpolicy-status-controller status write: %v", disp)
	}
	if _, disp = (fx{id: "m4", user: vapStatusSA, verb: "update", resource: "validatingadmissionpolicies", name: "x", sub: "status", code: 409}).run(t, p); disp != OutOfScope {
		t.Fatalf("validatingadmissionpolicy-status-controller status conflict: %v", disp)
	}
}

// A granted object's derived children stay attributed to the grant (and counted as verified), not dropped.
func TestControllerChildrenOfAGrantStayCleared(t *testing.T) {
	rs, lk := derivedFixture(t)
	p := New(rs, lk, vocab.Default())
	if _, disp := (fx{id: "g0", user: "system:serviceaccount:argo-rollouts:argo-rollouts", verb: "create", resource: "replicasets", name: "web-rs",
		obj: owned("ReplicaSet", "web-rs", "Rollout", "web", "clr_roll")}).run(t, p); disp != Assessed {
		t.Fatal(disp)
	}
	a, disp := fx{id: "g1", user: rsCtlSA, verb: "create", resource: "pods", name: "web-rs-x1", obj: owned("Pod", "web-rs-x1", "ReplicaSet", "web-rs", "clr_roll")}.run(t, p)
	if disp != Assessed || a.Signal != SignalOwnerGrant || a.Grant != "clr_roll" {
		t.Fatalf("%v %+v", disp, a)
	}
}

func TestControllerChildrenRulesAreValidated(t *testing.T) {
	base := string(DefaultRules())
	bad := map[string]string{
		"a pattern":                  `- {subject: "system:serviceaccount:kube-system:*", kinds: [Pod]}`,
		"another namespace":          `- {subject: "system:serviceaccount:shop:builder", kinds: [Pod]}`,
		"a person":                   `- {subject: "dana@example.com", kinds: [Pod]}`,
		"no kinds":                   `- {subject: "system:serviceaccount:kube-system:replicaset-controller", kinds: []}`,
		"a kind pattern":             `- {subject: "system:serviceaccount:kube-system:replicaset-controller", kinds: ["Po*"]}`,
		"a monitoring kind":          `- {subject: "system:serviceaccount:kube-system:replicaset-controller", kinds: [ValidatingWebhookConfiguration]}`,
		"a verb that is not a write": `- {subject: "system:serviceaccount:kube-system:job-controller", kinds: [Job], verbs: [get]}`,
		"the same subject twice":     `- {subject: "system:serviceaccount:kube-system:job-controller", kinds: [Job]}`,
	}
	for name, entry := range bad {
		t.Run(name, func(t *testing.T) {
			doc := strings.Replace(base, "  controller_children:\n", "  controller_children:\n    "+entry+"\n", 1)
			if _, err := Load([]byte(doc)); err == nil {
				t.Fatal("loaded")
			}
		})
	}
}

// A delete carries no object, so a pruned object's tracking annotation is read from the collector's before-state: the
// object itself, not the Application's list of what it manages (which no longer has it).
func TestPlatformGitopsDeleteUsesTheBeforeState(t *testing.T) {
	rs := platformRules(t, platformCtl)
	lk := gitopsLookups()
	before := func(kind, group, name, app string) map[string]any { return tracked(kind, group, "shop", name, app) }
	cases := []struct {
		name   string
		e      fx
		signal string
		app    string
	}{
		{"pruned role", fx{id: "d1", user: platformCtl, verb: "delete", resource: "roles", name: "reader", before: before("Role", "rbac.authorization.k8s.io", "reader", "platform-rbac")}, SignalPlatformGitops, "platform-cd/platform-rbac"},
		{"pruned rolebinding", fx{id: "d2", user: platformCtl, verb: "delete", resource: "rolebindings", name: "reader", before: before("RoleBinding", "rbac.authorization.k8s.io", "reader", "platform-rbac")}, SignalPlatformGitops, "platform-cd/platform-rbac"},
		{"pruned serviceaccount", fx{id: "d3", user: platformCtl, verb: "delete", resource: "serviceaccounts", name: "robot", before: before("ServiceAccount", "", "robot", "platform-rbac")}, SignalPlatformGitops, "platform-cd/platform-rbac"},
		{"tracking id names another object", fx{id: "d4", user: platformCtl, verb: "delete", resource: "roles", name: "reader", before: before("Role", "rbac.authorization.k8s.io", "other", "platform-rbac")}, "service-account.unknown", ""},
		{"before-state with no tracking annotation", fx{id: "d5", user: platformCtl, verb: "delete", resource: "roles", name: "reader",
			before: map[string]any{"kind": "Role", "metadata": map[string]any{"name": "reader", "namespace": "shop", "annotations": map[string]any{"x": "y"}}}}, "service-account.unknown", ""},
		{"an Application nobody sees", fx{id: "d6", user: platformCtl, verb: "delete", resource: "roles", name: "reader", before: before("Role", "rbac.authorization.k8s.io", "reader", "ghost")}, "service-account.unknown", ""},
		{"an Application with no revision", fx{id: "d7", user: platformCtl, verb: "delete", resource: "roles", name: "reader", before: before("Role", "rbac.authorization.k8s.io", "reader", "fresh")}, "service-account.unknown", ""},
		{"a person deleting a tracked role", fx{id: "d8", user: "dana@example.com", verb: "delete", resource: "roles", name: "reader", before: before("Role", "rbac.authorization.k8s.io", "reader", "platform-rbac")}, "human.no-grant", ""},
		{"no before-state and not in the Application's list", fx{id: "d9", user: platformCtl, verb: "delete", resource: "roles", name: "reader"}, "service-account.unknown", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, disp := c.e.run(t, New(rs, lk, vocab.Default()))
			if disp != Assessed || a.Signal != c.signal || a.Application != c.app {
				t.Fatalf("got %v %s app %q, want %s app %q", disp, a.Signal, a.Application, c.signal, c.app)
			}
			if c.app != "" && (a.Outcome != OutcomeNotAttributed || a.Revision == "") {
				t.Fatalf("%+v", a)
			}
		})
	}
}

// indexed is gitopsLookups with a switch for whether the Application index has synced.
type indexed struct {
	apps
	synced *bool
}

func (x indexed) ApplicationsSynced() bool { return *x.synced }

// Until the Application index has synced, a platform controller's write is held, not decided: the index being empty is the
// collector's start, not a fact about the write.
func TestPlatformGitopsWritesWaitForTheApplicationIndex(t *testing.T) {
	rs := platformRules(t, platformCtl)
	synced := false
	lk := indexed{gitopsLookups(), &synced}
	p := New(rs, lk, vocab.Default())
	p.HoldUnsyncedApplications(true)
	role := fx{id: "i1", user: platformCtl, verb: "patch", resource: "roles", name: "reader", obj: tracked("Role", "rbac.authorization.k8s.io", "shop", "reader", "platform-rbac")}

	a, disp := role.run(t, p)
	if disp != HeldIndex || a != nil || p.Stats().Events != 0 || p.Stats().Assessed != 0 {
		t.Fatalf("got %v %+v %+v, want held-index and nothing counted", disp, a, p.Stats())
	}
	// the timeout: the caller gives it back as Final, and it is decided as it stands
	r := role.raw()
	r.Final = true
	ra, rdisp, _, err := p.Process(r)
	if err != nil || rdisp != Assessed || ra.Signal != SignalPlatformGitops {
		t.Fatalf("final: %v %v %+v", rdisp, err, ra) // this lookups can answer: Final decides on what it knows
	}
	// not held: another identity, a refusal, a write that is not a platform controller's, and the index synced
	other := fx{id: "i2", user: "dana@example.com", verb: "patch", resource: "roles", name: "reader", obj: role.obj}
	if _, disp = other.run(t, p); disp != Assessed {
		t.Fatalf("a person's write was held: %v", disp)
	}
	refused := fx{id: "i3", user: platformCtl, verb: "patch", resource: "roles", name: "reader", code: 403, obj: role.obj}
	if _, disp = refused.run(t, p); disp != Assessed {
		t.Fatalf("a refusal was held: %v", disp)
	}
	synced = true
	if a, disp = role.run(t, p); disp != Assessed || a.Signal != SignalPlatformGitops {
		t.Fatalf("after the sync: %v %+v", disp, a)
	}
	// off: the pipeline decides at once, as before
	synced = false
	p.HoldUnsyncedApplications(false)
	if _, disp = role.run(t, p); disp != Assessed {
		t.Fatalf("hold off: %v", disp)
	}
}
