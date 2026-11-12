package pipeline

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/vocab"
)

const (
	platformCtl = "system:serviceaccount:platform-cd:argocd-application-controller"
	appsCtl     = "system:serviceaccount:argocd:argocd-application-controller" // the default set's gated instance
)

// apps is a ArgoApplications for the tests, over StaticLookups.
type apps struct {
	StaticLookups
	byName  map[string]ArgoApp   // "<ns>/<name>"
	managed map[string][]ArgoApp // "<app ns>|<ns>/<lower kind>/<name>"
	hooks   map[string][]ArgoApp // same key: the sync hooks of an Application's current or last operation
	prev    map[string][]ArgoApp // same key: the hooks of the operation the current one replaced (within HookCleanupWindow)
}

func (a apps) HookOfRecent(scope, appNS, ns, kind, name string, at time.Time) (ArgoApp, bool) {
	k := appNS + "|" + ns + "/" + strings.ToLower(kind) + "/" + name
	l := append(append([]ArgoApp{}, a.hooks[k]...), a.prev[k]...)
	if len(l) != 1 {
		return ArgoApp{}, false
	}
	return l[0], true
}

func (a apps) HookOf(scope, appNS, ns, kind, name string) (ArgoApp, bool) {
	l := a.hooks[appNS+"|"+ns+"/"+strings.ToLower(kind)+"/"+name]
	if len(l) != 1 {
		return ArgoApp{}, false
	}
	return l[0], true
}

func (a apps) Application(scope, ns, name string) (ArgoApp, bool) {
	x, ok := a.byName[ns+"/"+name]
	return x, ok
}

func (a apps) ManagedBy(scope, appNS, ns, kind, name string) (ArgoApp, bool) {
	l := a.managed[appNS+"|"+ns+"/"+strings.ToLower(kind)+"/"+name]
	if len(l) != 1 {
		return ArgoApp{}, false
	}
	return l[0], true
}

// platformRules is the default rule set with one platform instance named.
func platformRules(t *testing.T, subjects ...string) *RuleSet {
	t.Helper()
	list := `[]`
	if len(subjects) > 0 {
		list = `["` + strings.Join(subjects, `", "`) + `"]`
	}
	rs, err := Load([]byte(strings.Replace(string(DefaultRules()), "platform_gitops: []", "platform_gitops: "+list, 1)))
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func tracked(kind, group, ns, name, app string) map[string]any {
	md := map[string]any{"name": name, "annotations": map[string]any{
		"argocd.argoproj.io/tracking-id": fmt.Sprintf("%s:%s/%s:%s/%s", app, group, kind, ns, name)}}
	if ns != "" {
		md["namespace"] = ns
	}
	return map[string]any{"kind": kind, "metadata": md}
}

func gitopsLookups() apps {
	sync := ArgoApp{Namespace: "platform-cd", Name: "platform-rbac", Revision: "4771d884218725dff73023ee4ec112f764944129"}
	return apps{
		StaticLookups: StaticLookups{},
		byName:        map[string]ArgoApp{"platform-cd/platform-rbac": sync, "platform-cd/fresh": {Namespace: "platform-cd", Name: "fresh"}},
		managed:       map[string][]ArgoApp{"platform-cd|shop/secret/db-creds": {sync}, "platform-cd|shop/secret/both": {sync, sync}},
		hooks: map[string][]ArgoApp{"platform-cd|shop/job/redis-init": {sync}, "platform-cd|shop/job/twice": {sync, sync},
			"platform-cd|shop/serviceaccount/redis-init": {sync}},
		prev: map[string][]ArgoApp{"platform-cd|shop/job/old-init": {{Namespace: "platform-cd", Name: "platform-rbac", Revision: "aaaa1111"}}},
	}
}

// G-ARGO-10a: a write by a platform instance's application controller to an object that carries its tracking annotation,
// naming an Application the collector sees, is attributed to that Application and its revision; an object with no
// annotation, an annotation about another object or a tracked object of an Application nobody sees stays out-of-band, and
// no other identity (the gated instance's controller, a person, kubectl, impersonation) is touched.
func TestPlatformGitopsAttribution(t *testing.T) {
	const rev = "4771d884218725dff73023ee4ec112f764944129"
	rs := platformRules(t, platformCtl)
	lk := gitopsLookups()
	role := func(obj map[string]any) kev {
		return kev{id: "g", user: platformCtl, verb: "patch", resource: "roles", name: "reader", obj: obj}
	}
	untracked := map[string]any{"kind": "Role", "metadata": map[string]any{"name": "reader", "namespace": "shop"}}
	cases := []struct {
		name    string
		e       kev
		signal  string
		outcome string
		app     string
	}{
		{"tracked role", role(tracked("Role", "rbac.authorization.k8s.io", "shop", "reader", "platform-rbac")),
			SignalPlatformGitops, OutcomeNotAttributed, "platform-cd/platform-rbac"},
		{"tracked externalsecret create", kev{id: "g2", user: platformCtl, verb: "create", resource: "externalsecrets", name: "reader",
			obj: tracked("ExternalSecret", "external-secrets.io", "shop", "reader", "platform-rbac")}, SignalPlatformGitops, OutcomeNotAttributed, "platform-cd/platform-rbac"},
		{"no tracking annotation stays out-of-band", role(untracked), "service-account.unknown", OutcomeOutOfBand, ""},
		{"tracking id of another object", role(tracked("Role", "rbac.authorization.k8s.io", "shop", "other", "platform-rbac")), "service-account.unknown", OutcomeOutOfBand, ""},
		{"application nobody sees", role(tracked("Role", "rbac.authorization.k8s.io", "shop", "reader", "ghost")), "service-account.unknown", OutcomeOutOfBand, ""},
		{"application not compared yet has no revision", role(tracked("Role", "rbac.authorization.k8s.io", "shop", "reader", "fresh")), "service-account.unknown", OutcomeOutOfBand, ""},
		{"the gated instance's controller is not the platform's", kev{id: "g3", user: appsCtl, verb: "patch", resource: "roles", name: "reader",
			obj: tracked("Role", "rbac.authorization.k8s.io", "shop", "reader", "platform-rbac")}, "argo-controller.no-grant", OutcomeOutOfBand, ""},
		{"a person writing a tracked object", kev{id: "g4", user: "dana@example.com", verb: "patch", resource: "roles", name: "reader",
			obj: tracked("Role", "rbac.authorization.k8s.io", "shop", "reader", "platform-rbac")}, "human.no-grant", OutcomeOutOfBand, ""},
		{"kubectl as the platform controller", kev{id: "g5", user: platformCtl, verb: "patch", resource: "roles", name: "reader", ua: "kubectl/v1.36",
			obj: tracked("Role", "rbac.authorization.k8s.io", "shop", "reader", "platform-rbac")}, "kubectl-agent", OutcomeOutOfBand, ""},
		{"refused", kev{id: "g6", user: platformCtl, verb: "patch", resource: "roles", name: "reader", code: 403,
			obj: tracked("Role", "rbac.authorization.k8s.io", "shop", "reader", "platform-rbac")}, "response.refused", OutcomeRefused, ""},
		// A Secret is recorded at Metadata: no object, so no annotation. The instance's own list of what it manages stands in.
		{"secret the Application manages", kev{id: "g7", user: platformCtl, verb: "update", resource: "secrets", name: "db-creds"},
			SignalPlatformGitops, OutcomeNotAttributed, "platform-cd/platform-rbac"},
		{"secret no Application lists", kev{id: "g8", user: platformCtl, verb: "update", resource: "secrets", name: "other"}, "service-account.unknown", OutcomeOutOfBand, ""},
		{"secret two Applications claim", kev{id: "g9", user: platformCtl, verb: "update", resource: "secrets", name: "both"}, "service-account.unknown", OutcomeOutOfBand, ""},
		{"person writing the managed secret", kev{id: "g10", user: "dana@example.com", verb: "update", resource: "secrets", name: "db-creds"}, "human.no-grant", OutcomeOutOfBand, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, disp, _, err := New(rs, lk, vocab.Default()).Process(c.e.raw())
			if err != nil || disp != Assessed {
				t.Fatal(disp, err)
			}
			if a.Signal != c.signal || a.Outcome != c.outcome || a.Application != c.app {
				t.Fatalf("got %s/%s app %q (%s), want %s/%s app %q", a.Signal, a.Outcome, a.Application, a.Detail, c.signal, c.outcome, c.app)
			}
			if c.app != "" {
				if a.Revision != rev || !strings.Contains(a.Detail, c.app) || !strings.Contains(a.Detail, rev) {
					t.Fatalf("the detail must name the Application and the revision: %+v", a)
				}
				if a.Coverage != "observed-not-attributed" || a.Tier != 1 || a.Confidence != "" {
					t.Fatalf("coverage %s tier %d confidence %s", a.Coverage, a.Tier, a.Confidence)
				}
			}
		})
	}
}

// Without the identity in the rule set, or lookups that cannot say, nothing is attributed to GitOps.
func TestPlatformGitopsIsOffUnlessConfigured(t *testing.T) {
	e := kev{id: "o1", user: platformCtl, verb: "patch", resource: "roles", name: "reader",
		obj: tracked("Role", "rbac.authorization.k8s.io", "shop", "reader", "platform-rbac")}
	for name, p := range map[string]*Pipeline{
		"no subject named":     New(platformRules(t), gitopsLookups(), vocab.Default()),
		"lookups without apps": New(platformRules(t, platformCtl), StaticLookups{}, vocab.Default()),
	} {
		a, disp, _, err := p.Process(e.raw())
		if err != nil || disp != Assessed || a.Signal == SignalPlatformGitops {
			t.Fatalf("%s: %v %v %+v", name, disp, err, a)
		}
	}
}

// A grant stamp the object carries is judged first: the platform controller touching a granted object whose hash differs
// is out-of-band whatever tracking annotation it also carries.
func TestPlatformGitopsNeverOverridesAGrantMismatch(t *testing.T) {
	rs := platformRules(t, platformCtl)
	obj := tracked("Rollout", "argoproj.io", "shop", "web", "platform-rbac")
	obj["metadata"].(map[string]any)["annotations"].(map[string]any)[stampGrant] = "clr_roll"
	obj["spec"] = map[string]any{"replicas": 9}
	_, lk := derivedFixture(t)
	lk2 := gitopsLookups()
	lk2.StaticLookups = lk
	a, disp, _, err := New(rs, lk2, vocab.Default()).Process(kev{id: "m1", user: platformCtl, verb: "patch", resource: "rollouts", name: "web", obj: obj}.raw())
	if err != nil || disp != Assessed || a.Outcome != OutcomeOutOfBand || a.Signal != "grant-annotation+hash-differs" {
		t.Fatalf("%v %v %+v", disp, err, a)
	}
}

func TestPlatformGitopsIdentitiesAreValidatedAtLoad(t *testing.T) {
	for name, subject := range map[string]string{
		"pattern":         "system:serviceaccount:argocd:*",
		"group":           "system:serviceaccounts:argocd",
		"a person":        "dana@example.com",
		"the gated one":   "system:serviceaccount:argocd:argocd-application-controller", // in argo_controller of the default set
		"not one account": "system:serviceaccount:argocd",
	} {
		_, err := Load([]byte(strings.Replace(string(DefaultRules()), "platform_gitops: []", `platform_gitops: ["`+subject+`"]`, 1)))
		if err == nil || !strings.Contains(err.Error(), "platform_gitops") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTrackingIDParses(t *testing.T) {
	for in, want := range map[string]trackingID{
		"argocd-apps-install:/ConfigMap:argocd-apps/argocd-cm": {"", "argocd-apps-install", "ConfigMap", "argocd-apps", "argocd-cm", ""},
		"team-a_web:apps/Deployment:shop/web":                  {"team-a", "web", "Deployment", "shop", "web", "apps"},
		"cluster:rbac.authorization.k8s.io/ClusterRole:/admin": {"", "cluster", "ClusterRole", "", "admin", "rbac.authorization.k8s.io"},
	} {
		if got, ok := parseTrackingID(in); !ok || got != want {
			t.Errorf("%s: %+v %v, want %+v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "x", "a:b", "a:nokind:ns/n", "a:g/K:nonamespace"} {
		if _, ok := parseTrackingID(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

// Writes to the status subresource by a controller, and a service account's TokenRequest, are not changes: counted as out of
// scope, not assessed. A person's status write, a refusal, scale and every other subresource, and a node's token, are as
// before; a status write to an object a grant relates to is still attributed (listed-grant, owner-grant).
func TestStatusAndTokenWritesAreNotChanges(t *testing.T) {
	rs, lk := derivedFixture(t)
	cases := []struct {
		name    string
		e       kev
		oos     bool
		outcome string
	}{
		{"replicaset-controller status", kev{id: "n1", user: rsCtlSA, verb: "update", resource: "replicasets", name: "x", sub: "status"}, true, ""},
		{"deployment-controller status with a body", kev{id: "n2", user: "system:serviceaccount:kube-system:deployment-controller", verb: "update", resource: "deployments", name: "x", sub: "status",
			obj: map[string]any{"kind": "Deployment", "metadata": map[string]any{"name": "x", "namespace": "shop"}}}, true, ""},
		{"calico-node token", kev{id: "n3", user: "system:serviceaccount:kube-system:calico-node", verb: "create", resource: "serviceaccounts", name: "calico-cni-plugin", sub: "token"}, true, ""},
		{"person status", kev{id: "n4", user: "dana@example.com", verb: "patch", resource: "deployments", name: "x", sub: "status"}, false, OutcomeOutOfBand},
		{"kubectl as a controller, status", kev{id: "n5", user: rsCtlSA, verb: "patch", resource: "deployments", name: "x", sub: "status", ua: "kubectl/v1.36"}, false, OutcomeOutOfBand},
		{"person token", kev{id: "n6", user: "dana@example.com", verb: "create", resource: "serviceaccounts", name: "admin", sub: "token"}, false, OutcomeOutOfBand},
		{"node token (a named kubelet is an exact noise rule)", kev{id: "n7", user: "system:node:worker-9", verb: "create", resource: "serviceaccounts", name: "x", sub: "token"}, false, OutcomeOutOfBand},
		{"refused status write", kev{id: "n8", user: rsCtlSA, verb: "update", resource: "replicasets", name: "x", sub: "status", code: 403}, false, OutcomeRefused},
		{"scale is untouched", kev{id: "n9", user: rsCtlSA, verb: "update", resource: "deployments", name: "x", sub: "scale"}, false, OutcomeOutOfBand},
		{"another subresource is untouched", kev{id: "n10", user: rsCtlSA, verb: "update", resource: "services", name: "x", sub: "ephemeralcontainers"}, false, OutcomeOutOfBand},
		{"a write with no subresource is untouched", kev{id: "n11", user: rsCtlSA, verb: "update", resource: "deployments", name: "x"}, false, OutcomeOutOfBand},
		{"status of an object a grant lists keeps its attribution", kev{id: "n12", user: rolloutsSA, verb: "patch", resource: "rollouts", name: "web", sub: "status"}, false, OutcomeCleared},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := New(rs, lk, vocab.Default())
			a, disp, _, err := p.Process(c.e.raw())
			if err != nil {
				t.Fatal(err)
			}
			if c.oos {
				if disp != OutOfScope || a != nil || p.Stats().OutOfScope["prod-1"] != 1 || p.Stats().Assessed != 0 {
					t.Fatalf("got %v %+v %+v, want counted as out of scope", disp, a, p.Stats())
				}
				return
			}
			if disp != Assessed || a.Outcome != c.outcome {
				t.Fatalf("got %v %+v, want assessed %s", disp, a, c.outcome)
			}
		})
	}
}

// A status write to a monitoring kind is never dropped.
func TestStatusWriteToMonitoringIsNotDropped(t *testing.T) {
	rs := mustRules(t)
	p := New(rs, StaticLookups{}, vocab.Default())
	a, disp, _, err := p.Process(kev{id: "w1", user: rsCtlSA, verb: "update", resource: "validatingwebhookconfigurations", name: "x", sub: "status"}.raw())
	if err != nil || disp != Assessed || a.Outcome != OutcomeMonitoring {
		t.Fatalf("%v %v %+v", disp, err, a)
	}
}

// clusterEvent is a succeeded write to a cluster-scoped object (no namespace in objectRef), by the platform controller.
func clusterEvent(id, verb, resource, name string, obj map[string]any) fx {
	return fx{id: id, user: platformCtl, verb: verb, resource: resource, name: name, cluster: true, obj: obj}
}

// Argo CD (v3.5.0, util/argo/resource_tracking.go, UnstructuredToAppInstanceValue) writes the Application's destination namespace
// into the tracking id of a cluster-scoped object. Attribution matches group, kind and name and ignores that namespace; the
// Application must still be known with a revision, and an id that names another object, kind or group stays visible.
func TestPlatformGitopsClusterScopedObjects(t *testing.T) {
	rs := platformRules(t, platformCtl)
	lk := gitopsLookups()
	rbac := "rbac.authorization.k8s.io"
	cases := []struct {
		name   string
		e      fx
		signal string
		app    string
	}{
		{"clusterrole with the destination namespace", clusterEvent("c1", "patch", "clusterroles", "obs", tracked("ClusterRole", rbac, "clearance-system", "obs", "platform-rbac")), SignalPlatformGitops, "platform-cd/platform-rbac"},
		{"clusterrolebinding", clusterEvent("c2", "update", "clusterrolebindings", "obs", tracked("ClusterRoleBinding", rbac, "clearance-system", "obs", "platform-rbac")), SignalPlatformGitops, "platform-cd/platform-rbac"},
		{"validatingadmissionpolicy", clusterEvent("c3", "update", "validatingadmissionpolicies", "protected", tracked("ValidatingAdmissionPolicy", "admissionregistration.k8s.io", "clearance-system", "protected", "platform-rbac")), SignalPlatformGitops, "platform-cd/platform-rbac"},
		{"an empty namespace part still matches", clusterEvent("c4", "patch", "clusterroles", "obs", tracked("ClusterRole", rbac, "", "obs", "platform-rbac")), SignalPlatformGitops, "platform-cd/platform-rbac"},
		{"id names another object", clusterEvent("c5", "patch", "clusterroles", "obs", tracked("ClusterRole", rbac, "clearance-system", "other", "platform-rbac")), "service-account.unknown", ""},
		{"id names another kind", clusterEvent("c6", "patch", "clusterroles", "obs", func() map[string]any {
			o := tracked("ClusterRoleBinding", rbac, "clearance-system", "obs", "platform-rbac")
			o["kind"] = "ClusterRole"
			return o
		}()), "service-account.unknown", ""},
		{"id names another group", fx{id: "c7", user: platformCtl, verb: "patch", resource: "clusterroles", name: "obs", cluster: true, group: rbac,
			obj: tracked("ClusterRole", "example.io", "clearance-system", "obs", "platform-rbac")}, "service-account.unknown", ""},
		{"application nobody sees", clusterEvent("c8", "patch", "clusterroles", "obs", tracked("ClusterRole", rbac, "clearance-system", "obs", "ghost")), "service-account.unknown", ""},
		{"application with no revision", clusterEvent("c9", "patch", "clusterroles", "obs", tracked("ClusterRole", rbac, "clearance-system", "obs", "fresh")), "service-account.unknown", ""},
		{"a person writing it", fx{id: "c10", user: "dana@example.com", verb: "patch", resource: "clusterroles", name: "obs", cluster: true,
			obj: tracked("ClusterRole", rbac, "clearance-system", "obs", "platform-rbac")}, "human.no-grant", ""},
		{"a namespaced object still must match its namespace", fx{id: "c11", user: platformCtl, verb: "patch", resource: "roles", name: "reader",
			obj: tracked("Role", rbac, "elsewhere", "reader", "platform-rbac")}, "service-account.unknown", ""},
		{"delete reads the before-state", fx{id: "c12", user: platformCtl, verb: "delete", resource: "clusterroles", name: "obs", cluster: true,
			before: tracked("ClusterRole", rbac, "clearance-system", "obs", "platform-rbac")}, SignalPlatformGitops, "platform-cd/platform-rbac"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, disp := c.e.run(t, New(rs, lk, vocab.Default()))
			if disp != Assessed || a.Signal != c.signal || a.Application != c.app {
				t.Fatalf("got %v %s app %q, want %s app %q", disp, a.Signal, a.Application, c.signal, c.app)
			}
			if c.app != "" && (a.Outcome != OutcomeNotAttributed || a.Revision == "" || a.Coverage != "observed-not-attributed" || a.Tier != 1) {
				t.Fatalf("%+v", a)
			}
		})
	}
}

func hookJob(name, ann, val string) map[string]any {
	return map[string]any{"kind": "Job", "metadata": map[string]any{"name": name, "namespace": "shop", "annotations": map[string]any{ann: val}}}
}

// A sync hook carries no tracking annotation: it is attributed when it carries a hook annotation and exactly one Application of
// the instance lists it (as a hook) in its operation. Deletes (hook-delete-policy) read the annotation from the before-state.
// An object no Application lists, one two list, a hook-looking object with a tracking id of another object, a person's write
// and a non-hook annotation stay visible.
func TestPlatformGitopsSyncHooks(t *testing.T) {
	rs := platformRules(t, platformCtl)
	lk := gitopsLookups()
	cases := []struct {
		name   string
		e      fx
		signal string
		app    string
	}{
		{"create of an argo hook", fx{id: "h1", user: platformCtl, verb: "create", resource: "jobs", name: "redis-init", obj: hookJob("redis-init", "argocd.argoproj.io/hook", "PreSync")}, SignalPlatformGitops, "platform-cd/platform-rbac"},
		{"create of a helm hook", fx{id: "h2", user: platformCtl, verb: "create", resource: "jobs", name: "redis-init", obj: hookJob("redis-init", "helm.sh/hook", "pre-install")}, SignalPlatformGitops, "platform-cd/platform-rbac"},
		{"delete by hook-delete-policy uses the before-state", fx{id: "h3", user: platformCtl, verb: "delete", resource: "jobs", name: "redis-init", before: hookJob("redis-init", "argocd.argoproj.io/hook", "PostSync")}, SignalPlatformGitops, "platform-cd/platform-rbac"},
		{"hook-looking object no Application lists", fx{id: "h4", user: platformCtl, verb: "create", resource: "jobs", name: "stranger", obj: hookJob("stranger", "argocd.argoproj.io/hook", "PreSync")}, "service-account.unknown", ""},
		{"two Applications list it", fx{id: "h5", user: platformCtl, verb: "create", resource: "jobs", name: "twice", obj: hookJob("twice", "argocd.argoproj.io/hook", "PreSync")}, "service-account.unknown", ""},
		{"listed but carries no hook annotation", fx{id: "h6", user: platformCtl, verb: "create", resource: "jobs", name: "redis-init", obj: hookJob("redis-init", "example.io/x", "PreSync")}, "service-account.unknown", ""},
		{"hook annotation Skip", fx{id: "h7", user: platformCtl, verb: "create", resource: "jobs", name: "redis-init", obj: hookJob("redis-init", "argocd.argoproj.io/hook", "Skip")}, "service-account.unknown", ""},
		{"a person creating the hook", fx{id: "h8", user: "dana@example.com", verb: "create", resource: "jobs", name: "redis-init", obj: hookJob("redis-init", "argocd.argoproj.io/hook", "PreSync")}, "human.no-grant", ""},
		{"a tracking id of another object is not rescued by the hook list", fx{id: "h9", user: platformCtl, verb: "create", resource: "jobs", name: "redis-init", group: "batch",
			obj: func() map[string]any {
				o := tracked("Job", "batch", "shop", "other", "platform-rbac")
				o["metadata"].(map[string]any)["annotations"].(map[string]any)["argocd.argoproj.io/hook"] = "PreSync"
				return o
			}()}, "service-account.unknown", ""},
		{"the gated instance's controller", fx{id: "h10", user: appsCtl, verb: "create", resource: "jobs", name: "redis-init", obj: hookJob("redis-init", "argocd.argoproj.io/hook", "PreSync")}, "argo-controller.no-grant", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, disp := c.e.run(t, New(rs, lk, vocab.Default()))
			if disp != Assessed || a.Signal != c.signal || a.Application != c.app {
				t.Fatalf("got %v %s app %q (%s), want %s app %q", disp, a.Signal, a.Application, a.Detail, c.signal, c.app)
			}
			if c.app != "" && (a.Outcome != OutcomeNotAttributed || a.Revision == "" || a.Coverage != "observed-not-attributed" || a.Tier != 1) {
				t.Fatalf("%+v", a)
			}
		})
	}
}

func ownedBy(kind, name, owner, ownerName, ann string) map[string]any {
	md := map[string]any{"name": name, "namespace": "shop",
		"ownerReferences": []any{map[string]any{"apiVersion": "batch/v1", "kind": owner, "name": ownerName, "uid": "u1"}}}
	if ann != "" {
		md["annotations"] = map[string]any{ann: "PostSync"}
	}
	return map[string]any{"kind": kind, "metadata": md}
}

// Kubernetes removing a finished sync hook (the TTL controller deleting the hook Job, the garbage collector deleting the Job or its
// owned ServiceAccount, Role, RoleBinding) is the sync's consequence and is attributed to the Application and operation that ran
// the hook. Nothing else is: a non-hook Job, an object owned by a Job no Application lists, two claimants, another namespace, a
// person, a Metadata-level event with no before-state, an owner of another kind, another verb.
func TestPlatformGitopsHookCleanup(t *testing.T) {
	rs := platformRules(t, platformCtl)
	lk := gitopsLookups()
	del := func(id, user, res, name string, before map[string]any) fx {
		return fx{id: id, user: user, verb: "delete", resource: res, name: name, before: before}
	}
	hj := hookJob("redis-init", "argocd.argoproj.io/hook", "PreSync")
	cases := []struct {
		name   string
		e      fx
		signal string
		app    string
		rev    string
	}{
		{"ttl deletes the hook job", del("k1", ttlCtlSA, "jobs", "redis-init", hj), SignalPlatformGitops, "platform-cd/platform-rbac", "4771d884218725dff73023ee4ec112f764944129"},
		{"gc deletes the hook job", del("k2", gcSA, "jobs", "redis-init", hj), SignalPlatformGitops, "platform-cd/platform-rbac", "4771d884218725dff73023ee4ec112f764944129"},
		{"gc deletes the job's serviceaccount", del("k3", gcSA, "serviceaccounts", "redis-init", ownedBy("ServiceAccount", "redis-init", "Job", "redis-init", "")), SignalPlatformGitops, "platform-cd/platform-rbac", "4771d884218725dff73023ee4ec112f764944129"},
		{"gc deletes the job's role", del("k4", gcSA, "roles", "redis-init", ownedBy("Role", "redis-init", "Job", "redis-init", "")), SignalPlatformGitops, "platform-cd/platform-rbac", "4771d884218725dff73023ee4ec112f764944129"},
		{"gc deletes the job's rolebinding", del("k5", gcSA, "rolebindings", "redis-init", ownedBy("RoleBinding", "redis-init", "Job", "redis-init", "")), SignalPlatformGitops, "platform-cd/platform-rbac", "4771d884218725dff73023ee4ec112f764944129"},
		{"gc deletes a hook serviceaccount that is itself listed", del("k6", gcSA, "serviceaccounts", "redis-init",
			map[string]any{"kind": "ServiceAccount", "metadata": map[string]any{"name": "redis-init", "namespace": "shop", "annotations": map[string]any{"argocd.argoproj.io/hook": "PreSync"}}}), SignalPlatformGitops, "platform-cd/platform-rbac", "4771d884218725dff73023ee4ec112f764944129"},
		{"the previous operation's hook, within the window", del("k7", ttlCtlSA, "jobs", "old-init", hookJob("old-init", "argocd.argoproj.io/hook", "PreSync")), SignalPlatformGitops, "platform-cd/platform-rbac", "aaaa1111"},
		{"gc patches the hook job's finalizers off (metadata only)", fx{id: "k8", user: gcSA, verb: "patch", resource: "jobs", name: "redis-init",
			obj: map[string]any{"kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1", "metadata": map[string]any{"name": "redis-init", "namespace": "shop"}}},
			SignalPlatformGitops, "platform-cd/platform-rbac", "4771d884218725dff73023ee4ec112f764944129"},
		// stays visible
		{"gc patches the hook job with a full object", fx{id: "n16", user: gcSA, verb: "patch", resource: "jobs", name: "redis-init", obj: hj}, "service-account.unknown", "", ""},
		{"gc metadata patch on a job no Application lists", fx{id: "n17", user: gcSA, verb: "patch", resource: "jobs", name: "nightly",
			obj: map[string]any{"kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1", "metadata": map[string]any{"name": "nightly", "namespace": "shop"}}}, "service-account.unknown", "", ""},
		{"ttl deletes a job no Application lists", del("n1", ttlCtlSA, "jobs", "nightly", hookJob("nightly", "x/y", "z")), "service-account.unknown", "", ""},
		{"gc deletes an object owned by a job no Application lists", del("n2", gcSA, "serviceaccounts", "redis-init", ownedBy("ServiceAccount", "redis-init", "Job", "stranger", "")), "service-account.unknown", "", ""},
		{"gc deletes an object with no hook owner", del("n3", gcSA, "roles", "redis-init", map[string]any{"kind": "Role", "metadata": map[string]any{"name": "redis-init", "namespace": "shop"}}), "service-account.unknown", "", ""},
		{"owner of another kind", del("n4", gcSA, "serviceaccounts", "redis-init", ownedBy("ServiceAccount", "redis-init", "CronJob", "redis-init", "")), "service-account.unknown", "", ""},
		{"owned by a hook job but listed under two Applications", del("n5", gcSA, "serviceaccounts", "twice", ownedBy("ServiceAccount", "twice", "Job", "twice", "")), "service-account.unknown", "", ""},
		{"two Applications claim the job", del("n6", ttlCtlSA, "jobs", "twice", hookJob("twice", "argocd.argoproj.io/hook", "PreSync")), "service-account.unknown", "", ""},
		{"wrong namespace", fx{id: "n7", user: ttlCtlSA, verb: "delete", resource: "jobs", name: "redis-init", ns: "elsewhere", before: hookJob("redis-init", "argocd.argoproj.io/hook", "PreSync")}, "service-account.unknown", "", ""},
		{"a person deletes the hook job", del("n8", "dana@example.com", "jobs", "redis-init", hj), "human.no-grant", "", ""},
		{"no before-state (Metadata)", del("n9", ttlCtlSA, "jobs", "redis-init", nil), "service-account.unknown", "", ""},
		{"gc, no before-state", del("n10", gcSA, "serviceaccounts", "redis-init", nil), "service-account.unknown", "", ""},
		{"ttl deletes a non-job", del("n11", ttlCtlSA, "serviceaccounts", "redis-init", ownedBy("ServiceAccount", "redis-init", "Job", "redis-init", "")), "service-account.unknown", "", ""},
		{"gc patches an owned serviceaccount", fx{id: "n12", user: gcSA, verb: "patch", resource: "serviceaccounts", name: "redis-init", obj: ownedBy("ServiceAccount", "redis-init", "Job", "redis-init", "")}, "service-account.unknown", "", ""},
		{"another kube-system controller", del("n13", "system:serviceaccount:kube-system:job-controller", "jobs", "redis-init", hj), "service-account.unknown", "", ""},
		{"gc deletes a hook-annotated object no Application lists", del("n14", gcSA, "serviceaccounts", "other", ownedBy("ServiceAccount", "other", "Pod", "x", "argocd.argoproj.io/hook")), "service-account.unknown", "", ""},
		{"gc through a kubectl client", fx{id: "n15", user: gcSA, verb: "delete", resource: "jobs", name: "redis-init", before: hj, ua: "kubectl/v1.30"}, "kubectl-agent", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, disp := c.e.run(t, New(rs, lk, vocab.Default()))
			if disp == OutOfScope {
				if c.app != "" {
					t.Fatalf("counted out of scope, want %s", c.signal)
				}
				return // dropped as a controller child: not a finding either way
			}
			if disp != Assessed || a.Signal != c.signal || a.Application != c.app || a.Revision != c.rev {
				t.Fatalf("got %v %s app %q rev %q (%s), want %s app %q rev %q", disp, a.Signal, a.Application, a.Revision, a.Detail, c.signal, c.app, c.rev)
			}
			if c.app != "" && (a.Outcome != OutcomeNotAttributed || a.Coverage != "observed-not-attributed" || a.Tier != 1) {
				t.Fatalf("%+v", a)
			}
		})
	}
}
