package pipeline

import (
	"fmt"
	"strings"
	"testing"

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
		"argocd-apps-install:/ConfigMap:argocd-apps/argocd-cm": {"", "argocd-apps-install", "ConfigMap", "argocd-apps", "argocd-cm"},
		"team-a_web:apps/Deployment:shop/web":                  {"team-a", "web", "Deployment", "shop", "web"},
		"cluster:rbac.authorization.k8s.io/ClusterRole:/admin": {"", "cluster", "ClusterRole", "", "admin"},
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
