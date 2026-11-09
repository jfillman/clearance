package auditpolicy

import (
	"strings"
	"testing"
)

func render(t *testing.T, ns ...string) *Policy {
	t.Helper()
	b, err := Render(Params{ProtectedNamespaces: ns})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The build fails if any rule of the shipped template would record a Secret body: every verb, every namespace, every
// user and group the policy names, in the template rendered with several sets of protected namespaces.
func TestShippedPolicyNeverRecordsASecretBody(t *testing.T) {
	for _, nss := range [][]string{nil, {"app-gate-api-prod"}, {"shop", "payments", "argocd", "cert-manager", "kube-system", "clearance-system"}} {
		p := render(t, nss...)
		if vs := Check(p); len(vs) > 0 {
			t.Fatalf("namespaces %v: %v", nss, vs)
		}
		// And directly, the cases the owner named: Secrets in a protected namespace, written by anyone.
		for _, ns := range append(nss, "elsewhere") {
			for _, v := range []string{"create", "update", "patch", "delete", "deletecollection"} {
				for _, user := range []string{"dana@example.com", "system:serviceaccount:argocd:argocd-application-controller"} {
					lvl := p.Evaluate(Request{User: user, Verb: v, Resource: "secrets", Ns: ns, Name: "db"})
					if lvl != Metadata {
						t.Fatalf("secret %s in %q by %s is %s, want Metadata", v, ns, user, lvl)
					}
				}
			}
			for _, v := range []string{"get", "list", "watch"} {
				if lvl := p.Evaluate(Request{User: "x", Verb: v, Resource: "secrets", Ns: ns}); lvl != None {
					t.Fatalf("a Secret read is %s, want None", lvl)
				}
			}
		}
		if lvl := p.Evaluate(Request{User: "x", Verb: "create", Resource: "serviceaccounts", Subresource: "token", Ns: "shop"}); lvl != Metadata {
			t.Fatalf("a token request is %s: its response is a credential", lvl)
		}
	}
}

// The check itself is tested: policies that do record Secret bodies must fail it, however the rule is written.
func TestCheckFindsPoliciesThatRecordSecrets(t *testing.T) {
	const head = "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n"
	for name, body := range map[string]string{
		"secrets at RequestResponse":         "  - level: RequestResponse\n    resources: [{group: \"\", resources: [secrets]}]\n",
		"all core resources at Request":      "  - level: Request\n    resources: [{group: \"\"}]\n",
		"every write at Request":             "  - level: Request\n    verbs: [create, update, patch]\n",
		"everything at RequestResponse":      "  - level: RequestResponse\n",
		"protected namespace, all resources": "  - level: RequestResponse\n    namespaces: [shop]\n    verbs: [create, update, patch, delete]\n",
		"wildcard resource":                  "  - level: Request\n    resources: [{group: \"\", resources: [\"*\"]}]\n",
		"one user":                           "  - level: RequestResponse\n    users: [dana@example.com]\n    resources: [{group: \"\", resources: [secrets]}]\n",
		"one group":                          "  - level: Request\n    userGroups: [devs]\n    resources: [{group: \"\", resources: [secrets]}]\n",
		"service account token":              "  - level: RequestResponse\n    resources: [{group: \"\", resources: [serviceaccounts/token]}]\n",
		"named secret":                       "  - level: Request\n    resources: [{group: \"\", resources: [secrets], resourceNames: [db]}]\n",
		"secret sub-resource":                "  - level: Request\n    resources: [{group: \"\", resources: [\"secrets/*\"]}]\n",
	} {
		t.Run(name, func(t *testing.T) {
			p, err := Parse([]byte(head + body + "  - level: None\n"))
			if err != nil {
				t.Fatal(err)
			}
			if vs := Check(p); len(vs) == 0 {
				t.Fatal("the check passed a policy that records Secret bodies")
			}
		})
	}
	// An earlier Metadata rule for Secrets (and their sub-resources, which the probe also tries) protects the later wide rule: the check follows the first-match order.
	p, _ := Parse([]byte(head + "  - level: Metadata\n    resources: [{group: \"\", resources: [secrets, secrets/*, serviceaccounts/token]}]\n  - level: RequestResponse\n"))
	if vs := Check(p); len(vs) != 0 {
		t.Fatalf("a Secret rule placed first is enough: %v", vs)
	}
	// But a wide rule placed first is not.
	p, _ = Parse([]byte(head + "  - level: RequestResponse\n    namespaces: [shop]\n  - level: Metadata\n    resources: [{group: \"\", resources: [secrets]}]\n"))
	if vs := Check(p); len(vs) == 0 {
		t.Fatal("a wide rule before the Secret rule must fail the check")
	}
}

// The matcher follows the API server where it is easy to get wrong: users and groups together need both; a group
// entry with no resources ignores resourceNames; "resource/*" matches the resource itself.
func TestMatcherFollowsTheAPIServer(t *testing.T) {
	const head = "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n"
	p, _ := Parse([]byte(head + "  - level: Metadata\n    users: [alice]\n    userGroups: [devs]\n  - level: RequestResponse\n"))
	if got := p.Evaluate(Request{User: "alice", Groups: []string{"ops"}, Verb: "get", Resource: "pods"}); got != LevelRequestResponse {
		t.Fatalf("a user in the rule but not its group: %s, want the later rule", got)
	}
	if got := p.Evaluate(Request{User: "alice", Groups: []string{"devs"}, Verb: "get", Resource: "pods"}); got != Metadata {
		t.Fatalf("%s", got)
	}
	p, _ = Parse([]byte(head + "  - level: RequestResponse\n    resources: [{group: \"\", resourceNames: [x]}]\n"))
	if got := p.Evaluate(Request{User: "u", Verb: "get", Resource: "secrets", Name: "other"}); got != LevelRequestResponse {
		t.Fatalf("resourceNames with no resources matches the whole group: %s", got)
	}
	if vs := Check(p); len(vs) == 0 {
		t.Fatal("and so the check must catch it")
	}
	p, _ = Parse([]byte(head + "  - level: Metadata\n    resources: [{group: \"\", resources: [\"secrets/*\"]}]\n  - level: RequestResponse\n"))
	if got := p.Evaluate(Request{User: "u", Verb: "update", Resource: "secrets"}); got != Metadata {
		t.Fatalf("secrets/* matches secrets itself: %s", got)
	}
}

func TestRenderRefusesParamsThatBreakTheRule(t *testing.T) {
	for _, ns := range []string{"", "a b", "a\"b"} {
		if _, err := Render(Params{ProtectedNamespaces: []string{ns}}); err == nil {
			t.Fatalf("namespace %q was accepted", ns)
		}
	}
}

// What the card asks the policy to drop, keep at Metadata, and record with bodies.
func TestPolicyLevelsFollowTheCard(t *testing.T) {
	p := render(t, "shop", "argocd")
	ns := func(n string) string { return n }
	for _, c := range []struct {
		name string
		req  Request
		want string
	}{
		{"read", Request{User: "dana", Verb: "get", Resource: "pods", Ns: "shop"}, None},
		{"list configmaps", Request{User: "dana", Verb: "list", Resource: "configmaps", Ns: "shop"}, None},
		{"scheduler", Request{User: "system:kube-scheduler", Verb: "create", Resource: "pods", Subresource: "binding", Ns: "shop"}, None},
		{"kubelet", Request{User: "system:node:n1", Groups: []string{"system:nodes"}, Verb: "patch", Resource: "nodes", Subresource: "status"}, None},
		{"event", Request{User: "dana", Verb: "create", Resource: "events", Ns: "shop"}, None},
		{"endpoints", Request{User: "x", Verb: "update", Resource: "endpoints", Ns: "shop"}, None},
		{"endpointslice", Request{User: "x", Verb: "update", APIGroup: "discovery.k8s.io", Resource: "endpointslices", Ns: "shop"}, None},
		{"lease", Request{User: "x", Verb: "update", APIGroup: "coordination.k8s.io", Resource: "leases", Ns: "kube-system"}, None},
		{"healthz", Request{User: "x", Verb: "get", NonResourceURL: "/healthz"}, None},
		{"status write in a protected namespace", Request{User: "x", Verb: "update", APIGroup: "apps", Resource: "deployments", Subresource: "status", Ns: ns("shop")}, Metadata},
		{"desired state in a protected namespace", Request{User: "dana", Verb: "patch", APIGroup: "apps", Resource: "deployments", Ns: "shop"}, LevelRequestResponse},
		{"configmap in a protected namespace", Request{User: "dana", Verb: "update", Resource: "configmaps", Ns: "argocd"}, LevelRequestResponse},
		{"delete in a protected namespace", Request{User: "dana", Verb: "delete", Resource: "services", Ns: "shop"}, LevelRequestResponse},
		{"clusterrole", Request{User: "dana", Verb: "update", APIGroup: "rbac.authorization.k8s.io", Resource: "clusterroles"}, LevelRequestResponse},
		{"clusterrolebinding", Request{User: "dana", Verb: "create", APIGroup: "rbac.authorization.k8s.io", Resource: "clusterrolebindings"}, LevelRequestResponse},
		{"validating webhook config", Request{User: "dana", Verb: "update", APIGroup: "admissionregistration.k8s.io", Resource: "validatingwebhookconfigurations"}, LevelRequestResponse},
		{"crd", Request{User: "dana", Verb: "update", APIGroup: "apiextensions.k8s.io", Resource: "customresourcedefinitions"}, LevelRequestResponse},
		{"argo application", Request{User: "dana", Verb: "update", APIGroup: "argoproj.io", Resource: "applications", Ns: "other"}, LevelRequestResponse},
		{"other write", Request{User: "dana", Verb: "update", Resource: "configmaps", Ns: "elsewhere"}, Metadata},
		{"other read of a custom thing", Request{User: "dana", Verb: "get", APIGroup: "example.io", Resource: "widgets", Ns: "elsewhere"}, None},
		{"secret in a protected namespace", Request{User: "dana", Verb: "update", Resource: "secrets", Ns: "shop"}, Metadata},
	} {
		if got := p.Evaluate(c.req); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestTemplateListsTheSecretRuleFirst(t *testing.T) {
	b, _ := Render(Params{ProtectedNamespaces: []string{"shop"}})
	s := string(b)
	secrets, wide := strings.Index(s, "resources: [secrets, secrets/*, serviceaccounts/token]"), strings.Index(s, "level: RequestResponse")
	if secrets < 0 || wide < 0 || secrets > wide {
		t.Fatalf("the Secret rule must come before any rule that records bodies (%d, %d)", secrets, wide)
	}
}
