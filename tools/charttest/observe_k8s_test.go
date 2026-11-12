package charttest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/internal/vocab"
)

const observeChartDir = "../../charts/clearance-observe-k8s"

func helmObserve(t *testing.T, args ...string) (string, error) {
	t.Helper()
	bin, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not on PATH")
	}
	var out, errb bytes.Buffer
	cmd := exec.Command(bin, append([]string{"template", "t", observeChartDir, "--namespace", "clearance-system",
		"-f", observeChartDir + "/ci/minimal-values.yaml"}, args...)...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return errb.String(), err
	}
	return out.String(), nil
}

func renderObserve(t *testing.T, args ...string) []obj {
	t.Helper()
	text, err := helmObserve(t, args...)
	if err != nil {
		t.Fatalf("helm template %v: %v\n%s", args, err, text)
	}
	dec := yaml.NewDecoder(strings.NewReader(text))
	var out []obj
	for {
		var o obj
		if err := dec.Decode(&o); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decoding the render: %v", err)
		}
		if o != nil {
			out = append(out, o)
		}
	}
	return out
}

func rulesOf(o obj) []any {
	l, _ := get(o, "rules").([]any)
	return l
}

func TestObserveK8sChartRenders(t *testing.T) {
	objs := renderObserve(t)
	for _, want := range []string{"Deployment/clearance-observe-k8s", "Service/clearance-observe-k8s", "PersistentVolumeClaim/clearance-observe-k8s",
		"ServiceAccount/clearance-observe-k8s", "ClusterRole/clearance-observe-k8s", "NetworkPolicy/clearance-observe-k8s",
		"ConfigMap/clearance-observe-k8s-rules", "ConfigMap/clearance-observe-heartbeat", "Secret/clearance-observe-canary"} {
		if !slices.Contains(kinds(objs), want) {
			t.Errorf("missing %s in %v", want, kinds(objs))
		}
	}
	d := find(objs, "Deployment", "clearance-observe-k8s")
	if get(d, "spec", "replicas") != 1 || get(d, "spec", "strategy", "type") != "Recreate" {
		t.Errorf("replicas %v strategy %v; want 1, Recreate (one reader of a ReadWriteOnce queue)", get(d, "spec", "replicas"), get(d, "spec", "strategy", "type"))
	}
	ps := get(d, "spec", "template", "spec", "securityContext")
	c := container(t, d)
	sc := get(c, "securityContext")
	if get(ps, "runAsNonRoot") != true || get(ps, "runAsUser") != 65532 || get(ps, "seccompProfile", "type") != "RuntimeDefault" ||
		get(sc, "readOnlyRootFilesystem") != true || get(sc, "allowPrivilegeEscalation") != false || get(sc, "capabilities", "drop", 0) != "ALL" {
		t.Errorf("hardening: pod %v container %v", ps, sc)
	}
	// no credential: the core is reached with the projected token, and no env var is a secret
	for k, v := range env(c) {
		if strings.HasPrefix(v, "secret:") {
			t.Errorf("env %s reads a Secret: %s", k, v)
		}
	}
	vols, _ := get(d, "spec", "template", "spec", "volumes").([]any)
	var tok bool
	for _, v := range vols {
		if get(v, "name") == "clearance-token" && get(v, "projected", "sources", 0, "serviceAccountToken", "audience") == "clearance" &&
			get(v, "projected", "sources", 0, "serviceAccountToken", "expirationSeconds") == 3600 {
			tok = true
		}
	}
	if !tok {
		t.Errorf("the core's token is a short-lived projected one: %v", vols)
	}
	pvc := find(objs, "PersistentVolumeClaim", "clearance-observe-k8s")
	if get(pvc, "metadata", "annotations", "helm.sh/resource-policy") != "keep" {
		t.Errorf("the queue's volume must outlive the release: %v", get(pvc, "metadata", "annotations"))
	}
	if svc := find(objs, "Service", "clearance-observe-k8s"); get(svc, "spec", "clusterIP") != "10.96.200.50" || get(svc, "spec", "ports", 0, "port") != 8443 {
		t.Errorf("service %v", get(svc, "spec"))
	}
	args := strings.Join(toStrings(get(c, "args")), " ")
	for _, want := range []string{"--cluster=hangar-prod", "--allowed-client=kube-apiserver", "--canary-secret=clearance-observe-canary",
		"--policy-configmap=kube-system/audit-policy", "--watch-namespaces=app-gate-api-prod,argocd-apps"} {
		if !strings.Contains(args, want) {
			t.Errorf("args lack %s: %s", want, args)
		}
	}
	np := find(objs, "NetworkPolicy", "clearance-observe-k8s")
	if get(np, "spec", "ingress", 0, "from", 0, "ipBlock", "cidr") != "10.0.0.0/24" {
		t.Errorf("ingress is the control plane only: %v", get(np, "spec", "ingress"))
	}
}

func toStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, x.(string))
	}
	return out
}

// The collector never reads a Secret: no Role or ClusterRole it is bound to has get, list or watch on secrets (or on
// everything), and the one rule that names secrets is a patch of the canary by name.
func TestObserveK8sChartGivesNoReadOfSecrets(t *testing.T) {
	objs := renderObserve(t)
	n := 0
	for _, o := range objs {
		if o["kind"] != "Role" && o["kind"] != "ClusterRole" {
			continue
		}
		for _, r := range rulesOf(o) {
			res := toStrings(get(r, "resources"))
			verbs := toStrings(get(r, "verbs"))
			if slices.Contains(res, "*") || slices.Contains(verbs, "*") {
				t.Errorf("%v has a wildcard rule: %v", get(o, "metadata", "name"), r)
			}
			if !slices.ContainsFunc(res, func(s string) bool { return s == "secrets" || strings.HasPrefix(s, "secrets/") }) {
				continue
			}
			n++
			if !slices.Equal(verbs, []string{"patch"}) || !slices.Equal(toStrings(get(r, "resourceNames")), []string{"clearance-observe-canary"}) {
				t.Errorf("%v: a rule on secrets that is not a patch of the canary: %v", get(o, "metadata", "name"), r)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d rules name secrets, want exactly the canary patch", n)
	}
	// with the canary off there is no rule on Secrets at all
	for _, o := range renderObserve(t, "--set", "heartbeat.canarySecret.enabled=false") {
		for _, r := range rulesOf(o) {
			if slices.Contains(toStrings(get(r, "resources")), "secrets") {
				t.Errorf("a rule on secrets with the canary off: %v", r)
			}
		}
		if o["kind"] == "Secret" {
			t.Error("the canary Secret is rendered with the canary off")
		}
	}
}

// The rule set the chart renders loads in the pipeline (every rule compiles within its cost limit), carries the
// pipeline's attribution orders, and governs the cluster, namespaces and kinds the values name.
func TestObserveK8sChartRulesLoadInThePipeline(t *testing.T) {
	objs := renderObserve(t)
	cm := find(objs, "ConfigMap", "clearance-observe-k8s-rules")
	doc, _ := get(cm, "data", "observe-rules.yaml").(string)
	rs, err := pipeline.Load([]byte(doc))
	if err != nil {
		t.Fatalf("the rendered rule set does not load: %v\n%s", err, doc)
	}
	if rs.Ref.Name != "observe-hangar" || rs.Ref.Version != "2026.11.7" {
		t.Errorf("%+v", rs.Ref)
	}
	if !strings.Contains(doc, "hangar-prod") || !strings.Contains(doc, "app-gate-api-prod") || !strings.Contains(doc, "argocd-apps") {
		t.Error("the values are not in the rule set")
	}
	// the attribution section is the pipeline's, verbatim: it cannot drift from default.yaml
	def, err := os.ReadFile("../../internal/observe/pipeline/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tail := string(def)[strings.Index(string(def), "# Attribution: ordered signals"):]
	if !strings.Contains(doc, strings.TrimSpace(tail)) {
		t.Error("charts/clearance-observe-k8s/files/attribute.yaml has drifted from internal/observe/pipeline/default.yaml")
	}
	// an override replaces the generated set
	vf := filepath.Join(t.TempDir(), "override.yaml")
	ov, _ := yaml.Marshal(map[string]any{"rules": map[string]any{"override": string(def)}})
	if err := os.WriteFile(vf, ov, 0o600); err != nil {
		t.Fatal(err)
	}
	objs = renderObserve(t, "-f", vf)
	doc, _ = get(find(objs, "ConfigMap", "clearance-observe-k8s-rules"), "data", "observe-rules.yaml").(string)
	if _, err := pipeline.Load([]byte(doc)); err != nil || !strings.Contains(doc, "observe-default") {
		t.Errorf("override: %v", err)
	}
}

func TestObserveK8sChartRefusesWhatWouldBeUnsafe(t *testing.T) {
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"no cluster":           {[]string{"--set", "cluster="}, "cluster is required"},
		"no core":              {[]string{"--set", "coreURL="}, "coreURL is required"},
		"no allowed client":    {[]string{"--set", "webhook.allowedClients=null"}, "allowedClients is required"},
		"no tls secret":        {[]string{"--set", "webhook.tlsSecret="}, "tlsSecret is required"},
		"no namespaces":        {[]string{"--set", "protectedNamespaces=null"}, "protectedNamespaces is required"},
		"watching secrets":     {[]string{"--set", "watch.resources[0].resource=secrets"}, "must not name Secrets"},
		"watching Secret kind": {[]string{"--set", "watch.resources[0].kind=Secret"}, "must not name Secrets"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := helmObserve(t, c.args...)
			if err == nil || !strings.Contains(out, c.want) {
				t.Fatalf("got %v %q, want a refusal naming %q", err, out, c.want)
			}
		})
	}
}

// The routine writers the chart gives exact noise rules (live shapes from hangar-prod): each rule drops its one identity's
// succeeded write of exactly its shape, and nothing a step to the side of it: another verb, subresource, kind or owner,
// another identity, a refused attempt.
func TestObserveK8sChartNoiseRulesAreExact(t *testing.T) {
	objs := renderObserve(t)
	doc, _ := get(find(objs, "ConfigMap", "clearance-observe-k8s-rules"), "data", "observe-rules.yaml").(string)
	rs, err := pipeline.Load([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	const (
		ns         = "app-gate-api-prod"
		calico     = "system:serviceaccount:kube-system:calico-cni-plugin"
		agentSA    = "system:serviceaccount:clearance-system:clearance-argocd-agent"
		crossplane = "system:serviceaccount:crossplane-system:crossplane"
		disrupt    = "system:serviceaccount:kube-system:disruption-controller"
		eso        = "system:serviceaccount:external-secrets:external-secrets"
		jobCtl     = "system:serviceaccount:kube-system:job-controller"
	)
	owner := func(kind, name string) []any {
		return []any{map[string]any{"kind": kind, "name": name, "controller": true}}
	}
	obj := func(kind, name string, labels map[string]any, owners []any) map[string]any {
		md := map[string]any{"name": name, "namespace": ns, "labels": labels}
		if owners != nil {
			md["ownerReferences"] = owners
		}
		return map[string]any{"kind": kind, "metadata": md}
	}
	type c struct {
		name, user, verb, resource, objName, sub, ns string
		code                                         int
		obj                                          map[string]any
		want                                         string // the noise rule, or "" for an assessment
		oos                                          bool   // not a change (a controller's status write no rule names): counted, not assessed
	}
	composite := map[string]any{"crossplane.io/composite": "gate-api"}
	cases := []c{
		{name: "calico pod status", user: calico, verb: "patch", resource: "pods", objName: "web-1", sub: "status", want: "calico-cni-pod-status"},
		{name: "calico pod status, kube-system", user: calico, verb: "patch", resource: "pods", objName: "web-1", sub: "status", ns: "kube-system", want: "calico-cni-pod-status"},
		{name: "calico update", user: calico, verb: "update", resource: "pods", objName: "web-1", sub: "status", oos: true},
		{name: "calico pod body", user: calico, verb: "patch", resource: "pods", objName: "web-1"},
		{name: "calico configmap", user: calico, verb: "patch", resource: "configmaps", objName: "x", sub: "status", oos: true},
		{name: "calico refused", user: calico, verb: "patch", resource: "pods", objName: "web-1", sub: "status", code: 403},
		{name: "person patching pod status", user: "dana@example.com", verb: "patch", resource: "pods", objName: "web-1", sub: "status"},

		{name: "agent creates a grant", user: agentSA, verb: "create", resource: "clearancegrants", objName: "g", obj: map[string]any{"kind": "ClearanceGrant"}, want: "clearance-argocd-agent-grants"},
		{name: "agent patches a grant, Metadata level", user: agentSA, verb: "patch", resource: "clearancegrants", objName: "g", want: "clearance-argocd-agent-grants"},
		{name: "agent patches grant status", user: agentSA, verb: "patch", resource: "clearancegrants", objName: "g", sub: "status", want: "clearance-argocd-agent-grants"},
		{name: "agent deletes a grant", user: agentSA, verb: "delete", resource: "clearancegrants", objName: "g", want: "clearance-argocd-agent-grants"},
		{name: "agent's refused create (Forbidden)", user: agentSA, verb: "create", resource: "clearancegrants", objName: "g", code: 403},
		{name: "agent's create that found the grant there (AlreadyExists) is not a refusal", user: agentSA, verb: "create", resource: "clearancegrants", objName: "g", code: 409, oos: true},
		{name: "agent writing a configmap", user: agentSA, verb: "patch", resource: "configmaps", objName: "g"},
		{name: "person writing a grant", user: "dana@example.com", verb: "patch", resource: "clearancegrants", objName: "g"},

		{name: "crossplane patches its composite", user: crossplane, verb: "patch", resource: "rolloutwatches", objName: "gate-api", obj: obj("RolloutWatch", "gate-api", composite, nil), want: "crossplane-composite-resources"},
		{name: "crossplane patches its composite status", user: crossplane, verb: "patch", resource: "rolloutwatches", objName: "gate-api", sub: "status", obj: obj("RolloutWatch", "gate-api", composite, nil), want: "crossplane-composite-resources"},
		{name: "crossplane patches a RolloutWatch it does not compose", user: crossplane, verb: "patch", resource: "rolloutwatches", objName: "gate-api", obj: obj("RolloutWatch", "gate-api", map[string]any{}, nil)},
		{name: "crossplane deletes its composite", user: crossplane, verb: "delete", resource: "rolloutwatches", objName: "gate-api", obj: obj("RolloutWatch", "gate-api", composite, nil)},
		{name: "crossplane patches another kind", user: crossplane, verb: "patch", resource: "deployments", objName: "web", obj: obj("Deployment", "web", composite, nil)},
		{name: "crossplane patches the SA of the composite", user: crossplane, verb: "patch", resource: "serviceaccounts", objName: "diagnosis-dispatch", obj: obj("ServiceAccount", "diagnosis-dispatch", composite, owner("RolloutWatch", "gate-api")), want: "crossplane-composed-resources"},
		{name: "crossplane patches an SA owned by something else", user: crossplane, verb: "patch", resource: "serviceaccounts", objName: "x", obj: obj("ServiceAccount", "x", composite, owner("Deployment", "web"))},
		{name: "crossplane patches an SA with no owner", user: crossplane, verb: "patch", resource: "serviceaccounts", objName: "x", obj: obj("ServiceAccount", "x", composite, nil)},
		{name: "crossplane deletes the composed SA", user: crossplane, verb: "delete", resource: "serviceaccounts", objName: "diagnosis-dispatch", obj: obj("ServiceAccount", "diagnosis-dispatch", composite, owner("RolloutWatch", "gate-api"))},
		{name: "another SA patches the composite", user: "system:serviceaccount:default:default", verb: "patch", resource: "rolloutwatches", objName: "gate-api", obj: obj("RolloutWatch", "gate-api", composite, nil)},

		{name: "disruption controller PDB status", user: disrupt, verb: "update", resource: "poddisruptionbudgets", objName: "coredns", sub: "status", ns: "kube-system", want: "disruption-controller-status"},
		{name: "disruption controller PDB body", user: disrupt, verb: "update", resource: "poddisruptionbudgets", objName: "coredns", ns: "kube-system"},
		{name: "disruption controller patch", user: disrupt, verb: "patch", resource: "poddisruptionbudgets", objName: "coredns", sub: "status", ns: "kube-system", oos: true},
		{name: "person writes PDB status", user: "dana@example.com", verb: "update", resource: "poddisruptionbudgets", objName: "coredns", sub: "status", ns: "kube-system"},

		{name: "ESO ExternalSecret status", user: eso, verb: "update", resource: "externalsecrets", objName: "registry-credentials", sub: "status", want: "external-secrets-status"},
		{name: "ESO ExternalSecret status, argocd namespace", user: eso, verb: "update", resource: "externalsecrets", objName: "x", sub: "status", ns: "argocd-apps", want: "external-secrets-status"},
		{name: "ESO ExternalSecret body", user: eso, verb: "update", resource: "externalsecrets", objName: "registry-credentials"},
		{name: "ESO refreshes a Secret", user: eso, verb: "update", resource: "secrets", objName: "registry-credentials", want: "external-secrets-owned-secrets"},
		{name: "ESO creates a Secret, argocd namespace", user: eso, verb: "create", resource: "secrets", objName: "x", ns: "argocd-apps", want: "external-secrets-owned-secrets"},
		{name: "ESO deletes a Secret", user: eso, verb: "delete", resource: "secrets", objName: "registry-credentials"},
		{name: "ESO Secret refused", user: eso, verb: "update", resource: "secrets", objName: "registry-credentials", code: 403},
		{name: "ESO Secret update lost a conflict", user: eso, verb: "update", resource: "secrets", objName: "registry-credentials", code: 409, oos: true},
		{name: "person writes the Secret ESO owns", user: "dana@example.com", verb: "update", resource: "secrets", objName: "registry-credentials"},
		{name: "another SA writes a Secret", user: "system:serviceaccount:default:default", verb: "update", resource: "secrets", objName: "registry-credentials"},
		{name: "ESO ExternalSecret status refused", user: eso, verb: "update", resource: "externalsecrets", objName: "x", sub: "status", code: 403},

		{name: "job controller, the wait Job", user: jobCtl, verb: "update", resource: "jobs", objName: "clearance-awaiting-approval", sub: "status", want: "job-controller-wait-job"},
		{name: "job controller, the wait Job's pod", user: jobCtl, verb: "create", resource: "pods", objName: "clearance-awaiting-approval-mjd76", want: "job-controller-wait-job"},
		{name: "job controller, another Job", user: jobCtl, verb: "update", resource: "jobs", objName: "migrate", sub: "status", oos: true},
		// not the wait Job's noise rule (the name only starts alike), but a Job controller creating a Pod is a child of its Job
		// (scope.controller_children): counted out of scope, not assessed.
		{name: "job controller, a name that only starts alike", user: jobCtl, verb: "create", resource: "pods", objName: "clearance-awaiting-approvals", oos: true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.code == 0 {
				tc.code = 200
			}
			space := tc.ns
			if space == "" {
				space = ns
			}
			m := map[string]any{"auditID": fmt.Sprintf("n%d", i), "stage": "ResponseComplete", "verb": tc.verb, "level": "Metadata",
				"stageTimestamp": "2026-11-10T21:12:23Z", "user": map[string]any{"username": tc.user},
				"objectRef":      map[string]any{"resource": tc.resource, "namespace": space, "name": tc.objName, "subresource": tc.sub},
				"responseStatus": map[string]any{"code": tc.code}}
			if tc.obj != nil {
				m["level"], m["responseObject"] = "RequestResponse", tc.obj
				if md, ok := tc.obj["metadata"].(map[string]any); ok {
					md["namespace"] = space
				}
			}
			raw, _ := json.Marshal(m)
			a, disp, rule, err := pipeline.New(rs, nil, vocab.Default()).Process(pipeline.RawEvent{Provider: pipeline.Kubernetes, Scope: "hangar-prod", Raw: raw})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want != "" {
				if disp != pipeline.Filtered || rule != tc.want {
					t.Fatalf("got %v %q (%+v), want filtered under %s", disp, rule, a, tc.want)
				}
				return
			}
			if tc.oos {
				if disp != pipeline.OutOfScope {
					t.Fatalf("got %v %q, want counted as out of scope: a controller's status write is not a change", disp, rule)
				}
				return
			}
			if disp != pipeline.Assessed {
				t.Fatalf("got %v %q, want an assessment: this shape is not noise", disp, rule)
			}
		})
	}
	// every new rule says why, and loads as exact (no pattern, no group)
	for _, name := range []string{"calico-cni-pod-status", "clearance-argocd-agent-grants", "crossplane-composite-resources", "crossplane-composed-resources",
		"disruption-controller-status", "external-secrets-status", "external-secrets-owned-secrets", "job-controller-wait-job"} {
		if pipeline.New(rs, nil, vocab.Default()).NoiseWhy(name) == "" {
			t.Errorf("rule %s is missing or has no why", name)
		}
	}
}

// Platform GitOps (G-ARGO-10a) and the deployment's own noise, as Hangar sets them: the instance's subject is in the rule set,
// its Applications' namespace is watched and readable, and an extra noise rule is held to the same validator as the chart's own.
func TestObserveK8sChartPlatformGitopsAndExtraNoise(t *testing.T) {
	const platform = "system:serviceaccount:argocd:argocd-application-controller"
	vals := map[string]any{"rules": map[string]any{
		"platformGitops": map[string]any{"subjects": []string{platform}, "namespaces": []string{"argocd"}},
		"extraNoise": []any{map[string]any{
			"name": "notification-prune", "provider": "kubernetes",
			"why":      "the CronJob removing the notified.notifications.argoproj.io annotation from Rollouts",
			"identity": map[string]any{"subject": "system:serviceaccount:argo-rollouts:notification-prune"},
			"shape":    map[string]any{"kinds": []string{"Rollout"}, "verbs": []string{"patch"}, "namespaces": []string{"app-gate-api-prod"}}}}}}
	vf := filepath.Join(t.TempDir(), "v.yaml")
	b, _ := yaml.Marshal(vals)
	if err := os.WriteFile(vf, b, 0o600); err != nil {
		t.Fatal(err)
	}
	objs := renderObserve(t, "-f", vf)
	doc, _ := get(find(objs, "ConfigMap", "clearance-observe-k8s-rules"), "data", "observe-rules.yaml").(string)
	rs, err := pipeline.Load([]byte(doc))
	if err != nil {
		t.Fatalf("%v\n%s", err, doc)
	}
	if !strings.Contains(doc, `platform_gitops: ["`+platform+`"]`) {
		t.Errorf("the platform instance is not in identities:\n%s", doc)
	}
	args := strings.Join(toStrings(get(container(t, find(objs, "Deployment", "clearance-observe-k8s")), "args")), " ")
	if !strings.Contains(args, "--watch-namespaces=app-gate-api-prod,argocd-apps,argocd ") {
		t.Errorf("the platform Applications' namespace is not watched: %s", args)
	}
	var role obj
	for _, o := range objs {
		if o["kind"] == "Role" && get(o, "metadata", "namespace") == "argocd" {
			role = o
		}
	}
	if role == nil {
		t.Fatal("no watch Role in the platform instance's namespace")
	}
	// the extra rule filters exactly its shape
	ev := func(user, verb, resource string) pipeline.Disposition {
		m := map[string]any{"auditID": "e1", "stage": "ResponseComplete", "verb": verb, "level": "Metadata", "stageTimestamp": "2026-11-10T21:12:23Z",
			"user":           map[string]any{"username": user},
			"objectRef":      map[string]any{"resource": resource, "namespace": "app-gate-api-prod", "name": "web"},
			"responseStatus": map[string]any{"code": 200}}
		raw, _ := json.Marshal(m)
		_, disp, _, err := pipeline.New(rs, nil, vocab.Default()).Process(pipeline.RawEvent{Provider: pipeline.Kubernetes, Scope: "hangar-prod", Raw: raw})
		if err != nil {
			t.Fatal(err)
		}
		return disp
	}
	const pruner = "system:serviceaccount:argo-rollouts:notification-prune"
	if d := ev(pruner, "patch", "rollouts"); d != pipeline.Filtered {
		t.Errorf("the pruner's patch of a Rollout: %v", d)
	}
	for name, d := range map[string]pipeline.Disposition{"delete": ev(pruner, "delete", "rollouts"), "another kind": ev(pruner, "patch", "deployments"),
		"another identity": ev("system:serviceaccount:argo-rollouts:argo-rollouts-x", "patch", "rollouts")} {
		if d != pipeline.Assessed {
			t.Errorf("%s: %v, want assessed", name, d)
		}
	}
	// a rule wider than the validator allows fails the render's load, not silently
	vals["rules"].(map[string]any)["extraNoise"] = []any{map[string]any{"name": "wide", "provider": "kubernetes", "why": "x",
		"identity": map[string]any{"subject": "system:serviceaccount:argo-rollouts:*"},
		"shape":    map[string]any{"kinds": []string{"Rollout"}, "verbs": []string{"patch"}}}}
	b, _ = yaml.Marshal(vals)
	if err := os.WriteFile(vf, b, 0o600); err != nil {
		t.Fatal(err)
	}
	doc, _ = get(find(renderObserve(t, "-f", vf), "ConfigMap", "clearance-observe-k8s-rules"), "data", "observe-rules.yaml").(string)
	if _, err := pipeline.Load([]byte(doc)); !errors.Is(err, pipeline.ErrBlanketNoise) {
		t.Errorf("a pattern identity in extraNoise must be refused: %v", err)
	}
}

// A cluster with no gate has no ClearanceGrant CRD: grants.enabled=false drops the collector's list rule and tells it so; the
// default keeps both.
func TestObserveK8sChartGrantsEnabled(t *testing.T) {
	grantRule := func(objs []obj) bool {
		cr := find(objs, "ClusterRole", "clearance-observe-k8s")
		for _, r := range rulesOf(cr) {
			if slices.Contains(toStrings(get(r, "resources")), "clearancegrants") {
				return true
			}
		}
		return false
	}
	args := func(objs []obj) string {
		return strings.Join(toStrings(get(container(t, find(objs, "Deployment", "clearance-observe-k8s")), "args")), " ")
	}
	on := renderObserve(t)
	if !grantRule(on) || !strings.Contains(args(on), "--grants-enabled=true") {
		t.Errorf("default: rule %v, args %s", grantRule(on), args(on))
	}
	off := renderObserve(t, "--set", "grants.enabled=false")
	if grantRule(off) || !strings.Contains(args(off), "--grants-enabled=false") {
		t.Errorf("grants.enabled=false: rule %v, args %s", grantRule(off), args(off))
	}
}

// The before-state of a pruned Role, RoleBinding or ServiceAccount is what ties a platform Argo CD delete to its Application:
// they are watched (list and watch in each watched namespace, extraNamespaces included), and the kube-system controllers that
// manage the objects they created are in the rule set, which loads.
func TestObserveK8sChartWatchesRBACAndNamesTheControllerChildren(t *testing.T) {
	objs := renderObserve(t, "--set", "watch.extraNamespaces={kube-system}")
	role := find(objs, "Role", "clearance-observe-k8s-watch")
	var seen bool
	for _, r := range rulesOf(role) {
		if get(r, "apiGroups", 0) == "rbac.authorization.k8s.io" {
			seen = slices.Contains(toStrings(get(r, "resources")), "roles") && slices.Contains(toStrings(get(r, "resources")), "rolebindings")
		}
	}
	if !seen {
		t.Errorf("the watch Role does not list roles and rolebindings: %v", rulesOf(role))
	}
	var inKubeSystem bool
	for _, o := range objs {
		if o["kind"] == "Role" && get(o, "metadata", "namespace") == "kube-system" && get(o, "metadata", "name") == "clearance-observe-k8s-watch" {
			inKubeSystem = true
		}
	}
	if !inKubeSystem {
		t.Error("watch.extraNamespaces: no watch Role in kube-system")
	}
	args := strings.Join(toStrings(get(container(t, find(objs, "Deployment", "clearance-observe-k8s")), "args")), " ")
	for _, want := range []string{"rbac.authorization.k8s.io/v1/roles=Role", "rbac.authorization.k8s.io/v1/rolebindings=RoleBinding", "--watch-namespaces=app-gate-api-prod,argocd-apps,kube-system"} {
		if !strings.Contains(args, want) {
			t.Errorf("args lack %s: %s", want, args)
		}
	}
	cm := find(objs, "ConfigMap", "clearance-observe-k8s-rules")
	doc, _ := get(cm, "data", "observe-rules.yaml").(string)
	if _, err := pipeline.Load([]byte(doc)); err != nil {
		t.Fatalf("the rendered rule set does not load: %v", err)
	}
	for _, want := range []string{"system:serviceaccount:kube-system:replicaset-controller", "system:serviceaccount:kube-system:generic-garbage-collector"} {
		if !strings.Contains(doc, want) {
			t.Errorf("controller_children lack %s", want)
		}
	}
	// a child list of the deployment's own replaces the default; a pattern in it fails the load
	good, err := helmObserve(t)
	if err != nil {
		t.Fatal(err)
	}
	if i := strings.Index(good, "observe-rules.yaml: |"); i < 0 {
		t.Fatal("no rules in the render")
	} else if _, err := pipeline.Load([]byte(dedentBlock(good[i+len("observe-rules.yaml: |"):]))); err != nil {
		t.Fatalf("the un-indented default render must load, or the negative below proves nothing: %v", err)
	}
	bad, err := helmObserve(t, "--set-json", `rules.controllerChildren=[{"subject":"system:serviceaccount:kube-system:*","kinds":["Pod"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	if i := strings.Index(bad, "observe-rules.yaml: |"); i < 0 {
		t.Fatal("no rules in the render")
	} else if _, err := pipeline.Load([]byte(dedentBlock(bad[i+len("observe-rules.yaml: |"):]))); err == nil {
		t.Error("a pattern subject in controllerChildren loaded")
	}
}

// dedentBlock is the YAML block scalar that follows "key: |" in a rendered manifest, up to the next document, un-indented.
func dedentBlock(s string) string {
	if i := strings.Index(s, "\n---"); i >= 0 {
		s = s[:i]
	}
	var out []string
	for _, l := range strings.Split(s, "\n") {
		out = append(out, strings.TrimPrefix(l, "    "))
	}
	return strings.Join(out, "\n")
}
