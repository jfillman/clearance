package charttest

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/jfillman/clearance/internal/observe/pipeline"
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
	if rs.Ref.Name != "observe-hangar" || rs.Ref.Version != "2026.11.3" {
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
