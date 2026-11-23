package charttest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const agentChartDir = "../../charts/clearance-argocd-agent"

// helmAgent renders charts/clearance-argocd-agent over testdata/argocd-agent-values.yaml (example names only) and args.
func helmAgent(t *testing.T, args ...string) (string, error) {
	t.Helper()
	bin, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not on PATH")
	}
	var out, errb bytes.Buffer
	cmd := exec.Command(bin, append([]string{"template", "t", agentChartDir, "--namespace", "clearance-system",
		"-f", "testdata/argocd-agent-values.yaml"}, args...)...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return errb.String(), err
	}
	return out.String(), nil
}

func renderAgent(t *testing.T, args ...string) []obj {
	t.Helper()
	text, err := helmAgent(t, args...)
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

// decode reads a render's documents into a map keyed by kind and name.
func decodeDocs(t *testing.T, text string) map[string]obj {
	t.Helper()
	out := map[string]obj{}
	dec := yaml.NewDecoder(strings.NewReader(text))
	for {
		var o obj
		if err := dec.Decode(&o); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decoding a render: %v", err)
		}
		if o == nil {
			continue
		}
		k := fmt.Sprint(o["kind"], "/", get(o, "metadata", "namespace"), "/", get(o, "metadata", "name"))
		if _, dup := out[k]; dup {
			t.Fatalf("%s is rendered twice", k)
		}
		out[k] = o
	}
	return out
}

// An install that does not turn the opt-in on renders what charts/clearance-argocd-agent on main (2b3d6b7, before
// G-ARGO-10c) rendered over the same values: the golden file is that render. The comparison is of the decoded
// documents, not of bytes, because the order of the documents is Helm's and differs between Helm releases (the byte
// comparison, run by hand with Helm v3.21.3, was equal). Both sides are non-empty, so two renders that failed alike
// cannot pass.
func TestTheAgentChartRendersAsBeforeUnlessTheOptInIsOn(t *testing.T) {
	golden, err := os.ReadFile("testdata/argocd-agent-main.golden.yaml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := helmAgent(t)
	if err != nil {
		t.Fatalf("%v\n%s", err, got)
	}
	want, have := decodeDocs(t, string(golden)), decodeDocs(t, got)
	if len(want) < 8 || len(have) < 8 {
		t.Fatalf("a render is empty or not the chart's: golden %d documents, got %d", len(want), len(have))
	}
	for _, k := range []string{"Deployment/<nil>/clearance-argocd-agent", "ClusterRole/<nil>/clearance-argocd-agent", "Role/argocd/clearance-argocd-agent-applications"} {
		if want[k] == nil || have[k] == nil {
			t.Fatalf("%s is missing from a render", k)
		}
	}
	for k, w := range want {
		if h, ok := have[k]; !ok {
			t.Errorf("%s is in main's render and not in the default one", k)
		} else if !reflect.DeepEqual(w, h) {
			t.Errorf("%s differs from main's", k)
		}
	}
	for k := range have {
		if _, ok := want[k]; !ok {
			t.Errorf("%s is in the default render and not in main's", k)
		}
	}
	// Explicitly off is the same as unset.
	off, err := helmAgent(t, "--set", "optIn.enabled=false")
	if err != nil || !reflect.DeepEqual(decodeDocs(t, off), have) {
		t.Fatalf("optIn.enabled=false renders differently from the default: %v", err)
	}
	// The comparison can see a difference: with the opt-in on the render is not main's.
	on, err := helmAgent(t, "--set", "optIn.enabled=true")
	if err != nil || reflect.DeepEqual(decodeDocs(t, on), want) {
		t.Fatalf("the opt-in render equals main's, so this comparison proves nothing: %v", err)
	}
	for _, no := range []string{"--optin", "applicationsets", "resourceNames", "watch, patch"} {
		if strings.Contains(got, no) {
			t.Errorf("the default render has %q", no)
		}
	}
}

func verbsOf(rule any) []string {
	var out []string
	l, _ := get(rule, "verbs").([]any)
	for _, v := range l {
		out = append(out, fmt.Sprint(v))
	}
	return out
}

func TestTheOptInsRBACIsTheNarrowestItNeeds(t *testing.T) {
	objs := renderAgent(t, "--set", "optIn.enabled=true")
	d := find(objs, "Deployment", "clearance-argocd-agent")
	args, _ := get(d, "spec", "template", "spec", "containers", 0, "args").([]any)
	var as []string
	for _, a := range args {
		as = append(as, fmt.Sprint(a))
	}
	for _, want := range []string{"--optin", "--optin-plugin-name=clearance", "--optin-deny=clearance,clearance-*,*-clearance",
		"--optin-namespaces=app-web-prod,app-api-prod", "--optin-interval=30s", "--optin-report-every=5m", "--optin-max-grant-bytes=1500000"} {
		if !slices.Contains(as, want) {
			t.Errorf("args %v lack %s", as, want)
		}
	}
	// Cluster scope: the namespaces the operator named, get and patch, and nothing wider.
	cr := find(objs, "ClusterRole", "clearance-argocd-agent")
	var nsRules int
	for _, r := range rulesOf(cr) {
		res, _ := get(r, "resources").([]any)
		if !slices.Contains(res, any("namespaces")) {
			continue
		}
		nsRules++
		v := verbsOf(r)
		names, _ := get(r, "resourceNames").([]any)
		if len(names) == 0 {
			if fmt.Sprint(v) != "[list]" {
				t.Errorf("an unnamed namespaces rule may only list: %v", v)
			}
			continue
		}
		if fmt.Sprint(v) != "[get patch]" || fmt.Sprint(names) != "[app-web-prod app-api-prod]" {
			t.Errorf("namespaces rule: verbs %v names %v; want get and patch on the two named namespaces only", v, names)
		}
	}
	// And the one CRD it reads, get only.
	crd := 0
	for _, r := range rulesOf(cr) {
		if res, _ := get(r, "resources").([]any); slices.Contains(res, any("customresourcedefinitions")) {
			crd++
			if fmt.Sprint(verbsOf(r)) != "[get]" || fmt.Sprint(get(r, "resourceNames")) != "[clearancegrants.clearance.hangar.io]" {
				t.Errorf("the CRD rule: %v", r)
			}
		}
	}
	if crd != 1 {
		t.Errorf("%d CRD rules", crd)
	}
	if nsRules != 2 {
		t.Errorf("%d namespaces rules, want the existing list and the named get/patch", nsRules)
	}
	// Applications: patch is the only write, and only on applications; applicationsets are read.
	role := find(objs, "Role", "clearance-argocd-agent-applications")
	for _, r := range rulesOf(role) {
		res, _ := get(r, "resources").([]any)
		v := verbsOf(r)
		switch fmt.Sprint(res) {
		case "[applications]":
			if fmt.Sprint(v) != "[get list watch patch]" {
				t.Errorf("applications: %v", v)
			}
		case "[applicationsets]":
			if fmt.Sprint(v) != "[get]" {
				t.Errorf("applicationsets: %v", v)
			}
		default:
			t.Errorf("an unexpected rule in the Applications role: %v", r)
		}
	}
	// No rule anywhere grants a Secret, a wildcard, update or create of an Application, or delete of anything but grants.
	for _, o := range objs {
		if o["kind"] != "Role" && o["kind"] != "ClusterRole" {
			continue
		}
		for _, r := range rulesOf(o) {
			res := fmt.Sprint(get(r, "resources"))
			v := verbsOf(r)
			if strings.Contains(res, "secrets") || strings.Contains(res, "*") || slices.Contains(v, "*") {
				t.Errorf("%v: %v", get(o, "metadata", "name"), r)
			}
			if res == "[applications]" && (slices.Contains(v, "update") || slices.Contains(v, "create") || slices.Contains(v, "delete")) {
				t.Errorf("applications: %v", v)
			}
			if slices.Contains(v, "delete") && res != "[clearancegrants]" {
				t.Errorf("delete on %s", res)
			}
		}
	}
}

func TestTheOptInIsRefusedWithoutNamedNamespaces(t *testing.T) {
	text, err := helmAgent(t, "--set", "optIn.enabled=true", "--set", "protectedNamespaces=null")
	if err == nil || !strings.Contains(text, "optIn.enabled needs protectedNamespaces") {
		t.Fatalf("rendered without the namespaces the agent may label: %v\n%s", err, text)
	}
}

func TestTheOptInDenyListIsNotLabSpecific(t *testing.T) {
	b, err := os.ReadFile(agentChartDir + "/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"192.168.", ".local", "hangar-", "hangar_"} {
		for i, l := range strings.Split(string(b), "\n") {
			if strings.Contains(l, bad) && !strings.HasPrefix(strings.TrimSpace(l), "#") {
				t.Errorf("values.yaml:%d has %q: %s", i+1, bad, l)
			}
		}
	}
	objs := renderAgent(t, "--set", "optIn.enabled=true", "--set", "optIn.denyApplications={}")
	d := find(objs, "Deployment", "clearance-argocd-agent")
	args := fmt.Sprint(get(d, "spec", "template", "spec", "containers", 0, "args"))
	if !strings.Contains(args, "--optin-deny=") || strings.Contains(args, "--optin-deny=clearance") {
		t.Errorf("an empty deny list is passed as empty: %s", args)
	}
}

// scope: cluster (W-41): no per-namespace Roles, one ClusterRole and ClusterRoleBinding for the workload reads, and (opt-in)
// get and patch on Namespaces with no resourceNames. The default scope renders exactly as before (the golden test above).
func TestClusterScopeGrantsTheSameVerbsThroughClusterRoles(t *testing.T) {
	objs := renderAgent(t, "--set", "scope=cluster", "--set", "protectedNamespaces=null", "--set", "optIn.enabled=true")
	for _, o := range objs {
		if o["kind"] == "Role" && get(o, "metadata", "namespace") != "argocd" && get(o, "metadata", "namespace") != nil {
			t.Errorf("cluster scope still renders a per-namespace Role: %v", get(o, "metadata", "name"))
		}
	}
	// The scan ClusterRole has the very rules the per-namespace scan Role has.
	namespaced := renderAgent(t)
	wantRules := rulesOf(find(namespaced, "Role", "clearance-argocd-agent-scan"))
	scan := find(objs, "ClusterRole", "clearance-argocd-agent-scan")
	if len(wantRules) == 0 || !reflect.DeepEqual(rulesOf(scan), wantRules) {
		t.Errorf("the scan ClusterRole's rules differ from the scan Role's:\n%v\n%v", rulesOf(scan), wantRules)
	}
	crb := find(objs, "ClusterRoleBinding", "clearance-argocd-agent-scan")
	if fmt.Sprint(get(crb, "roleRef", "kind"), "/", get(crb, "roleRef", "name")) != "ClusterRole/clearance-argocd-agent-scan" {
		t.Errorf("the scan ClusterRoleBinding: %v", crb)
	}
	// Namespaces: the unnamed list, and get/patch with no resourceNames, and nothing else (no create, update, delete, watch).
	cr := find(objs, "ClusterRole", "clearance-argocd-agent")
	var verbs []string
	for _, r := range rulesOf(cr) {
		if res, _ := get(r, "resources").([]any); slices.Contains(res, any("namespaces")) {
			if get(r, "resourceNames") != nil {
				t.Errorf("a namespaces rule has resourceNames in cluster scope: %v", r)
			}
			verbs = append(verbs, verbsOf(r)...)
		}
	}
	slices.Sort(verbs)
	if fmt.Sprint(verbs) != "[get list patch]" {
		t.Errorf("namespaces verbs %v, want get, list, patch", verbs)
	}
	// The agent's own args: every namespace is configured; the projects limit is unchanged.
	d := find(objs, "Deployment", "clearance-argocd-agent")
	args, _ := get(d, "spec", "template", "spec", "containers", 0, "args").([]any)
	if !slices.Contains(args, any("--optin-namespaces=*")) || !slices.Contains(args, any("--projects=tenants")) {
		t.Errorf("args %v", args)
	}
}

func TestClusterScopeWithoutTheOptInHasNoNamespaceWrite(t *testing.T) {
	objs := renderAgent(t, "--set", "scope=cluster", "--set", "protectedNamespaces=null")
	for _, r := range rulesOf(find(objs, "ClusterRole", "clearance-argocd-agent")) {
		if res, _ := get(r, "resources").([]any); slices.Contains(res, any("namespaces")) && fmt.Sprint(verbsOf(r)) != "[list]" {
			t.Errorf("namespaces rule %v", r)
		}
	}
}

func TestClusterScopeIsRefusedWithAListOrABadValue(t *testing.T) {
	text, err := helmAgent(t, "--set", "scope=cluster")
	if err == nil || !strings.Contains(text, "scope: cluster takes no protectedNamespaces") {
		t.Fatalf("cluster scope rendered with a list: %v\n%s", err, text)
	}
	text, err = helmAgent(t, "--set", "scope=everything")
	if err == nil || !strings.Contains(text, "scope must be namespaces or cluster") {
		t.Fatalf("a bad scope rendered: %v\n%s", err, text)
	}
}

// I-43: the CA is opt-in. With no tls.caConfigMap and no waitJob.caConfigMap the render has no CA mount, setting or flag;
// with them the agent reads CLEARANCE_CA_FILE and tells the wait Job's validator which ConfigMap to expect.
func TestTheAgentChartCAIsOptIn(t *testing.T) {
	off, err := helmAgent(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"CLEARANCE_CA_FILE", "clearance-ca", "wait-ca-configmap"} {
		if strings.Contains(off, s) {
			t.Errorf("CA off but the render has %q", s)
		}
	}
	on, err := helmAgent(t, "--set", "tls.caConfigMap=clearance-ca", "--set", "waitJob.caConfigMap=clearance-ca")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"name: CLEARANCE_CA_FILE, value: /etc/clearance-ca/ca.crt", "--wait-ca-configmap=clearance-ca",
		"mountPath: /etc/clearance-ca, readOnly: true", "items: [{key: ca.crt, path: ca.crt}]"} {
		if !strings.Contains(on, s) {
			t.Errorf("CA on but the render lacks %q", s)
		}
	}
}

// I-59: waitJob.previousImage is opt-in. Unset, the render has no previous-image flag; set, the agent gets it.
func TestTheAgentChartPreviousWaitImageIsOptIn(t *testing.T) {
	off, err := helmAgent(t, "--set", "waitJob.image=registry.example.test/wait@sha256:00")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(off, "wait-previous-image") {
		t.Error("previousImage unset but the render has the flag")
	}
	on, err := helmAgent(t, "--set", "waitJob.image=registry.example.test/wait@sha256:00",
		"--set", "waitJob.previousImage=registry.example.test/wait@sha256:11")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"--wait-image=registry.example.test/wait@sha256:00", "--wait-previous-image=registry.example.test/wait@sha256:11"} {
		if !strings.Contains(on, s) {
			t.Errorf("previousImage set but the render lacks %q", s)
		}
	}
}
