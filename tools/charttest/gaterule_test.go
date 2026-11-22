package charttest

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// W-42: the gate rule's value. Off by default (TestTheAgentChartRendersAsBeforeUnlessTheOptInIsOn's golden is the default
// render); set, a ConfigMap, a read-only mount, the flag, a checksum that rolls the pod, and a state Role that cannot
// write the rule.
func TestTheGateRuleRendersOnlyWhenSet(t *testing.T) {
	objs := renderAgent(t, "-f", "../../charts/clearance-argocd-agent/ci/gaterule-values.yaml")
	cm := find(objs, "ConfigMap", "clearance-argocd-agent-gate-rule")
	if cm == nil {
		t.Fatal("no gate-rule ConfigMap")
	}
	var rule map[string]any
	if err := yaml.Unmarshal([]byte(fmt.Sprint(get(cm, "data", "rule.yaml"))), &rule); err != nil || rule["version"] != 1 {
		t.Fatalf("rule.yaml is the value: %v %v", rule, err)
	}
	d := find(objs, "Deployment", "clearance-argocd-agent")
	var args []string
	for _, a := range get(d, "spec", "template", "spec", "containers", 0, "args").([]any) {
		args = append(args, fmt.Sprint(a))
	}
	for _, want := range []string{"--gate-rule-file=/etc/clearance-gate-rule/rule.yaml", "--gate-exempt-max=2160h", "--gate-release-max=3",
		"--gate-exemption-recheck=5m", "--gate-exemption-recheck-timeout=30s"} {
		if !slices.Contains(args, want) {
			t.Errorf("args %v lack %s", args, want)
		}
	}
	if sum := fmt.Sprint(get(d, "spec", "template", "metadata", "annotations", "clearance.hangar.io/gate-rule-checksum")); len(sum) != 64 {
		t.Errorf("checksum annotation: %q", sum)
	}
	mounts := fmt.Sprint(get(d, "spec", "template", "spec", "containers", 0, "volumeMounts"))
	if !strings.Contains(mounts, "/etc/clearance-gate-rule") || !strings.Contains(mounts, "readOnly:true") {
		t.Errorf("mount: %s", mounts)
	}
	// The checksum follows the value.
	other := renderAgent(t, "-f", "../../charts/clearance-argocd-agent/ci/gaterule-values.yaml", "--set", "gateRule.select[0].projects[0]=other")
	if get(find(other, "Deployment", "clearance-argocd-agent"), "spec", "template", "metadata", "annotations", "clearance.hangar.io/gate-rule-checksum") ==
		get(d, "spec", "template", "metadata", "annotations", "clearance.hangar.io/gate-rule-checksum") {
		t.Error("a changed rule rolls the pod")
	}
	// get and patch only on the state ConfigMap.
	role := find(objs, "Role", "clearance-argocd-agent-state")
	for _, r := range rulesOf(role) {
		names, _ := get(r, "resourceNames").([]any)
		v := fmt.Sprint(verbsOf(r))
		if (v != "[create]" && len(names) == 0) || (len(names) > 0 && (v != "[get patch]" || fmt.Sprint(names) != "[clearance-argocd-agent-state]")) {
			t.Errorf("the state Role could write the rule: %v", r)
		}
	}
	// Default values: none of it.
	def := renderAgent(t, "--set", "optIn.enabled=true")
	if find(def, "ConfigMap", "clearance-argocd-agent-gate-rule") != nil ||
		strings.Contains(fmt.Sprint(get(find(def, "Deployment", "clearance-argocd-agent"), "spec", "template")), "gate-rule") {
		t.Error("an unset gateRule renders something")
	}
}

func TestABadGateRuleFailsTheRender(t *testing.T) {
	dir := t.TempDir()
	for name, c := range map[string]struct{ values, want string }{
		"no opt-in":   {"gateRule: {version: 1, select: [{name: a, projects: [x]}]}\n", "needs optIn.enabled"},
		"version":     {"optIn: {enabled: true}\ngateRule: {version: 2, select: []}\n", "version must be 1"},
		"empty entry": {"optIn: {enabled: true}\ngateRule: {version: 1, select: [{name: all}]}\n", "would match everything"},
		"no name":     {"optIn: {enabled: true}\ngateRule: {version: 1, select: [{projects: [x]}]}\n", "needs a name"},
		"twice":       {"optIn: {enabled: true}\ngateRule: {version: 1, select: [{name: a, projects: [x]}, {name: a, projects: [y]}]}\n", "named twice"},
		"no expiry":   {"optIn: {enabled: true}\ngateRule: {version: 1, exempt: [{application: a/b, reason: a long enough reason}]}\n", "needs application, reason and expires"},
		"short":       {"optIn: {enabled: true}\ngateRule: {version: 1, exempt: [{application: a/b, reason: short, expires: '2026-12-01'}]}\n", "10 to 500"},
	} {
		f := dir + "/" + strings.ReplaceAll(name, " ", "-") + ".yaml"
		if err := os.WriteFile(f, []byte(c.values), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := helmAgent(t, "-f", f)
		if err == nil || !strings.Contains(out, c.want) {
			t.Errorf("%s: %v %s", name, err, out)
		}
	}
}
