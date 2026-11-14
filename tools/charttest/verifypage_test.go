package charttest

import (
	"slices"
	"strings"
	"testing"
)

// The hosted verify page (P-3) is off unless verifyPage.enabled: no port, no Service, no route, no policy rule and no listener
// setting render for it. Enabling is the one value; its hostname and parents have no default, and nothing rendered is a lab
// value.
func TestTheVerifyPageIsOffByDefaultAndRendersNothing(t *testing.T) {
	for _, vf := range []string{"minimal-values.yaml", "full-values.yaml", "slack-values.yaml", "grc-values.yaml"} {
		text, err := helm(t, "-f", valuesFile(vf))
		if err != nil {
			t.Fatalf("%s: %v\n%s", vf, err, text)
		}
		for _, banned := range []string{"CLEARANCE_VERIFY", "CLEARANCE_STATEMENT", "core-verify", "clearance-verify", "verify-config", "containerPort: 8081"} {
			if strings.Contains(text, banned) {
				t.Errorf("%s renders %q with verifyPage off", vf, banned)
			}
		}
	}
}

func TestTheVerifyPageRendersOnItsOwnPortRouteAndPolicy(t *testing.T) {
	objs := render(t, "-f", valuesFile("verify-values.yaml"))
	for _, want := range []string{"Service/t-clearance-core-verify", "HTTPRoute/t-clearance-verify", "NetworkPolicy/t-clearance-verify", "ConfigMap/t-clearance-core-verify"} {
		if !slices.Contains(kinds(objs), want) {
			t.Errorf("not rendered: %s (have %v)", want, kinds(objs))
		}
	}
	d := find(objs, "Deployment", "t-clearance-core")
	if d == nil {
		t.Fatal("no core Deployment")
	}
	c := get(d, "spec", "template", "spec", "containers", 0)
	var ports []string
	for _, p := range get(c, "ports").([]any) {
		ports = append(ports, get(p, "name").(string))
	}
	if !slices.Equal(ports, []string{"http", "verify"}) {
		t.Errorf("the core's ports: %v", ports)
	}
	env := map[string]string{}
	for _, e := range get(c, "env").([]any) {
		if v, ok := get(e, "value").(string); ok {
			env[get(e, "name").(string)] = v
		}
	}
	if env["CLEARANCE_VERIFY_LISTEN"] != ":8081" || env["CLEARANCE_STATEMENT_INDEPENDENT_WITNESSES"] != "example-independent-witness" || env["CLEARANCE_STATEMENT_LOG_KEYS_FILE"] == "" {
		t.Errorf("env: %v", env)
	}
	// The route reaches only the page's own paths, on the one hostname given; never the API's port.
	r := find(objs, "HTTPRoute", "t-clearance-verify")
	if get(r, "spec", "hostnames", 0) != "verify.example.com" {
		t.Errorf("hostnames: %v", get(r, "spec", "hostnames"))
	}
	if get(r, "spec", "rules", 0, "matches", 0, "path", "value") != "/s/" || get(r, "spec", "rules", 0, "backendRefs", 0, "name") != "t-clearance-core-verify" || get(r, "spec", "rules", 0, "backendRefs", 0, "port") != 8081 {
		t.Errorf("rule: %v", get(r, "spec", "rules"))
	}
	// The policy opens the verify port to the Gateway only, and is ingress only.
	np := find(objs, "NetworkPolicy", "t-clearance-verify")
	if get(np, "spec", "ingress", 0, "ports", 0, "port") != 8081 || get(np, "spec", "ingress", 0, "from", 0, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "gateway-system" {
		t.Errorf("policy: %v", get(np, "spec"))
	}
	assertHardened(t, objs)
	text, _ := helm(t, "-f", valuesFile("verify-values.yaml"))
	for _, banned := range []string{"hostAliases", ".local", "192.168.", "10.0.", "hangar"} {
		if strings.Contains(text, banned) {
			t.Errorf("the render carries %q", banned)
		}
	}
}

func TestTheVerifyPageRefusesToRenderWithoutItsHostnameParentsAndPolicyPeers(t *testing.T) {
	base := []string{"-f", valuesFile("verify-values.yaml")}
	for name, args := range map[string][]string{
		"no hostname":     {"--set", "verifyPage.httpRoute.hostnames=null"},
		"no parents":      {"--set", "verifyPage.httpRoute.parentRefs=null"},
		"no policy peers": {"--set", "verifyPage.networkPolicy.from=null"},
		"http public URL": {"--set", "verifyPage.publicURL=http://verify.example.com"},
	} {
		if text, err := helm(t, append(slices.Clone(base), args...)...); err == nil {
			t.Errorf("%s rendered:\n%s", name, text)
		}
	}
}
