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
		"no hostname":                 {"--set", "verifyPage.httpRoute.hostnames=null"},
		"no parents":                  {"--set", "verifyPage.httpRoute.parentRefs=null"},
		"no policy peers":             {"--set", "verifyPage.networkPolicy.from=null"},
		"http public URL":             {"--set", "verifyPage.publicURL=http://verify.example.com"},
		"hops 0 behind a gateway":     {"--set", "verifyPage.limits.trustedProxyHops=0"},
		"hops with no network policy": {"--set", "networkPolicy.enabled=false"},
		"direct exposure with hops":   {"--set", "verifyPage.directExposure=true"},
	} {
		if text, err := helm(t, append(slices.Clone(base), args...)...); err == nil {
			t.Errorf("%s rendered:\n%s", name, text)
		}
	}
}

// Behind a Gateway the client is the address the Gateway saw, so the chart needs a trusted hop count of at least 1 and a
// NetworkPolicy that leaves the pod reachable from the Gateway alone; a direct listener says so, with no hops. Both ways render.
func TestTheVerifyPageClientAddressSettingsRenderBothWays(t *testing.T) {
	env := func(objs []obj) map[string]string {
		out := map[string]string{}
		for _, o := range objs {
			if o["kind"] != "Deployment" || get(o, "metadata", "name") != "t-clearance-core" {
				continue
			}
			for _, e := range get(o, "spec", "template", "spec", "containers", 0, "env").([]any) {
				if v, ok := get(e, "value").(string); ok {
					out[get(e, "name").(string)] = v
				}
			}
		}
		return out
	}
	e := env(render(t, "-f", valuesFile("verify-values.yaml")))
	if e["CLEARANCE_VERIFY_TRUSTED_PROXY_HOPS"] != "1" || e["CLEARANCE_VERIFY_DIRECT_EXPOSURE"] != "" {
		t.Errorf("behind a gateway: %v", e)
	}
	e = env(render(t, "-f", valuesFile("verify-values.yaml"), "--set", "verifyPage.directExposure=true", "--set", "verifyPage.limits.trustedProxyHops=0"))
	if e["CLEARANCE_VERIFY_TRUSTED_PROXY_HOPS"] != "0" || e["CLEARANCE_VERIFY_DIRECT_EXPOSURE"] != "true" {
		t.Errorf("direct: %v", e)
	}
}

// A change to the verify page's log keys changes the core pod's template, so the pod restarts and reads the file again.
func TestAChangeToTheVerifyLogKeysRestartsTheCore(t *testing.T) {
	sum := func(keys string) any {
		d := find(render(t, "-f", valuesFile("verify-values.yaml"), "--set", "verifyPage.logKeys="+keys), "Deployment", "t-clearance-core")
		return get(d, "spec", "template", "metadata", "annotations", "checksum/verify-config")
	}
	a, b := sum("example-log+00000000+AAAA"), sum("example-log+00000000+BBBB")
	if a == nil || a == b {
		t.Errorf("%v %v", a, b)
	}
}

// A change to the witness policy the statement checks read also changes the core pod's template: the core reads the policy once, at start.
func TestAChangeToTheWitnessPolicyRestartsTheCoreWhenTheVerifyPageIsOn(t *testing.T) {
	sum := func(policy string) any {
		d := find(render(t, "-f", valuesFile("verify-values.yaml"), "--set", "ledger.enabled=true", "--set", "ledger.existingSecret=clearance-ledger",
			"--set", "ledger.witnessPolicy="+policy), "Deployment", "t-clearance-core")
		return get(d, "spec", "template", "metadata", "annotations", "checksum/verify-config")
	}
	a, b := sum("witness a vkey-a https://a.example.com"), sum("witness b vkey-b https://b.example.com")
	if a == nil || a == b {
		t.Errorf("%v %v", a, b)
	}
}
