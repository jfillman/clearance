package charttest

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// clearance-grc (P-4): off unless enabled, one hardened replica with its secret as a file, a notifier of the api and a
// provider of the core for its own two record kinds alone, with no Postgres access and no ingress.
func TestGRCIsOffByDefault(t *testing.T) {
	for _, o := range render(t, "-f", valuesFile("minimal-values.yaml")) {
		if strings.Contains(get(o, "metadata", "name").(string), "grc") {
			t.Errorf("minimal values render %v/%v", o["kind"], get(o, "metadata", "name"))
		}
	}
	// and nothing of it leaks into the core's or the api's configuration
	objs := render(t, "-f", valuesFile("minimal-values.yaml"))
	for _, n := range []string{"t-clearance-core", "t-clearance-api"} {
		if d := find(objs, "Deployment", n); d != nil {
			for k, v := range env(container(t, d)) {
				if strings.Contains(v, "grc") {
					t.Errorf("%s: %s=%s names grc with grc off", n, k, v)
				}
			}
		}
	}
}

func TestGRCRendersHardenedWithItsSecretAsAFile(t *testing.T) {
	objs := render(t, "-f", valuesFile("grc-values.yaml"))
	assertHardened(t, objs)
	for _, want := range []string{"Deployment/t-clearance-grc", "ServiceAccount/t-clearance-grc", "NetworkPolicy/t-clearance-grc"} {
		if !slices.Contains(kinds(objs), want) {
			t.Errorf("not rendered: %s", want)
		}
	}
	d := find(objs, "Deployment", "t-clearance-grc")
	// liveness is the process, readiness is the loops: a vendor outage must not restart the pod
	if get(container(t, d), "livenessProbe", "httpGet", "path") != "/healthz" || get(container(t, d), "readinessProbe", "httpGet", "path") != "/readyz" {
		t.Errorf("probes: %v %v", get(container(t, d), "livenessProbe"), get(container(t, d), "readinessProbe"))
	}
	if get(d, "spec", "replicas") != 1 || get(d, "spec", "template", "spec", "automountServiceAccountToken") != false {
		t.Errorf("one replica, no API token: %v", get(d, "spec"))
	}
	c := container(t, d)
	if c["image"] != "ghcr.io/jfillman/clearance-grc:v0.0.0-dev" {
		t.Errorf("image %v", c["image"])
	}
	e := env(c)
	for k, v := range e {
		if strings.Contains(k, "SECRET") || strings.Contains(k, "TOKEN") {
			if !strings.HasSuffix(k, "_FILE") || !strings.HasPrefix(v, "/etc/clearance-grc/secrets/") && !strings.HasPrefix(v, "/var/run/secrets/tokens/") {
				t.Errorf("%s=%s is not a mounted file", k, v)
			}
		}
	}
	for k, want := range map[string]string{"CLEARANCE_GRC_TARGET": "vanta", "CLEARANCE_GRC_VANTA_BASE_URL": "https://api.vanta.com",
		"CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE": "/etc/clearance-grc/secrets/client-secret", "CLEARANCE_GRC_LINK_BASE": "https://clearance.example.com",
		"CLEARANCE_GRC_ENVS": "prod", "CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID": "res-evidence", "CLEARANCE_GRC_VANTA_REPORT_RESOURCE_ID": "res-report",
		"CLEARANCE_API_URL": "http://t-clearance-api.clearance.svc:8080", "CLEARANCE_URL": "http://t-clearance-core.clearance.svc:8080"} {
		if e[k] != want {
			t.Errorf("%s = %q, want %q", k, e[k], want)
		}
	}
}

func TestGRCIsANotifierAndAProviderOfOneKindPairOnly(t *testing.T) {
	objs := render(t, "-f", valuesFile("grc-values.yaml"))
	if got := env(container(t, find(objs, "Deployment", "t-clearance-api")))["CLEARANCE_API_NOTIFIERS"]; got != "tower/backstage,clearance/t-clearance-grc" {
		t.Errorf("api notifiers %q", got)
	}
	// not a delegate (it acts for nobody) and not an observation reader
	if got := env(container(t, find(objs, "Deployment", "t-clearance-api")))["CLEARANCE_API_OBSERVATION_READERS"]; strings.Contains(got, "grc") {
		t.Errorf("observation readers %q", got)
	}
	if got := env(container(t, find(objs, "Deployment", "t-clearance-core")))["CLEARANCE_DELEGATES"]; strings.Contains(got, "grc") {
		t.Errorf("delegates %q", got)
	}
	var ps []map[string]any
	if err := json.Unmarshal([]byte(env(container(t, find(objs, "Deployment", "t-clearance-core")))["CLEARANCE_PROVIDERS"]), &ps); err != nil || len(ps) != 1 {
		t.Fatalf("providers: %v %v", err, ps)
	}
	p := ps[0]
	if p["name"] != "clearance-grc" || len(p["principals"].([]any)) != 1 || p["principals"].([]any)[0] != "clearance/t-clearance-grc" ||
		len(p["kinds"].([]any)) != 2 || p["kinds"].([]any)[0] != "grc.push" || p["kinds"].([]any)[1] != "grc.report" {
		t.Errorf("provider %v", p)
	}
	// providers the operator set stay, and grc is added after them
	objs = render(t, "-f", valuesFile("grc-values.yaml"), "--set-json", `providers=[{"name":"x","version":"1","principals":["a/b"]}]`)
	if err := json.Unmarshal([]byte(env(container(t, find(objs, "Deployment", "t-clearance-core")))["CLEARANCE_PROVIDERS"]), &ps); err != nil || len(ps) != 2 {
		t.Errorf("providers with one set: %v %v", err, ps)
	}
}

func TestGRCNetworkPolicy(t *testing.T) {
	objs := render(t, "-f", valuesFile("grc-values.yaml"))
	np := find(objs, "NetworkPolicy", "t-clearance-grc")
	if in, _ := get(np, "spec", "ingress").([]any); len(in) != 0 {
		t.Errorf("ingress %v", in)
	}
	var core, api, hub bool
	for _, r := range get(np, "spec", "egress").([]any) {
		for _, p := range get(r, "to").([]any) {
			core = core || get(p, "podSelector", "matchLabels", "app.kubernetes.io/component") == "core"
			api = api || get(p, "podSelector", "matchLabels", "app.kubernetes.io/component") == "api"
			hub = hub || get(p, "ipBlock", "cidr") == "0.0.0.0/0"
		}
	}
	if !core || !api || !hub {
		t.Errorf("egress core %v api %v hub %v", core, api, hub)
	}
	// no Postgres rule, with or without cnpg: the push keeps no state
	for _, extra := range [][]string{nil, {"--set", "cnpg.enabled=true"}, {"--set-json", `networkPolicy.postgres.to=[{"ipBlock":{"cidr":"10.1.0.0/16"}}]`}} {
		np := find(render(t, append([]string{"-f", valuesFile("grc-values.yaml")}, extra...)...), "NetworkPolicy", "t-clearance-grc")
		for _, r := range get(np, "spec", "egress").([]any) {
			for _, p := range get(r, "ports").([]any) {
				if get(p, "port") == 5432 || get(p, "port") == float64(5432) {
					t.Errorf("the grc policy has a Postgres rule with %v", extra)
				}
			}
			for _, p := range get(r, "to").([]any) {
				if get(p, "podSelector", "matchLabels", "cnpg.io/cluster") != nil {
					t.Errorf("the grc policy reaches the database pods with %v", extra)
				}
			}
		}
	}
	// the hub's egress is any public host on 443 by default, and the pinned addresses when given
	pinned := find(render(t, "-f", valuesFile("grc-values.yaml"), "--set-json", `networkPolicy.grc.cidrs=["203.0.113.0/24"]`), "NetworkPolicy", "t-clearance-grc")
	var pin, open bool
	for _, r := range get(pinned, "spec", "egress").([]any) {
		for _, p := range get(r, "to").([]any) {
			pin = pin || get(p, "ipBlock", "cidr") == "203.0.113.0/24"
			open = open || get(p, "ipBlock", "cidr") == "0.0.0.0/0"
		}
	}
	if !pin || open {
		t.Errorf("pinned: cidr %v, still open to the internet %v", pin, open)
	}
	for _, name := range []string{"t-clearance-core", "t-clearance-api"} {
		var found bool
		for _, f := range get(find(objs, "NetworkPolicy", name), "spec", "ingress", 0, "from").([]any) {
			found = found || get(f, "podSelector", "matchLabels", "app.kubernetes.io/component") == "grc"
		}
		if !found {
			t.Errorf("%s does not accept the grc pod", name)
		}
	}
}

func TestGRCRefusals(t *testing.T) {
	base := []string{"-f", valuesFile("grc-values.yaml")}
	for name, tc := range map[string]struct{ set, want string }{
		"no secret":      {"grc.existingSecret=", "grc.existingSecret is required"},
		"no link base":   {"grc.linkBase=", "grc.linkBase is required"},
		"http link base": {"grc.linkBase=http://c.example", "grc.linkBase is an https URL"},
		"http hub":       {"grc.vanta.baseUrl=http://api.vanta.com", "grc.vanta.baseUrl is an https URL"},
		"no client id":   {"grc.vanta.clientId=", "grc.vanta.clientId is required"},
		"no resource":    {"grc.vanta.evidenceResourceId=", "grc.vanta.evidenceResourceId is required"},
		"no api":         {"api.enabled=false", "grc.enabled needs api.enabled"},
		"a bad digest":   {"grc.image.digest=latest", "grc.image.digest is sha256"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := helm(t, append(slices.Clone(base), "--set", tc.set)...)
			if err == nil {
				t.Fatalf("rendered; want a refusal mentioning %q", tc.want)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("refused with %q; want %q", out, tc.want)
			}
		})
	}
}
