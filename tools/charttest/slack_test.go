package charttest

import (
	"slices"
	"strings"
	"testing"
)

// clearance-slack: off unless enabled, one hardened replica that holds its secrets as files, a delegate, notifier and
// observation reader of this release's core and api, with its own NetworkPolicy and the core and the api's ingress
// opened to it alone.
func TestSlackIsOffByDefault(t *testing.T) {
	for _, o := range render(t, "-f", valuesFile("minimal-values.yaml")) {
		if strings.Contains(get(o, "metadata", "name").(string), "slack") {
			t.Errorf("minimal values render %v/%v", o["kind"], get(o, "metadata", "name"))
		}
	}
}

func TestSlackRendersHardenedWithItsSecretsAsFiles(t *testing.T) {
	objs := render(t, "-f", valuesFile("slack-values.yaml"))
	assertHardened(t, objs)
	for _, want := range []string{"Deployment/t-clearance-slack", "Service/t-clearance-slack", "ServiceAccount/t-clearance-slack",
		"ConfigMap/t-clearance-slack-routes", "NetworkPolicy/t-clearance-slack", "HTTPRoute/t-clearance-slack"} {
		if !slices.Contains(kinds(objs), want) {
			t.Errorf("not rendered: %s", want)
		}
	}
	d := find(objs, "Deployment", "t-clearance-slack")
	if get(d, "spec", "replicas") != 1 || get(d, "spec", "strategy", "type") != "Recreate" || get(d, "spec", "template", "spec", "automountServiceAccountToken") != false {
		t.Errorf("one replica, Recreate, no API token: %v", get(d, "spec"))
	}
	c := container(t, d)
	if c["image"] != "ghcr.io/jfillman/clearance-slack:v0.0.0-dev" {
		t.Errorf("image %v", c["image"])
	}
	e := env(c)
	// every secret is a file; no env var holds one (a value of an env var is visible in the pod spec)
	for k, v := range e {
		if strings.Contains(k, "TOKEN") || strings.Contains(k, "SECRET") || strings.Contains(k, "DSN") {
			if !strings.HasSuffix(k, "_FILE") || !strings.HasPrefix(v, "/etc/clearance-slack/secrets/") && !strings.HasPrefix(v, "/var/run/secrets/tokens/") {
				t.Errorf("%s=%s is not a mounted file", k, v)
			}
		}
	}
	for k, want := range map[string]string{"CLEARANCE_SLACK_TRANSPORT": "socket", "CLEARANCE_SLACK_BOT_TOKEN_FILE": "/etc/clearance-slack/secrets/bot-token",
		"CLEARANCE_SLACK_APP_TOKEN_FILE": "/etc/clearance-slack/secrets/app-token", "CLEARANCE_SLACK_CLIENT_SECRET_FILE": "/etc/clearance-slack/secrets/client-secret",
		"CLEARANCE_SLACK_DSN_FILE": "/etc/clearance-slack/secrets/dsn", "CLEARANCE_SLACK_CLEAR_MAX_TIER": "2", "CLEARANCE_OIDC_ISSUER": "https://dex.example.com/dex",
		"CLEARANCE_URL": "http://t-clearance-core.clearance.svc:8080", "CLEARANCE_API_URL": "http://t-clearance-api.clearance.svc:8080",
		"CLEARANCE_SLACK_WEB_URL": "https://clearance.example.com/changes/{id}", "CLEARANCE_SLACK_SA_TOKEN_FILE": "/var/run/secrets/tokens/clearance"} {
		if e[k] != want {
			t.Errorf("%s = %q, want %q", k, e[k], want)
		}
	}
	if _, has := e["CLEARANCE_SLACK_SIGNING_SECRET_FILE"]; has {
		t.Error("the signing secret is the events transport's")
	}
	// the credential at the core is a projected token of the core's audience
	var projected bool
	for _, v := range get(d, "spec", "template", "spec", "volumes").([]any) {
		if get(v, "name") == "clearance-token" && get(v, "projected", "sources", 0, "serviceAccountToken", "audience") == "clearance" {
			projected = true
		}
	}
	if !projected {
		t.Error("no projected service-account token for the core's audience")
	}
}

func TestSlackIsADelegateNotifierAndObserverOfThisRelease(t *testing.T) {
	objs := render(t, "-f", valuesFile("slack-values.yaml"))
	want := "tower/backstage,clearance/t-clearance-slack"
	if got := env(container(t, find(objs, "Deployment", "t-clearance-core")))["CLEARANCE_DELEGATES"]; got != want {
		t.Errorf("core delegates %q", got)
	}
	api := env(container(t, find(objs, "Deployment", "t-clearance-api")))
	if api["CLEARANCE_DELEGATES"] != want || api["CLEARANCE_API_NOTIFIERS"] != want || api["CLEARANCE_API_OBSERVATION_READERS"] != "clearance/t-clearance-slack" {
		t.Errorf("api: %v", api)
	}
	// without slack nothing is added
	if got := env(container(t, find(render(t, "-f", valuesFile("full-values.yaml")), "Deployment", "t-clearance-core")))["CLEARANCE_DELEGATES"]; got != "tower/backstage" {
		t.Errorf("slack off changes the delegates: %q", got)
	}
}

func TestSlackNetworkPolicy(t *testing.T) {
	objs := render(t, "-f", valuesFile("slack-values.yaml"))
	np := find(objs, "NetworkPolicy", "t-clearance-slack")
	if get(np, "spec", "ingress", 0, "from", 0, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "gateway-system" {
		t.Errorf("ingress %v", get(np, "spec", "ingress"))
	}
	egress, _ := get(np, "spec", "egress").([]any)
	var core, slackNet, idp bool
	for _, r := range egress {
		to, _ := get(r, "to").([]any)
		for _, p := range to {
			if get(p, "podSelector", "matchLabels", "app.kubernetes.io/component") == "core" {
				core = true
			}
			if get(p, "ipBlock", "cidr") == "0.0.0.0/0" && slices.Contains(get(p, "ipBlock", "except").([]any), any("10.0.0.0/8")) {
				slackNet = true
			}
			if get(p, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") == "dex" {
				idp = true
			}
		}
	}
	if !core || !slackNet || !idp {
		t.Errorf("egress to the core %v, Slack %v, the IdP %v", core, slackNet, idp)
	}
	// the core and the api accept the slack pod, and only because the service is on
	for _, name := range []string{"t-clearance-core", "t-clearance-api"} {
		var found bool
		for _, f := range get(find(objs, "NetworkPolicy", name), "spec", "ingress", 0, "from").([]any) {
			found = found || get(f, "podSelector", "matchLabels", "app.kubernetes.io/component") == "slack"
		}
		if !found {
			t.Errorf("%s does not accept the slack pod", name)
		}
	}
}

func TestSlackRefusals(t *testing.T) {
	base := []string{"-f", valuesFile("slack-values.yaml")}
	for name, tc := range map[string]struct{ set, want string }{
		"no secret":         {"slack.existingSecret=", "slack.existingSecret is required"},
		"no public url":     {"slack.publicUrl=", "slack.publicUrl is required"},
		"no slack client":   {"slack.slackClientId=", "slack.slackClientId is required"},
		"no idp client":     {"slack.idpClientId=", "slack.idpClientId is required"},
		"no issuer":         {"oidc.issuer=,oidc.audience=", "oidc.issuer is required"},
		"unknown transport": {"slack.transport=smoke", "slack.transport is socket or events"},
		"a tier of 4":       {"slack.clearMaxTier=4", "slack.clearMaxTier is 0 to 3"},
		"a bad digest":      {"slack.image.digest=latest", "slack.image.digest is sha256"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append(slices.Clone(base), "--set", tc.set)
			out, err := helm(t, args...)
			if err == nil {
				t.Fatalf("rendered; want a refusal mentioning %q", tc.want)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("refused with %q; want %q", out, tc.want)
			}
		})
	}
	// the events transport swaps the app token for the signing secret
	e := env(container(t, find(render(t, append(slices.Clone(base), "--set", "slack.transport=events")...), "Deployment", "t-clearance-slack")))
	if e["CLEARANCE_SLACK_SIGNING_SECRET_FILE"] == "" || e["CLEARANCE_SLACK_APP_TOKEN_FILE"] != "" {
		t.Errorf("events transport env: %v", e)
	}
}
