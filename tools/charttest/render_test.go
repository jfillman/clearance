// Package charttest holds the render tests of charts/clearance: `helm template` over the values files in
// charts/clearance/ci, with assertions on what each renders and on the values the chart refuses. They need the
// helm binary and skip without it (CI installs it: .github/workflows/chart.yaml).
package charttest

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/jfillman/clearance/internal/bundles"
	"github.com/jfillman/clearance/internal/vocab"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/jfillman/clearance/internal/authn"
)

const chartDir = "../../charts/clearance"

type obj = map[string]any

func helm(t *testing.T, args ...string) (string, error) {
	t.Helper()
	bin, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not on PATH")
	}
	var out, errb bytes.Buffer
	cmd := exec.Command(bin, append([]string{"template", "t", chartDir, "--namespace", "clearance"}, args...)...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return errb.String(), err
	}
	return out.String(), nil
}

func render(t *testing.T, args ...string) []obj {
	t.Helper()
	text, err := helm(t, args...)
	if err != nil {
		t.Fatalf("helm template %v: %v\n%s", args, err, text)
	}
	dec := yaml.NewDecoder(strings.NewReader(text))
	var out []obj
	for {
		var o obj
		err := dec.Decode(&o)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decoding the render: %v", err)
		}
		if o != nil {
			out = append(out, o)
		}
	}
	return out
}

func get(o any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := o.(obj)
			if !ok {
				return nil
			}
			o = m[k]
		case int:
			l, ok := o.([]any)
			if !ok || k >= len(l) {
				return nil
			}
			o = l[k]
		}
	}
	return o
}

func find(objs []obj, kind, name string) obj {
	for _, o := range objs {
		if o["kind"] == kind && get(o, "metadata", "name") == name {
			return o
		}
	}
	return nil
}

func kinds(objs []obj) []string {
	var out []string
	for _, o := range objs {
		out = append(out, o["kind"].(string)+"/"+get(o, "metadata", "name").(string))
	}
	slices.Sort(out)
	return out
}

func container(t *testing.T, d obj) obj {
	t.Helper()
	c, _ := get(d, "spec", "template", "spec", "containers", 0).(obj)
	if c == nil {
		t.Fatalf("%v has no container", get(d, "metadata", "name"))
	}
	return c
}

// env is the container's env by name: the value, or "secret:<name>/<key>".
func env(c obj) map[string]string {
	out := map[string]string{}
	list, _ := c["env"].([]any)
	for _, e := range list {
		m := e.(obj)
		name := m["name"].(string)
		if v, ok := m["value"].(string); ok {
			out[name] = v
		} else if ref := get(m, "valueFrom", "secretKeyRef"); ref != nil {
			out[name] = "secret:" + get(ref, "name").(string) + "/" + get(ref, "key").(string)
		}
	}
	return out
}

func valuesFile(name string) string { return filepath.Join(chartDir, "ci", name) }

// Every pod the chart renders runs as uid 65532, read-only root, no capabilities, RuntimeDefault seccomp.
func assertHardened(t *testing.T, objs []obj) {
	t.Helper()
	n := 0
	for _, o := range objs {
		var pod any
		switch o["kind"] {
		case "Deployment":
			pod = get(o, "spec", "template", "spec")
		case "Pod":
			pod = get(o, "spec")
		default:
			continue
		}
		n++
		name := get(o, "metadata", "name")
		ps := get(pod, "securityContext")
		if get(ps, "runAsNonRoot") != true || get(ps, "runAsUser") != 65532 || get(ps, "seccompProfile", "type") != "RuntimeDefault" {
			t.Errorf("%v: pod securityContext %v", name, ps)
		}
		for _, c := range get(pod, "containers").([]any) {
			sc := get(c, "securityContext")
			if get(sc, "readOnlyRootFilesystem") != true || get(sc, "allowPrivilegeEscalation") != false ||
				get(sc, "runAsUser") != 65532 || get(sc, "seccompProfile", "type") != "RuntimeDefault" ||
				get(sc, "capabilities", "drop", 0) != "ALL" {
				t.Errorf("%v/%v: container securityContext %v", name, get(c, "name"), sc)
			}
		}
	}
	if n == 0 {
		t.Fatal("no pods rendered")
	}
}

func TestMinimal(t *testing.T) {
	objs := render(t, "-f", valuesFile("minimal-values.yaml"))
	want := []string{
		"ClusterRoleBinding/clearance-t-clearance-auth-delegator",
		"Deployment/t-clearance-api", "Deployment/t-clearance-core",
		"NetworkPolicy/t-clearance-api", "NetworkPolicy/t-clearance-core", "NetworkPolicy/t-clearance-default-deny",
		"NetworkPolicy/t-clearance-test",
		"Pod/t-clearance-chain-verify", "PodDisruptionBudget/t-clearance-api",
		"Service/t-clearance-api", "Service/t-clearance-core",
		"ServiceAccount/t-clearance-api", "ServiceAccount/t-clearance-core",
	}
	if got := kinds(objs); !slices.Equal(got, want) {
		t.Fatalf("rendered\n  %v\nwant\n  %v", got, want)
	}
	assertHardened(t, objs)

	core := find(objs, "Deployment", "t-clearance-core")
	if get(core, "spec", "replicas") != 1 || get(core, "spec", "strategy", "type") != "Recreate" {
		t.Errorf("core: replicas %v strategy %v; want 1, Recreate (one writer)", get(core, "spec", "replicas"),
			get(core, "spec", "strategy", "type"))
	}
	c := container(t, core)
	if c["image"] != "ghcr.io/jfillman/clearance:v0.0.0-dev" || get(c, "args", 0) != "core" {
		t.Errorf("core: image %v args %v", c["image"], c["args"])
	}
	e := env(c)
	if e["CLEARANCE_DSN"] != "secret:clearance-db/uri" {
		t.Errorf("core: CLEARANCE_DSN %q", e["CLEARANCE_DSN"])
	}
	for _, unset := range []string{"CLEARANCE_PROVIDERS", "CLEARANCE_OIDC_ISSUER", "CLEARANCE_GITHUB_APP_ID",
		"BACKSTAGE_URL", "CLEARANCE_TRUSTED_REGISTRIES", "CLEARANCE_BUNDLES", "CLEARANCE_BUNDLE_SOURCES",
		"CLEARANCE_PROTECTED_ENVIRONMENTS", "CLEARANCE_BREAKGLASS_MAX_TTL"} {
		if _, ok := e[unset]; ok {
			t.Errorf("core: %s is set by default", unset)
		}
	}
	if e["CLEARANCE_AUDIENCE"] != "clearance" {
		t.Errorf("core: CLEARANCE_AUDIENCE %q", e["CLEARANCE_AUDIENCE"])
	}

	api := find(objs, "Deployment", "t-clearance-api")
	if get(api, "spec", "replicas") != 2 {
		t.Errorf("api replicas %v", get(api, "spec", "replicas"))
	}
	ae := env(container(t, api))
	if ae["CLEARANCE_API_DSN"] != "secret:clearance-db/uri" || ae["CLEARANCE_CORE_URL"] != "http://t-clearance-core.clearance.svc:8080" {
		t.Errorf("api env %v", ae)
	}
	if get(find(objs, "PodDisruptionBudget", "t-clearance-api"), "spec", "minAvailable") != 1 {
		t.Error("api PDB minAvailable is not 1")
	}

	crb := find(objs, "ClusterRoleBinding", "clearance-t-clearance-auth-delegator")
	if get(crb, "roleRef", "name") != "system:auth-delegator" || len(get(crb, "subjects").([]any)) != 2 {
		t.Errorf("auth-delegator binding %v", crb)
	}

	deny := find(objs, "NetworkPolicy", "t-clearance-default-deny")
	if types := get(deny, "spec", "policyTypes").([]any); len(types) != 2 || get(deny, "spec", "ingress") != nil ||
		get(deny, "spec", "egress") != nil {
		t.Errorf("default-deny %v", deny["spec"])
	}
	// No pod may reach the core until networkPolicy.core.from names one.
	if get(find(objs, "NetworkPolicy", "t-clearance-core"), "spec", "ingress") != nil {
		t.Error("core NetworkPolicy allows ingress by default")
	}
	for _, o := range objs {
		if o["kind"] == "Secret" {
			t.Errorf("the chart renders a Secret (%v): secrets are referenced, never rendered", get(o, "metadata", "name"))
		}
	}
}

// Every variable the core reads (internal/core's package doc and authn.EnvVars) is a chart value: the full render
// sets each of them.
func TestFullCoversEveryCoreVariable(t *testing.T) {
	objs := render(t, "-f", valuesFile("full-values.yaml"))
	assertHardened(t, objs)
	src, err := os.ReadFile("../../internal/core/core.go")
	if err != nil {
		t.Fatal(err)
	}
	doc, _, _ := strings.Cut(string(src), "package core")
	names := map[string]bool{}
	for _, n := range regexp.MustCompile(`\b(?:CLEARANCE|BACKSTAGE|AGENT|MODEL|RUNTIME)_[A-Z0-9_]*[A-Z0-9]\b`).FindAllString(doc, -1) {
		names[n] = true
	}
	for _, n := range append(append(append([]string(nil), authn.EnvVars...), bundles.EnvVars...), vocab.EnvVars...) {
		names[n] = true
	}
	if len(names) < 25 {
		t.Fatalf("found only %d variable names in internal/core and authn: the extraction is broken", len(names))
	}
	core := find(objs, "Deployment", "t-clearance-core")
	e := env(container(t, core))
	// A static attestation key and Fulcio are alternatives (the chart refuses both): full sets Fulcio.
	delete(names, "CLEARANCE_ATTEST_KEY_FILE")
	for n := range names {
		if _, ok := e[n]; !ok {
			t.Errorf("CLEARANCE core variable %s has no chart value (not set by ci/full-values.yaml)", n)
		}
	}
	if e["CLEARANCE_PROTECTED_ENVIRONMENTS"] != "hangar-prod/*" || e["CLEARANCE_BREAKGLASS_MAX_TTL"] != "2h" {
		t.Errorf("protected environments %q break-glass max TTL %q", e["CLEARANCE_PROTECTED_ENVIRONMENTS"], e["CLEARANCE_BREAKGLASS_MAX_TTL"])
	}
	if e["CLEARANCE_TRUSTED_REGISTRIES"] != "ghcr.io/riley-roooo/" || e["CLEARANCE_BUNDLES"] != "/etc/clearance/bundles/hangar/bundle.json" {
		t.Errorf("trusted registries %q bundles %q", e["CLEARANCE_TRUSTED_REGISTRIES"], e["CLEARANCE_BUNDLES"])
	}
	// Each source: a url with this pod's projected token, or a file from a ConfigMap.
	if want := `{"glidepath":{"tokenFile":"/var/run/clearance/sources/glidepath","url":"http://glidepath-api.platform-system.svc:8080/v1/contract"},"offline":{"file":"/etc/clearance/sources/offline/contract.json"}}`; e["CLEARANCE_BUNDLE_SOURCES"] != want {
		t.Errorf("CLEARANCE_BUNDLE_SOURCES %s", e["CLEARANCE_BUNDLE_SOURCES"])
	}
	if e["CLEARANCE_ON_BEHALF_OF_HEADER"] != "X-Hangar-On-Behalf-Of" || e["CLEARANCE_ENV_LOWER_PREFIXES"] != "pr-,agent-" {
		t.Errorf("vocabulary %q, environments %q", e["CLEARANCE_ON_BEHALF_OF_HEADER"], e["CLEARANCE_ENV_LOWER_PREFIXES"])
	}
	if e["CLEARANCE_AI_COAUTHORS"] != "<noreply@anthropic.com>,Acme Agent <agent@acme.dev>" {
		t.Errorf("CLEARANCE_AI_COAUTHORS %q", e["CLEARANCE_AI_COAUTHORS"])
	}
	var sawBundle, sawSourceToken bool
	for _, v := range get(core, "spec", "template", "spec", "volumes").([]any) {
		if get(v, "name") == "bundle-hangar" && get(v, "configMap", "name") == "clearance-bundle-hangar" {
			sawBundle = true
		}
		if get(v, "name") == "source-tokens" && get(v, "projected", "sources", 0, "serviceAccountToken", "path") == "glidepath" &&
			get(v, "projected", "sources", 0, "serviceAccountToken", "audience") == nil {
			sawSourceToken = true
		}
	}
	if !sawBundle || !sawSourceToken {
		t.Errorf("volumes: bundle %v, source token (API server audience) %v", sawBundle, sawSourceToken)
	}
	cnp := find(objs, "CiliumNetworkPolicy", "t-clearance-kube-apiserver")
	if cnp == nil || fmt.Sprint(get(cnp, "spec", "egress")) != "[map[toEntities:[kube-apiserver]]]" ||
		fmt.Sprint(get(cnp, "spec", "endpointSelector", "matchExpressions")) !=
			"[map[key:app.kubernetes.io/component operator:In values:[core api]]]" ||
		get(cnp, "spec", "endpointSelector", "matchLabels", "app.kubernetes.io/instance") != "t" {
		t.Errorf("ciliumEntity: %v", cnp)
	}
	np := find(objs, "NetworkPolicy", "t-clearance-core")
	if eg := fmt.Sprint(get(np, "spec", "egress")); !strings.Contains(eg, "glidepath-api") {
		t.Errorf("core NetworkPolicy has no egress to the bundle source: %s", eg)
	}
	if e["CLEARANCE_DSN"] != "secret:t-clearance-pg-app/uri" {
		t.Errorf("with cnpg the core's DSN is %q", e["CLEARANCE_DSN"])
	}
	if !strings.HasPrefix(e["CLEARANCE_PROVIDERS"], `[{"definitions":true,"name":"autopilot-gateway"`) {
		t.Errorf("CLEARANCE_PROVIDERS %q", e["CLEARANCE_PROVIDERS"])
	}
	c := container(t, core)
	if c["image"] != "ghcr.io/jfillman/clearance@sha256:"+strings.Repeat("0", 64) {
		t.Errorf("image by digest: %v", c["image"])
	}
	// The App's key and secret are files from the ExternalSecret's Secret, never values.
	if e["CLEARANCE_GITHUB_APP_KEY_FILE"] != "/etc/clearance/github-app/private-key.pem" {
		t.Errorf("key file %q", e["CLEARANCE_GITHUB_APP_KEY_FILE"])
	}
	vols := get(core, "spec", "template", "spec", "volumes").([]any)
	var sawApp, sawBackstage bool
	for _, v := range vols {
		if get(v, "name") == "github-app" && get(v, "secret", "secretName") == "t-clearance-github-app" {
			sawApp = true
		}
		if get(v, "name") == "backstage-token" && get(v, "projected", "sources", 0, "serviceAccountToken", "audience") == "backstage" {
			sawBackstage = true
		}
	}
	if !sawApp || !sawBackstage {
		t.Errorf("volumes: github-app %v, backstage projected token %v", sawApp, sawBackstage)
	}
	ae := env(container(t, find(objs, "Deployment", "t-clearance-api")))
	if ae["CLEARANCE_API_DSN"] != "secret:t-clearance-pg-reader/uri" || ae["CLEARANCE_API_AUDITORS"] != "user:auditor" {
		t.Errorf("api env %v", ae)
	}
	for _, want := range []string{"Cluster/t-clearance-pg", "ExternalSecret/t-clearance-github-app",
		"ExternalSecret/t-clearance-pg-reader", "HTTPRoute/t-clearance-core", "HTTPRoute/t-clearance-api",
		"NetworkPolicy/t-clearance-pg"} {
		if !slices.Contains(kinds(objs), want) {
			t.Errorf("full render has no %s", want)
		}
	}
	pg := find(objs, "Cluster", "t-clearance-pg")
	if get(pg, "spec", "managed", "roles", 0, "passwordSecret", "name") != "t-clearance-pg-reader" {
		t.Errorf("CNPG reader role %v", get(pg, "spec", "managed"))
	}
	route := find(objs, "HTTPRoute", "t-clearance-core")
	if get(route, "spec", "rules", 0, "matches", 0, "path", "value") != "/v1/github/webhook" {
		t.Errorf("core route %v", route["spec"])
	}
}

// Every variable `clearance api` reads (internal/api Config's doc and authn.EnvVars) is a chart value: the full
// render sets each of them on the api Deployment (PORT is the fallback the chart's CLEARANCE_LISTEN replaces).
func TestFullCoversEveryAPIVariable(t *testing.T) {
	objs := render(t, "-f", valuesFile("full-values.yaml"))
	src, err := os.ReadFile("../../internal/api/config.go")
	if err != nil {
		t.Fatal(err)
	}
	_, doc, _ := strings.Cut(string(src), "// Config is clearance-api's deployment")
	doc, _, _ = strings.Cut(doc, "type Config struct")
	names := map[string]bool{}
	for _, n := range regexp.MustCompile(`\b(?:CLEARANCE|BACKSTAGE)_[A-Z0-9_]*[A-Z0-9]\b`).FindAllString(doc, -1) {
		names[n] = true
	}
	for _, n := range append(append(append([]string(nil), authn.EnvVars...), bundles.EnvVars...), vocab.EnvVars...) {
		names[n] = true
	}
	if len(names) < 20 {
		t.Fatalf("found only %d variable names in internal/api and authn: the extraction is broken", len(names))
	}
	e := env(container(t, find(objs, "Deployment", "t-clearance-api")))
	for n := range names {
		if _, ok := e[n]; !ok {
			t.Errorf("clearance api variable %s has no chart value (not set by ci/full-values.yaml)", n)
		}
	}
	if e["CLEARANCE_LISTEN"] != ":8080" || e["CLEARANCE_GATEWAY_URL"] != "http://autopilot-gateway.autopilot-system.svc:8080" {
		t.Errorf("listen %q gateway %q", e["CLEARANCE_LISTEN"], e["CLEARANCE_GATEWAY_URL"])
	}
}

func TestInstallValues(t *testing.T) {
	objs := render(t, "-f", valuesFile("install-values.yaml"))
	np := find(objs, "NetworkPolicy", "t-clearance-core")
	if get(np, "spec", "ingress", 0, "from", 0, "podSelector", "matchLabels", "app") != "installtest" {
		t.Errorf("core ingress %v", get(np, "spec", "ingress"))
	}
	if get(find(objs, "NetworkPolicy", "t-clearance-core"), "spec", "egress", 1, "to", 0, "podSelector", "matchLabels", "app") != "postgres" {
		t.Errorf("core egress to postgres %v", get(np, "spec", "egress"))
	}
	if objs := render(t, "-f", valuesFile("install-values.yaml"), "--set", "api.enabled=false"); find(objs, "Deployment", "t-clearance-api") != nil ||
		find(objs, "PodDisruptionBudget", "t-clearance-api") != nil || find(objs, "NetworkPolicy", "t-clearance-api") != nil {
		t.Error("api.enabled=false still renders the api")
	}
}

func TestRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no database":                      {nil, "the core needs a database"},
		"core replicas":                    {[]string{"--set", "database.existingSecret=x", "--set", "core.replicas=2"}, "always one replica"},
		"oidc without users":               {[]string{"--set", "database.existingSecret=x", "--set", "oidc.issuer=https://i", "--set", "oidc.audience=a"}, "oidc.allowedUsers is required"},
		"oidc half":                        {[]string{"--set", "database.existingSecret=x", "--set", "oidc.issuer=https://i"}, "oidc.audience is set together"},
		"foreign cluster without accounts": {[]string{"--set", "database.existingSecret=x", "--set", "foreignCluster.issuer=https://t", "--set", "foreignCluster.cluster=c"}, "foreignCluster.serviceAccounts is required"},
		"app without secret":               {[]string{"--set", "database.existingSecret=x", "--set", "githubApp.enabled=true", "--set", "githubApp.appId=1"}, "githubApp.enabled needs"},
		"app without id":                   {[]string{"--set", "database.existingSecret=x", "--set", "githubApp.enabled=true", "--set", "githubApp.existingSecret=s"}, "githubApp.appId is required"},
		"bad comments":                     {[]string{"--set", "database.existingSecret=x", "--set", "githubApp.comments=all"}, "githubApp.comments is off or agent-failures"},
		"flight registry slash":            {[]string{"--set", "database.existingSecret=x", "--set", "gate.trustedRegistries[0]=ghcr.io/x"}, `must end in "/"`},
		"protected env shape":              {[]string{"--set", "database.existingSecret=x", "--set", "gate.protectedEnvironments[0]=prod"}, `is not <cluster>/<env>`},
		"bad digest":                       {[]string{"--set", "database.existingSecret=x", "--set", "image.digest=latest"}, "image.digest is sha256"},
		"route without parent":             {[]string{"--set", "database.existingSecret=x", "--set", "httpRoutes.core.enabled=true"}, "parentRefs is required"},
		"attestation both backends":        {[]string{"--set", "database.existingSecret=x", "--set", "attestation.existingSecret=k", "--set", "attestation.keyless.fulcioUrl=https://f"}, "not both"},
		"web without secret":               {[]string{"--set", "database.existingSecret=x", "--set", "web.enabled=true", "--set", "web.publicURL=https://c", "--set", "web.issuer=https://i"}, "web.clientSecret.existingSecret is required"},
		"web without issuer":               {[]string{"--set", "database.existingSecret=x", "--set", "web.enabled=true", "--set", "web.publicURL=https://c", "--set", "web.clientSecret.existingSecret=s"}, "web.issuer is required"},
		"web replicas":                     {[]string{"--set", "database.existingSecret=x", "--set", "web.enabled=true", "--set", "web.publicURL=https://c", "--set", "web.issuer=https://i", "--set", "web.clientSecret.existingSecret=s", "--set", "web.replicas=2"}, "web.replicas must be 1"},
		"web route without parent":         {[]string{"--set", "database.existingSecret=x", "--set", "web.enabled=true", "--set", "web.publicURL=https://c", "--set", "web.issuer=https://i", "--set", "web.clientSecret.existingSecret=s", "--set", "httpRoutes.web.enabled=true"}, "httpRoutes.web.parentRefs is required"},
		"eso without store":                {[]string{"--set", "database.existingSecret=x", "--set", "externalSecrets.enabled=true"}, "secretStoreRef.name is required"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := helm(t, tc.args...)
			if err == nil {
				t.Fatalf("rendered; want a refusal mentioning %q", tc.want)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("refused with %q; want %q", out, tc.want)
			}
		})
	}
}

// Change attestations (C-2): off by default; keyless projects the core's OIDC token for the core alone; a static key
// is an existing Secret mounted for the core alone.
func TestAttestationBackendsAreTheCoresAlone(t *testing.T) {
	has := func(o obj, name string) bool {
		for _, v := range get(o, "spec", "template", "spec", "volumes").([]any) {
			if get(v, "name") == name {
				return true
			}
		}
		return false
	}
	off := render(t, "-f", valuesFile("full-values.yaml"), "--set", "attestation.keyless.fulcioUrl=", "--set", "attestation.rekorUrl=")
	for k := range env(container(t, find(off, "Deployment", "t-clearance-core"))) {
		if strings.HasPrefix(k, "CLEARANCE_ATTEST_") {
			t.Errorf("attestations off, but %s is set", k)
		}
	}
	kl := render(t, "-f", valuesFile("full-values.yaml"), "--set", "attestation.keyless.fulcioUrl=https://fulcio.example",
		"--set", "attestation.rekorUrl=https://rekor.example")
	core, api := find(kl, "Deployment", "t-clearance-core"), find(kl, "Deployment", "t-clearance-api")
	e := env(container(t, core))
	if e["CLEARANCE_ATTEST_FULCIO_URL"] != "https://fulcio.example" || e["CLEARANCE_ATTEST_REKOR_URL"] != "https://rekor.example" ||
		e["CLEARANCE_ATTEST_OIDC_TOKEN_FILE"] != "/var/run/clearance-attest/oidc-token" || !has(core, "attest-oidc-token") || has(api, "attest-oidc-token") {
		t.Errorf("keyless: env %v", e)
	}
	for _, v := range get(core, "spec", "template", "spec", "volumes").([]any) {
		if get(v, "name") == "attest-oidc-token" && get(v, "projected", "sources", 0, "serviceAccountToken", "audience") != "sigstore" {
			t.Errorf("the OIDC token's audience: %v", v)
		}
	}
	st := render(t, "-f", valuesFile("full-values.yaml"), "--set", "attestation.keyless.fulcioUrl=", "--set", "attestation.existingSecret=attest-key")
	core, api = find(st, "Deployment", "t-clearance-core"), find(st, "Deployment", "t-clearance-api")
	if e := env(container(t, core)); e["CLEARANCE_ATTEST_KEY_FILE"] != "/etc/clearance/attest/attest-key.pem" || !has(core, "attest-key") || has(api, "attest-key") {
		t.Errorf("static: env %v", e)
	}
}

// The signing key is an existing Secret, mounted read-only for the core only; the api never sees it, and the feed
// readers reach the api as <principal>=<cluster>.
func TestTheSigningKeyIsTheCoresAlone(t *testing.T) {
	objs := render(t, "-f", valuesFile("full-values.yaml"))
	core, api := find(objs, "Deployment", "t-clearance-core"), find(objs, "Deployment", "t-clearance-api")
	e := env(container(t, core))
	if e["CLEARANCE_SIGNING_KEY_FILE"] != "/etc/clearance/signing/signing-key.pem" || e["CLEARANCE_TOKEN_TTL"] != "10m" {
		t.Errorf("core env %q %q", e["CLEARANCE_SIGNING_KEY_FILE"], e["CLEARANCE_TOKEN_TTL"])
	}
	var vol obj
	for _, v := range get(core, "spec", "template", "spec", "volumes").([]any) {
		if get(v, "name") == "signing-key" {
			vol = v.(obj)
		}
	}
	if get(vol, "secret", "secretName") != "clearance-signing-key" || fmt.Sprint(get(vol, "secret", "defaultMode")) != "256" ||
		get(vol, "secret", "items", 0, "key") != "signing-key.pem" {
		t.Errorf("signing volume %v", vol)
	}
	for _, v := range get(api, "spec", "template", "spec", "volumes").([]any) {
		if get(v, "name") == "signing-key" || get(v, "secret", "secretName") == "clearance-signing-key" {
			t.Error("the api mounts the signing key")
		}
	}
	ae := env(container(t, api))
	if _, ok := ae["CLEARANCE_SIGNING_KEY_FILE"]; ok {
		t.Error("the api is told where the signing key is")
	}
	if ae["CLEARANCE_API_FEED_READERS"] != "hangar-prod/clearance-system/clearance-agent=hangar-prod" {
		t.Errorf("feed readers %q", ae["CLEARANCE_API_FEED_READERS"])
	}
	// Without a Secret named, nothing is mounted and no tokens are issued.
	min := find(render(t, "-f", valuesFile("minimal-values.yaml")), "Deployment", "t-clearance-core")
	if _, ok := env(container(t, min))["CLEARANCE_SIGNING_KEY_FILE"]; ok {
		t.Error("a key file without a Secret")
	}
}

// vocabulary.aiCoauthors: unset keeps the core's default matchers (the variable is absent), an empty list turns the
// check off ("none"), on the core and clearance-api alike.
func TestAICoauthorsUnsetEmptyAndSet(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
		set  bool
	}{
		{nil, "", false},
		{[]string{"--set-json", "vocabulary.aiCoauthors=[]"}, "none", true},
		{[]string{"--set-json", `vocabulary.aiCoauthors=["<bot@acme.dev>"]`}, "<bot@acme.dev>", true},
	} {
		objs := render(t, append([]string{"-f", valuesFile("minimal-values.yaml")}, tc.args...)...)
		for _, d := range []string{"t-clearance-core", "t-clearance-api"} {
			dep := find(objs, "Deployment", d)
			if dep == nil {
				continue
			}
			got, ok := env(container(t, dep))["CLEARANCE_AI_COAUTHORS"]
			if ok != tc.set || got != tc.want {
				t.Errorf("%v %s: %q (set %v), want %q (set %v)", tc.args, d, got, ok, tc.want, tc.set)
			}
		}
	}
}

// The evidence ledger (C-3) is off unless configured: the default render has no volume, no environment and no mount
// for it, and the same Deployment as before. On, it is a ReadWriteOnce claim for the one core replica, whose rollout
// is Recreate, with the key from an existing Secret and never a value.
func TestTheLedgerIsOffUnlessConfigured(t *testing.T) {
	for _, f := range []string{"minimal-values.yaml", "install-values.yaml"} {
		objs := render(t, "-f", valuesFile(f))
		for _, o := range objs {
			if strings.Contains(fmt.Sprint(o), "ledger") {
				t.Errorf("%s renders something about the ledger with it off: %s/%v", f, o["kind"], get(o, "metadata", "name"))
			}
		}
	}
	objs := render(t, "-f", valuesFile("full-values.yaml"))
	core := find(objs, "Deployment", "t-clearance-core")
	if get(core, "spec", "strategy", "type") != "Recreate" || get(core, "spec", "replicas") != 1 {
		t.Errorf("rollout %v replicas %v", get(core, "spec", "strategy"), get(core, "spec", "replicas"))
	}
	e := env(container(t, core))
	if e["CLEARANCE_LEDGER_DIR"] != "/var/lib/clearance/ledger" || e["CLEARANCE_LEDGER_KEY_FILE"] != "/etc/clearance/ledger/ledger-key" ||
		e["CLEARANCE_LEDGER_TIER3_WAIT"] != "true" || e["CLEARANCE_LEDGER_CHECKPOINT_INTERVAL"] != "30s" {
		t.Errorf("ledger env %v", e)
	}
	for k, v := range e {
		if strings.Contains(k, "LEDGER") && strings.Contains(v, "PRIVATE") {
			t.Errorf("%s carries key material", k)
		}
	}
	pvc := find(objs, "PersistentVolumeClaim", "t-clearance-core-ledger")
	if pvc == nil || fmt.Sprint(get(pvc, "spec", "accessModes")) != "[ReadWriteOnce]" ||
		get(pvc, "spec", "resources", "requests", "storage") != "2Gi" || get(pvc, "spec", "storageClassName") != "fast" {
		t.Errorf("claim %v", pvc)
	}
	var key, claim bool
	for _, v := range get(core, "spec", "template", "spec", "volumes").([]any) {
		if get(v, "name") == "ledger-key" && get(v, "secret", "secretName") == "clearance-ledger-key" && get(v, "secret", "defaultMode") == 256 {
			key = true
		}
		if get(v, "name") == "ledger" && get(v, "persistentVolumeClaim", "claimName") == "t-clearance-core-ledger" {
			claim = true
		}
	}
	if !key || !claim {
		t.Errorf("volumes: key %v claim %v", key, claim)
	}
	cm := find(objs, "ConfigMap", "t-clearance-core-ledger")
	if cm == nil || !strings.Contains(fmt.Sprint(get(cm, "data", "witness-policy")), "quorum lab") || get(cm, "data", "retired-keys") == nil {
		t.Errorf("config %v", cm)
	}
	np := find(objs, "NetworkPolicy", "t-clearance-core")
	if !strings.Contains(fmt.Sprint(get(np, "spec", "egress")), "witness-system") {
		t.Errorf("no egress to the witness: %v", get(np, "spec", "egress"))
	}
	if api := find(objs, "NetworkPolicy", "t-clearance-api"); strings.Contains(fmt.Sprint(get(api, "spec", "egress")), "witness-system") {
		t.Error("the api may reach the witness")
	}
	if strings.Contains(fmt.Sprint(find(objs, "Deployment", "t-clearance-api")), "ledger") {
		t.Error("the api carries the ledger")
	}
}

func TestTheLedgerNeedsItsKeyAndAWitness(t *testing.T) {
	base := []string{"--set", "database.existingSecret=x", "--set", "ledger.enabled=true"}
	for name, tc := range map[string]struct {
		extra []string
		want  string
	}{
		"no key":     {[]string{"--set", "ledger.witnessPolicy=quorum none"}, "ledger.existingSecret"},
		"no witness": {[]string{"--set", "ledger.existingSecret=k"}, "ledger.witnessPolicy"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := helm(t, append(append([]string(nil), base...), tc.extra...)...)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("%v: %s", err, out)
			}
		})
	}
}

// The web UI (WEB-5) is off by default: the minimal and install renders have none of it. On, it is one hardened pod
// with the client secret as a file, every CLEARANCE_WEB_* variable the server reads is a chart value, and its
// NetworkPolicy is DNS, the IdP, the api and the core only.
func TestWeb(t *testing.T) {
	for _, f := range []string{"minimal-values.yaml", "install-values.yaml"} {
		for _, o := range render(t, "-f", valuesFile(f)) {
			if strings.Contains(get(o, "metadata", "name").(string), "-web") {
				t.Errorf("%s: web is off but %v renders", f, get(o, "metadata", "name"))
			}
		}
	}
	objs := render(t, "-f", valuesFile("full-values.yaml"))
	assertHardened(t, objs)
	dep := find(objs, "Deployment", "t-clearance-web")
	if dep == nil || find(objs, "Service", "t-clearance-web") == nil || find(objs, "HTTPRoute", "t-clearance-web") == nil ||
		find(objs, "NetworkPolicy", "t-clearance-web") == nil || find(objs, "ServiceAccount", "t-clearance-web") == nil {
		t.Fatalf("web objects missing: %v", kinds(objs))
	}
	if get(dep, "spec", "replicas") != 1 || get(dep, "spec", "template", "spec", "automountServiceAccountToken") != false {
		t.Errorf("replicas %v automount %v", get(dep, "spec", "replicas"), get(dep, "spec", "template", "spec", "automountServiceAccountToken"))
	}
	src, err := os.ReadFile("../../internal/web/config.go")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, n := range regexp.MustCompile(`\bCLEARANCE_WEB_[A-Z0-9_]*[A-Z0-9]\b`).FindAllString(string(src), -1) {
		names[n] = true
	}
	if len(names) < 15 {
		t.Fatalf("found only %d CLEARANCE_WEB_ names in internal/web/config.go: the extraction is broken", len(names))
	}
	e := env(container(t, dep))
	for n := range names {
		switch n {
		case "CLEARANCE_WEB_TLS_CERT", "CLEARANCE_WEB_TLS_KEY": // a Gateway terminates TLS; the chart does not serve it
			continue
		}
		if _, ok := e[n]; !ok {
			t.Errorf("clearance web variable %s has no chart value (not set by ci/full-values.yaml)", n)
		}
	}
	if e["CLEARANCE_WEB_CLIENT_SECRET_FILE"] != "/etc/clearance/web/client-secret" ||
		e["CLEARANCE_WEB_API_URL"] != "http://t-clearance-api.clearance.svc:8080" ||
		e["CLEARANCE_WEB_CORE_URL"] != "http://t-clearance-core.clearance.svc:8080" ||
		e["CLEARANCE_WEB_MAX_BODY_BYTES"] != "1048576" || e["CLEARANCE_WEB_MAX_RESPONSE_BYTES"] != "33554432" {
		t.Errorf("web env %v", e)
	}
	for k, v := range e {
		if strings.Contains(strings.ToLower(k), "secret") && !strings.HasSuffix(k, "_FILE") {
			t.Errorf("web env %s=%q: a secret is a file", k, v)
		}
	}
	for _, o := range []string{"t-clearance-core", "t-clearance-api"} {
		if !strings.Contains(fmt.Sprint(get(find(objs, "NetworkPolicy", o), "spec", "ingress")), "component:web") {
			t.Errorf("%s admits no web pod: %v", o, get(find(objs, "NetworkPolicy", o), "spec", "ingress"))
		}
	}
	if got := fmt.Sprint(get(find(objs, "NetworkPolicy", "t-clearance-web"), "spec", "egress")); !strings.Contains(got, "203.0.113.0/24") ||
		strings.Contains(got, "0.0.0.0/0") || strings.Contains(got, "5432") {
		t.Errorf("web egress %v", got)
	}
}
