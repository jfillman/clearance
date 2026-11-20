package charttest

import (
	"strings"
	"testing"
)

// I-43: TLS on the core and the api is off by default (the render is exactly what it was), and on it adds an https port,
// cert-manager Certificates and the mounted pair, beside plain http.
func TestTLSIsOffByDefault(t *testing.T) {
	objs := render(t, "-f", valuesFile("minimal-values.yaml"))
	for _, k := range kinds(objs) {
		if strings.HasPrefix(k, "Certificate/") || strings.HasPrefix(k, "Issuer/") {
			t.Errorf("tls is off but %s rendered", k)
		}
	}
	for _, d := range []string{"t-clearance-core", "t-clearance-api"} {
		c := container(t, find(objs, "Deployment", d))
		for k := range env(c) {
			if strings.HasPrefix(k, "CLEARANCE_TLS_") {
				t.Errorf("%s: %s is set with tls off", d, k)
			}
		}
		if env(c)["CLEARANCE_LISTEN"] != ":8080" {
			t.Errorf("%s: the plain listener changed", d)
		}
	}
}

func TestTLSBesidePlainHTTPWithItsOwnCA(t *testing.T) {
	objs := render(t, "-f", valuesFile("tls-values.yaml"))
	for _, want := range []string{"Certificate/t-clearance-ca", "Certificate/t-clearance-core-tls", "Certificate/t-clearance-api-tls",
		"Issuer/t-clearance-selfsigned", "Issuer/t-clearance-ca"} {
		if find(objs, strings.Split(want, "/")[0], strings.Split(want, "/")[1]) == nil {
			t.Errorf("missing %s in %v", want, kinds(objs))
		}
	}
	for _, comp := range []string{"core", "api"} {
		d := find(objs, "Deployment", "t-clearance-"+comp)
		c := container(t, d)
		e := env(c)
		if e["CLEARANCE_TLS_LISTEN"] != ":8443" || e["CLEARANCE_TLS_CERT_FILE"] != "/etc/clearance/tls/tls.crt" ||
			e["CLEARANCE_TLS_KEY_FILE"] != "/etc/clearance/tls/tls.key" || e["CLEARANCE_LISTEN"] != ":8080" {
			t.Errorf("%s env: %v", comp, e)
		}
		// the key pair, never the CA bundle or anything else, from the Secret cert-manager fills
		vols, _ := get(d, "spec", "template", "spec", "volumes").([]any)
		found := false
		for _, v := range vols {
			if get(v, "name") == "tls" {
				found = true
				if get(v, "secret", "secretName") != "t-clearance-"+comp+"-tls" {
					t.Errorf("%s: tls volume %v", comp, v)
				}
			}
		}
		if !found {
			t.Errorf("%s: no tls volume", comp)
		}
		svc := find(objs, "Service", "t-clearance-"+comp)
		ports, _ := get(svc, "spec", "ports").([]any)
		if len(ports) != 2 || get(ports[0], "port") != 8080 || get(ports[1], "port") != 8443 {
			t.Errorf("%s service ports: %v", comp, ports)
		}
		// no Secret is made by hand
	}
	for _, o := range objs {
		if o["kind"] == "Secret" {
			t.Errorf("the chart rendered a Secret: %v", get(o, "metadata", "name"))
		}
	}
	core := find(objs, "Certificate", "t-clearance-core-tls")
	if names, _ := get(core, "spec", "dnsNames").([]any); len(names) < 4 || names[3] != "t-clearance-core.clearance.svc.cluster.local" {
		t.Errorf("dnsNames: %v", names)
	}
}

func TestTLSOnlyUsesAnExistingIssuerAndHTTPSProbes(t *testing.T) {
	objs := render(t, "-f", valuesFile("tls-only-values.yaml"))
	if find(objs, "Issuer", "t-clearance-selfsigned") != nil || find(objs, "Certificate", "t-clearance-ca") != nil {
		t.Error("an issuerRef is set: the chart must not build its own CA")
	}
	cert := find(objs, "Certificate", "t-clearance-core-tls")
	if get(cert, "spec", "issuerRef", "name") != "cluster-ca" || get(cert, "spec", "issuerRef", "kind") != "ClusterIssuer" {
		t.Errorf("issuerRef: %v", get(cert, "spec", "issuerRef"))
	}
	for _, comp := range []string{"core", "api"} {
		c := container(t, find(objs, "Deployment", "t-clearance-"+comp))
		if env(c)["CLEARANCE_LISTEN"] != "off" {
			t.Errorf("%s: plain http is not off: %v", comp, env(c)["CLEARANCE_LISTEN"])
		}
		if get(c, "readinessProbe", "httpGet", "scheme") != "HTTPS" || get(c, "readinessProbe", "httpGet", "port") != "https" {
			t.Errorf("%s: probe %v", comp, get(c, "readinessProbe"))
		}
		ports, _ := get(find(objs, "Service", "t-clearance-"+comp), "spec", "ports").([]any)
		if len(ports) != 1 || get(ports[0], "port") != 8443 {
			t.Errorf("%s service ports: %v", comp, ports)
		}
	}
	if get(container(t, find(objs, "Deployment", "t-clearance-api")), "env") == nil {
		t.Fatal("no api env")
	}
	if v := env(container(t, find(objs, "Deployment", "t-clearance-api")))["CLEARANCE_CORE_URL"]; v != "https://t-clearance-core.clearance.svc:8443" {
		t.Errorf("the api names the core by %q", v)
	}
}

func TestTLSIsOpenOnTheNetworkPolicyToo(t *testing.T) {
	text, err := helm(t, "-f", valuesFile("full-values.yaml"), "--set", "tls.enabled=true")
	if err != nil {
		t.Fatal(err, text)
	}
	if !strings.Contains(text, "port: 8443") {
		t.Error("the core's and the api's ingress must allow the https port")
	}
}

func TestTLSRefusals(t *testing.T) {
	base := []string{"--set", "database.existingSecret=x", "--set", "tls.enabled=true"}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no certificate source":     {[]string{"--set", "tls.certManager.enabled=false"}, "tls.existingSecrets"},
		"port clash":                {[]string{"--set", "tls.port=8080"}, "must differ"},
		"plain off with the web UI": {[]string{"--set", "tls.plainHttp=false", "--set", "web.enabled=true", "--set", "web.publicURL=https://c", "--set", "web.issuer=https://i", "--set", "web.clientSecret.existingSecret=s"}, "tls.plainHttp false is not supported with web"},
		"plain off with a route":    {[]string{"--set", "tls.plainHttp=false", "--set", "httpRoutes.core.enabled=true", "--set", "httpRoutes.core.parentRefs[0].name=gw"}, "tls.plainHttp false is not supported with httpRoutes.core"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := helm(t, append(append([]string{}, base...), tc.args...)...)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("want a refusal mentioning %q; got err=%v %q", tc.want, err, out)
			}
		})
	}
}
