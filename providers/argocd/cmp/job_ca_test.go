package main

import (
	"strings"
	"testing"
	"time"
)

func TestWaitJobMountsTheCAOnlyWhenConfigured(t *testing.T) {
	cfg := Config{WaitImage: "registry.test/wait@sha256:abc", CoreURL: "https://core.test:8443", Destination: "prod", WaitTimeout: time.Hour}
	job, err := WaitJob(cfg, "ch-1")
	if err != nil {
		t.Fatal(err)
	}
	spec := job["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	if len(spec["volumes"].([]any)) != 1 {
		t.Fatal("no CA configured: only the token volume")
	}
	cfg.WaitCAConfigMap = "clearance-ca"
	job, _ = WaitJob(cfg, "ch-1")
	spec = job["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	vols := spec["volumes"].([]any)
	mounts := spec["containers"].([]any)[0].(map[string]any)["volumeMounts"].([]any)
	if len(vols) != 2 || len(mounts) != 2 || vols[1].(map[string]any)["name"] != WaitCAVolume ||
		mounts[1].(map[string]any)["mountPath"] != "/etc/clearance-ca" {
		t.Fatalf("%v %v", vols, mounts)
	}
}

func TestParseConfigCASettings(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := ParseConfig(get(map[string]string{"CLEARANCE_CA_FILE": "/etc/clearance-ca/ca.crt", "CLEARANCE_WAIT_CA_CONFIGMAP": "clearance-ca"}))
	if c.CAFile != "/etc/clearance-ca/ca.crt" || c.WaitCAConfigMap != "clearance-ca" {
		t.Fatalf("%+v", c)
	}
	_ = err // other required settings are absent: only the two fields are under test
	// otherwise valid settings: only the ConfigMap name decides
	valid := func(name string) map[string]string {
		return map[string]string{"ARGOCD_APP_NAME": "gate-api-prod", "ARGOCD_APP_NAMESPACE": "app-gate-api-prod", "ARGOCD_APP_REVISION": strings.Repeat("a", 40),
			"ARGOCD_APP_SOURCE_REPO_URL": "git@github.com:Jfillman/gitops-gate-api.git", "PARAM_APP": "gate-api", "PARAM_ENV": "prod", "PARAM_CLUSTER": "hangar-prod",
			"PARAM_CHARTREPO": "https://github.com/jfillman/airframe.git", "PARAM_CHARTREVISION": "v0.3.168", "PARAM_CHARTPATH": "charts/airframe-application",
			"CLEARANCE_CHART_REPOS": "https://github.com/jfillman/airframe.git", "CLEARANCE_URL": "http://clearance.test", "CLEARANCE_WAIT_CA_CONFIGMAP": name}
	}
	for _, ok := range []string{"clearance-ca", "clearance.ca", "a.b-c.d"} {
		if _, err := ParseConfig(get(valid(ok))); err != nil {
			t.Fatalf("%q must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"Bad Name", "-x", "x.", "a..b", strings.Repeat("a", 254)} {
		_, err := ParseConfig(get(valid(bad)))
		if err == nil || !strings.Contains(err.Error(), "CLEARANCE_WAIT_CA_CONFIGMAP") {
			t.Fatalf("%q: want the ConfigMap-name error, got %v", bad, err)
		}
	}
}
