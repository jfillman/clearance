package main

import (
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
	if _, err := ParseConfig(get(map[string]string{"CLEARANCE_WAIT_CA_CONFIGMAP": "Bad Name"})); err == nil {
		t.Fatal("a bad ConfigMap name must be refused")
	}
}
