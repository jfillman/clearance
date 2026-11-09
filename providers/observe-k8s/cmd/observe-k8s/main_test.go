package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/internal/vocab"
)

// `policy render` output passes `policy check`; a policy that records a Secret body fails it, with a non-nil error (the
// exit status the build and the operator rely on).
func TestPolicyRenderThenCheck(t *testing.T) {
	var out bytes.Buffer
	if err := policy([]string{"render", "--namespaces", "shop,payments"}, &out); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(good, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var res bytes.Buffer
	if err := policy([]string{"check", good}, &res); err != nil || !strings.Contains(res.String(), "never records a Secret body") {
		t.Fatalf("%v %s", err, res.String())
	}
	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte("apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n  - level: RequestResponse\n"), 0o600)
	res.Reset()
	if err := policy([]string{"check", bad}, &res); err == nil || !strings.Contains(res.String(), "FAIL") {
		t.Fatalf("a policy that records everything passed: %v %s", err, res.String())
	}
	if err := policy([]string{"render", "--namespaces", "bad name"}, &out); err == nil {
		t.Fatal("a bad namespace was rendered")
	}
}

// `normalize` turns a recorded export into what `clearance observe replay` reads, and the result runs.
func TestNormalizeProducesReplayInput(t *testing.T) {
	var out bytes.Buffer
	if err := normalize([]string{"--source", "eks", "--scope", "prod-1", "../../readers/testdata/eks.jsonl"}, &out); err != nil {
		t.Fatal(err)
	}
	rs, err := pipeline.Default()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := pipeline.Replay(&out, pipeline.New(rs, nil, vocab.Default()))
	if err != nil || len(rep.Assessments) != 3 {
		t.Fatalf("%v %v", err, rep)
	}
	if err := normalize([]string{"--source", "nope", "x"}, &out); err == nil {
		t.Fatal("an unknown source")
	}
}

func TestParseWatches(t *testing.T) {
	ws, err := parseWatches("v1/configmaps=ConfigMap;rbac.authorization.k8s.io/v1/clusterroles=ClusterRole,cluster;")
	if err != nil || len(ws) != 2 || ws[1].Namespaced {
		t.Fatalf("%+v %v", ws, err)
	}
	if _, err := parseWatches("v1/secrets=Secret"); err == nil {
		t.Fatal("watching Secrets must be refused")
	}
}
