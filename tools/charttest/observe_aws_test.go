package charttest

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/jfillman/clearance/internal/observe/pipeline"
)

// charts/clearance-observe-aws (O-4): the collector's chart renders a read-only, no-stored-credential Deployment.
func observeHelm(t *testing.T, args ...string) (string, error) {
	t.Helper()
	bin, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not on PATH")
	}
	var out, errb bytes.Buffer
	cmd := exec.Command(bin, append([]string{"template", "t", "../../charts/clearance-observe-aws", "--namespace", "clearance"}, args...)...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return errb.String(), err
	}
	return out.String(), nil
}

func TestObserveAWSChartRendersWithNoStoredCredential(t *testing.T) {
	text, err := observeHelm(t, "-f", "../../charts/clearance-observe-aws/ci/minimal-values.yaml")
	if err != nil {
		t.Fatal(text)
	}
	dec := yaml.NewDecoder(strings.NewReader(text))
	var dep obj
	kinds := map[string]bool{}
	for {
		var o obj
		if err := dec.Decode(&o); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		kinds[o["kind"].(string)] = true
		if o["kind"] == "Deployment" {
			dep = o
		}
	}
	for _, k := range []string{"Deployment", "ServiceAccount", "ConfigMap", "NetworkPolicy"} {
		if !kinds[k] {
			t.Errorf("no %s rendered", k)
		}
	}
	for _, k := range []string{"Role", "ClusterRole", "Secret"} {
		if kinds[k] {
			t.Errorf("the collector needs no %s", k)
		}
	}
	if get(dep, "spec", "replicas") != 1 || get(dep, "spec", "template", "spec", "automountServiceAccountToken") != false {
		t.Errorf("one replica, no Kubernetes API token")
	}
	vols := get(dep, "spec", "template", "spec", "volumes").([]any)
	var aud []string
	for _, v := range vols {
		for _, s := range asSlice(get(v.(obj), "projected", "sources")) {
			aud = append(aud, get(s.(obj), "serviceAccountToken", "audience").(string))
		}
	}
	if strings.Join(aud, ",") != "clearance,sts.amazonaws.com" {
		t.Errorf("projected token audiences %v", aud)
	}
	env := get(dep, "spec", "template", "spec", "containers", 0, "env").([]any)
	for _, e := range env {
		if n := e.(obj)["name"].(string); strings.Contains(n, "SECRET") || strings.Contains(n, "ACCESS_KEY") {
			t.Errorf("a credential in the environment: %s", n)
		}
	}
}

func asSlice(v any) []any { s, _ := v.([]any); return s }

func TestObserveAWSChartRefusesWhatItCannotRun(t *testing.T) {
	base := []string{"--set", "account=1", "--set", "apiURL=a", "--set", "coreURL=c", "--set", "queueURL=q", "--set", "aws.roleARN=r", "--set", "ruleset.applyRoles={a}"}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no account":      {[]string{"--set", "apiURL=a"}, "account is required"},
		"trail no role":   {append(append([]string{}, base...), "--set", "trail.bucket=b", "--set", "trail.prefix=p/"), "aws.trailRoleARN is required"},
		"trail no prefix": {append(append([]string{}, base...), "--set", "trail.bucket=b", "--set", "aws.trailRoleARN=x"), "trail.prefix is required"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := observeHelm(t, tc.args...)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("want a refusal mentioning %q, got %v %s", tc.want, err, out)
			}
		})
	}
	if out, err := observeHelm(t, base...); err != nil {
		t.Fatalf("the minimal chart without a trail renders: %s", out)
	}
}

// The rule set the AWS chart renders loads in the pipeline, names the values' apply roles, SSO admin roles and accounts,
// and is the pipeline's default everywhere else: its attribute, classify, correlate and monitoring sections cannot drift.
func TestObserveAWSChartRulesAreTheDefaultsPlusTheValues(t *testing.T) {
	const chart = "../../charts/clearance-observe-aws/ci/minimal-values.yaml"
	rulesOfRender := func(args ...string) map[string]any {
		t.Helper()
		text, err := observeHelm(t, append([]string{"-f", chart}, args...)...)
		if err != nil {
			t.Fatal(text)
		}
		dec := yaml.NewDecoder(strings.NewReader(text))
		for {
			var o obj
			if err := dec.Decode(&o); errors.Is(err, io.EOF) {
				t.Fatal("no clearance-observe-aws-rules ConfigMap rendered")
			} else if err != nil {
				t.Fatal(err)
			}
			if o["kind"] == "ConfigMap" && get(o, "metadata", "name") == "clearance-observe-aws-rules" {
				doc, _ := get(o, "data", "rules.yaml").(string)
				if _, err := pipeline.Load([]byte(doc)); err != nil {
					t.Fatalf("the rendered rule set does not load: %v\n%s", err, doc)
				}
				var m map[string]any
				if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
					t.Fatal(err)
				}
				return m
			}
		}
	}
	var def map[string]any
	if err := yaml.Unmarshal(pipeline.DefaultRules(), &def); err != nil {
		t.Fatal(err)
	}
	got := rulesOfRender()
	for _, k := range []string{"attribute", "classify", "correlate", "monitoring", "cost_limit", "schema", "annotations"} {
		if !reflect.DeepEqual(got[k], def[k]) || got[k] == nil {
			t.Errorf("%s has drifted from internal/observe/pipeline/default.yaml:\n got %v\nwant %v", k, got[k], def[k])
		}
	}
	ids, _ := got["identities"].(map[string]any)
	defIDs, _ := def["identities"].(map[string]any)
	for k, v := range defIDs {
		if k == "apply_roles" || k == "sso_admin_roles" {
			continue
		}
		if !reflect.DeepEqual(ids[k], v) {
			t.Errorf("identities.%s = %v, want the default %v", k, ids[k], v)
		}
	}
	if !reflect.DeepEqual(ids["apply_roles"], []any{"arn:aws:iam::111122223333:role/hangar-lab-apply"}) ||
		!reflect.DeepEqual(ids["sso_admin_roles"], []any{"arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_Admin_*"}) {
		t.Errorf("identities: %v", ids)
	}
	if got["name"] != "observe-aws" || got["version"] != "2026.11.5" {
		t.Errorf("name/version %v %v", got["name"], got["version"])
	}
	if n, _ := got["noise"].([]any); len(n) != 0 {
		t.Errorf("noise: %v, want none for AWS yet", n)
	}
	want := map[string]any{"governed": []any{map[string]any{"provider": "aws", "scopes": []any{"111122223333"}}}}
	if !reflect.DeepEqual(got["scope"], want) {
		t.Errorf("scope %v, want the observed account only", got["scope"])
	}
	// governedAccounts overrides the observed account
	got = rulesOfRender("--set", "ruleset.governedAccounts={111122223333,444455556666}")
	want = map[string]any{"governed": []any{map[string]any{"provider": "aws", "scopes": []any{"111122223333", "444455556666"}}}}
	if !reflect.DeepEqual(got["scope"], want) {
		t.Errorf("scope %v", got["scope"])
	}
	// rules_bundle replaces the rendered set whole
	got = rulesOfRender("--set-file", "rules_bundle=../../internal/observe/pipeline/default.yaml")
	if got["name"] != "observe-default" {
		t.Errorf("rules_bundle did not replace the rendered set: %v", got["name"])
	}
}

func TestObserveAWSChartRequiresApplyRoles(t *testing.T) {
	out, err := observeHelm(t, "-f", "../../charts/clearance-observe-aws/ci/minimal-values.yaml", "--set", "ruleset.applyRoles=null")
	if err == nil || !strings.Contains(out, "ruleset.applyRoles is required") {
		t.Fatalf("got %v %q, want a refusal naming ruleset.applyRoles", err, out)
	}
	if out, err := observeHelm(t, "-f", "../../charts/clearance-observe-aws/ci/minimal-values.yaml", "--set", "ruleset.applyRoles=null",
		"--set", "rules_bundle=x"); err != nil {
		t.Errorf("a rules_bundle needs no applyRoles: %v %s", err, out)
	}
}
