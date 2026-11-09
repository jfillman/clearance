package charttest

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
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
	base := []string{"--set", "account=1", "--set", "apiURL=a", "--set", "coreURL=c", "--set", "queueURL=q", "--set", "aws.roleARN=r"}
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
