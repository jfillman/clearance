package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// marker puts a fake helm and kustomize on PATH that append a line to a file when they run.
func marker(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	m := filepath.Join(dir, "ran")
	for _, n := range []string{"helm", "kustomize"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/sh\necho x >> '"+m+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return m
}

func runs(m string) int {
	b, _ := os.ReadFile(m)
	return strings.Count(string(b), "x")
}

// netnsMode sets the mode for one test, captures the warning and restores the defaults afterwards.
func withNetns(t *testing.T, mode string) *bytes.Buffer {
	t.Helper()
	var w bytes.Buffer
	oldW, oldI := netnsWarn, isolate
	netnsWarn = &w
	SetNetns(mode)
	t.Cleanup(func() { netnsWarn, isolate = oldW, oldI; SetNetns("") })
	return &w
}

// refuse makes every namespace attempt fail, counting the attempts.
func refuse(t *testing.T) *int {
	t.Helper()
	n := 0
	isolate = func(*exec.Cmd) (bool, error) { n++; return false, errors.New("injected: operation not permitted") }
	return &n
}

func kustomizeBuild(t *testing.T) error {
	t.Helper()
	_, err := OSRun(context.Background(), t.TempDir(), nil, "kustomize", "build", ".")
	return err
}

// try, the default (and with the value unset): the kernel refuses, the render runs without the namespace, one warning
// for the whole process, one attempt only, and the state says so.
func TestTryRendersWithoutTheNamespaceAndWarnsOnce(t *testing.T) {
	m := marker(t)
	w := withNetns(t, NetnsTry)
	attempts := refuse(t)
	for i := 0; i < 3; i++ {
		if err := kustomizeBuild(t); err != nil {
			t.Fatal(err)
		}
	}
	if runs(m) != 3 {
		t.Fatalf("the tool ran %d times, want 3", runs(m))
	}
	if got := strings.Count(w.String(), "WITHOUT a private network namespace"); got != 1 {
		t.Fatalf("%d warnings, want 1:\n%s", got, w.String())
	}
	for _, want := range []string{NetnsEnv + "=" + NetnsRequire, "CLONE_NEWUSER", "operation not permitted"} {
		if !strings.Contains(w.String(), want) {
			t.Errorf("the warning lacks %q: %s", want, w.String())
		}
	}
	if *attempts != 1 {
		t.Fatalf("the kernel was asked %d times, want once per process", *attempts)
	}
	if s := NetnsState(); s != "unavailable" {
		t.Fatalf("state %q, want unavailable", s)
	}
}

// require: refused means fail closed, the tool never runs, and the error names the capability.
func TestRequireFailsClosedWithoutANetworkNamespace(t *testing.T) {
	m := marker(t)
	w := withNetns(t, NetnsRequire)
	refuse(t)
	for _, c := range [][]string{{"helm", "template", "x", "."}, {"helm", "dependency", "build", "--skip-refresh"}, {"kustomize", "build", "."}} {
		_, err := OSRun(context.Background(), t.TempDir(), nil, c[0], c[1:]...)
		if err == nil {
			t.Fatalf("%v rendered without a network namespace", c)
		}
		for _, want := range []string{"private network namespace", "CLONE_NEWUSER", NetnsEnv} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%v: error does not mention %q: %v", c, want, err)
			}
		}
	}
	if runs(m) != 0 {
		t.Fatal("a render tool ran although the namespace could not be created")
	}
	if w.Len() != 0 {
		t.Fatalf("require printed a fallback warning: %s", w.String())
	}
}

// off: the namespace is never attempted, the render runs, and the state says off.
func TestOffNeverAttemptsTheNamespace(t *testing.T) {
	m := marker(t)
	w := withNetns(t, NetnsOff)
	attempts := refuse(t)
	if err := kustomizeBuild(t); err != nil {
		t.Fatal(err)
	}
	if *attempts != 0 || runs(m) != 1 || w.Len() != 0 {
		t.Fatalf("attempts %d, runs %d, warning %q", *attempts, runs(m), w.String())
	}
	if s := NetnsState(); s != "off" {
		t.Fatalf("state %q, want off", s)
	}
}

// The plugin's own fetches (helm pull, git) are not render steps: no namespace, no attempt, even under require.
func TestFetchesNeedNoNetworkNamespace(t *testing.T) {
	m := marker(t)
	withNetns(t, NetnsRequire)
	attempts := refuse(t)
	if _, err := OSRun(context.Background(), t.TempDir(), nil, "helm", "pull", "--repo", "https://charts.example.test", "app"); err != nil {
		t.Fatal(err)
	}
	if runs(m) != 1 || *attempts != 0 {
		t.Fatalf("runs %d, attempts %d", runs(m), *attempts)
	}
}

// Only the three exact values are accepted, at ParseConfig, so a typo stops the plugin at start.
func TestNetnsSettingIsParsedStrictly(t *testing.T) {
	for v, want := range map[string]string{"": NetnsTry, "try": NetnsTry, "require": NetnsRequire, "off": NetnsOff} {
		if got, err := ParseNetns(v); err != nil || got != want {
			t.Errorf("%q: %q, %v", v, got, err)
		}
	}
	base := map[string]string{"ARGOCD_APP_NAME": "gate-api-prod", "ARGOCD_APP_NAMESPACE": "app-gate-api-prod", "ARGOCD_APP_REVISION": mergeSHA,
		"ARGOCD_APP_SOURCE_REPO_URL": "git@github.com:Jfillman/gitops-gate-api.git", "PARAM_APP": "gate-api", "PARAM_ENV": "prod", "PARAM_CLUSTER": "hangar-prod",
		"PARAM_CHARTREPO": "https://github.com/jfillman/airframe.git", "PARAM_CHARTREVISION": "v0.3.168", "PARAM_CHARTPATH": "charts/airframe-application",
		"CLEARANCE_CHART_REPOS": "https://github.com/jfillman/airframe.git", "CLEARANCE_URL": "http://clearance.test"}
	for _, v := range []string{"TRUE", "Require", "on", "true", "1", "required"} {
		base[NetnsEnv] = v
		_, err := ParseConfig(func(k string) string { return base[k] })
		if err == nil {
			t.Fatalf("%q accepted", v)
		}
		for _, want := range []string{"try", "require", "off"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q: the message does not list %q: %v", v, want, err)
			}
		}
	}
	base[NetnsEnv] = "require"
	if c, err := ParseConfig(func(k string) string { return base[k] }); err != nil || c.Netns != NetnsRequire {
		t.Fatal(c.Netns, err)
	}
}
