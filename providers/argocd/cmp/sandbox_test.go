package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeBin puts executables that print their environment first on PATH.
func fakeBin(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/sh\nenv\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// helm template and kustomize build (and edit) are run with the network off, git and helm pull are not.
func TestOSRunTakesTheNetworkAwayFromTheRenderStep(t *testing.T) {
	fakeBin(t, "helm", "kustomize", "git")
	for _, c := range []struct {
		name string
		args []string
		off  bool
	}{
		{"helm", []string{"template", "x", "."}, true},
		{"helm", []string{"dependency", "build", "--skip-refresh"}, true},
		{"kustomize", []string{"build", "."}, true},
		{"kustomize", []string{"edit", "add", "component", "c"}, true},
		{"helm", []string{"pull", "--repo", "https://charts.example.test", "app"}, false},
		{"git", []string{"clone", "--", "https://github.com/o/r.git", "d"}, false},
	} {
		out, err := OSRun(context.Background(), t.TempDir(), nil, c.name, c.args...)
		if err != nil {
			t.Fatal(c.name, c.args, err)
		}
		env := "\n" + string(out)
		for _, w := range []string{"GIT_ALLOW_PROTOCOL=none", "HTTP_PROXY=http://127.0.0.1:9", "HTTPS_PROXY=http://127.0.0.1:9", "ALL_PROXY=http://127.0.0.1:9",
			"http_proxy=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9", "all_proxy=http://127.0.0.1:9", "NO_PROXY=\n", "no_proxy=\n",
			"HELM_REPOSITORY_CONFIG=", "HELM_REPOSITORY_CACHE=", "HELM_REGISTRY_CONFIG="} {
			if got := strings.Contains(env, "\n"+w); got != c.off {
				t.Errorf("%s %v: %q present=%v, want %v", c.name, c.args, w, got, c.off)
			}
		}
	}
}

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// With the real helm: a chart whose Chart.yaml names a dependency on an unlisted HTTP repository cannot be built, and
// a chart that is local only (a file:// dependency) renders.
func TestRealHelmCannotReachAnUnlistedDependencyButRendersALocalChart(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "lib/Chart.yaml"), "apiVersion: v2\nname: lib\nversion: 0.1.0\n")
	writeFile(t, filepath.Join(root, "lib/templates/cm.yaml"), "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: lib}\n")
	writeFile(t, filepath.Join(root, "local/Chart.yaml"), "apiVersion: v2\nname: local\nversion: 0.1.0\ndependencies:\n- name: lib\n  version: 0.1.0\n  repository: file://../lib\n")
	writeFile(t, filepath.Join(root, "evil/Chart.yaml"), "apiVersion: v2\nname: evil\nversion: 0.1.0\ndependencies:\n- name: lib\n  version: 0.1.0\n  repository: https://evil.invalid/charts\n")
	ctx := context.Background()
	home := []string{"HELM_CACHE_HOME=" + t.TempDir(), "HELM_CONFIG_HOME=" + t.TempDir(), "HELM_DATA_HOME=" + t.TempDir()}
	if _, err := OSRun(ctx, filepath.Join(root, "local"), home, "helm", "dependency", "build", "--skip-refresh"); err != nil {
		t.Fatalf("a file:// dependency builds offline: %v", err)
	}
	out, err := OSRun(ctx, filepath.Join(root, "local"), home, "helm", "template", "x", ".")
	if err != nil || !strings.Contains(string(out), "name: lib") {
		t.Fatalf("a local-only chart renders: %v\n%s", err, out)
	}
	if _, err := OSRun(ctx, filepath.Join(root, "evil"), home, "helm", "dependency", "build", "--skip-refresh"); err == nil {
		t.Fatal("a dependency on an unlisted HTTP repository was built")
	}
	if _, err := OSRun(ctx, filepath.Join(root, "evil"), home, "helm", "template", "x", "."); err == nil {
		t.Fatal("a chart with a missing remote dependency rendered")
	}
}

// With the real kustomize, when it is installed: a remote base fails, a local kustomization builds.
func TestRealKustomizeCannotFetchARemoteBaseButBuildsALocalOne(t *testing.T) {
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize is not installed")
	}
	ctx := context.Background()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "ok/cm.yaml"), "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: ok}\n")
	writeFile(t, filepath.Join(root, "ok/kustomization.yaml"), "resources:\n- cm.yaml\n")
	writeFile(t, filepath.Join(root, "bad/kustomization.yaml"), "resources:\n- https://github.com/kubernetes-sigs/kustomize//examples/helloWorld?ref=v5.0.0\n")
	if out, err := OSRun(ctx, root, nil, "kustomize", "build", filepath.Join(root, "ok")); err != nil || !strings.Contains(string(out), "name: ok") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := OSRun(ctx, root, nil, "kustomize", "build", filepath.Join(root, "bad")); err == nil {
		t.Fatal("a remote base was fetched")
	}
}
