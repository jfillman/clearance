package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
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
		eff := effective(strings.Split(strings.TrimSpace(string(out)), "\n"))
		want := map[string]string{"GIT_ALLOW_PROTOCOL": "none", "NO_PROXY": "", "no_proxy": ""}
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
			want[k] = "http://127.0.0.1:9"
		}
		for k, v := range want {
			if got, set := eff[k]; set != c.off || (c.off && got != v) {
				t.Errorf("%s %v: %s = %q (set %v), want off=%v value %q", c.name, c.args, k, got, set, c.off, v)
			}
		}
		for _, k := range []string{"HELM_REPOSITORY_CONFIG", "HELM_REPOSITORY_CACHE", "HELM_REGISTRY_CONFIG"} {
			if _, set := eff[k]; set != c.off {
				t.Errorf("%s %v: %s set=%v, want %v", c.name, c.args, k, set, c.off)
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

// listener is a test-owned HTTP endpoint on a non-loopback address of this machine (Go clients do not proxy loopback,
// so a loopback endpoint would be reached with or without the restriction). It counts the requests it gets.
func listener(t *testing.T) (host string, hits func() int32) {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	var ip string
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			ip = n.IP.String()
			break
		}
	}
	if ip == "" {
		t.Skip("no non-loopback IPv4 address to bind a test endpoint on")
	}
	l, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Skip("cannot bind", ip, err)
	}
	var n atomic.Int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.NotFound(w, r)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String(), func() int32 { return n.Load() }
}

// bare runs a command on this machine with no sandbox: the control that shows the endpoint is reachable.
func bare(t *testing.T, dir string, env []string, name string, args ...string) error {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}, env...)
	_, err := cmd.CombinedOutput()
	return err
}

// With the real helm: a dependency on an HTTP repository (a test endpoint) is reached without the sandbox and never
// reached with it, and a chart that is local only renders either way.
func TestRealHelmDoesNotReachAnHTTPDependencyUnderTheSandbox(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	host, hits := listener(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "lib/Chart.yaml"), "apiVersion: v2\nname: lib\nversion: 0.1.0\n")
	writeFile(t, filepath.Join(root, "lib/templates/cm.yaml"), "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: lib}\n")
	writeFile(t, filepath.Join(root, "local/Chart.yaml"), "apiVersion: v2\nname: local\nversion: 0.1.0\ndependencies:\n- name: lib\n  version: 0.1.0\n  repository: file://../lib\n")
	writeFile(t, filepath.Join(root, "remote/Chart.yaml"), "apiVersion: v2\nname: remote\nversion: 0.1.0\ndependencies:\n- name: lib\n  version: 0.1.0\n  repository: http://"+host+"/charts\n")
	home := []string{"HELM_CACHE_HOME=" + t.TempDir(), "HELM_CONFIG_HOME=" + t.TempDir(), "HELM_DATA_HOME=" + t.TempDir()}
	ctx := context.Background()

	// positive control: a local-only chart builds and renders under the sandbox
	if _, err := OSRun(ctx, filepath.Join(root, "local"), home, "helm", "dependency", "build"); err != nil {
		t.Fatalf("a file:// dependency builds under the sandbox: %v", err)
	}
	out, err := OSRun(ctx, filepath.Join(root, "local"), home, "helm", "template", "x", ".")
	if err != nil || !strings.Contains(string(out), "name: lib") {
		t.Fatalf("a local-only chart renders: %v\n%s", err, out)
	}
	// control: without the sandbox the endpoint is reached (the test would prove nothing otherwise)
	_ = bare(t, filepath.Join(root, "remote"), home, "helm", "dependency", "build")
	if hits() == 0 {
		t.Fatalf("control: an unsandboxed helm never reached the test endpoint %s", host)
	}
	before := hits()
	// the sandbox: the same command is refused without the endpoint seeing anything
	if _, err := OSRun(ctx, filepath.Join(root, "remote"), home, "helm", "dependency", "build"); err == nil {
		t.Fatal("a dependency on an unlisted HTTP repository was built")
	}
	if _, err := OSRun(ctx, filepath.Join(root, "remote"), home, "helm", "template", "x", "."); err == nil {
		t.Fatal("a chart with a missing remote dependency rendered")
	}
	if got := hits(); got != before {
		t.Fatalf("the sandboxed helm sent %d requests to the test endpoint", got-before)
	}
}

// With the real kustomize, when it is installed: an HTTP resource on a test endpoint is fetched without the sandbox and
// never with it; a local kustomization builds either way.
func TestRealKustomizeDoesNotFetchAnHTTPBaseUnderTheSandbox(t *testing.T) {
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize is not installed")
	}
	host, hits := listener(t)
	ctx := context.Background()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "ok/cm.yaml"), "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: ok}\n")
	writeFile(t, filepath.Join(root, "ok/kustomization.yaml"), "resources:\n- cm.yaml\n")
	writeFile(t, filepath.Join(root, "bad/kustomization.yaml"), "resources:\n- http://"+host+"/base.yaml\n")
	if out, err := OSRun(ctx, root, nil, "kustomize", "build", filepath.Join(root, "ok")); err != nil || !strings.Contains(string(out), "name: ok") {
		t.Fatalf("%v\n%s", err, out)
	}
	_ = bare(t, root, nil, "kustomize", "build", filepath.Join(root, "bad"))
	if hits() == 0 {
		t.Fatalf("control: an unsandboxed kustomize never reached the test endpoint %s", host)
	}
	before := hits()
	if _, err := OSRun(ctx, root, nil, "kustomize", "build", filepath.Join(root, "bad")); err == nil {
		t.Fatal("a remote base was fetched")
	}
	if got := hits(); got != before {
		t.Fatalf("the sandboxed kustomize sent %d requests to the test endpoint", got-before)
	}
}
