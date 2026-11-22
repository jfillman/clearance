//go:build linux

package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const tokenSecret = "s3cr3t-clearance-token-value"

// tokenFixture writes a token file (valid YAML, so a tool that reads it as a resource would put it in the render) in a
// directory of its own and points the sandbox at it.
func tokenFixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tokens", "clearance")
	writeFile(t, p, "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: stolen}\ndata: {token: "+tokenSecret+"}\n")
	withFS(t, NetnsTry, p)
	return p
}

// needLandlock skips where the kernel has no Landlock, except in CI, which must have it so these tests prove something.
func needLandlock(t *testing.T) {
	t.Helper()
	if FSSandboxState() != "on" {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI must have Landlock: %v", fsSandboxCause())
		}
		t.Skipf("this kernel has no usable Landlock: %v", fsSandboxCause())
	}
}

func noSecret(t *testing.T, what string, out []byte, err error) {
	t.Helper()
	if strings.Contains(string(out), tokenSecret) || (err != nil && strings.Contains(err.Error(), tokenSecret)) {
		t.Fatalf("%s: the token reached the step's output or error", what)
	}
}

// X6: a render step cannot read the token file. The control (the same command, unsandboxed, as the same user) reads
// it, so the assertion is not vacuous; a file in the source directory stays readable, so the sandbox is not simply
// refusing everything.
func TestRenderStepCannotReadTheToken(t *testing.T) {
	token := tokenFixture(t)
	withNetns(t, NetnsOff)
	SetFSSandbox(NetnsTry, token)
	needLandlock(t)
	ctx, b := budgetCtx(t, DefaultLimits())
	writeFile(t, filepath.Join(b.src, "values.yaml"), "ok: true\n")
	fakeTool(t, "helm", `cat "$1"`)

	ctl, err := exec.Command("cat", token).Output()
	if err != nil || !strings.Contains(string(ctl), tokenSecret) {
		t.Fatalf("control: the token is not readable by this user unsandboxed: %v", err)
	}
	// with a render's budget (the plugin's own path)
	out, err := OSRun(ctx, b.src, nil, "helm", token)
	if err == nil {
		t.Fatalf("a render step read the token:\n%s", out)
	}
	noSecret(t, "helm", out, err)
	if !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("want EACCES, got %v", err)
	}
	if out, err := OSRun(ctx, b.src, nil, "helm", filepath.Join(b.src, "values.yaml")); err != nil || string(out) != "ok: true\n" {
		t.Fatalf("the source directory is not readable under the sandbox: %v %q", err, out)
	}
	// git, too, and a step outside a render (the chart tag lookup), with the token under the system temp directory
	fakeTool(t, "git", `cat "$1"`)
	out, err = OSRun(context.Background(), t.TempDir(), nil, "git", token)
	if err == nil {
		t.Fatal("a step outside a render read the token")
	}
	noSecret(t, "git", out, err)
	// and what the step starts inherits the rules
	fakeTool(t, "kustomize", `sh -c 'cat "$1"' x "$1"`)
	out, err = OSRun(ctx, b.src, nil, "kustomize", token)
	if err == nil {
		t.Fatal("a child of a render step read the token")
	}
	noSecret(t, "kustomize child", out, err)
	// nor can it read the plugin's environment or memory (Landlock scopes ptrace to the step's own domain)
	fakeTool(t, "helm", `cat /proc/$PPID/environ /proc/`+strconv.Itoa(os.Getpid())+`/environ`)
	out, err = OSRun(ctx, b.src, nil, "helm", "x")
	if err == nil && len(out) > 0 {
		t.Fatalf("a render step read the plugin's environment:\n%q", out)
	}
}

// The real kustomize, told to load a resource from anywhere (a kustomize.buildOptions an operator might set), puts the
// token in the render without the sandbox and cannot read it with it.
func TestRealKustomizeCannotReadTheToken(t *testing.T) {
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize is not installed")
	}
	token := tokenFixture(t)
	withNetns(t, NetnsOff)
	SetFSSandbox(NetnsTry, token)
	needLandlock(t)
	ctx, b := budgetCtx(t, DefaultLimits())
	writeFile(t, filepath.Join(b.src, "kz", "kustomization.yaml"), "resources:\n- "+token+"\n")
	args := []string{"build", "--load-restrictor", "LoadRestrictionsNone", filepath.Join(b.src, "kz")}
	ctl, err := exec.Command("kustomize", args...).Output()
	if err != nil || !strings.Contains(string(ctl), tokenSecret) {
		t.Fatalf("control: unsandboxed kustomize did not render the token: %v\n%s", err, ctl)
	}
	out, err := OSRun(ctx, b.src, nil, "kustomize", args...)
	if err == nil {
		t.Fatalf("kustomize rendered under the sandbox:\n%s", out)
	}
	noSecret(t, "kustomize", out, err)
}

// The real helm follows a template that is a symlink to the token (the kind of link the plugin's own containment check
// refuses before helm runs: this is the layer under it).
func TestRealHelmCannotReadTheTokenThroughASymlink(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	token := tokenFixture(t)
	withNetns(t, NetnsOff)
	SetFSSandbox(NetnsTry, token)
	needLandlock(t)
	ctx, b := budgetCtx(t, DefaultLimits())
	chart := filepath.Join(b.src, "chart")
	writeFile(t, filepath.Join(chart, "Chart.yaml"), "apiVersion: v2\nname: c\nversion: 0.1.0\n")
	if err := os.MkdirAll(filepath.Join(chart, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(token, filepath.Join(chart, "templates", "stolen.yaml")); err != nil {
		t.Fatal(err)
	}
	home := []string{"HELM_CACHE_HOME=" + filepath.Join(b.root, "c"), "HELM_CONFIG_HOME=" + filepath.Join(b.root, "f"), "HELM_DATA_HOME=" + filepath.Join(b.root, "d")}
	if err := bare(t, chart, home, "helm", "template", "x", "."); err != nil {
		t.Fatalf("control: unsandboxed helm failed: %v", err)
	}
	ctl := exec.Command("helm", "template", "x", ".")
	ctl.Dir, ctl.Env = chart, append(os.Environ(), home...)
	if o, _ := ctl.Output(); !strings.Contains(string(o), tokenSecret) {
		t.Fatalf("control: unsandboxed helm did not render the token:\n%s", o)
	}
	out, err := OSRun(ctx, chart, home, "helm", "template", "x", ".")
	if err == nil {
		t.Fatalf("helm rendered under the sandbox:\n%s", out)
	}
	noSecret(t, "helm", out, err)
}

// X7: a step that burns CPU past its bound is stopped by RLIMIT_CPU, and the error says so.
func TestCPUBoundStopsAStep(t *testing.T) {
	withFS(t, NetnsTry, "")
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "helm"), []byte("#!/bin/bash\nwhile :; do :; done\n"), 0o755)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	lim := DefaultLimits()
	lim.CPU = time.Second
	ctx, _ := budgetCtx(t, lim)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	start := time.Now()
	_, err := OSRun(ctx, t.TempDir(), nil, "helm", "template", "x", ".")
	le := asLimit(t, err, LimitCPU)
	if le.Setting != EnvMaxCPU || time.Since(start) > 15*time.Second {
		t.Fatalf("%+v after %s", le, time.Since(start))
	}
}

// X7: a step that allocates past its memory bound (here the test binary itself, a Go program like helm) fails at
// RLIMIT_DATA with the memory class; with room it completes, so the bound is what stopped it.
func TestMemoryBoundStopsAStep(t *testing.T) {
	if raceEnabled {
		t.Skip("the hog is this test binary, and a race-built one cannot start under RLIMIT_DATA (CI runs this test without -race)")
	}
	withFS(t, NetnsOff, "")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(filepath.Join(dir, "helm"), os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	dst.Close()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	lim := DefaultLimits()
	lim.Memory = 128 << 20
	ctx, _ := budgetCtx(t, lim)
	_, err = OSRun(ctx, t.TempDir(), []string{"CMP_TEST_HOG=memory"}, "helm", "template")
	le := asLimit(t, err, LimitMemory)
	if le.Bound != "128Mi" {
		t.Fatalf("%+v", le)
	}
	lim.Memory = 1 << 30
	ctx, _ = budgetCtx(t, lim)
	if _, err := OSRun(ctx, t.TempDir(), []string{"CMP_TEST_HOG=memory"}, "helm", "template"); err != nil {
		t.Fatalf("with room the same step fails: %v", err)
	}
}
