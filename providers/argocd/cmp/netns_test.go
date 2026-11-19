package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// marker puts a fake helm and kustomize on PATH that leave a file behind when they run.
func marker(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	m := filepath.Join(dir, "ran")
	for _, n := range []string{"helm", "kustomize"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/sh\ntouch '"+m+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return m
}

func failIsolate(t *testing.T) {
	t.Helper()
	old := isolate
	isolate = func(*exec.Cmd) (bool, error) { return false, errors.New("injected: operation not permitted") }
	t.Cleanup(func() { isolate = old })
}

// When the namespace cannot be created the plugin refuses to render, names the missing capability, and never runs
// the tool.
func TestRenderFailsClosedWithoutANetworkNamespace(t *testing.T) {
	m := marker(t)
	failIsolate(t)
	t.Setenv(AllowNoNetnsEnv, "")
	for _, c := range [][]string{{"helm", "template", "x", "."}, {"helm", "dependency", "build", "--skip-refresh"}, {"kustomize", "build", "."}} {
		_, err := OSRun(context.Background(), t.TempDir(), nil, c[0], c[1:]...)
		if err == nil {
			t.Fatalf("%v rendered without a network namespace", c)
		}
		for _, want := range []string{"private network namespace", "CLONE_NEWUSER", AllowNoNetnsEnv} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%v: error does not mention %q: %v", c, want, err)
			}
		}
	}
	if _, err := os.Stat(m); err == nil {
		t.Fatal("a render tool ran although the namespace could not be created")
	}
}

// Only a command that is not a render step (helm pull, git: the plugin's own fetches) keeps the network and needs no
// namespace.
func TestFetchesNeedNoNetworkNamespace(t *testing.T) {
	m := marker(t)
	failIsolate(t)
	t.Setenv(AllowNoNetnsEnv, "")
	if _, err := OSRun(context.Background(), t.TempDir(), nil, "helm", "pull", "--repo", "https://charts.example.test", "app"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m); err != nil {
		t.Fatal("helm pull did not run")
	}
}

// The explicit switch lets the render run without the namespace; anything but "true" stays closed.
func TestExplicitSwitchAllowsRenderWithoutNetworkNamespace(t *testing.T) {
	m := marker(t)
	failIsolate(t)
	t.Setenv(AllowNoNetnsEnv, "true")
	if _, err := OSRun(context.Background(), t.TempDir(), nil, "kustomize", "build", "."); err != nil {
		t.Fatalf("with %s=true: %v", AllowNoNetnsEnv, err)
	}
	if _, err := os.Stat(m); err != nil {
		t.Fatal("kustomize did not run")
	}
	for _, v := range []string{"yes", "TRUE", "True", "1"} {
		t.Setenv(AllowNoNetnsEnv, v)
		os.Remove(m)
		if _, err := OSRun(context.Background(), t.TempDir(), nil, "kustomize", "build", "."); err == nil {
			t.Fatalf("%q opened the switch; only exactly \"true\" does", v)
		}
	}
}
