//go:build linux

package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// loopbackListener counts connections accepted on 127.0.0.1.
func loopbackListener(t *testing.T) (port string, conns func() int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot bind loopback:", err)
	}
	var n atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { l.Close() })
	_, p, _ := net.SplitHostPort(l.Addr().String())
	return p, func() int32 { return n.Load() }
}

// A render step (here a stand-in `kustomize` that dials the listener with bash's /dev/tcp) cannot reach a service on
// the sidecar's own loopback, which Go clients' proxy settings never cover. The control, the same script unsandboxed,
// does reach it, so the assertion is not vacuous.
func TestRenderStepCannotReachLoopback(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	port, conns := loopbackListener(t)
	bin := t.TempDir()
	script := "#!/bin/bash\nexec 3<>/dev/tcp/127.0.0.1/" + port + "\n"
	if err := os.WriteFile(filepath.Join(bin, "kustomize"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	// control: unsandboxed, the dial succeeds and the listener sees it
	ctl := exec.Command(filepath.Join(bin, "kustomize"))
	if err := ctl.Run(); err != nil {
		t.Fatalf("control: the unsandboxed dial failed: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for conns() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if conns() == 0 {
		t.Fatal("control: the listener saw no connection from an unsandboxed process")
	}
	before := conns()

	_, err := OSRun(context.Background(), t.TempDir(), nil, "kustomize", "build", ".")
	if err == nil {
		t.Fatal("the sandboxed render step connected to loopback")
	}
	if strings.Contains(err.Error(), "private network namespace") {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI must allow unprivileged user namespaces: %v", err)
		}
		t.Skipf("this machine cannot create a user+network namespace: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := conns(); got != before {
		t.Fatalf("the listener saw %d connection(s) from the sandboxed render step", got-before)
	}
}

// badNamespace makes the kernel refuse the namespace at Start (a uid mapping to a host id this process may not map),
// the way a seccomp profile or sysctl would.
func badNamespace(t *testing.T) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("root may map any id")
	}
	old := isolate
	isolate = func(cmd *exec.Cmd) (bool, error) {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid() + 1, Size: 1}},
		}
		return true, nil
	}
	t.Cleanup(func() { isolate = old })
}

// A namespace the kernel refuses at Start fails closed by default, and with the explicit switch the tool runs once,
// in a fresh unisolated attempt.
func TestStartTimeNamespaceFailureFailsClosedUnlessSwitched(t *testing.T) {
	badNamespace(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "runs")
	script := "#!/bin/sh\necho x >> '" + log + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "kustomize"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	t.Setenv(AllowNoNetnsEnv, "")
	_, err := OSRun(context.Background(), t.TempDir(), nil, "kustomize", "build", ".")
	if err == nil || !strings.Contains(err.Error(), "private network namespace") {
		t.Fatalf("want the namespace refusal, got %v", err)
	}
	if _, e := os.Stat(log); e == nil {
		t.Fatal("the tool ran although the namespace was refused")
	}

	t.Setenv(AllowNoNetnsEnv, "true")
	if _, err := OSRun(context.Background(), t.TempDir(), nil, "kustomize", "build", "."); err != nil {
		t.Fatalf("with the switch: %v", err)
	}
	b, _ := os.ReadFile(log)
	if got := strings.Count(string(b), "x"); got != 1 {
		t.Fatalf("the tool ran %d times, want 1", got)
	}
}
