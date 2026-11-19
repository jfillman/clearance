//go:build linux

package main

import (
	"bytes"
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
	withNetns(t, NetnsTry) // the default
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

	if NetnsState() != "on" {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI must allow unprivileged user namespaces: state %s", NetnsState())
		}
		t.Skipf("this machine cannot create a user+network namespace: state %s", NetnsState())
	}
	if _, err := OSRun(context.Background(), t.TempDir(), nil, "kustomize", "build", "."); err == nil {
		t.Fatal("the sandboxed render step connected to loopback")
	}
	time.Sleep(200 * time.Millisecond)
	if got := conns(); got != before {
		t.Fatalf("the listener saw %d connection(s) from the sandboxed render step", got-before)
	}
}

// A namespace the kernel refuses at Start (after a good probe): require fails closed and never runs the tool; try
// runs it once in a fresh attempt without the namespace, warns, and remembers.
func TestStartTimeNamespaceRefusal(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "runs")
	script := "#!/bin/sh\necho x >> '" + log + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "kustomize"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	run := func() error {
		_, err := OSRun(context.Background(), t.TempDir(), nil, "kustomize", "build", ".")
		return err
	}
	// the probe succeeds (the real isolateNetwork is in place for it) and only the render's own start is refused
	setup := func(mode string) *bytes.Buffer {
		w := withNetns(t, mode)
		if os.Getuid() == 0 {
			t.Skip("root may map any id")
		}
		real := isolateNetwork
		first := true
		isolate = func(cmd *exec.Cmd) (bool, error) {
			if first { // the probe
				first = false
				return real(cmd)
			}
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
				UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid() + 1, Size: 1}},
			}
			return true, nil
		}
		return w
	}
	setup(NetnsRequire)
	if err := run(); err == nil || !strings.Contains(err.Error(), "private network namespace") {
		if NetnsState() != "on" {
			t.Skip("this machine cannot create a user+network namespace")
		}
		t.Fatalf("require: want the namespace refusal, got %v", err)
	}
	if _, e := os.Stat(log); e == nil {
		t.Fatal("require: the tool ran although the namespace was refused")
	}

	w := setup(NetnsTry)
	if NetnsState() != "on" { // the probe (real function) must succeed, so the render's own start is what is refused
		t.Skip("this machine cannot create a user+network namespace")
	}
	if err := run(); err != nil {
		t.Fatalf("try: %v", err)
	}
	if err := run(); err != nil {
		t.Fatalf("try, second render: %v", err)
	}
	b, _ := os.ReadFile(log)
	if got := strings.Count(string(b), "x"); got != 2 {
		t.Fatalf("the tool ran %d times, want 2", got)
	}
	if got := strings.Count(w.String(), "WITHOUT a private network namespace"); got != 1 {
		t.Fatalf("%d warnings, want 1: %s", got, w.String())
	}
	if NetnsState() != "unavailable" {
		t.Fatalf("state %s", NetnsState())
	}
}
