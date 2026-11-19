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
