//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A descendant that detaches from the step's process group (setsid: a session and a group of its own) is still
// killed: it is re-parented to the plugin, the child subreaper, and reaped after the step.
func TestADetachedDescendantDoesNotOutliveItsStep(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is not installed")
	}
	withFS(t, NetnsOff, "")
	pidFile := filepath.Join(t.TempDir(), "pid")
	// A grandchild in a new session: the step's shell exits at once, the detached sleep would live on.
	fakeTool(t, "helm", `(setsid sleep 300 >/dev/null 2>&1 </dev/null & echo $! > '`+pidFile+`') ; exit 0`)
	if _, err := OSRun(context.Background(), t.TempDir(), nil, "helm", "template", "x", "."); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(pidFile)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("no pid: %q", b)
	}
	for i := 0; i < 100 && syscall.Kill(pid, 0) == nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if syscall.Kill(pid, 0) == nil {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("a descendant in its own session outlived its step")
	}
}

// The Landlock probe needs nothing outside the plugin binary: with no `true` on PATH it still installs a ruleset in a
// child and reports on.
func TestTheLandlockProbeNeedsNoToolOnPath(t *testing.T) {
	withNetns(t, NetnsOff)
	withFS(t, NetnsTry, "")
	needLandlock(t)
	t.Setenv("PATH", t.TempDir())
	SetFSSandbox(NetnsTry, "")
	if FSSandboxState() != "on" {
		t.Fatalf("with an empty PATH the probe says %s (%v)", FSSandboxState(), fsSandboxCause())
	}
}
