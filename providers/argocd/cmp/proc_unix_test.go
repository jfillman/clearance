//go:build unix

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A descendant a step leaves behind (a backgrounded process, a stalled helper) does not outlive the step: the step's
// process group is killed when it returns, and on a deadline.
func TestAStepsDescendantsDoNotOutliveIt(t *testing.T) {
	withFS(t, NetnsOff, "")
	pidFile := filepath.Join(t.TempDir(), "pid")
	alive := func() (int, bool) {
		b, _ := os.ReadFile(pidFile)
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			t.Fatalf("no pid recorded: %q", b)
		}
		for i := 0; i < 50; i++ {
			if syscall.Kill(pid, 0) != nil {
				return pid, false
			}
			time.Sleep(20 * time.Millisecond)
		}
		return pid, true
	}
	// a step that exits, leaving a child running with its output elsewhere
	fakeTool(t, "helm", `sleep 300 >/dev/null 2>&1 </dev/null & echo $! > '`+pidFile+`'`)
	if _, err := OSRun(context.Background(), t.TempDir(), nil, "helm", "template", "x", "."); err != nil {
		t.Fatal(err)
	}
	if pid, ok := alive(); ok {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("a backgrounded child outlived its step")
	}
	// a step stopped at its deadline, whose child holds its stdout
	fakeTool(t, "helm", `sleep 300 & echo $! > '`+pidFile+`'; wait`)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := OSRun(ctx, t.TempDir(), nil, "helm", "template", "x", "."); err == nil {
		t.Fatal("the step outlived its deadline")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the step returned %s after a 300ms deadline", took)
	}
	if pid, ok := alive(); ok {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("a child outlived its step's deadline")
	}
}

// A part of the scratch a step made unreadable is a failed measurement, never a smaller total.
func TestAnUnreadableScratchIsNotUnderTheBound(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads every directory")
	}
	withFS(t, NetnsOff, "")
	fakeTool(t, "helm", `mkdir -p "$TMPDIR/../hidden/d" && head -c 1000 /dev/zero > "$TMPDIR/../hidden/d/f" && chmod 000 "$TMPDIR/../hidden"`)
	ctx, b := budgetCtx(t, DefaultLimits())
	t.Cleanup(func() { os.Chmod(filepath.Join(b.root, "hidden"), 0o755) })
	if _, err := OSRun(ctx, t.TempDir(), nil, "helm", "template", "x", "."); err == nil || !strings.Contains(err.Error(), "could not be measured") {
		t.Fatalf("an unreadable scratch passed the bound: %v", err)
	}
}
