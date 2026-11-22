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
)

// A descendant that detaches from the step's process group (setsid: a session and a group of its own) is still
// killed: it is re-parented to the plugin, the child subreaper, and reaped after the step.
func TestADetachedDescendantDoesNotOutliveItsStep(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is not installed")
	}
	withFS(t, NetnsOff, "")
	withReaping(t)
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
	// Gone means terminated and reaped: no /proc entry at all (a zombie would still have one).
	if st, ok := procState(pid); ok {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("a descendant in its own session outlived its step (state %s)", st)
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

// withReaping turns the subreaper and the sweep on for one test, as the plugin's generate does (EnableReaping).
func withReaping(t *testing.T) {
	t.Helper()
	EnableReaping()
	t.Cleanup(func() { reaping.Store(false) })
}

// Without reaping (the parity tool, which runs steps beside its own commands), the sweep never runs: a process that is
// not a step's is left alone.
func TestWithoutReapingOtherProcessesAreLeftAlone(t *testing.T) {
	withFS(t, NetnsOff, "")
	reaping.Store(false)
	other := exec.Command("sleep", "30")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { other.Process.Kill(); other.Wait() }()
	fakeTool(t, "helm", `exit 0`)
	if _, err := OSRun(context.Background(), t.TempDir(), nil, "helm", "template", "x", "."); err != nil {
		t.Fatal(err)
	}
	// Running means a /proc entry in a state other than zombie (signal 0 succeeds on a zombie too).
	if st, ok := procState(other.Process.Pid); !ok || st == "Z" {
		t.Fatalf("a process that was not the step's was killed (state %q)", st)
	}
}

// With reaping on, steps run one at a time, so the sweep after one never meets another running step.
func TestReapingSerialisesSteps(t *testing.T) {
	withFS(t, NetnsOff, "")
	withReaping(t)
	log := filepath.Join(t.TempDir(), "log")
	fakeTool(t, "helm", `echo start >> '`+log+`'; sleep 0.2; echo end >> '`+log+`'`)
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := OSRun(context.Background(), t.TempDir(), nil, "helm", "template", "x", ".")
			done <- err
		}()
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(log)
	if got := strings.Fields(string(b)); strings.Join(got, " ") != "start end start end" {
		t.Fatalf("the steps overlapped: %v", got)
	}
}

// procState is a process's state letter from /proc/<pid>/stat (R, S, Z, ...); false when there is no such process (it
// exited and was reaped).
func procState(pid int) (string, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", false
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return "", false
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) == 0 {
		return "", false
	}
	return f[0], true
}

// A descendant that detaches and replaces its whole environment (setsid env -i) is still the plugin's to stop: nothing
// about it is matched by its environment.
func TestADetachedDescendantWithAnEmptyEnvironmentIsStopped(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is not installed")
	}
	withFS(t, NetnsOff, "")
	withReaping(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	fakeTool(t, "helm", `(setsid env -i sleep 300 >/dev/null 2>&1 </dev/null & echo $! > '`+pidFile+`') ; exit 0`)
	if _, err := OSRun(context.Background(), t.TempDir(), nil, "helm", "template", "x", "."); err != nil {
		t.Fatal(err)
	}
	pid := readPid(t, pidFile)
	if st, ok := procState(pid); ok {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("a detached descendant with an empty environment outlived its step (state %s)", st)
	}
}

// A chain of more than 16 descendants, each in a session of its own and each the parent of the next, is followed to its
// end: killing one hands the next to the plugin, and the sweep goes on until wait4 says there is no child.
func TestALongChainOfDetachedDescendantsIsStopped(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is not installed")
	}
	withFS(t, NetnsOff, "")
	withReaping(t)
	dir := t.TempDir()
	pids := filepath.Join(dir, "pids")
	chain := filepath.Join(dir, "chain")
	if err := os.WriteFile(chain, []byte("#!/bin/sh\necho $$ >> '"+pids+"'\nif [ \"$1\" -gt 0 ]; then setsid '"+chain+"' $(($1 - 1)) </dev/null >/dev/null 2>&1 & fi\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// the step starts the chain detached and waits until all 21 links exist before it exits
	fakeTool(t, "helm", `setsid '`+chain+`' 20 </dev/null >/dev/null 2>&1 &
i=0; while [ "$(wc -l < '`+pids+`' 2>/dev/null || echo 0)" -lt 21 ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done`)
	if _, err := OSRun(context.Background(), t.TempDir(), nil, "helm", "template", "x", "."); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(pids)
	links := strings.Fields(string(b))
	if len(links) != 21 {
		t.Fatalf("the chain had %d links, want 21", len(links))
	}
	for _, l := range links {
		pid, _ := strconv.Atoi(l)
		if st, ok := procState(pid); ok {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Errorf("link %d outlived its step (state %s)", pid, st)
		}
	}
}

// A leftover that cannot be stopped in time fails the step: it is never reported as a success.
func TestACleanupThatRunsOutOfTimeFailsTheStep(t *testing.T) {
	withFS(t, NetnsOff, "")
	withReaping(t)
	old := reapTimeout
	reapTimeout = 0 // the sweep has no time at all: whatever is left is left
	t.Cleanup(func() { reapTimeout = old; reapAll() })
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is not installed")
	}
	// detached, so the group kill does not reach it and only the sweep could
	fakeTool(t, "helm", `(setsid sleep 300 >/dev/null 2>&1 </dev/null &) ; exit 0`)
	_, err := OSRun(context.Background(), t.TempDir(), nil, "helm", "template", "x", ".")
	if err == nil || !strings.Contains(err.Error(), "could not be stopped") {
		t.Fatalf("a step whose leftover outlived the sweep succeeded: %v", err)
	}
}

func readPid(t *testing.T, f string) int {
	t.Helper()
	b, _ := os.ReadFile(f)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("no pid in %s: %q", f, b)
	}
	return pid
}
