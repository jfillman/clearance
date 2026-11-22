//go:build linux

package main

import (
	"bytes"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Containment that survives setsid(2). A step's process group (proc_unix.go) misses a descendant that starts a session
// or a group of its own. So in the plugin's own `generate` (EnableReaping, from main) the plugin is a child subreaper
// (PR_SET_CHILD_SUBREAPER: unprivileged, Linux 3.4+, nothing to configure): an orphaned descendant of a step, however
// it detached, is re-parented to the plugin and not to init. Steps then run one at a time (stepMu), and after each one
// the plugin kills and reaps every child it has, zombies included: at that moment every child is a leftover of the step
// that just ended, because the plugin starts processes only through its steps. The parity tool, which runs steps and
// `argocd` side by side on an operator's machine, does not reap: there a descendant that detaches is not followed.

var (
	reaping       atomic.Bool
	subreaperOnce sync.Once
	stepMu        sync.Mutex
)

// EnableReaping turns the subreaper and the sweep after every step on, for this process.
func EnableReaping() {
	subreaperOnce.Do(func() { unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) })
	reaping.Store(true)
}

// stepLock serialises the steps while reaping is on (a no-op otherwise); the returned func releases it.
func stepLock() func() {
	if !reaping.Load() {
		return func() {}
	}
	stepMu.Lock()
	return stepMu.Unlock
}

// reapStep runs after a step's Wait, under stepLock: it kills every child of the plugin (its own group or session
// too) and reaps every exited one, until there is none (ECHILD) or the bound passes.
func reapStep() {
	if !reaping.Load() {
		return
	}
	reapAll()
}

// reapAll kills and reaps every child of this process, until there is none (ECHILD) or the bound passes.
func reapAll() {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, pid := range childrenOf(os.Getpid()) {
			syscall.Kill(-pid, syscall.SIGKILL) // its own group or session, if it made one
			syscall.Kill(pid, syscall.SIGKILL)
		}
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		switch {
		case err == syscall.ECHILD:
			return
		case err == nil && pid == 0:
			time.Sleep(5 * time.Millisecond) // a killed child not yet exited
		}
	}
}

// childrenOf lists the live (not zombie) pids whose parent is ppid, from /proc/<pid>/stat.
func childrenOf(ppid int) []int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// pid (comm) state ppid ...: comm may hold spaces and parentheses, so read after the last ')'.
		i := bytes.LastIndexByte(b, ')')
		if i < 0 {
			continue
		}
		f := bytes.Fields(b[i+1:])
		if len(f) >= 2 && string(f[0]) != "Z" {
			if p, err := strconv.Atoi(string(f[1])); err == nil && p == ppid {
				out = append(out, pid)
			}
		}
	}
	return out
}
