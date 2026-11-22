//go:build linux

package main

import (
	"bytes"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Containment that survives setsid(2). A step's process group (proc_unix.go) misses a descendant that starts a session
// or a group of its own. So the plugin is a child subreaper (PR_SET_CHILD_SUBREAPER: unprivileged, Linux 3.4+, nothing
// to configure): an orphaned descendant of a step, however it detached, is re-parented to the plugin and not to init.
//
// Every step's environment carries a token of its own (stepEnv). After the step, reapStep kills and reaps every child
// of the plugin whose environment holds that token: only that step's adopted descendants, never another step's
// processes or anything else the plugin runs (the parity tool's workers run steps and `argocd` side by side). It goes on
// until none is left, so a chain of descendants each in its own session is followed to its end, within a time bound.
// A descendant that clears its environment before it is adopted is not recognised; the plugin's own run then ends with
// reapAll (main), which kills every child left.

const stepEnv = "CLEARANCE_CMP_STEP_ID"

var subreaperOnce sync.Once

// becomeSubreaper makes this process the subreaper of what its steps start (once).
func becomeSubreaper() {
	subreaperOnce.Do(func() { unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) })
}

// reapStep kills and reaps the plugin's children that carry the step's token, until none is left or the bound passes.
func reapStep(token string) {
	if token == "" {
		return
	}
	needle := []byte(stepEnv + "=" + token + "\x00")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var found []int
		for _, pid := range childrenOf(os.Getpid()) {
			if env, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ"); err == nil && bytes.Contains(append(env, 0), needle) {
				found = append(found, pid)
			}
		}
		if len(found) == 0 {
			return
		}
		for _, pid := range found {
			syscall.Kill(-pid, syscall.SIGKILL) // its own group or session, if it made one
			syscall.Kill(pid, syscall.SIGKILL)
			var ws syscall.WaitStatus
			syscall.Wait4(pid, &ws, 0, nil) // its children, if any, are now the plugin's: the next pass finds them
		}
	}
}

// reapAll kills and reaps every child of this process, until there is none (ECHILD) or the bound passes. Only the
// plugin's `generate` calls it, once, at its very end, when it runs nothing else.
func reapAll() {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		kids := childrenOf(os.Getpid())
		for _, pid := range kids {
			syscall.Kill(-pid, syscall.SIGKILL)
			syscall.Kill(pid, syscall.SIGKILL)
		}
		var ws syscall.WaitStatus
		if _, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil); err == syscall.ECHILD && len(kids) == 0 {
			return
		}
		if len(kids) == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// childrenOf lists the pids whose parent is ppid, from /proc/<pid>/stat.
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
		if len(f) >= 2 && string(f[0]) != "Z" { // a zombie is reaped by whoever waits for it, not taken here
			if p, err := strconv.Atoi(string(f[1])); err == nil && p == ppid {
				out = append(out, pid)
			}
		}
	}
	return out
}
