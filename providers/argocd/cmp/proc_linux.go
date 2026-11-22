//go:build linux

package main

import (
	"bytes"
	"os"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Containment that survives setsid(2). A step's process group (proc_unix.go) misses a descendant that starts a session
// or a group of its own. So the plugin is a child subreaper (PR_SET_CHILD_SUBREAPER: unprivileged, Linux 3.4+, nothing
// to configure): an orphaned descendant of a step, however it detached, is re-parented to the plugin and not to init,
// and after every step the plugin kills and reaps each child of its own that is not a step still running. A descendant
// cannot leave the subtree of its nearest subreaper.

var (
	subreaperOnce sync.Once
	active        struct {
		sync.Mutex
		pids map[int]bool
	}
)

// becomeSubreaper makes this process the subreaper of what its steps start (once).
func becomeSubreaper() {
	subreaperOnce.Do(func() { unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) })
}

// trackStep records a step's pid as running (on true) or finished, so reapOrphans never touches it.
func trackStep(pid int, running bool) {
	active.Lock()
	defer active.Unlock()
	if active.pids == nil {
		active.pids = map[int]bool{}
	}
	if running {
		active.pids[pid] = true
	} else {
		delete(active.pids, pid)
	}
}

// reapOrphans kills and reaps every child of this process that is not a running step: the descendants of finished
// steps, re-parented here. Killing one can orphan its own children, which then come here too, so it repeats until
// none is left (bounded).
func reapOrphans() {
	self := os.Getpid()
	for round := 0; round < 16; round++ {
		var found []int
		for _, pid := range childrenOf(self) {
			active.Lock()
			running := active.pids[pid]
			active.Unlock()
			if !running {
				found = append(found, pid)
			}
		}
		if len(found) == 0 {
			return
		}
		for _, pid := range found {
			syscall.Kill(-pid, syscall.SIGKILL) // its own group or session, if it made one
			syscall.Kill(pid, syscall.SIGKILL)
		}
		for _, pid := range found {
			var ws syscall.WaitStatus
			syscall.Wait4(pid, &ws, 0, nil)
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
		if len(f) >= 2 {
			if p, err := strconv.Atoi(string(f[1])); err == nil && p == ppid {
				out = append(out, pid)
			}
		}
	}
	return out
}
