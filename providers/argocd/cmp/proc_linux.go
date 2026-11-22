//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

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

// EnableReaping turns the subreaper and the sweep after every step on, for this process. An error when the kernel
// refuses PR_SET_CHILD_SUBREAPER or /proc cannot be read: containment cannot be established, and the plugin refuses to
// start rather than render without it.
func EnableReaping() error {
	var err error
	subreaperOnce.Do(func() { err = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) })
	if err != nil {
		return fmt.Errorf("the render steps' descendants cannot be contained: PR_SET_CHILD_SUBREAPER was refused (%w)", err)
	}
	var on int32 // the kernel writes an int
	if _, _, e := unix.Syscall6(unix.SYS_PRCTL, unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&on)), 0, 0, 0, 0); e != 0 || on == 0 {
		return fmt.Errorf("the render steps' descendants cannot be contained: this process is not a child subreaper (errno %v)", e)
	}
	if _, err := childrenOf(os.Getpid()); err != nil {
		return fmt.Errorf("the render steps' descendants cannot be contained: %w", err)
	}
	reaping.Store(true)
	return nil
}

// stepLock serialises the steps while reaping is on (a no-op otherwise); the returned func releases it.
func stepLock() func() {
	if !reaping.Load() {
		return func() {}
	}
	stepMu.Lock()
	return stepMu.Unlock
}

// reapTimeout bounds one sweep; a test shortens it. killProc is the signal the sweep sends; a test replaces it to stand
// for a process that does not die.
var (
	reapTimeout = 5 * time.Second
	killProc    = syscall.Kill
)

// reapStep runs after a step's Wait, under stepLock: it kills every child of the plugin (its own group or session
// too) and reaps every exited one, until there is none (ECHILD). An error when the bound passes with any left: the step
// then fails, it never reports success over a process that outlives it.
func reapStep() error {
	if !reaping.Load() {
		return nil
	}
	return reapAll()
}

// reapAll kills and reaps every child of this process. It succeeds only when wait4 says there is no child left
// (ECHILD): a child still alive, a zombie it could not reap, or a /proc it cannot read when the bound passes is an error.
func reapAll() error {
	deadline := time.Now().Add(reapTimeout)
	for {
		kids, lerr := childrenOf(os.Getpid())
		for _, pid := range kids {
			killProc(-pid, syscall.SIGKILL) // its own group or session, if it made one
			killProc(pid, syscall.SIGKILL)
		}
		// Reap every child that has exited, zombies a step left included.
		for {
			var ws syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
			if err == syscall.ECHILD {
				return nil // no child at all: the step left nothing
			}
			if err != nil || pid == 0 {
				break // children remain, none has exited yet
			}
		}
		if !time.Now().Before(deadline) {
			if lerr != nil {
				return fmt.Errorf("the processes a render step started could not be listed within %s: %w", reapTimeout, lerr)
			}
			return fmt.Errorf("%d process(es) a render step started could not be stopped within %s (pids %v)", len(kids), reapTimeout, kids)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// childrenOf lists the live (not zombie) pids whose parent is ppid, from /proc/<pid>/stat; an error when /proc cannot be
// read (a process that exits while it is read is simply not listed).
func childrenOf(ppid int) ([]int, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("reading /proc: %w", err)
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
	return out, nil
}
