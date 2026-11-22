//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// shimSupported: the shim runs on Linux, where the limits and Landlock exist.
const shimSupported = true

// The Landlock file-system rights. ABI 1's are always handled: what a rule does not grant is denied. REFER (ABI 2:
// linking or renaming a file into another directory) and TRUNCATE (ABI 3: truncate(2), O_TRUNC) are handled too when
// the kernel knows them, granted beneath the scratch directory only. On an ABI 1 or 2 kernel a step can still truncate
// a file that its user may write outside its scratch (the source directory): reads are refused all the same, which is
// what keeps the token out of reach, and doctor says which ABI is in force.
const (
	llFileRights = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE
	llDirRights  = unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	llV1      = llFileRights | llDirRights
	llRead    = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	llRX      = llRead | unix.LANDLOCK_ACCESS_FS_EXECUTE
	llDev     = llRead | unix.LANDLOCK_ACCESS_FS_WRITE_FILE // /dev/null, /dev/urandom, a tty
	llNoDevNo = unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK
)

// llRights is the handled set, the scratch directory's grant and a file rule's mask for a kernel's ABI.
func llRights(abi int) (handled, rw, file uint64) {
	handled, file = llV1, llFileRights
	if abi >= 2 {
		handled |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		handled |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
		file |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return handled, handled &^ llNoDevNo, file
}

// rulesetAttr is struct landlock_ruleset_attr up to handled_access_fs, the part ABI 1 knows (every later kernel
// accepts the short form).
type rulesetAttr struct{ handledFS uint64 }

// landlockABI asks the kernel for its Landlock ABI version: an error when Landlock is not built in, not an active LSM,
// or the seccomp profile refuses the call.
func landlockABI() (int, error) {
	v, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 {
		switch e {
		case unix.ENOSYS:
			return 0, errors.New("landlock: the kernel has no Landlock (ENOSYS; Linux 5.13+ needed)")
		case unix.EOPNOTSUPP:
			return 0, errors.New("landlock: the kernel has Landlock but it is not active (add landlock to the lsm= boot parameter)")
		case unix.EPERM:
			return 0, errors.New("landlock: the seccomp profile refuses landlock_create_ruleset (EPERM)")
		}
		return 0, fmt.Errorf("landlock: %w", e)
	}
	if int(v) < 1 {
		return 0, fmt.Errorf("landlock: ABI %d", v)
	}
	return int(v), nil
}

// setupFD is the shim's setup-error channel: a pipe the plugin passes as fd 3, close-on-exec in the shim, so the tool
// never holds it. Only the shim can write it, and only before exec; the tool's own stderr and exit status never decide
// whether a step is retried without the sandbox.
const setupFD = 3

// shimSetupFailed reports a setup failure on the setup channel (when the plugin passed one) and returns err.
func shimSetupFailed(spec sandboxSpec, err error) error {
	if spec.ErrFD > 0 {
		f := os.NewFile(uintptr(spec.ErrFD), "setup")
		f.WriteString(err.Error())
		f.Close()
	}
	return err
}

// shimExec applies spec to this process and execs path. It returns only on failure.
func shimExec(spec sandboxSpec, path string, argv, env []string) error {
	// Landlock and no_new_privs apply to the calling thread and what it execs: stay on one thread to the exec.
	runtime.LockOSThread()
	if spec.ErrFD > 0 {
		unix.CloseOnExec(spec.ErrFD) // the tool must never inherit the setup channel
	}
	for _, l := range []struct {
		res int
		cur uint64
		max uint64
	}{{unix.RLIMIT_CPU, spec.CPU, spec.CPU + 2}, {unix.RLIMIT_DATA, spec.Data, spec.Data}, {unix.RLIMIT_FSIZE, spec.FSize, spec.FSize}} {
		if l.cur == 0 {
			continue
		}
		var old unix.Rlimit
		if err := unix.Getrlimit(l.res, &old); err != nil {
			return shimSetupFailed(spec, fmt.Errorf("clearance-cmp sandbox: getrlimit %d: %w", l.res, err))
		}
		nl := unix.Rlimit{Cur: min(l.cur, old.Max), Max: min(l.max, old.Max)} // never above a hard limit already set
		if err := unix.Setrlimit(l.res, &nl); err != nil {
			return shimSetupFailed(spec, fmt.Errorf("clearance-cmp sandbox: setrlimit %d: %w", l.res, err))
		}
	}
	if spec.Landlock {
		if err := applyLandlock(spec); err != nil {
			return shimSetupFailed(spec, errors.New(shimLandlockPrefix+err.Error()))
		}
	}
	return shimSetupFailed(spec, fmt.Errorf("clearance-cmp sandbox: exec %s: %w", path, syscall.Exec(path, argv, env)))
}

func applyLandlock(spec sandboxSpec) error {
	abi, err := landlockABI()
	if err != nil {
		return err
	}
	handled, rwRights, fileMask := llRights(abi)
	attr := rulesetAttr{handledFS: handled}
	fd, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if e != 0 {
		return fmt.Errorf("create_ruleset: %w", e)
	}
	defer unix.Close(int(fd))
	add := func(p string, rights uint64) error {
		pfd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
				return nil // a root this system does not have (/lib64)
			}
			return fmt.Errorf("open %s: %w", p, err)
		}
		defer unix.Close(pfd)
		var st unix.Stat_t
		if err := unix.Fstat(pfd, &st); err != nil {
			return fmt.Errorf("stat %s: %w", p, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			rights &= fileMask // a rule on a file takes file rights only
		}
		pb := unix.LandlockPathBeneathAttr{Allowed_access: rights, Parent_fd: int32(pfd)}
		if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&pb)), 0, 0, 0); e != 0 {
			return fmt.Errorf("add_rule %s: %w", p, e)
		}
		return nil
	}
	for _, g := range []struct {
		paths  []string
		rights uint64
	}{{spec.RX, llRX}, {spec.RO, llRead}, {spec.RW, rwRights}, {spec.Dev, llDev}} {
		for _, p := range g.paths {
			if err := add(p, g.rights); err != nil {
				return err
			}
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if _, _, e := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); e != 0 {
		return fmt.Errorf("restrict_self: %w", e)
	}
	return nil
}

// stepUsage is the CPU time and peak RSS of a finished step, from its rusage.
func stepUsage(ps *os.ProcessState) (cpuSec float64, maxRSS int64) {
	if ps == nil {
		return 0, 0
	}
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return 0, 0
	}
	cpu := float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
	return cpu, ru.Maxrss * 1024
}

// signalLimit is the bound a signal that ended a step stands for: SIGXCPU the CPU bound, SIGXFSZ the file-size bound;
// "killed" for SIGKILL (the CPU hard limit, the deadline, or the kernel's OOM killer), "" otherwise.
func signalLimit(ps *os.ProcessState) string {
	ws, ok := ps.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return ""
	}
	switch ws.Signal() {
	case syscall.SIGXCPU:
		return LimitCPU
	case syscall.SIGXFSZ:
		return LimitTemp
	case syscall.SIGKILL:
		return "killed"
	}
	return ""
}
