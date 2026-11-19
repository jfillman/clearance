package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/jfillman/clearance/internal/argosrc"
)

// NetnsEnv is the one setting for the private network namespace of the render steps (helm template, helm dependency
// build, kustomize). Exactly one of:
//
//	try      (default, also unset) use a user+network namespace when the kernel allows it; when it does not, render
//	         without it and say so once on stderr;
//	require  render only inside the namespace: when it cannot be created, refuse (fail closed);
//	off      never attempt it.
const NetnsEnv = "CLEARANCE_CMP_NETNS"

// Netns modes.
const (
	NetnsTry     = "try"
	NetnsRequire = "require"
	NetnsOff     = "off"
)

// ParseNetns reads the setting's value; anything but the three exact values is an error.
func ParseNetns(v string) (string, error) {
	switch v {
	case "", NetnsTry:
		return NetnsTry, nil
	case NetnsRequire, NetnsOff:
		return v, nil
	}
	return "", fmt.Errorf("%s is one of %q, %q or %q, got %q", NetnsEnv, NetnsTry, NetnsRequire, NetnsOff, v)
}

// isolate is the namespace step; a test replaces it.
var isolate = isolateNetwork

// netnsWarn is where the one-line fallback notice goes.
var netnsWarn io.Writer = os.Stderr

var ns struct {
	sync.Mutex
	mode   string
	probed bool
	usable bool
	cause  error
	warned bool
}

// SetNetns sets the mode (from the parsed Config) and forgets any earlier probe.
func SetNetns(mode string) {
	ns.Lock()
	defer ns.Unlock()
	ns.mode, ns.probed, ns.usable, ns.cause, ns.warned = mode, false, false, nil, false
}

func netnsMode() string {
	if ns.mode == "" {
		return NetnsTry
	}
	return ns.mode
}

// netnsRequired is whether a render step that cannot get its namespace must stop.
func netnsRequired() bool {
	ns.Lock()
	defer ns.Unlock()
	return netnsMode() == NetnsRequire
}

// probeLocked tries the namespace once per process, with a command that does nothing, and remembers the answer.
func probeLocked() {
	if ns.probed {
		return
	}
	ns.probed = true
	bin, err := exec.LookPath("true")
	if err != nil {
		ns.usable = true // nothing to probe with: let the real command decide
		return
	}
	cmd := exec.Command(bin)
	if _, err := isolate(cmd); err != nil {
		ns.cause = err
		return
	}
	if err := cmd.Run(); err != nil && startFailedForNetns(err) {
		ns.cause = err
		return
	}
	ns.usable = true
}

// markUnavailable records that a real start was refused after a good probe.
func markUnavailable(cause error) {
	ns.Lock()
	defer ns.Unlock()
	ns.probed, ns.usable, ns.cause = true, false, cause
}

// NetnsState is what the plugin reports in its summary line: off, on (renders are isolated) or unavailable (try
// was asked for and the kernel refused: renders run without it).
func NetnsState() string {
	ns.Lock()
	defer ns.Unlock()
	if netnsMode() == NetnsOff {
		return "off"
	}
	probeLocked()
	if ns.usable {
		return "on"
	}
	return "unavailable"
}

// errNoNetns says what is missing, naming the capability and the way out.
func errNoNetns(name string, cause error) error {
	return &netnsError{fmt.Errorf("refusing to run %s: cannot create a private network namespace (%w). %s=%s needs "+
		"unprivileged user namespaces: the clearance-cmp container's seccomp profile must permit unshare/clone with "+
		"CLONE_NEWUSER and CLONE_NEWNET (the RuntimeDefault profile does not), and the node kernel must allow them "+
		"(user.max_user_namespaces > 0, no AppArmor/sysctl restriction). Set %s=%s to render without this isolation",
		name, cause, NetnsEnv, NetnsRequire, NetnsEnv, NetnsTry)}
}

// netnsError marks the refusal, so the caller returns it as it is.
type netnsError struct{ error }

func (e *netnsError) Unwrap() error { return e.error }

// warnOnceLocked prints the fallback notice the first time in this process.
func warnOnceLocked(cause error) {
	if ns.warned {
		return
	}
	ns.warned = true
	fmt.Fprintf(netnsWarn, "clearance: WARNING render steps run WITHOUT a private network namespace (%v): a chart or "+
		"kustomization can reach this pod's loopback. For isolation give the clearance-cmp container a seccomp profile "+
		"allowing unshare/clone with CLONE_NEWUSER|CLONE_NEWNET and set %s=%s (docs/gate.md)\n", cause, NetnsEnv, NetnsRequire)
}

// sandboxStart is what a render command needs before it starts: the namespace flags on cmd when argosrc says this
// command is a render step and the mode and the probe allow it. The bool is whether the namespace is in use.
func sandboxStart(cmd *exec.Cmd, name string, args []string) (bool, error) {
	if !argosrc.NetworkOffFor(name, args) {
		return false, nil
	}
	ns.Lock()
	defer ns.Unlock()
	if netnsMode() == NetnsOff {
		return false, nil
	}
	probeLocked()
	if !ns.usable {
		if netnsMode() == NetnsRequire {
			return false, errNoNetns(name, ns.cause)
		}
		warnOnceLocked(ns.cause)
		return false, nil
	}
	ok, err := isolate(cmd)
	if err != nil {
		if netnsMode() == NetnsRequire {
			return false, errNoNetns(name, err)
		}
		warnOnceLocked(err)
		return false, nil
	}
	return ok, nil
}

// noteStartRefused handles a Start the kernel refused for the namespace after a good probe: require stops, try
// remembers it, warns and lets the caller run the command bare.
func noteStartRefused(name string, err error) error {
	if netnsRequired() {
		return errNoNetns(name, err)
	}
	markUnavailable(err)
	ns.Lock()
	warnOnceLocked(err)
	ns.Unlock()
	return errRetryBare
}

// startFailedForNetns reports whether a Start error is the kernel or runtime refusing the namespace (EPERM, EINVAL,
// ENOSPC from max_user_namespaces, EACCES) rather than a missing binary.
func startFailedForNetns(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EACCES)
}
