package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jfillman/clearance/internal/argosrc"
)

// AllowNoNetnsEnv names the one switch that lets a render run without a private network namespace. It is off unless
// set to "true", so a sidecar that cannot create the namespace refuses to render (fails closed) rather than render
// with loopback reachable.
const AllowNoNetnsEnv = "CLEARANCE_CMP_ALLOW_NO_NETNS"

// isolate is the namespace step; a test replaces it to inject a failure.
var isolate = isolateNetwork

// netnsRequired is whether a render step that cannot get its namespace must stop.
func netnsRequired() bool { return strings.ToLower(os.Getenv(AllowNoNetnsEnv)) != "true" }

// errNoNetns says what is missing, naming the capability and the way out.
func errNoNetns(name string, cause error) error {
	return &netnsError{fmt.Errorf("refusing to run %s: cannot create a private network namespace (%w). The render step runs in its "+
		"own user+network namespace so a chart or kustomization cannot reach the sidecar pod's loopback; this needs "+
		"unprivileged user namespaces: the clearance-cmp container's seccomp profile must permit unshare/clone with "+
		"CLONE_NEWUSER and CLONE_NEWNET (the RuntimeDefault profile does not), and the node kernel must allow them "+
		"(user.max_user_namespaces > 0, no AppArmor/sysctl restriction). Set %s=true only to render without this "+
		"isolation, accepting that loopback in this pod is reachable from a render", name, cause, AllowNoNetnsEnv)}
}

// netnsError marks the refusal, so the caller returns it as it is.
type netnsError struct{ error }

func (e *netnsError) Unwrap() error { return e.error }

// sandboxStart is what a render command needs before it starts: the namespace flags on cmd when argosrc says this
// command is a render step. The returned bool is whether the namespace is in use.
func sandboxStart(cmd *exec.Cmd, name string, args []string) (bool, error) {
	if !argosrc.NetworkOffFor(name, args) {
		return false, nil
	}
	ok, err := isolate(cmd)
	if err != nil {
		if netnsRequired() {
			return false, errNoNetns(name, err)
		}
		return false, nil
	}
	return ok, nil
}

// startFailedForNetns reports whether a Start error is the kernel or runtime refusing the namespace (EPERM, EINVAL,
// ENOSPC from max_user_namespaces) rather than a missing binary.
func startFailedForNetns(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*exec.Error); ok { // not found in PATH
		return false
	}
	s := err.Error()
	return strings.Contains(s, "operation not permitted") || strings.Contains(s, "invalid argument") ||
		strings.Contains(s, "no space left") || strings.Contains(s, "permission denied")
}
