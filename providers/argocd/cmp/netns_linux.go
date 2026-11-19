//go:build linux

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// isolateNetwork puts cmd in a user and network namespace of its own: the child sees one network interface, a
// loopback that is down, and nothing else, so no address (the pod's own 127.0.0.1 included) is reachable. The
// current uid and gid are mapped to themselves, so the child owns the same files; no capability is needed in the
// parent (unprivileged user namespaces, which the container's seccomp profile and the kernel must allow).
func isolateNetwork(cmd *exec.Cmd) (bool, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	a := cmd.SysProcAttr
	a.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET
	a.UidMappings = []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}}
	a.GidMappings = []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}}
	a.GidMappingsEnableSetgroups = false
	return true, nil
}
