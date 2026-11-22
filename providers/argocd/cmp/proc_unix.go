//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// ownGroup starts cmd as the leader of a process group of its own, and makes a cancellation (the deadline, the output
// bound) kill the whole group: the step and every process it started.
func ownGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		killGroup(cmd)
		return cmd.Process.Kill()
	}
}

// killGroup kills what is left of cmd's process group (nothing, usually).
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil && cmd.Process.Pid > 0 {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
