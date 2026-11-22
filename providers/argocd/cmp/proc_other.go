//go:build !unix

package main

import "os/exec"

// Off unix there are no process groups to kill; cancellation kills the step itself (exec.CommandContext).
func ownGroup(*exec.Cmd) {}

func killGroup(*exec.Cmd) {}
