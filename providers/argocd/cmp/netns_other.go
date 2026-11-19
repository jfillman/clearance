//go:build !linux

package main

import "os/exec"

// isolateNetwork on a platform without network namespaces: nothing to apply (false). The sidecar image is Linux
// only; this is for an operator's laptop running the parity tool and for the unit tests, where the environment
// settings of argosrc/sandbox.go are all the render step gets.
func isolateNetwork(cmd *exec.Cmd) (bool, error) { return false, nil }
