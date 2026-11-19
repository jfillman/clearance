//go:build !linux

package main

import (
	"errors"
	"os/exec"
)

// isolateNetwork on a platform without network namespaces: unavailable. In try mode (the default) the render runs
// without it and says so once; that is the case for an operator's laptop running the parity tool and for the unit
// tests. The sidecar image is Linux only.
func isolateNetwork(cmd *exec.Cmd) (bool, error) {
	return false, errors.New("network namespaces are Linux only")
}
