//go:build !linux

package main

import (
	"errors"
	"os"
)

// shimSupported: off Linux there is no Landlock and no shim. Steps run directly; the wall time and output bounds still
// hold (they are the plugin's own), the CPU, memory and file-size bounds do not. The sidecar image is Linux only; this
// is an operator's laptop running the parity tool, and the unit tests.
const shimSupported = false

func landlockAvailable() error { return errors.New("landlock is Linux only") }

func shimExec(sandboxSpec, string, []string, []string) error {
	return errors.New("clearance-cmp sandbox: Linux only")
}

func stepUsage(*os.ProcessState) (float64, int64) { return 0, 0 }

func signalLimit(*os.ProcessState) string { return "" }
