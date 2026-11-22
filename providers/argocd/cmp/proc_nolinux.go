//go:build !linux

package main

// Off Linux there is no child subreaper: a descendant that leaves the step's process group (setsid) is not followed.
// The sidecar is Linux only; off Linux this is the parity tool on an operator's machine.
func EnableReaping() error { return nil }
func stepLock() func()     { return func() {} }
func reapStep() error      { return nil }
func reapAll() error       { return nil }
