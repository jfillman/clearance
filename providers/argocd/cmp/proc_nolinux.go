//go:build !linux

package main

// Off Linux there is no child subreaper: a descendant that leaves the step's process group (setsid) is not followed.
// The sidecar is Linux only; off Linux this is the parity tool on an operator's machine.
const stepEnv = "CLEARANCE_CMP_STEP_ID"

func becomeSubreaper() {}
func reapStep(string)  {}
func reapAll()         {}
