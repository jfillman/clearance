package verify

import (
	"fmt"
	"io"
	"strings"
)

// Status is the outcome of one check.
type Status string

const (
	// Pass: checked, against trust the verifier's user supplied (or needing none).
	Pass Status = "PASS"
	// Fail: checked and wrong. Findings name what.
	Fail Status = "FAIL"
	// SelfVouched: consistent, but only with keys or policy taken from the packet itself, which proves nothing about
	// who the log or the witnesses are.
	SelfVouched Status = "SELF-VOUCHED"
	// NotChecked: not checked, with the reason (usually a trust input nobody supplied).
	NotChecked Status = "NOT CHECKED"
	// NotCheckpointed: the packet has no witnessed checkpoint. Not a pass of the witness check, and not a failure.
	NotCheckpointed Status = "NOT CHECKPOINTED"
)

// Check is one thing the verifier did.
type Check struct {
	Name   string
	Status Status
	// Trust says where the keys or policy the check used came from, when it used any.
	Trust    string
	Detail   string
	Findings []string // what is wrong (Fail), or what was not checked
}

// Input is one trust input and where it came from.
type Input struct {
	Name   string
	Source string // "supplied by you (path)", "TAKEN FROM THE PACKET", or "none"
}

// Report is everything the verifier found.
type Report struct {
	Packet string
	Inputs []Input
	Checks []Check
	Notes  []string
}

func (r *Report) add(c Check) { r.Checks = append(r.Checks, c) }

func (r *Report) note(f string, a ...any) { r.Notes = append(r.Notes, fmt.Sprintf(f, a...)) }

// Failed is true when any check failed.
func (r *Report) Failed() bool {
	for _, c := range r.Checks {
		if c.Status == Fail {
			return true
		}
	}
	return false
}

// Complete is true when every check passed: nothing failed, nothing was left unchecked, self-vouched or not
// checkpointed.
func (r *Report) Complete() bool {
	for _, c := range r.Checks {
		if c.Status != Pass {
			return false
		}
	}
	return true
}

// ExitCode is 0 when every check passed, 1 when any failed and 2 when nothing failed but something could not be
// established (not checked, self-vouched, not checkpointed): a caller must not read 2 as a pass.
func (r *Report) ExitCode() int {
	switch {
	case r.Failed():
		return 1
	case r.Complete():
		return 0
	}
	return 2
}

// Verdict is the one-line result.
func (r *Report) Verdict() string {
	switch r.ExitCode() {
	case 0:
		return "VERIFIED: every check passed against the trust inputs you supplied."
	case 1:
		return "FAILED: the packet does not verify. Do not rely on it."
	}
	var what []string
	for _, c := range r.Checks {
		if c.Status != Pass {
			what = append(what, c.Name+" ("+strings.ToLower(string(c.Status))+")")
		}
	}
	return "NOT FULLY VERIFIED: nothing failed, but these could not be established: " + strings.Join(what, "; ") + "."
}

// Write prints the report.
func (r *Report) Write(w io.Writer) {
	fmt.Fprintf(w, "clearance verify %s\n\nTrust inputs (a packet vouching for its own keys proves nothing):\n", r.Packet)
	for _, in := range r.Inputs {
		fmt.Fprintf(w, "  %-22s %s\n", in.Name, in.Source)
	}
	fmt.Fprintln(w, "\nChecks:")
	for _, c := range r.Checks {
		fmt.Fprintf(w, "  [%s] %s", c.Status, c.Name)
		if c.Detail != "" {
			fmt.Fprintf(w, ": %s", c.Detail)
		}
		fmt.Fprintln(w)
		if c.Trust != "" {
			fmt.Fprintf(w, "      trust: %s\n", c.Trust)
		}
		for _, f := range c.Findings {
			fmt.Fprintf(w, "      - %s\n", f)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "\nNote: %s\n", n)
	}
	fmt.Fprintf(w, "\n%s\n", r.Verdict())
}
