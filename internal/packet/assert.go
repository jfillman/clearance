package packet

import (
	"fmt"
)

// evaluator tests one assertion against the sections already built. It counts a record as support only when the
// fields it rests on are ones the writer verified; a record that supports an assertion only through a claimed field is
// counted under ClaimedOnly and is not support.
type evaluator func(pk *Packet, b *builder) Assertion

var evaluators = map[string]evaluator{
	"deploy-cleared-before-apply":  evalClearedBeforeApply,
	"approvals-distinct-people":    evalApprovers,
	"outcome-matches-cleared":      evalOutcomeMatches,
	"failures-rolled-back":         evalRolledBack,
	"no-unauthorized-changes":      evalNoUnauthorized,
	"records-checkpointed":         evalCheckpointed,
	"observation-coverage-healthy": evalFeedsHealthy,
	"exceptions-resolved":          evalResolved,
	"monitoring-protected":         evalMonitoring,
}

const maxSeqs = 50

func finish(a Assertion) Assertion {
	switch {
	case a.Population == 0:
		a.Status = "not-evidenced"
	case a.Supported == a.Population:
		a.Status = "met"
	case a.Supported > 0:
		a.Status = "met-with-exceptions"
	case a.Failed == 0 && a.ClaimedOnly > 0:
		a.Status = "claimed-only" // everything in the population rests on a claimed field: nothing is support
	default:
		a.Status = "not-met"
	}
	return a
}

func (a *Assertion) note(seq int64) {
	if len(a.Seqs) < maxSeqs {
		a.Seqs = append(a.Seqs, seq)
	}
}

func appliedChanges(pk *Packet) []Change {
	var out []Change
	for _, c := range pk.Changes {
		if c.Outcome != nil && c.Outcome.Applied != nil && *c.Outcome.Applied {
			out = append(out, c)
		}
	}
	return out
}

func evalClearedBeforeApply(pk *Packet, _ *builder) Assertion {
	a := Assertion{}
	for _, c := range appliedChanges(pk) {
		a.Population++
		switch {
		case c.Clear == nil || *c.Clear > c.Outcome.Seq:
			a.Failed++
			a.note(c.Outcome.Seq)
		case !c.ClearVerified:
			a.ClaimedOnly++
			a.note(*c.Clear)
		default:
			a.Supported++
		}
	}
	a.Note = "Population: changes with an applied outcome in the window. A clearance recorded earlier in the window or before it counts only if its record is in the window."
	return finish(a)
}

func evalApprovers(pk *Packet, _ *builder) Assertion {
	a := Assertion{}
	for _, h := range pk.HumanCleared {
		a.Population++
		if h.Statement != "" {
			a.Supported++
		} else {
			a.ClaimedOnly++ // the record has no verified person kind (before C-14), or two approvals share a subject
			a.note(h.ClearSeq)
		}
	}
	a.Note = "An approval recorded before the C-14 person check proves nothing and is not counted."
	return finish(a)
}

func evalOutcomeMatches(pk *Packet, _ *builder) Assertion {
	a := Assertion{}
	for _, c := range pk.Changes {
		o := c.Outcome
		if o == nil || o.Applied == nil || !*o.Applied {
			continue
		}
		a.Population++
		switch {
		case o.Matched == nil:
			a.ClaimedOnly++
			a.note(o.Seq)
		case !*o.Matched:
			a.Failed++
			a.note(o.Seq)
		case !o.Verified:
			a.ClaimedOnly++ // the provider says the digest matched; the core did not compare it
			a.note(o.Seq)
		default:
			a.Supported++
		}
	}
	a.Note = "Only a comparison the core made itself (a Terraform plan's matched) is support; a provider's claim that its digest matched is listed, not counted."
	return finish(a)
}

func evalRolledBack(pk *Packet, _ *builder) Assertion {
	a := Assertion{}
	for _, c := range pk.Changes {
		if !c.Failed {
			continue
		}
		a.Population++
		rb := c.Outcome.Rollback
		switch {
		case rb != nil && rb.Used != nil && *rb.Used:
			a.ClaimedOnly++ // a rollback is the provider's claim; the core does not see the target
			a.note(c.Outcome.Seq)
		default:
			a.Failed++
			a.note(c.Outcome.Seq)
		}
	}
	a.Note = "A rollback is reported by the deploying provider: it is listed as claimed, never as verified."
	return finish(a)
}

func evalNoUnauthorized(pk *Packet, _ *builder) Assertion {
	a := Assertion{Note: "Out-of-band, drift, untraced-apply and digest-mismatch exceptions. Not evidenced unless every observation feed was healthy for the window."}
	for _, e := range pk.Exceptions.Rows {
		if e.Class == ClassOutOfBand {
			a.Failed++
			a.note(e.Seq)
		}
	}
	a.Population = a.Failed
	if a.Failed > 0 {
		a.Status = "not-met"
		return a
	}
	if !pk.Coverage.WindowVerified {
		a.Status = "not-evidenced"
		a.Note += " This window's coverage was not verified, so an absence of exceptions supports nothing."
		return a
	}
	a.Population, a.Supported, a.Status = 1, 1, "met"
	return a
}

func evalCheckpointed(pk *Packet, b *builder) Assertion {
	a := Assertion{Note: "Records are checkpointed when a witnessed ledger checkpoint covers them."}
	for _, c := range pk.Coverage.ByAssurance {
		a.Population += c.Count
		if c.State == "checkpointed" {
			a.Supported = c.Count
		}
	}
	a.Failed = a.Population - a.Supported
	if a.Failed > 0 {
		a.Note += fmt.Sprintf(" %d of %d are recorded in the hash chain only.", a.Failed, a.Population)
	}
	return finish(a)
}

func evalFeedsHealthy(pk *Packet, _ *builder) Assertion {
	a := Assertion{}
	for _, s := range pk.Coverage.Scopes {
		a.Population++
		if s.Collector && s.Statement.State == "healthy" && !s.Statement.Truncated {
			a.Supported++
		} else {
			a.Failed++
		}
	}
	a.Note = "Population: observed scopes. A scope with no collector, or any blind or degraded stretch, fails."
	return finish(a)
}

func evalResolved(pk *Packet, _ *builder) Assertion {
	a := Assertion{}
	for _, e := range pk.Exceptions.Rows {
		if e.Source != "observation" || (e.Class != ClassOutOfBand && e.Class != ClassBreakGlass) {
			continue
		}
		a.Population++
		if e.Resolution != "none recorded" {
			a.Supported++
		} else {
			a.Failed++
			a.note(e.Seq)
		}
	}
	a.Note = "Population: observations seen and not cleared. Resolutions are the provider's assessments of how a change ended."
	return finish(a)
}

func evalMonitoring(pk *Packet, _ *builder) Assertion {
	a := Assertion{Note: "Not evidenced unless every observation feed was healthy for the window."}
	for _, e := range pk.Exceptions.Rows {
		if e.Class == ClassMonitoring {
			a.Failed++
			a.note(e.Seq)
		}
	}
	a.Population = a.Failed
	switch {
	case a.Failed > 0:
		a.Status = "not-met"
	case !pk.Coverage.WindowVerified:
		a.Status = "not-evidenced"
	default:
		a.Population, a.Supported, a.Status = 1, 1, "met"
	}
	return a
}

// evaluate runs every mapped assertion.
func (b *builder) evaluate(pk *Packet, maps []Mapping) []Control {
	out := []Control{}
	for _, m := range maps {
		for _, c := range m.Controls {
			ctl := Control{Framework: m.Framework, Version: m.Version, Control: c.ID, Title: c.Title}
			for _, as := range c.Assertions {
				a := evaluators[as.Evaluator](pk, b)
				a.ID, a.Statement, a.Evaluator = as.ID, as.Statement, as.Evaluator
				ctl.Assertions = append(ctl.Assertions, a)
			}
			out = append(out, ctl)
		}
	}
	return out
}
