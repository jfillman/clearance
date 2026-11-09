package packet

import (
	"fmt"
	"strings"
)

// PDF renders the packet's presentation. It prints what the JSON says and nothing else: the same counts, the same
// sentences, and the "no exceptions" sentence only where the packet's Exceptions section carries it.
func PDF(pk *Packet) []byte {
	title := "Clearance evidence packet"
	switch pk.Header.View {
	case ViewFreeze:
		title = "Clearance change-freeze report"
	case ViewIncident:
		title = "Clearance incident report"
	}
	d := newPDF(title)
	h := pk.Header
	d.emit(strings.ToUpper(title), true, 14)
	if h.Title != "" {
		d.bold(h.Title)
	}
	d.blank()
	d.kv("Window", h.From+" to "+h.To+" (UTC, from inclusive, to exclusive)")
	d.kv("Generated", h.GeneratedAt+" by "+h.Producer)
	if h.Filter != (Filter{}) {
		d.kv("Scoped to", strings.TrimSpace(fmt.Sprintf("app=%s env=%s cluster=%s", h.Filter.App, h.Filter.Env, h.Filter.Cluster)))
	}
	d.kv("Observation scopes", orNone(strings.Join(h.Scopes, ", ")))
	d.kv("Mappings", orNone(strings.Join(h.Mappings, ", ")))
	d.kv("Chain", fmt.Sprintf("%d records, head %s, verified from genesis by the job", h.Chain.Count, h.Chain.Head))
	d.kv("Records", fmt.Sprintf("%d in the window; %d carried in full (seq %d to %d, and context)", h.Chain.Window, h.Chain.Carried, h.Chain.FirstSeq, h.Chain.LastSeq))

	cv := pk.Coverage
	d.h1("Coverage statement")
	d.para(cv.Text)
	d.h2("Records by coverage state (every state is listed, at zero too)")
	var rows [][]string
	for _, m := range cv.Matrix {
		rows = append(rows, []string{m.Coverage, itoa(m.Checkpoint), itoa(m.Recorded), itoa(m.NotRecorded), itoa(m.Total)})
	}
	rows = append(rows, []string{"TOTAL", itoa(sumBy(cv.ByAssurance, "checkpointed")), itoa(sumBy(cv.ByAssurance, "recorded-not-checkpointed")),
		itoa(sumBy(cv.ByAssurance, "not-recorded")), itoa(cv.Total)})
	d.table([]string{"coverage", "checkpointed", "recorded-not-ckpt", "not-recorded", "total"}, []int{26, 12, 17, 12, 0}, rows)
	d.h2("Degraded and blind windows")
	rows = nil
	for _, g := range cv.Degraded {
		rows = append(rows, []string{g.Kind, orDash(g.Scope), g.From, g.To, fmt.Sprint(g.Seconds) + "s", g.Reason})
	}
	d.table([]string{"kind", "scope", "from", "to", "len", "reason"}, []int{12, 14, 20, 20, 9, 0}, rows)
	d.h2("Observation health by scope")
	if len(cv.Scopes) == 0 {
		d.para("No scope. No collector reported, so observation coverage is blind for this window.")
	}
	for _, s := range cv.Scopes {
		d.para(s.Text)
		for _, sh := range s.Statement.Health.Sources {
			d.para(fmt.Sprintf("  feed %s: worst %s, now %s, blind %ds, degraded %ds, stale %v", sh.Source, sh.State, sh.Now, sh.Blind, sh.Degraded, sh.Stale))
		}
		d.para(fmt.Sprintf("  cleared and verified %d, seen and not cleared %d, audit gaps %d", s.Statement.Cleared.Count, s.Statement.Seen.Count, len(s.Statement.Blind.Gaps)))
	}

	keep := map[string]bool{}
	for _, s := range h.Sections {
		keep[s] = true
	}
	if keep["control_assertions"] {
		d.h1("Control assertions")
		d.para("Each assertion rests on fields the writer verified. A record that supports it only through a claimed field is counted as claimed-only and is not support.")
		for _, c := range pk.Assertions {
			d.h2(fmt.Sprintf("%s/%s %s", c.Framework, c.Version, c.Control))
			d.para(c.Title)
			rows = nil
			for _, a := range c.Assertions {
				rows = append(rows, []string{a.Status, itoa(a.Supported) + "/" + itoa(a.Population), itoa(a.ClaimedOnly), itoa(a.Failed), a.Statement})
			}
			d.table([]string{"status", "ok/pop", "claimed", "failed", "assertion"}, []int{20, 8, 8, 7, 0}, rows)
			for _, a := range c.Assertions {
				if len(a.Seqs) > 0 {
					d.para(fmt.Sprintf("  %s: see seq %s", a.ID, joinSeqs(a.Seqs)))
				}
			}
		}
	}
	d.h1("Changes")
	d.para("Argo CD manifest trees and Terraform plans side by side; the subject kind says which.")
	rows = nil
	for _, c := range pk.Changes {
		sk, sd := "-", "-"
		if c.Subject != nil {
			sk, sd = c.Subject.Kind, c.Subject.SHA256[:min(8, len(c.Subject.SHA256))]
		}
		tier := "-"
		if c.Tier != nil {
			tier = fmt.Sprint(*c.Tier)
		}
		out := "-"
		if o := c.Outcome; o != nil {
			out = fmt.Sprintf("applied=%s matched=%s by %s", boolStr(o.Applied), boolStr(o.Matched), o.Reporter.Name)
			if o.Reporter.Conformance != "" {
				out += " (" + o.Reporter.Conformance + ")"
			}
			if o.Rollback != nil {
				out += fmt.Sprintf(" rollback used=%s", boolStr(o.Rollback.Used))
			}
		}
		rows = append(rows, []string{c.ID, c.App + "/" + c.Env, sk + ":" + sd, tier, c.State, out})
	}
	d.table([]string{"change", "app/env", "subject", "tier", "state", "outcome"}, []int{19, 18, 24, 4, 12, 0}, rows)
	for _, c := range pk.Changes {
		// Printed only where the records carry it (I-1 adds it to every deploy record about a registered change).
		if len(c.OperationalClass) > 0 {
			d.para(c.ID + ": operational class " + strings.Join(c.OperationalClass, ", ") + orEmpty(c.ClassMapping, " (mapping ", ")"))
		}
	}

	if keep["human_cleared_changes"] {
		d.h1("Human-cleared changes")
		rows = nil
		for _, hc := range pk.HumanCleared {
			for _, a := range hc.Approvers {
				k := a.Kind
				if k == "" {
					k = "not recorded"
				}
				rows = append(rows, []string{hc.Change, a.Person, a.Role, k, a.At})
			}
		}
		d.table([]string{"change", "approver", "role", "kind", "at"}, []int{19, 22, 14, 14, 0}, rows)
		for _, hc := range pk.HumanCleared {
			d.para(hc.Change + " -> " + hc.Printed)
		}
	}
	if keep["ai_identities"] {
		d.h1("AI identities")
		rows = nil
		for _, a := range pk.AIIdentities {
			rows = append(rows, []string{a.Agent, strings.Join(a.Principals, " "), strings.Join(a.ModelVersions, " "), itoa(a.Allowed) + "/" + itoa(a.Denied), strings.Join(a.Changes, " ")})
		}
		d.table([]string{"agent", "principal", "model (claimed)", "allow/deny", "changes proposed"}, []int{18, 26, 18, 10, 0}, rows)
	}

	if len(pk.Timeline) > 0 {
		d.h1("Timeline")
		rows = nil
		for _, t := range pk.Timeline {
			rows = append(rows, []string{t.TS, fmt.Sprint(t.Seq), t.Kind, t.Detail})
		}
		d.table([]string{"ts", "seq", "kind", "detail"}, []int{20, 5, 24, 0}, rows)
	}

	d.h1("Exceptions")
	ex := pk.Exceptions
	rows = nil
	for _, c := range ex.ByClass {
		rows = append(rows, []string{c.State, itoa(c.Count)})
	}
	d.table([]string{"class", "rows"}, []int{32, 0}, rows)
	if ex.Clean != "" {
		d.blank()
		d.bold(ex.Clean)
	}
	if ex.Unverified != "" {
		d.blank()
		d.bold("NOT A CLEAN LIST. " + ex.Unverified)
	}
	for _, class := range ExceptionClasses {
		var cr [][]string
		for _, e := range ex.Rows {
			if e.Class != class {
				continue
			}
			who := orDash(e.Actor)
			cr = append(cr, []string{fmt.Sprint(e.Seq), e.TS, e.Kind, who, orDash(e.Diff), e.Resolution + causeSuffix(e)})
		}
		if len(cr) == 0 {
			continue
		}
		d.h2(class)
		d.table([]string{"seq", "ts", "kind", "actor", "diff", "resolution"}, []int{5, 20, 14, 16, 30, 0}, cr)
	}

	if keep["policy_changes"] {
		d.h1("Policy changes")
		rows = nil
		for _, e := range pk.Policy {
			rows = append(rows, []string{fmt.Sprint(e.Seq), e.TS, e.Kind, orDash(e.Name + e.Ref), orDash(e.Version), e.Detail})
		}
		d.table([]string{"seq", "ts", "kind", "name/ref", "version", "detail"}, []int{5, 20, 16, 30, 14, 0}, rows)
	}

	v := pk.Verification
	d.h1("Verification")
	d.para(v.Chain)
	d.para(v.Statement)
	d.kv("Records file", v.Records)
	if v.Proofs != "" {
		d.kv("Inclusion proofs", fmt.Sprintf("%s (%d)", v.Proofs, v.Ledger.ProofsCarried))
	}
	if v.Ledger.CheckpointFile != "" {
		d.kv("Checkpoint", v.Ledger.CheckpointFile)
	}
	d.kv("Attestation bundles", fmt.Sprintf("%d carried in %s", v.Attestations, orDash(v.AttestationDir)))
	if len(v.AttestationsMissing) > 0 {
		d.kv("Attestations not carried", strings.Join(v.AttestationsMissing, " "))
	}
	if v.OSCAL != "" {
		d.kv("Control mappings (OSCAL)", v.OSCAL)
	}

	d.h1("Acceptances")
	d.para(pk.Acceptances.Statement)
	rows = nil
	for _, rc := range pk.Acceptances.Receipts {
		rows = append(rows, []string{rc.PacketID, rc.Engagement, strings.Join(rc.Mappings, " "), rc.Verdict})
	}
	if len(rows) > 0 {
		d.table([]string{"packet", "engagement", "mappings", "verdict"}, []int{24, 24, 30, 0}, rows)
	}
	return d.bytes()
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func causeSuffix(e Exception) string {
	if e.Cause != "" {
		return " (" + e.Cause + ")"
	}
	return ""
}

func orEmpty(s, pre, post string) string {
	if s == "" {
		return ""
	}
	return pre + s + post
}
