package packet

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
)

// CSVs are the packet's sections as CSV projections, by file name. The JSON is canonical; these are views of it for
// a spreadsheet, and every cell that a spreadsheet would read as a formula is prefixed so it stays text.
func CSVs(pk *Packet) (map[string][]byte, error) {
	out := map[string][]byte{}
	put := func(name string, header []string, rows [][]string) error {
		var b bytes.Buffer
		w := csv.NewWriter(&b)
		if err := w.Write(header); err != nil {
			return err
		}
		for _, r := range rows {
			for i := range r {
				r[i] = safeCell(r[i])
			}
			if err := w.Write(r); err != nil {
				return err
			}
		}
		w.Flush()
		out[name] = b.Bytes()
		return w.Error()
	}
	var err error
	do := func(e error) {
		if err == nil {
			err = e
		}
	}
	cov := pk.Coverage
	var rows [][]string
	for _, m := range cov.Matrix {
		rows = append(rows, []string{m.Coverage, itoa(m.Checkpoint), itoa(m.Recorded), itoa(m.NotRecorded), itoa(m.Total)})
	}
	rows = append(rows, []string{"TOTAL", itoa(sumBy(cov.ByAssurance, "checkpointed")), itoa(sumBy(cov.ByAssurance, "recorded-not-checkpointed")),
		itoa(sumBy(cov.ByAssurance, "not-recorded")), itoa(cov.Total)})
	do(put("coverage.csv", []string{"coverage", "checkpointed", "recorded_not_checkpointed", "not_recorded", "total"}, rows))
	rows = nil
	for _, s := range cov.Scopes {
		st := s.Statement
		rows = append(rows, []string{s.Scope, fmt.Sprint(s.Collector), st.State, fmt.Sprint(st.Clean), itoa(st.Cleared.Count), itoa(st.Seen.Count),
			fmt.Sprint(st.Blind.Seconds), fmt.Sprint(cov.WindowVerified), s.Text, itoa(st.Integrity.Observations), itoa(st.Integrity.Verified), itoa(st.Integrity.Later)})
	}
	do(put("coverage-scopes.csv", []string{"scope", "collector", "state", "clean", "cleared_and_verified", "seen_not_cleared", "could_not_see_seconds", "window_verified", "text",
		"observations", "source_verified", "source_verified_later"}, rows))
	rows = nil
	for _, d := range cov.Degraded {
		seq := ""
		if d.Seq != nil {
			seq = fmt.Sprint(*d.Seq)
		}
		rows = append(rows, []string{d.Kind, d.Scope, d.Source, d.From, d.To, fmt.Sprint(d.Seconds), d.Reason, seq})
	}
	do(put("degraded-windows.csv", []string{"kind", "scope", "source", "from", "to", "seconds", "reason", "seq"}, rows))
	rows = nil
	for _, c := range pk.Assertions {
		for _, a := range c.Assertions {
			rows = append(rows, []string{c.Framework + "/" + c.Version, c.Control, a.ID, a.Status, itoa(a.Population), itoa(a.Supported),
				itoa(a.ClaimedOnly), itoa(a.Failed), joinSeqs(a.Seqs), a.Statement})
		}
	}
	do(put("assertions.csv", []string{"mapping", "control", "assertion", "status", "population", "supported", "claimed_only", "failed", "seqs", "statement"}, rows))
	rows = nil
	for _, c := range pk.Changes {
		var sk, sd, sg string
		if c.Subject != nil {
			sk, sd, sg = c.Subject.Kind, c.Subject.SHA256, c.Subject.GitCommit
		}
		tier, applied, matched, rep, conf, rb := "", "", "", "", "", ""
		if c.Tier != nil {
			tier = fmt.Sprint(*c.Tier)
		}
		if o := c.Outcome; o != nil {
			applied, matched, rep, conf = boolStr(o.Applied), boolStr(o.Matched), o.Reporter.Name, o.Reporter.Conformance
			if o.Rollback != nil {
				rb = fmt.Sprintf("available=%s used=%s to=%s", boolStr(o.Rollback.Available), boolStr(o.Rollback.Used), o.Rollback.To)
			}
		}
		rows = append(rows, []string{c.ID, c.App, c.Env, c.Place, sk, sd, sg, tier, strings.Join(c.OperationalClass, " "), c.State,
			ptrStr(c.Request), ptrStr(c.Clear), c.ClearedBy, applied, matched, rep, conf, rb, fmt.Sprint(c.Failed), joinSeqs(c.Exceptions)})
	}
	do(put("changes.csv", []string{"change", "app", "env", "place", "subject_kind", "subject_sha256", "git_commit", "tier", "operational_class", "state",
		"request_seq", "clear_seq", "cleared_by", "applied", "matched", "reported_by", "conformance", "rollback", "failed", "exception_seqs"}, rows))
	rows = nil
	for _, h := range pk.HumanCleared {
		for _, a := range h.Approvers {
			kind := a.Kind
			if kind == "" {
				kind = "unrecorded"
			}
			rows = append(rows, []string{h.Change, h.App, h.Env, fmt.Sprint(h.ClearSeq), a.Person, a.Sub, a.Iss, a.Role, a.Via, a.At, kind, h.Printed})
		}
	}
	do(put("human-cleared.csv", []string{"change", "app", "env", "clear_seq", "person", "sub", "iss", "role", "via", "at", "kind", "approvers_statement"}, rows))
	rows = nil
	for _, a := range pk.AIIdentities {
		rows = append(rows, []string{a.Agent, strings.Join(a.Principals, " "), strings.Join(a.ModelVersions, " "), itoa(a.Records), itoa(a.Allowed), itoa(a.Denied),
			strings.Join(a.Changes, " "), strings.Join(a.Provenance, " "), a.FirstTS, a.LastTS})
	}
	do(put("ai-identities.csv", []string{"agent", "principals", "model_versions_claimed", "records", "allowed", "denied", "changes_proposed", "provenance", "first_ts", "last_ts"}, rows))
	rows = nil
	for _, e := range pk.Exceptions.Rows {
		rows = append(rows, []string{e.Class, fmt.Sprint(e.Seq), e.TS, e.Kind, e.Source, e.Scope, e.Subject, e.Actor, e.Diff, e.Resolution, e.Cause, e.Window,
			strings.Join(e.OperationalClass, " "), e.Detail, ptrStr(e.ResolutionSeq), e.ResolvedBy, fmt.Sprint(e.SourceVerified)})
	}
	do(put("exceptions.csv", []string{"class", "seq", "ts", "kind", "source", "scope", "subject", "actor", "diff", "resolution", "cause", "break_glass_window", "operational_class", "detail",
		"resolution_seq", "resolved_by", "source_verified"}, rows))
	if oc := pk.Observed; oc != nil {
		rows = nil
		for _, o := range oc.Rows {
			rows = append(rows, []string{fmt.Sprint(o.Seq), o.TS, o.Scope, o.Source, o.Resource, o.Actor, o.API, o.Diff, o.Coverage, o.Resolution, o.Cause, o.ResolvedBy,
				fmt.Sprint(o.SourceVerified), o.VerifiedBy})
		}
		do(put("observed-changes.csv", []string{"seq", "ts", "scope", "source", "resource", "actor", "api", "diff", "coverage", "resolution", "cause", "resolved_by", "source_verified", "verified_by"}, rows))
	}
	rows = nil
	for _, e := range pk.Policy {
		rows = append(rows, []string{fmt.Sprint(e.Seq), e.TS, e.Kind, e.Name, e.Ref, e.Version, e.Digest, e.Detail})
	}
	do(put("policy-changes.csv", []string{"seq", "ts", "kind", "name", "ref", "version", "digest", "detail"}, rows))
	rows = nil
	for _, r := range pk.Acceptances.Receipts {
		rows = append(rows, []string{r.PacketID, r.Engagement, strings.Join(r.Mappings, " "), r.Checkpoint, r.Verdict})
	}
	do(put("acceptances.csv", []string{"packet_id", "engagement", "framework_mapping_versions", "checkpoint", "verdict"}, rows))
	return out, err
}

func itoa(n int) string { return fmt.Sprint(n) }

func sumBy(cs []Count, state string) int {
	for _, c := range cs {
		if c.State == state {
			return c.Count
		}
	}
	return 0
}

func boolStr(b *bool) string {
	if b == nil {
		return ""
	}
	return fmt.Sprint(*b)
}

func ptrStr(n *int64) string {
	if n == nil {
		return ""
	}
	return fmt.Sprint(*n)
}

// safeCell keeps a spreadsheet from reading a cell as a formula (CSV injection).
func safeCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
