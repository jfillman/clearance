package verify

import (
	"fmt"
	"sort"

	"github.com/jfillman/clearance/internal/evidence"
)

// The assurance states a record has as the packet counts them.
const (
	assCheckpointed = "checkpointed"
	assRecorded     = "recorded-not-checkpointed"
)

// figuresCheck recounts the packet's figures from the carried records: the coverage statement's totals, its counts by
// coverage and by assurance state and their cross, and the header's and verification section's counts. A figure that
// no longer recomputes is named. The tables and sentences of the packet (changes, assertions, exceptions) are not
// recomputed; they are presentation of the records, which the checks above bind.
func (c *ctx) figuresCheck() {
	chk := Check{Name: "packet.json: counted figures recompute from the records"}
	p := c.pk
	if p == nil {
		return // loadPacket reported it
	}
	if len(c.recs) == 0 {
		chk.Status, chk.Detail = NotChecked, "no records to recount from"
		c.rep.add(chk)
		return
	}
	var bad []string
	h := p.Header
	cpSize := int64(-1)
	if c.cp != nil {
		cpSize = c.cp.size
	}
	ass := func(seq int64) string {
		if cpSize >= 0 && seq < cpSize {
			return assCheckpointed
		}
		return assRecorded
	}

	var sel []rec
	inWin, lo, hi := 0, int64(-1), int64(-1)
	scopeOK := map[string]bool{}
	for _, s := range h.Scopes {
		scopeOK[s] = true
	}
	observed := map[string]bool{}
	for _, k := range evidence.ObservedKinds {
		observed[k] = true
	}
	for _, r := range c.recs {
		ts, _ := r.m["ts"].(string)
		if !(ts >= h.From && ts < h.To) {
			continue
		}
		inWin++
		if lo < 0 {
			lo = r.seq
		}
		hi = r.seq
		tool, _ := r.m["tool"].(string)
		if observed[tool] {
			// The builder's scopeWanted: with scopes named, only those; a record with no scope is then out.
			sc, _ := r.m["scope"].(string)
			if (sc != "" && !scopeOK[sc]) || (sc == "" && h.Named) {
				continue
			}
		} else if !gateMatch(r.m, h.Filter.App, h.Filter.Env, h.Filter.Cluster) {
			continue
		}
		sel = append(sel, r)
	}

	eq := func(what string, stated, got any) {
		if stated != got {
			bad = append(bad, fmt.Sprintf("%s: the packet says %v, the records give %v", what, stated, got))
		}
	}
	eq("header: records carried", h.Chain.Carried, len(c.recs))
	eq("header: records in the window", h.Chain.Window, inWin)
	eq("header: first seq in the window", h.Chain.FirstSeq, lo)
	eq("header: last seq in the window", h.Chain.LastSeq, hi)

	cv := p.Coverage
	eq("coverage: total records", cv.Total, len(sel))
	byCov, byAss := map[string]int{}, map[string]int{}
	type cell struct{ ck, rec int }
	mx := map[string]*cell{}
	for _, r := range sel {
		cov, _ := r.m["coverage"].(string)
		if cov == "" {
			cov = evidence.CoverageAuthorizedAndVerified
		}
		a := ass(r.seq)
		byCov[cov]++
		byAss[a]++
		if mx[cov] == nil {
			mx[cov] = &cell{}
		}
		if a == assCheckpointed {
			mx[cov].ck++
		} else {
			mx[cov].rec++
		}
	}
	listed := map[string]bool{}
	sumCov := 0
	for _, e := range cv.ByCoverage {
		listed[e.State] = true
		sumCov += e.Count
		eq("coverage: records "+e.State, e.Count, byCov[e.State])
	}
	for _, s := range evidence.Coverage {
		if !listed[s] {
			bad = append(bad, "coverage: the state "+s+" is not listed (a state left out reads as none)")
		}
	}
	for s := range byCov {
		if !listed[s] {
			bad = append(bad, fmt.Sprintf("coverage: %d record(s) are %s and the packet does not list that state", byCov[s], s))
		}
	}
	eq("coverage: the by-coverage counts add up to the total", sumCov, cv.Total)
	listedA := map[string]bool{}
	sumAss := 0
	for _, e := range cv.ByAssurance {
		listedA[e.State] = true
		sumAss += e.Count
		eq("coverage: records "+e.State, e.Count, byAss[e.State])
	}
	for _, s := range evidence.Assurance {
		if !listedA[s] {
			bad = append(bad, "coverage: the assurance state "+s+" is not listed")
		}
	}
	eq("coverage: the by-assurance counts add up to the total", sumAss, cv.Total)
	for _, m := range cv.Matrix {
		x := mx[m.Coverage]
		if x == nil {
			x = &cell{}
		}
		eq("coverage x assurance: "+m.Coverage+" checkpointed", m.Checkpoint, x.ck)
		eq("coverage x assurance: "+m.Coverage+" recorded-not-checkpointed", m.Recorded, x.rec)
		eq("coverage x assurance: "+m.Coverage+" total", m.Total, x.ck+x.rec)
		eq("coverage x assurance: "+m.Coverage+" not-recorded", m.NotRecorded, 0)
	}

	l := p.Verification.Ledger
	if c.cp != nil || l.State == "checkpointed" {
		ck, after := 0, 0
		for _, r := range c.recs {
			if ass(r.seq) == assCheckpointed {
				ck++
			} else {
				after++
			}
		}
		eq("verification: carried records under the checkpoint", l.Checkpointed, ck)
		eq("verification: carried records after the checkpoint", l.NotCheckpointed, after)
		eq("verification: proofs carried", l.ProofsCarried, ck)
	}
	nb := 0
	for _, ch := range p.Changes {
		if ch.Attestation != nil && ch.Attestation.Bundle != "" {
			nb++
		}
	}
	eq("verification: attestations carried", p.Verification.Attestations, nb)

	sort.Strings(bad)
	chk.Findings = bad
	if len(bad) > 0 {
		chk.Status, chk.Detail = Fail, fmt.Sprintf("%d figure(s) no longer recompute", len(bad))
	} else {
		chk.Status, chk.Detail = Pass, fmt.Sprintf("totals, coverage and assurance counts, their cross and the header and verification counts all recompute (%d records in the counts)", len(sel))
	}
	c.rep.add(chk)
}

// gateMatch is the view's app, env and cluster scoping of a gate record (the packet's rule, restated: the verifier
// does not import the packet builder).
func gateMatch(r map[string]any, app, env, cluster string) bool {
	if app == "" && env == "" && cluster == "" {
		return true
	}
	cl, en := place(r)
	a := str(r, "app")
	if a == "" {
		a = str(obj(r, "change"), "app")
	}
	return (app == "" || a == app) && (env == "" || en == env) && (cluster == "" || cl == cluster)
}

func place(r map[string]any) (cluster, env string) {
	d := obj(r, "destination")
	if w := obj(d, "workspace"); w != nil {
		return str(w, "backend") + "/" + str(w, "key") + "#" + str(w, "name"), str(w, "name")
	}
	cluster, env = str(d, "cluster"), str(d, "environment")
	if ch := obj(r, "change"); ch != nil {
		if cluster == "" {
			cluster = str(ch, "cluster")
		}
		if env == "" {
			env = str(ch, "env")
		}
	}
	if bg := obj(r, "breakglass"); bg != nil {
		if cluster == "" {
			cluster = str(bg, "cluster")
		}
		if env == "" {
			env = str(bg, "env")
		}
	}
	return
}

func str(m map[string]any, k string) string { v, _ := m[k].(string); return v }

func obj(m map[string]any, k string) map[string]any { v, _ := m[k].(map[string]any); return v }
