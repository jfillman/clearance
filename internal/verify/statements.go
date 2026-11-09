package verify

import (
	"fmt"
	"sort"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/observe"
)

// statementsCheck rebuilds each observed scope's coverage statement from the carried records with the same function the
// packet and GET /v1/coverage use (observe.Build), and compares what the packet prints: the feed's state, whether the
// window was clean, how many observations were cleared and verified, seen and not cleared, how many seconds could not
// be seen (a collector that stopped is a blind window here, recomputed from the health records and the clock the
// packet was made at) and how many observations had their source verified. A packet whose scope says healthy and clean
// over a window the records show blind does not pass.
func (c *ctx) statementsCheck() {
	chk := Check{Name: "packet.json: each scope's coverage statement recomputes from the records"}
	p := c.pk
	if p == nil {
		return // loadPacket reported it
	}
	if len(c.recs) == 0 {
		chk.Status, chk.Detail = NotChecked, "no records to rebuild the statements from"
		c.rep.add(chk)
		return
	}
	from, e1 := time.Parse(time.RFC3339, p.Header.From)
	to, e2 := time.Parse(time.RFC3339, p.Header.To)
	now, e3 := time.Parse(time.RFC3339, p.Header.Generated)
	if e1 != nil || e2 != nil || e3 != nil {
		chk.Status, chk.Detail = Fail, "the header's from, to and generated_at are not RFC 3339 times: the statements cannot be rebuilt"
		c.rep.add(chk)
		return
	}
	fromS, toS := p.Header.From, p.Header.To
	var bad []string
	eq := func(scope, what string, stated, got any) {
		if stated != got {
			bad = append(bad, fmt.Sprintf("scope %s, %s: the packet says %v, the records give %v", scope, what, stated, got))
		}
	}
	checked := 0
	for _, s := range p.Coverage.Scopes {
		in := observe.Input{Scope: s.Scope, Window: observe.Window{From: from.UTC(), To: to.UTC()}}
		for _, r := range c.recs {
			m := r.m
			if sc, _ := m["scope"].(string); sc != s.Scope {
				continue
			}
			tool, _ := m["tool"].(string)
			ts, _ := m["ts"].(string)
			switch tool {
			case evidence.KindObservation:
				if ts >= fromS && ts < toS {
					in.Observations = append(in.Observations, m)
				}
			case evidence.KindAssessment:
				in.Assessments = append(in.Assessments, m)
			case evidence.KindResolution:
				in.Resolutions = append(in.Resolutions, m)
			case evidence.KindVerification:
				in.Verifications = append(in.Verifications, m)
			case evidence.KindHealth:
				if ts < toS {
					in.Health = append(in.Health, m)
				}
			case evidence.KindAuditGap:
				if ts >= fromS && ts < toS {
					in.Gaps = append(in.Gaps, m)
				}
			}
		}
		st := observe.Build(in, now.UTC())
		eq(s.Scope, "feed state", s.Statement.State, st.State)
		eq(s.Scope, "clean", s.Statement.Clean, st.Clean)
		eq(s.Scope, "collector reported", s.Collector, len(st.Health.Sources) > 0)
		eq(s.Scope, "cleared and verified", s.Statement.Cleared.Count, st.Cleared.Count)
		eq(s.Scope, "seen, not cleared", s.Statement.Seen.Count, st.Seen.Count)
		eq(s.Scope, "seconds that could not be seen", s.Statement.Blind.Seconds, st.Blind.Seconds)
		eq(s.Scope, "observations counted for source integrity", s.Statement.Integrity.Observations, st.Integrity.Observations)
		eq(s.Scope, "observations with a verified source", s.Statement.Integrity.Verified, st.Integrity.Verified)
		eq(s.Scope, "observations verified by a later record", s.Statement.Integrity.Later, st.Integrity.Later)
		checked++
	}
	sort.Strings(bad)
	chk.Findings = bad
	switch {
	case len(bad) > 0:
		chk.Status, chk.Detail = Fail, fmt.Sprintf("%d statement figure(s) no longer recompute", len(bad))
	case checked == 0:
		chk.Status, chk.Detail = NotChecked, "the packet states no observation scope: there is no statement to rebuild"
	default:
		chk.Status, chk.Detail = Pass, fmt.Sprintf("%d scope statement(s) (state, clean, cleared, seen, could-not-see seconds, source integrity) rebuild from the carried records", checked)
	}
	c.rep.add(chk)
}
