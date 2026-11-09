package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/store"
)

// eventKey is the provider's own id for the event a record reports: source.name (""when the source has none) and
// source.event_id. A record without an event_id has no key and is never a duplicate.
func eventKey(ev store.Event) (source, id string, ok bool) {
	src, _ := ev["source"].(map[string]any)
	id, ok = src["event_id"].(string)
	source, _ = src["name"].(string)
	return source, id, ok && id != ""
}

// observedVerified is what the core establishes about an observation kind's record beyond provider and ts: the tier
// of an operation on monitoring, and whether the feed's health supported the observation's completeness claim.
func observedVerified(extra ...string) map[string]bool {
	m := union(recordVerified, "")
	delete(m, "")
	for _, k := range extra {
		m[k] = true
	}
	return m
}

// coreVerified is for the records the core derives itself (a feed's health flipped by an operation on monitoring, the
// audit gap a feed dropping leaves): everything in them is the core's own conclusion.
var coreVerified = union(evidence.GatewayVerified, "ts", "scope", "source", "health", "gap", "about", "tier")

func bad(format string, a ...any) error { return &gate.BadReport{Message: fmt.Sprintf(format, a...)} }

// appendObserved writes an observation kind's record and what follows from it, in one transaction: for an
// observation, whether its feed's health supports its completeness claim, and, for an operation on monitoring, the
// scope's health flipped (blind when it succeeded, degraded when it did not) and an audit gap; for an assessment or a
// resolution, that the record it is about exists, is of the right kind and is in the same scope; for a health
// record, an audit gap when the feed went from healthy (or unseen) to degraded or blind.
func (s *Server) appendObserved(ctx context.Context, tx store.Tx, kind string, ev store.Event, wr evidence.Writer,
	res observe.Result) (store.Record, error) {
	now := s.opt.Clock()
	scope, _ := ev["scope"].(string)
	source := res.Source
	verified := observedVerified()
	switch kind {
	case evidence.KindObservation:
		health, err := tx.LatestHealth(ctx, scope, source)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		ev["completeness_supported"] = err == nil && observe.Supports(health, now)
		verified["completeness_supported"] = true
		if res.Monitoring {
			verified["tier"] = true
		}
	case evidence.KindAssessment, evidence.KindResolution, evidence.KindVerification:
		about, _ := observe.About(ev)
		rs, err := tx.Records(ctx, about, 1)
		if err != nil {
			return nil, err
		}
		if len(rs) == 0 {
			return nil, bad("about.seq %d is not a record", about)
		}
		a := rs[0]
		if seq, _ := gate.SeqInt(a["seq"]); seq != about {
			return nil, bad("about.seq %d is not a record", about)
		}
		ok := a["tool"] == evidence.KindObservation || (kind == evidence.KindResolution && a["tool"] == evidence.KindAssessment)
		if !ok {
			if kind == evidence.KindVerification {
				return nil, bad("about.seq %d is a %v record: a verification is about an observation", about, a["tool"])
			}
			if kind == evidence.KindResolution {
				return nil, bad("about.seq %d is a %v record: a resolution is about an observation or an assessment", about, a["tool"])
			}
			return nil, bad("about.seq %d is a %v record: an assessment is about an observation", about, a["tool"])
		}
		if kind == evidence.KindVerification {
			if src, _ := a["source"].(map[string]any); src["name"] != source {
				return nil, bad("about.seq %d was reported by source %v: a feed verifies only its own observations", about, src["name"])
			}
		}
		if a["scope"] != scope {
			return nil, bad("about.seq %d is in scope %v, not %s", about, a["scope"], scope)
		}
	case evidence.KindHealth:
		// below
	}
	var prev store.Record
	if kind == evidence.KindHealth || res.Monitoring {
		var err error
		if prev, err = tx.LatestHealth(ctx, scope, source); err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			prev = nil
		}
	}
	sealed := wr
	sealed.Verified = verified
	rec, err := tx.Append(ctx, ev, sealed)
	if err != nil {
		return nil, err
	}
	seq, _ := gate.SeqInt(rec["seq"])
	switch {
	case kind == evidence.KindHealth:
		if st := observe.HealthState(rec); st != observe.Healthy {
			err = s.gap(ctx, tx, scope, source, st, "health-reported", seq, prev, now)
		}
	case res.Monitoring:
		st := observe.Degraded
		if res.Succeeded {
			st = observe.Blind
		}
		if observe.PrevRank(prev) < observe.Rank(st) {
			err = s.flip(ctx, tx, scope, source, st, seq, res, prev, now)
		}
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// flip records the scope's health as the core now sees it after an operation on monitoring (the provider's next
// healthy health record, which its own checks produce, is what clears it), and the gap if the feed was healthy.
func (s *Server) flip(ctx context.Context, tx store.Tx, scope, source, state string, about int64, res observe.Result,
	prev store.Record, now time.Time) error {
	outcome := "refused"
	if res.Succeeded {
		outcome = "succeeded"
	}
	h := store.Event{"ts": evidence.ISO(now), "tool": evidence.KindHealth, "boundary": "deployment",
		"scope": scope, "source": map[string]any{"name": source}, "coverage": evidence.CoverageObservedNotAttributed,
		"about": map[string]any{"seq": json.Number(fmt.Sprint(about))},
		"health": map[string]any{"state": state, "checks": []any{map[string]any{"name": "monitoring-protection",
			"ok": false, "detail": "an operation on the controls that watch " + scope + " " + outcome}}}}
	wr := evidence.Core(s.opt.Version)
	wr.Verified = coreVerified
	rec, err := tx.Append(ctx, h, wr)
	if err != nil {
		return err
	}
	hseq, _ := gate.SeqInt(rec["seq"])
	return s.gap(ctx, tx, scope, source, state, "monitoring-protection", hseq, prev, now)
}

// gap writes the audit gap a feed dropping leaves, when it was healthy (or never seen) just before.
func (s *Server) gap(ctx context.Context, tx store.Tx, scope, source, state, reason string, healthSeq int64,
	prev store.Record, now time.Time) error {
	if observe.PrevRank(prev) > 0 {
		return nil // already down: the gap is open
	}
	g := map[string]any{"state": state, "reason": reason, "health_seq": json.Number(fmt.Sprint(healthSeq))}
	if prev != nil {
		g["since"] = prev["ts"]
	}
	e := store.Event{"ts": evidence.ISO(now), "tool": evidence.KindAuditGap, "boundary": "deployment", "scope": scope,
		"source": map[string]any{"name": source}, "coverage": "coverage-unavailable", "gap": g}
	wr := evidence.Core(s.opt.Version)
	wr.Verified = coreVerified
	_, err := tx.Append(ctx, e, wr)
	return err
}
