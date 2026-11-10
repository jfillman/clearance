package collector

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/observe"
)

// TrailState is what the CloudTrail API says about a trail (feeds.Control.Trails).
type TrailState struct {
	Name          string
	Logging       bool // GetTrailStatus.IsLogging
	MultiRegion   bool
	Organization  bool
	LogValidation bool
	DeliveryError string // GetTrailStatus.LatestDeliveryError
	Management    bool   // the event selectors include management events
	ReadWrite     string // All, WriteOnly or ReadOnly
	DataBuckets   []string
}

// RecorderState is an AWS Config configuration recorder's status.
type RecorderState struct {
	Name       string
	Recording  bool
	LastStatus string // SUCCESS, PENDING or FAILURE
	Error      string
}

// RuleState is an EventBridge rule's state.
type RuleState struct{ Name, State string }

// Control reads the controls that watch an account, read-only. Any may be nil: that check is then not made (and is not
// claimed).
type Control struct {
	Trails func(ctx context.Context) ([]TrailState, error)
	// DataTrails are the trails the observed account owns, read with the observed account's own role (the main trail
	// is an organization trail owned by the management account, which Trails reads). A data bucket's events may be
	// recorded by either.
	DataTrails func(ctx context.Context) ([]TrailState, error)
	Recorders  func(ctx context.Context) ([]RecorderState, error)
	Rules      func(ctx context.Context, names []string) ([]RuleState, error)
}

// HealthConfig is what the account's feeds are expected to look like.
type HealthConfig struct {
	Account string
	// Trail is the name of the trail expected (empty: any logging trail satisfies trail-enabled).
	Trail string
	// DataTrail is the name of the account's own trail expected to record the data buckets' events (empty: any trail in
	// the account, or the main trail, that records them satisfies event-selectors).
	DataTrail string
	// MustCoverRegions are the regions the trail must cover: a multi-region (or organization) trail covers all of them.
	MustCoverRegions []string
	// DataBuckets are the buckets whose data events the selectors must include.
	DataBuckets []string
	// Rules are the EventBridge rules that must be enabled.
	Rules []string
	// DigestMaxAge is how old the newest verified digest may be (default 3h: digests are hourly and delivery lags).
	DigestMaxAge time.Duration
	// FailureMemory is how long a verification failure keeps digests-validating failed (default 24h). A tampered file
	// does not heal by itself.
	FailureMemory time.Duration
	// DrainMaxAge is how old the last successful drain of the queue may be (default 2 x the interval, at least 2m).
	DrainMaxAge time.Duration
	Interval    time.Duration // how often health is reported (default 5m)
}

// Health assembles and reports an account's health record.
type Health struct {
	Cfg     HealthConfig
	Ctl     Control
	Trail   *TrailReader // nil: the S3 trail is not read (digests checks are not made)
	Col     *Collector
	Core    Core
	Now     func() time.Time
	started time.Time

	mu      sync.Mutex
	drained time.Time
}

func (h *Health) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Drained records a successful drain of the queue.
func (h *Health) Drained() {
	h.mu.Lock()
	h.drained = h.now()
	h.mu.Unlock()
}

type check struct {
	name   string
	ok     bool
	detail string
	blind  bool // failing this leaves nothing seen: blind, not degraded
}

func (h *Health) cfg() HealthConfig {
	c := h.Cfg
	if c.Interval == 0 {
		c.Interval = 5 * time.Minute
	}
	if c.DigestMaxAge == 0 {
		c.DigestMaxAge = 3 * time.Hour
	}
	if c.FailureMemory == 0 {
		c.FailureMemory = 24 * time.Hour
	}
	if c.DrainMaxAge == 0 {
		c.DrainMaxAge = max(2*c.Interval, 2*time.Minute)
	}
	return c
}

// Checks runs the checks. The conventional names are docs/evidence.md's: trail-enabled, regions-covered,
// event-selectors, digests-arriving, digests-validating, recorder-running, rules-enabled, collector-current.
func (h *Health) Checks(ctx context.Context) []check {
	c := h.cfg()
	now := h.now()
	var out []check
	if h.Ctl.Trails != nil {
		trails, err := h.Ctl.Trails(ctx)
		var own []TrailState
		var ownErr error
		if h.Ctl.DataTrails != nil {
			own, ownErr = h.Ctl.DataTrails(ctx)
		}
		out = append(out, trailChecks(c, trails, err, own, ownErr, h.Ctl.DataTrails != nil)...)
	}
	if h.Trail != nil {
		newest := h.Trail.Newest()
		switch {
		case newest.IsZero() && now.Sub(h.started) < c.DigestMaxAge:
			out = append(out, check{"digests-arriving", true, "no digest read yet; within the first " + c.DigestMaxAge.String(), true})
		case newest.IsZero():
			out = append(out, check{"digests-arriving", false, "no digest has been read since the collector started", true})
		case now.Sub(newest) > c.DigestMaxAge:
			out = append(out, check{"digests-arriving", false, fmt.Sprintf("the newest verified digest ended %s ago (limit %s)", now.Sub(newest).Round(time.Minute), c.DigestMaxAge), true})
		default:
			out = append(out, check{"digests-arriving", true, "newest verified digest ended " + newest.UTC().Format(time.RFC3339), true})
		}
		fs := h.Trail.Failures(now.Add(-c.FailureMemory))
		if len(fs) == 0 {
			out = append(out, check{name: "digests-validating", ok: true, detail: "every digest signature, link and log file hash verified"})
		} else {
			var d []string
			for _, f := range fs[max(0, len(fs)-3):] {
				d = append(d, f.Reason+" "+f.Key)
			}
			out = append(out, check{name: "digests-validating", detail: fmt.Sprintf("%d verification failure(s) in the last %s; latest: %s", len(fs), c.FailureMemory, strings.Join(d, "; "))})
		}
	}
	if h.Ctl.Recorders != nil {
		rs, err := h.Ctl.Recorders(ctx)
		out = append(out, recorderCheck(rs, err))
	}
	if h.Ctl.Rules != nil && len(c.Rules) > 0 {
		rs, err := h.Ctl.Rules(ctx, c.Rules)
		out = append(out, ruleCheck(c, rs, err))
	}
	h.mu.Lock()
	drained := h.drained
	h.mu.Unlock()
	switch {
	case drained.IsZero() && now.Sub(h.started) < c.DrainMaxAge:
		out = append(out, check{"collector-current", true, "starting", true})
	case drained.IsZero():
		out = append(out, check{"collector-current", false, "the queue has not been drained since the collector started", true})
	case now.Sub(drained) > c.DrainMaxAge:
		out = append(out, check{"collector-current", false, fmt.Sprintf("the queue was last drained %s ago (limit %s)", now.Sub(drained).Round(time.Second), c.DrainMaxAge), true})
	default:
		out = append(out, check{"collector-current", true, "last drained " + drained.UTC().Format(time.RFC3339), true})
	}
	if h.Col != nil {
		out = append(out, check{name: "scope-not-evaluated", ok: true, detail: clipText(h.Col.Filter.Statement(), 3500)})
	}
	return out
}

// The main trail (c.Trail, the organization trail) carries the management events and trail-enabled. The data buckets'
// events may be recorded by it or by a trail the observed account owns (own, read with that account's role): each
// bucket needs one logging trail, with log file validation on, that records it. A trail that records a bucket and is
// not logging (or has validation off) is named in the detail, so a StopLogging shows on the next health record.
func trailChecks(c HealthConfig, trails []TrailState, err error, own []TrailState, ownErr error, ownRead bool) []check {
	if err != nil {
		return []check{{"trail-enabled", false, "the trail could not be read: " + err.Error(), true}}
	}
	var pick []TrailState
	for _, t := range trails {
		if c.Trail == "" || t.Name == c.Trail {
			pick = append(pick, t)
		}
	}
	if len(pick) == 0 {
		return []check{{"trail-enabled", false, "no trail named " + orElse(c.Trail, "(any)") + " exists", true}}
	}
	var logging []TrailState
	for _, t := range pick {
		if t.Logging {
			logging = append(logging, t)
		}
	}
	var out []check
	if len(logging) == 0 {
		out = append(out, check{"trail-enabled", false, "trail " + pick[0].Name + " is not logging", true})
		return out
	}
	t := logging[0]
	out = append(out, check{"trail-enabled", true, "trail " + t.Name + " is logging", true})
	switch {
	case t.MultiRegion || t.Organization:
		out = append(out, check{name: "regions-covered", ok: true, detail: "trail " + t.Name + " is multi-region"})
	default:
		out = append(out, check{name: "regions-covered", detail: "trail " + t.Name + " covers one region only; required: " + strings.Join(c.MustCoverRegions, ", ")})
	}
	var bad []string
	if !t.Management {
		bad = append(bad, "management events are not included")
	}
	if t.ReadWrite != "" && t.ReadWrite != "All" && t.ReadWrite != "WriteOnly" {
		bad = append(bad, "ReadWriteType is "+t.ReadWrite+": writes are not recorded")
	}
	bad = append(bad, dataTrailProblems(c, t, own, ownErr, ownRead)...)
	if !t.LogValidation {
		bad = append(bad, "log file validation is off")
	}
	if t.DeliveryError != "" {
		bad = append(bad, "latest delivery error: "+t.DeliveryError)
	}
	if len(bad) == 0 {
		out = append(out, check{name: "event-selectors", ok: true, detail: "management events and the expected data events are recorded; log file validation on" + trailsDetail(t, c, own)})
	} else {
		out = append(out, check{name: "event-selectors", detail: strings.Join(bad, "; ")})
	}
	return out
}

func recorderCheck(rs []RecorderState, err error) check {
	if err != nil {
		return check{name: "recorder-running", detail: "the Config recorder could not be read: " + err.Error()}
	}
	if len(rs) == 0 {
		return check{name: "recorder-running", detail: "no AWS Config recorder exists in the account"}
	}
	for _, r := range rs {
		if !r.Recording || (r.LastStatus != "" && r.LastStatus != "SUCCESS") {
			return check{name: "recorder-running", detail: fmt.Sprintf("recorder %s is not recording (recording %t, last status %s %s)", r.Name, r.Recording, r.LastStatus, r.Error)}
		}
	}
	return check{name: "recorder-running", ok: true, detail: "recording"}
}

func ruleCheck(c HealthConfig, rs []RuleState, err error) check {
	if err != nil {
		return check{name: "rules-enabled", detail: "the rules could not be read: " + err.Error()}
	}
	state := map[string]string{}
	for _, r := range rs {
		state[r.Name] = r.State
	}
	var bad []string
	for _, n := range c.Rules {
		if state[n] != "ENABLED" {
			bad = append(bad, n+" is "+orElse(state[n], "missing"))
		}
	}
	if len(bad) > 0 {
		return check{name: "rules-enabled", detail: strings.Join(bad, "; ")}
	}
	return check{name: "rules-enabled", ok: true, detail: "enabled: " + strings.Join(c.Rules, ", ")}
}

// State is the health the checks add up to: healthy when all pass, else blind if a check that leaves nothing seen
// failed, else degraded.
func State(cs []check) string {
	state := observe.Healthy
	for _, c := range cs {
		if c.ok {
			continue
		}
		if c.blind {
			return observe.Blind
		}
		state = observe.Degraded
	}
	return state
}

// Post runs the checks and reports them: an observation.health record for the account. Only a healthy record clears
// the pipeline's health flip (Pipeline.Healthy): a feed that is still broken keeps the account blind.
func (h *Health) Post(ctx context.Context) (string, error) {
	if h.started.IsZero() {
		h.started = h.now()
	}
	cs := h.Checks(ctx)
	state := State(cs)
	list := make([]any, 0, len(cs))
	for _, c := range cs {
		m := map[string]any{"name": c.name, "ok": c.ok}
		if c.detail != "" {
			m["detail"] = clipText(c.detail, 3900)
		}
		list = append(list, m)
	}
	interval := int(h.cfg().Interval.Seconds())
	rec := client.ProviderEvent{Scope: client.String(h.Cfg.Account), Source: map[string]any{"name": ProviderName},
		Health: map[string]any{"state": state, "checks": list, "interval_seconds": interval}}
	if _, err := h.Core.Record(ctx, &client.RecordRequest{Kind: evidence.KindHealth, Record: rec}); err != nil {
		return state, fmt.Errorf("posting health: %w", err)
	}
	if state == observe.Healthy && h.Col != nil {
		h.Col.Pipe.Healthy(h.Cfg.Account)
	}
	return state, nil
}

// Start sets the clock the startup grace is measured from.
func (h *Health) Start() {
	if h.started.IsZero() {
		h.started = h.now()
	}
}

// dataTrailProblems is what keeps the data buckets from being recorded by a logging, validated trail.
func dataTrailProblems(c HealthConfig, main TrailState, own []TrailState, ownErr error, ownRead bool) []string {
	var cands []TrailState // every trail that may satisfy a data bucket: the main trail, then the account's own
	cands = append(cands, main)
	var bad []string
	if ownRead && c.DataTrail != "" {
		found := false
		for _, t := range own {
			if t.Name == c.DataTrail {
				found = true
				if !t.Logging {
					bad = append(bad, "data trail "+t.Name+" is not logging")
				}
				if t.DeliveryError != "" {
					bad = append(bad, "data trail "+t.Name+" latest delivery error: "+t.DeliveryError)
				}
			}
		}
		if !found && ownErr == nil {
			bad = append(bad, "data trail "+c.DataTrail+" does not exist in the account")
		}
	}
	for _, t := range own {
		if c.DataTrail == "" || t.Name == c.DataTrail {
			cands = append(cands, t)
		}
	}
	for _, b := range c.DataBuckets {
		var why []string
		ok := false
		for _, t := range cands {
			if !slices.Contains(t.DataBuckets, b) {
				continue
			}
			switch {
			case !t.Logging:
				why = append(why, "data trail "+t.Name+" is not logging")
			case !t.LogValidation:
				why = append(why, "data trail "+t.Name+" has log file validation off")
			default:
				ok = true
			}
		}
		switch {
		case ok:
		case len(why) > 0:
			bad = append(bad, why...)
		case ownErr != nil:
			bad = append(bad, "no data events for bucket "+b+" on trail "+main.Name+" and the account's trails could not be read: "+ownErr.Error())
		case !ownRead:
			bad = append(bad, "no data events for bucket "+b)
		default:
			bad = append(bad, "no data events for bucket "+b+" on any logging trail ("+trailNames(cands)+")")
		}
	}
	// the same trail can explain several buckets
	var out []string
	for _, m := range bad {
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

func trailNames(ts []TrailState) string {
	var n []string
	for _, t := range ts {
		n = append(n, t.Name)
	}
	return strings.Join(n, ", ")
}

// trailsDetail reports each trail that carries a data bucket's events.
func trailsDetail(main TrailState, c HealthConfig, own []TrailState) string {
	var parts []string
	for _, t := range append([]TrailState{main}, own...) {
		if len(t.DataBuckets) > 0 && (t.Name == main.Name || c.DataTrail == "" || t.Name == c.DataTrail) {
			parts = append(parts, fmt.Sprintf("%s (logging %t, validation %t: %s)", t.Name, t.Logging, t.LogValidation, strings.Join(t.DataBuckets, ", ")))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "; data events: " + strings.Join(parts, "; ")
}
