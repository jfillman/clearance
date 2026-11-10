package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/observe"
)

func healthy() (TrailState, RecorderState, []RuleState) {
	return TrailState{Name: "organization", Logging: true, MultiRegion: true, Organization: true, LogValidation: true, Management: true,
			ReadWrite: "All", DataBuckets: []string{"tf-state"}},
		RecorderState{Name: "default", Recording: true, LastStatus: "SUCCESS"},
		[]RuleState{{"observe-aws-cloudtrail", "ENABLED"}, {"observe-aws-config", "ENABLED"}}
}

type hrig struct {
	h    *Health
	r    *rig
	tr   *trailRig
	st   TrailState
	rec  RecorderState
	rule []RuleState
	err  error
}

func newHealth(t *testing.T) *hrig {
	g := &hrig{r: newRig(t), tr: newTrail(t)}
	g.st, g.rec, g.rule = healthy()
	g.h = &Health{Cfg: HealthConfig{Account: acct, Trail: "organization", DataBuckets: []string{"tf-state"}, Rules: []string{"observe-aws-cloudtrail", "observe-aws-config"}},
		Ctl: Control{
			Trails:    func(context.Context) ([]TrailState, error) { return []TrailState{g.st}, g.err },
			Recorders: func(context.Context) ([]RecorderState, error) { return []RecorderState{g.rec}, nil },
			Rules:     func(context.Context, []string) ([]RuleState, error) { return g.rule, nil }},
		Trail: g.tr.rd, Col: g.r.c, Core: g.r.co, Now: g.r.clk.now}
	g.tr.rd.Now = g.r.clk.now
	g.h.Start()
	g.tr.hour(1, "e1")
	g.tr.rd.Since = t0
	g.r.clk.t = t0.Add(2*time.Hour + 20*time.Minute) // after hour 1's digest; before it is stale
	if _, _, err := g.tr.rd.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	g.h.Drained()
	return g
}

func (g *hrig) post(t *testing.T) (string, map[string]string) {
	t.Helper()
	st, err := g.h.Post(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	failed := map[string]string{}
	last := g.r.co.of("observation.health")
	for _, c := range last[len(last)-1].Record.Health["checks"].([]any) {
		m := c.(map[string]any)
		if m["ok"] == false {
			failed[m["name"].(string)] = m["detail"].(string)
		}
	}
	return st, failed
}

func TestHealthyAccount(t *testing.T) {
	g := newHealth(t)
	st, failed := g.post(t)
	if st != observe.Healthy || len(failed) != 0 {
		t.Fatal(st, failed)
	}
	checks := g.r.co.of("observation.health")[0].Record.Health["checks"].([]any)
	names := map[string]bool{}
	for _, c := range checks {
		names[c.(map[string]any)["name"].(string)] = true
	}
	for _, n := range []string{"trail-enabled", "regions-covered", "event-selectors", "digests-arriving", "digests-validating", "recorder-running", "rules-enabled", "collector-current", "scope-not-evaluated"} {
		if !names[n] {
			t.Errorf("health lacks check %s (%v)", n, names)
		}
	}
	if g.r.co.of("observation.health")[0].Record.Health["interval_seconds"] != 300 {
		t.Fatal("the interval is reported: the core holds a record for twice it")
	}
}

// The third Done-when's other half: StopLogging flips the account to blind and only a healthy record clears it.
func TestStopLoggingFlipsHealthAndOnlyAHealthyRecordClearsIt(t *testing.T) {
	g := newHealth(t)
	e := ct{id: "ev-stop", name: "StopLogging", source: "cloudtrail.amazonaws.com", at: t0, utype: "AssumedRole", issuer: ssoRole,
		arn: "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_0123456789abcdef/dana", srcIdentity: "dana@example.com",
		params: map[string]any{"name": "organization"}}
	g.r.ingest(e.envelope(), t0)
	g.r.settle()
	if g.r.c.Pipe.Health(acct) != observe.Blind {
		t.Fatalf("a successful StopLogging is blind: %s", g.r.c.Pipe.Health(acct))
	}
	g.st.Logging = false // the trail really is stopped
	st, failed := g.post(t)
	if st != observe.Blind || failed["trail-enabled"] == "" {
		t.Fatal(st, failed)
	}
	if g.r.c.Pipe.Health(acct) != observe.Blind {
		t.Fatal("a blind record does not clear the flip")
	}
	g.st.Logging = true // someone turns it back on
	st, _ = g.post(t)
	if st != observe.Healthy || g.r.c.Pipe.Health(acct) != observe.Healthy {
		t.Fatalf("%s %s", st, g.r.c.Pipe.Health(acct))
	}
}

func TestEachChecksFailureIsNamed(t *testing.T) {
	for name, c := range map[string]struct {
		edit  func(*hrig)
		check string
		state string
	}{
		"selectors drop writes":  {func(g *hrig) { g.st.ReadWrite = "ReadOnly" }, "event-selectors", observe.Degraded},
		"state bucket unwatched": {func(g *hrig) { g.st.DataBuckets = nil }, "event-selectors", observe.Degraded},
		"validation off":         {func(g *hrig) { g.st.LogValidation = false }, "event-selectors", observe.Degraded},
		"single region trail":    {func(g *hrig) { g.st.MultiRegion, g.st.Organization = false, false }, "regions-covered", observe.Degraded},
		"recorder stopped":       {func(g *hrig) { g.rec.Recording = false }, "recorder-running", observe.Degraded},
		"rule disabled":          {func(g *hrig) { g.rule[0].State = "DISABLED" }, "rules-enabled", observe.Degraded},
		"trail unreadable":       {func(g *hrig) { g.err = errors.New("AccessDenied") }, "trail-enabled", observe.Blind},
		"digests stale":          {func(g *hrig) { g.r.clk.add(5 * time.Hour) }, "digests-arriving", observe.Blind},
		"queue not drained": {func(g *hrig) {
			g.r.clk.add(time.Hour)
			g.h.Trail.Now = func() time.Time { return t0.Add(2 * time.Hour) }
		}, "collector-current", observe.Blind},
	} {
		t.Run(name, func(t *testing.T) {
			g := newHealth(t)
			c.edit(g)
			st, failed := g.post(t)
			if failed[c.check] == "" || st != c.state && !(c.check != "digests-arriving" && st == observe.Blind) {
				t.Fatalf("state %s failed %v, want %s failing as %s", st, failed, c.check, c.state)
			}
		})
	}
}

func TestADigestValidationFailureDegradesAndStaysFor24Hours(t *testing.T) {
	g := newHealth(t)
	d2, l2 := g.tr.hour(2, "e2")
	_ = d2
	g.tr.tr.Tamper(l2, func(b []byte) []byte { return []byte(strings.Replace(string(b), "e2", "forged", 1)) })
	g.r.clk.t = t0.Add(3*time.Hour + 20*time.Minute)
	g.h.Drained()
	if _, _, err := g.tr.rd.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, failed := g.post(t)
	if st != observe.Degraded || !strings.Contains(failed["digests-validating"], "log-file-hash-mismatch") {
		t.Fatal(st, failed)
	}
	g.r.clk.add(20 * time.Hour)
	g.h.Drained()
	if _, failed := g.post(t); failed["digests-validating"] == "" {
		t.Fatal("tamper evidence does not heal within a day")
	}
}

// The lab layout: management events from the organization trail (management account), the state bucket's data events
// from a separate trail the observed account owns (observe-data), read with the account's own role.
func labLayout(g *hrig) *TrailState {
	g.st.DataBuckets = nil // the organization trail records no data events
	data := &TrailState{Name: "observe-data", Logging: true, LogValidation: true, DataBuckets: []string{"tf-state"}}
	g.h.Ctl.DataTrails = func(context.Context) ([]TrailState, error) { return []TrailState{*data}, g.err }
	return data
}

func TestDataEventsFromTheAccountsOwnTrail(t *testing.T) {
	g := newHealth(t)
	data := labLayout(g)
	st, failed := g.post(t)
	if st != observe.Healthy || len(failed) != 0 {
		t.Fatal(st, failed)
	}
	for _, c := range g.r.co.of("observation.health")[0].Record.Health["checks"].([]any) {
		if m := c.(map[string]any); m["name"] == "event-selectors" && !strings.Contains(m["detail"].(string), "observe-data") {
			t.Fatalf("the detail names each trail: %v", m["detail"])
		}
	}
	// StopLogging on observe-data
	data.Logging = false
	st, failed = g.post(t)
	if st != observe.Degraded || !strings.Contains(failed["event-selectors"], "data trail observe-data is not logging") {
		t.Fatal(st, failed)
	}
	// logging again, validation off
	data.Logging, data.LogValidation = true, false
	if _, failed = g.post(t); !strings.Contains(failed["event-selectors"], "observe-data has log file validation off") {
		t.Fatal(failed)
	}
}

func TestNoTrailRecordsTheDataBucket(t *testing.T) {
	g := newHealth(t)
	data := labLayout(g)
	data.DataBuckets = []string{"another-bucket"}
	st, failed := g.post(t)
	if st != observe.Degraded || !strings.Contains(failed["event-selectors"], "no data events for bucket tf-state on any logging trail (organization, observe-data)") {
		t.Fatal(st, failed)
	}
}

func TestNamedDataTrail(t *testing.T) {
	g := newHealth(t)
	data := labLayout(g)
	g.h.Cfg.DataTrail = "observe-data"
	if st, failed := g.post(t); st != observe.Healthy {
		t.Fatal(st, failed)
	}
	// the named trail not logging fails even when the organization trail would cover the bucket
	g.st.DataBuckets = []string{"tf-state"}
	data.Logging = false
	if _, failed := g.post(t); !strings.Contains(failed["event-selectors"], "data trail observe-data is not logging") {
		t.Fatal(failed)
	}
	g.h.Cfg.DataTrail = "missing"
	if _, failed := g.post(t); !strings.Contains(failed["event-selectors"], "data trail missing does not exist") {
		t.Fatal(failed)
	}
}

func TestAccountTrailsUnreadable(t *testing.T) {
	g := newHealth(t)
	g.st.DataBuckets = nil
	g.h.Ctl.DataTrails = func(context.Context) ([]TrailState, error) { return nil, errors.New("AccessDenied: DescribeTrails") }
	_, failed := g.post(t)
	if !strings.Contains(failed["event-selectors"], "the account's trails could not be read: AccessDenied") {
		t.Fatal(failed)
	}
	// the organization trail covering the bucket needs no account trail
	g.st.DataBuckets = []string{"tf-state"}
	if st, failed := g.post(t); st != observe.Healthy {
		t.Fatal(st, failed)
	}
}
