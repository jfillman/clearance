package observe

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/vocab"
)

var t0 = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

func health(seq int64, at time.Time, state string, interval int, failed ...string) Record {
	checks := []any{map[string]any{"name": "trail-enabled", "ok": len(failed) == 0}}
	return Record{"seq": json.Number(strconv.FormatInt(seq, 10)), "ts": at.Format(time.RFC3339), "tool": "observation.health",
		"source": map[string]any{"name": "cloudtrail"},
		"health": map[string]any{"state": state, "checks": checks, "interval_seconds": json.Number(itoa(interval))}}
}

func itoa(n int) string { return strconv.Itoa(n) }

func window(from, to time.Duration) Window { return Window{t0.Add(from), t0.Add(to)} }

func TestATimelineHoldsAStateUntilTheFeedIsDueAndThenIsBlind(t *testing.T) {
	recs := hrecs([]Record{health(1, t0, Healthy, 300), health(2, t0.Add(30*time.Minute), Degraded, 300)})["cloudtrail"]
	segs := Timeline("cloudtrail", recs, window(0, time.Hour), t0.Add(time.Hour))
	want := []struct {
		state, reason string
		secs          int64
	}{{Healthy, "reported", 600}, {Blind, "stale", 1200}, {Degraded, "reported", 600}, {Blind, "stale", 1200}}
	if len(segs) != len(want) {
		t.Fatalf("%+v", segs)
	}
	for i, w := range want {
		if segs[i].State != w.state || segs[i].Reason != w.reason || segs[i].Seconds != w.secs {
			t.Errorf("segment %d: %+v, want %+v", i, segs[i], w)
		}
	}
	// before the first record the feed was unseen; no record at all is blind throughout
	if s := Timeline("x", recs, window(-10*time.Minute, 0), t0); len(s) != 1 || s[0].Reason != "never-seen" || s[0].Seconds != 600 {
		t.Fatalf("%+v", s)
	}
	if s := Timeline("x", nil, window(0, time.Hour), t0); len(s) != 1 || s[0].State != Blind {
		t.Fatalf("%+v", s)
	}
}

func TestAWindowIsHealthyOnlyIfEverySecondWasHealthy(t *testing.T) {
	now := t0.Add(10 * time.Minute)
	st := Build(Input{Scope: "s", Window: window(0, 10*time.Minute), Health: []Record{health(1, t0, Healthy, 600)}}, now)
	if st.State != Healthy || !st.Clean {
		t.Fatalf("%+v", st)
	}
	// a window longer than the feed has lived is partly unseen
	st = Build(Input{Scope: "s", Window: window(-time.Minute, 10*time.Minute), Health: []Record{health(1, t0, Healthy, 600)}}, now)
	if st.State != Blind || st.Clean {
		t.Fatalf("%+v", st)
	}
	// the future is not spoken for
	st = Build(Input{Scope: "s", Window: window(0, time.Hour), Health: []Record{health(1, t0, Healthy, 600)}}, now)
	if st.To != now.Format(time.RFC3339) || st.State != Healthy {
		t.Fatalf("%+v", st)
	}
	// an uncleared observation is never clean, even when healthy; a truncated read never is either
	obs := Record{"seq": json.Number("5"), "ts": t0.Format(time.RFC3339), "tool": "observation",
		"source": map[string]any{"name": "cloudtrail"}}
	st = Build(Input{Scope: "s", Window: window(0, 10*time.Minute), Observations: []Record{obs},
		Health: []Record{health(1, t0, Healthy, 600)}}, now)
	if st.Clean || st.Seen.Count != 1 || st.Seen.ByCoverage["unassessed"] != 1 {
		t.Fatalf("%+v", st)
	}
	st = Build(Input{Scope: "s", Window: window(0, 10*time.Minute), Truncated: true, Health: []Record{health(1, t0, Healthy, 600)}}, now)
	if st.Clean {
		t.Fatal("a statement built from a truncated read was clean")
	}
}

func TestSupportsNeedsAFreshHealthyRecord(t *testing.T) {
	h := health(1, t0, Healthy, 300)
	if !Supports(h, t0.Add(9*time.Minute)) || Supports(h, t0.Add(10*time.Minute)) {
		t.Fatal("fresh for twice the interval, then not")
	}
	if Supports(health(1, t0, Degraded, 300, "x"), t0) || Supports(nil, t0) {
		t.Fatal("a degraded or missing record supports nothing")
	}
}

func TestMonitoringProtectionComesFromConfiguration(t *testing.T) {
	v := vocab.Default()
	if v.MonitoringProtectionOps == nil || len(v.MonitoringProtectionOps) != 0 {
		t.Fatalf("the default names no platform operation: %v", v.MonitoringProtectionOps)
	}
	if monitoring(v, "cloudtrail", "StopLogging") {
		t.Fatal("product-neutral by default")
	}
	v.MonitoringProtectionOps = []string{"Stop*", "kube-audit:patch-policy"}
	if !monitoring(v, "cloudtrail", "StopLogging") || !monitoring(v, "kube-audit", "patch-policy") ||
		monitoring(v, "cloudtrail", "patch-policy") {
		t.Fatal("globs on the api, or source:api")
	}
}

func TestAVerificationNamesTheObservationItVerifiesAndSaysItVerified(t *testing.T) {
	mk := func(edit func(m map[string]any)) map[string]any {
		ev := map[string]any{"scope": "aws-1", "source": map[string]any{"name": "observe-aws", "event_id": "e1/verification"},
			"about": map[string]any{"seq": json.Number("7")}, "verification": map[string]any{"method": "cloudtrail-digest-chain", "verified": true}}
		if edit != nil {
			edit(ev)
		}
		return ev
	}
	res, err := Check("observation.verification", mk(nil), vocab.Vocabulary{})
	if err != nil || res.Source != "observe-aws" || res.EventID != "e1/verification" {
		t.Fatalf("%+v %v", res, err)
	}
	for name, edit := range map[string]func(m map[string]any){
		"not verified":  func(m map[string]any) { m["verification"].(map[string]any)["verified"] = false },
		"no event id":   func(m map[string]any) { delete(m["source"].(map[string]any), "event_id") },
		"no about":      func(m map[string]any) { delete(m, "about") },
		"no method":     func(m map[string]any) { delete(m["verification"].(map[string]any), "method") },
		"extra field":   func(m map[string]any) { m["verification"].(map[string]any)["by"] = "me" },
		"a coverage":    func(m map[string]any) { m["coverage"] = "authorized-and-verified" },
		"a stray field": func(m map[string]any) { m["resolution"] = map[string]any{"state": "ratified"} },
	} {
		if _, err := Check("observation.verification", mk(edit), vocab.Vocabulary{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the field is the observation kinds' alone
	if _, err := Check("tool.call", map[string]any{"verification": map[string]any{}}, vocab.Vocabulary{}); err == nil {
		t.Error("a tool.call carries a verification")
	}
}

func TestAnObservationIsCountedOnceHoweverManyRecordsVouchForIt(t *testing.T) {
	obs := func(seq int64, verified bool) Record {
		return Record{"seq": json.Number(itoa(int(seq))), "ts": t0.Format(time.RFC3339), "tool": "observation", "source": map[string]any{"name": "cloudtrail"},
			"integrity": map[string]any{"sourceVerified": verified}, "action": map[string]any{"api": "x", "succeeded": true}}
	}
	ver := func(seq, about int64) Record {
		return Record{"seq": json.Number(itoa(int(seq))), "tool": "observation.verification", "about": map[string]any{"seq": json.Number(itoa(int(about)))}}
	}
	st := Build(Input{Scope: "s", Window: window(-time.Hour, time.Hour), Observations: []Record{obs(1, false), obs(2, true), obs(3, false)},
		Verifications: []Record{ver(10, 1), ver(11, 1), ver(12, 2)}, Health: []Record{health(9, t0.Add(-30*time.Minute), Healthy, 3600)}}, t0.Add(10*time.Minute))
	if si := st.Integrity; si.Observations != 3 || si.Verified != 2 || si.Own != 1 || si.Later != 1 || si.Unverified != 1 {
		t.Fatalf("%+v", si)
	}
	if st.Seen.Count+st.Cleared.Count != 3 {
		t.Fatal("a verification record is not an observation")
	}
}
