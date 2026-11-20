package observe

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func num(n int) json.Number { return json.Number(strconv.Itoa(n)) }

// padded adds the keys a stored record carries that Build never reads, so a Project that kept too little or too much
// shows in the statement or in the size.
func padded(r Record) Record {
	r["hash"], r["prev_hash"], r["assurance"], r["extra"] = "h", "p", "recorded", map[string]any{"deep": []any{"x", map[string]any{"y": "z"}}}
	for _, k := range []string{"source", "provider", "action", "resource", "integrity", "resolution", "gap"} {
		if m, ok := r[k].(map[string]any); ok {
			m["unread"] = "junk"
		}
	}
	return r
}

func TestProjectKeepsWhatBuildReads(t *testing.T) {
	obs := func(seq int, ts time.Time, extra map[string]any) Record {
		r := Record{"seq": num(seq), "ts": ts.Format(time.RFC3339), "tool": "observation", "tier": num(2), "completeness_supported": true,
			"source":   map[string]any{"name": "cloudtrail", "event_id": "e"},
			"provider": map[string]any{"name": "observe-aws"}, "action": map[string]any{"api": "RunInstances", "succeeded": true, "verb": "create"},
			"resource": map[string]any{"kind": "Instance", "id": "i-1", "name": "web"}, "integrity": map[string]any{"sourceVerified": seq%2 == 0}}
		for k, v := range extra {
			r[k] = v
		}
		return padded(r)
	}
	in := Input{Scope: "aws:1", Window: window(0, time.Hour), Truncated: true}
	in.Observations = []Record{obs(1, t0.Add(time.Minute), nil), obs(2, t0.Add(2*time.Minute), nil), obs(3, t0.Add(3*time.Minute), nil),
		obs(4, t0.Add(4*time.Minute), map[string]any{"verified": []any{"tier"}, "tier": num(3)})}
	in.Assessments = []Record{padded(Record{"seq": num(10), "ts": "x", "about": map[string]any{"seq": num(1)}, "coverage": "authorized-and-verified", "tier": num(1)}),
		padded(Record{"seq": num(11), "ts": "x", "about": map[string]any{"seq": num(2)}, "coverage": "observed-not-attributed", "tier": num(3)})}
	in.Resolutions = []Record{padded(Record{"seq": num(12), "ts": t0.Add(5 * time.Minute).Format(time.RFC3339), "about": map[string]any{"seq": num(2)},
		"provider": map[string]any{"name": "ops"}, "resolution": map[string]any{"state": "accepted", "cause": "known", "by": "alice"}})}
	in.Verifications = []Record{padded(Record{"seq": num(13), "ts": "x", "about": map[string]any{"seq": num(3)}})}
	hl := func(seq int, at time.Time, state string, bad bool) Record {
		return padded(Record{"seq": num(seq), "ts": at.Format(time.RFC3339), "source": map[string]any{"name": "cloudtrail"}, "provider": map[string]any{"name": "observe-aws"},
			"health": map[string]any{"state": state, "interval_seconds": num(300), "detail": "junk",
				"checks": []any{map[string]any{"name": "trail", "ok": !bad, "detail": "junk"}, map[string]any{"name": "cfg", "ok": true}}}})
	}
	in.Health = []Record{hl(20, t0, "healthy", false), hl(21, t0.Add(20*time.Minute), "degraded", true)}
	in.Gaps = []Record{padded(Record{"seq": num(30), "ts": t0.Add(7 * time.Minute).Format(time.RFC3339), "source": map[string]any{"name": "cloudtrail"},
		"gap": map[string]any{"state": "open", "reason": "lost", "detail": "junk"}})}

	now := t0.Add(2 * time.Hour)
	want := Build(in, now)
	if want.Seen.Count+want.Cleared.Count != 4 || len(want.Blind.Gaps) != 1 || want.Integrity.Verified == 0 || want.Health.Sources[0].Failed == nil {
		t.Fatalf("the fixture does not exercise the statement: %+v", want)
	}
	proj := func(rs []Record) []Record {
		out := make([]Record, len(rs))
		for i, r := range rs {
			out[i] = Project(r)
		}
		return out
	}
	got := Build(Input{Scope: in.Scope, Window: in.Window, Truncated: in.Truncated, Observations: proj(in.Observations), Assessments: proj(in.Assessments),
		Resolutions: proj(in.Resolutions), Verifications: proj(in.Verifications), Health: proj(in.Health), Gaps: proj(in.Gaps)}, now)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Build over projected records differs:\n got %+v\nwant %+v", got, want)
	}
	if p := Project(in.Observations[0]); p["hash"] != nil || p["extra"] != nil || p["source"].(map[string]any)["event_id"] != nil {
		t.Errorf("Project kept what Build does not read: %v", p)
	}
}
