package api

// The unscoped coverage answer and a scope's statement read bounded health: Store.Scopes and Store.HealthBefore, never
// the whole history. The statement built from the bounded input must equal the one built from every health record.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/observe"
)

var t0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

type rawChain struct {
	rows []map[string]any
}

func (c *rawChain) add(ts time.Time, tool, scope string, body map[string]any) {
	n := len(c.rows)
	r := map[string]any{"seq": json.Number(fmt.Sprint(n)), "hash": fmt.Sprintf("h%06d", n), "prev_hash": fmt.Sprintf("h%06d", n-1),
		"ts": evidence.ISO(ts), "tool": tool, "scope": scope}
	for k, v := range body {
		r[k] = v
	}
	c.rows = append(c.rows, r)
}

func (c *rawChain) health(ts time.Time, scope, source, provider, state string, failed bool) {
	checks := []any{map[string]any{"name": "c1", "ok": !failed}}
	c.add(ts, "observation.health", scope, map[string]any{"source": map[string]any{"name": source},
		"provider": map[string]any{"name": provider},
		"health":   map[string]any{"state": state, "checks": checks, "interval_seconds": json.Number("300")}})
}

func (c *rawChain) observation(ts time.Time, scope, id string) {
	c.add(ts, "observation", scope, map[string]any{"source": map[string]any{"name": "cloudtrail", "event_id": id},
		"provider": map[string]any{"name": "fake-trail"}, "action": map[string]any{"verb": "create", "api": "RunInstances", "succeeded": true},
		"integrity": map[string]any{"sourceVerified": true}})
}

// history is two days of 5-minute health records from two sources of aws:111, with degraded stretches, silences and
// core flips (an operation on monitoring) held across collector records; plus other scopes.
func history() *rawChain {
	c := &rawChain{}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 576; i++ {
		ts := t0.Add(time.Duration(i) * 5 * time.Minute)
		for _, src := range []string{"cloudtrail", "config"} {
			if rng.Intn(25) == 0 && !(src == "config" && i >= 300 && i <= 310) {
				continue // a silence
			}
			if src == "config" && i == 300 { // a flip the collector's degraded records do not end, until it says healthy
				c.health(ts, "aws:111", src, evidence.CoreProviderName, "blind", false)
			}
			if src == "config" && i >= 300 && i <= 310 {
				c.health(ts.Add(time.Second), "aws:111", src, "fake-trail", "degraded", true)
				continue
			}
			if src == "config" && rng.Intn(40) == 0 {
				c.health(ts, "aws:111", src, evidence.CoreProviderName, []string{"blind", "degraded"}[rng.Intn(2)], rng.Intn(2) == 0)
			}
			state, failed := "healthy", false
			if rng.Intn(6) == 0 {
				state, failed = "degraded", true
			}
			c.health(ts.Add(time.Second), "aws:111", src, "fake-trail", state, failed)
		}
		if i%40 == 0 {
			c.observation(ts.Add(2*time.Second), "aws:111", fmt.Sprint("e", i))
		}
	}
	// scope B: health only, long before the window; scope C: one observation before the window; scope D: after it.
	c.health(t0.Add(time.Hour), "aws:222", "cloudtrail", "fake-trail", "healthy", false)
	c.observation(t0.Add(time.Hour), "aws:333", "x1")
	c.health(t0.Add(100*time.Hour), "aws:444", "cloudtrail", "fake-trail", "healthy", false)
	c.observation(t0.Add(49*time.Hour), "aws:555", "x2")
	c.add(t0.Add(49*time.Hour), "assessment", "aws:666", map[string]any{})
	return c
}

func TestScopesAreTheDistinctNamesOfTheIndexedKindsInTheWindow(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			st, _ := b.build(t, world{raw: history().rows})
			from, to := evidence.ISO(t0.Add(48*time.Hour)), evidence.ISO(t0.Add(72*time.Hour))
			aud := &Viewer{Role: RoleAuditor}
			got, err := st.Scopes(bg, aud, from, to, 10)
			if err != nil {
				t.Fatal(err)
			}
			// 111 and 222 have health before the window's end; 555 an observation in it; 333 is before the window and
			// has no health; 444's health is after it; 666 has only an assessment.
			if want := []string{"aws:111", "aws:222", "aws:555"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("scopes %v, want %v", got, want)
			}
			if got, _ = st.Scopes(bg, aud, from, to, 2); !reflect.DeepEqual(got, []string{"aws:111", "aws:222"}) {
				t.Fatalf("limit 2: %v", got)
			}
			// the records name no principal: a person who is not an auditor sees none of them
			if got, _ = st.Scopes(bg, &Viewer{Person: "user:nobody"}, from, to, 10); len(got) != 0 {
				t.Fatalf("a person saw %v", got)
			}
		})
	}
}

func TestHealthBeforeIsPerSourceFromTheLastHealthyCollectorRecord(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			c := &rawChain{}
			c.health(t0, "s", "a", "fake", "degraded", true)
			c.health(t0.Add(1*time.Minute), "s", "a", "fake", "healthy", false) // anchor of a
			c.health(t0.Add(2*time.Minute), "s", "a", evidence.CoreProviderName, "blind", false)
			c.health(t0.Add(3*time.Minute), "s", "a", "fake", "degraded", true)
			c.health(t0.Add(1*time.Minute), "s", "b", "fake", "degraded", true) // b has no healthy collector record
			c.health(t0.Add(2*time.Minute), "s", "b", evidence.CoreProviderName, "blind", false)
			c.health(t0.Add(3*time.Minute), "other", "a", "fake", "healthy", false)
			c.health(t0.Add(10*time.Minute), "s", "a", "fake", "healthy", false) // not before
			st, _ := b.build(t, world{raw: c.rows})
			rs, err := st.HealthBefore(bg, &Viewer{Role: RoleAuditor}, "s", evidence.ISO(t0.Add(5*time.Minute)))
			if err != nil {
				t.Fatal(err)
			}
			var seqs []int
			for _, r := range rs {
				n, _ := seqOf(r)
				seqs = append(seqs, int(n))
			}
			sort.Ints(seqs)
			if want := []int{1, 2, 3, 4, 5}; !reflect.DeepEqual(seqs, want) {
				t.Fatalf("seqs %v, want %v", seqs, want)
			}
			if rs, _ = st.HealthBefore(bg, &Viewer{Person: "user:nobody"}, "s", evidence.ISO(t0.Add(5*time.Minute))); len(rs) != 0 {
				t.Fatal("a person saw the records")
			}
		})
	}
}

// oldInput reads the health as statement did before: every health record of the scope up to the window's end.
func (s *Server) oldHealth(t *testing.T, scope string, to time.Time) []Record {
	t.Helper()
	rs, cut, err := s.collect(bg, EvidenceFilter{Scope: scope, Tools: []string{evidence.KindHealth}, Until: evidence.ISO(to), Outcomes: OutcomesInclude},
		&Viewer{Role: RoleAuditor}, MaxCoverageRecords)
	if err != nil || cut {
		t.Fatal(err, cut)
	}
	return rs
}

func TestTheBoundedStatementEqualsTheOneBuiltFromEveryHealthRecord(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			h := newHarness(t, b, world{raw: history().rows})
			s := h.srv
			aud := &Viewer{Role: RoleAuditor}
			checked := 0
			for i := 1; i < 570; i += 7 {
				for _, span := range []time.Duration{20 * time.Minute, 3 * time.Hour, 20 * time.Hour} {
					from := t0.Add(time.Duration(i)*5*time.Minute + 90*time.Second)
					to, now := from.Add(span), from.Add(span+time.Minute)
					got, err := s.statement(bg, aud, "aws:111", from, to, now)
					if err != nil {
						t.Fatal(err)
					}
					// the old input: everything the new statement reads, but the health from the beginning of time
					f, tt := evidence.ISO(from), evidence.ISO(to)
					in := observe.Input{Scope: "aws:111", Window: observe.Window{From: from, To: to}, Health: s.oldHealth(t, "aws:111", to)}
					in.Observations, _, _ = s.collect(bg, EvidenceFilter{Scope: "aws:111", Tools: []string{evidence.KindObservation}, Since: f, Until: tt, Outcomes: OutcomesInclude}, aud, MaxCoverageRecords)
					in.Gaps, _, _ = s.collect(bg, EvidenceFilter{Scope: "aws:111", Tools: []string{evidence.KindAuditGap}, Since: f, Until: tt, Outcomes: OutcomesInclude}, aud, MaxCoverageRecords)
					want := observe.Build(in, now)
					gj, _ := json.Marshal(got)
					wj, _ := json.Marshal(want)
					if string(gj) != string(wj) {
						t.Fatalf("from %s span %s:\nbounded %s\nfull    %s", f, span, gj, wj)
					}
					if len(got.Health.Sources) != 2 {
						t.Fatalf("sources %v", got.Health.Sources)
					}
					checked++
				}
			}
			if checked < 150 {
				t.Fatal("checked", checked)
			}
			// and the bounded read is small next to the history: the window's records plus a few before it
			before, err := s.opt.Store.HealthBefore(bg, aud, "aws:111", evidence.ISO(t0.Add(40*time.Hour)))
			if err != nil || len(before) == 0 || len(before) > 40 {
				t.Fatalf("HealthBefore read %d records (err %v)", len(before), err)
			}
		})
	}
}

func TestUnscopedCoverageListsTheScopesWithoutReadingTheirHistory(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			now := t0.Add(72 * time.Hour)
			h := newHarness(t, b, world{raw: history().rows}, func(o *Options) { o.Clock = func() time.Time { return now } })
			out := h.ok("/v1/coverage?from="+evidence.ISO(t0.Add(48*time.Hour)), "audit")
			var names []string
			for _, sc := range out["scopes"].([]any) {
				names = append(names, sc.(map[string]any)["scope"].(string))
			}
			if want := []string{"aws:111", "aws:222", "aws:555"}; !reflect.DeepEqual(names, want) || out["truncated"] != false {
				t.Fatalf("%v %v", names, out["truncated"])
			}
		})
	}
}
