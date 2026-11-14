package sampling_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/sampling"
)

func pi(n int64) *int64 { return &n }

// lab builds a population of n cleared changes over tiers 0..3 and two months, a few not cleared and a few with no proof.
func lab(n int) ([]sampling.Change, func(int64) bool) {
	var cs []sampling.Change
	for i := 0; i < n; i++ {
		month := "2026-10-%02dT09:00:00Z"
		if i%3 == 0 {
			month = "2026-11-%02dT09:00:00Z"
		}
		cs = append(cs, sampling.Change{ID: fmt.Sprintf("ch-%016x", i), App: "a", Env: "prod", Tier: pi(int64(i % 4)), State: "applied",
			FirstTS: fmt.Sprintf(month, 1+i%27), Clear: pi(int64(100 + 2*i)), ClearVerified: true})
	}
	cs = append(cs, sampling.Change{ID: "ch-ffffffffffffff01", State: "denied", FirstTS: "2026-10-05T00:00:00Z"})
	cs = append(cs, sampling.Change{ID: "ch-ffffffffffffff02", State: "applied", FirstTS: "2026-10-05T00:00:00Z", Clear: pi(9000)})
	return cs, func(seq int64) bool { return seq != 9000 }
}

func TestPopulationSaysWhyAChangeIsNotInTheFrame(t *testing.T) {
	cs, have := lab(30)
	rows, err := sampling.Population(cs, have)
	if err != nil {
		t.Fatal(err)
	}
	all, cleared, eligible := sampling.Counts(rows)
	if all != 32 || cleared != 31 || eligible != 30 {
		t.Fatalf("%d %d %d", all, cleared, eligible)
	}
	why := map[string]string{}
	for _, r := range rows {
		why[r.Change] = r.Excluded
	}
	if why["ch-ffffffffffffff01"] != sampling.ExcludedNotCleared || why["ch-ffffffffffffff02"] != sampling.ExcludedNoProof {
		t.Fatalf("%v", why)
	}
	if !slices.IsSortedFunc(rows, func(a, b sampling.Row) int { return strings.Compare(a.Change, b.Change) }) {
		t.Fatal("rows are not in change-id order")
	}
}

func TestPopulationRefusesWhatItCannotKey(t *testing.T) {
	have := func(int64) bool { return true }
	for name, cs := range map[string][]sampling.Change{
		"repeated id":      {{ID: "a", Clear: pi(1), FirstTS: "2026-10-01T00:00:00Z"}, {ID: "a", Clear: pi(2), FirstTS: "2026-10-01T00:00:00Z"}},
		"empty id":         {{ID: "", Clear: pi(1), FirstTS: "2026-10-01T00:00:00Z"}},
		"shared clear seq": {{ID: "a", Clear: pi(1), FirstTS: "2026-10-01T00:00:00Z"}, {ID: "b", Clear: pi(1), FirstTS: "2026-10-01T00:00:00Z"}},
		"negative seq":     {{ID: "a", Clear: pi(-1), FirstTS: "2026-10-01T00:00:00Z"}},
	} {
		if _, err := sampling.Population(cs, have); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A change with no readable timestamp is excluded, not sampled with an empty stratum.
	rows, err := sampling.Population([]sampling.Change{{ID: "a", Clear: pi(1), FirstTS: "yesterday"}}, have)
	if err != nil || rows[0].Eligible || rows[0].Excluded != sampling.ExcludedTimestamp {
		t.Fatalf("%v %v", rows, err)
	}
}

func draw(t *testing.T, rows []sampling.Row, seed string, n int, strat string) ([]int64, []sampling.Stratum) {
	t.Helper()
	seqs, strata, err := sampling.Select(rows, sampling.EffectiveSeed(strings.Repeat("a", 64), seed), n, strat)
	if err != nil {
		t.Fatal(err)
	}
	return seqs, strata
}

func TestTheSameSeedDrawsTheSameSampleAndAnotherSeedDoesNot(t *testing.T) {
	cs, have := lab(60)
	rows, _ := sampling.Population(cs, have)
	for _, strat := range []string{sampling.StratifyNone, sampling.StratifyTierMonth} {
		a, _ := draw(t, rows, "audit-2026", 25, strat)
		b, _ := draw(t, rows, "audit-2026", 25, strat)
		c, _ := draw(t, rows, "audit-2027", 25, strat)
		if len(a) != 25 || !slices.Equal(a, b) || slices.Equal(a, c) {
			t.Fatalf("%s: %v %v %v", strat, a, b, c)
		}
		if !slices.IsSorted(a) {
			t.Fatalf("%s: the sample is not in clear-record order", strat)
		}
	}
	// The seed is bound to the packet: the same seed on another packet is another sample.
	a, _, _ := sampling.Select(rows, sampling.EffectiveSeed(strings.Repeat("a", 64), "x"), 25, sampling.StratifyNone)
	b, _, _ := sampling.Select(rows, sampling.EffectiveSeed(strings.Repeat("b", 64), "x"), 25, sampling.StratifyNone)
	if slices.Equal(a, b) {
		t.Fatal("a seed means the same on two packets")
	}
}

func TestOnlyEligibleChangesAreEverDrawn(t *testing.T) {
	cs, have := lab(30)
	rows, _ := sampling.Population(cs, have)
	for i := 0; i < 20; i++ {
		seqs, _ := draw(t, rows, fmt.Sprint("s", i), 30, sampling.StratifyNone)
		if len(seqs) != 30 || slices.Contains(seqs, 9000) {
			t.Fatalf("%v", seqs)
		}
	}
	if _, _, err := sampling.Select(rows, nil, 31, sampling.StratifyNone); err == nil {
		t.Fatal("a sample larger than the eligible population was drawn")
	}
	for _, n := range []int{0, -1} {
		if _, _, err := sampling.Select(rows, nil, n, sampling.StratifyNone); err == nil {
			t.Fatalf("n=%d", n)
		}
	}
	if _, _, err := sampling.Select(rows, nil, 5, "by-colour"); err == nil {
		t.Fatal("an unknown stratification was accepted")
	}
	// Rows a hostile sample could print: an eligible row with no clear record, and two sharing one.
	bad := []sampling.Row{{Change: "a", Eligible: true}}
	if _, _, err := sampling.Select(bad, nil, 1, sampling.StratifyNone); err == nil {
		t.Fatal("an eligible row with no clear record was drawn")
	}
	bad = []sampling.Row{{Change: "a", Eligible: true, ClearSeq: pi(1)}, {Change: "b", Eligible: true, ClearSeq: pi(1)}}
	if _, _, err := sampling.Select(bad, nil, 1, sampling.StratifyNone); err == nil {
		t.Fatal("two rows sharing a clear record were drawn")
	}
}

func TestStratifiedAllocationIsProportionalAndExact(t *testing.T) {
	cs, have := lab(97)
	rows, _ := sampling.Population(cs, have)
	for _, n := range []int{1, 7, 25, 50, 97} {
		seqs, strata := draw(t, rows, "x", n, sampling.StratifyTierMonth)
		total, pop := 0, 0
		for _, s := range strata {
			total += s.Sample
			pop += s.Population
			if s.Sample > s.Population || s.Sample < 0 {
				t.Fatalf("n=%d: %+v", n, s)
			}
			// proportional: within one of n*size/eligible
			if want := float64(n) * float64(s.Population) / 97; float64(s.Sample) < want-1 || float64(s.Sample) > want+1 {
				t.Fatalf("n=%d: stratum %+v is not proportional (%.2f)", n, s, want)
			}
		}
		if total != n || len(seqs) != n || pop != 97 {
			t.Fatalf("n=%d: total %d, drawn %d, population %d", n, total, len(seqs), pop)
		}
	}
}

func TestUniformSamplesNest(t *testing.T) {
	cs, have := lab(60)
	rows, _ := sampling.Population(cs, have)
	small, _ := draw(t, rows, "x", 10, sampling.StratifyNone)
	big, _ := draw(t, rows, "x", 25, sampling.StratifyNone)
	for _, s := range small {
		if !slices.Contains(big, s) {
			t.Fatalf("%d is in the sample of 10 and not the sample of 25", s)
		}
	}
}

func TestSeedsAreRestricted(t *testing.T) {
	for _, ok := range []string{"a", "FY26.audit_1-x", strings.Repeat("a", 64)} {
		if !sampling.ValidSeed(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", 65), "a b", "a\x00b", "a\nb", "é", "a/b", "a=b", "../x", "<script>"} {
		if sampling.ValidSeed(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
