package golden

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/decide"
)

// realistic is the traffic-like part of the corpus: what the Python test suite and the fixture agents' calls
// decide. The edge probes (2 MiB artifacts, YAML corner cases) are benchmarked on their own.
func realistic(l line) bool {
	return strings.HasPrefix(l.Source, "tests/") || strings.Contains(l.Source, "test_fixture_agent_calls")
}

// BenchmarkDecide decides the realistic mix (tool calls, spawns, opens and model calls, with the Hangar pack),
// already decoded, and builds each record, reporting p50 and p99 of single calls. The decide path's budget is
// 2 ms p99 in-process (spec section 12).
func BenchmarkDecide(b *testing.B) { benchDecide(b, realistic) }

// BenchmarkDecideProbes is the same over the edge probes only, the worst case: 2 MiB arguments, deep YAML.
func BenchmarkDecideProbes(b *testing.B) { benchDecide(b, func(l line) bool { return !realistic(l) }) }

func benchDecide(b *testing.B, keep func(line) bool) {
	es := engines(b)
	var reqs []*decide.EvaluationRequest
	var eng []*decide.Engine
	for _, l := range loadCorpus(b)[1:] {
		if l.Kind == "activation" || !keep(l) {
			continue
		}
		r, err := decide.DecodeEvaluation(bytes.NewReader(l.Request))
		if err != nil {
			b.Fatal(err)
		}
		reqs = append(reqs, r)
		eng = append(eng, engineFor(es, l))
	}
	ctx := context.Background()
	lat := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := i % len(reqs)
		t0 := time.Now()
		resp := eng[j].Decide(ctx, reqs[j])
		_ = eng[j].RecordFields(reqs[j], resp)
		lat = append(lat, time.Since(t0))
	}
	b.StopTimer()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	q := func(p float64) float64 { return float64(lat[int(p*float64(len(lat)-1))].Microseconds()) }
	b.ReportMetric(q(0.50), "p50-us")
	b.ReportMetric(q(0.99), "p99-us")
	b.ReportMetric(q(1.0), "max-us")
}

// BenchmarkDecodeAndDecide includes strict decoding of the request body, as the HTTP route will.
func BenchmarkDecodeAndDecide(b *testing.B) {
	es := engines(b)
	lines := loadCorpus(b)[1:]
	var bodies [][]byte
	var eng []*decide.Engine
	for _, l := range lines {
		if l.Kind != "activation" {
			bodies = append(bodies, l.Request)
			eng = append(eng, engineFor(es, l))
		}
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := i % len(bodies)
		r, err := decide.DecodeEvaluation(bytes.NewReader(bodies[j]))
		if err != nil {
			b.Fatal(err)
		}
		eng[j].Decide(ctx, r)
	}
}
