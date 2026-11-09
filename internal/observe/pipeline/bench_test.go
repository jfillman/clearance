package pipeline

import (
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/vocab"
)

// benchEvents is the Kubernetes and AWS corpora: the whole per-event path, Normalize through Correlate, across
// every kind of event (cleared, out of band, filtered, out of scope, refused, monitoring).
func benchEvents(b testing.TB) (*Pipeline, []RawEvent) {
	rs := mustRules(b)
	evs := append(corpus(b, "kubernetes.jsonl"), corpus(b, "aws.jsonl")...)
	return New(rs, mustLookups(b, rs), vocab.Default()), evs
}

// Done when: the per-event path stays under 1 ms (go test -bench Process ./internal/observe/pipeline).
func BenchmarkProcess(b *testing.B) {
	p, evs := benchEvents(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%len(evs) == 0 {
			p.Flush() // the correlator closes what it holds, as a window ending would; its cost is in the figure
		}
		if _, _, _, err := p.Process(evs[i%len(evs)]); err != nil {
			b.Fatal(err)
		}
	}
}

// perEventBudget is the card's bound.
const perEventBudget = time.Millisecond

func TestPerEventPathUnderOneMillisecond(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark")
	}
	res := testing.Benchmark(BenchmarkProcess)
	if res.N == 0 {
		t.Fatal("the benchmark did not run")
	}
	per := time.Duration(res.NsPerOp())
	t.Logf("%d ns/op over %d events (%d allocs/op)", res.NsPerOp(), res.N, res.AllocsPerOp())
	if per >= perEventBudget {
		t.Fatalf("the per-event path takes %s, over %s", per, perEventBudget)
	}
}
