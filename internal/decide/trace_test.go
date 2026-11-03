package decide

import (
	"context"
	"testing"
)

func TestTraceOfAnInvalidRequestIsEveryRuleErroring(t *testing.T) {
	e, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := e.Trace(context.Background(), &EvaluationRequest{})
	if len(out) != len(e.Rules()) || len(out) == 0 {
		t.Fatalf("%d verdicts for %d rules", len(out), len(e.Rules()))
	}
	for i, v := range out {
		if !v.Error || v.Matched != nil || v.ID != e.Rules()[i].ID {
			t.Errorf("%d: %+v", i, v)
		}
	}
}
