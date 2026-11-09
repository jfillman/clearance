package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeQueue struct {
	batches [][]Message
	deleted []string
	recv    int
}

func (q *fakeQueue) Receive(context.Context) ([]Message, error) {
	q.recv++
	if len(q.batches) == 0 {
		return nil, nil
	}
	b := q.batches[0]
	q.batches = q.batches[1:]
	return b, nil
}

func (q *fakeQueue) Delete(_ context.Context, h string) error {
	q.deleted = append(q.deleted, h)
	return nil
}

func TestDrainDeletesOnlyAfterPostAndLeavesPoison(t *testing.T) {
	r := newRig(t)
	q := &fakeQueue{batches: [][]Message{{
		{ID: "m1", Handle: "h1", Body: string(consoleSG("ev-1", t0).envelope())},
		{ID: "m2", Handle: "h2", Body: `{"detail-type":"Something Else","detail":{}}`},
		{ID: "m3", Handle: "h3", Body: string(sgConfig(t0.Add(time.Minute), "ev-1").envelope())},
	}}}
	d := &Drainer{Q: q, Col: r.c}
	n, err := d.Drain(context.Background())
	if n != 2 || err == nil || !strings.Contains(err.Error(), "m2") {
		t.Fatalf("two taken in, the poison named: %d %v", n, err)
	}
	if len(q.deleted) != 0 {
		t.Fatal("nothing is deleted before it is posted")
	}
	r.settle()
	if strings.Join(q.deleted, ",") != "h1,h3" && strings.Join(q.deleted, ",") != "h3,h1" {
		t.Fatalf("both deliveries of the one change are deleted, the poison message is not: %v", q.deleted)
	}
	if len(r.co.of("observation")) != 1 {
		t.Fatal("one change")
	}
}

func TestDrainMarksTheCollectorCurrent(t *testing.T) {
	g := newHealth(t)
	g.h.Cfg.DrainMaxAge = time.Minute
	g.r.clk.add(10 * time.Minute)
	if _, failed := g.post(t); failed["collector-current"] == "" {
		t.Fatal("not drained for ten minutes")
	}
	d := &Drainer{Q: &fakeQueue{}, Col: g.r.c, Health: g.h}
	if _, err := d.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, failed := g.post(t); failed["collector-current"] != "" {
		t.Fatal("a successful drain makes the collector current")
	}
}

func TestRunnerRunsDueTasksAndOneFailureDoesNotStopTheRest(t *testing.T) {
	clk := &clock{t0}
	var a, b int
	r := &Runner{Now: clk.now, Tasks: []*Task{
		{Name: "a", Every: time.Minute, Fn: func(context.Context) error { a++; return errors.New("boom") }},
		{Name: "b", Every: time.Hour, Fn: func(context.Context) error { b++; return nil }}}}
	if errs := r.Tick(context.Background()); len(errs) != 1 || a != 1 || b != 1 {
		t.Fatal(errs, a, b)
	}
	clk.add(30 * time.Second)
	r.Tick(context.Background())
	clk.add(40 * time.Second)
	r.Tick(context.Background())
	if a != 2 || b != 1 {
		t.Fatalf("a every minute, b every hour: %d %d", a, b)
	}
}
