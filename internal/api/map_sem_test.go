package api

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stalledGate holds every GateActivity until release is closed, and counts how many are in flight at once.
type stalledGate struct {
	Store
	release  chan struct{}
	inflight atomic.Int32
	peak     atomic.Int32
}

func (s *stalledGate) GateActivity(ctx context.Context, v *Viewer, from, to string) ([]GateRow, bool, error) {
	n := s.inflight.Add(1)
	defer s.inflight.Add(-1)
	for {
		p := s.peak.Load()
		if n <= p || s.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case <-s.release:
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
	return s.Store.GateActivity(ctx, v, from, to)
}

// A Map holds one reader connection per statement (four), and the pool defaults to five: two Maps reading at once
// would leave no connection for anything else. The second waits for the first, and other endpoints answer meanwhile.
func TestConcurrentMapReadsAreBounded(t *testing.T) {
	var sg *stalledGate
	b := backend{"stalled", func(t *testing.T, w world) (Store, string) {
		st, dsn := backends[0].build(t, w)
		sg = &stalledGate{Store: st, release: make(chan struct{})}
		return sg, dsn
	}}
	h := newHarness(t, b, world{}, func(o *Options) { o.Clock = func() time.Time { return mapNow } })
	var wg sync.WaitGroup
	status := make([]int, 2)
	for i := range status {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status[i] = h.get("/v1/map", "audit").status
		}(i)
	}
	for i := 0; i < 100 && sg.inflight.Load() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // the second Map would have started its statements by now
	if n := sg.inflight.Load(); n != 1 {
		t.Errorf("%d Map reads are in flight, want 1 (the other waits for its turn)", n)
	}
	done := make(chan resp, 1)
	go func() { done <- h.get("/v1/evidence/counts?by=provider", "audit") }()
	select {
	case r := <-done:
		if r.status != 200 {
			t.Errorf("another endpoint answered %d while Maps were reading: %s", r.status, r.body)
		}
	case <-time.After(3 * time.Second):
		t.Error("another endpoint did not answer while two Maps were reading")
	}
	close(sg.release)
	wg.Wait()
	for i, s := range status {
		if s != 200 {
			t.Errorf("Map %d answered %d", i, s)
		}
	}
	if p := sg.peak.Load(); p != 1 {
		t.Errorf("peak %d Map reads at once, want %d", p, MaxConcurrentMapReads)
	}
}
