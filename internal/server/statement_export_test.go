package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jfillman/clearance/internal/store"
)

// ResetStatementIndexForTest drops the in-memory index of statements and the kept results, as a restart does, and reads the
// index again from the chain, as the start does.
func (s *Server) ResetStatementIndexForTest() {
	s.stmts.mu.Lock()
	s.stmts.byID, s.stmts.byReq, s.stmts.warmed = nil, nil, false
	s.stmts.mu.Unlock()
	s.stmts.refreshMu.Lock()
	s.stmts.next = 0
	s.stmts.refreshMu.Unlock()
	s.stmtRes.mu.Lock()
	s.stmtRes.by, s.stmtRes.order = nil, nil
	s.stmtRes.mu.Unlock()
	_ = s.WarmStatements(context.Background())
}

// ColdStatementIndexForTest drops the index and does NOT read it again: the state of a core whose start could not read the chain.
func (s *Server) ColdStatementIndexForTest() {
	s.stmts.mu.Lock()
	s.stmts.byID, s.stmts.byReq, s.stmts.warmed = nil, nil, false
	s.stmts.mu.Unlock()
	s.stmts.refreshMu.Lock()
	s.stmts.next = 0
	s.stmts.refreshMu.Unlock()
}

// StatementIndexSizeForTest is how many statements the in-memory index holds.
func (s *Server) StatementIndexSizeForTest() int {
	s.stmts.mu.RLock()
	defer s.stmts.mu.RUnlock()
	return len(s.stmts.byID)
}

// AgeStatementIndexForTest makes the index look as if it was last read d ago.
func (s *Server) AgeStatementIndexForTest(d time.Duration) {
	s.stmts.mu.Lock()
	s.stmts.synced = s.opt.Clock().Add(-d)
	s.stmts.mu.Unlock()
}

// faultStore fails or hangs the chain's record reads while its mode says so. It is installed once and then only its mode changes,
// atomically, so a background retry that is reading the store never races the test that heals it.
type faultStore struct {
	store.Store
	mode atomic.Int32 // 0 healthy, 1 broken, 2 hung
}

func (s *Server) fault() *faultStore {
	if f, ok := s.opt.Store.(*faultStore); ok {
		return f
	}
	f := &faultStore{Store: s.opt.Store}
	s.opt.Store = f
	return f
}

func (f *faultStore) Records(ctx context.Context, from int64, limit int) ([]store.Record, error) {
	switch f.mode.Load() {
	case 1:
		return nil, errors.New("the store is down")
	case 2:
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.Store.Records(ctx, from, limit)
}

// BreakReadsForTest makes every read of the chain's records fail from now on, and the index look old.
func (s *Server) BreakReadsForTest() {
	s.fault().mode.Store(1)
	s.AgeStatementIndexForTest(time.Hour)
}

// HangReadsForTest makes every read of the chain's records wait for its context, and the index look old: a hung store.
func (s *Server) HangReadsForTest() {
	s.fault().mode.Store(2)
	s.AgeStatementIndexForTest(time.Hour)
}

// HealReadsForTest undoes BreakReadsForTest and HangReadsForTest.
func (s *Server) HealReadsForTest() { s.fault().mode.Store(0) }

// SlowAtomicForTest makes every store write take d first.
func (s *Server) SlowAtomicForTest(d time.Duration) {
	s.opt.Store = &slowWrites{Store: s.opt.Store, d: d}
}

type slowWrites struct {
	store.Store
	d  time.Duration
	mu sync.Mutex
}

func (w *slowWrites) Atomic(ctx context.Context, fn func(store.Tx) error) error {
	time.Sleep(w.d)
	return w.Store.Atomic(ctx, fn)
}

// CountReadsForTest counts the reads of the chain's records from now on.
func (s *Server) CountReadsForTest() func() int {
	c := &countingReads{Store: s.opt.Store}
	s.opt.Store = c
	return func() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }
}

type countingReads struct {
	store.Store
	mu sync.Mutex
	n  int
}

func (c *countingReads) Records(ctx context.Context, from int64, limit int) ([]store.Record, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.Store.Records(ctx, from, limit)
}
