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
	_ = s.refreshForWrite(context.Background())
}

// RefreshStatementsForTest is one synchronous read of the chain's tail into the index.
func (s *Server) RefreshStatementsForTest(ctx context.Context) error { return s.refreshForWrite(ctx) }

// StatementIndexNextForTest is the next seq the index will read.
func (s *Server) StatementIndexNextForTest() int64 {
	s.stmts.refreshMu.Lock()
	defer s.stmts.refreshMu.Unlock()
	return s.stmts.next
}

// StatementLoopRunningForTest says whether the background goroutine is running.
func (s *Server) StatementLoopRunningForTest() bool {
	s.stmts.mu.RLock()
	defer s.stmts.mu.RUnlock()
	return s.stmts.loop
}

// SetStatementPageSizeForTest changes how many records one read of the chain takes (0: the default).
func SetStatementPageSizeForTest(n int) {
	if n == 0 {
		n = 2000
	}
	statementPageSize = n
}

// StatementResultCachedForTest says whether the page holds a check result for the statement.
func (s *Server) StatementResultCachedForTest(id string) bool {
	s.stmtRes.mu.Lock()
	defer s.stmtRes.mu.Unlock()
	_, ok := s.stmtRes.by[id]
	return ok
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
	mode   atomic.Int32 // 0 healthy, 1 broken, 2 hung, 3 slow
	delay  atomic.Int64 // mode 3: each read takes this many nanoseconds
	budget atomic.Int32 // reads of the records that may succeed before they fail (negative: no limit)
}

func (f *faultStore) Head(ctx context.Context) (int64, string, error) {
	if err := f.wait(ctx); err != nil {
		return 0, "", err
	}
	return f.Store.Head(ctx)
}

func (f *faultStore) wait(ctx context.Context) error {
	switch f.mode.Load() {
	case 1:
		return errors.New("the store is down")
	case 2:
		for f.mode.Load() == 2 { // hung until healed or the caller gives up
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
	case 3:
		select {
		case <-time.After(time.Duration(f.delay.Load())):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (s *Server) fault() *faultStore {
	if f, ok := s.opt.Store.(*faultStore); ok {
		return f
	}
	var f *faultStore
	s.pauseStatementLoop(func() {
		f = &faultStore{Store: s.opt.Store}
		f.budget.Store(-1)
		s.opt.Store = f
	})
	return f
}

// pauseStatementLoop runs swap with the background goroutine stopped (it reads the store without a lock, as production code does)
// and starts it again if it was running.
func (s *Server) pauseStatementLoop(swap func()) {
	s.stmts.mu.RLock()
	was := s.stmts.loop
	s.stmts.mu.RUnlock()
	if was {
		s.PauseStatementLoopForTest()
		for i := 0; i < 500; i++ {
			s.stmts.mu.RLock()
			running := s.stmts.loop
			s.stmts.mu.RUnlock()
			if !running {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	swap()
	if was {
		s.StartStatements()
	}
}

// PauseStatementLoopForTest ends the running goroutine WITHOUT ending the core's statement life: StartStatements starts it again.
func (s *Server) PauseStatementLoopForTest() {
	s.stmts.mu.RLock()
	stop := s.stmts.stop
	s.stmts.mu.RUnlock()
	if stop != nil {
		stop()
	}
	for i := 0; i < 500; i++ {
		s.stmts.mu.RLock()
		running := s.stmts.loop
		s.stmts.mu.RUnlock()
		if !running {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// RestartStatementsForTest is what a restart of the core does for statements: the loop and the index are gone, and the startup pass over
// the chain decides whether anything runs.
func (s *Server) RestartStatementsForTest() error {
	s.PauseStatementLoopForTest()
	s.ColdStatementIndexForTest()
	s.stmtRes.mu.Lock()
	s.stmtRes.by, s.stmtRes.order = nil, nil
	s.stmtRes.mu.Unlock()
	return s.startupPass(context.Background())
}

// StatementsSeenForTest says whether the core knows the chain holds a statement.
func (s *Server) StatementsSeenForTest() bool { return s.stmtSeen.Load() }

// CountStoreCallsForTest counts the reads of the chain's head and records and of the signing keys from now on.
func (s *Server) CountStoreCallsForTest() func() int {
	c := &callCounter{}
	s.pauseStatementLoop(func() { c.Store = s.opt.Store; s.opt.Store = c })
	return func() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }
}

type callCounter struct {
	store.Store
	mu sync.Mutex
	n  int
}

func (c *callCounter) bump() { c.mu.Lock(); c.n++; c.mu.Unlock() }

func (c *callCounter) Head(ctx context.Context) (int64, string, error) {
	c.bump()
	return c.Store.Head(ctx)
}

func (c *callCounter) Records(ctx context.Context, from int64, limit int) ([]store.Record, error) {
	c.bump()
	return c.Store.Records(ctx, from, limit)
}

func (c *callCounter) SigningKeys(ctx context.Context, since time.Time) ([]store.SigningKey, error) {
	c.bump()
	return c.Store.SigningKeys(ctx, since)
}

func (f *faultStore) Records(ctx context.Context, from int64, limit int) ([]store.Record, error) {
	if err := f.wait(ctx); err != nil {
		return nil, err
	}
	if b := f.budget.Load(); b >= 0 {
		if b == 0 {
			return nil, errors.New("the store stopped answering")
		}
		f.budget.Add(-1)
	}
	return f.Store.Records(ctx, from, limit)
}

// SlowReadsForTest makes every read of the chain take d.
func (s *Server) SlowReadsForTest(d time.Duration) {
	f := s.fault()
	f.delay.Store(int64(d))
	f.mode.Store(3)
}

// FailRecordsAfterForTest lets n more reads of the chain's records succeed, then fails them (until HealReadsForTest).
func (s *Server) FailRecordsAfterForTest(n int) { s.fault().budget.Store(int32(n)) }

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
func (s *Server) HealReadsForTest() {
	f := s.fault()
	f.mode.Store(0)
	f.budget.Store(-1)
}

// SlowAtomicForTest makes every store write take d first.
func (s *Server) SlowAtomicForTest(d time.Duration) {
	s.pauseStatementLoop(func() { s.opt.Store = &slowWrites{Store: s.opt.Store, d: d} })
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
	c := &countingReads{}
	s.pauseStatementLoop(func() { c.Store = s.opt.Store; s.opt.Store = c })
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
