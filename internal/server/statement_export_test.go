package server

import (
	"context"
	"errors"

	"github.com/jfillman/clearance/internal/store"
)

// ResetStatementIndexForTest drops the in-memory index of statements and the kept results, as a restart does: the next
// request rebuilds the index from the chain.
func (s *Server) ResetStatementIndexForTest() {
	s.stmts.mu.Lock()
	s.stmts.byID, s.stmts.byReq, s.stmts.next = nil, nil, 0
	s.stmts.mu.Unlock()
	s.stmtRes.mu.Lock()
	s.stmtRes.by, s.stmtRes.order = nil, nil
	s.stmtRes.mu.Unlock()
}

// StatementIndexSizeForTest is how many statements the in-memory index holds.
func (s *Server) StatementIndexSizeForTest() int {
	s.stmts.mu.Lock()
	defer s.stmts.mu.Unlock()
	return len(s.stmts.byID)
}

// BreakReadsForTest makes every read of the chain's records fail from now on.
func (s *Server) BreakReadsForTest() { s.opt.Store = &brokenReads{Store: s.opt.Store} }

type brokenReads struct{ store.Store }

func (b *brokenReads) Records(context.Context, int64, int) ([]store.Record, error) {
	return nil, errors.New("the store is down")
}
