package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/store"
)

// ResetSampleIndexForTest drops the in-memory index of samplings, as a restart does: the next sampling rebuilds it from the chain.
func (s *Server) ResetSampleIndexForTest() {
	s.sampleMu.Lock()
	s.sampled = nil
	s.sampleMu.Unlock()
}

// SetSampleMaxForTest lowers the cap on an encoded sample (0 restores the default).
func (s *Server) SetSampleMaxForTest(n int) { s.sampleMax = n }

// FailAtomicForTest makes the next store write fail once: before the commit ("before"), or after it ("after": the write is
// made and the caller is told it failed, as a connection lost at commit looks).
func (s *Server) FailAtomicForTest(mode string) {
	s.opt.Store = &failingStore{Store: s.opt.Store, mode: mode}
}

type failingStore struct {
	store.Store
	mu   sync.Mutex
	mode string
}

func (f *failingStore) Atomic(ctx context.Context, fn func(store.Tx) error) error {
	f.mu.Lock()
	mode := f.mode
	f.mode = ""
	f.mu.Unlock()
	switch mode {
	case "before":
		return errors.New("injected: the write failed before commit")
	case "after":
		if err := f.Store.Atomic(ctx, fn); err != nil {
			return err
		}
		return errors.New("injected: the connection was lost at commit")
	}
	return f.Store.Atomic(ctx, fn)
}

func TestSamplerCacheEvictsOneAtATime(t *testing.T) {
	var c samplers
	for i := 0; i < samplerCacheSize; i++ {
		c.put(string(rune('a'+i)), &sampleFrame{digest: "d"})
	}
	c.put("z", &sampleFrame{digest: "d"})
	have := 0
	for _, id := range []string{"a", "b", "c", "d", "z"} {
		if c.get(id, "d") != nil {
			have++
		}
	}
	if have != samplerCacheSize || c.get("a", "d") != nil || c.get("z", "d") == nil || c.get("b", "d") == nil {
		t.Fatalf("a full cache lost more than its oldest entry (%d held)", have)
	}
}

func TestAPacketThatFailsBuildFrameIsRefusedWithoutBeingReadAgainForAWhile(t *testing.T) {
	var c samplers
	now := time.Now()
	err := errors.New("bad")
	if _, ok := c.known("p", now); ok {
		t.Fatal("known before it failed")
	}
	c.failed("p", err, now)
	if got, ok := c.known("p", now.Add(badFrameTTL-time.Second)); !ok || got != err {
		t.Fatal("not remembered")
	}
	if _, ok := c.known("p", now.Add(badFrameTTL+time.Second)); ok {
		t.Fatal("remembered past its time")
	}
}
