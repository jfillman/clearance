package client

import (
	"sync"
	"time"
)

// BreakerState is the breaker's state.
type BreakerState string

// Breaker states.
const (
	BreakerClosed   BreakerState = "closed"    // calls go through
	BreakerOpen     BreakerState = "open"      // calls fail fast with ErrCoreUnavailable until the cooldown ends
	BreakerHalfOpen BreakerState = "half-open" // the cooldown ended: one probe call goes through, the rest fail fast
)

// breaker opens after threshold consecutive unavailable calls, fails every call fast for cooldown, then lets one
// probe through: its success closes the breaker, its failure opens it for another cooldown. A call the core
// answered (2xx, 4xx, an unreadable body) is a success: the core is reachable.
type breaker struct {
	threshold int // <= 0: no breaker
	cooldown  time.Duration
	now       func() time.Time

	mu       sync.Mutex
	failures int
	openedAt time.Time
	open     bool
	probing  bool
}

// allow reports whether a call may go out, and whether it is the half-open probe.
func (b *breaker) allow() (ok, probe bool) {
	if b.threshold <= 0 {
		return true, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return true, false
	}
	if b.probing || b.now().Sub(b.openedAt) < b.cooldown {
		return false, false
	}
	b.probing = true
	return true, true
}

// done records a call's result. failed is the core being unavailable.
func (b *breaker) done(probe, failed bool) {
	if b.threshold <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if probe {
		b.probing = false
	}
	if !failed {
		b.failures, b.open = 0, false
		return
	}
	b.failures++
	if probe || b.failures >= b.threshold {
		b.open, b.openedAt = true, b.now()
	}
}

// cancel releases a probe whose call ended without a verdict on the core (the caller's context ended).
func (b *breaker) cancel(probe bool) {
	if probe && b.threshold > 0 {
		b.mu.Lock()
		b.probing = false
		b.mu.Unlock()
	}
}

func (b *breaker) state() BreakerState {
	if b.threshold <= 0 {
		return BreakerClosed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case !b.open:
		return BreakerClosed
	case b.probing || b.now().Sub(b.openedAt) >= b.cooldown:
		return BreakerHalfOpen
	}
	return BreakerOpen
}
