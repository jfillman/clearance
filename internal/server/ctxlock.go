package server

import (
	"context"
	"sync"

	"golang.org/x/sync/semaphore"
)

// ctxMutex is a mutex whose wait ends when the caller's context does: a request queued behind a slow one gives up with its own deadline
// instead of holding its goroutine for as long as the other takes.
type ctxMutex struct {
	once sync.Once
	ch   chan struct{}
}

func (m *ctxMutex) init() { m.once.Do(func() { m.ch = make(chan struct{}, 1) }) }

// Lock takes the mutex, or returns the context's error.
func (m *ctxMutex) Lock(ctx context.Context) error {
	m.init()
	select {
	case m.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Unlock releases a mutex Lock took.
func (m *ctxMutex) Unlock() { <-m.ch }

// gateMax is the weight a writer takes: more than any number of concurrent readers.
const gateMax = 1 << 30

// ctxGate is a reader-writer lock whose waits end with the caller's context. Readers share it; a writer excludes them all. Waiters are served
// in order, so a writer that waits holds back readers that come after it: the sections it guards are therefore kept short.
type ctxGate struct {
	once sync.Once
	sem  *semaphore.Weighted
}

func (g *ctxGate) init() { g.once.Do(func() { g.sem = semaphore.NewWeighted(gateMax) }) }

// Read takes the gate for reading; the returned func releases it and may be called more than once.
func (g *ctxGate) Read(ctx context.Context) (func(), error) {
	g.init()
	if err := g.sem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(func() { g.sem.Release(1) }) }, nil
}

// Write takes the gate for writing; the returned func releases it and may be called more than once.
func (g *ctxGate) Write(ctx context.Context) (func(), error) {
	g.init()
	if err := g.sem.Acquire(ctx, gateMax); err != nil {
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(func() { g.sem.Release(gateMax) }) }, nil
}
