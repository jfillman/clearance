package client_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
)

// With RetryBackoff set, the retries of an unavailable core wait a jittered, doubling time between attempts (and never
// at once); the caller's context still bounds the whole call.
func TestRetryBackoffWaitsBetweenAttempts(t *testing.T) {
	addr := closedAddr(t)
	c := newClient(t, addr, gw, func(o *client.Options) {
		o.Retries, o.RetryBackoff, o.RetryBackoffMax, o.BreakerThreshold = 2, 40*time.Millisecond, 60*time.Millisecond, -1
	})
	start := time.Now()
	_, err := c.Evaluate(context.Background(), evalReq())
	took := time.Since(start)
	unavailable(t, err, client.ReasonConnection, 3)
	// waits: [20,40] ms then [30,60] ms (capped): at least 50 ms in all, well under a second
	if took < 50*time.Millisecond || took > time.Second {
		t.Fatalf("three attempts took %s", took)
	}
	// the default is the outage policy's: retried at once
	c = newClient(t, addr, gw, func(o *client.Options) { o.BreakerThreshold = -1 })
	start = time.Now()
	_, err = c.Evaluate(context.Background(), evalReq())
	unavailable(t, err, client.ReasonConnection, 2)
	if time.Since(start) > 40*time.Millisecond {
		t.Fatalf("the default retry waited %s", time.Since(start))
	}
	// a context that ends during the wait returns its error, not a verdict on the core
	c = newClient(t, addr, gw, func(o *client.Options) { o.Retries, o.RetryBackoff, o.BreakerThreshold = 2, 5*time.Second, -1 })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err = c.Evaluate(ctx, evalReq())
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, client.ErrCoreUnavailable) || time.Since(start) > 2*time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
	if _, err := client.New(client.Options{BaseURL: "http://x.test", RetryBackoff: -time.Second}); err == nil {
		t.Fatal("a negative backoff was accepted")
	}
}

// Callers that failed together do not retry together: the waits of concurrent calls spread.
func TestRetryBackoffIsJittered(t *testing.T) {
	addr := closedAddr(t)
	var mu sync.Mutex
	var took []time.Duration
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := newClient(t, addr, gw, func(o *client.Options) { o.Retries, o.RetryBackoff, o.BreakerThreshold = 1, 200*time.Millisecond, -1 })
			start := time.Now()
			c.Evaluate(context.Background(), evalReq())
			mu.Lock()
			took = append(took, time.Since(start))
			mu.Unlock()
		}()
	}
	wg.Wait()
	lo, hi := took[0], took[0]
	for _, d := range took {
		lo, hi = min(lo, d), max(hi, d)
	}
	if lo < 100*time.Millisecond || hi-lo < 5*time.Millisecond {
		t.Fatalf("waits %v: not in [100,200] ms or not spread", took)
	}
}
