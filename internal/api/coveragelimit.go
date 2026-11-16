package api

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Coverage reads are the API's heaviest: a statement is six record reads plus a health read per scope, and the
// unscoped form is one statement per scope. They are bounded three ways: at most DefaultCoverageConcurrency compute
// at once (a request past that waits a short, bounded time for a slot, then is refused with 503 and Retry-After), the request's context
// reaches every query and ends the work when the client goes away, and, only when Options.CoverageCacheTTL is set, an
// answer is reused for that long.
const (
	// DefaultCoverageConcurrency is the coverage computations in flight at once when Options.CoverageConcurrency is 0.
	DefaultCoverageConcurrency = 2
	// coverageRetryAfter is the Retry-After of a refused coverage read, in seconds.
	coverageRetryAfter = 5
	// maxCoverageCache caps the cached answers; past it the oldest are dropped.
	maxCoverageCache = 64
	// CoverageWaitersPerSlot bounds the reads waiting for a slot to this many per slot; past it a read is refused at once.
	CoverageWaitersPerSlot = 4
)

// covKey names an answer. The raw from and to are in it, not the window they resolve to, so every read with no from
// shares an entry for the TTL. The viewer is not: the store is read as an auditor whoever asks (readerOf) and the
// answer carries no per-person redaction, so every caller allowed the route gets the same body.
type covKey struct{ scope, names, from, to string }

type covEntry struct {
	body []byte
	at   time.Time
}

type covCache struct {
	ttl time.Duration
	mu  sync.Mutex
	m   map[covKey]covEntry
}

func (c *covCache) get(k covKey, now time.Time) (covEntry, bool) {
	if c == nil || c.ttl <= 0 {
		return covEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok || now.Sub(e.at) >= c.ttl || now.Before(e.at) {
		return covEntry{}, false
	}
	return e, true
}

func (c *covCache) put(k covKey, body []byte, now time.Time) {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[covKey]covEntry{}
	}
	for kk, e := range c.m {
		if now.Sub(e.at) >= c.ttl {
			delete(c.m, kk)
		}
	}
	for len(c.m) >= maxCoverageCache {
		var oldest covKey
		var at time.Time
		for kk, e := range c.m {
			if at.IsZero() || e.at.Before(at) {
				oldest, at = kk, e.at
			}
		}
		delete(c.m, oldest)
	}
	c.m[k] = covEntry{body: body, at: now}
}

// acquireCoverage takes a computation slot. A read that finds none waits up to Options.CoverageWait for one (the wait
// ends at once when the client goes away); past that, or when MaxCoverageWaiters reads already wait, it is answered 503
// with Retry-After. It says false when it answered.
func (s *Server) acquireCoverage(w http.ResponseWriter, r *http.Request) bool {
	select {
	case s.covSem <- struct{}{}:
		return true
	default:
	}
	if s.opt.CoverageWait > 0 {
		if n := s.covWaiters.Add(1); n <= int64(cap(s.covSem)*CoverageWaitersPerSlot) {
			t := time.NewTimer(s.opt.CoverageWait)
			select {
			case s.covSem <- struct{}{}:
				t.Stop()
				s.covWaiters.Add(-1)
				return true
			case <-t.C:
			case <-r.Context().Done():
				t.Stop()
				s.covWaiters.Add(-1)
				s.log.InfoContext(r.Context(), "read abandoned: the client went away", "path", r.URL.Path)
				writeError(w, http.StatusServiceUnavailable, "read failed")
				return false
			}
		}
		s.covWaiters.Add(-1)
	}
	s.log.InfoContext(r.Context(), "coverage read refused: the computations already running are at the limit", "path", r.URL.Path)
	w.Header().Set("Retry-After", strconv.Itoa(coverageRetryAfter))
	writeError(w, http.StatusServiceUnavailable, "coverage reads are at their limit; retry shortly")
	return false
}

func (s *Server) releaseCoverage() { <-s.covSem }
