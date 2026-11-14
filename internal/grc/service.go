package grc

import (
	"context"
	"log/slog"
	"math/rand"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/gate"
)

// Service is the push loop. It reads the cleared production changes of the window from clearance-api, builds the
// complete evidence set, and sends it to the hub; it reads and writes nothing on the core's decision path.
//
// Idempotent by construction: an item's id is derived from the change id, the hub replaces its set with the one sent,
// so sending a change twice (a retry, a restart, a second replica) leaves one item; and each ledger record carries the
// event id hub+change+item digest, so the core records an item once however often it is told.
type Service struct {
	Cfg     Config
	Target  Target
	Reader  *Reader
	Ledger  *Ledger
	Builder Builder
	Log     *slog.Logger
	Now     func() time.Time
	// Sleep waits between attempts; a test replaces it.
	Sleep func(context.Context, time.Duration) error

	mu           sync.Mutex
	lastEvidence string          // set digest of the last successful evidence push
	recorded     map[string]bool // event ids the core has acknowledged
	lastReport   string
	lastErr      error
	lastOK       time.Time
}

// NewService wires a service; its clients refuse redirects.
func NewService(cfg Config, t Target, log *slog.Logger) *Service {
	h := func() *http.Client {
		return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	controls, _ := ControlsFor(cfg.Mappings)
	return &Service{Cfg: cfg, Target: t, Log: log, Now: time.Now, Sleep: sleep,
		Reader:  &Reader{API: cfg.APIURL, TokenFile: cfg.SATokenFile, HTTP: h()},
		Ledger:  &Ledger{Core: cfg.CoreURL, TokenFile: cfg.SATokenFile, Provider: cfg.Provider, HTTP: h()},
		Builder: Builder{LinkBase: cfg.LinkBase, Controls: controls}, recorded: map[string]bool{}}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run pushes every Interval and the report every ReportInterval until ctx ends. A failed cycle is logged and recorded
// and the next one tries again from the ledger and the api: nothing is queued in memory that a restart would lose.
func (s *Service) Run(ctx context.Context) {
	rep := time.NewTimer(0)
	defer rep.Stop()
	tick := time.NewTimer(0)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := s.PushOnce(ctx); err != nil && ctx.Err() == nil {
				s.Log.Error("evidence push failed", "error", err.Error())
			}
			tick.Reset(s.Cfg.Interval)
		case <-rep.C:
			if err := s.ReportOnce(ctx); err != nil && ctx.Err() == nil {
				s.Log.Error("coverage report push failed", "error", err.Error())
			}
			rep.Reset(s.Cfg.ReportInterval)
		}
	}
}

func (s *Service) fetch(ctx context.Context, states ...string) ([]gate.Change, error) {
	since := s.Now().Add(-s.Cfg.Window)
	var out []gate.Change
	for _, env := range s.Cfg.Envs {
		for _, st := range states {
			cs, err := s.Reader.Changes(ctx, st, env, since, s.Cfg.MaxItems)
			if err != nil {
				return nil, err
			}
			out = append(out, cs...)
		}
	}
	return out, nil
}

// Evidence builds the set for changes: cleared, in window, newest first up to MaxItems.
func (s *Service) Evidence(changes []gate.Change) []Item {
	since := s.Now().Add(-s.Cfg.Window)
	sort.SliceStable(changes, func(i, j int) bool {
		a, b := changes[i].DecidedAt, changes[j].DecidedAt
		if a == nil || b == nil {
			return a != nil
		}
		return a.Time.After(b.Time)
	})
	var items []Item
	seen := map[string]bool{}
	for _, c := range changes {
		if c.DecidedAt == nil || c.DecidedAt.Time.Before(since) || seen[c.ID] {
			continue
		}
		if it, ok := s.Builder.Evidence(c); ok {
			seen[c.ID] = true
			items = append(items, it)
		}
		if len(items) >= s.Cfg.MaxItems {
			break
		}
	}
	return items
}

// PushOnce is one evidence cycle.
func (s *Service) PushOnce(ctx context.Context) error {
	changes, err := s.fetch(ctx, gate.StateCleared)
	if err != nil {
		return s.note(err)
	}
	items := s.Evidence(changes)
	digest := SetDigest(items)
	s.mu.Lock()
	same := s.lastEvidence == digest
	s.mu.Unlock()
	if !same {
		if err := s.withRetry(ctx, func() error { return s.Target.PushEvidence(ctx, items) }); err != nil {
			s.recordFailure(ctx, KindPush, digest, len(items), err)
			return s.note(err)
		}
		s.mu.Lock()
		s.lastEvidence = digest
		s.mu.Unlock()
	}
	// The ledger: one record per item, once (the core drops a repeat by its event id). A record that cannot be
	// written is retried next cycle: the set digest is only advanced for the hub, never for the ledger.
	var lerr error
	for _, it := range items {
		ev := s.Target.Name() + ":" + it.ID + ":" + Digest(it)
		s.mu.Lock()
		done := s.recorded[ev]
		s.mu.Unlock()
		if done {
			continue
		}
		_, err := s.Ledger.Write(ctx, Record{Kind: KindPush, Target: s.Target.Name(), Result: "pushed", Change: it.ID[len("clearance-change-"):],
			Digest: Digest(it), EventID: ev, Link: it.Link})
		if err != nil {
			lerr = err
			s.Log.Error("recording a push failed; it is retried next cycle", "error", err.Error())
			break
		}
		s.mu.Lock()
		s.recorded[ev] = true
		s.mu.Unlock()
	}
	if lerr != nil {
		return s.note(lerr)
	}
	return s.note(nil)
}

// ReportOnce is one report cycle: the per-day counts of the window as a complete set.
func (s *Service) ReportOnce(ctx context.Context) error {
	changes, err := s.fetch(ctx, gate.StateCleared, gate.StateDenied, gate.StateException, gate.StateDegraded)
	if err != nil {
		return s.note(err)
	}
	items := s.Builder.Reports(changes)
	digest := SetDigest(items)
	if err := s.withRetry(ctx, func() error { return s.Target.PushReport(ctx, items) }); err != nil {
		if err == ErrNoReport {
			return nil
		}
		s.recordFailure(ctx, KindReport, digest, len(items), err)
		return s.note(err)
	}
	// Record once per distinct set (the event id is the set's digest).
	_, err = s.Ledger.Write(ctx, Record{Kind: KindReport, Target: s.Target.Name(), Result: "pushed", Digest: digest,
		EventID: s.Target.Name() + ":report:" + digest, Link: s.Cfg.LinkBase, Count: len(items)})
	return s.note(err)
}

// Record kinds (server.KindGRCPush, server.KindGRCReport; not imported, so this package does not depend on the core).
const (
	KindPush   = "grc.push"
	KindReport = "grc.report"
)

// recordFailure writes the failed push to the ledger: a bounded number of tries ended, and nothing was sent. If the
// ledger cannot be reached either, it is logged (the next cycle fails and records again).
func (s *Service) recordFailure(ctx context.Context, kind, digest string, n int, cause error) {
	if ctx.Err() != nil {
		return // shutting down: not a push failure
	}
	class := "unknown"
	if e, ok := cause.(*Error); ok {
		class = e.Class
	}
	if _, err := s.Ledger.Write(ctx, Record{Kind: kind, Target: s.Target.Name(), Result: "failed", Digest: digest, Reason: class, Count: n}); err != nil {
		s.Log.Error("recording a failed push failed", "error", err.Error())
	}
}

func (s *Service) note(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = err
	if err == nil {
		s.lastOK = s.Now()
	}
	return err
}

// Healthy is false once a cycle failed and no cycle has since succeeded.
func (s *Service) Healthy() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.lastErr == nil }

// withRetry runs f up to Attempts times: a retryable *Error waits (the hub's Retry-After when longer, else
// exponential backoff with jitter, capped at BackoffMax) and goes again; anything else stops at once. The last error
// is returned.
func (s *Service) withRetry(ctx context.Context, f func() error) error {
	var err error
	for attempt := 0; attempt < s.Cfg.Attempts; attempt++ {
		if err = f(); err == nil {
			return nil
		}
		e, ok := err.(*Error)
		if !ok || !e.Retryable || attempt == s.Cfg.Attempts-1 {
			return err
		}
		wait := s.Cfg.BackoffBase << attempt
		if wait <= 0 || wait > s.Cfg.BackoffMax {
			wait = s.Cfg.BackoffMax
		}
		wait = wait/2 + time.Duration(rand.Int63n(int64(wait/2)+1))
		if e.RetryAfter > wait {
			wait = e.RetryAfter
		}
		if wait > s.Cfg.BackoffMax {
			wait = s.Cfg.BackoffMax
		}
		s.Log.Warn("hub push failed; retrying", "class", e.Class, "status", e.Status, "attempt", attempt+1, "wait", wait.String())
		if serr := s.Sleep(ctx, wait); serr != nil {
			return serr
		}
	}
	return err
}
