package grc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/gate"
)

// Service is the push loop. It reads the changes of the window from clearance-api, builds the complete evidence
// set, and sends it to the hub; it reads and writes nothing on the core's decision path.
//
// The hub REPLACES its set with the one sent: whatever a push leaves out is deleted there. So the service never
// sends a set it cannot vouch for. Before each push it refuses, and records, a set that is empty, much smaller than
// the last one sent, read from an incomplete or unreadable source, or trimmed by a cap (docs/grc-push.md, Guardrails).
//
// Idempotent by construction: an item's id is derived from the change id, so sending a change twice (a retry, a
// restart, a second replica) leaves one item; and each ledger record carries an event id the core de-duplicates.
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

	mu       sync.Mutex
	recorded map[string]bool // event ids the core has acknowledged
	push     loopState
	report   loopState
}

// loopState is what one loop (evidence or report) remembers: its last pushed set (the floor for the shrink guard,
// held in memory only: after a restart only an empty set is refused), when it was sent, and its health.
type loopState struct {
	size         int
	ids          map[string]bool
	digest       string
	sentAt       time.Time
	lastErr      error
	failingSince time.Time
}

// Failure classes besides an *Error's: a refusal is a push the service chose not to make.
const (
	ReasonShrink     = "shrink-refused"
	ReasonTruncated  = "truncated"
	ReasonUnreadable = "unreadable-source"
)

// Reasons are every value a failed record's reason takes (the core accepts these and no others).
var Reasons = []string{"auth", "rate-limited", "unavailable", "rejected", "bad-response", "network", "config", "unknown",
	ReasonShrink, ReasonTruncated, ReasonUnreadable, "source"}

// Refusal is a push the service declined to make, with the sizes that explain it.
type Refusal struct {
	Reason string
	Detail string
	Items  int
}

func (r *Refusal) Error() string { return "grc: push refused: " + r.Reason + " (" + r.Detail + ")" }

// NewService wires a service; its clients refuse redirects and ignore the proxy settings unless asked.
func NewService(cfg Config, t Target, log *slog.Logger) *Service {
	h := NewHTTPClient(cfg.UseProxy)
	controls, _ := ControlsFor(cfg.Mappings)
	return &Service{Cfg: cfg, Target: t, Log: log, Now: time.Now, Sleep: sleep,
		Reader:  &Reader{API: cfg.APIURL, TokenFile: cfg.SATokenFile, HTTP: h},
		Ledger:  &Ledger{Core: cfg.CoreURL, TokenFile: cfg.SATokenFile, Provider: cfg.Provider, HTTP: h},
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

// Run pushes every Interval and the report every ReportInterval, each in its own loop so a report's retries cannot
// delay the evidence, until ctx ends. A failed cycle is logged and recorded; the next one starts again from
// clearance-api: nothing is queued in memory that a restart would lose.
func (s *Service) Run(ctx context.Context) {
	var wg sync.WaitGroup
	loop := func(every time.Duration, name string, f func(context.Context) error) {
		defer wg.Done()
		t := time.NewTimer(0)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := f(ctx); err != nil && ctx.Err() == nil {
					s.Log.Error(name+" failed", "error", err.Error())
				}
				t.Reset(every)
			}
		}
	}
	wg.Add(2)
	go loop(s.Cfg.Interval, "evidence push", s.PushOnce)
	go loop(s.Cfg.ReportInterval, "coverage report push", s.ReportOnce)
	wg.Wait()
}

// Mux serves /healthz (the process is up: liveness) and /readyz (neither loop has been failing for longer than
// UnreadyAfter). They are separate so a vendor outage takes the pod out of rotation without restarting it.
func (s *Service) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.Ready() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	return mux
}

// Ready is false once either loop has been failing for longer than UnreadyAfter.
func (s *Service) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range []*loopState{&s.push, &s.report} {
		if !l.failingSince.IsZero() && s.Now().Sub(l.failingSince) > s.Cfg.UnreadyAfter {
			return false
		}
	}
	return true
}

// Healthy is false while the last evidence cycle failed.
func (s *Service) Healthy() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.push.lastErr == nil }

// fetch reads every state of every configured env into slim changes, refusing at once an incomplete read.
func (s *Service) fetch(ctx context.Context, since time.Time, states ...string) ([]Change, error) {
	var out []Change
	var unreadable, truncated int
	for _, env := range s.Cfg.Envs {
		for _, st := range states {
			cs, rs, err := s.Reader.Changes(ctx, st, env, since, s.Cfg.MaxItems)
			if err != nil {
				return nil, &Refusal{Reason: "source", Detail: err.Error()}
			}
			unreadable += rs.Unreadable
			if rs.Truncated {
				truncated++
			}
			out = append(out, cs...)
		}
	}
	switch {
	case unreadable > 0:
		return nil, &Refusal{Reason: ReasonUnreadable, Detail: fmt.Sprintf("%d records did not parse", unreadable), Items: len(out)}
	case truncated > 0:
		return nil, &Refusal{Reason: ReasonTruncated, Detail: fmt.Sprintf("%d reads stopped at %d with more pages available", truncated, s.Cfg.MaxItems), Items: len(out)}
	}
	return out, nil
}

// Evidence builds the set for changes: every one cleared within the window, whatever state it is in now, newest
// first. A set over MaxItems is a truncation, which the caller refuses.
func (s *Service) Evidence(changes []Change) ([]Item, bool) {
	since := s.Now().Add(-s.Cfg.Window)
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].ClearedAt().After(changes[j].ClearedAt()) })
	var items []Item
	seen := map[string]bool{}
	for _, c := range changes {
		if !c.WasCleared() || c.ClearedAt().Before(since) || seen[c.ID] {
			continue
		}
		if it, ok := s.Builder.Evidence(c); ok {
			seen[c.ID] = true
			items = append(items, it)
		}
	}
	if len(items) > s.Cfg.MaxItems {
		return items[:s.Cfg.MaxItems], true
	}
	return items, false
}

// guard refuses a set that would make the hub delete what it should keep: an empty one, or one smaller than
// MinSetRatio of the last set this process sent, unless AllowShrink.
func (s *Service) guard(l *loopState, n int) *Refusal {
	if s.Cfg.AllowShrink {
		return nil
	}
	if n == 0 {
		return &Refusal{Reason: ReasonShrink, Detail: fmt.Sprintf("an empty set; the last sent had %d", l.size)}
	}
	if l.size > 0 && float64(n) < s.Cfg.MinSetRatio*float64(l.size) {
		return &Refusal{Reason: ReasonShrink, Detail: fmt.Sprintf("%d items against %d last sent (floor %.0f%%)", n, l.size, s.Cfg.MinSetRatio*100), Items: n}
	}
	return nil
}

// PushOnce is one evidence cycle.
func (s *Service) PushOnce(ctx context.Context) error {
	since := s.Now().Add(-s.Cfg.Window)
	changes, err := s.fetch(ctx, since, gate.StateCleared, gate.StateSuperseded, gate.StateException)
	var items []Item
	if err == nil {
		var capped bool
		if items, capped = s.Evidence(changes); capped {
			err = &Refusal{Reason: ReasonTruncated, Detail: fmt.Sprintf("more than %d cleared changes in the window", s.Cfg.MaxItems), Items: len(items)}
		}
	}
	s.mu.Lock()
	l := s.push
	s.mu.Unlock()
	if err == nil {
		if r := s.guard(&l, len(items)); r != nil {
			err = r
		}
	}
	if err != nil {
		s.fail(ctx, KindPush, "", len(items), err)
		return s.note(&s.push, err)
	}
	digest := SetDigest(items)
	if digest != l.digest || s.Now().Sub(l.sentAt) >= s.Cfg.ResendEvery {
		if err := s.withRetry(ctx, func() error { return s.Target.PushEvidence(ctx, items) }); err != nil {
			s.fail(ctx, KindPush, digest, len(items), err)
			return s.note(&s.push, err)
		}
		ids := map[string]bool{}
		for _, it := range items {
			ids[it.ID] = true
		}
		left := 0
		for id := range l.ids {
			if !ids[id] {
				left++
			}
		}
		s.mu.Lock()
		s.push.size, s.push.ids, s.push.digest, s.push.sentAt = len(items), ids, digest, s.Now()
		s.mu.Unlock()
		// One record for the set, with how many items left it since the last push, so a shrink is explainable.
		if err := s.write(ctx, Record{Kind: KindPush, Target: s.Target.Name(), Result: "pushed", Digest: digest,
			EventID: s.Target.Name() + ":set:" + digest, Count: len(items), Left: left}); err != nil {
			return s.note(&s.push, err)
		}
	}
	// The ledger: one record per item, once (the core drops a repeat by its event id). A record the core refuses
	// is skipped and logged; one it cannot take (5xx, network) stops the loop and is retried next cycle.
	for _, it := range items {
		ev := s.Target.Name() + ":" + it.ID + ":" + Digest(it)
		s.mu.Lock()
		done := s.recorded[ev]
		s.mu.Unlock()
		if done {
			continue
		}
		err := s.write(ctx, Record{Kind: KindPush, Target: s.Target.Name(), Result: "pushed", Change: it.ID[len("clearance-change-"):],
			Digest: Digest(it), EventID: ev, Link: it.Link})
		var ce *CoreError
		if errors.As(err, &ce) && ce.Rejected() {
			s.Log.Error("the core refused a push record; skipped", "item", it.ID, "status", ce.Status)
			s.mu.Lock()
			s.recorded[ev] = true // not sent again: it will be refused again
			s.mu.Unlock()
			continue
		}
		if err != nil {
			s.Log.Error("recording a push failed; it is retried next cycle", "error", err.Error())
			return s.note(&s.push, err)
		}
	}
	return s.note(&s.push, nil)
}

// write records r once (the event id is remembered after the core acknowledges it).
func (s *Service) write(ctx context.Context, r Record) error {
	if r.EventID != "" {
		s.mu.Lock()
		done := s.recorded[r.EventID]
		s.mu.Unlock()
		if done {
			return nil
		}
	}
	if _, err := s.Ledger.Write(ctx, r); err != nil {
		return err
	}
	if r.EventID != "" {
		s.mu.Lock()
		s.recorded[r.EventID] = true
		s.mu.Unlock()
	}
	return nil
}

// ReportOnce is one report cycle: the per-day counts of the window, from the day that contains its start.
func (s *Service) ReportOnce(ctx context.Context) error {
	if rc, ok := s.Target.(interface{ ReportEnabled() bool }); ok && !rc.ReportEnabled() {
		return nil
	}
	now := s.Now().UTC()
	from := now.Add(-s.Cfg.Window).Truncate(24 * time.Hour)
	changes, err := s.fetch(ctx, from, gate.StateCleared, gate.StateSuperseded, gate.StateException, gate.StateDenied, gate.StateDegraded, gate.StateExpired)
	var items []Item
	if err == nil {
		items = s.Builder.Reports(changes, from)
	}
	s.mu.Lock()
	l := s.report
	s.mu.Unlock()
	if err == nil {
		if r := s.guard(&l, len(items)); r != nil {
			err = r
		}
	}
	if err != nil {
		s.fail(ctx, KindReport, "", len(items), err)
		return s.note(&s.report, err)
	}
	digest := SetDigest(items)
	if err := s.withRetry(ctx, func() error { return s.Target.PushReport(ctx, items) }); err != nil {
		if err == ErrNoReport {
			return nil
		}
		s.fail(ctx, KindReport, digest, len(items), err)
		return s.note(&s.report, err)
	}
	s.mu.Lock()
	s.report.size, s.report.digest, s.report.sentAt = len(items), digest, s.Now()
	s.mu.Unlock()
	// Once per distinct set and day (two identical days are two records).
	return s.note(&s.report, s.write(ctx, Record{Kind: KindReport, Target: s.Target.Name(), Result: "pushed", Digest: digest,
		EventID: s.Target.Name() + ":report:" + Day(now) + ":" + digest, Link: s.Cfg.LinkBase, Count: len(items)}))
}

// Record kinds (server.KindGRCPush, server.KindGRCReport; not imported, so this package does not depend on the core).
const (
	KindPush   = "grc.push"
	KindReport = "grc.report"
)

// fail writes a refused or failed push to the ledger and the log. Its event id holds the kind, the class and the hour,
// so a persistent failure is one record an hour per class, not one a cycle. If the ledger cannot be reached either it
// is logged; the next cycle fails and records again.
func (s *Service) fail(ctx context.Context, kind, digest string, n int, cause error) {
	if ctx.Err() != nil {
		return // shutting down: not a push failure
	}
	class, detail := "unknown", ""
	var e *Error
	var rf *Refusal
	switch {
	case errors.As(cause, &e):
		class = e.Class
	case errors.As(cause, &rf):
		class, detail = rf.Reason, rf.Detail
	}
	s.Log.Error("hub push not made", "kind", kind, "reason", class, "detail", detail, "items", n)
	ev := fmt.Sprintf("%s:fail:%s:%s:%s", s.Target.Name(), kind, class, s.Now().UTC().Format("2006-01-02T15"))
	if err := s.write(ctx, Record{Kind: kind, Target: s.Target.Name(), Result: "failed", Digest: digest, Reason: class, Count: n, EventID: ev}); err != nil {
		s.Log.Error("recording a failed push failed", "error", err.Error())
	}
}

// note keeps a loop's last result and when it started failing (for /readyz).
func (s *Service) note(l *loopState, err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l.lastErr = err
	switch {
	case err == nil:
		l.failingSince = time.Time{}
	case l.failingSince.IsZero():
		l.failingSince = s.Now()
	}
	return err
}

// withRetry runs f up to Attempts times: a retryable *Error waits (the hub's Retry-After when longer, else
// exponential backoff with jitter, capped at BackoffMax) and goes again; anything else stops at once, and so does a
// Retry-After longer than BackoffMax: the cycle ends and the next tick tries again, not sooner. The last error is
// returned.
func (s *Service) withRetry(ctx context.Context, f func() error) error {
	var err error
	for attempt := 0; attempt < s.Cfg.Attempts; attempt++ {
		if err = f(); err == nil {
			return nil
		}
		e, ok := err.(*Error)
		if !ok || !e.Retryable || attempt == s.Cfg.Attempts-1 || e.RetryAfter > s.Cfg.BackoffMax {
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
		s.Log.Warn("hub push failed; retrying", "class", e.Class, "status", e.Status, "attempt", attempt+1, "wait", wait.String())
		if serr := s.Sleep(ctx, wait); serr != nil {
			return serr
		}
	}
	return err
}
