package grantexpiry

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// Source lists and watches the active grants of every namespace (agent.API implements it).
type Source interface {
	ListActiveGrants(ctx context.Context) ([]agent.Grant, string, error)
	WatchActiveGrants(ctx context.Context, rv string, fn func(agent.GrantEvent)) error
}

// Cache is an informer over the active grants: one list, then a watch from its resourceVersion; a broken or expired
// watch lists again. Synced says whether it has listed at least once and heard from the API server within maxAge: a
// list, an event, a bookmark, or a watch the server ended (a watch that is open and silent counts only when it ends,
// at most WatchDeadline later, so maxAge must be longer than WatchDeadline; the command refuses a shorter one). A cache
// that is not synced answers every lookup with ok false, so the webhook refuses (enforce) instead of deciding on old state.
type Cache struct {
	src    Source
	maxAge time.Duration
	now    func() time.Time
	log    *slog.Logger

	// watchDeadline bounds one watch from the client's side (WatchDeadline; tests shorten it).
	watchDeadline time.Duration

	mu     sync.RWMutex
	grants map[string]map[string]agent.Grant // namespace -> name -> grant
	listed bool
	heard  time.Time
}

// WatchDeadline bounds one watch from the client's side: the server ends it after 300 s (timeoutSeconds), and a
// connection that died silently is given up on here. A healthy quiet watch can go this long without an event.
const WatchDeadline = 330 * time.Second

// NewCache builds a cache; maxAge <= 0 means 10 minutes.
func NewCache(src Source, maxAge time.Duration, now func() time.Time, log *slog.Logger) *Cache {
	if maxAge <= 0 {
		maxAge = 10 * time.Minute
	}
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Cache{src: src, maxAge: maxAge, now: now, log: log, watchDeadline: WatchDeadline, grants: map[string]map[string]agent.Grant{}}
}

// Synced reports whether lookups are answered.
func (c *Cache) Synced() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.listed && c.now().Sub(c.heard) < c.maxAge
}

// Active returns the namespace's active grants, sorted by name, and whether the cache is synced.
func (c *Cache) Active(namespace string) ([]agent.Grant, bool) {
	if !c.Synced() {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []agent.Grant
	for _, g := range c.grants[namespace] {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, true
}

// All returns every cached grant (for the metrics), sorted by namespace and name.
func (c *Cache) All() []agent.Grant {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []agent.Grant
	for _, m := range c.grants {
		for _, g := range m {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (c *Cache) replace(gs []agent.Grant) {
	m := map[string]map[string]agent.Grant{}
	for _, g := range gs {
		if !g.Active() {
			continue
		}
		if m[g.Namespace] == nil {
			m[g.Namespace] = map[string]agent.Grant{}
		}
		m[g.Namespace][g.Name] = g
	}
	c.mu.Lock()
	c.grants, c.listed, c.heard = m, true, c.now()
	c.mu.Unlock()
}

func (c *Cache) apply(ev agent.GrantEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.heard = c.now()
	g := ev.Grant
	switch ev.Type {
	case "ADDED", "MODIFIED":
		if !g.Active() { // a watch by label selector reports a grant leaving it as DELETED; this is belt and braces
			delete(c.grants[g.Namespace], g.Name)
			return
		}
		if c.grants[g.Namespace] == nil {
			c.grants[g.Namespace] = map[string]agent.Grant{}
		}
		c.grants[g.Namespace][g.Name] = g
	case "DELETED":
		delete(c.grants[g.Namespace], g.Name)
	}
}

func (c *Cache) touch() {
	c.mu.Lock()
	c.heard = c.now()
	c.mu.Unlock()
}

// Run keeps the cache until ctx ends. backoff is the wait after a failed list or watch (default 2 s).
func (c *Cache) Run(ctx context.Context, backoff time.Duration) {
	if backoff <= 0 {
		backoff = 2 * time.Second
	}
	wait := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
			return true
		}
	}
	for ctx.Err() == nil {
		gs, rv, err := c.src.ListActiveGrants(ctx)
		if err != nil {
			c.log.Warn("listing the active grants failed", "err", err)
			if !wait() {
				return
			}
			continue
		}
		c.replace(gs)
		for ctx.Err() == nil {
			start := c.now()
			// The server ends a watch after 300 s; a connection that dies silently would hang the read forever (and the
			// cache would go stale and stop answering), so the client gives up on its own a little after that.
			wctx, cancel := context.WithTimeout(ctx, c.watchDeadline)
			err := c.src.WatchActiveGrants(wctx, rv, func(ev agent.GrantEvent) {
				if ev.RV != "" {
					rv = ev.RV
				}
				if ev.Type == "BOOKMARK" {
					c.touch()
					return
				}
				c.apply(ev)
			})
			timedOut := wctx.Err() != nil && ctx.Err() == nil
			cancel()
			if ctx.Err() != nil {
				return
			}
			if timedOut { // the client's deadline, not the server: nothing was heard, so not touched; list again
				c.log.Warn("a watch of the active grants outlived its deadline: listing again")
				break
			}
			if err == nil { // the server ended the watch (its timeout): watch again from the last resourceVersion
				c.touch()
				if c.now().Sub(start) < time.Second && !wait() { // not in a tight loop if it ends at once
					return
				}
				continue
			}
			if ctx.Err() != nil {
				return
			}
			if !errors.Is(err, agent.ErrWatchGone) {
				c.log.Warn("watching the active grants failed: listing again", "err", err)
				if !wait() {
					return
				}
			}
			break // list again
		}
	}
}
