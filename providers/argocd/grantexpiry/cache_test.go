package grantexpiry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// fakeSource lists lists[i] on the i-th list (the last one again after) and plays watches[i] on the i-th watch, then
// returns its error (nil: the server ended it).
type fakeSource struct {
	mu      sync.Mutex
	lists   [][]agent.Grant
	listErr error
	watches []struct {
		events []agent.GrantEvent
		err    error
	}
	nList, nWatch int
	rvs           []string
	done          chan struct{}
}

func (f *fakeSource) ListActiveGrants(context.Context) ([]agent.Grant, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, "", f.listErr
	}
	i := min(f.nList, len(f.lists)-1)
	f.nList++
	return f.lists[i], "rv-list", nil
}

func (f *fakeSource) WatchActiveGrants(ctx context.Context, rv string, fn func(agent.GrantEvent)) error {
	f.mu.Lock()
	f.rvs = append(f.rvs, rv)
	if f.nWatch >= len(f.watches) {
		f.mu.Unlock()
		if f.done != nil {
			select {
			case f.done <- struct{}{}:
			default:
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}
	w := f.watches[f.nWatch]
	f.nWatch++
	f.mu.Unlock()
	for _, ev := range w.events {
		fn(ev)
	}
	return w.err
}

func active(ns, name string) agent.Grant {
	g := grant(name, future, objs(cmKey, h1))
	g.Namespace = ns
	return g
}

func names(gs []agent.Grant) []string {
	var out []string
	for _, g := range gs {
		out = append(out, g.Namespace+"/"+g.Name)
	}
	return out
}

func TestTheCacheListsWatchesAndRelists(t *testing.T) {
	inactive := active("a", "g2")
	delete(inactive.Labels, agent.LabelActive)
	src := &fakeSource{done: make(chan struct{}, 1),
		lists: [][]agent.Grant{{active("a", "g1"), inactive}, {active("b", "g9")}}}
	src.watches = append(src.watches, struct {
		events []agent.GrantEvent
		err    error
	}{events: []agent.GrantEvent{
		{Type: "ADDED", Grant: active("a", "g3"), RV: "rv-1"},
		{Type: "BOOKMARK", RV: "rv-2"},
	}, err: nil}, struct {
		events []agent.GrantEvent
		err    error
	}{events: []agent.GrantEvent{
		{Type: "DELETED", Grant: active("a", "g1"), RV: "rv-3"},
	}, err: agent.ErrWatchGone})
	c := NewCache(src, time.Minute, nil, nil)
	if _, ok := c.Active("a"); ok || c.Synced() {
		t.Fatal("a cache that has not listed is not synced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx, time.Millisecond)
	select {
	case <-src.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the cache never settled into a watch")
	}
	// After list 1 (g1; g2 is not active), watch 1 (+g3, a bookmark), watch 2 (-g1, then 410), list 2 replaces it all.
	got, ok := c.Active("b")
	if !ok || len(got) != 1 || got[0].Name != "g9" {
		t.Fatalf("after the relist the cache is the second list: %v %v", names(got), ok)
	}
	if a, _ := c.Active("a"); len(a) != 0 {
		t.Fatalf("the relist dropped namespace a: %v", names(a))
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	// Watch 1 starts at the list's rv; watch 2 resumes at the bookmark's; after the 410 the next starts at the new list's.
	if len(src.rvs) < 3 || src.rvs[0] != "rv-list" || src.rvs[1] != "rv-2" || src.rvs[2] != "rv-list" {
		t.Fatalf("watch resourceVersions %v", src.rvs)
	}
}

func TestTheCacheAppliesEvents(t *testing.T) {
	c := NewCache(&fakeSource{}, time.Minute, nil, nil)
	c.replace([]agent.Grant{active("a", "g1")})
	c.apply(agent.GrantEvent{Type: "ADDED", Grant: active("a", "g2")})
	if a, _ := c.Active("a"); len(a) != 2 || a[0].Name != "g1" || a[1].Name != "g2" {
		t.Fatalf("added: %v", names(a))
	}
	off := active("a", "g2")
	delete(off.Labels, agent.LabelActive)
	c.apply(agent.GrantEvent{Type: "MODIFIED", Grant: off})
	if a, _ := c.Active("a"); len(a) != 1 {
		t.Fatalf("a grant that lost the active label leaves the cache: %v", names(a))
	}
	c.apply(agent.GrantEvent{Type: "DELETED", Grant: active("a", "g1")})
	if a, _ := c.Active("a"); len(a) != 0 {
		t.Fatalf("deleted: %v", names(a))
	}
	if all := c.All(); len(all) != 0 {
		t.Fatalf("All after deletes: %v", names(all))
	}
}

func TestACacheNotHeardFromIsNotSynced(t *testing.T) {
	at := now
	c := NewCache(&fakeSource{}, time.Minute, func() time.Time { return at }, nil)
	c.replace(nil)
	if !c.Synced() {
		t.Fatal("just listed: synced")
	}
	at = at.Add(59 * time.Second)
	if !c.Synced() {
		t.Fatal("under maxAge: synced")
	}
	at = at.Add(2 * time.Second)
	if _, ok := c.Active("a"); ok || c.Synced() {
		t.Fatal("past maxAge with no word from the API server: not synced, no answers")
	}
	c.touch()
	if !c.Synced() {
		t.Fatal("a bookmark or a reopened watch counts as heard")
	}
}

func TestTheCacheRetriesAFailedList(t *testing.T) {
	src := &fakeSource{listErr: errors.New("forbidden")}
	c := NewCache(src, time.Minute, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c.Run(ctx, time.Millisecond)
	if c.Synced() {
		t.Fatal("a cache whose list fails is never synced")
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	if src.nList != 0 { // listErr returns before counting
		t.Fatalf("lists counted %d", src.nList)
	}
}

// A watch whose connection dies silently is given up on at the client's deadline, and the cache lists again; the dead
// watch does not count as word from the API server.
func TestAHungWatchIsAbandonedAtItsDeadline(t *testing.T) {
	src := &fakeSource{lists: [][]agent.Grant{{active("a", "g1")}}} // no watches: each one hangs until its context ends
	c := NewCache(src, time.Minute, nil, nil)
	c.watchDeadline = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	c.Run(ctx, time.Millisecond)
	src.mu.Lock()
	defer src.mu.Unlock()
	if src.nList < 3 {
		t.Fatalf("a hung watch must end at its deadline and the cache list again: %d lists in 400 ms", src.nList)
	}
}
