package collector

import (
	"sort"
	"sync"
	"time"
)

// Gaps finds the changes the audit feed missed: a change to desired state the watch stream showed and no audit event
// reported. The two streams arrive in either order, so each remembers the other: a watch change waits for an audit
// event for the same object (by resourceVersion when the event has one, else by time within Match); an audit event
// waits, for a short while, for a watch change that has not arrived yet. A watch change still unmatched after Grace
// (plus however far behind the queue is) is a gap.
type Gaps struct {
	Grace time.Duration // how long an audit event may trail the change it reports
	Match time.Duration // how close in time an audit event and a watch change are to be the same change

	mu       sync.Mutex
	pending  []*pend
	audits   []auditSeen
	matched  int
	reported int
}

type pend struct {
	Change
	key cacheKey
}

type auditSeen struct {
	key cacheKey
	rv  string
	at  time.Time
	got time.Time // when the collector read it
}

// NewGaps builds a tracker.
func NewGaps(grace time.Duration) *Gaps {
	return &Gaps{Grace: grace, Match: 30 * time.Second}
}

// Watched records a watch change to desired state (a status write is not one).
func (g *Gaps) Watched(ch Change) {
	if !ch.Desired {
		return
	}
	k := cacheKey{ch.Kind, ch.Namespace, ch.Name}
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, a := range g.audits { // the audit event came first
		if a.key == k && g.same(a.rv, a.at, ch.RV, ch.At) {
			g.audits = append(g.audits[:i], g.audits[i+1:]...)
			g.matched++
			return
		}
	}
	g.pending = append(g.pending, &pend{ch, k})
}

func (g *Gaps) same(auditRV string, auditAt time.Time, watchRV string, watchAt time.Time) bool {
	if auditRV != "" && watchRV != "" {
		return auditRV == watchRV
	}
	d := watchAt.Sub(auditAt)
	if d < 0 {
		d = -d
	}
	return d <= g.Match
}

// Audited records an audit write event for an object: it accounts for the oldest watch change it can be.
func (g *Gaps) Audited(kind, ns, name, rv string, at, now time.Time) {
	k := cacheKey{kind, ns, name}
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, p := range g.pending {
		if p.key == k && g.same(rv, at, p.RV, p.At) {
			g.pending = append(g.pending[:i], g.pending[i+1:]...)
			g.matched++
			return
		}
	}
	g.audits = append(g.audits, auditSeen{k, rv, at, now})
	if len(g.audits) > 4096 {
		g.audits = g.audits[len(g.audits)-2048:]
	}
}

// Expired removes and returns the watch changes no audit event accounted for within Grace plus lag (the age of the
// oldest event still in the queue, which may be the very one), oldest first. It also forgets audit events that waited
// for a watch change longer than that.
func (g *Gaps) Expired(now time.Time, lag time.Duration) []Change {
	g.mu.Lock()
	defer g.mu.Unlock()
	limit := g.Grace + lag
	var out []Change
	keep := g.pending[:0]
	for _, p := range g.pending {
		if now.Sub(p.At) > limit {
			out = append(out, p.Change)
		} else {
			keep = append(keep, p)
		}
	}
	g.pending = keep
	ak := g.audits[:0]
	for _, a := range g.audits {
		if now.Sub(a.got) <= limit {
			ak = append(ak, a)
		}
	}
	g.audits = ak
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	g.reported += len(out)
	return out
}

// Counts: changes matched to an audit event, reported as gaps, and waiting.
func (g *Gaps) Counts() (matched, reported, pending int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.matched, g.reported, len(g.pending)
}

// Requeue puts back a gap whose record could not be posted, so the next pass tries again.
func (g *Gaps) Requeue(ch Change) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pending = append(g.pending, &pend{ch, cacheKey{ch.Kind, ch.Namespace, ch.Name}})
	g.reported--
}
