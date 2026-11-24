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
//
// A finalized delete (Change.Finalized: the API server removed an object once a write took its last finalizer away,
// as the garbage collector does to end a foreground deletion) is matched by time alone, to an update or patch. Its resourceVersion is the
// deletion's, and no audit event carries that one: the write that ended it reports the version it read. Matched by
// version, every foreground deletion (an Argo CD hook's delete policy, for one) was reported as a change nobody audited.
type Gaps struct {
	Grace time.Duration // how long an audit event may trail the change it reports
	Match time.Duration // how close in time an audit event and a watch change are to be the same change

	mu       sync.Mutex
	pending  []*pend
	created  map[cacheKey][]time.Time // each object's recent creates, from their audit events and watch changes, both kept
	audits   []auditSeen
	matched  int
	reported int
}

type pend struct {
	Change
	key cacheKey
}

type auditSeen struct {
	key    cacheKey
	rv     string
	verb   string
	marked *bool // the response object carries deletionTimestamp; nil: the event has no response object (Metadata)
	at     time.Time
	got    time.Time // when the collector read it
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
	if ch.Created {
		g.sawCreate(k, ch.At)
	}
	for i, a := range g.audits { // the audit event came first
		if a.key == k && g.same(a, ch.RV, ch.At, ch.Finalized) {
			g.audits = append(g.audits[:i], g.audits[i+1:]...)
			g.matched++
			return
		}
	}
	g.pending = append(g.pending, &pend{ch, k})
}

// endsDelete: a write of this verb can remove an object's last finalizer, and so end a deletion (Change.Finalized).
// A create cannot: matched by time alone, a finalized delete would otherwise take the audit event of the object an Argo
// CD hook recreates under the same name a moment later, and leave that create to be reported as a gap.
func endsDelete(verb string) bool { return verb == "update" || verb == "patch" }

// finalizeSkew is how far an audit event's time may trail the watch's sight of the deletion it ended: the write that
// removed the last finalizer completes before (or as) the API server deletes the object, never seconds after it.
const finalizeSkew = 2 * time.Second

// canEnd: the audit event can be the write that ended a finalized delete the watch saw at watchAt. An update or patch,
// whose response object (when the event has one) still carries deletionTimestamp, from at most Match before the
// deletion to finalizeSkew after it. A later write to the object an Argo CD hook recreates under the same name has an
// unmarked response object, or is too late, so it is left for its own watch change, whichever arrives first.
//
// A write from after a create of the same name is a write to the recreated object, not the one that ended the delete
// (that write came before the deletion, and so before any recreate). This is what tells a Metadata-level write (no
// response object to read deletionTimestamp from) to the recreate inside the skew from the garbage collector's patch,
// in either arrival order: the create's audit event is read before the later write's (one API server's audit stream is
// in order), and the watch's ADDED counts too, each at its own time. The caller holds g.mu.
func (g *Gaps) canEnd(a auditSeen, watchAt time.Time) bool {
	if !endsDelete(a.verb) || (a.marked != nil && !*a.marked) {
		return false
	}
	d := watchAt.Sub(a.at)
	if d < -finalizeSkew || d > g.Match {
		return false
	}
	for _, c := range g.created[a.key] {
		if !c.Before(watchAt.Add(-finalizeSkew)) && !a.at.Before(c) {
			return false // a write to the object recreated after the deletion
		}
	}
	return true
}

// sawCreate notes a create of the object at `at`. Every time is kept, not the newest: the audit event's time (the API
// server's) and the watch's (when the collector saw it) of one create differ, and a write between the two must still be
// told from the write that ended the delete. The caller holds g.mu.
func (g *Gaps) sawCreate(k cacheKey, at time.Time) {
	if g.created == nil {
		g.created = map[cacheKey][]time.Time{}
	}
	g.created[k] = append(g.created[k], at)
}

func (g *Gaps) same(a auditSeen, watchRV string, watchAt time.Time, finalized bool) bool {
	if finalized {
		return g.canEnd(a, watchAt) // whatever versions the two carry
	}
	if a.rv != "" && watchRV != "" {
		return a.rv == watchRV
	}
	d := watchAt.Sub(a.at)
	if d < 0 {
		d = -d
	}
	return d <= g.Match
}

// Audited records an audit write event for an object: it accounts for the oldest watch change it can be.
func (g *Gaps) Audited(kind, ns, name, rv string, at, now time.Time) {
	g.AuditedWrite(kind, ns, name, rv, "", nil, at, now)
}

// AuditedVerb is Audited with the write's verb and no response object (a Metadata event).
func (g *Gaps) AuditedVerb(kind, ns, name, rv, verb string, at, now time.Time) {
	g.AuditedWrite(kind, ns, name, rv, verb, nil, at, now)
}

// AuditedWrite is Audited with the write's verb and whether its response object carries deletionTimestamp (nil: the
// event has none), which say whether it can have ended a finalized delete. A change it matches by resourceVersion is
// preferred to a finalized delete it matches only by time.
func (g *Gaps) AuditedWrite(kind, ns, name, rv, verb string, marked *bool, at, now time.Time) {
	k := cacheKey{kind, ns, name}
	a := auditSeen{k, rv, verb, marked, at, now}
	g.mu.Lock()
	defer g.mu.Unlock()
	if verb == "create" {
		g.sawCreate(k, at)
	}
	for _, byTime := range []bool{false, true} {
		for i, p := range g.pending {
			if p.key != k || p.Finalized != byTime {
				continue
			}
			if g.same(a, p.RV, p.At, p.Finalized) {
				g.pending = append(g.pending[:i], g.pending[i+1:]...)
				g.matched++
				return
			}
		}
	}
	g.audits = append(g.audits, a)
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
	for k, cs := range g.created {
		keep := cs[:0]
		for _, c := range cs {
			if now.Sub(c) <= limit+g.Match {
				keep = append(keep, c)
			}
		}
		if len(keep) == 0 {
			delete(g.created, k)
		} else {
			g.created[k] = keep
		}
	}
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
