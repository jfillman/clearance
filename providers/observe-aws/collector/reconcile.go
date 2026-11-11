package collector

import (
	"sort"
	"sync"
	"time"
)

// Merged is one change as the reconciler hands it on: the CloudTrail event, the Config configuration item(s) that
// recorded its effect, or either alone. Exactly one Merged is made per change, so one change is one exception.
type Merged struct {
	Item   *Item   // the CloudTrail event; nil for a configuration item no event explains
	View   *ctView // its parsed record
	Config []*ConfigChange

	items []*Item // every delivery behind it (a redelivered SQS message adds one), acked by Done
	first time.Time
	cfgIt map[string][]*Item // the deliveries behind each joined item, by item id
}

// Reconciler joins the two feeds of one change.
//
// The correlation key. A configuration item is the effect of a CloudTrail event when
//
//  1. the item lists the event: configurationItem.relatedEvents contains the event's eventID (AWS Config's own
//     pointer, and the strongest key); or, when the item lists no related event,
//  2. the same account, the item's resource (its resourceId, ARN or resourceName) is a resource the event names
//     (resources[], request parameters or response elements), and the item was captured no earlier than a minute
//     before the event and no later than Window after it.
//
// An item that lists related events never joins an event it does not list, and joins every event it lists. A fallback
// item (one that lists none) is the effect of exactly one event: the nearest, the one with the latest event time that is
// no later than a minute after the item's capture (ties: the smaller event id). Without that, a security group rule
// added and then removed within the window had the removal's item attached to the add as well, and the add's diff
// was overwritten by the removal's, so the pair could not fold as a revert. Because a nearer event could still be on its
// way, a fallback item is not joined until Grace has passed since it arrived (capped at Settle, so an entry never waits
// longer than Settle for it); an event that a not-yet-eligible item could still join is held for it, which can
// extend that event's wait by at most Grace. The nearest rule also decides Late: an item whose nearest event was emitted
// already is counted Late, but one with a pending event nearer joins that event instead. The join is made when an entry is due, over
// everything pending, so the order the two arrive in does not matter: an event waits up to Settle for its item, and an
// item waits up to Settle for its event. An item whose event never comes is emitted alone (an effect the trail
// did not report: itself a finding). An item that arrives after its event was emitted is counted Late (the live gate
// saw Config take longer than ten minutes for a security group, hence the fifteen-minute default); the event then
// carries the diff of its own CloudTrail request (requestDiff), which does not depend on Config at all.
type Reconciler struct {
	Settle time.Duration // how long an entry waits for its counterpart (and for the outcomes attribution looks up); default 15m
	Window time.Duration // the fallback key's time window; default 15m
	Grace  time.Duration // how long a fallback item waits, from its arrival, before choosing its nearest event, so a nearer event can arrive first; default 2m, capped at Settle
	Now    func() time.Time

	mu      sync.Mutex
	cts     map[string]*pendCT
	cfgs    map[string]*pendCfg
	seen    map[string]time.Time // emitted and done: event ids and config ids
	emitted map[string]*emittedCT
	late    int
}

type pendCT struct {
	m     *Merged
	cfgs  []*pendCfg
	first time.Time
}

type pendCfg struct {
	c     *ConfigChange
	items []*Item
	first time.Time
}

type emittedCT struct {
	view *ctView
	at   time.Time
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reconciler) settle() time.Duration {
	if r.Settle == 0 {
		return 15 * time.Minute
	}
	return r.Settle
}

func (r *Reconciler) grace() time.Duration {
	g := r.Grace
	if g == 0 {
		g = 2 * time.Minute
	}
	if s := r.settle(); g > s {
		g = s
	}
	return g
}

func (r *Reconciler) window() time.Duration {
	if r.Window == 0 {
		return 15 * time.Minute
	}
	return r.Window
}

func (r *Reconciler) init() {
	if r.cts == nil {
		r.cts, r.cfgs, r.seen, r.emitted = map[string]*pendCT{}, map[string]*pendCfg{}, map[string]time.Time{}, map[string]*emittedCT{}
	}
}

// AddCT takes a CloudTrail event. A redelivery of one already pending adds its acks to the pending entry; one already
// emitted and done is a duplicate (its acks run at once: it was posted), and AddCT says so (true): the copy may still
// carry what the posted one lacked, a verified trail's proof (Collector.Ingest hands that on as a verification).
// A copy that arrives while the event is still pending replaces the pending one when it is verified and the pending
// one is not, so the event is posted once, with the proof.
func (r *Reconciler) AddCT(it *Item, v *ctView) (alreadyPosted bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	if _, done := r.seen[v.ID]; done {
		runAcks(it.Acks)
		return true
	}
	if p, ok := r.cts[v.ID]; ok {
		p.m.items = append(p.m.items, it)
		if it.Verified && !p.m.Item.Verified {
			p.m.Item = it
		}
		return false
	}
	r.cts[v.ID] = &pendCT{first: r.now(), m: &Merged{Item: it, View: v, items: []*Item{it}, first: r.now()}}
	return false
}

// AddConfig takes a Config configuration item, with the same duplicate rules.
func (r *Reconciler) AddConfig(it *Item) {
	c := it.Config
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	if _, done := r.seen[c.ID]; done {
		runAcks(it.Acks)
		return
	}
	if p, ok := r.cfgs[c.ID]; ok {
		p.items = append(p.items, it)
		return
	}
	r.cfgs[c.ID] = &pendCfg{c: c, items: []*Item{it}, first: r.now()}
}

func runAcks(a []func()) {
	for _, f := range a {
		f()
	}
}

func (r *Reconciler) joins(c *ConfigChange, v *ctView) bool {
	if c.Account != "" && v.Account != "" && c.Account != v.Account {
		return false
	}
	if len(c.Related) > 0 {
		for _, id := range c.Related {
			if id == v.ID {
				return true
			}
		}
		return false
	}
	if !(v.Refs[c.ResourceID] || (c.ARN != "" && v.Refs[c.ARN]) || (c.ResourceName != "" && v.Refs[c.ResourceName])) {
		return false
	}
	d := c.Captured.Sub(v.Time)
	return d >= -time.Minute && d <= r.window()
}

// Ready returns what is due: events whose Settle has passed (with every item that joins them), and items whose
// Settle has passed with no event. Ordered by event time. Each must come back through Done or Fail.
func (r *Reconciler) Ready() []*Merged {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	now := r.now()
	// 1. join every pending item. An item that lists its events joins each of them; one that lists none joins the single
	// nearest event, once it has waited Grace for a nearer one to arrive.
	ids := make([]string, 0, len(r.cfgs))
	for id := range r.cfgs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		pc := r.cfgs[id]
		if len(pc.c.Related) == 0 {
			if now.Sub(pc.first) < r.grace() {
				continue
			}
			var best *ctView
			var bestPend *pendCT
			consider := func(v *ctView, pe *pendCT) {
				if !r.joins(pc.c, v) {
					return
				}
				if best == nil || v.Time.After(best.Time) || (v.Time.Equal(best.Time) && v.ID < best.ID) {
					best, bestPend = v, pe
				}
			}
			for _, pe := range r.cts {
				consider(pe.m.View, pe)
			}
			for _, e := range r.emitted {
				consider(e.view, nil)
			}
			switch {
			case best == nil:
			case bestPend != nil:
				bestPend.cfgs = append(bestPend.cfgs, pc)
				delete(r.cfgs, id)
			default:
				r.late++
				runAcks(itemAcks(pc.items))
				r.seen[pc.c.ID] = now
				delete(r.cfgs, id)
			}
			continue
		}
		joined := false
		for _, pe := range r.cts {
			if r.joins(pc.c, pe.m.View) {
				pe.cfgs = append(pe.cfgs, pc)
				joined = true
			}
		}
		if joined {
			delete(r.cfgs, id)
			continue
		}
		// an item whose events were emitted already: it cannot be attached any more
		for _, e := range r.emitted {
			if r.joins(pc.c, e.view) {
				r.late++
				runAcks(itemAcks(pc.items))
				r.seen[pc.c.ID] = now
				delete(r.cfgs, id)
				break
			}
		}
	}
	var out []*Merged
	// 2. events that are due
	for id, pe := range r.cts {
		if now.Sub(pe.first) < r.settle() || r.awaitsGrace(pe.m.View, now) {
			continue
		}
		m := pe.m
		m.cfgIt = map[string][]*Item{}
		for _, pc := range pe.cfgs {
			m.Config = append(m.Config, pc.c)
			m.cfgIt[pc.c.ID] = pc.items
		}
		out = append(out, m)
		delete(r.cts, id)
	}
	// 3. items with no event, once due
	for id, pc := range r.cfgs {
		if now.Sub(pc.first) < r.settle() {
			continue
		}
		out = append(out, &Merged{Config: []*ConfigChange{pc.c}, cfgIt: map[string][]*Item{pc.c.ID: pc.items}, first: pc.first})
		delete(r.cfgs, id)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].at().Before(out[j].at()) })
	return out
}

// awaitsGrace says a fallback item that has not waited Grace yet could still join the event, so the event is held
// for it (at most Grace past its Settle).
func (r *Reconciler) awaitsGrace(v *ctView, now time.Time) bool {
	for _, pc := range r.cfgs {
		if len(pc.c.Related) == 0 && now.Sub(pc.first) < r.grace() && r.joins(pc.c, v) {
			return true
		}
	}
	return false
}

func (m *Merged) at() time.Time {
	if m.View != nil {
		return m.View.Time
	}
	return m.Config[0].Captured
}

func itemAcks(items []*Item) []func() {
	var a []func()
	for _, it := range items {
		a = append(a, it.Acks...)
	}
	return a
}

// ID is the id the observation is reported under: the CloudTrail event id, or for an item no event explains the
// first event Config lists for it (the trail's own id, so a later trail copy de-duplicates against it), else "cfg:" and
// the item's id.
func (m *Merged) ID() string {
	switch {
	case m.View != nil:
		return m.View.ID
	case len(m.Config[0].Related) > 0:
		return m.Config[0].Related[0]
	}
	return "cfg:" + m.Config[0].ID
}

// Done records that the Merged was posted: its deliveries are acked and it is never emitted again.
func (r *Reconciler) Done(m *Merged) {
	r.mu.Lock()
	r.init()
	now := r.now()
	if m.View != nil {
		r.seen[m.View.ID] = now
		r.emitted[m.View.ID] = &emittedCT{m.View, now}
	}
	for _, c := range m.Config {
		r.seen[c.ID] = now
	}
	acks := itemAcks(m.items)
	for _, its := range m.cfgIt {
		acks = append(acks, itemAcks(its)...)
	}
	r.gc(now)
	r.mu.Unlock()
	runAcks(acks)
}

// Fail puts the Merged back as it was: it is due again on the next Ready, and nothing is acked.
func (r *Reconciler) Fail(m *Merged) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	past := r.now().Add(-r.settle() - time.Second)
	for _, c := range m.Config {
		r.cfgs[c.ID] = &pendCfg{c: c, items: m.cfgIt[c.ID], first: past}
	}
	if m.View != nil {
		// the items are pending again; the next Ready joins them to the event once more
		m.Config, m.cfgIt = nil, nil
		r.cts[m.View.ID] = &pendCT{m: m, first: past}
	}
}

func (r *Reconciler) gc(now time.Time) {
	for k, t := range r.seen {
		if now.Sub(t) > 24*time.Hour {
			delete(r.seen, k)
		}
	}
	for k, e := range r.emitted {
		if now.Sub(e.at) > r.window()+r.settle() {
			delete(r.emitted, k)
		}
	}
}

// Pending is how many events and items wait.
func (r *Reconciler) Pending() (events, configs int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cts), len(r.cfgs)
}

// Late is how many items arrived after their event was emitted (the diff could not be attached).
func (r *Reconciler) Late() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.late
}
