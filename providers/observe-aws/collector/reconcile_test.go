package collector

import (
	"reflect"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newRec(c *clock) *Reconciler {
	return &Reconciler{Settle: 5 * time.Minute, Window: 15 * time.Minute, Now: c.now}
}
func ctItem(c ct, now time.Time) (*Item, *ctView) {
	it := mustItem(c.envelope(), now)
	v, err := parseCT(it.Raw)
	if err != nil {
		panic(err)
	}
	return it, v
}

// One change, two feeds, either order, by the item's own pointer: one Merged, carrying the diff.
func TestConfigItemAndEventAreOneChangeInEitherOrder(t *testing.T) {
	for _, order := range []string{"event-first", "config-first", "together"} {
		t.Run(order, func(t *testing.T) {
			clk := &clock{t0}
			r := newRec(clk)
			ev := consoleSG("ev-1", t0)
			evIt, v := ctItem(ev, clk.t)
			cfIt := mustItem(sgConfig(t0.Add(40*time.Second), "ev-1").envelope(), clk.t)
			switch order {
			case "event-first":
				r.AddCT(evIt, v)
				clk.add(3 * time.Minute)
				r.AddConfig(cfIt)
			case "config-first":
				r.AddConfig(cfIt)
				clk.add(3 * time.Minute)
				r.AddCT(evIt, v)
			default:
				r.AddCT(evIt, v)
				r.AddConfig(cfIt)
				clk.add(time.Minute)
			}
			if got := r.Ready(); len(got) != 0 {
				t.Fatalf("nothing is due yet, got %d", len(got))
			}
			clk.add(10 * time.Minute)
			got := r.Ready()
			if len(got) != 1 || got[0].View == nil || len(got[0].Config) != 1 || got[0].ID() != "ev-1" {
				t.Fatalf("want one merged change with its diff, got %+v", got)
			}
			if p := got[0].Config[0].Pointers(); len(p) != 1 || p[0] != "Configuration.IpPermissions.0 (CREATE)" {
				t.Fatal(p)
			}
			if e, c := r.Pending(); e != 0 || c != 0 {
				t.Fatalf("nothing should be left pending: %d %d", e, c)
			}
		})
	}
}

// Without relatedEvents the key is the resource and a time window.
func TestFallbackKeyIsTheResourceInAWindow(t *testing.T) {
	clk := &clock{t0}
	r := newRec(clk)
	evIt, v := ctItem(consoleSG("ev-1", t0), clk.t)
	r.AddCT(evIt, v)
	r.AddConfig(mustItem(sgConfig(t0.Add(2*time.Minute)).envelope(), clk.t))
	// another security group's item, and the same group's item an hour later: neither joins
	other := sgConfig(t0.Add(time.Minute))
	other.resourceID = "sg-0other999"
	r.AddConfig(mustItem(other.envelope(), clk.t))
	r.AddConfig(mustItem(sgConfig(t0.Add(time.Hour)).envelope(), clk.t))
	clk.add(10 * time.Minute)
	got := r.Ready()
	if len(got) != 3 {
		t.Fatalf("want the merged change and the two items nothing explains, got %d", len(got))
	}
	merged := 0
	for _, m := range got {
		if m.View != nil {
			merged++
			if len(m.Config) != 1 || m.Config[0].Captured != t0.Add(2*time.Minute) {
				t.Fatalf("the wrong item joined: %+v", m.Config)
			}
		} else if len(m.Config) != 1 {
			t.Fatal("an item alone is emitted alone")
		}
	}
	if merged != 1 {
		t.Fatal("exactly one change carries an event")
	}
}

// An item that lists related events never joins an event it does not list, however well resource and time fit.
func TestListedRelatedEventsAreStrict(t *testing.T) {
	clk := &clock{t0}
	r := newRec(clk)
	evIt, v := ctItem(consoleSG("ev-1", t0), clk.t)
	r.AddCT(evIt, v)
	r.AddConfig(mustItem(sgConfig(t0.Add(time.Minute), "some-other-event").envelope(), clk.t))
	clk.add(10 * time.Minute)
	got := r.Ready()
	if len(got) != 2 {
		t.Fatalf("event and item stay two changes, got %d", len(got))
	}
	for _, m := range got {
		if m.View != nil && len(m.Config) != 0 {
			t.Fatal("must not join")
		}
		if m.View == nil && m.ID() != "some-other-event" {
			t.Fatalf("the item is reported under the event Config says caused it: %s", m.ID())
		}
	}
}

func TestLateItemIsCountedNotReposted(t *testing.T) {
	clk := &clock{t0}
	r := newRec(clk)
	evIt, v := ctItem(consoleSG("ev-1", t0), clk.t)
	r.AddCT(evIt, v)
	clk.add(6 * time.Minute)
	got := r.Ready()
	if len(got) != 1 {
		t.Fatal(len(got))
	}
	r.Done(got[0])
	acked := false
	late := mustItem(sgConfig(t0.Add(7*time.Minute), "ev-1").envelope(), clk.t)
	late.Acks = []func(){func() { acked = true }}
	r.AddConfig(late)
	clk.add(6 * time.Minute)
	if got := r.Ready(); len(got) != 0 {
		t.Fatalf("a late item is not a second exception: %d", len(got))
	}
	if r.Late() != 1 || !acked {
		t.Fatalf("late %d acked %t", r.Late(), acked)
	}
}

// An SQS redelivery while pending, and after it was posted, is one change; acks run only after Done.
func TestRedeliveryIsOneChangeAndAcksWaitForDone(t *testing.T) {
	clk := &clock{t0}
	r := newRec(clk)
	acks := 0
	mk := func() (*Item, *ctView) {
		it, v := ctItem(consoleSG("ev-1", t0), clk.t)
		it.Acks = []func(){func() { acks++ }}
		return it, v
	}
	it, v := mk()
	r.AddCT(it, v)
	it2, v2 := mk()
	r.AddCT(it2, v2) // the queue redelivered it while it waited
	clk.add(6 * time.Minute)
	got := r.Ready()
	if len(got) != 1 || acks != 0 {
		t.Fatalf("one change, nothing acked before it is posted: %d %d", len(got), acks)
	}
	r.Done(got[0])
	if acks != 2 {
		t.Fatalf("both deliveries are acked once it is posted: %d", acks)
	}
	it3, v3 := mk()
	r.AddCT(it3, v3) // a third copy after it was posted
	if acks != 3 {
		t.Fatal("a copy of a posted event is acked at once")
	}
	clk.add(time.Hour)
	if got := r.Ready(); len(got) != 0 {
		t.Fatal("never emitted twice")
	}
}

func TestFailPutsTheChangeBackWithItsItems(t *testing.T) {
	clk := &clock{t0}
	r := newRec(clk)
	acks := 0
	evIt, v := ctItem(consoleSG("ev-1", t0), clk.t)
	evIt.Acks = []func(){func() { acks++ }}
	cf := mustItem(sgConfig(t0.Add(time.Minute), "ev-1").envelope(), clk.t)
	cf.Acks = []func(){func() { acks++ }}
	r.AddCT(evIt, v)
	r.AddConfig(cf)
	clk.add(6 * time.Minute)
	got := r.Ready()
	if len(got) != 1 {
		t.Fatal(len(got))
	}
	r.Fail(got[0])
	if acks != 0 {
		t.Fatal("a failed post acks nothing")
	}
	got = r.Ready()
	if len(got) != 1 || len(got[0].Config) != 1 {
		t.Fatalf("the change returns whole: %+v", got)
	}
	r.Done(got[0])
	if acks != 2 {
		t.Fatal(acks)
	}
}

// The trail's verified copy of an event: pending with the EventBridge copy it replaces it (the event is posted once,
// with the proof); after the event was posted it is reported as already posted, for a verification record.
func TestAVerifiedCopyUpgradesAPendingEventOrIsReportedAfterItWasPosted(t *testing.T) {
	clk := &clock{t0}
	r := newRec(clk)
	ev := consoleSG("ev-v", t0)
	eb, v := ctItem(ev, clk.t)
	tr, _ := ctItem(ev, clk.t)
	tr.Feed, tr.Verified, tr.Method = FeedTrail, true, MethodDigestChain
	if r.AddCT(eb, v) {
		t.Fatal("the first copy is not a duplicate")
	}
	if r.AddCT(tr, v) {
		t.Fatal("a copy of a pending event is not yet 'already posted'")
	}
	clk.add(10 * time.Minute)
	got := r.Ready()
	if len(got) != 1 || !got[0].Item.Verified || got[0].Item.Feed != FeedTrail {
		t.Fatalf("the pending event takes the verified copy: %+v", got)
	}
	r.Done(got[0])
	late, _ := ctItem(ev, clk.t)
	late.Verified = true
	if !r.AddCT(late, v) {
		t.Fatal("a copy after the event was posted is reported, so the collector can post its verification")
	}
}

func sgDelete(at time.Time, related ...string) cfgItem {
	return cfgItem{resourceID: "sg-0abc1234", name: "web", at: at, related: related, changeType: "UPDATE", changed: map[string]map[string]any{
		"Configuration.IpPermissions.0": {"previousValue": map[string]any{"fromPort": 22, "toPort": 22, "ipRanges": []string{"0.0.0.0/0"}}, "updatedValue": nil, "changeType": "DELETE"}}}
}

func revokeSG(id string, at time.Time) ct {
	c := consoleSG(id, at)
	c.name = "RevokeSecurityGroupIngress"
	return c
}

// The live case: a rule added and removed ten minutes later, Config reporting neither with relatedEvents. Both events
// are still pending when the DELETE item arrives, and it fits the add's window too; it must join only the nearer revoke.
func TestFallbackItemJoinsOnlyTheNearestEvent(t *testing.T) {
	clk := &clock{t0}
	r := &Reconciler{Settle: 15 * time.Minute, Window: 15 * time.Minute, Now: clk.now}
	addIt, addV := ctItem(consoleSG("ev-add", t0), clk.t)
	r.AddCT(addIt, addV)
	clk.add(time.Minute)
	r.AddConfig(mustItem(sgConfig(t0.Add(time.Minute)).envelope(), clk.t))
	clk.add(9 * time.Minute)
	rvIt, rvV := ctItem(revokeSG("ev-revoke", clk.t), clk.t)
	r.AddCT(rvIt, rvV)
	clk.add(time.Minute)
	r.AddConfig(mustItem(sgDelete(t0.Add(11*time.Minute)).envelope(), clk.t))
	var got []*Merged
	for i := 0; i < 25 && len(got) < 2; i++ {
		clk.add(time.Minute)
		got = append(got, r.Ready()...)
	}
	if len(got) != 2 {
		t.Fatalf("want the add and the revoke, got %d", len(got))
	}
	byID := map[string]*Merged{}
	for _, m := range got {
		byID[m.ID()] = m
	}
	add, rv := byID["ev-add"], byID["ev-revoke"]
	if add == nil || rv == nil {
		t.Fatalf("%v", byID)
	}
	if len(add.Config) != 1 || add.Config[0].ChangeType != "UPDATE" || add.Config[0].Changed["Configuration.IpPermissions.0"].ChangeType != "CREATE" {
		t.Fatalf("the add carries only the CREATE item: %+v", add.Config)
	}
	if len(rv.Config) != 1 || rv.Config[0].Changed["Configuration.IpPermissions.0"].ChangeType != "DELETE" {
		t.Fatalf("the revoke carries only the DELETE item: %+v", rv.Config)
	}
	da, dr := configDelta(add.Config), configDelta(rv.Config)
	k := "Configuration.IpPermissions.0"
	if da == nil || dr == nil || da.Before[k] != nil || dr.After[k] != nil || !reflect.DeepEqual(da.After[k], dr.Before[k]) {
		t.Fatalf("the two deltas must be inverse: %+v %+v", da, dr)
	}
	if e, c := r.Pending(); e != 0 || c != 0 {
		t.Fatalf("%d %d", e, c)
	}
}

// A nearer event that arrives after the item, within Grace, still wins; and an item waits for Grace before it joins.
func TestFallbackItemWaitsGraceForANearerEvent(t *testing.T) {
	clk := &clock{t0}
	r := newRec(clk)
	addIt, addV := ctItem(consoleSG("ev-add", t0), clk.t)
	r.AddCT(addIt, addV)
	clk.add(8 * time.Minute)
	r.AddConfig(mustItem(sgDelete(t0.Add(8*time.Minute)).envelope(), clk.t))
	if got := r.Ready(); len(got) != 0 {
		t.Fatalf("nothing due: %d", len(got))
	}
	clk.add(30 * time.Second)
	rvIt, rvV := ctItem(revokeSG("ev-revoke", t0.Add(7*time.Minute)), clk.t)
	r.AddCT(rvIt, rvV)
	clk.add(10 * time.Minute)
	var got []*Merged
	for i := 0; i < 20 && len(got) < 2; i++ {
		clk.add(time.Minute)
		got = append(got, r.Ready()...)
	}
	for _, m := range got {
		switch m.ID() {
		case "ev-add":
			if len(m.Config) != 0 {
				t.Fatal("the add must not take the item")
			}
		case "ev-revoke":
			if len(m.Config) != 1 {
				t.Fatal("the revoke takes the item")
			}
		}
	}
	if len(got) != 2 {
		t.Fatal(len(got))
	}
}

// An item whose nearest event is pending is not counted Late against an earlier event that was emitted already;
// one whose nearest event was emitted is.
func TestNearestRuleDecidesLate(t *testing.T) {
	clk := &clock{t0}
	r := newRec(clk)
	addIt, addV := ctItem(consoleSG("ev-add", t0), clk.t)
	r.AddCT(addIt, addV)
	clk.add(6 * time.Minute)
	for _, m := range r.Ready() {
		r.Done(m)
	}
	rvIt, rvV := ctItem(revokeSG("ev-revoke", clk.t), clk.t)
	r.AddCT(rvIt, rvV)
	r.AddConfig(mustItem(sgDelete(t0.Add(7*time.Minute)).envelope(), clk.t))
	clk.add(3 * time.Minute)
	if got := r.Ready(); len(got) != 0 || r.Late() != 0 {
		t.Fatalf("joined to the pending revoke, not late: %d %d", len(got), r.Late())
	}
	clk.add(5 * time.Minute)
	got := r.Ready()
	if len(got) != 1 || got[0].ID() != "ev-revoke" || len(got[0].Config) != 1 || r.Late() != 0 {
		t.Fatalf("%+v late %d", got, r.Late())
	}
	r.Done(got[0])
	// an item nearest to an emitted event is late
	r.AddConfig(mustItem(sgDelete(t0.Add(20*time.Minute)).envelope(), clk.t))
	clk.add(3 * time.Minute)
	if len(r.Ready()) != 0 || r.Late() != 1 {
		t.Fatalf("late %d", r.Late())
	}
}

// Items that list relatedEvents join every event they list, however near another event is.
func TestListedRelatedEventsJoinEachListedEvent(t *testing.T) {
	clk := &clock{t0}
	r := newRec(clk)
	a, av := ctItem(consoleSG("ev-a", t0), clk.t)
	b, bv := ctItem(revokeSG("ev-b", t0.Add(3*time.Minute)), clk.t)
	c, cv := ctItem(revokeSG("ev-c", t0.Add(4*time.Minute)), clk.t)
	r.AddCT(a, av)
	r.AddCT(b, bv)
	r.AddCT(c, cv)
	r.AddConfig(mustItem(sgConfig(t0.Add(5*time.Minute), "ev-a", "ev-b").envelope(), clk.t))
	clk.add(10 * time.Minute)
	n := map[string]int{}
	for _, m := range r.Ready() {
		n[m.ID()] = len(m.Config)
	}
	if n["ev-a"] != 1 || n["ev-b"] != 1 || n["ev-c"] != 0 || len(n) != 3 {
		t.Fatalf("%v", n)
	}
}

// One event carrying several items on one pointer gets the net diff, whatever order the items arrived or are held in.
func TestNetDiffOrdersItemsByCapturedAndKeepsEarliestPreviousLatestUpdated(t *testing.T) {
	k := "Configuration.IpPermissions.0"
	mk := func(id string, at time.Time, prev, upd any) *ConfigChange {
		return &ConfigChange{ID: id, Captured: at, Changed: map[string]PropChange{k: {Previous: prev, Updated: upd}}}
	}
	first, second := mk("a", t0, nil, "r1"), mk("b", t0.Add(time.Minute), "r1", "r2")
	for _, cfgs := range [][]*ConfigChange{{first, second}, {second, first}} {
		d := configDelta(cfgs)
		if d == nil || d.Before[k] != nil || d.After[k] != "r2" {
			t.Fatalf("%+v", d)
		}
		sc := stateChange(cfgs)
		if sc["before"].(map[string]any)[k] != nil || sc["after"].(map[string]any)[k] != "r2" {
			t.Fatalf("%+v", sc)
		}
	}
	// changed and changed back: the pointer is kept, before == after, in both views
	back := mk("c", t0.Add(2*time.Minute), "r2", nil)
	d := configDelta([]*ConfigChange{back, first, second})
	sc := stateChange([]*ConfigChange{back, first, second})
	b, a := sc["before"].(map[string]any), sc["after"].(map[string]any)
	if d == nil || len(d.Before) != 1 || len(b) != 1 || len(a) != 1 || b[k] != nil || a[k] != nil {
		t.Fatalf("%+v %+v", d, sc)
	}
}
