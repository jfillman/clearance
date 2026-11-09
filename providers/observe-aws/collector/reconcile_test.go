package collector

import (
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
