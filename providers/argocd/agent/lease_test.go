package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// memLeases is an API server's view of Leases: optimistic concurrency on resourceVersion.
type memLeases struct {
	mu   sync.Mutex
	l    *Lease
	rv   int
	fail atomic.Bool // every call fails (the API server is unreachable)
}

func (m *memLeases) GetLease(_ context.Context, ns, name string) (Lease, error) {
	if m.fail.Load() {
		return Lease{}, errors.New("unreachable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.l == nil {
		return Lease{}, ErrNotFound
	}
	return *m.l, nil
}

func (m *memLeases) CreateLease(_ context.Context, l Lease) error {
	if m.fail.Load() {
		return errors.New("unreachable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.l != nil {
		return ErrConflict
	}
	m.rv++
	l.ResourceVersion = fmt.Sprint(m.rv)
	m.l = &l
	return nil
}

func (m *memLeases) UpdateLease(_ context.Context, l Lease) error {
	if m.fail.Load() {
		return errors.New("unreachable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.l == nil || m.l.ResourceVersion != l.ResourceVersion {
		return ErrConflict
	}
	m.rv++
	l.ResourceVersion = fmt.Sprint(m.rv)
	m.l = &l
	return nil
}

func (m *memLeases) holder() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.l == nil {
		return ""
	}
	return m.l.Holder
}

func TestTheLeaseGoesToOneCandidateAndPassesOnlyAfterItsDuration(t *testing.T) {
	store := &memLeases{}
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return at }
	a := &Elector{Store: store, Namespace: "ns", Name: "agent", Identity: "pod-a", Now: clock}
	b := &Elector{Store: store, Namespace: "ns", Name: "agent", Identity: "pod-b", Now: clock}
	for _, e := range []*Elector{a, b} {
		if err := e.defaults(); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	if ok, err := a.tryAcquireOrRenew(ctx); !ok || err != nil {
		t.Fatalf("the first candidate creates the lease: %v %v", ok, err)
	}
	if ok, _ := b.tryAcquireOrRenew(ctx); ok {
		t.Fatal("the second candidate must not take a held lease")
	}
	at = at.Add(10 * time.Second)
	if ok, _ := a.tryAcquireOrRenew(ctx); !ok {
		t.Fatal("the holder renews")
	}
	at = at.Add(10 * time.Second)
	if ok, _ := b.tryAcquireOrRenew(ctx); ok {
		t.Fatal("renewed 10 s ago: still held (b judges by when it saw the renewal, not by the holder's clock)")
	}
	// a stops renewing. b saw the last renewal at the previous attempt; 15 s after that it takes over.
	at = at.Add(14 * time.Second)
	if ok, _ := b.tryAcquireOrRenew(ctx); ok {
		t.Fatal("taken before the lease's duration passed on b's clock")
	}
	at = at.Add(2 * time.Second)
	if ok, err := b.tryAcquireOrRenew(ctx); !ok || err != nil {
		t.Fatalf("after the duration b takes the lease: %v %v", ok, err)
	}
	if store.holder() != "pod-b" || store.l.Transitions != 1 {
		t.Fatalf("holder %q, transitions %d", store.holder(), store.l.Transitions)
	}
	if ok, _ := a.tryAcquireOrRenew(ctx); ok {
		t.Fatal("the old holder must not take it back while b renews")
	}
}

func TestAReleasedLeaseIsTakenAtOnce(t *testing.T) {
	store := &memLeases{}
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	a := &Elector{Store: store, Namespace: "ns", Name: "agent", Identity: "pod-a", Now: func() time.Time { return at }}
	b := &Elector{Store: store, Namespace: "ns", Name: "agent", Identity: "pod-b", Now: func() time.Time { return at }}
	_ = a.defaults()
	_ = b.defaults()
	if ok, _ := a.tryAcquireOrRenew(context.Background()); !ok {
		t.Fatal("a takes the lease")
	}
	a.release(context.Background())
	if ok, _ := b.tryAcquireOrRenew(context.Background()); !ok {
		t.Fatal("a released lease (no holder) is taken without waiting")
	}
}

func TestRunStopsTheWorkWhenTheLeaseCannotBeRenewed(t *testing.T) {
	store := &memLeases{}
	e := &Elector{Store: store, Namespace: "ns", Name: "agent", Identity: "pod-a",
		Duration: 300 * time.Millisecond, RenewDeadline: 150 * time.Millisecond, RetryPeriod: 20 * time.Millisecond, Log: quiet}
	started, stopped := make(chan struct{}), make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		errc <- e.Run(context.Background(), func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(stopped)
			return ctx.Err()
		})
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the work never started")
	}
	store.fail.Store(true)
	select {
	case err := <-errc:
		if !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("Run returned %v, want ErrLeaseLost", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept running with a lease it could not renew")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("the work's context was not cancelled before Run returned")
	}
}

func TestRunWaitsAsACandidateAndReleasesOnShutdown(t *testing.T) {
	store := &memLeases{}
	opts := func(id string) *Elector {
		return &Elector{Store: store, Namespace: "ns", Name: "agent", Identity: id,
			Duration: 2 * time.Second, RenewDeadline: time.Second, RetryPeriod: 20 * time.Millisecond, Log: quiet}
	}
	var running atomic.Int32
	work := func(ctx context.Context) error {
		if running.Add(1) != 1 {
			t.Error("two replicas ran the loops at once")
		}
		<-ctx.Done()
		running.Add(-1)
		return ctx.Err()
	}
	ctxA, stopA := context.WithCancel(context.Background())
	doneA := make(chan error, 1)
	go func() { doneA <- opts("pod-a").Run(ctxA, work) }()
	for store.holder() != "pod-a" {
		time.Sleep(5 * time.Millisecond)
	}
	ctxB, stopB := context.WithCancel(context.Background())
	defer stopB()
	doneB := make(chan error, 1)
	go func() { doneB <- opts("pod-b").Run(ctxB, work) }()
	time.Sleep(200 * time.Millisecond)
	if store.holder() != "pod-a" || running.Load() != 1 {
		t.Fatalf("b must wait: holder %q, running %d", store.holder(), running.Load())
	}
	stopA() // a shuts down and releases: b takes over well before the 2 s duration
	if err := <-doneA; !errors.Is(err, context.Canceled) {
		t.Fatalf("a returned %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for store.holder() != "pod-b" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if store.holder() != "pod-b" {
		t.Fatalf("b did not take the released lease within a second: holder %q", store.holder())
	}
	stopB()
	<-doneB
}

func TestTheElectorRefusesAnUnsafeConfiguration(t *testing.T) {
	for name, e := range map[string]Elector{
		"no identity":                {Store: &memLeases{}, Namespace: "n", Name: "l"},
		"renew deadline >= duration": {Store: &memLeases{}, Namespace: "n", Name: "l", Identity: "p", Duration: time.Second, RenewDeadline: time.Second},
		"retry >= renew deadline":    {Store: &memLeases{}, Namespace: "n", Name: "l", Identity: "p", RenewDeadline: time.Second, RetryPeriod: time.Second},
	} {
		if err := e.defaults(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTheLeaseWireRoundTrips(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 123456000, time.UTC)
	l := Lease{Namespace: "ns", Name: "agent", ResourceVersion: "7", Holder: "pod-a", DurationSeconds: 15, AcquireTime: at, RenewTime: at, Transitions: 2}
	w := leaseToWire(l)
	if w.Spec.RenewTime != "2026-11-20T12:00:00.123456Z" || w.APIVersion != "coordination.k8s.io/v1" || w.Kind != "Lease" {
		t.Fatalf("wire: %+v", w)
	}
	if back := leaseFromWire(w); back != l {
		t.Fatalf("round trip: %+v, want %+v", back, l)
	}
	empty := leaseToWire(Lease{Namespace: "ns", Name: "agent"})
	if empty.Spec.HolderIdentity == nil || *empty.Spec.HolderIdentity != "" {
		t.Fatal("a released lease sends an empty holder, not none")
	}
}
