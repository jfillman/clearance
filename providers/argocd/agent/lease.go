package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Leader election for an agent run with more than one replica (I-44, option 0). Only the holder of one
// coordination.k8s.io Lease runs the loops; the other replicas wait, and take over once the holder has not renewed
// for the lease's duration. It is client-go's algorithm, without client-go: the expiry of another holder's lease is
// judged on this replica's own clock, from when it last saw the record change, never by comparing its clock with the
// holder's renewTime. A holder that cannot renew within RenewDeadline stops its loops and Run returns ErrLeaseLost:
// the process exits and the kubelet restarts it as a candidate.

// ErrLeaseLost: the elector could not renew its lease in time and stopped the work.
var ErrLeaseLost = errors.New("agent: the leader lease was lost")

// Lease is the part of a coordination.k8s.io/v1 Lease the elector reads and writes.
type Lease struct {
	Namespace, Name string
	ResourceVersion string
	Holder          string
	DurationSeconds int
	AcquireTime     time.Time
	RenewTime       time.Time
	Transitions     int
}

// LeaseStore reads and writes one Lease. Create fails with ErrConflict when the Lease exists, Update with ErrConflict
// when ResourceVersion is not the stored one; Get fails with ErrNotFound when there is none.
type LeaseStore interface {
	GetLease(ctx context.Context, namespace, name string) (Lease, error)
	CreateLease(ctx context.Context, l Lease) error
	UpdateLease(ctx context.Context, l Lease) error
}

// Elector runs work while it holds the lease.
type Elector struct {
	Store           LeaseStore
	Namespace, Name string
	Identity        string        // this replica (the pod's name)
	Duration        time.Duration // how long a lease holds without a renewal (default 15 s)
	RenewDeadline   time.Duration // how long a holder keeps trying to renew before it stops (default 10 s)
	RetryPeriod     time.Duration // how often candidates try and the holder renews (default 2 s)
	Now             func() time.Time
	Log             *slog.Logger

	observed   Lease
	observedAt time.Time

	mu        sync.Mutex
	holding   bool
	renewedAt time.Time // when the last successful take or renewal was STARTED (before its GET)
}

// fenceMargin is how long before the earliest takeover the fence closes: one retry period (the attempt timeout).
func (e *Elector) fenceMargin() time.Duration { return e.RetryPeriod }

// Fence is the write fence (CodeRabbit on clearance#210): a write may go out only while this replica holds the lease
// with time to spare. Another replica can take the lease no earlier than Duration after it saw this replica's last
// renewal, and it saw it no earlier than the renewal started, so every write is given a deadline of renewedAt +
// Duration - margin and refused once that has passed (a process that stalled past its lease and resumed). The deadline
// also cancels a write still in flight. It returns ErrLeaseLost when the lease is not (or no longer surely) held.
func (e *Elector) Fence(ctx context.Context) (context.Context, context.CancelFunc, error) {
	e.mu.Lock()
	holding, renewed := e.holding, e.renewedAt
	e.mu.Unlock()
	until := renewed.Add(e.Duration - e.fenceMargin())
	if !holding || !e.Now().Before(until) {
		return nil, nil, ErrLeaseLost
	}
	fctx, cancel := context.WithDeadline(ctx, until)
	return fctx, cancel, nil
}

func (e *Elector) setHeld(held bool, at time.Time) {
	e.mu.Lock()
	e.holding = held
	if held {
		e.renewedAt = at
	}
	e.mu.Unlock()
}

func (e *Elector) defaults() error {
	if e.Duration <= 0 {
		e.Duration = 15 * time.Second
	}
	if e.RenewDeadline <= 0 {
		e.RenewDeadline = 10 * time.Second
	}
	if e.RetryPeriod <= 0 {
		e.RetryPeriod = 2 * time.Second
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Log == nil {
		e.Log = slog.Default()
	}
	switch {
	case e.Store == nil || e.Namespace == "" || e.Name == "" || e.Identity == "":
		return errors.New("agent: leader election needs a store, the lease's namespace and name, and an identity")
	case e.Duration%time.Second != 0:
		// The Lease stores whole seconds (leaseDurationSeconds), and other replicas judge a takeover by that number: a
		// fractional duration would leave this replica's fence open past the stored lease's end.
		return errors.New("agent: the lease's duration must be a whole number of seconds")
	case e.RenewDeadline >= e.Duration:
		return errors.New("agent: the lease's renew deadline must be shorter than its duration")
	case e.RetryPeriod >= e.RenewDeadline:
		return errors.New("agent: the lease's retry period must be shorter than its renew deadline")
	case e.Duration < e.RenewDeadline+2*e.RetryPeriod:
		// The holder stops its work at most RenewDeadline plus one attempt (RetryPeriod) after its last renewal began,
		// and the write fence closes RetryPeriod before the earliest takeover: both must fit inside Duration.
		return errors.New("agent: the lease's duration must be at least its renew deadline plus two retry periods")
	}
	return nil
}

// tryAcquireOrRenew takes or renews the lease once; true when this replica holds it afterwards.
func (e *Elector) tryAcquireOrRenew(ctx context.Context) (bool, error) {
	now := e.Now()
	cur, err := e.Store.GetLease(ctx, e.Namespace, e.Name)
	if errors.Is(err, ErrNotFound) {
		l := Lease{Namespace: e.Namespace, Name: e.Name, Holder: e.Identity, DurationSeconds: int(e.Duration / time.Second),
			AcquireTime: now, RenewTime: now}
		if err := e.Store.CreateLease(ctx, l); err != nil {
			return false, err
		}
		e.observed, e.observedAt = l, e.Now()
		return true, nil
	}
	if err != nil {
		return false, err
	}
	// The observation time is sampled AFTER the GET returns: a GET that was slow (or a pause before it) must not
	// back-date when this replica saw the holder's renewal, or it would take a lease the holder still renews and both
	// would write. now (sampled before) stays the holder's own conservative start, which the write fence uses.
	seen := e.Now()
	if cur.Holder != e.observed.Holder || !cur.RenewTime.Equal(e.observed.RenewTime) || cur.ResourceVersion != e.observed.ResourceVersion {
		e.observed, e.observedAt = cur, seen
	}
	held := cur.Holder == e.Identity
	dur := time.Duration(cur.DurationSeconds) * time.Second
	if dur <= 0 {
		dur = e.Duration
	}
	if !held && cur.Holder != "" && seen.Before(e.observedAt.Add(dur)) {
		return false, nil // another replica holds it and has renewed within its duration, as this replica saw it
	}
	next := cur
	next.Holder, next.RenewTime, next.DurationSeconds = e.Identity, now, int(e.Duration/time.Second)
	if !held {
		next.AcquireTime = now
		next.Transitions++
	}
	if err := e.Store.UpdateLease(ctx, next); err != nil {
		return false, err
	}
	e.observed, e.observedAt = next, e.Now()
	return true, nil
}

// release gives the lease up (holder emptied) so another replica need not wait out its duration.
func (e *Elector) release(ctx context.Context) {
	cur, err := e.Store.GetLease(ctx, e.Namespace, e.Name)
	if err != nil || cur.Holder != e.Identity {
		return
	}
	cur.Holder, cur.DurationSeconds, cur.RenewTime = "", 1, e.Now()
	if err := e.Store.UpdateLease(ctx, cur); err != nil {
		e.Log.Warn("releasing the leader lease failed", "err", err)
	}
}

// Run waits until it holds the lease, then runs work with a context that ends when the lease is lost or ctx ends.
// It returns work's error when work returns by itself, ErrLeaseLost when the lease could not be renewed, and
// ctx.Err() when ctx ended (the lease is then released).
func (e *Elector) Run(ctx context.Context, work func(context.Context) error) error {
	if err := e.defaults(); err != nil {
		return err
	}
	defer e.setHeld(false, time.Time{})
	for {
		start := e.Now()
		ok, err := e.tryAcquireOrRenew(ctx)
		if ok {
			e.setHeld(true, start)
		}
		if err != nil && ctx.Err() == nil {
			e.Log.Info("leader lease not taken", "lease", e.Namespace+"/"+e.Name, "err", err)
		}
		if ok {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(e.RetryPeriod):
		}
	}
	e.Log.Info("leader lease taken: running", "lease", e.Namespace+"/"+e.Name, "identity", e.Identity)
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- work(wctx) }()
	e.mu.Lock()
	lastRenew := e.renewedAt
	e.mu.Unlock()
	tick := time.NewTicker(e.RetryPeriod)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			e.setHeld(false, time.Time{})
			rctx, rc := context.WithTimeout(context.Background(), e.RetryPeriod)
			e.release(rctx)
			rc()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		case <-tick.C:
			rctx, rc := context.WithTimeout(ctx, e.RetryPeriod)
			start := e.Now()
			ok, err := e.tryAcquireOrRenew(rctx)
			rc()
			if ok {
				lastRenew = start
				e.setHeld(true, start)
				continue
			}
			if e.Now().Sub(lastRenew) < e.RenewDeadline && ctx.Err() == nil {
				e.Log.Warn("leader lease not renewed: retrying", "err", err)
				continue
			}
			if ctx.Err() != nil {
				continue // shutting down: the done branch releases the lease
			}
			e.Log.Error("leader lease lost: stopping", "lease", e.Namespace+"/"+e.Name, "err", err)
			e.setHeld(false, time.Time{})
			cancel()
			<-done
			return ErrLeaseLost
		}
	}
}

// The REST side: coordination.k8s.io/v1 Leases through the agent's API.

type leaseWire struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion,omitempty"`
	} `json:"metadata"`
	Spec struct {
		HolderIdentity       *string `json:"holderIdentity,omitempty"`
		LeaseDurationSeconds int     `json:"leaseDurationSeconds,omitempty"`
		AcquireTime          string  `json:"acquireTime,omitempty"`
		RenewTime            string  `json:"renewTime,omitempty"`
		LeaseTransitions     int     `json:"leaseTransitions,omitempty"`
	} `json:"spec"`
}

// microTime is metav1.MicroTime's wire format.
const microTime = "2006-01-02T15:04:05.000000Z07:00"

func (a *API) leasePath(ns, name string) string {
	p := "/apis/coordination.k8s.io/v1/namespaces/" + url.PathEscape(ns) + "/leases"
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p
}

func leaseToWire(l Lease) leaseWire {
	var w leaseWire
	w.APIVersion, w.Kind = "coordination.k8s.io/v1", "Lease"
	w.Metadata.Name, w.Metadata.Namespace, w.Metadata.ResourceVersion = l.Name, l.Namespace, l.ResourceVersion
	h := l.Holder
	w.Spec.HolderIdentity = &h
	w.Spec.LeaseDurationSeconds = l.DurationSeconds
	if !l.AcquireTime.IsZero() {
		w.Spec.AcquireTime = l.AcquireTime.UTC().Format(microTime)
	}
	if !l.RenewTime.IsZero() {
		w.Spec.RenewTime = l.RenewTime.UTC().Format(microTime)
	}
	w.Spec.LeaseTransitions = l.Transitions
	return w
}

func leaseFromWire(w leaseWire) Lease {
	l := Lease{Namespace: w.Metadata.Namespace, Name: w.Metadata.Name, ResourceVersion: w.Metadata.ResourceVersion,
		DurationSeconds: w.Spec.LeaseDurationSeconds, Transitions: w.Spec.LeaseTransitions}
	if w.Spec.HolderIdentity != nil {
		l.Holder = *w.Spec.HolderIdentity
	}
	l.AcquireTime, _ = time.Parse(time.RFC3339Nano, w.Spec.AcquireTime)
	l.RenewTime, _ = time.Parse(time.RFC3339Nano, w.Spec.RenewTime)
	return l
}

func leaseErr(err error) error {
	var se *StatusError
	if errors.As(err, &se) {
		switch se.Code {
		case http.StatusNotFound:
			return ErrNotFound
		case http.StatusConflict:
			return fmt.Errorf("%w: %s", ErrConflict, se.Body)
		}
	}
	return err
}

// GetLease implements LeaseStore.
func (a *API) GetLease(ctx context.Context, ns, name string) (Lease, error) {
	var w leaseWire
	if err := a.call(ctx, "GET", a.leasePath(ns, name), "", nil, &w); err != nil {
		return Lease{}, leaseErr(err)
	}
	return leaseFromWire(w), nil
}

// CreateLease implements LeaseStore.
func (a *API) CreateLease(ctx context.Context, l Lease) error {
	w := leaseToWire(l)
	w.Metadata.ResourceVersion = ""
	return leaseErr(a.call(ctx, "POST", a.leasePath(l.Namespace, ""), "application/json", w, nil))
}

// UpdateLease implements LeaseStore: a PUT guarded by the resourceVersion it was read at.
func (a *API) UpdateLease(ctx context.Context, l Lease) error {
	return leaseErr(a.call(ctx, "PUT", a.leasePath(l.Namespace, l.Name), "application/json", leaseToWire(l), nil))
}

// Fencer is what Fenced asks before each write (an Elector).
type Fencer interface {
	Fence(ctx context.Context) (context.Context, context.CancelFunc, error)
}

// Fenced is k with every write the agent makes to the cluster behind f's fence: the grant writes (create, update,
// status, delete), the state ConfigMap, the opt-in's Application and namespace writes. Reads pass through. A write
// refused by the fence fails with ErrLeaseLost and the loop reports it; the elector stops the loops soon after.
func Fenced(k Kube, f Fencer) Kube { return fencedKube{k, f} }

type fencedKube struct {
	Kube
	f Fencer
}

func (k fencedKube) fenced(ctx context.Context, w func(context.Context) error) error {
	fctx, cancel, err := k.f.Fence(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	return w(fctx)
}

func (k fencedKube) CreateGrant(ctx context.Context, g Grant) error {
	return k.fenced(ctx, func(c context.Context) error { return k.Kube.CreateGrant(c, g) })
}

func (k fencedKube) UpdateGrant(ctx context.Context, g, cur Grant) error {
	return k.fenced(ctx, func(c context.Context) error { return k.Kube.UpdateGrant(c, g, cur) })
}

func (k fencedKube) SetGrantValid(ctx context.Context, ns, name string, valid bool, reason string, at time.Time) error {
	return k.fenced(ctx, func(c context.Context) error { return k.Kube.SetGrantValid(c, ns, name, valid, reason, at) })
}

func (k fencedKube) DeleteGrant(ctx context.Context, ns, name string) error {
	return k.fenced(ctx, func(c context.Context) error { return k.Kube.DeleteGrant(c, ns, name) })
}

func (k fencedKube) UpdateApplicationSource(ctx context.Context, app Application, e SourceEdit) error {
	return k.fenced(ctx, func(c context.Context) error { return k.Kube.UpdateApplicationSource(c, app, e) })
}

func (k fencedKube) SetNamespaceProtected(ctx context.Context, ns string, protected bool) error {
	return k.fenced(ctx, func(c context.Context) error { return k.Kube.SetNamespaceProtected(c, ns, protected) })
}

func (k fencedKube) PutData(ctx context.Context, ns, name string, data map[string]string) error {
	return k.fenced(ctx, func(c context.Context) error { return k.Kube.PutData(c, ns, name, data) })
}
