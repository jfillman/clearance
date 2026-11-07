package attest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
)

// Retry policy for a signing that failed (Fulcio or Rekor down, the token file missing): the item stays pending,
// retried with a doubling delay, and is dropped after MaxAttempts (the core's next start finds it again: Catchup).
const (
	MaxAttempts   = 12
	baseDelay     = 5 * time.Second
	maxDelay      = 5 * time.Minute
	tick          = 2 * time.Second
	CatchupWindow = 2000 // records from the chain's head Catchup looks back over
)

// Attestor signs change attestations after the deploy outcomes arrive. It runs in the core: Notify queues a change
// (from the outcome's write path, after its commit), Run signs the queue off the request path, so a slow Fulcio or
// Rekor never holds a provider's POST. Signing is at most once per change: the first attestation stands.
type Attestor struct {
	Backend Backend
	Store   store.Store
	Gate    *gate.Service
	Issuer  string // the token issuer the predicate's clearance block was decided under (gate.Tokens.Issuer)
	Clock   func() time.Time
	Log     *slog.Logger

	mu      sync.Mutex
	pending map[string]*item
	// signed holds a bundle already signed and logged whose storing failed, by change id: the retry stores it
	// instead of signing and logging again (one Rekor entry, not one per retry). It is in memory only: a restart
	// between the log and the store costs one extra Rekor entry.
	signed map[string]heldAttestation
	wake   chan struct{}
}

type heldAttestation struct {
	seq int64
	att store.Attestation
}

type item struct {
	seqs     []int64 // every deploy.outcome seen for the change; the first that is attestable is attested
	attempts int
	next     time.Time
}

func (a *Attestor) now() time.Time {
	if a.Clock != nil {
		return a.Clock()
	}
	return time.Now()
}

func (a *Attestor) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

// Notify queues change id, whose deploy.outcome is record seq. It never blocks and never fails.
func (a *Attestor) Notify(id string, seq int64) {
	a.mu.Lock()
	if a.pending == nil {
		a.pending = map[string]*item{}
		a.wake = make(chan struct{}, 1)
	}
	it := a.pending[id]
	if it == nil {
		it = &item{}
		a.pending[id] = it
	}
	// Every outcome of the change stays queued until it has been checked (an applied one must never be dropped for
	// the count of earlier ones); Drain drops the ones it has found not attestable.
	if !slices.Contains(it.seqs, seq) {
		it.seqs = append(it.seqs, seq)
	}
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// NotifyRecord queues the change a deploy.outcome record names (the generic records route's hook).
func (a *Attestor) NotifyRecord(rec store.Record) {
	if tool, _ := rec["tool"].(string); tool != "deploy.outcome" {
		return
	}
	id := mapStr(rec, "change", "id")
	seq, ok := gate.SeqInt(rec["seq"])
	if id == "" || !ok {
		return
	}
	a.Notify(id, seq)
}

// Catchup queues the deploy.outcome records of the chain's last CatchupWindow records, so an outcome that arrived
// while the core was down, or whose signing was dropped, is attested once the core is up. Process skips a change
// that already has an attestation.
func (a *Attestor) Catchup(ctx context.Context) error {
	head, _, err := a.Store.Head(ctx)
	if err != nil {
		return err
	}
	from := max(head-CatchupWindow+1, 0)
	for from <= head {
		recs, err := a.Store.Records(ctx, from, 500)
		if err != nil {
			return err
		}
		if len(recs) == 0 {
			break
		}
		for _, r := range recs {
			a.NotifyRecord(r)
		}
		from += int64(len(recs))
	}
	return nil
}

// Run signs the queue until ctx ends.
func (a *Attestor) Run(ctx context.Context) {
	a.mu.Lock()
	if a.pending == nil {
		a.pending = map[string]*item{}
		a.wake = make(chan struct{}, 1)
	}
	wake := a.wake
	a.mu.Unlock()
	if err := a.Catchup(ctx); err != nil && ctx.Err() == nil {
		a.log().ErrorContext(ctx, "attest: catching up on outcomes failed", "error", err.Error())
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		a.Drain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-t.C:
		}
	}
}

// Drain processes every queued change that is due, once.
func (a *Attestor) Drain(ctx context.Context) {
	a.mu.Lock()
	var due []string
	now := a.now()
	for id, it := range a.pending {
		if !it.next.After(now) {
			due = append(due, id)
		}
	}
	a.mu.Unlock()
	for _, id := range due {
		if ctx.Err() != nil {
			return
		}
		a.mu.Lock()
		it := a.pending[id]
		seqs := slices.Clone(it.seqs)
		a.mu.Unlock()
		err := a.processAny(ctx, id, seqs)
		a.mu.Lock()
		switch {
		case err == nil:
			delete(a.pending, id)
		case errors.Is(err, ErrNoAttestation):
			// An outcome Notify added while this one was processed is not covered by this verdict: leave it queued.
			if len(it.seqs) == len(seqs) {
				delete(a.pending, id)
				a.log().DebugContext(ctx, "attest: no attestation", "change", id, "reason", err.Error())
			} else { // forget the outcomes just checked; the newer ones stay
				it.seqs = slices.DeleteFunc(it.seqs, func(n int64) bool { return slices.Contains(seqs, n) })
			}
		default:
			it.attempts++
			if it.attempts >= MaxAttempts {
				delete(a.pending, id)
				delete(a.signed, id)
				a.log().ErrorContext(ctx, "attest: giving up until the next start", "change", id, "error", err.Error())
			} else {
				it.next = a.now().Add(min(baseDelay<<(it.attempts-1), maxDelay))
				a.log().WarnContext(ctx, "attest: signing failed, will retry", "change", id, "attempt", it.attempts, "error", err.Error())
			}
		}
		a.mu.Unlock()
	}
}

// processAny tries each outcome seq in turn: the first one that is attestable is attested. ErrNoAttestation only when
// none is.
func (a *Attestor) processAny(ctx context.Context, id string, seqs []int64) error {
	var last error = ErrNoAttestation
	for _, seq := range seqs {
		err := a.Process(ctx, id, seq)
		if err == nil || !errors.Is(err, ErrNoAttestation) {
			return err
		}
		last = err
	}
	return last
}

// Process attests change id's deploy.outcome record seq: build the statement, sign and log it, then store the bundle
// and append deploy.attestation. nil when the change now has an attestation (it did, or this call made it); an error
// wrapping ErrNoAttestation when it gets none.
func (a *Attestor) Process(ctx context.Context, id string, seq int64) error {
	if _, err := a.Store.Attestation(ctx, id); err == nil {
		a.mu.Lock()
		delete(a.signed, id)
		a.mu.Unlock()
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	row, err := a.Store.Change(ctx, id)
	if err != nil {
		return fmt.Errorf("attest: the change: %w", err)
	}
	c, err := gate.FromRecord(row.Record)
	if err != nil {
		return err
	}
	recs, err := a.Store.Records(ctx, seq, 1)
	if err != nil || len(recs) != 1 {
		return fmt.Errorf("attest: the outcome record %d: %v", seq, err)
	}
	st, err := BuildStatement(c, recs[0], a.Issuer)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return err
	}
	a.mu.Lock()
	held, ok := a.signed[id]
	a.mu.Unlock()
	if !ok || held.seq != seq {
		signed, err := a.Backend.Sign(ctx, payload)
		if err != nil {
			return err
		}
		bundle, err := json.Marshal(signed.Bundle)
		if err != nil {
			return err
		}
		held = heldAttestation{seq: seq, att: store.Attestation{ChangeID: id, Digest: EnvelopeDigest(signed.Bundle.DSSEEnvelope),
			Backend: signed.Backend, KeyID: signed.KeyID, RekorLogIndex: signed.RekorLogIndex, RekorUUID: signed.RekorUUID,
			OutcomeSeq: seq, Bundle: bundle}}
		a.mu.Lock()
		if a.signed == nil {
			a.signed = map[string]heldAttestation{}
		}
		a.signed[id] = held
		a.mu.Unlock()
	}
	if _, err := a.Gate.RecordAttestation(ctx, held.att); err != nil {
		return err // the signed bundle is kept: the retry stores it
	}
	a.mu.Lock()
	delete(a.signed, id)
	a.mu.Unlock()
	return nil
}
