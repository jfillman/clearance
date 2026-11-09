package ledger

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/store"
)

// The ledger's states, in Status.State.
const (
	// StateCurrent: every chain record is under a witnessed checkpoint.
	StateCurrent = "current"
	// StateCheckpointing: records are waiting for the next checkpoint, within the time one takes.
	StateCheckpointing = "checkpointing"
	// StateWitnessUnavailable: every witness failed to answer its last request (down, timing out, 5xx).
	StateWitnessUnavailable = "witness-unavailable"
	// StateWitnessRejected: a witness refused a checkpoint (a log that was truncated, rewritten or forked, or a key it
	// does not trust). Nothing is published until it accepts one.
	StateWitnessRejected = "witness-rejected"
	// StateStalled: records have waited longer than StallAfter for a witnessed checkpoint, whatever the cause.
	StateStalled = "stalled"
)

// Config is the service's configuration.
type Config struct {
	Log LogConfig
	// Tier3Wait is the outage knob: while evidence cannot be checkpointed, a tier 3 change waits (Hold). The
	// zero value is off; the core's environment turns it on by default.
	Tier3Wait bool
	// StallAfter is how long records may wait for a witnessed checkpoint before the ledger counts as stalled
	// (default: three checkpoint intervals and one witness timeout).
	StallAfter time.Duration
	// PollEvery is how often new chain records are added and new checkpoints looked for (default 1s).
	PollEvery time.Duration
}

// WitnessStatus is the last thing a witness did.
type WitnessStatus struct {
	URL    string `json:"url"`
	State  string `json:"state"` // ok | unavailable | rejected | unknown
	Detail string `json:"detail,omitempty"`
	At     string `json:"at,omitempty"`
}

// Status is the ledger as the core reports it (GET /readyz, "ledger").
type Status struct {
	Enabled bool   `json:"enabled"`
	Origin  string `json:"origin,omitempty"`
	State   string `json:"state,omitempty"`
	Detail  string `json:"detail,omitempty"`
	// Chain is the number of chain records, Ledger how many of them the log holds, Witnessed how many are under a
	// witnessed checkpoint (assurance checkpointed).
	Chain     int64 `json:"chain"`
	Ledger    int64 `json:"ledger"`
	Witnessed int64 `json:"witnessed"`
	// Tier3Wait is the outage knob; Holding is whether a tier 3 change would wait right now.
	Tier3Wait bool            `json:"tier3_wait"`
	Holding   bool            `json:"holding"`
	Witnesses []WitnessStatus `json:"witnesses,omitempty"`
}

// Service runs the ledger beside the chain: it adds each new record's hash to the log, records the checkpoints the
// witnesses countersigned, and says whether evidence can be checkpointed.
type Service struct {
	cfg   Config
	chain Chain
	st    store.Ledger
	clock func() time.Time
	log   *slog.Logger
	lg    *Log

	mu        sync.Mutex
	chainN    int64
	ledgerN   int64
	witnessed int64
	progress  time.Time // when records last started waiting or a checkpoint last advanced
	witness   map[string]WitnessStatus
	feedErr   string

	closeOnce sync.Once
}

// Open brings the ledger up (OpenLog), then checks it against the last checkpoint a witness signed, which the
// store holds: the chain must still hold at least that many records and must hash to that checkpoint's root. A
// chain that does not is refused here, so the core does not start serving evidence a witness has already seen
// differently. A lost or empty volume is rebuilt from the chain first (OpenLog) and held to the same test.
func Open(ctx context.Context, cfg Config, chain Chain, st store.Ledger, clock func() time.Time, log *slog.Logger) (*Service, error) {
	if clock == nil {
		clock = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = time.Second
	}
	if cfg.Log.CheckpointInterval <= 0 {
		cfg.Log.CheckpointInterval = DefaultCheckpointInterval
	}
	if cfg.Log.WitnessTimeout <= 0 {
		cfg.Log.WitnessTimeout = DefaultWitnessTimeout
	}
	if cfg.StallAfter <= 0 {
		cfg.StallAfter = 3*cfg.Log.CheckpointInterval + cfg.Log.WitnessTimeout
	}
	s := &Service{cfg: cfg, chain: chain, st: st, clock: clock, log: log, witness: map[string]WitnessStatus{}}
	base := cfg.Log.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 30 * time.Second}
	}
	rt := base.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	obs := *base
	obs.Transport = observer{next: rt, s: s}
	s.cfg.Log.HTTPClient = &obs

	seq, _, err := chain.Head(ctx)
	if err != nil {
		return nil, err
	}
	held, err := st.LedgerCheckpoint(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	have := err == nil
	if have && held.Size > seq+1 {
		return nil, fmt.Errorf("%w: a witness signed a checkpoint of %d records and the chain holds %d: the chain was truncated or restored from an older copy",
			ErrChainBehind, held.Size, seq+1)
	}
	s.lg, err = OpenLog(ctx, s.cfg.Log, chain)
	if err != nil {
		return nil, err
	}
	if have {
		roots, err := Roots(ctx, chain, held.Size)
		if err != nil {
			_ = s.closeLog()
			return nil, err
		}
		if hex.EncodeToString(roots[0]) != held.Root {
			_ = s.closeLog()
			return nil, fmt.Errorf("%w: the chain's first %d records hash to %s, the checkpoint a witness signed says %s",
				ErrRootMismatch, held.Size, hex.EncodeToString(roots[0]), held.Root)
		}
		s.witnessed = held.Size
	}
	s.chainN, s.progress = seq+1, clock()
	s.ledgerN, _ = s.lg.Size(ctx)
	return s, nil
}

func (s *Service) closeLog() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.Close(ctx)
}

// Log is the underlying log.
func (s *Service) Log() *Log { return s.lg }

// Run adds records and records checkpoints until ctx ends, then closes the log.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.PollEvery)
	defer t.Stop()
	for {
		s.Step(ctx)
		select {
		case <-ctx.Done():
			if err := s.closeLog(); err != nil {
				s.log.Warn("ledger: closing", "error", err.Error())
			}
			return
		case <-t.C:
		}
	}
}

// Step does one round: add the chain's new records to the log, then record the newest witnessed checkpoint.
func (s *Service) Step(ctx context.Context) {
	if err := s.feed(ctx); err != nil && ctx.Err() == nil {
		s.mu.Lock()
		changed := s.feedErr != err.Error()
		s.feedErr = err.Error()
		s.mu.Unlock()
		if changed {
			s.log.Error("ledger: adding records failed", "error", err.Error())
		}
	} else if err == nil {
		s.mu.Lock()
		s.feedErr = ""
		s.mu.Unlock()
	}
	if err := s.observe(ctx); err != nil && ctx.Err() == nil {
		s.log.Error("ledger: recording a checkpoint failed", "error", err.Error())
	}
}

func (s *Service) feed(ctx context.Context) error {
	seq, _, err := s.chain.Head(ctx)
	if err != nil {
		return err
	}
	n := seq + 1
	have, err := s.lg.Size(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.chainN == s.witnessed && n > s.witnessed {
		s.progress = s.clock() // records began to wait
	}
	s.chainN, s.ledgerN = n, have
	s.mu.Unlock()
	if have > n {
		return fmt.Errorf("%w: %d against %d", ErrChainBehind, have, n)
	}
	for have < n {
		var hashes [][]byte
		err := eachHash(ctx, s.chain, have, min(n, have+batchSize), func(_ int64, h []byte) error {
			hashes = append(hashes, h)
			return nil
		})
		if err != nil {
			return err
		}
		if err := s.lg.Add(ctx, hashes, have); err != nil {
			return err
		}
		have += int64(len(hashes))
		s.mu.Lock()
		s.ledgerN = have
		s.mu.Unlock()
	}
	return nil
}

func (s *Service) observe(ctx context.Context) error {
	cp, ok, err := s.lg.Latest(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	witnessed := s.witnessed
	s.mu.Unlock()
	if !ok || !cp.Witnessed || cp.Size <= witnessed {
		return nil
	}
	err = s.st.PutLedgerCheckpoint(ctx, store.LedgerCheckpoint{Origin: cp.Origin, Size: cp.Size,
		Root: hex.EncodeToString(cp.Root), Note: cp.Note, At: s.clock().UTC()})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.witnessed, s.progress = cp.Size, s.clock()
	s.mu.Unlock()
	s.log.Info("ledger: checkpoint witnessed", "size", cp.Size, "witnesses", cp.Cosigned)
	return nil
}

// Status is the ledger's state now.
func (s *Service) Status(_ context.Context) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Enabled: true, Origin: s.lg.origin, Chain: s.chainN, Ledger: s.ledgerN, Witnessed: s.witnessed,
		Tier3Wait: s.cfg.Tier3Wait}
	failing, rejected := 0, ""
	for _, w := range s.witness {
		st.Witnesses = append(st.Witnesses, w)
		switch w.State {
		case "unavailable":
			failing++
		case "rejected":
			rejected = w.URL + ": " + w.Detail
		}
	}
	sort.Slice(st.Witnesses, func(i, j int) bool { return st.Witnesses[i].URL < st.Witnesses[j].URL })
	pending := s.chainN - s.witnessed
	waited := s.clock().Sub(s.progress)
	switch {
	case rejected != "":
		st.State, st.Detail = StateWitnessRejected, "a witness refused the log's checkpoint ("+rejected+"): the log it holds is not the one it cosigned"
	case len(s.witness) > 0 && failing == len(s.witness):
		st.State, st.Detail = StateWitnessUnavailable, "no witness answered the log's last checkpoint request"
	case pending > 0 && waited > s.cfg.StallAfter:
		st.State = StateStalled
		st.Detail = fmt.Sprintf("%d records have waited %s for a witnessed checkpoint", pending, waited.Truncate(time.Second))
		if s.feedErr != "" {
			st.Detail += " (" + s.feedErr + ")"
		}
	case pending > 0:
		st.State = StateCheckpointing
	default:
		st.State = StateCurrent
	}
	st.Holding = s.cfg.Tier3Wait && (st.State == StateWitnessRejected || st.State == StateWitnessUnavailable || st.State == StateStalled)
	return st
}

// Hold is gate.EvidenceGate: whether a tier 3 change waits because the evidence cannot be checkpointed, and why.
func (s *Service) Hold(ctx context.Context) (bool, string) {
	st := s.Status(ctx)
	if !st.Holding {
		return false, ""
	}
	return true, st.State + ": " + st.Detail
}

// observer reports each witness request's outcome to the service.
type observer struct {
	next http.RoundTripper
	s    *Service
}

func (o observer) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := o.next.RoundTrip(r)
	u := r.URL.Scheme + "://" + r.URL.Host + r.URL.Path
	w := WitnessStatus{URL: u, At: o.s.clock().UTC().Format(time.RFC3339)}
	switch {
	case err != nil:
		w.State, w.Detail = "unavailable", "request failed"
	case resp.StatusCode == http.StatusOK:
		w.State = "ok"
	case resp.StatusCode == http.StatusConflict && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/x.tlog.size"):
		// The witness is telling the log its size, part of a normal exchange (the log's idea of it was stale)...
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		size, perr := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
		o.s.mu.Lock()
		have := o.s.ledgerN
		o.s.mu.Unlock()
		if perr != nil || size <= have {
			return resp, err
		}
		// ...unless it has cosigned a bigger tree than this log holds: the log was truncated.
		w.State, w.Detail = "rejected", fmt.Sprintf("the witness cosigned a tree of %d records, this log holds %d: it was truncated", size, have)
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout:
		w.State, w.Detail = "unavailable", fmt.Sprintf("HTTP %d", resp.StatusCode)
	default:
		w.State, w.Detail = "rejected", fmt.Sprintf("HTTP %d: %s", resp.StatusCode, rejectionReason(resp.StatusCode))
	}
	o.s.mu.Lock()
	o.s.witness[u] = w
	o.s.mu.Unlock()
	return resp, err
}

func rejectionReason(code int) string {
	switch code {
	case http.StatusConflict:
		return "the log's tree is not the one the witness cosigned"
	case http.StatusUnprocessableEntity:
		return "the consistency proof does not verify"
	case http.StatusForbidden:
		return "no log signature verifies under a key the witness trusts"
	case http.StatusNotFound:
		return "the witness does not know this log"
	case http.StatusBadRequest:
		return "the checkpoint is older than the witness's"
	}
	return "refused"
}

// Close stops the log (Run does it itself when its context ends).
func (s *Service) Close(ctx context.Context) error {
	var err error
	s.closeOnce.Do(func() { err = s.lg.Close(ctx) })
	return err
}
