package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GET /v1/stream: server-sent events of new evidence records and of the gate's state changes (C-10).
//
// One hub per process polls the chain's head (one indexed query per StreamPoll, whatever the number of streams);
// only when the head moves does each stream read what is new for its viewer, through the same scoped queries as
// the reads (so a stream never shows what the list would not). clearance-api is read-only and runs as replicas,
// so it cannot be told of a write the way the core's own waiters are; the head poll is its whole cost when idle.
//
// Bounds (section 12): at most MaxStreams per replica and MaxStreamsPerCaller per caller (503 past either), a
// write deadline of StreamWriteTimeout on every event (a reader that stops reading is dropped, never buffered for),
// a comment every StreamHeartbeat, and the stream ends after StreamMaxDuration (the client reconnects with
// Last-Event-ID). Delivery is at least once: an event is resent after a reconnect that missed its id; dedupe by seq.
const (
	StreamPoll          = time.Second
	StreamHeartbeat     = 15 * time.Second
	StreamMaxDuration   = 10 * time.Minute
	StreamWriteTimeout  = 10 * time.Second
	MaxStreams          = 64
	MaxStreamsPerCaller = 8
	streamBatch         = 200
)

// StreamTypes are what a stream may carry (types=).
var StreamTypes = []string{"records", "clearances"}

// StreamEvent is a clearance event's data: the deploy.* record's seq, tool and ts, and the change summary it
// recorded (id, app, env, cluster, head, tree, tier, state, objects): the change's state as of that record. A record
// event's data is the record itself, as getEvidence serves it.
type StreamEvent struct {
	Seq    int64          `json:"seq"`
	Tool   string         `json:"tool"`
	TS     string         `json:"ts"`
	Change map[string]any `json:"change"`
}

// hub is the process's head poller.
type hub struct {
	st    Store
	every time.Duration
	log   *slog.Logger

	mu        sync.Mutex
	running   bool
	head      int64
	wake      chan struct{}
	streams   int
	perCaller map[string]int
}

var errStreamsFull = errors.New("api: too many streams")

func newHub(st Store, every time.Duration, log *slog.Logger) *hub {
	if every <= 0 {
		every = StreamPoll
	}
	return &hub{st: st, every: every, log: log, head: -1, wake: make(chan struct{}), perCaller: map[string]int{}}
}

// join admits one stream for caller, starting the poller if it is the first; leave must be called when it ends.
func (h *hub) join(ctx context.Context, caller string) (leave func(), err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streams >= MaxStreams || h.perCaller[caller] >= MaxStreamsPerCaller {
		return nil, errStreamsFull
	}
	if !h.running {
		head, err := h.st.Head(ctx)
		if err != nil {
			return nil, err
		}
		h.head, h.running = head, true
		go h.poll()
	}
	h.streams++
	h.perCaller[caller]++
	var once sync.Once
	return func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.streams--
			if h.perCaller[caller]--; h.perCaller[caller] <= 0 {
				delete(h.perCaller, caller)
			}
		})
	}, nil
}

// state is the head now and the channel closed when it next moves.
func (h *hub) state() (int64, <-chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.head, h.wake
}

// poll reads the head every h.every while a stream is open, waking the streams when it moves.
func (h *hub) poll() {
	t := time.NewTicker(h.every)
	defer t.Stop()
	for range t.C {
		h.mu.Lock()
		if h.streams == 0 {
			h.running = false
			h.mu.Unlock()
			return
		}
		h.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), ReadyTimeout)
		head, err := h.st.Head(ctx)
		cancel()
		if err != nil {
			h.log.Warn("stream: reading the head failed", "error", err.Error())
			continue
		}
		h.mu.Lock()
		if head > h.head {
			h.head = head
			close(h.wake)
			h.wake = make(chan struct{})
		}
		h.mu.Unlock()
	}
}

// sseWriter writes events with a deadline on each.
type sseWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (s *sseWriter) send(chunk []byte) error {
	if err := s.rc.SetWriteDeadline(time.Now().Add(StreamWriteTimeout)); err != nil {
		return err // no deadline, no stream: a stalled reader must not hold the handler
	}
	if _, err := s.w.Write(chunk); err != nil {
		return err
	}
	return s.rc.Flush()
}

func event(id *int64, name string, data any) ([]byte, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if id != nil {
		fmt.Fprintf(&b, "id: %d\n", *id)
	}
	fmt.Fprintf(&b, "event: %s\ndata: %s\n\n", name, raw)
	return b.Bytes(), nil
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	types := map[string]bool{"records": true, "clearances": true}
	if raw := q["types"]; raw != "" {
		types = map[string]bool{}
		for _, t := range strings.Split(raw, ",") {
			t = strings.TrimSpace(t)
			if !in(StreamTypes, t) {
				writeError(w, 400, "types is a list of "+strings.Join(StreamTypes, ", "))
				return
			}
			types[t] = true
		}
	}
	if v.Role == RoleFeed {
		if types["records"] && q["types"] != "" {
			writeError(w, 403, v.Person+" reads clearance events of its clusters only (types=clearances)")
			return
		}
		types = map[string]bool{"clearances": true}
	}
	resume := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if a := q["after"]; a != "" {
		resume = a
	}
	var cursor int64
	haveCursor := false
	if resume != "" {
		n, err := strconv.ParseInt(resume, 10, 64)
		if err != nil || n < -1 {
			writeError(w, 400, "Last-Event-ID (or after) is a record seq")
			return
		}
		cursor, haveCursor = n, true
	}
	caller := v.Person
	if v.Via != "" {
		caller = v.Via
	}
	leave, err := s.hub.join(r.Context(), caller)
	if errors.Is(err, errStreamsFull) {
		w.Header().Set("Retry-After", "10")
		writeError(w, 503, "too many streams open; retry")
		return
	}
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	defer leave()
	head, wake := s.hub.state()
	if !haveCursor {
		cursor = head
	}
	rc := http.NewResponseController(w)
	// A GET has no body; an expired read deadline would cancel the request. Each event sets its write deadline.
	if err := rc.SetReadDeadline(time.Time{}); err != nil {
		s.log.ErrorContext(r.Context(), "stream: the connection's deadlines cannot be set", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "this server cannot stream")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	out := &sseWriter{w: w, rc: rc}
	if out.send([]byte("retry: 3000\n: clearance stream\n\n")) != nil {
		return
	}
	end := time.NewTimer(StreamMaxDuration)
	defer end.Stop()
	beat := time.NewTicker(StreamHeartbeat)
	defer beat.Stop()
	f := EvidenceFilter{Outcomes: OutcomesInclude}
	for {
		if head > cursor {
			next, err := s.drain(r, out, v, f, types, cursor, head)
			if err != nil {
				if !errors.Is(err, errGone) {
					s.log.ErrorContext(r.Context(), "stream: read failed", "error", err.Error())
					if b, e := event(nil, "error", ErrorBody{Error: "read failed"}); e == nil {
						_ = out.send(b)
					}
				}
				return
			}
			cursor = next
		}
		select {
		case <-wake:
			head, wake = s.hub.state()
		case <-beat.C:
			if out.send([]byte(": keep-alive\n\n")) != nil {
				return
			}
		case <-end.C:
			return
		case <-r.Context().Done():
			return
		}
	}
}

// errGone is a reader that went away (a failed write): the stream just ends.
var errGone = errors.New("api: the reader went away")

// drain sends what the viewer may see with seq in (cursor, head], in seq order, and returns the new cursor.
func (s *Server) drain(r *http.Request, out *sseWriter, v *Viewer, f EvidenceFilter, types map[string]bool, cursor, head int64) (int64, error) {
	for cursor < head {
		ctx, cancel := context.WithTimeout(r.Context(), HandlerTimeout)
		bound := head
		var recs []Record
		var deps []DeployEvent
		var err error
		if types["records"] {
			if recs, err = s.opt.Store.EvidenceAfter(ctx, f, v, cursor, streamBatch); err == nil && len(recs) == streamBatch {
				if n, ok := seqOf(recs[len(recs)-1]); ok && n < bound {
					bound = n
				}
			}
		}
		if err == nil && types["clearances"] {
			if deps, err = s.opt.Store.DeploysAfter(ctx, cursor, streamBatch); err == nil && len(deps) == streamBatch &&
				deps[len(deps)-1].Seq < bound {
				bound = deps[len(deps)-1].Seq
			}
		}
		cancel()
		if err != nil {
			return cursor, err
		}
		// Merge by seq up to bound: a record and the clearance event of the same seq go together, the id on the
		// last, so a reconnect at that id has both.
		type item struct {
			rec Record
			dep *DeployEvent
		}
		bySeq := map[int64]*item{}
		var seqs []int64
		at := func(n int64) *item {
			it := bySeq[n]
			if it == nil {
				it = &item{}
				bySeq[n] = it
				seqs = append(seqs, n)
			}
			return it
		}
		for _, rec := range recs {
			if n, ok := seqOf(rec); ok && n <= bound {
				at(n).rec = rec
			}
		}
		for i := range deps {
			d := &deps[i]
			if d.Seq <= bound && depVisible(d, v) {
				at(d.Seq).dep = d
			}
		}
		slices.Sort(seqs)
		for _, n := range seqs {
			it := bySeq[n]
			seq := n
			if it.rec != nil {
				id := &seq
				if it.dep != nil {
					id = nil
				}
				b, err := event(id, "record", project(it.rec))
				if err != nil {
					return cursor, err
				}
				if out.send(b) != nil {
					return cursor, errGone
				}
			}
			if it.dep != nil {
				var summary map[string]any
				_ = json.Unmarshal(it.dep.Summary, &summary)
				b, err := event(&seq, "clearance", StreamEvent{Seq: n, Tool: it.dep.Tool, TS: it.dep.TS, Change: summary})
				if err != nil {
					return cursor, err
				}
				if out.send(b) != nil {
					return cursor, errGone
				}
			}
		}
		cursor = bound
	}
	return cursor, nil
}

// depVisible is whether the viewer may see a clearance event: a feed reader its clusters' (from the summary), an
// auditor every one, a person the changes they may read (changeVisible on the change as stored).
func depVisible(d *DeployEvent, v *Viewer) bool {
	switch {
	case v.All():
		return true
	case v.Role == RoleFeed:
		var c struct {
			Cluster string `json:"cluster"`
		}
		return json.Unmarshal(d.Summary, &c) == nil && v.FeedOf(c.Cluster)
	case d.Change == nil:
		return false
	}
	return changeVisible(d.Change, v)
}
