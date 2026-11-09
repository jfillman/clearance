// Package queue is the collector's durable queue: an append-only log on a PersistentVolume, no broker. The webhook
// receiver acknowledges the API server only after Append has returned, and Append returns only after the entries are
// written and fsynced, so an outage of the processor, the core or the collector's pod loses nothing the API server
// was told arrived. The processor reads with Next and moves the cursor with Commit once it has handled (posted) what
// it read; Commit stores a small meta document in the same atomic write as the cursor, which is how the processor
// keeps its counters exactly as durable as its progress.
//
// Layout: segment files seg-<first sequence number>.log, each a run of frames (length, CRC-32C, append time, payload),
// and a cursor file. A torn tail (a crash mid-write) is cut off on Open; the API server was never told that frame
// arrived, so it sends it again. Delivery is at least once: the processor's downstream is idempotent (the core
// de-duplicates on source.event_id).
package queue

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Limits and defaults.
const (
	MaxEntry         = 8 << 20
	DefaultSegment   = 16 << 20
	DefaultMaxBytes  = 1 << 30
	frameHeader      = 4 + 4 + 8
	cursorFile       = "cursor.json"
	segPrefix        = "seg-"
	segSuffix        = ".log"
	segNameDigits    = 16
	cursorTmp        = "cursor.json.tmp"
	filePerm         = 0o600
	dirPerm          = 0o700
	maxBatchBytesCap = 64 << 20
)

// ErrFull is Append's answer when the unacknowledged entries would exceed MaxBytes: the receiver then refuses the
// batch (503) rather than lose an older one.
var ErrFull = errors.New("queue: full")

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Options configure Open.
type Options struct {
	SegmentBytes int64 // roll to a new segment past this size (default 16 MiB)
	MaxBytes     int64 // refuse appends when the unacknowledged bytes would pass this (default 1 GiB)
	Now          func() time.Time
}

// Entry is one queued payload.
type Entry struct {
	Seq     uint64
	At      time.Time // when it was appended
	Payload []byte
}

type segment struct {
	start uint64 // sequence number of its first entry
	path  string
	count uint64
	size  int64
}

// Queue is safe for concurrent use: any number of Append callers, one reader.
type Queue struct {
	dir  string
	opt  Options
	mu   sync.Mutex
	segs []*segment
	act  *os.File // the active (last) segment
	next uint64   // the sequence number the next appended entry gets
	cur  uint64   // the cursor: everything below it is handled
	meta json.RawMessage
	size int64 // bytes of unacknowledged segments (segment files on disk)
	head time.Time
	wake chan struct{}

	// read position cache: the segment (by its first sequence number), the byte offset in it, the next sequence number
	rStart uint64
	rOff   int64
	rSeq   uint64
}

// Open opens (or creates) the queue in dir and repairs a torn tail.
func Open(dir string, opt Options) (*Queue, error) {
	if opt.SegmentBytes <= 0 {
		opt.SegmentBytes = DefaultSegment
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = DefaultMaxBytes
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, err
	}
	q := &Queue{dir: dir, opt: opt, wake: make(chan struct{}, 1)}
	if err := q.loadCursor(); err != nil {
		return nil, err
	}
	names, err := filepath.Glob(filepath.Join(dir, segPrefix+"*"+segSuffix))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	for _, n := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(n), segPrefix), segSuffix)
		start, err := strconv.ParseUint(base, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("queue: segment %s: %w", n, err)
		}
		q.segs = append(q.segs, &segment{start: start, path: n})
	}
	for i, s := range q.segs {
		good, count, err := scan(s.path)
		if err != nil {
			return nil, err
		}
		if st, err := os.Stat(s.path); err == nil && st.Size() > good {
			if i != len(q.segs)-1 {
				return nil, fmt.Errorf("queue: segment %s is damaged before the tail", s.path)
			}
			if err := os.Truncate(s.path, good); err != nil {
				return nil, err
			}
		}
		s.count, s.size = count, good
		q.size += good
		if i > 0 && q.segs[i-1].start+q.segs[i-1].count != s.start {
			return nil, fmt.Errorf("queue: a gap between segments %s and %s", q.segs[i-1].path, s.path)
		}
	}
	if n := len(q.segs); n > 0 {
		last := q.segs[n-1]
		q.next = last.start + last.count
	} else {
		q.next = q.cur
	}
	if q.cur > q.next {
		return nil, fmt.Errorf("queue: cursor %d is past the end %d", q.cur, q.next)
	}
	if err := q.openActive(); err != nil {
		return nil, err
	}
	q.resetRead()
	q.dropAcked()
	return q, nil
}

func segPath(dir string, start uint64) string {
	return filepath.Join(dir, fmt.Sprintf("%s%0*d%s", segPrefix, segNameDigits, start, segSuffix))
}

func (q *Queue) openActive() error {
	if len(q.segs) == 0 || q.segs[len(q.segs)-1].size >= q.opt.SegmentBytes {
		s := &segment{start: q.next, path: segPath(q.dir, q.next)}
		q.segs = append(q.segs, s)
	}
	s := q.segs[len(q.segs)-1]
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, filePerm)
	if err != nil {
		return err
	}
	if q.act != nil {
		_ = q.act.Close()
	}
	q.act = f
	return syncDir(q.dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// scan returns the byte length of the valid frames of a segment and how many there are.
func scan(path string) (good int64, count uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		_, n, err := readFrame(r)
		if err != nil {
			return good, count, nil // EOF, torn or corrupt: the valid prefix is what there is
		}
		good += n
		count++
	}
}

func readFrame(r *bufio.Reader) (Entry, int64, error) {
	var h [frameHeader]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Entry{}, 0, err
	}
	n := binary.BigEndian.Uint32(h[0:4])
	if n > MaxEntry {
		return Entry{}, 0, errors.New("queue: frame too long")
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return Entry{}, 0, err
	}
	sum := crc32.New(castagnoli)
	sum.Write(h[8:])
	sum.Write(p)
	if sum.Sum32() != binary.BigEndian.Uint32(h[4:8]) {
		return Entry{}, 0, errors.New("queue: bad checksum")
	}
	at := time.Unix(0, int64(binary.BigEndian.Uint64(h[8:16]))).UTC()
	return Entry{At: at, Payload: p}, int64(frameHeader) + int64(n), nil
}

func frame(at time.Time, p []byte) []byte {
	b := make([]byte, frameHeader+len(p))
	binary.BigEndian.PutUint32(b[0:4], uint32(len(p)))
	binary.BigEndian.PutUint64(b[8:16], uint64(at.UnixNano()))
	copy(b[frameHeader:], p)
	binary.BigEndian.PutUint32(b[4:8], crc32.Checksum(b[8:], castagnoli))
	return b
}

// Append writes the payloads and returns only after they are on disk. ErrFull when the queue holds too much.
func (q *Queue) Append(payloads ...[]byte) error {
	var total int64
	for _, p := range payloads {
		if len(p) > MaxEntry {
			return fmt.Errorf("queue: an entry is %d bytes, the most is %d", len(p), MaxEntry)
		}
		total += int64(frameHeader + len(p))
	}
	if total == 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.size+total > q.opt.MaxBytes {
		return ErrFull
	}
	now := q.opt.Now()
	wasEmpty := q.cur == q.next
	var buf []byte
	for _, p := range payloads {
		buf = append(buf, frame(now, p)...)
	}
	s := q.segs[len(q.segs)-1]
	if s.size > 0 && s.size+total > q.opt.SegmentBytes {
		if err := q.act.Sync(); err != nil {
			return err
		}
		q.segs = append(q.segs, &segment{start: q.next, path: segPath(q.dir, q.next)})
		if err := q.openActive(); err != nil {
			return err
		}
		s = q.segs[len(q.segs)-1]
	}
	if _, err := q.act.Write(buf); err != nil {
		_ = q.act.Truncate(s.size) // do not leave half a batch behind
		return err
	}
	if err := q.act.Sync(); err != nil {
		return err
	}
	s.size += total
	s.count += uint64(len(payloads))
	q.size += total
	q.next += uint64(len(payloads))
	if wasEmpty {
		q.head = now
	}
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

// Wait returns a channel that has a value when something was appended since the last receive.
func (q *Queue) Wait() <-chan struct{} { return q.wake }

// Next returns up to max entries at or after the cursor, in order, without moving it.
func (q *Queue) Next(max int) ([]Entry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []Entry
	var bytes int
	for len(out) < max && q.rSeq < q.next && bytes < maxBatchBytesCap {
		s := q.segmentOf(q.rSeq)
		if s == nil {
			return out, fmt.Errorf("queue: no segment holds entry %d", q.rSeq)
		}
		if s.start != q.rStart {
			q.rStart, q.rOff = s.start, 0
		}
		f, err := os.Open(s.path)
		if err != nil {
			return out, err
		}
		if _, err := f.Seek(q.rOff, io.SeekStart); err != nil {
			f.Close()
			return out, err
		}
		r := bufio.NewReader(f)
		for len(out) < max && q.rSeq < s.start+s.count && bytes < maxBatchBytesCap {
			e, n, err := readFrame(r)
			if err != nil {
				f.Close()
				return out, fmt.Errorf("queue: reading %s: %w", s.path, err)
			}
			e.Seq = q.rSeq
			out = append(out, e)
			bytes += len(e.Payload)
			q.rOff += n
			q.rSeq++
		}
		f.Close()
	}
	if len(out) > 0 && q.head.IsZero() {
		q.head = out[0].At
	}
	return out, nil
}

func (q *Queue) segmentOf(seq uint64) *segment {
	for _, s := range q.segs {
		if seq >= s.start && seq < s.start+s.count {
			return s
		}
	}
	return nil
}

// Rewind makes the next Next start again at the cursor (the processor calls it after a failed batch).
func (q *Queue) Rewind() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.resetRead()
}

// resetRead positions the reader at the cursor.
func (q *Queue) resetRead() {
	q.rSeq, q.rStart, q.rOff = q.cur, 0, 0
	s := q.segmentOf(q.cur)
	if s == nil {
		// At the end: the next appended entry is the next one to read, at the end of the last segment.
		if n := len(q.segs); n > 0 && q.segs[n-1].start+q.segs[n-1].count == q.cur {
			q.rStart, q.rOff = q.segs[n-1].start, q.segs[n-1].size
		}
		return
	}
	q.rStart = s.start
	f, err := os.Open(s.path)
	if err != nil {
		return
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for seq := s.start; seq < q.cur; seq++ {
		_, n, err := readFrame(r)
		if err != nil {
			break
		}
		q.rOff += n
	}
}

// Commit moves the cursor to upTo (everything below it is handled) and stores meta beside it in one atomic write,
// then deletes the segments that are fully handled.
func (q *Queue) Commit(upTo uint64, meta json.RawMessage) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if upTo < q.cur || upTo > q.next {
		return fmt.Errorf("queue: commit %d outside [%d, %d]", upTo, q.cur, q.next)
	}
	if err := q.writeCursor(upTo, meta); err != nil {
		return err
	}
	q.cur, q.meta = upTo, meta
	q.head = time.Time{} // the next Next sets it
	if q.rSeq < q.cur {
		q.resetRead()
	}
	q.dropAcked()
	return nil
}

func (q *Queue) dropAcked() {
	for len(q.segs) > 1 {
		s := q.segs[0]
		if s.start+s.count > q.cur {
			break
		}
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return
		}
		q.size -= s.size
		q.segs = q.segs[1:]
	}
}

type cursorDoc struct {
	Next uint64          `json:"next"`
	Meta json.RawMessage `json:"meta,omitempty"`
}

func (q *Queue) writeCursor(next uint64, meta json.RawMessage) error {
	b, err := json.Marshal(cursorDoc{next, meta})
	if err != nil {
		return err
	}
	tmp := filepath.Join(q.dir, cursorTmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(q.dir, cursorFile)); err != nil {
		return err
	}
	return syncDir(q.dir)
}

func (q *Queue) loadCursor() error {
	b, err := os.ReadFile(filepath.Join(q.dir, cursorFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var d cursorDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return fmt.Errorf("queue: the cursor file: %w", err)
	}
	q.cur, q.meta = d.Next, d.Meta
	return nil
}

// Cursor is the sequence number everything below which is handled.
func (q *Queue) Cursor() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.cur
}

// Meta is the document stored by the last Commit (nil: none).
func (q *Queue) Meta() json.RawMessage {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.meta
}

// Stats are the queue's depth.
type Stats struct {
	Pending   uint64        // entries appended and not yet handled
	Bytes     int64         // bytes on disk
	OldestAge time.Duration // the age of the oldest unhandled entry (0: empty)
}

// Stats reports the depth and the age of the oldest unhandled entry.
func (q *Queue) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := Stats{Pending: q.next - q.cur, Bytes: q.size}
	if s.Pending > 0 && !q.head.IsZero() {
		s.OldestAge = q.opt.Now().Sub(q.head)
	}
	return s
}

// Close closes the active segment.
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.act == nil {
		return nil
	}
	err := q.act.Close()
	q.act = nil
	return err
}
