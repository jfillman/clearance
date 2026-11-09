package queue

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func mustOpen(t *testing.T, dir string, o Options) *Queue {
	t.Helper()
	q, err := Open(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func payloads(n int) [][]byte {
	var out [][]byte
	for i := 0; i < n; i++ {
		out = append(out, []byte(fmt.Sprintf(`{"auditID":"e%d"}`, i)))
	}
	return out
}

// What was appended survives a restart, in order, until it is committed; commit survives too.
func TestAppendSurvivesRestartUntilCommitted(t *testing.T) {
	dir := t.TempDir()
	q := mustOpen(t, dir, Options{})
	if err := q.Append(payloads(5)...); err != nil {
		t.Fatal(err)
	}
	q.Close()
	q = mustOpen(t, dir, Options{})
	es, err := q.Next(100)
	if err != nil || len(es) != 5 {
		t.Fatalf("got %d entries, %v; want 5", len(es), err)
	}
	for i, e := range es {
		if e.Seq != uint64(i) || string(e.Payload) != fmt.Sprintf(`{"auditID":"e%d"}`, i) {
			t.Fatalf("entry %d: %d %s", i, e.Seq, e.Payload)
		}
	}
	if err := q.Commit(3, json.RawMessage(`{"filtered":{"hpa-scale":2}}`)); err != nil {
		t.Fatal(err)
	}
	q.Close()
	q = mustOpen(t, dir, Options{})
	es, _ = q.Next(100)
	if len(es) != 2 || es[0].Seq != 3 {
		t.Fatalf("after commit 3: %d entries from %d; want 2 from 3", len(es), es[0].Seq)
	}
	if string(q.Meta()) != `{"filtered":{"hpa-scale":2}}` {
		t.Fatalf("meta %s", q.Meta())
	}
}

// A crash mid-write leaves a torn frame: Open cuts it off and keeps every whole frame before it.
func TestTornTailIsCutOff(t *testing.T) {
	dir := t.TempDir()
	q := mustOpen(t, dir, Options{})
	if err := q.Append(payloads(3)...); err != nil {
		t.Fatal(err)
	}
	q.Close()
	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.log"))
	if len(segs) != 1 {
		t.Fatalf("segments %v", segs)
	}
	f, err := os.OpenFile(segs[0], os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(frame(time.Now(), []byte("never finished"))[:20]) // half a frame
	f.Close()
	q = mustOpen(t, dir, Options{})
	es, _ := q.Next(100)
	if len(es) != 3 {
		t.Fatalf("got %d entries, want the 3 whole ones", len(es))
	}
	if err := q.Append([]byte(`{"auditID":"after"}`)); err != nil {
		t.Fatal(err)
	}
	es, _ = q.Next(100)
	if len(es) != 1 || !bytes.Contains(es[0].Payload, []byte("after")) {
		t.Fatalf("append after repair: %v", es)
	}
}

func TestCorruptFrameStopsTheScan(t *testing.T) {
	dir := t.TempDir()
	q := mustOpen(t, dir, Options{})
	q.Append(payloads(4)...)
	q.Close()
	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.log"))
	b, _ := os.ReadFile(segs[0])
	b[len(b)-3] ^= 0xff // damage the last payload
	os.WriteFile(segs[0], b, 0o600)
	q = mustOpen(t, dir, Options{})
	es, _ := q.Next(100)
	if len(es) != 3 {
		t.Fatalf("got %d, want 3 (the damaged last frame is dropped)", len(es))
	}
}

func TestSegmentsRollAndAreDeletedWhenHandled(t *testing.T) {
	dir := t.TempDir()
	q := mustOpen(t, dir, Options{SegmentBytes: 200})
	for i := 0; i < 20; i++ {
		if err := q.Append(payloads(1)...); err != nil {
			t.Fatal(err)
		}
	}
	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*.log"))
	if len(segs) < 3 {
		t.Fatalf("only %d segments", len(segs))
	}
	var seen int
	for {
		es, err := q.Next(7)
		if err != nil {
			t.Fatal(err)
		}
		if len(es) == 0 {
			break
		}
		for _, e := range es {
			if e.Seq != uint64(seen) {
				t.Fatalf("out of order: %d at %d", e.Seq, seen)
			}
			seen++
		}
		if err := q.Commit(es[len(es)-1].Seq+1, nil); err != nil {
			t.Fatal(err)
		}
	}
	if seen != 20 {
		t.Fatalf("read %d, want 20", seen)
	}
	after, _ := filepath.Glob(filepath.Join(dir, "seg-*.log"))
	if len(after) != 1 {
		t.Fatalf("%d segments left, want only the active one", len(after))
	}
	q.Close()
	q = mustOpen(t, dir, Options{SegmentBytes: 200})
	if es, _ := q.Next(10); len(es) != 0 {
		t.Fatalf("a handled queue reopened with %d entries", len(es))
	}
	if err := q.Append(payloads(1)...); err != nil {
		t.Fatal(err)
	}
	es, _ := q.Next(10)
	if len(es) != 1 || es[0].Seq != 20 {
		t.Fatalf("sequence continues at 20: %+v", es)
	}
}

func TestFullQueueRefusesInsteadOfDropping(t *testing.T) {
	q := mustOpen(t, t.TempDir(), Options{MaxBytes: 100})
	if err := q.Append(payloads(2)...); err != nil {
		t.Fatal(err)
	}
	if err := q.Append(bytes.Repeat([]byte("x"), 200)); err != ErrFull {
		t.Fatalf("got %v, want ErrFull", err)
	}
	if st := q.Stats(); st.Pending != 2 {
		t.Fatalf("pending %d", st.Pending)
	}
}

func TestRewindRereadsFromTheCursor(t *testing.T) {
	q := mustOpen(t, t.TempDir(), Options{})
	q.Append(payloads(4)...)
	es, _ := q.Next(2)
	q.Commit(es[1].Seq+1, nil)
	a, _ := q.Next(10)
	q.Rewind()
	b, _ := q.Next(10)
	if len(a) != 2 || len(b) != 2 || b[0].Seq != 2 {
		t.Fatalf("%d %d %+v", len(a), len(b), b)
	}
}

func TestConcurrentAppendersLoseNothing(t *testing.T) {
	q := mustOpen(t, t.TempDir(), Options{SegmentBytes: 4096})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if err := q.Append([]byte(fmt.Sprintf("g%d-%d", g, i))); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	wg.Wait()
	seen := map[string]bool{}
	for {
		es, err := q.Next(50)
		if err != nil {
			t.Fatal(err)
		}
		if len(es) == 0 {
			break
		}
		for _, e := range es {
			seen[string(e.Payload)] = true
		}
	}
	if len(seen) != 200 {
		t.Fatalf("read %d distinct entries, want 200", len(seen))
	}
}

func TestOldestAge(t *testing.T) {
	now := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	q := mustOpen(t, t.TempDir(), Options{Now: func() time.Time { return now }})
	q.Append(payloads(1)...)
	now = now.Add(3 * time.Minute)
	if st := q.Stats(); st.OldestAge != 3*time.Minute {
		t.Fatalf("age %v", st.OldestAge)
	}
}

// A queue that was fully handled and reopened mid-segment reads only what is appended afterwards.
func TestReopenAtTheEndOfASegmentReadsOnlyNewEntries(t *testing.T) {
	dir := t.TempDir()
	q := mustOpen(t, dir, Options{})
	q.Append(payloads(5)...)
	es, _ := q.Next(10)
	q.Commit(es[len(es)-1].Seq+1, nil)
	q.Close()
	q = mustOpen(t, dir, Options{})
	q.Append([]byte(`{"auditID":"new"}`))
	es, _ = q.Next(10)
	if len(es) != 1 || es[0].Seq != 5 || !bytes.Contains(es[0].Payload, []byte("new")) {
		t.Fatalf("got %+v", es)
	}
}
