package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe for the hold's timer goroutine and the test reading it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// stderrSignalChild is a plugin run that holds a warning and then waits to be killed (TestASIGTERMLeavesTheHeldLines).
func stderrSignalChild() {
	ps := newPluginStderr(os.Stderr, stderrHoldFor, stderrHoldMax)
	flushOnSignal(ps, os.Stderr, time.Now())
	fmt.Fprintln(ps, "clearance-cmp: WARNING held before the kill")
	fmt.Println("ready")
	time.Sleep(time.Minute)
	os.Exit(0)
}

// A clean failure inside the hold's bounds keeps the code line first, with the real bounds.
func TestACleanFailureKeepsTheCodeLineFirst(t *testing.T) {
	var out syncBuffer
	ps := newPluginStderr(&out, stderrHoldFor, stderrHoldMax)
	fmt.Fprintln(ps, "clearance-cmp: WARNING render steps run WITHOUT a private network namespace")
	fmt.Fprintln(ps, "clearance-cmp: summary")
	if out.String() != "" {
		t.Fatalf("written inside the hold: %q", out.String())
	}
	ps.Fail(newErr(CodeRenderHelm, "helm template failed", errors.New("boom")))
	got := out.String()
	if !strings.HasPrefix(got, "clearance-cmp: "+CodeRenderHelm+": ") {
		t.Fatalf("the first line is not the code line:\n%s", got)
	}
	if !strings.Contains(got, "WARNING render steps run WITHOUT") || !strings.HasSuffix(got, "clearance-cmp: summary\n") {
		t.Fatalf("the held lines are lost or out of order:\n%s", got)
	}
}

// Past the time bound the held lines are written without waiting for the run to end, and later lines stream; a late
// failure's code line then follows them.
func TestPastTheTimeBoundStderrStreams(t *testing.T) {
	var out syncBuffer
	ps := newPluginStderr(&out, 20*time.Millisecond, stderrHoldMax)
	fmt.Fprintln(ps, "early")
	if out.String() != "" {
		t.Fatalf("written inside the hold: %q", out.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for out.String() != "early\n" {
		if time.Now().After(deadline) {
			t.Fatalf("the held line was not written past the bound: %q", out.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	fmt.Fprintln(ps, "late")
	if out.String() != "early\nlate\n" {
		t.Fatalf("a line past the bound was held: %q", out.String())
	}
	ps.Fail(newErr(CodeRenderHelm, "helm template failed", errors.New("boom")))
	if got := out.String(); !strings.HasPrefix(got, "early\nlate\nclearance-cmp: "+CodeRenderHelm+": ") {
		t.Fatalf("a late failure: %q", got)
	}
}

// Past the size bound the same: what is held is written, and later lines stream.
func TestPastTheSizeBoundStderrStreams(t *testing.T) {
	var out syncBuffer
	ps := newPluginStderr(&out, 0, 64)
	fmt.Fprintln(ps, "short")
	if out.String() != "" {
		t.Fatalf("written under the size bound: %q", out.String())
	}
	long := strings.Repeat("x", 80) + "\n"
	ps.Write([]byte(long))
	if out.String() != "short\n"+long {
		t.Fatalf("not written past the size bound: %q", out.String())
	}
	fmt.Fprintln(ps, "next")
	if !strings.HasSuffix(out.String(), "next\n") {
		t.Fatalf("a line past the bound was held: %q", out.String())
	}
	ps.Flush()
	ps.Flush()
	if strings.Count(out.String(), "short\n") != 1 {
		t.Fatalf("written twice: %q", out.String())
	}
}
