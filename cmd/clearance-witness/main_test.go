package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/ledger"
)

// syncBuffer is a buffer the serving goroutine and the test may both touch.
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

func TestWitnessNeedsItsKeyLogsAndState(t *testing.T) {
	var stderr bytes.Buffer
	if rc := run(context.Background(), nil, &stderr); rc != 2 || !strings.Contains(stderr.String(), "required") {
		t.Fatalf("%d %s", rc, stderr.String())
	}
}

func TestWitnessServesAndStops(t *testing.T) {
	dir := t.TempDir()
	wkey, _, _, err := ledger.GenerateKey("w")
	if err != nil {
		t.Fatal(err)
	}
	_, lvkey, _, err := ledger.GenerateKey("some-log")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "w.key")
	if err := ledger.WriteKeyFile(keyFile, wkey); err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(dir, "logs")
	if err := os.WriteFile(logs, []byte("# the logs\n"+lvkey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var stderr syncBuffer
	go func() {
		done <- run(ctx, []string{"--listen", addr, "--key-file", keyFile, "--logs-file", logs, "--state-file", filepath.Join(dir, "state.json")}, &stderr)
	}()
	var resp *http.Response
	for i := 0; i < 50; i++ {
		if resp, err = http.Get("http://" + addr + "/healthz"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v %s", resp, err, stderr.String())
	}
	resp.Body.Close()
	if r, err := http.Get("http://" + addr + "/add-checkpoint"); err != nil || r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("a GET of add-checkpoint: %v %v", r, err)
	}
	if strings.Contains(stderr.String(), "PRIVATE+KEY") {
		t.Fatal("the secret key reached the log")
	}
	cancel()
	select {
	case rc := <-done:
		if rc != 0 {
			t.Fatalf("exit %d: %s", rc, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("did not stop")
	}
}
