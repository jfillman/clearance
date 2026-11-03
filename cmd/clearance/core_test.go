package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/cli"
)

func TestCoreRefusesTheClockSkewOffOnAKeptStore(t *testing.T) {
	for _, args := range [][]string{
		{"core", "--max-clock-skew", "0"},
		{"core", "--max-clock-skew", "soon", "--memory"},
	} {
		var out, errb bytes.Buffer
		t.Setenv("CLEARANCE_DSN", "postgres://unused")
		if code := cli.Main(context.Background(), args, &out, &errb); code != 2 {
			t.Fatalf("%v: exit %d\n%s", args, code, errb.String())
		}
		if !strings.Contains(errb.String(), "clock") {
			t.Errorf("%v: %s", args, errb.String())
		}
	}
	var out, errb bytes.Buffer
	t.Setenv("CLEARANCE_MAX_CLOCK_SKEW", "0")
	if code := cli.Main(context.Background(), []string{"core"}, &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), "only with --memory") {
		t.Fatalf("CLEARANCE_MAX_CLOCK_SKEW=0 without --memory: exit %d %s", code, errb.String())
	}
}

// A test core on a fixed clock, from the unmodified binary: --memory --insecure-dev-auth --max-clock-skew 0. An
// evaluation dated 2026-09-26 is decided, and the chain is read back at GET /v1/dev/records.
func TestATestCoreOnAFixedClock(t *testing.T) {
	t.Setenv("CLEARANCE_PROVIDERS", `[{"name":"autopilot-gateway","version":"test","principals":["autopilot-system/clearance"]}]`)
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	done := make(chan int, 1)
	go func() {
		done <- cli.Main(ctx, []string{"core", "--memory", "--insecure-dev-auth", "--max-clock-skew", "0",
			"--listen", "127.0.0.1:0"}, io.Discard, pw)
		pw.Close()
	}()
	addr := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			var l map[string]any
			if json.Unmarshal(sc.Bytes(), &l) == nil && l["msg"] == "clearance core serving" {
				addr <- l["addr"].(string)
			}
		}
	}()
	var base string
	select {
	case a := <-addr:
		base = "http://" + a
	case <-time.After(10 * time.Second):
		t.Fatal("the core did not start")
	}
	defer func() {
		cancel()
		if code := <-done; code != 0 {
			t.Errorf("exit %d", code)
		}
	}()
	body := `{"subject": {"type": "principal", "id": "user:alice", "properties": {"kind": "user", "tier_ceiling": 1}},
	  "action": {"name": "session.open", "properties": {"run": true, "via": "tower/backstage"}},
	  "resource": {"type": "agent", "id": "nobody"},
	  "context": {"now": "2026-09-26T12:00:00Z", "new_session_id": "s-1"}}`
	req, _ := http.NewRequest("POST", base+"/access/v1/evaluation", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer autopilot-system/clearance")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var res map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if resp.StatusCode != 200 || res["decision"] != false {
		t.Fatalf("%d %v", resp.StatusCode, res)
	}
	req, _ = http.NewRequest("GET", base+"/v1/dev/records", nil)
	req.Header.Set("Authorization", "Bearer autopilot-system/clearance")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&recs)
	resp.Body.Close()
	if len(recs) != 1 || recs[0]["ts"] != "2026-09-26T12:00:00Z" || recs[0]["tool"] != "session.open" {
		t.Fatalf("%v", recs)
	}
}
