// Package storetest is the conformance suite every store.Store implementation passes (store/memory always,
// store/pg when CLEARANCE_TEST_DSN is set), so the in-memory test core behaves as the durable one does.
package storetest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
)

// Writer seals the conformance suite's records: a fixture provider, the default verified set (the evidence tests' goWriter, so go-extended.jsonl is the same chain).
var Writer = evidence.Writer{Provider: evidence.Provider{Name: "clearance", Version: "0.0.0-test"}}

// Opener returns a fresh, empty store holding seed (an already valid chain) as its first records.
type Opener func(t *testing.T, seed []store.Record) store.Store

// Run runs the suite.
func Run(t *testing.T, open Opener) {
	for _, c := range []struct {
		name string
		fn   func(*testing.T, Opener)
	}{
		{"EmptyHead", testEmptyHead},
		{"AppendAndRead", testAppendAndRead},
		{"TxIsolation", testTxIsolation},
		{"Rollback", testRollback},
		{"Panic", testPanic},
		{"TxAfterDone", testTxAfterDone},
		{"Rejects", testRejects},
		{"Receipts", testReceipts},
		{"Assurance", testAssurance},
		{"Changes", testChanges},
		{"Definitions", testDefinitions},
		{"Tokens", testTokens},
		{"SigningKeys", testSigningKeys},
		{"Feeds", testFeeds},
		{"Attestations", testAttestations},
		{"Breakglass", testBreakglass},
		{"Concurrent", testConcurrent},
		{"CancelledContext", testCancelled},
		{"PythonChainExtended", testPythonChainExtended},
	} {
		t.Run(c.name, func(t *testing.T) { c.fn(t, open) })
	}
}

var bg = context.Background()

func appendOne(t *testing.T, s store.Store, ev store.Event) store.Record {
	t.Helper()
	var rec store.Record
	if err := s.Atomic(bg, func(tx store.Tx) error {
		var err error
		rec, err = tx.Append(bg, ev, Writer)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return rec
}

func head(t *testing.T, r store.Reader) (int64, string) {
	t.Helper()
	seq, h, err := r.Head(bg)
	if err != nil {
		t.Fatal(err)
	}
	return seq, h
}

func all(t *testing.T, r store.Reader) []store.Record {
	t.Helper()
	recs, err := r.Records(bg, 0, 100000)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func verifies(t *testing.T, r store.Reader, n int) {
	t.Helper()
	recs := all(t, r)
	if ok, bad := evidence.Verify(recs); !ok {
		t.Fatalf("chain broken at %d", bad)
	}
	if len(recs) != n {
		t.Fatalf("%d records, want %d", len(recs), n)
	}
}

func testEmptyHead(t *testing.T, open Opener) {
	s := open(t, nil)
	if seq, h := head(t, s); seq != -1 || h != store.Genesis {
		t.Fatalf("empty head = %d %s", seq, h)
	}
	if recs := all(t, s); len(recs) != 0 {
		t.Fatalf("records on an empty store: %v", recs)
	}
}

func testAppendAndRead(t *testing.T, open Opener) {
	s := open(t, nil)
	ev := store.Event{"ts": "2026-11-02T00:00:00Z", "tool": "model.call", "spend": map[string]any{"usd": 0.25},
		"ratio": 1e-05, "n": 3, "note": "café   \U0001f600 <&>\x7f", "list": []string{"b", "a"}, "f": 2.0}
	r0 := appendOne(t, s, ev)
	if r0["seq"] != json.Number("0") || r0["prev_hash"] != store.Genesis || r0["schema"] != evidence.Schema {
		t.Fatalf("record 0 envelope: %v", r0)
	}
	r1 := appendOne(t, s, store.Event{"tool": "x"})
	if r1["prev_hash"] != r0["hash"] || r1["seq"] != json.Number("1") {
		t.Fatalf("record 1 does not link: %v", r1)
	}
	if seq, h := head(t, s); seq != 1 || h != r1["hash"] {
		t.Fatalf("head %d %s", seq, h)
	}
	recs := all(t, s)
	verifies(t, s, 2)
	a, _ := canon.Canonical(recs[0])
	b, _ := canon.Canonical(r0)
	if !bytes.Equal(a, b) {
		t.Fatalf("stored record differs from the appended one:\n%s\n%s", a, b)
	}
	page, err := s.Records(bg, 1, 5)
	if err != nil || len(page) != 1 || page[0]["hash"] != r1["hash"] {
		t.Fatalf("Records(1, 5) = %v, %v", page, err)
	}
	if page, err := s.Records(bg, 0, 1); err != nil || len(page) != 1 {
		t.Fatalf("Records(0, 1) = %d, %v", len(page), err)
	}
	if _, err := s.Records(bg, 0, 0); err == nil {
		t.Fatal("Records with limit 0: want an error")
	}
}

func testTxIsolation(t *testing.T, open Opener) {
	s := open(t, nil)
	appendOne(t, s, store.Event{"tool": "a"})
	err := s.Atomic(bg, func(tx store.Tx) error {
		r, err := tx.Append(bg, store.Event{"tool": "b"}, Writer)
		if err != nil {
			return err
		}
		if seq, h := head(t, tx); seq != 1 || h != r["hash"] {
			return fmt.Errorf("tx head %d %s", seq, h)
		}
		if n := len(all(t, tx)); n != 2 {
			return fmt.Errorf("tx sees %d records, want 2", n)
		}
		if seq, _ := head(t, s); seq != 0 {
			return fmt.Errorf("outside the tx the head moved to %d before commit", seq)
		}
		if n := len(all(t, s)); n != 1 {
			return fmt.Errorf("outside the tx %d records are visible before commit", n)
		}
		if err := tx.PutChange(bg, change("c1", "app", "holding", "r", 1, "h1", "2026-01-01")); err != nil {
			return err
		}
		if _, err := tx.Change(bg, "c1"); err != nil {
			return fmt.Errorf("tx does not see its change: %v", err)
		}
		if _, err := s.Change(bg, "c1"); !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("uncommitted change visible outside: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	verifies(t, s, 2)
	if _, err := s.Change(bg, "c1"); err != nil {
		t.Fatal(err)
	}
}

func change(id, app, state, repo string, pr int, head, created string, extra ...string) store.Change {
	rec := fmt.Sprintf(`{"id":%q,"created_at":%q%s}`, id, created, joinExtra(extra))
	return store.Change{ID: id, App: app, Env: "prod", State: state, Repo: repo, PR: pr, Head: head,
		ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Record: json.RawMessage(rec)}
}

func joinExtra(extra []string) string {
	var b bytes.Buffer
	for _, e := range extra {
		b.WriteByte(',')
		b.WriteString(e)
	}
	return b.String()
}

var errBoom = errors.New("boom")

func testRollback(t *testing.T, open Opener) {
	s := open(t, nil)
	r0 := appendOne(t, s, store.Event{"tool": "a"})
	setDefs(t, s, store.Definition{Name: "d", State: "active", Record: json.RawMessage(`{"v":1}`)})
	err := s.Atomic(bg, func(tx store.Tx) error {
		for i := 0; i < 2; i++ {
			if _, err := tx.Append(bg, store.Event{"tool": "doomed", "i": i}, Writer); err != nil {
				return err
			}
		}
		if err := tx.PutChange(bg, change("c", "app", "holding", "r", 1, "h", "x")); err != nil {
			return err
		}
		if err := tx.ReplaceDefinitions(bg, nil); err != nil {
			return err
		}
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("Atomic = %v, want fn's error", err)
	}
	if seq, h := head(t, s); seq != 0 || h != r0["hash"] {
		t.Fatalf("head not restored: %d %s", seq, h)
	}
	verifies(t, s, 1)
	if _, err := s.Change(bg, "c"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rolled-back change visible: %v", err)
	}
	if defs, _ := s.Definitions(bg); len(defs) != 1 {
		t.Fatalf("rolled-back definitions replace visible: %v", defs)
	}
	r1 := appendOne(t, s, store.Event{"tool": "after"})
	if r1["seq"] != json.Number("1") || r1["prev_hash"] != r0["hash"] {
		t.Fatalf("append after rollback: %v", r1)
	}
	verifies(t, s, 2)
}

func testPanic(t *testing.T, open Opener) {
	s := open(t, nil)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic swallowed")
			}
		}()
		_ = s.Atomic(bg, func(tx store.Tx) error {
			if _, err := tx.Append(bg, store.Event{"tool": "a"}, Writer); err != nil {
				return err
			}
			panic("in fn")
		})
	}()
	if seq, _ := head(t, s); seq != -1 {
		t.Fatalf("panicked tx committed: head %d", seq)
	}
	appendOne(t, s, store.Event{"tool": "b"})
	verifies(t, s, 1)
}

func testTxAfterDone(t *testing.T, open Opener) {
	s := open(t, nil)
	var kept store.Tx
	if err := s.Atomic(bg, func(tx store.Tx) error { kept = tx; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := kept.Append(bg, store.Event{"tool": "late"}, Writer); err == nil {
		t.Fatal("Append on a finished tx: want an error")
	}
	if _, _, err := kept.Head(bg); err == nil {
		t.Fatal("Head on a finished tx: want an error")
	}
	verifies(t, s, 0)
}

func testRejects(t *testing.T, open Opener) {
	s := open(t, nil)
	err := s.Atomic(bg, func(tx store.Tx) error {
		if _, err := tx.Append(bg, store.Event{"seq": 5}, Writer); !errors.Is(err, evidence.ErrEnvelopeField) {
			return fmt.Errorf("envelope field: %v", err)
		}
		for _, ev := range []store.Event{{"x": 1e16}, {"x": math.Copysign(0, -1)}, {"x": math.NaN()}, {"x": "\x00"}} {
			if _, err := tx.Append(bg, ev, Writer); !errors.Is(err, evidence.ErrNotStorable) {
				return fmt.Errorf("%v: %v", ev, err)
			}
		}
		// A refused event leaves the transaction usable.
		_, err := tx.Append(bg, store.Event{"tool": "ok", "coverage": "observed-not-attributed", "boundary": "deployment"}, Writer)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	verifies(t, s, 1)
}

func testReceipts(t *testing.T, open Opener) {
	s := open(t, nil)
	tools := []string{"repo.pr.open", "repo.pr.update"}
	var want []string
	for _, ev := range []store.Event{
		{"tool": "repo.pr.open", "effect": map[string]any{"repo": "o/r", "pr": 7}},     // yes
		{"tool": "repo.pr.open", "effect": map[string]any{"repo": "o/r", "pr": 8}},     // other pr
		{"tool": "repo.file.put", "effect": map[string]any{"repo": "o/r", "pr": 7}},    // other tool
		{"tool": "repo.pr.update", "effect": map[string]any{"repo": "o/r", "pr": "7"}}, // yes: ->> compares text
		{"tool": "repo.pr.open", "effect": map[string]any{"repo": "o/x", "pr": 7}},     // other repo
		{"tool": "repo.pr.open"},                    // no effect
		{"tool": "repo.pr.open", "effect": nil},     // null effect
		{"tool": "repo.pr.open", "effect": "o/r#7"}, // not an object
		{"tool": "repo.pr.update", "effect": map[string]any{"repo": "o/r", "pr": 7, "url": "u"}}, // yes
	} {
		r := appendOne(t, s, ev)
		if eff, ok := ev["effect"].(map[string]any); ok && eff["repo"] == "o/r" && fmt.Sprint(eff["pr"]) == "7" && ev["tool"] != "repo.file.put" {
			want = append(want, r["hash"].(string))
		}
	}
	got, err := s.Receipts(bg, "o/r", 7, tools)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("%d receipts, want %d: %v", len(got), len(want), got)
	}
	for i := range got {
		if got[i]["hash"] != want[i] {
			t.Fatalf("receipt %d out of order or wrong", i)
		}
	}
	if got, _ := s.Receipts(bg, "o/r", 7, nil); len(got) != 0 {
		t.Fatalf("no tools should match nothing: %v", got)
	}
}

func testAssurance(t *testing.T, open Opener) {
	s := open(t, nil)
	appendOne(t, s, store.Event{"tool": "a"})
	if a, err := s.Assurance(bg, 0); err != nil || a != "recorded-not-checkpointed" {
		t.Fatalf("Assurance(0) = %q, %v", a, err)
	}
	if _, err := s.Assurance(bg, 9); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Assurance(9) = %v", err)
	}
}

func put(t *testing.T, s store.Store, cs ...store.Change) {
	t.Helper()
	if err := s.Atomic(bg, func(tx store.Tx) error {
		for _, c := range cs {
			if err := tx.PutChange(bg, c); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func ids(cs []store.Change, err error) string {
	if err != nil {
		return err.Error()
	}
	var b bytes.Buffer
	for _, c := range cs {
		b.WriteString(c.ID + " ")
	}
	return b.String()
}

func testChanges(t *testing.T, open Opener) {
	s := open(t, nil)
	put(t, s,
		change("c3", "app", "holding", "o/r", 1, "h1", "2026-01-03"),
		change("c1", "app", "holding", "o/r", 1, "h1", "2026-01-01"),
		change("c2", "app", "cleared", "o/r", 2, "h2", "2026-01-02",
			`"deployments":[{"answer":"approved","delivered":false}]`),
		change("c4", "app", "cleared", "o/r", 2, "h2", "2026-01-04",
			`"deployments":[{"answer":null,"delivered":false}]`), // contained, but no answer yet
		change("c5", "app", "cleared", "o/r", 3, "h3", "2026-01-05",
			`"deployments":[{"answer":"approved","delivered":true},{"answer":"approved"}]`), // no delivered:false
		change("c6", "app", "cleared", "o/r", 3, "h3", "2026-01-06",
			`"deployments":[{"answer":"rejected","delivered":true},{"answer":"","delivered":false},{"answer":"approved"}]`),
	)
	for _, c := range []struct {
		name string
		got  string
		want string
	}{
		{"ForPR", ids(s.ChangesForPR(bg, "o/r", 1)), "c1 c3 "},
		{"ForHead", ids(s.ChangesForHead(bg, "o/r", "h2")), "c2 c4 "},
		{"Holding", ids(s.ChangesHolding(bg)), "c1 c3 "},
		{"Cleared", ids(s.ChangesCleared(bg, "app", "prod")), "c2 c4 c5 c6 "},
		{"Cleared other env", ids(s.ChangesCleared(bg, "app", "dev")), ""},
		{"Undelivered", ids(s.ChangesUndelivered(bg)), "c2 c6 "},
		{"ForPR none", ids(s.ChangesForPR(bg, "o/x", 1)), ""},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	// The upsert moves state, expiry and record, and keeps app, env, repo, pr and head (pg.py).
	moved := change("c1", "other", "cleared", "o/other", 99, "h9", "2026-01-01", `"v":2`)
	moved.ExpiresAt = time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
	put(t, s, moved)
	c, err := s.Change(bg, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if c.App != "app" || c.Repo != "o/r" || c.PR != 1 || c.Head != "h1" || c.Env != "prod" || c.State != "cleared" ||
		!c.ExpiresAt.Equal(moved.ExpiresAt) {
		t.Fatalf("upsert: %+v", c)
	}
	var rec map[string]any
	if err := json.Unmarshal(c.Record, &rec); err != nil || rec["v"] != 2.0 {
		t.Fatalf("upsert record: %s", c.Record)
	}
	if _, err := s.Change(bg, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Change(nope) = %v", err)
	}
	if err := s.Atomic(bg, func(tx store.Tx) error {
		return tx.PutChange(bg, store.Change{ID: "bad", Record: json.RawMessage(`{`)})
	}); err == nil {
		t.Fatal("a change whose record is not JSON: want an error")
	}
}

func setDefs(t *testing.T, s store.Store, defs ...store.Definition) {
	t.Helper()
	if err := s.Atomic(bg, func(tx store.Tx) error { return tx.ReplaceDefinitions(bg, defs) }); err != nil {
		t.Fatal(err)
	}
}

func testDefinitions(t *testing.T, open Opener) {
	s := open(t, nil)
	def := func(name, state string) store.Definition {
		return store.Definition{Name: name, State: state, Record: json.RawMessage(fmt.Sprintf(`{"name":%q}`, name))}
	}
	setDefs(t, s, def("b", "active"), def("a", "pending"), def("a", "active"), def("B", "active"))
	got, err := s.Definitions(bg)
	if err != nil {
		t.Fatal(err)
	}
	var order string
	for _, d := range got {
		order += d.State + "/" + d.Name + " "
	}
	if order != "active/B active/a active/b pending/a " {
		t.Fatalf("order %q", order)
	}
	setDefs(t, s, def("z", "active"))
	if got, _ := s.Definitions(bg); len(got) != 1 || got[0].Name != "z" {
		t.Fatalf("replace is not whole: %v", got)
	}
	if err := s.Atomic(bg, func(tx store.Tx) error {
		return tx.ReplaceDefinitions(bg, []store.Definition{def("x", "a"), def("x", "a")})
	}); err == nil {
		t.Fatal("duplicate (name, state): want an error")
	}
	if got, _ := s.Definitions(bg); len(got) != 1 || got[0].Name != "z" {
		t.Fatalf("failed replace changed definitions: %v", got)
	}
}

func testConcurrent(t *testing.T, open Opener) {
	s := open(t, nil)
	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- s.Atomic(bg, func(tx store.Tx) error {
				_, err := tx.Append(bg, store.Event{"tool": "c", "i": i}, Writer)
				if err == nil && i%5 == 0 {
					return errBoom // some roll back, interleaved with commits
				}
				return err
			})
			_, _, _ = s.Head(bg)
			_, _ = s.Records(bg, 0, 10)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, errBoom) {
			t.Fatal(err)
		}
	}
	verifies(t, s, n-n/5)
}

func testCancelled(t *testing.T, open Opener) {
	s := open(t, nil)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if err := s.Atomic(ctx, func(tx store.Tx) error {
		_, err := tx.Append(ctx, store.Event{"tool": "x"}, Writer)
		return err
	}); err == nil {
		t.Fatal("Atomic on a cancelled context: want an error")
	}
	verifies(t, s, 0)
	appendOne(t, s, store.Event{"tool": "y"})
	verifies(t, s, 1)
}

// GoEvents are the events Go appends to the Python fixture chain (internal/evidence/testdata); the result must
// be byte for byte go-extended.jsonl, which Python's audit.verify accepted (python_chain.py verify).
// internal/evidence's TestExtendPythonChain holds the same list and writes the file with -update.
var GoEvents = []store.Event{
	{"ts": "2026-11-02T11:00:00Z", "tool": "session.open", "agent": "go", "decision": "allow", "rule": nil,
		"args_sha256": mustDigest(map[string]any{"b": 1, "a": []any{1.0, 2}})},
	{"ts": "2026-11-02T11:00:01Z", "tool": "model.call", "spend": map[string]any{"usd": 0.0123, "tokens": 1500},
		"ratio": 1e-05, "big": json.Number("123456789012345678901234567890"), "note": "café   \U0001f600 <&> \x7f \t\n\"\\"},
	{"ts": "2026-11-02T11:00:02Z", "tool": "repo.pr.open", "effect": map[string]any{"repo": "jfillman/x", "pr": 8},
		"coverage": "observed-not-attributed", "labels": []string{"b", "a"}, "env": map[string]string{"￿": "1", "\U00010000": "2"}},
	{"ts": "2026-11-02T11:00:03Z", "tool": "deploy.clear", "boundary": "deployment",
		"floats": []any{0.1, 1.5, 100.0, 1e-7, 2.5e-300, 9999999999999998.0, json.Number("1.50"), json.Number("1E2")}},
}

func mustDigest(v any) string {
	d, err := canon.ArgsDigest(v)
	if err != nil {
		panic(err)
	}
	return d
}

// EvidenceTestdata is the path of a file in internal/evidence/testdata.
func EvidenceTestdata(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "evidence", "testdata", name)
}

// ReadJSONL reads one record per line ("\n" only: canonical JSON writes U+2028 raw).
func ReadJSONL(t testing.TB, path string) []store.Record {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.Record
	for _, l := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		v, err := canon.Parse(l)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v.(map[string]any))
	}
	return out
}

func testPythonChainExtended(t *testing.T, open Opener) {
	py := ReadJSONL(t, EvidenceTestdata("python-chain.jsonl"))
	s := open(t, py)
	if seq, h := head(t, s); seq != int64(len(py)-1) || h != py[len(py)-1]["hash"] {
		t.Fatalf("seeded head %d %s", seq, h)
	}
	for _, e := range GoEvents {
		appendOne(t, s, e)
	}
	var got bytes.Buffer
	for _, r := range all(t, s) {
		c, err := canon.Canonical(r)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(c)
		got.WriteByte('\n')
	}
	want, err := os.ReadFile(EvidenceTestdata("go-extended.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("the extended chain differs from go-extended.jsonl (which Python's audit.verify accepted):\n%s", got.String())
	}
}

func putToken(t *testing.T, s store.Store, tks ...store.Token) {
	t.Helper()
	if err := s.Atomic(bg, func(tx store.Tx) error {
		for _, tk := range tks {
			if err := tx.PutToken(bg, tk); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func tokenIDs(tks []store.Token, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	out := ""
	for _, tk := range tks {
		out += tk.ChangeID + " "
	}
	return out
}

func testTokens(t *testing.T, open Opener) {
	s := open(t, nil)
	t0 := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	tok := func(id, kid string, exp time.Duration) store.Token {
		return store.Token{ChangeID: id, Cluster: "prod-1", Nonce: "n-" + id, KeyID: kid, IssuedAt: t0,
			ExpiresAt: t0.Add(exp), Envelope: json.RawMessage(`{"payloadType":"x","payload":"e30=","signatures":[]}`),
			JWT: "a.b.c"}
	}
	revoked := tok("t4", "k1", time.Minute)
	at := t0.Add(time.Second)
	revoked.RevokedAt = &at
	putToken(t, s, tok("t1", "k1", 10*time.Minute), tok("t2", "k1", time.Minute), tok("t3", "k0", time.Hour), revoked)
	got, err := s.Token(bg, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Cluster != "prod-1" || got.Nonce != "n-t1" || !got.ExpiresAt.Equal(t0.Add(10*time.Minute)) || got.RevokedAt != nil ||
		got.JWT != "a.b.c" || !json.Valid(got.Envelope) {
		t.Fatalf("Token = %+v", got)
	}
	r, _ := s.Token(bg, "t4")
	if r.RevokedAt == nil || !r.RevokedAt.Equal(at) {
		t.Fatalf("revoked_at %v", r.RevokedAt)
	}
	if _, err := s.Token(bg, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	// Due: not revoked, and expiring before due or signed by another key; soonest first.
	for _, c := range []struct{ name, got, want string }{
		{"due soon", tokenIDs(s.TokensDue(bg, t0.Add(5*time.Minute), "k1", 10)), "t2 t3 "},
		{"due later", tokenIDs(s.TokensDue(bg, t0.Add(30*time.Minute), "k1", 10)), "t2 t1 t3 "},
		{"limit", tokenIDs(s.TokensDue(bg, t0.Add(30*time.Minute), "k1", 1)), "t2 "},
		{"other key", tokenIDs(s.TokensDue(bg, t0, "k0", 10)), "t2 t1 "},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	// The upsert replaces the row; a rolled-back write leaves it.
	moved := tok("t1", "k2", 20*time.Minute)
	moved.Nonce = "n2"
	putToken(t, s, moved)
	if got, _ := s.Token(bg, "t1"); got.Nonce != "n2" || got.KeyID != "k2" {
		t.Fatalf("upsert: %+v", got)
	}
	boom := errors.New("boom")
	if err := s.Atomic(bg, func(tx store.Tx) error {
		if err := tx.PutToken(bg, tok("t1", "k9", time.Hour)); err != nil {
			return err
		}
		if in, _ := tx.Token(bg, "t1"); in.KeyID != "k9" {
			t.Errorf("a transaction does not see its own token write: %+v", in)
		}
		return boom
	}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if got, _ := s.Token(bg, "t1"); got.KeyID != "k2" {
		t.Fatalf("rollback: %+v", got)
	}
}

func testSigningKeys(t *testing.T, open Opener) {
	s := open(t, nil)
	t0 := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	use := func(kid string, at time.Time) {
		t.Helper()
		if err := s.Atomic(bg, func(tx store.Tx) error {
			return tx.UseSigningKey(bg, store.SigningKey{KeyID: kid, JWK: json.RawMessage(`{"kid":"` + kid + `"}`)}, at)
		}); err != nil {
			t.Fatal(err)
		}
	}
	names := func(ks []store.SigningKey, err error) string {
		if err != nil {
			return err.Error()
		}
		out := ""
		for _, k := range ks {
			r := "-"
			if k.RetiredAt != nil {
				r = k.RetiredAt.Sub(t0).String()
			}
			out += k.KeyID + "@" + r + " "
		}
		return out
	}
	use("k1", t0)
	use("k1", t0.Add(time.Hour)) // a restart with the same key changes nothing
	use("k2", t0.Add(2*time.Hour))
	if got := names(s.SigningKeys(bg, t0)); got != "k2@- k1@2h0m0s " {
		t.Fatalf("after rotation: %q", got)
	}
	if got := names(s.SigningKeys(bg, t0.Add(3*time.Hour))); got != "k2@- " {
		t.Fatalf("retired before since: %q", got)
	}
	use("k1", t0.Add(4*time.Hour)) // rolled back to the old key
	if got := names(s.SigningKeys(bg, t0.Add(3*time.Hour))); got != "k2@4h0m0s k1@- " {
		t.Fatalf("roll back: %q", got)
	}
}

func testFeeds(t *testing.T, open Opener) {
	s := open(t, nil)
	t0 := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	tok := func(id, cluster string, exp time.Duration) store.Token {
		return store.Token{ChangeID: id, Cluster: cluster, Nonce: "n-" + id, KeyID: "k1", IssuedAt: t0,
			ExpiresAt: t0.Add(exp), Envelope: json.RawMessage(`{"payloadType":"x","payload":"e30=","signatures":[]}`),
			JWT: "a.b.c"}
	}
	revoked := tok("t4", "prod-1", time.Hour)
	at := t0
	revoked.RevokedAt = &at
	putToken(t, s, tok("t2", "prod-1", time.Hour), tok("t1", "prod-1", time.Hour), tok("t3", "prod-1", -time.Second),
		revoked, tok("t5", "prod-2", time.Hour), tok("t6", "", time.Hour))
	// Live: this cluster's, not revoked, not expired; by change id.
	if got := tokenIDs(s.LiveTokens(bg, "prod-1", t0, 0)); got != "t1 t2 " {
		t.Errorf("LiveTokens = %s", got)
	}
	if got := tokenIDs(s.LiveTokens(bg, "prod-1", t0, 1)); got != "t1 " {
		t.Errorf("LiveTokens limit = %s", got)
	}
	if _, err := s.Feed(bg, "prod-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Feed before any: %v", err)
	}
	f := store.Feed{Cluster: "prod-3", Seq: 1, KeyID: "k1", IssuedAt: t0, ExpiresAt: t0.Add(5 * time.Minute),
		Envelope: json.RawMessage(`{"payloadType":"f","payload":"e30=","signatures":[]}`), Tokens: json.RawMessage(`[]`)}
	put := func(f store.Feed) {
		t.Helper()
		if err := s.Atomic(bg, func(tx store.Tx) error {
			if err := tx.PutFeed(bg, f); err != nil {
				return err
			}
			got, err := tx.Feed(bg, f.Cluster) // a transaction reads its own write
			if err != nil || got.Seq != f.Seq {
				t.Errorf("tx.Feed = %+v, %v", got, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	put(f)
	f.Seq, f.Tokens = 2, json.RawMessage(`[{"change_id":"t1"}]`)
	put(f)
	got, err := s.Feed(bg, "prod-3")
	if err != nil || got.Seq != 2 || got.KeyID != "k1" || !got.ExpiresAt.Equal(t0.Add(5*time.Minute)) ||
		!json.Valid(got.Envelope) || !strings.Contains(string(got.Tokens), "t1") {
		t.Fatalf("Feed = %+v, %v", got, err)
	}
	cs, err := s.FeedClusters(bg)
	if err != nil || strings.Join(cs, ",") != "prod-1,prod-2,prod-3" {
		t.Fatalf("FeedClusters = %v, %v", cs, err)
	}
}

func testAttestations(t *testing.T, open Opener) {
	s := open(t, nil)
	t0 := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	if _, err := s.Attestation(bg, "c1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Attestation before any: %v", err)
	}
	idx := int64(41)
	a := store.Attestation{ChangeID: "c1", Digest: "sha256:aa", Backend: "keyless", RekorLogIndex: &idx, RekorUUID: "u1",
		OutcomeSeq: 7, RecordSeq: 8, CreatedAt: t0, Bundle: json.RawMessage(`{"mediaType":"x"}`)}
	// A rolled-back transaction leaves nothing; a committed one is read back, inside the transaction too.
	_ = s.Atomic(bg, func(tx store.Tx) error {
		if err := tx.PutAttestation(bg, a); err != nil {
			t.Fatal(err)
		}
		return errors.New("roll back")
	})
	if _, err := s.Attestation(bg, "c1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a rolled-back attestation: %v", err)
	}
	if err := s.Atomic(bg, func(tx store.Tx) error {
		if err := tx.PutAttestation(bg, a); err != nil {
			return err
		}
		got, err := tx.Attestation(bg, "c1")
		if err != nil || got.Digest != "sha256:aa" {
			t.Errorf("tx.Attestation = %+v, %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Attestation(bg, "c1")
	if err != nil || got.Digest != "sha256:aa" || got.Backend != "keyless" || got.RekorLogIndex == nil || *got.RekorLogIndex != 41 ||
		got.RekorUUID != "u1" || got.OutcomeSeq != 7 || got.RecordSeq != 8 || !got.CreatedAt.Equal(t0) || !strings.Contains(string(got.Bundle), "mediaType") {
		t.Fatalf("Attestation = %+v, %v", got, err)
	}
	// No Rekor entry: a nil index reads back nil.
	b := store.Attestation{ChangeID: "c2", Digest: "sha256:bb", Backend: "static", KeyID: "k", OutcomeSeq: 1, RecordSeq: 2,
		CreatedAt: t0, Bundle: json.RawMessage(`{}`)}
	if err := s.Atomic(bg, func(tx store.Tx) error { return tx.PutAttestation(bg, b) }); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Attestation(bg, "c2"); err != nil || got.RekorLogIndex != nil || got.KeyID != "k" {
		t.Fatalf("Attestation c2 = %+v, %v", got, err)
	}
}

func testBreakglass(t *testing.T, open Opener) {
	s := open(t, nil)
	t0 := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	win := func(id, state string, exp time.Duration) store.Breakglass {
		return store.Breakglass{ID: id, Cluster: "prod-1", Env: "prod", State: state, ExpiresAt: t0.Add(exp),
			Record: json.RawMessage(`{"id":"` + id + `"}`)}
	}
	put := func(bs ...store.Breakglass) {
		t.Helper()
		if err := s.Atomic(bg, func(tx store.Tx) error {
			for _, b := range bs {
				if err := tx.PutBreakglass(bg, b); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	names := func(bs []store.Breakglass, err error) string {
		if err != nil {
			return err.Error()
		}
		out := ""
		for _, b := range bs {
			out += b.ID + " "
		}
		return out
	}
	put(win("bg-2", "open", 2*time.Hour), win("bg-1", "open", time.Hour), win("bg-0", "closed", 0))
	if got := names(s.BreakglassOpen(bg)); got != "bg-1 bg-2 " {
		t.Fatalf("open = %q", got)
	}
	got, err := s.Breakglass(bg, "bg-0")
	if err != nil || got.State != "closed" || got.Cluster != "prod-1" || !got.ExpiresAt.Equal(t0) || !json.Valid(got.Record) {
		t.Fatalf("Breakglass = %+v %v", got, err)
	}
	if _, err := s.Breakglass(bg, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	// closing is an upsert; a rolled-back close leaves the window open
	boom := errors.New("boom")
	if err := s.Atomic(bg, func(tx store.Tx) error {
		if err := tx.PutBreakglass(bg, win("bg-1", "closed", time.Hour)); err != nil {
			return err
		}
		if in := names(tx.BreakglassOpen(bg)); in != "bg-2 " {
			t.Errorf("a transaction does not see its own close: %q", in)
		}
		return boom
	}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if got := names(s.BreakglassOpen(bg)); got != "bg-1 bg-2 " {
		t.Fatalf("rollback: %q", got)
	}
	put(win("bg-1", "closed", time.Hour))
	if got := names(s.BreakglassOpen(bg)); got != "bg-2 " {
		t.Fatalf("after close: %q", got)
	}
}
