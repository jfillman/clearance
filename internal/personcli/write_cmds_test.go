package personcli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// sent is one request the fake core saw.
type sent struct {
	Method, Path string
	Header       http.Header
	Body         map[string]any
}

// fakeCore records every request and answers by "METHOD path" (a func) or with 404.
type fakeCore struct {
	mu     sync.Mutex
	reqs   []sent
	routes map[string]func(w http.ResponseWriter, r *http.Request, body map[string]any)
}

func (f *fakeCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.reqs = append(f.reqs, sent{r.Method, r.URL.Path, r.Header.Clone(), body})
	f.mu.Unlock()
	if h, ok := f.routes[r.Method+" "+r.URL.Path]; ok {
		h(w, r, body)
		return
	}
	jsonAnswer(w, 404, map[string]any{"error": "not found"})
}

func (f *fakeCore) n() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.reqs) }

func serveCore(t *testing.T, routes map[string]func(http.ResponseWriter, *http.Request, map[string]any)) (*fakeCore, string) {
	t.Helper()
	f := &fakeCore{routes: routes}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv.URL
}

func answer(code int, v any) func(http.ResponseWriter, *http.Request, map[string]any) {
	return func(w http.ResponseWriter, _ *http.Request, _ map[string]any) { jsonAnswer(w, code, v) }
}

// writeHarness is a signed-in CLI with an api (serving change c-1 at the given tier and state) and a core.
func writeHarness(t *testing.T, tier int, state string, core map[string]func(http.ResponseWriter, *http.Request, map[string]any)) (*harness, *fakeCore, *fakeAPI) {
	t.Helper()
	c := map[string]any{}
	for k, v := range change1 {
		c[k] = v
	}
	c["tier"], c["state"] = tier, state
	api, apiURL := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/clearances/c-1": ok(c)})
	fc, coreURL := serveCore(t, core)
	h := newHarness(t, apiURL)
	h.setenv("CLEARANCE_URL", coreURL)
	h.env.IsTTY = true // stdout is a terminal: table output
	return h, fc, api
}

func tty(h *harness, input string) {
	h.env.StdinTTY = true
	h.env.Stdin = strings.NewReader(input)
}

var decided = map[string]any{"id": "c-1", "state": "cleared", "approvals": []any{}, "audit_seq": 77}

func TestClearShowsTheChangeAsksAndSendsViaCLIWithThePersonsOwnToken(t *testing.T) {
	h, core, api := writeHarness(t, 2, "holding", map[string]func(http.ResponseWriter, *http.Request, map[string]any){
		"POST /v1/clearances/c-1/clear": answer(200, decided)})
	tty(h, "y\n")
	code, out, errs := h.run((*Env).ChangesClear, "c-1", "--reason", "diff reviewed")
	if code != 0 || !strings.Contains(out, "approved c-1") || !strings.Contains(out, "record 77") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	// what will happen was shown (to stderr), before the question
	for _, want := range []string{"gate-api", "tier", "binds to", "head", "Clear c-1", "diff reviewed", "[y/N]"} {
		if !strings.Contains(errs, want) {
			t.Errorf("the preview lacks %q:\n%s", want, errs)
		}
	}
	r := core.reqs[0]
	if r.Header.Get("X-Clearance-Via") != "cli" || r.Body["reason"] != "diff reviewed" ||
		r.Header.Get("Authorization") != "Bearer "+personToken("https://idp.example", t0.Add(60*60e9), t0) {
		t.Fatalf("the write: %+v", r)
	}
	if strings.Contains(out+errs, "eyJ") {
		t.Fatal("a token was printed")
	}
	if len(api.seen) != 1 || core.n() != 1 {
		t.Fatalf("one read, one write: %v %d", api.seen, core.n())
	}
}

func TestClearAsksAndANoSendsNothing(t *testing.T) {
	h, core, _ := writeHarness(t, 2, "holding", nil)
	tty(h, "n\n")
	if code, _, errs := h.run((*Env).ChangesClear, "c-1"); code != ExitError || !strings.Contains(errs, "cancelled") || core.n() != 0 {
		t.Fatalf("%d %q %d", code, errs, core.n())
	}
}

func TestClearWithoutATerminalNeedsYesAndATierThreeNeverGoesWithoutOne(t *testing.T) {
	routes := map[string]func(http.ResponseWriter, *http.Request, map[string]any){"POST /v1/clearances/c-1/clear": answer(200, decided)}
	// tier 2, no terminal: refused until --yes
	h, core, _ := writeHarness(t, 2, "holding", routes)
	if code, _, errs := h.run((*Env).ChangesClear, "c-1"); code != ExitUsage || !strings.Contains(errs, "--yes") || core.n() != 0 {
		t.Fatalf("%d %q", code, errs)
	}
	if code, out, errs := h.run((*Env).ChangesClear, "c-1", "--yes"); code != 0 || core.n() != 1 || !strings.Contains(out, "approved") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	// tier 3: --yes is not honored without a terminal
	h, core, _ = writeHarness(t, 3, "holding", routes)
	if code, _, errs := h.run((*Env).ChangesClear, "c-1", "--yes"); code != ExitUsage || !strings.Contains(errs, "interactive") || core.n() != 0 {
		t.Fatalf("tier 3 --yes without a terminal: %d %q", code, errs)
	}
	// on a terminal --yes skips the question for tier 3
	h, core, _ = writeHarness(t, 3, "holding", routes)
	tty(h, "")
	if code, _, errs := h.run((*Env).ChangesClear, "c-1", "--yes"); code != 0 || core.n() != 1 {
		t.Fatalf("%d %q", code, errs)
	}
	// --token-stdin leaves no terminal to ask on
	h, core, _ = writeHarness(t, 3, "holding", routes)
	tty(h, personToken("https://idp.example", t0.Add(3600e9), t0))
	if code, _, _ := h.run((*Env).ChangesClear, "c-1", "--yes", "--token-stdin"); code != ExitUsage || core.n() != 0 {
		t.Fatalf("a tier 3 clear with the token on stdin went through: %d", code)
	}
}

func TestClearRefusesAChangeThatIsNotHoldingWithoutCallingTheCore(t *testing.T) {
	h, core, _ := writeHarness(t, 2, "cleared", nil)
	tty(h, "y\n")
	if code, _, errs := h.run((*Env).ChangesClear, "c-1", "--yes"); code != ExitError || !strings.Contains(errs, "cleared") || core.n() != 0 {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestAStaleSignInIsExit4WithSignInAgain(t *testing.T) {
	h, _, _ := writeHarness(t, 2, "holding", map[string]func(http.ResponseWriter, *http.Request, map[string]any){
		"POST /v1/clearances/c-1/clear": answer(401, map[string]any{"error": "your sign-in is 22m0s old; this action needs one at most 15m0s old",
			"rule": "DG-AUTH-NOT-FRESH", "max_age": "15m0s", "age": "22m0s", "hint": "Sign in again"})})
	tty(h, "")
	code, _, errs := h.run((*Env).ChangesClear, "c-1", "--yes")
	if code != ExitUnauthorized || !strings.Contains(errs, "sign in again (`clearance login`)") || !strings.Contains(errs, "15m0s") {
		t.Fatalf("%d %q", code, errs)
	}
	// a plain 401 keeps its own message
	h, _, _ = writeHarness(t, 2, "holding", map[string]func(http.ResponseWriter, *http.Request, map[string]any){
		"POST /v1/clearances/c-1/clear": answer(401, map[string]any{"error": "bad token"})})
	tty(h, "")
	if code, _, errs := h.run((*Env).ChangesClear, "c-1", "--yes"); code != ExitUnauthorized || strings.Contains(errs, "sign in again") || !strings.Contains(errs, "clearance login") {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestWritesNeedTheCoreURLAndSayWhichServerFailed(t *testing.T) {
	h, _, _ := writeHarness(t, 2, "holding", nil)
	h.setenv("CLEARANCE_URL", "")
	if code, _, errs := h.run((*Env).ChangesClear, "c-1", "--yes"); code != ExitUsage || !strings.Contains(errs, "CLEARANCE_URL") {
		t.Fatalf("%d %q", code, errs)
	}
	h, _, _ = writeHarness(t, 2, "holding", map[string]func(http.ResponseWriter, *http.Request, map[string]any){
		"POST /v1/clearances/c-1/clear": answer(409, map[string]any{"error": "this change is cleared", "rule": "DG-STATE", "hint": "x"})})
	tty(h, "")
	if code, _, errs := h.run((*Env).ChangesClear, "c-1", "--yes"); code != ExitError || !strings.Contains(errs, "HTTP 409") {
		t.Fatalf("%d %q", code, errs)
	}
	h, _, _ = writeHarness(t, 2, "holding", map[string]func(http.ResponseWriter, *http.Request, map[string]any){
		"POST /v1/clearances/c-1/clear": answer(503, map[string]any{"error": "store down"})})
	tty(h, "")
	if code, _, errs := h.run((*Env).ChangesClear, "c-1", "--yes"); code != ExitUnavailable || !strings.Contains(errs, "the Clearance core is unavailable") {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestDenyNeedsAReason(t *testing.T) {
	h, core, _ := writeHarness(t, 2, "holding", map[string]func(http.ResponseWriter, *http.Request, map[string]any){
		"POST /v1/clearances/c-1/deny": answer(200, map[string]any{"id": "c-1", "state": "denied", "audit_seq": 78})})
	tty(h, "y\n")
	if code, _, errs := h.run((*Env).ChangesDeny, "c-1"); code != ExitUsage || !strings.Contains(errs, "reason is required") || core.n() != 0 {
		t.Fatalf("%d %q", code, errs)
	}
	if code, _, _ := h.run((*Env).ChangesDeny, "c-1", "--reason", "   "); code != ExitUsage || core.n() != 0 {
		t.Fatal("a blank reason was sent")
	}
	tty(h, "y\n")
	code, out, errs := h.run((*Env).ChangesDeny, "c-1", "--reason", "wrong tree")
	if code != 0 || !strings.Contains(out, "denied c-1") || core.reqs[0].Body["reason"] != "wrong tree" || core.reqs[0].Header.Get("X-Clearance-Via") != "cli" {
		t.Fatalf("%d %q %q %+v", code, out, errs, core.reqs)
	}
}

func TestJSONOutputIsTheCoresAnswerAndThePromptsStayOnStderr(t *testing.T) {
	h, _, _ := writeHarness(t, 2, "holding", map[string]func(http.ResponseWriter, *http.Request, map[string]any){
		"POST /v1/clearances/c-1/clear": answer(200, decided)})
	tty(h, "y\n")
	code, out, errs := h.run((*Env).ChangesClear, "c-1", "-o", "json")
	var m map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &m) != nil || m["audit_seq"] != float64(77) || !strings.Contains(errs, "[y/N]") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
}

// ---- resolve -------------------------------------------------------------------------------------------------------

func bulkRoutes() map[string]func(http.ResponseWriter, *http.Request, map[string]any) {
	return map[string]func(http.ResponseWriter, *http.Request, map[string]any){
		"POST /v1/observations/resolutions": func(w http.ResponseWriter, _ *http.Request, b map[string]any) {
			items, _ := b["items"].([]any)
			rec := []any{}
			for _, it := range items {
				rec = append(rec, map[string]any{"seq": it, "record_seq": 1000, "scope": "s"})
			}
			jsonAnswer(w, 200, map[string]any{"batch": "b-1", "recorded": rec, "skipped": []any{}, "failed": []any{}})
		},
		"POST /v1/observations/5/resolution": answer(200, map[string]any{"seq": 99, "about": 5, "state": "ratified"}),
	}
}

func resolveHarness(t *testing.T) (*harness, *fakeCore) {
	core, coreURL := serveCore(t, bulkRoutes())
	h := newHarness(t, "https://api.invalid")
	h.setenv("CLEARANCE_URL", coreURL)
	h.env.IsTTY = true
	return h, core
}

func TestResolveOneUsesTheSingleRoute(t *testing.T) {
	h, core := resolveHarness(t)
	code, out, errs := h.run((*Env).ExceptionsResolve, "5", "--as", "ratified", "--note", "known", "--yes")
	if code != 0 || core.n() != 1 || core.reqs[0].Path != "/v1/observations/5/resolution" || core.reqs[0].Body["state"] != "ratified" ||
		core.reqs[0].Body["note"] != "known" || core.reqs[0].Header.Get("X-Clearance-Via") != "cli" || !strings.Contains(out, "1 recorded") {
		t.Fatalf("%d %q %q %+v", code, out, errs, core.reqs)
	}
}

func TestResolveChunksAtTwoHundredAndPlanSendsNothing(t *testing.T) {
	h, core := resolveHarness(t)
	var lines []string
	for i := 1; i <= 450; i++ {
		lines = append(lines, fmt.Sprint(i))
	}
	lines = append(lines, "# a comment", "", "7") // a repeat is one
	file := filepath.Join(t.TempDir(), "seqs.txt")
	if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := h.run((*Env).ExceptionsResolve, "--from-file", file, "--as", "reverted", "--cause", "human-initiated", "--plan")
	if code != 0 || core.n() != 0 || !strings.Contains(out, "resolve 450 as reverted (human-initiated) in 3 call(s)") || !strings.Contains(out, "nothing is sent") {
		t.Fatalf("plan: %d %q %q %d", code, out, errs, core.n())
	}
	// the plan as json is the calls verbatim
	code, out, _ = h.run((*Env).ExceptionsResolve, "--from-file", file, "--as", "ratified", "--plan", "-o", "json")
	var doc struct {
		Count int
		Calls []struct {
			Method, Path string
			Body         struct{ Items []int64 }
		}
	}
	if code != 0 || json.Unmarshal([]byte(out), &doc) != nil || doc.Count != 450 || len(doc.Calls) != 3 ||
		len(doc.Calls[0].Body.Items) != 200 || len(doc.Calls[2].Body.Items) != 50 || doc.Calls[1].Path != "/v1/observations/resolutions" {
		t.Fatalf("%d %s", code, out)
	}
	// without --yes and without a terminal: refused, nothing sent
	if code, _, errs := h.run((*Env).ExceptionsResolve, "--from-file", file, "--as", "ratified"); code != ExitUsage || core.n() != 0 {
		t.Fatalf("%d %q", code, errs)
	}
	// with --yes: three calls
	code, out, errs = h.run((*Env).ExceptionsResolve, "--from-file", file, "--as", "ratified", "--yes")
	if code != 0 || core.n() != 3 || !strings.Contains(out, "450 recorded") || !strings.Contains(out, "3 call(s)") {
		t.Fatalf("%d %q %q %d", code, out, errs, core.n())
	}
	for _, r := range core.reqs {
		if r.Header.Get("X-Clearance-Via") != "cli" || len(r.Body["items"].([]any)) > MaxBulk {
			t.Fatalf("%+v", r.Header)
		}
	}
}

func TestResolveStopsAtTheFirstFailedChunkAndSaysWhatWasRecorded(t *testing.T) {
	calls := 0
	core, coreURL := serveCore(t, map[string]func(http.ResponseWriter, *http.Request, map[string]any){
		"POST /v1/observations/resolutions": func(w http.ResponseWriter, r *http.Request, b map[string]any) {
			calls++
			if calls == 2 {
				jsonAnswer(w, 403, map[string]any{"error": "user:erin is not a Clearance admin"})
				return
			}
			jsonAnswer(w, 200, map[string]any{"batch": "b", "recorded": make([]any, len(b["items"].([]any))), "skipped": []any{}, "failed": []any{}})
		}})
	h := newHarness(t, "https://api.invalid")
	h.setenv("CLEARANCE_URL", coreURL)
	var lines []string
	for i := 1; i <= 450; i++ {
		lines = append(lines, fmt.Sprint(i))
	}
	file := filepath.Join(t.TempDir(), "s")
	_ = os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0o600)
	code, _, errs := h.run((*Env).ExceptionsResolve, "--from-file", file, "--as", "still-live", "--yes")
	if code != ExitForbidden || core.n() != 2 || !strings.Contains(errs, "1 of 3 call(s) were already recorded (200 resolutions)") {
		t.Fatalf("%d %d %q", code, core.n(), errs)
	}
}

func TestResolveValidatesBeforeAnyCall(t *testing.T) {
	h, core := resolveHarness(t)
	for name, args := range map[string][]string{
		"no state":        {"5", "--yes"},
		"bad state":       {"5", "--as", "fixed", "--yes"},
		"reverted/cause":  {"5", "--as", "reverted", "--yes"},
		"bad cause":       {"5", "--as", "reverted", "--cause", "luck", "--yes"},
		"cause alone":     {"5", "--as", "ratified", "--cause", "human-initiated", "--yes"},
		"no selection":    {"--as", "ratified", "--yes"},
		"two selections":  {"5", "--all-matching", "--as", "ratified", "--yes"},
		"not a seq":       {"abc", "--as", "ratified", "--yes"},
		"negative":        {"--from-file", "/nonexistent", "--as", "ratified", "--yes"},
		"note too long":   {"5", "--as", "ratified", "--note", strings.Repeat("x", 4097), "--yes"},
		"no core and yes": nil,
	} {
		if args == nil {
			continue
		}
		if code, _, _ := h.run((*Env).ExceptionsResolve, args...); code != ExitUsage || core.n() != 0 {
			t.Errorf("%s: exit %d, %d sent", name, code, core.n())
		}
	}
}

func TestResolveAllMatchingReadsTheListAndKeepsOnlyResolvableKinds(t *testing.T) {
	ex := func(seq int, kind string) map[string]any {
		return map[string]any{"seq": seq, "tool": "deploy.exception", "app": "gate-api", "exception": map[string]any{"kind": kind},
			"destination": map[string]any{"cluster": "hangar-prod"}}
	}
	api, apiURL := serve(t, map[string]func(http.ResponseWriter, *http.Request){"/v1/exceptions": ok(map[string]any{"items": []any{
		ex(3, "drift"), ex(4, "attempted-refused"), ex(5, "out-of-band"), ex(5, "out-of-band")}, "next": nil})})
	core, coreURL := serveCore(t, bulkRoutes())
	h := newHarness(t, apiURL)
	h.setenv("CLEARANCE_URL", coreURL)
	code, out, errs := h.run((*Env).ExceptionsResolve, "--all-matching", "--scope", "hangar-prod", "--app", "gate-api", "--as", "ratified", "--plan", "-o", "json")
	var doc struct {
		Count int
		Calls []struct{ Body struct{ Items []int64 } }
	}
	if code != 0 || json.Unmarshal([]byte(out), &doc) != nil || doc.Count != 2 || len(doc.Calls) != 1 || fmt.Sprint(doc.Calls[0].Body.Items) != "[3 5]" {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	if !strings.Contains(api.last(), "app=gate-api") || !strings.Contains(api.last(), "tool=deploy.exception") || core.n() != 0 {
		t.Fatalf("%s %d", api.last(), core.n())
	}
}

func TestParseSeqsAcceptsListsLinesAndExceptionsListOutput(t *testing.T) {
	for in, want := range map[string]string{
		"1\n2 # x\n\n# c\n3":    "[1 2 3]",
		"[4,5,6]":               "[4 5 6]",
		`[{"seq":7},{"seq":8}]`: "[7 8]",
		"{\"seq\":9,\"tool\":\"x\"}\n{\"seq\":10}":      "[9 10]",
		`{"items":[{"seq":11},{"seq":12}],"next":null}`: "[11 12]",
		"": "[]",
	} {
		got, err := parseSeqs([]byte(in))
		if err != nil || fmt.Sprint(got) != want && !(want == "[]" && len(got) == 0) {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"abc", "-1", "[1,\"x\"]", `{"nope":1}`, "1.5"} {
		if _, err := parseSeqs([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// ---- break-glass ---------------------------------------------------------------------------------------------------

func TestBreakglassOpenIsAlwaysInteractiveAndTypedBack(t *testing.T) {
	win := map[string]any{"id": "bg-1", "state": "open", "cluster": "hangar-prod", "env": "prod", "expires_at": "2026-11-13T13:00:00Z"}
	core, coreURL := serveCore(t, map[string]func(http.ResponseWriter, *http.Request, map[string]any){"POST /v1/breakglass": answer(200, win)})
	h := newHarness(t, "https://api.invalid")
	h.setenv("CLEARANCE_URL", coreURL)
	h.env.IsTTY = true
	args := []string{"--cluster", "hangar-prod", "--env", "prod", "--ttl", "30m", "--reason", "prod is down"}
	// no terminal: refused, even with --yes (not even a flag)
	if code, _, _ := h.run((*Env).BreakglassOpen, args...); code != ExitUsage || core.n() != 0 {
		t.Fatalf("no terminal: %d", code)
	}
	if code, _, _ := h.run((*Env).BreakglassOpen, append(args, "--yes")...); code != ExitUsage || core.n() != 0 {
		t.Fatalf("--yes: %d", code)
	}
	// a y is not enough: the scope is typed back
	tty(h, "y\n")
	if code, _, errs := h.run((*Env).BreakglassOpen, args...); code != ExitError || core.n() != 0 || !strings.Contains(errs, "Type hangar-prod/prod") {
		t.Fatalf("%d %q", code, errs)
	}
	tty(h, "hangar-prod/prod\n")
	code, out, errs := h.run((*Env).BreakglassOpen, args...)
	if code != 0 || core.n() != 1 || !strings.Contains(out, "bg-1 is open") || !strings.Contains(errs, "prod is down") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	r := core.reqs[0]
	if r.Body["reason"] != "prod is down" || r.Body["ttl"] != "30m" || r.Body["cluster"] != "hangar-prod" || r.Header.Get("X-Clearance-Via") != "cli" {
		t.Fatalf("%+v", r)
	}
	if _, has := r.Body["app"]; has {
		t.Fatal("an app was sent that was not asked for")
	}
	// missing reason is a usage error
	if code, _, _ := h.run((*Env).BreakglassOpen, "--cluster", "c", "--env", "e", "--ttl", "5m"); code != ExitUsage {
		t.Fatal(code)
	}
}

func TestBreakglassCloseAndList(t *testing.T) {
	core, coreURL := serveCore(t, map[string]func(http.ResponseWriter, *http.Request, map[string]any){
		"POST /v1/breakglass/bg-1/close": answer(200, map[string]any{"id": "bg-1", "state": "closed"}),
		"GET /v1/breakglass": answer(200, map[string]any{"items": []any{map[string]any{"id": "bg-1", "cluster": "hangar-prod", "env": "prod",
			"person": "user:root", "expires_at": "2026-11-13T13:00:00Z", "reason": "down"}}})})
	h := newHarness(t, "https://api.invalid")
	h.setenv("CLEARANCE_URL", coreURL)
	h.env.IsTTY = true
	if code, out, errs := h.run((*Env).BreakglassClose, "bg-1", "--yes"); code != 0 || !strings.Contains(out, "bg-1 is closed") || core.reqs[0].Header.Get("X-Clearance-Via") != "cli" {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	if code, out, _ := h.run((*Env).BreakglassList); code != 0 || !strings.Contains(out, "hangar-prod/prod") || !strings.Contains(out, "user:root") {
		t.Fatalf("%d %q", code, out)
	}
}
