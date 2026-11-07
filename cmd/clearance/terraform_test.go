package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/cli"
)

const (
	tfSecretVar  = "hunter2-SECRET"
	tfSecretAttr = "attr-SECRET-value"
	tfRunner     = "app-infra-cicd/pipeline-runner"
)

var noToken = func(context.Context, map[string]string, string) (string, error) { return "unused", nil }

// tfDir is a working directory with a saved plan's bytes and the fixture plan JSON.
func tfDir(t *testing.T, fixture, planBody string) (dir, plan, planJSON string) {
	t.Helper()
	dir = t.TempDir()
	plan = filepath.Join(dir, "tfplan")
	if err := os.WriteFile(plan, []byte(planBody), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../internal/tfplan/testdata/" + fixture + ".json")
	if err != nil {
		t.Fatal(err)
	}
	planJSON = filepath.Join(dir, "plan.json")
	if err := os.WriteFile(planJSON, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

func tfEnv() map[string]string {
	return map[string]string{"GITHUB_REPOSITORY": "jfillman/hangar-infra", "GITHUB_SHA": strings.Repeat("a", 40), "GITHUB_ACTOR": "dana"}
}

func holdArgv(plan, planJSON string, extra ...string) []string {
	return append([]string{"--plan", plan, "--json", planJSON, "--backend", "s3", "--state-key", "network/lab/terraform.tfstate",
		"--app", "network", "--env", "lab", "--lock-file", "none"}, extra...)
}

func tfRun(t *testing.T, f func(stdout, stderr io.Writer) int) (int, string, string) {
	t.Helper()
	var o, e bytes.Buffer
	c := f(&o, &e)
	return c, o.String(), e.String()
}

func TestHoldUsageErrorsExitTwo(t *testing.T) {
	_, plan, pj := tfDir(t, "create", "p")
	for name, argv := range map[string][]string{
		"no plan":        {"--app", "a", "--env", "e", "--backend", "s3", "--state-key", "k"},
		"no state key":   {"--plan", plan, "--app", "a", "--env", "e", "--backend", "s3"},
		"unknown flag":   {"--nope"},
		"bad proposer":   append(holdArgv(plan, pj), "--proposer-kind", "robot"),
		"missing plan":   holdArgv(plan+".missing", pj),
		"not plan json":  holdArgv(plan, plan),
		"no repo or sha": holdArgv(plan, pj),
		"no url, no dry": holdArgv(plan, pj),
		"stray argument": append(holdArgv(plan, pj), "extra"),
	} {
		env := tfEnv()
		if name == "no repo or sha" {
			env = map[string]string{}
		}
		code, _, stderr := tfRun(t, func(o, e io.Writer) int {
			return holdWith(context.Background(), argv, env, noToken, terraformShow, o, e)
		})
		if code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s", name, code, stderr)
		}
	}
	for name, f := range map[string]func(o, e io.Writer) int{
		"release": func(o, e io.Writer) int {
			return releaseMain(context.Background(), []string{"--plan", plan}, tfEnv(), noToken, o, e)
		},
		"report": func(o, e io.Writer) int {
			return reportMain(context.Background(), []string{"--plan", plan}, tfEnv(), noToken, o, e)
		},
	} {
		if code, _, _ := tfRun(t, f); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}

// The request holds digests, addresses and attribute names: no secret, and never the plan file.
func TestHoldDryRunSendsNoSecretAndNoPlan(t *testing.T) {
	_, plan, pj := tfDir(t, "replace", "PLAN-FILE-BYTES-"+tfSecretAttr)
	code, out, stderr := tfRun(t, func(o, e io.Writer) int {
		return holdWith(context.Background(), holdArgv(plan, pj, "--dry-run", "--check", "ci=pass"), tfEnv(), noToken, terraformShow, o, e)
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, s := range []string{tfSecretVar, tfSecretAttr, "PLAN-FILE-BYTES"} {
		if strings.Contains(out+stderr, s) {
			t.Fatalf("%q in the output", s)
		}
	}
	var body struct {
		Subject struct {
			Kind, PlanDigest, VariableSetDigest string
			Summary                             struct{ Replace int }
		}
		Proposer string
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil || body.Subject.Kind != "terraform-plan" ||
		body.Subject.Summary.Replace != 1 || !strings.HasPrefix(body.Subject.PlanDigest, "sha256:") || body.Proposer != "user:dana" {
		t.Fatalf("%v\n%s", err, out)
	}
}

// The plan JSON comes from `<binary> show -json <plan>` when --json is not given.
func TestHoldRunsTheBinary(t *testing.T) {
	dir, plan, pj := tfDir(t, "update", "p")
	bin := filepath.Join(dir, "fakeform")
	script := "#!/bin/sh\n[ \"$1 $2 $3\" = \"show -json " + plan + "\" ] || exit 9\ncat " + pj + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	argv := holdArgv(plan, pj, "--dry-run", "--binary", bin)
	argv = append(argv[:2], argv[4:]...) // drop --json
	code, out, stderr := tfRun(t, func(o, e io.Writer) int {
		return holdWith(context.Background(), argv, tfEnv(), noToken, terraformShow, o, e)
	})
	if code != 0 || !strings.Contains(out, `"update": 1`) {
		t.Fatalf("exit %d: %s\n%s", code, out, stderr)
	}
	argv[len(argv)-1] = filepath.Join(dir, "missing-binary")
	if code, _, _ := tfRun(t, func(o, e io.Writer) int {
		return holdWith(context.Background(), argv, tfEnv(), noToken, terraformShow, o, e)
	}); code != 2 {
		t.Fatalf("a binary that fails: exit %d", code)
	}
}

// A fake Clearance: registers holding, then answers the wait call with the next state.
func fakeClearance(t *testing.T, register string, waits ...string) (*httptest.Server, *atomic.Int32) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		if r.Method == "POST" {
			io.WriteString(w, register)
			return
		}
		i := int(n.Add(1)) - 1
		io.WriteString(w, waits[min(i, len(waits)-1)])
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestHoldExitCodes(t *testing.T) {
	_, plan, pj := tfDir(t, "destroy", "p")
	tokFile := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tokFile, []byte("tok\n"), 0o600)
	holding := `{"id":"ch-1","state":"holding","tier":3,"requirement":{"owner":1,"ownerGroup":"group:default/net","outside":1}}`
	cases := []struct {
		name, register string
		waits          []string
		extra          []string
		code           int
	}{
		{"cleared at once", `{"id":"ch-1","state":"cleared","tier":1}`, nil, nil, 0},
		{"holding, --no-wait", holding, nil, []string{"--no-wait"}, 3},
		{"holding, then cleared", holding, []string{`{"id":"ch-1","state":"holding","changed":false}`, `{"id":"ch-1","state":"cleared","tier":3,"changed":true}`}, nil, 0},
		{"holding, then denied", holding, []string{`{"id":"ch-1","state":"denied","tier":3,"changed":true}`}, nil, 1},
		{"holding, then expired", holding, []string{`{"id":"ch-1","state":"expired","changed":true}`}, nil, 1},
		{"denied at once", `{"id":"ch-1","state":"denied","tier":3,"deny_reason":"no"}`, nil, nil, 1},
		{"refused", `{"rule":"DG-REPO","message":"not your repo"}`, nil, nil, 0}, // status below
	}
	for _, c := range cases {
		srv, _ := fakeClearance(t, c.register, c.waits...)
		url := srv.URL
		if c.name == "refused" {
			ref := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403); io.WriteString(w, c.register) }))
			defer ref.Close()
			url, c.code = ref.URL, 1
		}
		code, out, stderr := tfRun(t, func(o, e io.Writer) int {
			return holdWith(context.Background(), holdArgv(plan, pj, append(c.extra, "--url", url, "--token-file", tokFile)...), tfEnv(), noToken, terraformShow, o, e)
		})
		if code != c.code {
			t.Errorf("%s: exit %d, want %d\n%s\n%s", c.name, code, c.code, out, stderr)
		}
		if c.code == 0 && !strings.Contains(out, "ch-1 cleared") {
			t.Errorf("%s: %s", c.name, out)
		}
	}
}

func TestHoldWaitTimeoutExitsHolding(t *testing.T) {
	_, plan, pj := tfDir(t, "destroy", "p")
	tokFile := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tokFile, []byte("tok"), 0o600)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			io.WriteString(w, `{"id":"ch-1","state":"holding","tier":3}`)
			return
		}
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	code, _, stderr := tfRun(t, func(o, e io.Writer) int {
		return holdWith(context.Background(), holdArgv(plan, pj, "--url", srv.URL, "--token-file", tokFile, "--wait-timeout", "300ms"),
			tfEnv(), noToken, terraformShow, o, e)
	})
	if code != 3 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

func TestApplyLogParse(t *testing.T) {
	log := `{"@message":"Apply complete","type":"change_summary","@timestamp":"2026-11-03T12:00:09.5+00:00"}
{"type":"apply_start","@timestamp":"2026-11-03T12:00:00.1+00:00","hook":{"resource":{"addr":"aws_vpc.lab"},"action":"update"}}
{"type":"apply_complete","@timestamp":"2026-11-03T12:00:08+00:00","hook":{"resource":{"addr":"aws_vpc.lab"},"action":"update"}}
{"type":"apply_start","hook":{"resource":{"addr":"aws_x.y"},"action":"mystery"}}
`
	l, err := parseApplyLog(strings.NewReader(log))
	if err != nil || !l.applied || len(l.changes) != 1 || l.changes[0].Status != "complete" ||
		l.finished.Sub(l.started) < 9*time.Second {
		t.Fatalf("%+v %v", l, err)
	}
	bad := `{"type":"apply_errored","hook":{"resource":{"addr":"aws_vpc.lab"},"action":"update"}}
{"type":"diagnostic","diagnostic":{"severity":"error","summary":"boom","detail":"password=hunter2-SECRET"}}`
	l, err = parseApplyLog(strings.NewReader(bad))
	if err != nil || l.applied || l.errText != "boom" || strings.Contains(l.errText, "hunter2") {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err = parseApplyLog(strings.NewReader("not json")); err == nil {
		t.Fatal("accepted")
	}
}

// ---- end to end against `clearance core --memory` ----

func startCore(t *testing.T) string {
	t.Helper()
	t.Setenv("CLEARANCE_VERIFIERS", tfRunner)
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	done := make(chan int, 1)
	go func() {
		done <- cli.Main(ctx, []string{"core", "--memory", "--insecure-dev-auth", "--listen", "127.0.0.1:0"}, io.Discard, pw)
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
	select {
	case a := <-addr:
		t.Cleanup(func() {
			cancel()
			if code := <-done; code != 0 {
				t.Errorf("core exit %d", code)
			}
		})
		return "http://" + a
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("the core did not start")
		return ""
	}
}

func cliRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var o, e bytes.Buffer
	c := cli.Main(context.Background(), args, &o, &e)
	return c, o.String(), e.String()
}

func TestEndToEndHoldReleaseReport(t *testing.T) {
	base := startCore(t)
	tokFile := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tokFile, []byte(tfRunner), 0o600) // --insecure-dev-auth: the token is the principal
	auth := []string{"--url", base, "--token-file", tokFile}
	t.Setenv("GITHUB_REPOSITORY", "jfillman/hangar-infra")
	t.Setenv("GITHUB_SHA", strings.Repeat("a", 40))
	t.Setenv("GITHUB_ACTOR", "dana")
	hold := func(plan, pj string, extra ...string) (int, string, string) {
		return cliRun(t, append(append([]string{"hold"}, holdArgv(plan, pj, extra...)...), auth...)...)
	}
	idOf := func(out string) string { return strings.Fields(out)[0] }

	// hold: a tag-only plan with green checks is cleared by policy (tier 1).
	_, plan, pj := tfDir(t, "tag-only", "the saved plan A")
	code, out, stderr := hold(plan, pj, "--check", "ci=pass", "--check", "provenance=not-agent")
	if code != 0 || !strings.Contains(out, " cleared tier 1") {
		t.Fatalf("hold: exit %d\n%s\n%s", code, out, stderr)
	}
	id := idOf(out)
	// ... and registering the same plan again is the same change.
	if code, out2, _ := hold(plan, pj, "--check", "ci=pass", "--check", "provenance=not-agent"); code != 0 || idOf(out2) != id {
		t.Fatalf("again: %d %s", code, out2)
	}

	// release: the cleared plan passes, another plan file does not (exit non-zero, so the apply step never runs).
	if code, out, stderr := cliRun(t, append([]string{"release", "--plan", plan, "--clearance", id}, auth...)...); code != 0 {
		t.Fatalf("release: exit %d\n%s\n%s", code, out, stderr)
	}
	other := filepath.Join(filepath.Dir(plan), "other")
	os.WriteFile(other, []byte("a different saved plan"), 0o600)
	if code, _, stderr := cliRun(t, append([]string{"release", "--plan", other, "--clearance", id}, auth...)...); code != 1 ||
		!strings.Contains(stderr, "do not apply") {
		t.Fatalf("mismatched release: exit %d\n%s", code, stderr)
	}
	if code, _, _ := cliRun(t, append([]string{"release", "--plan", plan, "--clearance", "ch-nope"}, auth...)...); code != 1 {
		t.Fatalf("release of an unknown change: exit %d", code)
	}

	// report: the apply's outcome matches; a second outcome is refused (DG-STATE).
	applyLog := filepath.Join(filepath.Dir(plan), "apply.jsonl")
	os.WriteFile(applyLog, []byte(`{"type":"apply_start","@timestamp":"`+time.Now().UTC().Add(-time.Second).Format(time.RFC3339)+`","hook":{"resource":{"addr":"aws_vpc.lab"},"action":"update"}}
{"type":"apply_complete","@timestamp":"`+time.Now().UTC().Format(time.RFC3339)+`","hook":{"resource":{"addr":"aws_vpc.lab"},"action":"update"}}
{"type":"change_summary","changes":{"update":1}}
`), 0o600)
	report := func(plan, id string) (int, string, string) {
		return cliRun(t, append([]string{"report", "--plan", plan, "--apply-log", applyLog, "--clearance", id}, auth...)...)
	}
	if code, out, stderr := report(plan, id); code != 0 || !strings.Contains(out, "matched=true") {
		t.Fatalf("report: exit %d\n%s\n%s", code, out, stderr)
	}
	if code, _, stderr := report(plan, id); code != 1 || !strings.Contains(stderr, "DG-STATE") {
		t.Fatalf("second report: exit %d\n%s", code, stderr)
	}

	// report of a different plan than the cleared one: recorded as a mismatch, exit 1.
	_, planB, pjB := tfDir(t, "tag-only", "the saved plan B")
	code, outB, stderr := hold(planB, pjB, "--check", "ci=pass", "--check", "provenance=not-agent")
	if code != 0 {
		t.Fatalf("hold B: %d %s", code, stderr)
	}
	idB := idOf(outB)
	if idB == id {
		t.Fatal("two plans are one change")
	}
	if code, _, stderr := report(other, idB); code != 1 || !strings.Contains(stderr, "digest-mismatch") {
		t.Fatalf("mismatched report: exit %d\n%s", code, stderr)
	}
	// ... and the change is no longer cleared: release refuses it.
	if code, _, _ := cliRun(t, append([]string{"release", "--plan", planB, "--clearance", idB}, auth...)...); code != 1 {
		t.Fatalf("release after a mismatch: exit %d", code)
	}

	// hold: a destroy in a protected workspace is tier 3 and holds; --no-wait exits 3. Without the checks, the
	// tag-only plan holds too (tier 2). An unknown proposer is denied (exit 1).
	_, planD, pjD := tfDir(t, "destroy", "the saved plan D")
	if code, out, stderr := hold(planD, pjD, "--no-wait", "--owner", "group:default/net"); code != 3 || !strings.Contains(out, "holding") {
		t.Fatalf("holding: exit %d\n%s\n%s", code, out, stderr)
	}
	if code, _, _ := hold(planD, pjD, "--proposer-kind", "unknown", "--owner", "group:default/net"); code != 1 {
		t.Fatalf("denied: exit %d", code)
	}
}
