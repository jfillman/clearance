package main

// Ported from tests/test_register.py: the CLI half (the objects of two rendered directories, the body from the
// Actions environment, exit codes, dry run, token file, the User-Agent and a refusal from in front of Clearance).
// The GitHub Actions authenticator tests are R-1d's (authentication); DG-REPO is in internal/gate.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/gate/render"
)

const (
	rhead = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rrepo = "jfillman/clearance-deploy-scratch"
)

const deploy = `apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop-prod}
spec:
  replicas: {replicas}
  template:
    spec:
      containers:
        - name: web
          image: ghcr.io/acme/web@sha256:{digest}
`

func write(t *testing.T, d string, replicas, digest, extra string) string {
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	body := strings.ReplaceAll(strings.ReplaceAll(deploy, "{replicas}", replicas), "{digest}", digest) + extra
	if err := os.WriteFile(filepath.Join(d, "web.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestObjectsAreTheDifferenceOfTwoRenderedDirectories(t *testing.T) {
	tmp := t.TempDir()
	cm := "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: cfg, namespace: shop-prod}\ndata: {a: '1'}\n"
	before, err := render.LoadDir(write(t, filepath.Join(tmp, "b"), "2", strings.Repeat("1", 64), ""))
	if err != nil {
		t.Fatal(err)
	}
	after, err := render.LoadDir(write(t, filepath.Join(tmp, "a"), "3", strings.Repeat("2", 64), cm))
	if err != nil {
		t.Fatal(err)
	}
	objs, err := render.Objects(before, after)
	if err != nil {
		t.Fatal(err)
	}
	by := map[[2]string]render.Object{}
	for _, o := range objs {
		by[[2]string{o.Kind, o.Op}] = o
	}
	web := by[[2]string{"Deployment", "changed"}]
	if !reflect.DeepEqual(web.Fields, []string{"/spec/replicas", "/spec/template/spec/containers/0/image"}) {
		t.Fatal(web.Fields)
	}
	if !reflect.DeepEqual(web.Images, []string{"ghcr.io/acme/web@sha256:" + strings.Repeat("2", 64)}) || len(web.Digest) != 64 {
		t.Fatal(web)
	}
	if _, ok := by[[2]string{"ConfigMap", "added"}]; !ok {
		t.Fatal(objs)
	}
	if same, _ := render.Objects(after, after); len(same) != 0 {
		t.Fatal(same)
	}
	files, _ := render.ChangedFiles(filepath.Join(tmp, "b"), filepath.Join(tmp, "a"))
	if !reflect.DeepEqual(files, []string{"web.yaml"}) {
		t.Fatal(files)
	}
}

func envFor(t *testing.T, tmp string, event any) map[string]string {
	if event == nil {
		event = map[string]any{"ref": "refs/heads/main"}
	}
	raw, _ := json.Marshal(event)
	p := filepath.Join(tmp, "event.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"GITHUB_REPOSITORY": "jfillman/Clearance-Deploy-Scratch", "GITHUB_SHA": rhead, "GITHUB_ACTOR": "jfillman",
		"GITHUB_EVENT_PATH": p, "ACTIONS_ID_TOKEN_REQUEST_URL": "https://x/token?v=1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req"}
}

func argsFor(t *testing.T, tmp string, extra ...string) []string {
	return append([]string{"--url", "https://clearance.example", "--app", "deploy-scratch", "--env", "Prod", "--cluster", "hangar-dev",
		"--before", write(t, filepath.Join(tmp, "b"), "2", strings.Repeat("1", 64), ""),
		"--after", write(t, filepath.Join(tmp, "a"), "3", strings.Repeat("1", 64), "")}, extra...)
}

type sent struct {
	url, token string
	body       map[string]any
}

func capture(s *sent, status int, reply map[string]any) poster {
	return func(_ context.Context, url, token string, body []byte) (int, map[string]any, error) {
		s.url, s.token = url, token
		_ = json.Unmarshal(body, &s.body)
		return status, reply, nil
	}
}

func fetchFor(_ context.Context, _ map[string]string, aud string) (string, error) {
	return "oidc-for-" + aud, nil
}

func runRegister(t *testing.T, args []string, env map[string]string, post poster, fetch tokenFetcher) (int, string, string) {
	var out, errb bytes.Buffer
	code := registerMain(context.Background(), args, env, post, fetch, &out, &errb)
	return code, out.String(), errb.String()
}

func TestTheBodyComesFromTheActionsEnvironmentAndIsAValidChange(t *testing.T) {
	tmp := t.TempDir()
	var s sent
	code, out, _ := runRegister(t, argsFor(t, tmp, "--check", "ci=pass"), envFor(t, tmp, nil),
		capture(&s, 200, map[string]any{"id": "ch-1", "state": "cleared", "tier": json.Number("1"), "cleared_by": "policy"}), fetchFor)
	b := s.body
	if code != exitCleared || s.token != "oidc-for-clearance" || out != "ch-1 cleared tier 1 cleared_by policy\n" {
		t.Fatal(code, s.token, out)
	}
	if b["repo"] != rrepo || b["head"] != rhead || b["pr"] != 0.0 || b["env"] != "prod" || b["proposer"] != "user:jfillman" {
		t.Fatal(b)
	}
	if !reflect.DeepEqual(b["checks"], map[string]any{"render": "ok", "ci": "pass"}) ||
		!reflect.DeepEqual(b["objects"].([]any)[0].(map[string]any)["fields"], []any{"/spec/replicas"}) {
		t.Fatal(b)
	}
}

func TestAPullRequestEventNamesItsPrAndHead(t *testing.T) {
	tmp := t.TempDir()
	var s sent
	ev := map[string]any{"pull_request": map[string]any{"number": 12, "head": map[string]any{"sha": strings.Repeat("b", 40)}, "base": map[string]any{"sha": strings.Repeat("c", 40)}}}
	runRegister(t, argsFor(t, tmp), envFor(t, tmp, ev), capture(&s, 200, map[string]any{"state": "cleared"}), fetchFor)
	if s.body["pr"] != 12.0 || s.body["head"] != strings.Repeat("b", 40) || s.body["base"] != strings.Repeat("c", 40) {
		t.Fatal(s.body)
	}
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		status int
		reply  map[string]any
		code   int
		stdout string
		stderr string
	}{
		{200, map[string]any{"id": "ch-1", "state": "holding", "tier": json.Number("2"), "requirement": map[string]any{"owner": json.Number("1"), "ownerGroup": "group:default/admins"}},
			exitHolding, "ch-1 holding tier 2\nholding for people: 1 from group:default/admins\n", ""},
		{200, map[string]any{"id": "ch-1", "state": "holding", "tier": json.Number("3"), "requirement": map[string]any{"owner": json.Number("1"), "ownerGroup": "group:a/b", "outside": json.Number("1"), "outsideGroups": []any{"group:default/admins"}}},
			exitHolding, "ch-1 holding tier 3\nholding for people: 1 from group:a/b, 1 from group:default/admins\n", ""},
		{200, map[string]any{"id": "ch-1", "state": "denied", "tier": json.Number("3"), "deny_reason": "loosens"}, exitDenied, "ch-1 denied tier 3\n", "denied: loosens\n"},
		{403, map[string]any{"error": "may register changes for x only", "rule": "DG-REPO"}, exitDenied, "", "clearance register: refused (403) DG-REPO may register changes for x only\n"},
		{400, map[string]any{"error": "head is missing or malformed"}, exitDenied, "", "clearance register: refused (400)  head is missing or malformed\n"},
	}
	for _, c := range cases {
		tmp := t.TempDir()
		var s sent
		code, out, errs := runRegister(t, argsFor(t, tmp), envFor(t, tmp, nil), capture(&s, c.status, c.reply), fetchFor)
		if code != c.code || out != c.stdout || errs != c.stderr {
			t.Errorf("%v: %d %q %q", c.reply, code, out, errs)
		}
	}
}

func TestNoOidcPermissionIsAUsageErrorAndDryRunSendsNothing(t *testing.T) {
	tmp := t.TempDir()
	env := envFor(t, tmp, nil)
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_URL")
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	never := func(context.Context, string, string, []byte) (int, map[string]any, error) {
		t.Fatal("sent")
		return 0, nil, nil
	}
	code, _, errs := runRegister(t, argsFor(t, tmp), env, never, actionsToken)
	if code != exitUsage || !strings.Contains(errs, "id-token: write") {
		t.Fatal(code, errs)
	}
	code, out, _ := runRegister(t, argsFor(t, tmp, "--dry-run"), env, never, actionsToken)
	var b map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &b) != nil || b["app"] != "deploy-scratch" || !strings.Contains(out, "\n  \"app\": ") {
		t.Fatal(code, out)
	}
}

func TestATokenFileReplacesTheOidcToken(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "tok")
	_ = os.WriteFile(f, []byte("file-token\n"), 0o600)
	var s sent
	noFetch := func(context.Context, map[string]string, string) (string, error) { t.Fatal("fetched"); return "", nil }
	runRegister(t, argsFor(t, tmp, "--token-file", f), envFor(t, tmp, nil), capture(&s, 200, map[string]any{"state": "cleared"}), noFetch)
	if s.token != "file-token" {
		t.Fatal(s.token)
	}
}

func TestPostNamesItselfAndReportsARefusalFromInFrontOfClearance(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.WriteHeader(403)
		_, _ = w.Write([]byte("error code: 1010"))
	}))
	defer srv.Close()
	status, out, err := postChange(context.Background(), srv.URL, "t", []byte("{}"))
	if err != nil || !strings.HasPrefix(ua, "clearance-register") || status != 403 || out["error"] != "not from Clearance: error code: 1010" {
		t.Fatal(ua, status, out, err)
	}
}

func TestUsageErrors(t *testing.T) {
	tmp := t.TempDir()
	for _, args := range [][]string{
		{"--app", "x"}, // required flags missing
		argsFor(t, tmp, "--proposer-kind", "robot"),
		argsFor(t, tmp, "--check", "nonsense"),
		argsFor(t, tmp, "--pr", "seven"),
		argsFor(t, tmp, "stray"),
		argsFor(t, tmp, "--paths-from-git", "--base", strings.Repeat("c", 40)), // the Go binary never shells out to git
		argsFor(t, tmp, "--repo", "not a repo"),                                // the gate's own validation
	} {
		code, _, _ := runRegister(t, args, envFor(t, tmp, nil), func(context.Context, string, string, []byte) (int, map[string]any, error) {
			t.Fatal("sent", args)
			return 0, nil, nil
		}, fetchFor)
		if code != exitUsage {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	if code, _, _ := runRegister(t, []string{"-h"}, nil, nil, nil); code != 0 {
		t.Fatal("help exits 0")
	}
}

func TestTheActionsTokenIsFetchedForTheAudience(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery + " " + r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"value": "the-token"}`))
	}))
	defer srv.Close()
	tok, err := actionsToken(context.Background(), map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": srv.URL + "/t?v=1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req"}, "clearance")
	if err != nil || tok != "the-token" || got != "v=1&audience=clearance Bearer req" {
		t.Fatal(tok, got, err)
	}
}

// The body binds the change to the rendered tree: treeDigest is the manifest-tree digest of --after (docs/gate.md,
// The manifest-tree digest), not a placeholder; an --after with no manifests is refused before anything is sent.
func TestTheTreeDigestIsTheManifestTreeOfAfter(t *testing.T) {
	tmp := t.TempDir()
	var s sent
	runRegister(t, argsFor(t, tmp), envFor(t, tmp, nil), capture(&s, 200, map[string]any{"state": "cleared"}), fetchFor)
	after, err := render.LoadDir(filepath.Join(tmp, "a"))
	if err != nil || len(after) != 1 {
		t.Fatal(after, err)
	}
	if got := s.body["treeDigest"]; got != render.TreeDigest(after) || got == strings.Repeat("0", 64) {
		t.Fatalf("treeDigest %v, want %s", got, render.TreeDigest(after))
	}
	empty := filepath.Join(tmp, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	args := []string{"--app", "web", "--env", "prod", "--cluster", "hangar-dev", "--after", empty}
	code, _, errOut := runRegister(t, args, envFor(t, tmp, nil), func(context.Context, string, string, []byte) (int, map[string]any, error) {
		t.Fatal("sent a change with no tree")
		return 0, nil, nil
	}, fetchFor)
	if code != exitUsage || !strings.Contains(errOut, "holds no manifests") {
		t.Fatal(code, errOut)
	}
	file := filepath.Join(tmp, "a", "web.yaml") // a file, not a directory: once read as an empty tree
	args = []string{"--app", "web", "--env", "prod", "--cluster", "hangar-dev", "--after", file}
	code, _, errOut = runRegister(t, args, envFor(t, tmp, nil), func(context.Context, string, string, []byte) (int, map[string]any, error) {
		t.Fatal("sent a change with no tree")
		return 0, nil, nil
	}, fetchFor)
	if code != exitUsage || !strings.Contains(errOut, "not a directory") {
		t.Fatal(code, errOut)
	}
}
