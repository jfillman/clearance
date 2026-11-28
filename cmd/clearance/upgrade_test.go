package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpgradeCheckFromFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cur := write("current.json", `{"core":"v0.58.0","schema":{"version":1,"min_core":"0.0.0","no_rollback":false,"migrations":[]},"compat":{"format":1,"releases":[]}}`)
	tab := write("compat.json", `{"format":1,"releases":[
	  {"core":"0.58.0","schema_version":1,"min_core":"0.0.0","no_rollback":false},
	  {"core":"0.60.0","schema_version":2,"min_core":"0.60.0","no_rollback":true,"providers":{"observe-k8s":{"min":"0.59.0"}}}]}`)
	notes := write("notes.md", "### Changed\n\n- **no-rollback**: migration 2 (drop-legacy) drops a column.\n- unrelated line\n")
	var out, errb bytes.Buffer
	code := upgradeCheck(context.Background(), []string{"--to", "v0.60.0", "--current-file", cur, "--compat", tab, "--notes", notes,
		"--provider", "observe-k8s=0.58.0"}, &out, &errb)
	if code != 0 {
		t.Fatalf("%d %s %s", code, out.String(), errb.String())
	}
	for _, want := range []string{"upgrade 0.58.0 -> 0.60.0", "NO ROLLBACK: 0.60.0", "provider observe-k8s: observe-k8s 0.58.0 is older than 0.59.0",
		"schema 1 -> 2", "migration 2 (drop-legacy)", "doctor: not run"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "unrelated line") {
		t.Error("an unrelated note line was printed")
	}
	// Negative: a target older than the schema blocks, exit 1.
	out.Reset()
	cur2 := write("current2.json", `{"core":"0.60.0","schema":{"version":2,"min_core":"0.60.0","no_rollback":true,"migrations":[]},"compat":{"format":1,"releases":[]}}`)
	if code := upgradeCheck(context.Background(), []string{"--to", "0.58.0", "--current-file", cur2, "--compat", tab, "--notes", notes}, &out, &errb); code != 1 || !strings.Contains(out.String(), "BLOCKED") {
		t.Fatalf("%d %s", code, out.String())
	}
	if code := upgradeCheck(context.Background(), []string{"--to", "nope"}, &out, &errb); code != 2 {
		t.Fatalf("usage: %d", code)
	}
}

func TestUpgradeCheckLive(t *testing.T) {
	dir := t.TempDir()
	tab := filepath.Join(dir, "compat.json")
	notes := filepath.Join(dir, "notes.md")
	for p, s := range map[string]string{
		tab:   `{"format":1,"releases":[{"core":"0.58.0","schema_version":1,"min_core":"0.0.0","no_rollback":false}]}`,
		notes: "- migration 1 is the baseline\n",
	} {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A core from before N-6 has no /v1/version: the operator names its release, and the schema reads as unversioned.
	old := httptest.NewServer(http.NotFoundHandler())
	defer old.Close()
	var out, errb bytes.Buffer
	args := []string{"--to", "0.58.0", "--url", old.URL, "--compat", tab, "--notes", notes}
	if code := upgradeCheck(context.Background(), args, &out, &errb); code != 1 || !strings.Contains(errb.String(), "--current-core") {
		t.Fatalf("no /v1/version, no --current-core: %d %s", code, errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := upgradeCheck(context.Background(), append(args, "--current-core", "v0.57.3"), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "schema 0 -> 1") || !strings.Contains(out.String(), "upgrade 0.57.3 -> 0.58.0") {
		t.Fatalf("%d %s %s", code, out.String(), errb.String())
	}
	// A core that answers: the bearer token goes only over https or loopback.
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"core":"0.58.0","compat":{"format":1,"releases":[]}}`))
	}))
	defer srv.Close()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := upgradeCheck(context.Background(), []string{"--to", "v0.58.0", "--url", srv.URL, "--token-file", tok, "--compat", tab, "--notes", notes}, &out, &errb); code != 0 || auth != "Bearer secret-token" {
		t.Fatalf("loopback: %d %q %s", code, auth, errb.String())
	}
	// Not loopback, not https: refused before anything is sent.
	auth = ""
	plain := strings.Replace(srv.URL, "127.0.0.1", "example.com", 1)
	errb.Reset()
	if code := fetchErr(plain, tok); code == nil || auth != "" {
		t.Fatalf("a token over plain http to a remote host was not refused (%v, %q)", code, auth)
	}
}

func fetchErr(url, tokenFile string) error {
	_, err := fetchVersion(context.Background(), url+"/v1/version", tokenFile)
	return err
}
