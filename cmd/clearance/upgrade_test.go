package main

import (
	"bytes"
	"context"
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
