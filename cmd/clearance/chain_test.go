package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const extended = "../../internal/evidence/testdata/go-extended.jsonl"

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := chainVerify(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestChainVerifyFile(t *testing.T) {
	code, out, _ := run("--file", extended)
	if code != 0 || out != "ok 8 head 0715e32f906cb7fea89e530e627e0ba2d92ef7d9dff09cc287d9f35deecb1f1c\n" {
		t.Fatalf("code %d out %q", code, out)
	}
	raw, err := os.ReadFile(extended)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	// One byte changed in record 5.
	lines[5] = strings.Replace(lines[5], `"tool":"model.call"`, `"tool":"model.calm"`, 1)
	bad := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(bad, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run("--file", bad); code != 1 || out != "bad seq 5: hash does not match the record\n" {
		t.Fatalf("tampered: code %d out %q", code, out)
	}
	trunc := filepath.Join(t.TempDir(), "trunc.jsonl")
	if err := os.WriteFile(trunc, []byte(strings.Join(lines[:3], "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	anchor := "4:" + "e8b0a2d4f2c1f4dbf8f8a4b4f7e1d0c3b2a1908f7e6d5c4b3a291807f6e5d4c3"
	if code, out, _ := run("--file", trunc, "--anchor", anchor); code != 1 || !strings.HasPrefix(out, "truncated: 3 records, anchored 4") {
		t.Fatalf("truncated: code %d out %q", code, out)
	}
	if code, out, _ := run("--file", extended, "--anchor", anchor); code != 1 || !strings.HasPrefix(out, "history rewritten") {
		t.Fatalf("wrong anchor: code %d out %q", code, out)
	}
}

func TestChainVerifyAnchor(t *testing.T) {
	// Record 3's hash (the Python fixture's head) anchors count 4.
	raw, _ := os.ReadFile("../../internal/evidence/testdata/python-chain.jsonl")
	var head string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		i := strings.Index(l, `"hash": "`)
		head = l[i+9 : i+9+64]
	}
	if code, out, _ := run("--file", extended, "--anchor", "4:"+head); code != 0 || !strings.HasPrefix(out, "ok 8 ") {
		t.Fatalf("code %d out %q", code, out)
	}
}

func TestChainVerifyUsage(t *testing.T) {
	t.Setenv("CLEARANCE_DSN", "")
	for _, args := range [][]string{{}, {"--file", "a", "--dsn", "b"}, {"--file", extended, "--anchor", "x"}} {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: code %d, want 2", args, code)
		}
	}
}
