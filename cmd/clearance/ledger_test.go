package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLedgerKeygenWritesTheSecretToAFileAndPrintsOnlyThePublicKey(t *testing.T) {
	out := filepath.Join(t.TempDir(), "log.key")
	var stdout, stderr bytes.Buffer
	if rc := ledgerKeygen(context.Background(), []string{"--name", "clearance-ledger", "--out", out}, &stdout, &stderr); rc != 0 {
		t.Fatalf("%d %s", rc, stderr.String())
	}
	secret, err := os.ReadFile(out)
	if err != nil || !strings.HasPrefix(string(secret), "PRIVATE+KEY+clearance-ledger+") {
		t.Fatalf("%v", err)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if strings.Contains(stdout.String()+stderr.String(), "PRIVATE+KEY") || !strings.HasPrefix(stdout.String(), "clearance-ledger+") {
		t.Fatalf("stdout %q stderr %q", stdout.String(), stderr.String())
	}
	// It never replaces a key.
	if rc := ledgerKeygen(context.Background(), []string{"--name", "x", "--out", out}, &stdout, &stderr); rc == 0 {
		t.Fatal("replaced an existing key file")
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, secret) {
		t.Fatal("the key file changed")
	}
	stdout.Reset()
	w := filepath.Join(t.TempDir(), "w.key")
	if rc := ledgerKeygen(context.Background(), []string{"--name", "w", "--out", w, "--witness"}, &stdout, &stderr); rc != 0 {
		t.Fatal(stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "w+") {
		t.Fatal(stdout.String())
	}
}
