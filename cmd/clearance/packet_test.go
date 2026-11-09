package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
)

func packetChainFile(t *testing.T) string {
	t.Helper()
	st := memory.New()
	defer st.Close()
	ctx := context.Background()
	err := st.Atomic(ctx, func(tx store.Tx) error {
		for _, ev := range []store.Event{
			{"ts": "2026-11-02T10:00:00Z", "tool": "repo.pr.open", "boundary": "runtime", "principal": "autopilot-runs/x", "agent": "x", "decision": "allow",
				"args_sha256": strings.Repeat("0", 64), "result": "ok"},
			{"ts": "2026-11-03T10:00:00Z", "tool": "repo.pr.merge", "boundary": "runtime", "principal": "autopilot-runs/x", "agent": "x", "decision": "deny",
				"rule": "R006", "args_sha256": strings.Repeat("1", 64), "result": "no"},
		} {
			if _, err := tx.Append(ctx, ev, evidence.Core("test")); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := st.Records(ctx, 0, 10)
	var b bytes.Buffer
	for _, r := range recs {
		c, _ := canon.Canonical(r)
		b.Write(c)
		b.WriteByte('\n')
	}
	f := filepath.Join(t.TempDir(), "chain.jsonl")
	if err := os.WriteFile(f, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPacketCommandWritesAllThreeForms(t *testing.T) {
	chain := packetChainFile(t)
	out := filepath.Join(t.TempDir(), "p")
	var so, se bytes.Buffer
	rc := packetRun(context.Background(), []string{"--file", chain, "--from", "2026-11-01", "--to", "2026-11-08", "--scope", "aws-1", "--out", out, "--title", "t"}, &so, &se)
	if rc != 0 {
		t.Fatalf("%d %s", rc, se.String())
	}
	if !strings.Contains(so.String(), "NOT verified") || !strings.Contains(so.String(), "2 records") {
		t.Fatalf("%q", so.String())
	}
	for _, f := range []string{"packet.json", "packet.pdf", "csv/coverage.csv", "evidence/records.jsonl", "oscal/component-definition.json", "MANIFEST.json"} {
		if st, err := os.Stat(filepath.Join(out, f)); err != nil || st.Size() == 0 {
			t.Errorf("%s: %v", f, err)
		}
	}
	// It does not write into a packet that exists, and rejects bad flags.
	if rc := packetRun(context.Background(), []string{"--file", chain, "--out", out}, &so, &se); rc == 0 {
		t.Error("wrote over a packet")
	}
	for _, args := range [][]string{{}, {"--file", chain}, {"--file", chain, "--out", t.TempDir() + "/x", "--view", "nope"}, {"--file", chain, "--out", t.TempDir() + "/y", "--from", "yesterday"},
		{"--file", chain, "--out", t.TempDir() + "/z", "--format", "doc"}} {
		if rc := packetRun(context.Background(), args, &so, &se); rc == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
}

func TestPacketOSCALCommand(t *testing.T) {
	out := t.TempDir()
	var so, se bytes.Buffer
	if rc := packetOSCAL(context.Background(), []string{"--out", out, "--mapping", "soc2/2017"}, &so, &se); rc != 0 || !strings.Contains(so.String(), "unsigned") {
		t.Fatalf("%d %s %s", rc, so.String(), se.String())
	}
	b, err := os.ReadFile(filepath.Join(out, "component-definition.json"))
	if err != nil || !strings.Contains(string(b), "CC8.1") || strings.Contains(string(b), "CC7.1") {
		t.Fatalf("%v %s", err, b)
	}
	if rc := packetOSCAL(context.Background(), []string{"--out", out, "--mapping", "nope/1"}, &so, &se); rc == 0 {
		t.Error("unknown mapping")
	}
}
