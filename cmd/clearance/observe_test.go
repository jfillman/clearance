package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const corpusDir = "../../internal/observe/pipeline/testdata"

func replayCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := observeReplay(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestObserveReplayPrintsTheGoldenReport(t *testing.T) {
	code, out, errs := replayCLI("--lookups", corpusDir+"/lookups.json", corpusDir+"/aws.jsonl")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	want, err := os.ReadFile(corpusDir + "/aws.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if json.Unmarshal([]byte(out), &a) != nil || json.Unmarshal(want, &b) != nil {
		t.Fatal("not JSON")
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if !bytes.Equal(x, y) || len(x) < 1000 {
		t.Fatal("the command's report is not the golden one")
	}
}

func TestObserveReplaySummary(t *testing.T) {
	code, out, errs := replayCLI("--summary", "--lookups", corpusDir+"/lookups.json", corpusDir+"/kubernetes.jsonl")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	for _, want := range []string{"filtered: 3 events under rule argo-application-bookkeeping", "monitoring-protection", "health prod-eu-1: blind", "(2 events, reverted)"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
}

func TestObserveReplayRefusesABadBundleAndBadUsage(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(bad, []byte("schema: clearance.observe-rules/v1\nname: x\nversion: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := replayCLI("--rules", bad, corpusDir+"/aws.jsonl"); code != 1 || !strings.Contains(errs, "observe rules") {
		t.Fatalf("%d %s", code, errs)
	}
	if code, _, _ := replayCLI(); code != 2 {
		t.Fatal("usage")
	}
	if code, _, _ := replayCLI(corpusDir + "/nosuch.jsonl"); code != 1 {
		t.Fatal("a missing file")
	}
}
