package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestFederateTraefikHubPrints(t *testing.T) {
	var out, errb bytes.Buffer
	dir := "../../internal/federate/traefikhub/testdata/"
	code := federateTraefikHub(context.Background(), []string{"--hub-log", dir + "lab-hub.log", "--access-log",
		dir + "lab-access.log"}, &out, &errb)
	if code != 0 {
		t.Fatal(code, errb.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines", len(lines))
	}
	var r map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil || r["provider"] != "traefik-hub" ||
		r["kind"] != "federated.decision" {
		t.Fatal(err, r)
	}
	if !strings.Contains(errb.String(), `"records":4`) {
		t.Fatal(errb.String())
	}
}

func TestFederateTraefikHubUsage(t *testing.T) {
	for _, args := range [][]string{{}, {"--hub-log", "x", "--core", "http://c"}, {"--hub-log", "x", "--state", "s"},
		{"--hub-log", "x", "extra"}} {
		var out, errb bytes.Buffer
		if code := federateTraefikHub(context.Background(), args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	var out, errb bytes.Buffer
	if code := federateTraefikHub(context.Background(), []string{"--hub-log", "/nonexistent"}, &out, &errb); code != 1 {
		t.Errorf("missing file: exit %d", code)
	}
}
