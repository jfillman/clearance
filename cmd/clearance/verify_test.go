package main

import (
	"os"
	"strings"
	"testing"
)

func TestVerifyIsRegisteredAndRefusesWhatItCannotRead(t *testing.T) {
	if code, _, errs := runCLI("verify"); code != 2 || !strings.Contains(errs, "usage: clearance verify") {
		t.Fatalf("%d %q", code, errs)
	}
	if code, _, errs := runCLI("verify", "/does/not/exist"); code != 2 || !strings.Contains(errs, "not a packet directory") {
		t.Fatalf("%d %q", code, errs)
	}
	// An empty directory is not a packet: it fails, it does not pass.
	dir := t.TempDir()
	code, out, _ := runCLI("verify", dir, "--no-seen")
	if code != 1 || !strings.Contains(out, "FAILED") || !strings.Contains(out, "MANIFEST.json") {
		t.Fatalf("%d %s", code, out)
	}
	if _, err := os.Stat(dir + "/MANIFEST.json"); err == nil {
		t.Fatal("the verifier wrote into the packet")
	}
}
