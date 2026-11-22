package main

import (
	"os"
	"testing"
)

// TestMain lets the test binary stand in for clearance-cmp when OSRun re-executes itself as the sandbox shim, and for a
// misbehaving tool (CMP_TEST_HOG) in the limit tests.
func TestMain(m *testing.M) {
	maybeShim()
	switch os.Getenv("CMP_TEST_HOG") {
	case "memory": // a step that keeps allocating: the Go runtime fails at the data-segment bound
		var keep [][]byte
		for i := 0; i < 16; i++ { // 256 MiB
			b := make([]byte, 16<<20)
			for j := 0; j < len(b); j += 4096 {
				b[j] = 1
			}
			keep = append(keep, b)
		}
		os.Stdout.Write([]byte{keep[0][0]})
		os.Exit(0)
	}
	os.Exit(m.Run())
}
