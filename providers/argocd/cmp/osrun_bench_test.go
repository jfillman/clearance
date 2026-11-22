package main

import (
	"context"
	"testing"
)

// BenchmarkOSRunStep is one render step through OSRun (the real process start; the tool is `true`).
func BenchmarkOSRunStep(b *testing.B) {
	dir := b.TempDir()
	for i := 0; i < b.N; i++ {
		if _, err := OSRun(context.Background(), dir, nil, "true"); err != nil {
			b.Fatal(err)
		}
	}
}
