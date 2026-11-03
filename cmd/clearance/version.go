package main

import (
	"context"
	"fmt"
	"io"
	"runtime/debug"

	"github.com/jfillman/clearance/internal/cli"
)

// version is set at link time by the release build (-ldflags "-X main.version=vX.Y.Z").
var version = ""

func init() {
	cli.Register(cli.Command{Name: "version", Summary: "print the build version", Run: func(_ context.Context, _ []string, out, _ io.Writer) int {
		v := version
		if v == "" {
			if bi, ok := debug.ReadBuildInfo(); ok {
				v = bi.Main.Version
			}
		}
		fmt.Fprintln(out, v)
		return 0
	}})
}
