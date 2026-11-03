// Package cli is the subcommand registry of the one clearance binary.
//
// Each subcommand lives in its own file under cmd/clearance and registers itself from init(), so packages
// built in parallel never edit the same dispatch table.
package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Command is one subcommand. Name may hold a space for a nested command ("chain verify").
type Command struct {
	Name    string
	Summary string
	Run     func(ctx context.Context, args []string, stdout, stderr io.Writer) int
}

var commands = map[string]Command{}

// Register adds a subcommand; a name registered twice is a programming error.
func Register(c Command) {
	if _, dup := commands[c.Name]; dup {
		panic("clearance: subcommand registered twice: " + c.Name)
	}
	commands[c.Name] = c
}

// Main dispatches args (without the program name) to the longest matching subcommand.
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	for n := min(2, len(args)); n > 0; n-- {
		if c, ok := commands[strings.Join(args[:n], " ")]; ok {
			return c.Run(ctx, args[n:], stdout, stderr)
		}
	}
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintln(w, "usage: clearance <command> [flags]")
	for _, n := range names {
		fmt.Fprintf(w, "  %-22s %s\n", n, commands[n].Summary)
	}
}
