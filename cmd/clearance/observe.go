package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/internal/vocab"
)

func init() {
	cli.Register(cli.Command{Name: "observe replay", Summary: "run recorded raw events through the observation pipeline (a rule set's test harness; reads nothing but its files)", Run: observeReplay})
}

// observeReplay replays a JSONL file of raw events through the pipeline and prints the report (JSON), or the
// summary lines with --summary. No network, no store, no cluster: the rules, the lookups and the events are files.
func observeReplay(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("observe replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rules := fs.String("rules", "", "a clearance.observe-rules/v1 bundle (default: the build's default rule set)")
	lookups := fs.String("lookups", "", "a JSON file of the grants, break-glass windows, attestations, runs, sessions, plans and apply windows the events are attributed against (default: none known)")
	summary := fs.Bool("summary", false, "print one line per assessment, the filtered lines and the exceptions, not the JSON report")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: clearance observe replay [--rules bundle.yaml] [--lookups lookups.json] [--summary] <events.jsonl | ->")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	b := pipeline.DefaultRules()
	if *rules != "" {
		var err error
		if b, err = os.ReadFile(*rules); err != nil {
			fmt.Fprintln(stderr, "observe replay:", err)
			return 1
		}
	}
	rs, err := pipeline.Load(b)
	if err != nil {
		fmt.Fprintln(stderr, "observe replay:", err) // fail closed: a rule that does not compile or is over its cost limit is no rule set
		return 1
	}
	var lk pipeline.Lookups
	if *lookups != "" {
		lb, err := os.ReadFile(*lookups)
		if err != nil {
			fmt.Fprintln(stderr, "observe replay:", err)
			return 1
		}
		if lk, err = pipeline.LoadLookups(lb, rs); err != nil {
			fmt.Fprintln(stderr, "observe replay:", err)
			return 1
		}
	}
	in := io.Reader(os.Stdin)
	if name := fs.Arg(0); name != "-" {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(stderr, "observe replay:", err)
			return 1
		}
		defer f.Close()
		in = f
	}
	rep, err := pipeline.Replay(in, pipeline.New(rs, lk, vocab.Get()))
	if err != nil {
		fmt.Fprintln(stderr, "observe replay:", err)
		return 1
	}
	if *summary {
		fmt.Fprintf(stdout, "rule set %s@%s (%.12s): %d events, %d assessed, %d not writes\n", rep.RuleSet.Name, rep.RuleSet.Version,
			rep.RuleSet.Digest, rep.Events, len(rep.Assessments), rep.NotWrites)
		for _, a := range rep.Assessments {
			fmt.Fprintf(stdout, "%s  %-9s %-24s tier %d  %-8s %s  [%s]\n", a.EventID, a.Scope, a.Outcome, a.Tier, a.Severity, a.Resource, a.Signal)
		}
		for _, l := range rep.FilteredLines {
			fmt.Fprintln(stdout, l)
		}
		for s, n := range rep.OutOfScope {
			fmt.Fprintf(stdout, "out of scope: %d events in %s\n", n, s)
		}
		for _, e := range rep.Exceptions {
			fmt.Fprintf(stdout, "exception %s %s tier %d %s (%d events, %s)\n", e.ID, e.Kind, e.Tier, e.Resources, len(e.Events), e.Resolution)
		}
		for s, h := range rep.Health {
			fmt.Fprintf(stdout, "health %s: %s\n", s, h)
		}
		return 0
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintln(stderr, "observe replay:", err)
		return 1
	}
	return 0
}
