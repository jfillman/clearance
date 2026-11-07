package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/cli"
)

func init() {
	cli.Register(cli.Command{Name: "trust-root build", Summary: "build a Sigstore TrustedRoot JSON from public Fulcio chains and Rekor keys, each with its validity window (--fulcio, --rekor, --out)", Run: trustRootBuild})
}

// entry splits "<path>[,key=value...]" into the path and its options.
func entry(v string, allowed ...string) (string, map[string]string, error) {
	parts := strings.Split(v, ",")
	opts := map[string]string{}
	for _, p := range parts[1:] {
		k, val, ok := strings.Cut(p, "=")
		if !ok || val == "" {
			return "", nil, fmt.Errorf("%q: want key=value", p)
		}
		known := false
		for _, a := range allowed {
			known = known || a == k
		}
		if !known {
			return "", nil, fmt.Errorf("%q: unknown option %q (have %s)", v, k, strings.Join(allowed, ", "))
		}
		opts[k] = val
	}
	if parts[0] == "" {
		return "", nil, fmt.Errorf("%q: no file", v)
	}
	return parts[0], opts, nil
}

func window(o map[string]string) (attest.Window, error) {
	var w attest.Window
	var err error
	if v := o["start"]; v != "" {
		if w.Start, err = time.Parse(time.RFC3339, v); err != nil {
			return w, fmt.Errorf("start: %w", err)
		}
	}
	if v := o["end"]; v != "" {
		if w.End, err = time.Parse(time.RFC3339, v); err != nil {
			return w, fmt.Errorf("end: %w", err)
		}
	}
	return w, nil
}

func trustRootBuild(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust-root build", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var fulcio, rekor repeated
	fs.Var(&fulcio, "fulcio", "a Fulcio chain: <pem>[,uri=<url>][,start=<RFC3339>][,end=<RFC3339>]; the PEM holds the intermediate(s) then the root, or the root alone; repeatable")
	fs.Var(&rekor, "rekor", "a Rekor public key: <pem>[,url=<url>][,start=<RFC3339>][,end=<RFC3339>]; repeatable")
	fulcioURI := fs.String("fulcio-uri", "", "the Fulcio URL for a chain with no uri=")
	rekorURL := fs.String("rekor-url", "", "the Rekor URL for a key with no url=")
	out := fs.String("out", "-", "where to write the TrustedRoot JSON; - for stdout")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: clearance trust-root build --fulcio <chain.pem>[,start=..,end=..]... --rekor <key.pem>[,start=..,end=..]... [--out <file>]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 || len(fulcio) == 0 || len(rekor) == 0 {
		fs.Usage()
		return 2
	}
	fail := func(f string, a ...any) int {
		fmt.Fprintf(stderr, "trust-root build: %s\n", fmt.Sprintf(f, a...))
		return 1
	}
	var cas []attest.BuildCA
	for _, v := range fulcio {
		path, o, err := entry(v, "uri", "start", "end")
		if err != nil {
			return fail("--fulcio %v", err)
		}
		w, err := window(o)
		if err != nil {
			return fail("--fulcio %s: %v", path, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fail("%v", err)
		}
		uri := o["uri"]
		if uri == "" {
			uri = *fulcioURI
		}
		cas = append(cas, attest.BuildCA{URI: uri, PEM: raw, Window: w})
	}
	var logs []attest.BuildLog
	for _, v := range rekor {
		path, o, err := entry(v, "url", "start", "end")
		if err != nil {
			return fail("--rekor %v", err)
		}
		w, err := window(o)
		if err != nil {
			return fail("--rekor %s: %v", path, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fail("%v", err)
		}
		u := o["url"]
		if u == "" {
			u = *rekorURL
		}
		logs = append(logs, attest.BuildLog{BaseURL: u, PEM: raw, Window: w})
	}
	doc, err := attest.BuildTrustedRoot(cas, logs)
	if err != nil {
		return fail("%v", err)
	}
	doc = append(doc, '\n')
	if *out == "-" {
		_, _ = stdout.Write(doc)
		return 0
	}
	if err := os.WriteFile(*out, doc, 0o644); err != nil { // public material
		return fail("%v", err)
	}
	fmt.Fprintf(stderr, "trust-root build: wrote %s (%d Fulcio chain(s), %d Rekor key(s))\n", *out, len(cas), len(logs))
	return 0
}
