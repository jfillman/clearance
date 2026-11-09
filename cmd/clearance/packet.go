package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
	"github.com/jfillman/clearance/internal/store/pg"
	"github.com/jfillman/clearance/internal/token"
)

func init() {
	cli.Register(cli.Command{Name: "packet", Summary: "make an evidence packet for a date range and scope (JSON, CSV, PDF and the originals an offline verifier needs)", Run: packetRun})
	cli.Register(cli.Command{Name: "packet oscal", Summary: "write the control mappings as an OSCAL component definition, signed when --signing-key is given", Run: packetOSCAL})
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func parseWhen(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is an RFC 3339 time or a date (2026-11-01)", s)
	}
	return t, nil
}

func loadSigner(path string) (token.Signer, error) {
	if path == "" {
		return nil, nil
	}
	return token.LoadKeyFile(path)
}

func packetRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("packet", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var scopes, maps listFlag
	dsn := fs.String("dsn", "", "a Postgres DSN, opened read-only (default $CLEARANCE_DSN when --file is not given)")
	file := fs.String("file", "", "a JSONL dump of the chain instead of a database (the lab and the tests)")
	from := fs.String("from", "", "window start, RFC 3339 or a date (default: --days before --to)")
	to := fs.String("to", "", "window end, exclusive, RFC 3339 or a date (default: now)")
	days := fs.Int("days", 30, "the window's length when --from is not given")
	fs.Var(&scopes, "scope", "an observed scope (an account, cluster or workspace); repeatable; none is every scope the chain holds a feed for")
	view := fs.String("view", "packet", "packet, freeze or incident: the freeze and incident reports are scoped views of the same records")
	title := fs.String("title", "", "the freeze's or incident's name, printed in the header")
	app := fs.String("app", "", "narrow the gate's records to one app")
	env := fs.String("env", "", "narrow the gate's records to one environment")
	cluster := fs.String("cluster", "", "narrow the gate's records to one cluster or workspace")
	fs.Var(&maps, "mapping", "a control mapping, framework/version (repeatable; default every mapping the build carries)")
	out := fs.String("out", "", "the directory to write the packet to (new or empty)")
	format := fs.String("format", "json,csv,pdf", "the presentations to write; the originals for offline verification are always written")
	key := fs.String("signing-key", "", "an ECDSA P-256 PEM key file: signs the published OSCAL component definition")
	logKeys := fs.String("ledger-log-keys", "", "a file of the ledger log's public vkeys, one per line (the key in use first): the checkpoint's signatures are checked and the keys are copied into the packet")
	policy := fs.String("ledger-witness-policy", "", "the witness policy file (Tessera's text form): the checkpoint's countersignatures are checked against it and it is copied into the packet")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: clearance packet (--dsn <dsn> | --file <chain.jsonl>) --out <dir> [--from .. --to .. | --days N] [--scope s]... [--view packet|freeze|incident]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" && *dsn == "" {
		*dsn = os.Getenv("CLEARANCE_DSN")
	}
	if (*file == "") == (*dsn == "") || *out == "" || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "packet:", err)
		return 1
	}
	p := packet.Params{Scopes: scopes, View: *view, Title: *title, App: *app, Env: *env, Cluster: *cluster, Mappings: maps, Version: orDev(buildVersion())}
	var err error
	if *to != "" {
		if p.To, err = parseWhen(*to); err != nil {
			return fail(err)
		}
	}
	if *from != "" {
		if p.From, err = parseWhen(*from); err != nil {
			return fail(err)
		}
	} else {
		end := p.To
		if end.IsZero() {
			end = time.Now()
		}
		p.From = end.Add(-time.Duration(*days) * 24 * time.Hour)
	}
	if *logKeys != "" {
		raw, err := os.ReadFile(*logKeys)
		if err != nil {
			return fail(fmt.Errorf("the ledger log keys: %w", err))
		}
		for _, l := range strings.Split(string(raw), "\n") {
			if l, _, _ = strings.Cut(l, "#"); strings.TrimSpace(l) != "" {
				p.LogKeys = append(p.LogKeys, strings.TrimSpace(l))
			}
		}
	}
	if *policy != "" {
		if p.WitnessPolicy, err = os.ReadFile(*policy); err != nil {
			return fail(fmt.Errorf("the witness policy: %w", err))
		}
	}
	signer, err := loadSigner(*key)
	if err != nil {
		return fail(err)
	}

	var r store.Reader
	if *file != "" {
		recs, err := readJSONL(*file)
		if err != nil {
			return fail(err)
		}
		if r, err = memory.Load(recs); err != nil {
			return fail(err)
		}
	} else {
		pr, err := pg.OpenReader(ctx, *dsn, pg.Options{})
		if err != nil {
			return fail(err)
		}
		defer pr.Close()
		r = pr
	}
	res, err := packet.Build(ctx, r, p)
	if err != nil {
		return fail(err)
	}
	m, err := packet.Write(ctx, *out, res, strings.Split(*format, ","), signer)
	if err != nil {
		return fail(err)
	}
	pk := res.Packet
	fmt.Fprintf(stdout, "packet %s %s to %s: %d records, %d exceptions, window %s; %d files in %s\n", pk.Header.View, pk.Header.From, pk.Header.To,
		pk.Coverage.Total, pk.Exceptions.Count, verifiedWord(pk.Coverage.WindowVerified), len(m.Files)+1, filepath.Clean(*out))
	return 0
}

func verifiedWord(v bool) string {
	if v {
		return "verified"
	}
	return "NOT verified"
}

func packetOSCAL(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("packet oscal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var maps listFlag
	out := fs.String("out", "", "the directory to write component-definition.json (and .dsse.json when signed) to")
	key := fs.String("signing-key", "", "an ECDSA P-256 PEM key file: signs the document as a DSSE envelope")
	fs.Var(&maps, "mapping", "a control mapping, framework/version (repeatable; default all)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: clearance packet oscal --out <dir> [--signing-key <pem>] [--mapping soc2/2017]...")
		return 2
	}
	ms, err := packet.SelectMappings(maps)
	if err != nil {
		fmt.Fprintln(stderr, "packet oscal:", err)
		return 1
	}
	doc, err := packet.OSCAL(ms)
	if err != nil {
		fmt.Fprintln(stderr, "packet oscal:", err)
		return 1
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(stderr, "packet oscal:", err)
		return 1
	}
	if err := os.WriteFile(filepath.Join(*out, "component-definition.json"), doc, 0o644); err != nil {
		fmt.Fprintln(stderr, "packet oscal:", err)
		return 1
	}
	signer, err := loadSigner(*key)
	if err != nil {
		fmt.Fprintln(stderr, "packet oscal:", err)
		return 1
	}
	if signer != nil {
		env, err := packet.SignOSCAL(ctx, doc, signer)
		if err != nil {
			fmt.Fprintln(stderr, "packet oscal:", err)
			return 1
		}
		raw, err := json.Marshal(env)
		if err != nil {
			fmt.Fprintln(stderr, "packet oscal:", err)
			return 1
		}
		if err := os.WriteFile(filepath.Join(*out, "component-definition.dsse.json"), raw, 0o644); err != nil {
			fmt.Fprintln(stderr, "packet oscal:", err)
			return 1
		}
		fmt.Fprintf(stdout, "signed with key %s\n", signer.KeyID())
	} else {
		fmt.Fprintln(stdout, "unsigned (no --signing-key)")
	}
	return 0
}

// readJSONL reads a chain dump, one record a line (blank lines skipped; lines split on "\n" only).
func readJSONL(path string) ([]store.Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []store.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.Trim(line, " \t\r")) == 0 {
			continue
		}
		v, err := canon.Parse(line)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", len(out), err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("record %d is not a JSON object", len(out))
		}
		out = append(out, m)
	}
	return out, sc.Err()
}

func orDev(v string) string {
	if v == "" {
		return "dev"
	}
	return v
}
