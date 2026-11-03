package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store/pg"
)

// maxLine caps one record line in --file mode.
const maxLine = 16 << 20

func init() {
	cli.Register(cli.Command{Name: "chain verify", Summary: "verify the evidence chain (--file <jsonl> or --dsn, read-only)", Run: chainVerify})
}

func chainVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("chain verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "a JSONL dump, one record per line (psql -Atc \"select record::text from clearance_evidence order by seq\"); - for stdin")
	dsn := fs.String("dsn", "", "a Postgres DSN, opened read-only (default $CLEARANCE_DSN when --file is not given)")
	anchor := fs.String("anchor", "", "a checkpoint anchored elsewhere, <count>:<head>: the chain must still hold it")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: clearance chain verify (--file <jsonl> | --dsn <dsn>) [--anchor <count>:<head>]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" && *dsn == "" {
		*dsn = os.Getenv("CLEARANCE_DSN")
	}
	if (*file == "") == (*dsn == "") || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	var want *evidence.Checkpoint
	if *anchor != "" {
		c, h, ok := strings.Cut(*anchor, ":")
		n, err := strconv.ParseInt(c, 10, 64)
		if !ok || err != nil || n < 0 || len(h) != 64 {
			fmt.Fprintln(stderr, "chain verify: --anchor is <count>:<64-hex head>")
			return 2
		}
		want = &evidence.Checkpoint{Count: n, Head: h}
	}
	// Remember the hash at the anchor's position as the chain streams past it.
	var atAnchor string
	each := func(seq int64, hash string) {
		if want != nil && seq == want.Count-1 {
			atAnchor = hash
		}
	}

	var cp evidence.Checkpoint
	var err error
	if *file != "" {
		cp, err = verifyFile(*file, each)
	} else {
		cp, err = verifyDSN(ctx, *dsn, each)
	}
	var bad *evidence.BadRecord
	switch {
	case errors.As(err, &bad):
		fmt.Fprintf(stdout, "bad seq %d: %s\n", bad.Seq, bad.Reason)
		return 1
	case err != nil:
		fmt.Fprintf(stderr, "chain verify: %v\n", err)
		return 1
	}
	if want != nil {
		if ok, msg := evidence.Anchored(cp.Count, func(int64) string { return atAnchor }, *want); !ok {
			fmt.Fprintf(stdout, "%s (ok %d head %s)\n", msg, cp.Count, cp.Head)
			return 1
		}
	}
	fmt.Fprintf(stdout, "ok %d head %s\n", cp.Count, cp.Head)
	return 0
}

// verifyFile streams a JSONL dump. Lines split on "\n" only: canonical JSON and jsonb text both write U+2028 raw.
func verifyFile(path string, each func(int64, string)) (evidence.Checkpoint, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return evidence.Checkpoint{}, err
		}
		defer f.Close()
		r = f
	}
	v := evidence.NewVerifier()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.Trim(line, " \t\r")) == 0 { // a blank line, as AuditLog skips them
			continue
		}
		at := v.Checkpoint().Count
		val, err := canon.Parse(line)
		if err != nil {
			return v.Checkpoint(), &evidence.BadRecord{Seq: at, Reason: err.Error()}
		}
		rec, ok := val.(map[string]any)
		if !ok {
			return v.Checkpoint(), &evidence.BadRecord{Seq: at, Reason: "not a JSON object"}
		}
		if err := v.Add(rec); err != nil {
			return v.Checkpoint(), err
		}
		each(at, v.Checkpoint().Head)
	}
	if err := sc.Err(); err != nil {
		return v.Checkpoint(), fmt.Errorf("record %d: %w", v.Checkpoint().Count, err)
	}
	return v.Checkpoint(), nil
}

func verifyDSN(ctx context.Context, dsn string, each func(int64, string)) (evidence.Checkpoint, error) {
	r, err := pg.OpenReader(ctx, dsn, pg.Options{})
	if err != nil {
		return evidence.Checkpoint{}, err
	}
	defer r.Close()
	return r.Verify(ctx, each)
}
