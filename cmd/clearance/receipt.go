package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/assurance"
	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/receipt"
)

// The recipient's commands (P-1, docs/assurance.md): for a firm that has no system to pull a packet and sign a receipt
// from. No Clearance account, no sign-in: the credential the subscriber handed over and the firm's own key.

// credentialEnv is where `receipt pull` reads the credential when --credential-file is not given: a credential on a
// command line is in shell history and in `ps`.
const credentialEnv = "CLEARANCE_PACKET_CREDENTIAL"

func init() {
	cli.Register(cli.Command{Name: "receipt pull", Summary: "recipient: read a packet under the credential a subscriber gave you and unpack it (no account)", Run: receiptPull})
	cli.Register(cli.Command{Name: "receipt sign", Summary: "recipient: sign an acceptance receipt for a packet you were given, with your own key (offline)", Run: receiptSign})
	cli.Register(cli.Command{Name: "receipt submit", Summary: "recipient: send a signed receipt to the core that holds the packet (no account: the signature is the proof)", Run: receiptSubmit})
}

func readCredential(file string, stdin io.Reader) (string, error) {
	var raw []byte
	var err error
	switch {
	case file == "-":
		raw, err = io.ReadAll(io.LimitReader(stdin, 8192))
	case file != "":
		raw, err = os.ReadFile(file)
	default:
		return strings.TrimSpace(os.Getenv(credentialEnv)), nil
	}
	return strings.TrimSpace(string(raw)), err
}

func receiptPull(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("receipt pull", flag.ContinueOnError)
	fs.SetOutput(stderr)
	core := fs.String("core", os.Getenv("CLEARANCE_URL"), "the core's URL (default $CLEARANCE_URL)")
	id := fs.String("packet", "", "the packet id (pk-...), from the subscriber")
	credFile := fs.String("credential-file", "", "a file holding the credential (- for stdin; default $"+credentialEnv+"): never a flag value")
	part := fs.String("part", "", "read one part only: summary or evidence (it must be in the credential's scope)")
	out := fs.String("out", "", "the directory to unpack the packet into (new or empty)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *core == "" || !packet.ValidID(*id) || *out == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: clearance receipt pull --core <url> --packet <pk-id> --out <dir> [--credential-file <file>|-] [--part summary|evidence]")
		return 2
	}
	cred, err := readCredential(*credFile, os.Stdin)
	if err != nil || cred == "" {
		fmt.Fprintln(stderr, "receipt pull: no credential: give --credential-file (or - for stdin) or set "+credentialEnv)
		return 2
	}
	b, err := (&assurance.Client{Base: *core}).Pull(ctx, *id, cred, *part)
	if err != nil {
		fmt.Fprintln(stderr, "receipt pull:", err)
		return 1
	}
	if err := b.Unpack(*out); err != nil {
		fmt.Fprintln(stderr, "receipt pull:", err)
		return 1
	}
	fmt.Fprintf(stdout, "packet %s (digest %s): %d files in %s\nverify it with: clearance verify %s\n", b.ID, b.Digest, len(b.Files), *out, *out)
	return 0
}

func receiptSign(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("receipt sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var notes listFlag
	dir := fs.String("packet-dir", "", "the packet directory you were given (it must hold packet.json)")
	delivery := fs.String("delivery", "", "the delivery id the subscriber gave you (dl-...)")
	recipient := fs.String("recipient", "", "your registered recipient name")
	engagement := fs.String("engagement", "", "your name for the review (an engagement, a questionnaire, a ticket)")
	verdict := fs.String("verdict", "", "accepted, accepted-with-notes, questioned or rejected")
	fs.Var(&notes, "note", "a control note, <row id>=<text>, keyed to a control or assertion id of the packet's mappings (repeatable)")
	key := fs.String("key", "", "your ECDSA P-256 private key (PEM): the key you registered with the subscriber")
	out := fs.String("out", "", "write the signed receipt here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" || *delivery == "" || *recipient == "" || *engagement == "" || *verdict == "" || *key == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: clearance receipt sign --packet-dir <dir> --delivery <dl-id> --recipient <name> --engagement <text> --verdict <v> --key <pem> [--note row=text]... [--out file]")
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "receipt sign:", err)
		return 1
	}
	b, err := packet.ReadDir(*dir)
	if err != nil {
		return fail(err)
	}
	nm := map[string]string{}
	for _, n := range notes {
		k, v, ok := strings.Cut(n, "=")
		if !ok || k == "" || v == "" {
			return fail(fmt.Errorf("--note %q is <row id>=<text>", n))
		}
		nm[k] = v
	}
	signer, err := loadSigner(*key)
	if err != nil {
		return fail(err)
	}
	p, err := assurance.Payload(b, assurance.Review{Delivery: *delivery, Recipient: *recipient, Engagement: *engagement, Verdict: *verdict, Notes: nm, Now: time.Now()})
	if err != nil {
		return fail(err)
	}
	env, err := receipt.Sign(ctx, signer, p)
	if err != nil {
		return fail(err)
	}
	if *out == "" {
		fmt.Fprintln(stdout, string(env))
		return 0
	}
	if err := os.WriteFile(*out, append(env, '\n'), 0o644); err != nil {
		return fail(err)
	}
	fmt.Fprintf(stdout, "signed %s for packet %s with key %s: %s\n", *verdict, b.ID, signer.KeyID(), *out)
	return 0
}

func receiptSubmit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("receipt submit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	core := fs.String("core", os.Getenv("CLEARANCE_URL"), "the core's URL (default $CLEARANCE_URL)")
	file := fs.String("receipt", "", "the signed receipt (from `clearance receipt sign`)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *core == "" || *file == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: clearance receipt submit --core <url> --receipt <file>")
		return 2
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintln(stderr, "receipt submit:", err)
		return 1
	}
	pl, err := receipt.Read(raw)
	if err != nil {
		fmt.Fprintln(stderr, "receipt submit:", err)
		return 1
	}
	rec, err := (&assurance.Client{Base: *core}).Submit(ctx, pl.PacketID, raw)
	if err != nil {
		fmt.Fprintln(stderr, "receipt submit:", err)
		return 1
	}
	fmt.Fprintf(stdout, "recorded %s for packet %s from %s: record %d (%s)\n", rec.Verdict, rec.PacketID, rec.Recipient, rec.Seq, rec.Hash)
	return 0
}
