package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/token"
)

func init() {
	cli.Register(cli.Command{Name: "attest verify", Summary: "verify a change attestation bundle offline (--file, --subject, --key or --trust-root)", Run: attestVerify})
}

// repeated is a flag that may be given more than once.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

func attestVerify(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attest verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "-", "the bundle (GET /v1/clearances/{id}/attestation) or a bare DSSE envelope; - for stdin")
	keyFile := fs.String("key", "", "static key: the signing key's public half (PEM) or the core's JWKS (GET /v1/keys)")
	roots := fs.String("trust-root", "", "keyless: the Fulcio root and intermediate certificates to trust (PEM), or a Sigstore TrustedRoot JSON from `clearance trust-root build` (then Rekor's key comes from it, not --rekor-key)")
	identity := fs.String("identity", "", "keyless: the identity the certificate must name (its SAN), e.g. the core's OIDC subject")
	issuer := fs.String("issuer", "", "keyless: the OIDC issuer the certificate must record")
	rekorKey := fs.String("rekor-key", "", "Rekor's public key (PEM): checks the log entry; required for keyless")
	var subjects repeated
	fs.Var(&subjects, "subject", "a digest the statement must name as a subject, <alg>:<hex> (sha256:..., gitCommit:...); repeatable")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: clearance attest verify [--file <bundle>] [--subject sha256:<hex>]... "+
			"(--key <pem|jwks> | --trust-root <pem|trusted-root.json> --identity <id> --issuer <url> [--rekor-key <pem>])")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 || (*keyFile == "") == (*roots == "") {
		fs.Usage()
		return 2
	}
	fail := func(f string, a ...any) int {
		fmt.Fprintf(stderr, "attest verify: FAILED: "+f+"\n", a...)
		return 1
	}
	var raw []byte
	var err error
	if *file == "-" {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, token.MaxEnvelopeBytes+1))
	} else {
		raw, err = readCapped(*file)
	}
	if err != nil {
		return fail("%v", err)
	}
	opts := attest.VerifyOptions{Subjects: subjects, Identity: *identity, Issuer: *issuer}
	read := func(path string) ([]byte, bool) {
		b, err := readCapped(path)
		if err != nil {
			fail("%v", err)
			return nil, false
		}
		return b, true
	}
	if *keyFile != "" {
		b, ok := read(*keyFile)
		if !ok {
			return 1
		}
		if opts.Keys, err = attest.ParseKeys(b); err != nil {
			return fail("--key: %v", err)
		}
	}
	if *roots != "" {
		b, ok := read(*roots)
		if !ok {
			return 1
		}
		if strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
			if *rekorKey != "" {
				return fail("--rekor-key: not with a TrustedRoot JSON, which carries Rekor's keys")
			}
			if opts.Trust, err = attest.ParseTrustedRoot(b); err != nil {
				return fail("--trust-root: %v", err)
			}
		} else if opts.Roots, err = attest.ParseRoots(b); err != nil {
			return fail("--trust-root: %v", err)
		}
	}
	if *rekorKey != "" {
		b, ok := read(*rekorKey)
		if !ok {
			return 1
		}
		if opts.RekorKey, err = attest.ParseRekorKey(b); err != nil {
			return fail("--rekor-key: %v", err)
		}
	}
	res, err := attest.Verify(raw, opts)
	if err != nil {
		return fail("%v", err)
	}
	st := res.Statement
	fmt.Fprintf(stdout, "ok: %s attestation of change %s (tier %d, app %s/%s)\n", res.Mode, st.Predicate.Clearance.ID,
		st.Predicate.Tier, st.Predicate.Target.Cluster, st.Predicate.Target.App)
	fmt.Fprintf(stdout, "envelope %s\n", res.Digest)
	if res.Identity != "" {
		fmt.Fprintf(stdout, "signed by %s (issuer %s)\n", res.Identity, res.Issuer)
	}
	if res.KeyID != "" {
		fmt.Fprintf(stdout, "signed by key %s\n", res.KeyID)
	}
	if res.LogVerified {
		fmt.Fprintf(stdout, "rekor entry %d verified\n", *res.LogIndex)
	} else {
		fmt.Fprintln(stdout, "not checked against a Rekor entry")
	}
	for _, s := range st.Subject {
		fmt.Fprintf(stdout, "subject %s %v\n", s.Name, s.Digest)
	}
	return 0
}

// readCapped reads a file of at most token.MaxEnvelopeBytes.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, token.MaxEnvelopeBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > token.MaxEnvelopeBytes {
		return nil, fmt.Errorf("%s is over %d bytes", path, token.MaxEnvelopeBytes)
	}
	return b, nil
}
