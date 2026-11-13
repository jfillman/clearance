package personcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// AttestGet is `clearance attest get <change>`: the summary of the change's attestation (the reference
// GET /v1/clearances/{id} carries). `attest download` fetches the bundle itself.
func (e *Env) AttestGet(ctx context.Context, args []string) int {
	s, pos, ee := e.begin("attest get", "<change-id>", args, nil)
	if ee != nil {
		return e.finish("attest get", ee)
	}
	if len(pos) != 1 {
		return e.finish("attest get", s.usageErr())
	}
	return e.finish("attest get", func() error {
		c, err := s.client(false)
		if err != nil {
			return err
		}
		var raw json.RawMessage
		if err := c.Get(ctx, "/v1/clearances/"+url.PathEscape(pos[0]), nil, &raw); err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		at := sub(m, "attestation")
		if at == nil {
			return fail(ExitNotFound, "change %s has no attestation yet (a deploy has not reported an applied outcome)", pos[0])
		}
		doc, _ := json.Marshal(at)
		if wrote, err := emit(e.Stdout, s.format, doc, ""); wrote || err != nil {
			return err
		}
		rows := [][2]string{{"change", str(m, "id")}, {"digest", str(at, "digest")}, {"backend", str(at, "backend")}}
		if v := str(at, "key_id"); v != "" {
			rows = append(rows, [2]string{"key id", v})
		}
		if v := str(at, "rekor_log_index"); v != "" {
			rows = append(rows, [2]string{"rekor log index", v})
		}
		rows = append(rows, [2]string{"signed", str(at, "created_at")}, [2]string{"outcome record", str(at, "outcome_seq")},
			[2]string{"attestation record", str(at, "record_seq")})
		kv(e.Stdout, rows)
		return nil
	}())
}

// fetchBundle reads the attestation bundle verbatim.
func fetchBundle(ctx context.Context, c *Client, id string) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := c.Get(ctx, "/v1/clearances/"+url.PathEscape(id)+"/attestation", nil, &raw); err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == 404 {
			return nil, fail(ExitNotFound, "change %s has no attestation: %s", id, ae.Message)
		}
		return nil, err
	}
	return raw, nil
}

// AttestDownload is `clearance attest download <change> -o file`: the Sigstore bundle, as the api serves it.
func (e *Env) AttestDownload(ctx context.Context, args []string) int {
	// -o is the file here, not the output format.
	var out string
	var force bool
	name := "attest download"
	s := &session{e: e, name: name}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	fs.StringVar(&s.fl.APIURL, "api", "", "clearance-api URL (env CLEARANCE_API_URL)")
	fs.StringVar(&out, "o", "", "write the bundle to this file (- for stdout)")
	fs.BoolVar(&force, "force", false, "overwrite an existing file")
	fs.BoolVar(&s.tokenStdin, "token-stdin", false, "read an ID token from stdin (kept in memory)")
	fs.Usage = func() {
		fmt.Fprintf(e.Stderr, "usage: %s attest download <change-id> -o <file>\n", e.prog())
		fs.PrintDefaults()
	}
	var pos []string
	for rest := args; ; {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return ExitOK
			}
			return ExitUsage
		}
		if fs.NArg() == 0 {
			break
		}
		pos, rest = append(pos, fs.Arg(0)), fs.Args()[1:]
	}
	if len(pos) != 1 || out == "" {
		fs.Usage()
		return ExitUsage
	}
	s.fs = fs
	return e.finish(name, func() error {
		var err error
		if s.cfg, err = LoadConfig(e.Getenv, e.ConfigPath, s.fl); err != nil {
			return fail(ExitUsage, "%v", err)
		}
		c, err := s.client(false)
		if err != nil {
			return err
		}
		raw, err := fetchBundle(ctx, c, pos[0])
		if err != nil {
			return err
		}
		var b bytes.Buffer
		_ = json.Indent(&b, raw, "", "  ")
		b.WriteByte('\n')
		if out == "-" {
			_, err = e.Stdout.Write(b.Bytes())
			return err
		}
		flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if force {
			flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		f, err := os.OpenFile(out, flags, 0o644)
		if err != nil {
			return fail(ExitError, "%v (use --force to overwrite)", err)
		}
		if _, err := f.Write(b.Bytes()); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Fprintf(e.Stdout, "wrote the attestation bundle of %s to %s; check it with `%s attest verify --file %s ...`\n", pos[0], out, e.prog(), out)
		return nil
	}())
}

type repeatedFlag []string

func (r *repeatedFlag) String() string     { return strings.Join(*r, ",") }
func (r *repeatedFlag) Set(v string) error { *r = append(*r, v); return nil }

// AttestVerify is `clearance attest verify <change>`: by default the api verifies the stored bundle
// (GET /v1/clearances/{id}/attestation/verify, with the trust the api holds). With --trust-root or --key the bundle is
// downloaded and verified here, offline, by the same code as `attest verify --file` (nothing the api says is trusted).
func (e *Env) AttestVerify(ctx context.Context, args []string) int {
	var trust, key, identity, issuer, rekor string
	var subjects repeatedFlag
	s, pos, ee := e.begin("attest verify", "<change-id> [--trust-root PEM|JSON --identity ID --issuer URL [--rekor-key PEM] | --key PEM|JWKS] [--subject sha256:HEX]", args, func(fs *flag.FlagSet) {
		fs.StringVar(&trust, "trust-root", "", "offline, keyless: the Fulcio roots (PEM) or a Sigstore trusted-root.json")
		fs.StringVar(&key, "key", "", "offline, static key: the signing key's public half (PEM) or the core's JWKS")
		fs.StringVar(&identity, "identity", "", "offline, keyless: the identity the certificate must name")
		fs.StringVar(&issuer, "issuer", "", "offline, keyless: the OIDC issuer the certificate must record")
		fs.StringVar(&rekor, "rekor-key", "", "offline: Rekor's public key (PEM)")
		fs.Var(&subjects, "subject", "offline: a digest the statement must name, <alg>:<hex>; repeatable")
	})
	if ee != nil {
		return e.finish("attest verify", ee)
	}
	if len(pos) != 1 {
		return e.finish("attest verify", s.usageErr())
	}
	return e.finish("attest verify", func() error {
		c, err := s.client(false)
		if err != nil {
			return err
		}
		if trust != "" || key != "" {
			if e.OfflineVerify == nil {
				return fail(ExitError, "offline verification is not wired in this build")
			}
			raw, err := fetchBundle(ctx, c, pos[0])
			if err != nil {
				return err
			}
			var vargs []string
			for flag, v := range map[string]string{"--trust-root": trust, "--key": key, "--identity": identity, "--issuer": issuer, "--rekor-key": rekor} {
				if v != "" {
					vargs = append(vargs, flag, v)
				}
			}
			for _, sj := range subjects {
				vargs = append(vargs, "--subject", sj)
			}
			if code := e.OfflineVerify(ctx, raw, vargs, e.Stdout, e.Stderr); code != 0 {
				return &exitError{code: code}
			}
			return nil
		}
		var raw json.RawMessage
		if err := c.Get(ctx, "/v1/clearances/"+url.PathEscape(pos[0])+"/attestation/verify", nil, &raw); err != nil {
			if isMissingRoute(err) {
				return fail(ExitNotFound, "this clearance-api cannot verify server-side; verify offline with --trust-root (or --key) and the trust you hold")
			}
			var ae *APIError
			if errors.As(err, &ae) && ae.Status == 404 {
				return fail(ExitNotFound, "change %s: %s (no attestation, or this api holds no trust to verify with; try offline with --trust-root)", pos[0], ae.Message)
			}
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, raw, ""); wrote || err != nil {
			if err == nil && m["verified"] != true {
				return &exitError{code: ExitError}
			}
			return err
		}
		rows := [][2]string{{"verified", str(m, "verified")}, {"checked by", "clearance-api (its trust, not yours; use --trust-root to verify with your own)"},
			{"mode", str(m, "mode")}, {"digest", str(m, "digest")}}
		if v := str(m, "identity"); v != "" {
			rows = append(rows, [2]string{"signed by", v + " (issuer " + str(m, "issuer") + ")"})
		}
		if v := str(m, "key_id"); v != "" {
			rows = append(rows, [2]string{"key id", v})
		}
		if rk := sub(m, "rekor"); rk != nil {
			rows = append(rows, [2]string{"rekor", fmt.Sprintf("log index %s, verified %s", str(rk, "log_index"), str(rk, "verified"))})
		}
		kv(e.Stdout, rows)
		if m["verified"] != true {
			if es, _ := m["errors"].([]any); len(es) > 0 {
				for _, x := range es {
					fmt.Fprintf(e.Stderr, "attest verify: FAILED: %s\n", clean(fmt.Sprint(x)))
				}
			}
			return &exitError{code: ExitError}
		}
		return nil
	}())
}
