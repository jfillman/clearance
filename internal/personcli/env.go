package personcli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Env is everything a command touches outside itself, so tests supply fakes: the keychain, the HTTP client, the
// clock, the sleeper, stdin and the environment.
type Env struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Store          TokenStore
	HTTP           *http.Client // the IdP and the api, with a deadline
	StreamHTTP     *http.Client // the event stream: no overall deadline
	Now            func() time.Time
	Sleep          func(context.Context, time.Duration) error
	IsTTY          bool   // stdout is a terminal: table is the default format, else json
	StdinTTY       bool   // stdin is a terminal: the write commands can ask for confirmation
	ConfigPath     string // "" reads no file
	Version        string
	Prog           string // clearance or clr, for messages
	// OfflineVerify verifies a downloaded attestation bundle offline (clearance attest verify's code), with the
	// verify flags the person gave (--trust-root, --identity, ...).
	OfflineVerify func(ctx context.Context, bundle []byte, args []string, stdout, stderr io.Writer) int
}

// DefaultEnv is the real environment.
func DefaultEnv(version, prog string) *Env {
	st, _ := os.Stdout.Stat()
	in, _ := os.Stdin.Stat()
	return &Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Store: Keychain{},
		HTTP: NewHTTP(30 * time.Second), StreamHTTP: NewHTTP(0), Now: time.Now, Sleep: sleep,
		IsTTY: st != nil && st.Mode()&os.ModeCharDevice != 0, StdinTTY: in != nil && in.Mode()&os.ModeCharDevice != 0, Version: version, Prog: prog}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (e *Env) prog() string {
	if e.Prog == "" {
		return "clearance"
	}
	return e.Prog
}

// session is what one command invocation resolved: flags, config, output format.
type session struct {
	e          *Env
	fs         *flag.FlagSet
	fl         Flags
	format     string
	tokenStdin bool
	cfg        Config
	name       string
	stdinUsed  bool   // a command read stdin (a --from-file -): no prompt can be answered from it
	tok        string // the accepted token, kept for the invocation (stdin is read once)
	tokEnd     time.Time
}

// begin parses a command's flags (the common ones and extra's) and returns its positional arguments. Positionals
// and flags may be mixed. Usage errors have exit code 2 already.
func (e *Env) begin(name, usage string, args []string, extra func(*flag.FlagSet)) (*session, []string, *exitError) {
	s := &session{e: e, name: name}
	s.fs = flag.NewFlagSet(name, flag.ContinueOnError)
	s.fs.SetOutput(e.Stderr)
	s.fs.StringVar(&s.fl.APIURL, "api", "", "clearance-api URL (env CLEARANCE_API_URL)")
	s.fs.StringVar(&s.fl.URL, "url", "", "the Clearance core URL (env CLEARANCE_URL)")
	s.fs.StringVar(&s.format, "o", "", "output: table, json, jsonl or yaml (default table on a terminal, else json)")
	s.fs.BoolVar(&s.tokenStdin, "token-stdin", false, "read an ID token from stdin and use it for this invocation only (kept in memory)")
	if extra != nil {
		extra(s.fs)
	}
	s.fs.Usage = func() {
		fmt.Fprintf(e.Stderr, "usage: %s %s %s\n", e.prog(), name, usage)
		s.fs.PrintDefaults()
	}
	var pos []string
	for {
		if err := s.fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, nil, &exitError{code: ExitOK}
			}
			return nil, nil, &exitError{code: ExitUsage}
		}
		if s.fs.NArg() == 0 {
			break
		}
		pos = append(pos, s.fs.Arg(0))
		args = s.fs.Args()[1:]
	}
	if s.format == "" {
		if e.IsTTY {
			s.format = FormatTable
		} else {
			s.format = FormatJSON
		}
	}
	if err := checkFormat(s.format); err != nil {
		return nil, nil, fail(ExitUsage, "%v", err)
	}
	var err error
	if s.cfg, err = LoadConfig(e.Getenv, e.ConfigPath, s.fl); err != nil {
		return nil, nil, fail(ExitUsage, "%v", err)
	}
	return s, pos, nil
}

func (s *session) usageErr() *exitError {
	s.fs.Usage()
	return &exitError{code: ExitUsage}
}

// token is the ID token this invocation uses: stdin (--token-stdin), else CLEARANCE_TOKEN, else the keychain. An
// expired token, or one older than an hour, is refused.
func (s *session) token() (string, time.Time, *exitError) {
	if s.tok != "" {
		return s.tok, s.tokEnd, nil
	}
	e := s.e
	var tok string
	var saved time.Time
	switch {
	case s.tokenStdin:
		t, err := ReadTokenStdin(e.Stdin)
		if err != nil {
			return "", time.Time{}, fail(ExitUsage, "--token-stdin: %v", err)
		}
		tok = t
	case e.Getenv("CLEARANCE_TOKEN") != "":
		tok = strings.TrimSpace(e.Getenv("CLEARANCE_TOKEN"))
		if e.IsTTY {
			fmt.Fprintln(e.Stderr, "warning: CLEARANCE_TOKEN is set; it is for automation (prefer `clearance login`, or --token-stdin)")
		}
	default:
		st, err := e.Store.Get()
		switch {
		case errors.Is(err, ErrNoToken):
			return "", time.Time{}, fail(ExitUnauthorized, "not signed in: run `%s login`", e.prog())
		case err != nil:
			return "", time.Time{}, fail(ExitUnauthorized, "cannot read the keychain (%v); use --token-stdin", err)
		}
		tok, saved = st.IDToken, time.Unix(st.SavedAt, 0)
	}
	c, err := ParseClaims(tok)
	if err != nil {
		return "", time.Time{}, fail(ExitUnauthorized, "the token is not an ID token (JWT); run `%s login`", e.prog())
	}
	end := Expiry(c, saved)
	if !end.IsZero() && !e.Now().Before(end) {
		if !s.tokenStdin && e.Getenv("CLEARANCE_TOKEN") == "" {
			_ = e.Store.Delete()
		}
		return "", time.Time{}, fail(ExitUnauthorized, "the token expired at %s: run `%s login`", end.UTC().Format(time.RFC3339), e.prog())
	}
	s.tok, s.tokEnd = tok, end
	return tok, end, nil
}

// client is an authenticated api client.
func (s *session) client(stream bool) (*Client, error) {
	if s.cfg.APIURL == "" {
		return nil, fail(ExitUsage, "no clearance-api URL: set --api, CLEARANCE_API_URL or api_url in %s", cfgHint(s.e))
	}
	tok, _, err := s.token()
	if err != nil {
		return nil, err
	}
	hc := s.e.HTTP
	if stream {
		hc = s.e.StreamHTTP
	}
	return &Client{Base: s.cfg.APIURL, Token: tok, HTTP: hc, UserAgent: "clearance-cli/" + s.e.Version}, nil
}

func cfgHint(e *Env) string {
	if e.ConfigPath != "" {
		return e.ConfigPath
	}
	return "~/.config/clearance/config.yaml"
}

// finish prints a command's failure and returns its exit code.
func (e *Env) finish(name string, err error) int {
	if err == nil {
		return ExitOK
	}
	ee := mapError(err)
	if ee.msg != "" {
		fmt.Fprintf(e.Stderr, "%s %s: %s\n", e.prog(), name, ee.msg)
	}
	return ee.code
}
