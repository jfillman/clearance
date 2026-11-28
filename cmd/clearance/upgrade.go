package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/compat"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/upgrade"
)

func init() {
	cli.Register(cli.Command{Name: "upgrade check", Summary: "what upgrading to a release changes and what must go first (schema, rollback, provider skew)", Run: upgradeCheck})
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

const releaseBase = "https://github.com/jfillman/clearance/releases/download/"

// upgradeCheck is `clearance upgrade check --to vX.Y.Z (--url CORE [--token-file F] | --current-file F) [--provider program=version]...`.
// It reads the target release's compat.json and notes (release assets; --compat and --notes name a file or https URL
// instead), and the running core's GET /v1/version, and prints what changes and what must go first. Exit 0 when nothing
// blocks, 1 when something does, 2 on a usage error. Doctor (N-3) does not exist yet, so it is not run.
func upgradeCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upgrade check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	to := fs.String("to", "", "the release to upgrade to (vX.Y.Z)")
	coreURL := fs.String("url", "", "the running core's base URL (reads GET /v1/version)")
	tokenFile := fs.String("token-file", "", "a file holding a bearer token for --url")
	current := fs.String("current-file", "", "a saved GET /v1/version answer, instead of --url")
	currentCore := fs.String("current-core", "", "with --url, the running core's release (vX.Y.Z), for a core from before N-6 that has no GET /v1/version: its schema is read as unversioned")
	compatSrc := fs.String("compat", "", "the target's compat.json: a file or https URL (default: the release's asset)")
	notesSrc := fs.String("notes", "", "the target's release notes: a file or https URL (default: the release's GitHub notes)")
	var provs multi
	fs.Var(&provs, "provider", "a running provider as program=version (argocd-agent=0.57.3); repeatable")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if _, ok := compat.Parse3(*to); !ok || fs.NArg() > 0 || (*coreURL == "") == (*current == "") {
		fmt.Fprintln(stderr, "usage: clearance upgrade check --to vX.Y.Z (--url CORE_URL [--token-file F] | --current-file F) [--compat SRC] [--notes SRC] [--provider program=version]...")
		return 2
	}
	tag := "v" + strings.TrimPrefix(*to, "v") // the release's tag and the URLs under it; the table and the report use the version without the v
	in := upgrade.Input{Target: strings.TrimPrefix(*to, "v"), Providers: map[string]string{}}
	for _, p := range provs {
		name, v, ok := strings.Cut(p, "=")
		if !ok || name == "" || v == "" {
			fmt.Fprintf(stderr, "upgrade check: --provider %q is not program=version\n", p)
			return 2
		}
		in.Providers[name] = v
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var raw []byte
	var err error
	if *current != "" {
		raw, err = os.ReadFile(*current)
	} else {
		raw, err = fetchVersion(ctx, strings.TrimRight(*coreURL, "/")+"/v1/version", *tokenFile)
	}
	var cur server.VersionResponse
	var status *httpStatusError
	switch {
	case errors.As(err, &status) && status.code == http.StatusNotFound && *coreURL != "":
		// A core from before N-6 has no GET /v1/version. The operator names its release; its schema is the unversioned one.
		if _, ok := compat.Parse3(*currentCore); !ok {
			fmt.Fprintln(stderr, "upgrade check: the core has no GET /v1/version (it predates N-6): pass its release as --current-core vX.Y.Z")
			return 1
		}
		cur.Core = *currentCore
		cur.Schema = &store.SchemaInfo{Version: 0, MinCore: "0.0.0", Migrations: []store.AppliedMigration{}}
		err = nil
	case err == nil:
		err = json.Unmarshal(raw, &cur)
	}
	if err != nil {
		fmt.Fprintln(stderr, "upgrade check: the running core's version:", err)
		return 1
	}
	in.CurrentCore, in.Schema = strings.TrimPrefix(cur.Core, "v"), cur.Schema

	src := *compatSrc
	if src == "" {
		src = releaseBase + tag + "/compat.json"
	}
	if raw, err = readSource(ctx, src); err == nil {
		in.Table, err = compat.Parse(raw)
	}
	if err != nil {
		fmt.Fprintln(stderr, "upgrade check: the compatibility table:", err)
		return 1
	}
	if *notesSrc != "" {
		raw, err = readSource(ctx, *notesSrc)
		in.Notes = string(raw)
	} else if raw, err = readSource(ctx, "https://api.github.com/repos/jfillman/clearance/releases/tags/"+tag); err == nil {
		var rel struct {
			Body string `json:"body"`
		}
		if err = json.Unmarshal(raw, &rel); err == nil {
			in.Notes = rel.Body
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "upgrade check: the release notes:", err)
		return 1
	}

	rep := upgrade.Check(in)
	fmt.Fprintf(stdout, "upgrade %s -> %s\n", orUnknown(in.CurrentCore), in.Target)
	section := func(title string, lines []string) {
		if len(lines) == 0 {
			return
		}
		fmt.Fprintln(stdout, "\n"+title)
		for _, l := range lines {
			fmt.Fprintln(stdout, "  - "+l)
		}
	}
	section("BLOCKED", rep.Blockers)
	section("must go first", rep.Before)
	section("what it changes", rep.Changes)
	section("from the release notes", rep.Notes)
	fmt.Fprintln(stdout, "\ndoctor: not run (clearance doctor, N-3, is not built yet); until it is, check the install by hand against docs/upgrade.md")
	if len(rep.Blockers) > 0 {
		return 1
	}
	return 0
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

// readSource reads a local file or an https URL (at most 4 MiB).
func readSource(ctx context.Context, src string) ([]byte, error) {
	if !strings.HasPrefix(src, "https://") {
		return os.ReadFile(src)
	}
	return httpGet(ctx, src, "")
}

func fetchVersion(ctx context.Context, rawURL, tokenFile string) ([]byte, error) {
	tok := ""
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, err
		}
		tok = strings.TrimSpace(string(b))
	}
	// A bearer token goes over TLS, or to this machine (a port-forward): never in clear over a network.
	if u, err := url.Parse(rawURL); err != nil {
		return nil, err
	} else if tok != "" && u.Scheme != "https" && !isLoopback(u.Hostname()) {
		return nil, errors.New("--token-file needs an https --url (or a loopback address): the token is not sent in clear")
	}
	return httpGet(ctx, rawURL, tok)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// httpStatusError is a non-200 answer.
type httpStatusError struct {
	url  string
	code int
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.url, e.code) }

func httpGet(ctx context.Context, rawURL, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	cl.Timeout = 15 * time.Second
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		// GitHub release assets redirect to a signed host: follow once, without the bearer token.
		loc, err := resp.Location()
		if err != nil || loc.Scheme != "https" {
			return nil, errors.New("unsafe redirect")
		}
		return httpGet(ctx, loc.String(), "")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{url: rawURL, code: resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return b, err
}
