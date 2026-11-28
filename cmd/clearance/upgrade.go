package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/compat"
	"github.com/jfillman/clearance/internal/server"
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
	if err == nil {
		err = json.Unmarshal(raw, &cur)
	}
	if err != nil {
		fmt.Fprintln(stderr, "upgrade check: the running core's version:", err)
		return 1
	}
	in.CurrentCore, in.Schema = strings.TrimPrefix(cur.Core, "v"), cur.Schema

	src := *compatSrc
	if src == "" {
		src = releaseBase + *to + "/compat.json"
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
	} else if raw, err = readSource(ctx, "https://api.github.com/repos/jfillman/clearance/releases/tags/"+*to); err == nil {
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

func fetchVersion(ctx context.Context, url, tokenFile string) ([]byte, error) {
	tok := ""
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, err
		}
		tok = strings.TrimSpace(string(b))
	}
	return httpGet(ctx, url, tok)
}

func httpGet(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if !strings.HasPrefix(url, "https://") {
		// A core in the cluster is often plain http; the token only ever goes to the URL the operator named.
		cl.Timeout = 15 * time.Second
	}
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
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return b, err
}
