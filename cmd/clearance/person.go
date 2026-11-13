package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/personcli"
)

// The person commands (docs/cli.md): sign-in, the read commands (clearance-api) and the write commands (the core),
// each with the person's own ID token. `clr` is the same binary under another name: a symlink (`ln -s clearance clr`) is all it takes; the
// commands behave the same and only their messages name it.

func personEnv() *personcli.Env {
	prog := "clearance"
	if strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") == "clr" {
		prog = "clr"
	}
	e := personcli.DefaultEnv(cliVersion(), prog)
	e.ConfigPath = personcli.ConfigPath(os.Getenv)
	e.OfflineVerify = offlineVerifyBundle
	return e
}

func personEnvFor(out, errw io.Writer) *personcli.Env {
	e := personEnv()
	e.Stdout, e.Stderr = out, errw
	return e
}

// offlineVerifyBundle runs `clearance attest verify --file <bundle>` on a downloaded bundle: the same code, the
// person's own trust inputs. The bundle goes through a private temp directory, removed after.
func offlineVerifyBundle(ctx context.Context, bundle []byte, args []string, stdout, stderr io.Writer) int {
	dir, err := os.MkdirTemp("", "clearance-attest-")
	if err != nil {
		return 1
	}
	defer os.RemoveAll(dir)
	f := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(f, bundle, 0o600); err != nil {
		return 1
	}
	return attestVerify(ctx, append([]string{"--file", f}, args...), stdout, stderr)
}

func init() {
	reg := func(name, summary string, run func(*personcli.Env, context.Context, []string) int) {
		cli.Register(cli.Command{Name: name, Summary: summary, Run: func(ctx context.Context, args []string, out, errw io.Writer) int {
			e := personEnv()
			e.Stdout, e.Stderr = out, errw
			return run(e, ctx, args)
		}})
	}
	reg("login", "sign in to the people IdP (OIDC device code); the ID token goes to the OS keychain", (*personcli.Env).Login)
	reg("logout", "remove the stored ID token from the keychain", (*personcli.Env).Logout)
	reg("whoami", "who clearance-api takes you for: principal, roles, groups, apps, admin", (*personcli.Env).Whoami)
	reg("inbox", "the holding changes you may clear now", (*personcli.Env).Awaiting)
	reg("changes list", "list changes (--app --env --state --tier --since)", (*personcli.Env).ChangesList)
	reg("changes show", "one change: why this tier, approvals, what it binds to, outcome, attestation", (*personcli.Env).ChangesShow)
	reg("changes history", "a change's deploy.* records in chain order", (*personcli.Env).ChangesHistory)
	reg("changes clear", "approve a holding change as yourself (--reason, --yes); goes to the core", (*personcli.Env).ChangesClear)
	reg("changes deny", "deny a holding change (--reason required, --yes); goes to the core", (*personcli.Env).ChangesDeny)
	reg("exceptions resolve", "resolve exceptions: seqs, --from-file or --all-matching, --as STATE [--cause C] [--plan] [--yes]", (*personcli.Env).ExceptionsResolve)
	reg("breakglass open", "open a break-glass window (admin; always interactive)", (*personcli.Env).BreakglassOpen)
	reg("breakglass close", "close a break-glass window early (admin)", (*personcli.Env).BreakglassClose)
	reg("breakglass list", "the break-glass windows open now (admin)", (*personcli.Env).BreakglassList)
	reg("attest get", "a change's attestation summary", (*personcli.Env).AttestGet)
	reg("attest download", "save a change's attestation bundle (-o file)", (*personcli.Env).AttestDownload)
	reg("exceptions list", "the exceptions (--scope --kind --since)", (*personcli.Env).ExceptionsList)
	reg("coverage", "the coverage statement for a scope; exit 0 covered, 2 degraded, 3 blind or unavailable", (*personcli.Env).Coverage)
	reg("evidence", "query evidence records (--tool --app --coverage --since --limit)", (*personcli.Env).EvidenceList)
	reg("watch", "follow the live event stream, filtered", (*personcli.Env).Watch)
}

func cliVersion() string {
	if v := buildVersion(); v != "" {
		return v
	}
	return "dev"
}
