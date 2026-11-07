// Command clearance-wait is the PreSync hook the Argo CD plugin injects while a change is held for people
// (G-ARGO-5). It polls the core's generic wait route (GET /v1/clearances/{id}/wait) until the change is decided:
//
//	exit 0  cleared: the sync goes on
//	exit 1  denied, expired, superseded or otherwise not clearable (or the core refused the call): the sync fails
//	exit 2  timed out still holding: the sync fails; a new sync waits again
//	exit 3  a usage error
//
// Its last line is also the container's termination message, so Argo CD's UI and history read
// "clearance awaiting approval: ..." for the PreSync hook. It is not a control: `argocd app sync --strategy apply`
// skips hooks, and the admission policy (a ClearanceGrant per protected namespace) still refuses objects that no
// grant covers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jfillman/clearance/client"
)

// Exit codes.
const (
	ExitCleared = 0
	ExitFailed  = 1
	ExitTimeout = 2
	ExitUsage   = 3
)

// Core is the part of the Clearance client the wait uses.
type Core interface {
	Clearance(ctx context.Context, id string) (*client.ClearanceAnswer, error)
	Wait(ctx context.Context, id, known string, timeout time.Duration) (*client.WaitAnswer, error)
}

// Options are one wait's settings.
type Options struct {
	ChangeID string
	Timeout  time.Duration // the whole wait
	Poll     time.Duration // one long poll (1 to 60 s)
	Backoff  time.Duration // between attempts while the core is unreachable
	Now      func() time.Time
	Sleep    func(context.Context, time.Duration)
	Out      io.Writer
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Wait blocks until the change is cleared, or it cannot be, and returns the exit code and the message.
func Wait(ctx context.Context, core Core, o Options) (int, string) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	deadline := o.Now().Add(o.Timeout)
	logf := func(format string, a ...any) {
		if o.Out != nil {
			fmt.Fprintf(o.Out, format+"\n", a...)
		}
	}
	state := ""
	for {
		remaining := deadline.Sub(o.Now())
		if remaining <= 0 {
			return ExitTimeout, fmt.Sprintf("clearance awaiting approval: change %s is still %q after %s; nothing was applied", o.ChangeID, state, o.Timeout)
		}
		var ans *client.ClearanceAnswer
		var err error
		if state == "" {
			ans, err = core.Clearance(ctx, o.ChangeID)
		} else {
			var w *client.WaitAnswer
			poll := min(o.Poll, remaining)
			if poll < time.Second {
				poll = time.Second
			}
			w, err = core.Wait(ctx, o.ChangeID, state, poll.Truncate(time.Second))
			if w != nil {
				ans = &w.ClearanceAnswer
			}
		}
		switch {
		case err == nil:
		case errors.Is(err, client.ErrCoreUnavailable) || errors.Is(err, context.DeadlineExceeded):
			logf("the core is unreachable (%v); retrying", err)
			o.Sleep(ctx, o.Backoff)
			if ctx.Err() != nil {
				return ExitFailed, "clearance awaiting approval: interrupted"
			}
			continue
		default:
			return ExitFailed, fmt.Sprintf("clearance awaiting approval: the core refused the wait for %s: %v", o.ChangeID, err)
		}
		if ans.State != state {
			logf("change %s (%s/%s, tier %d) is %s", ans.ID, ans.App, ans.Env, ans.Tier, ans.State)
		}
		state = ans.State
		switch state {
		case "cleared":
			by := ""
			if ans.ClearedBy != nil {
				by = " by " + *ans.ClearedBy
			}
			return ExitCleared, fmt.Sprintf("clearance cleared: change %s%s", ans.ID, by)
		case "holding":
		default:
			return ExitFailed, fmt.Sprintf("clearance %s: change %s will not clear (%s); nothing was applied", state, ans.ID, state)
		}
	}
}

func main() {
	fs := flag.NewFlagSet("clearance-wait", flag.ContinueOnError)
	id := fs.String("change", os.Getenv("CLEARANCE_CHANGE_ID"), "the change to wait for (CLEARANCE_CHANGE_ID)")
	timeout := fs.Duration("timeout", 24*time.Hour, "give up after this long (exit 2)")
	poll := fs.Duration("poll", 30*time.Second, "one long poll, 1s to 60s")
	url := fs.String("url", os.Getenv("CLEARANCE_URL"), "the core (CLEARANCE_URL)")
	tokenFile := fs.String("token-file", orDefault(os.Getenv("CLEARANCE_TOKEN_FILE"), "/var/run/secrets/tokens/clearance"), "the projected service-account token, audience clearance")
	termLog := fs.String("termination-log", "/dev/termination-log", "where the last line is written for Kubernetes")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(ExitUsage)
	}
	if *id == "" || *url == "" || *timeout <= 0 || *poll < time.Second || *poll > client.MaxWait {
		fmt.Fprintln(os.Stderr, "clearance-wait: --change and --url are required; --timeout is positive; --poll is 1s to 60s")
		os.Exit(ExitUsage)
	}
	c, err := client.New(client.Options{BaseURL: *url, Token: client.FileToken(*tokenFile), Timeout: 10 * time.Second, Retries: 1,
		UserAgent: "clearance-argocd-wait"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "clearance-wait:", err)
		os.Exit(ExitUsage)
	}
	code, msg := Wait(context.Background(), c, Options{ChangeID: *id, Timeout: *timeout, Poll: *poll, Backoff: 5 * time.Second, Out: os.Stdout})
	fmt.Println(msg)
	if code != ExitCleared {
		_ = os.WriteFile(*termLog, []byte(msg), 0o644)
	}
	os.Exit(code)
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
