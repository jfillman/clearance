package slack

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/gate"
)

// The alerts that are not about one change: exceptions and break-glass, coverage that turned degraded or blind,
// attestations that are stuck, and a hold that is about to expire. All of them are transition-based and their last
// state is kept in the store, so a restart does not repeat them and a steady bad state is said once.

// resolvable are the exception kinds a person resolves (the core skips the others).
var resolvable = []string{"out-of-band", "drift", "untraced-apply", "digest-mismatch"}

// RunAlerts polls every AlertInterval until ctx ends.
func (n *Notifier) RunAlerts(ctx context.Context) {
	t := time.NewTicker(n.Cfg.AlertInterval)
	defer t.Stop()
	for {
		for name, f := range map[string]func(context.Context) error{"exceptions": n.alertExceptions, "coverage": n.alertCoverage, "attestations": n.alertAttestations} {
			if err := f(ctx); err != nil && ctx.Err() == nil {
				n.Log.Warn("alert poll failed", "poll", name, "error", err.Error())
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// tell posts one alert to each channel (a channel named twice gets one). It reports whether the alert should be tried
// again: a post that failed for a reason that may pass (Slack unreachable, rate limited, HTTP 5xx). A refusal from
// Slack itself (the bot is not in the channel, the channel is gone) is logged and is not retried: it would fail the
// same way every time, and one bad route must not hold back every later alert.
func (n *Notifier) tell(ctx context.Context, channels []string, title string, lines []string, resolveSeq int64) (retry bool) {
	text, blocks := RenderAlert(title, lines, resolveSeq)
	var done []string
	for _, ch := range channels {
		if ch == "" || slices.Contains(done, ch) {
			continue
		}
		done = append(done, ch)
		if _, err := n.Slack.Post(ctx, ch, text, blocks, ""); err != nil {
			n.Log.Warn("posting an alert failed", "channel", ch, "error", err.Error())
			var se *Error
			if !errors.As(err, &se) {
				retry = true
			}
		}
	}
	return retry
}

// -- exceptions and break-glass ----------------------------------------------------------------------------------

const exceptionsKey = "exceptions.seq"

func (n *Notifier) alertExceptions(ctx context.Context) error {
	recs, err := n.Clear.Exceptions(ctx, 100)
	if err != nil {
		return err
	}
	var top int64
	for _, r := range recs {
		top = max(top, r.seq())
	}
	raw, ok, err := n.Store.KV(ctx, exceptionsKey)
	if err != nil {
		return err
	}
	if !ok { // the first run: what is already there is history, not news
		return n.Store.SetKV(ctx, exceptionsKey, strconv.FormatInt(top, 10))
	}
	mark, _ := strconv.ParseInt(raw, 10, 64)
	var fresh []Record
	for _, r := range recs {
		if r.seq() > mark {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) == 100 {
		n.Log.Warn("more than a page of exceptions since the last poll; the oldest may have been missed", "since_seq", mark)
	}
	slices.Reverse(fresh) // oldest first
	// The watermark moves only past alerts that were posted (or refused by Slack for good): a Slack outage leaves the
	// rest to the next poll instead of dropping them.
	upTo := mark
	for _, r := range fresh {
		if n.exceptionAlert(ctx, r) {
			break
		}
		upTo = r.seq()
	}
	if upTo > mark {
		return n.Store.SetKV(ctx, exceptionsKey, strconv.FormatInt(upTo, 10))
	}
	return nil
}

// exceptionAlert tells the channels an exception goes to; it reports whether to try it again.
func (n *Notifier) exceptionAlert(ctx context.Context, r Record) (retry bool) {
	tool, app, principal := r.str("tool"), r.str("app"), r.str("principal")
	kind := ""
	if ex, ok := r["exception"].(map[string]any); ok {
		kind, _ = ex["kind"].(string)
	}
	lines := []string{"Record " + strconv.FormatInt(r.seq(), 10) + " at " + r.str("ts")}
	if app != "" {
		lines = append(lines, "App: "+app)
	}
	if t := r.str("target"); t != "" {
		lines = append(lines, "Target: "+clip(t, 200))
	}
	if principal != "" {
		lines = append(lines, "By: "+principal)
	}
	appCh := n.Routes.Apps[app]
	if appCh == "" {
		appCh = n.Routes.Default
	}
	switch {
	case tool == "breakglass.open" || tool == "breakglass.close":
		verb := map[string]string{"breakglass.open": "opened", "breakglass.close": "closed"}[tool]
		return n.tell(ctx, []string{n.Routes.Security, appCh}, "Break-glass "+verb, lines, 0)
	case tool == "deploy.exception" && (kind == "monitoring-protection" || kind == "attempted-refused"):
		return n.tell(ctx, []string{n.Routes.Security, appCh}, "Exception: "+kind, lines, 0)
	case tool == "deploy.exception":
		var seq int64
		if slices.Contains(resolvable, kind) {
			seq = r.seq()
		}
		ch := appCh
		if ch == "" {
			ch = n.Routes.Security
		}
		return n.tell(ctx, []string{ch}, "Exception: "+kind, lines, seq)
	}
	return false
}

// -- coverage ----------------------------------------------------------------------------------------------------

var stateRank = map[string]int{"healthy": 0, "degraded": 1, "blind": 2}

// scopeNow is a scope's state now: the worst of its sources' state at the end of the window (each source's `now`, not
// the worst it was at any moment of the window, which would keep a recovered scope alarming for the whole window).
// A scope with no source in the window has nothing watching it: blind.
func scopeNow(s ScopeStatement) (string, []SourceHealth) {
	if len(s.Health.Sources) == 0 {
		return "blind", nil
	}
	worst := "healthy"
	var bad []SourceHealth
	for _, src := range s.Health.Sources {
		now, ok := stateRank[src.Now]
		if !ok { // a state this does not know is not healthy
			now, src.Now = stateRank["blind"], "blind"
		}
		if now > stateRank[worst] {
			worst = src.Now
		}
		if now > 0 {
			bad = append(bad, src)
		}
	}
	return worst, bad
}

func (n *Notifier) alertCoverage(ctx context.Context) error {
	now := n.now()
	scopes, truncated, err := n.Clear.Coverage(ctx, now.Add(-time.Hour), now)
	if err != nil {
		return err
	}
	if truncated {
		n.Log.Warn("coverage lists more scopes than one answer holds; the rest are not watched")
	}
	for _, s := range scopes {
		state, bad := scopeNow(s)
		key := "coverage." + s.Scope
		prev, had, err := n.Store.KV(ctx, key)
		if err != nil {
			return err
		}
		if had && prev == state {
			continue
		}
		channels := []string{n.Routes.Scopes[s.Scope], n.Routes.Security}
		retry := false
		switch {
		case state == "healthy" && had && prev != "healthy":
			retry = n.tell(ctx, channels, "Coverage recovered: "+s.Scope, []string{"Every feed is healthy again (was " + prev + ")."}, 0)
		case state != "healthy":
			var lines []string
			if len(bad) == 0 {
				lines = append(lines, "No feed has reported for this scope in the last hour.")
			}
			for _, b := range bad {
				stale := ""
				if b.Stale {
					stale = ", stale"
				}
				lines = append(lines, fmt.Sprintf("%s: %s%s", b.Source, b.Now, stale))
			}
			retry = n.tell(ctx, channels, fmt.Sprintf("Coverage %s: %s", state, s.Scope), lines, 0)
		}
		if retry { // Slack could not be reached: the state is not recorded as said, so the next poll says it
			continue
		}
		if err := n.Store.SetKV(ctx, key, state); err != nil {
			return err
		}
	}
	return nil
}

// -- stuck attestations ------------------------------------------------------------------------------------------

const attestKey = "attestations.stuck"

// alertAttestations says how many changes have been applied for longer than StuckAttestAfter and still have no signed
// attestation. The api counts by attestation state (pending: applied, none stored) for changes updated since a
// time, so the number older than the threshold is the pending count of a week less the pending count since the
// threshold. A change is counted by when it was last updated, which for a pending one is its apply.
func (n *Notifier) alertAttestations(ctx context.Context) error {
	now := n.now()
	pending := func(since time.Time) (int64, error) {
		cs, err := n.Clear.Counts(ctx, url.Values{"by": {"attestation"}, "since": {since.UTC().Format("2006-01-02T15:04:05Z")}})
		if err != nil {
			return 0, err
		}
		for _, c := range cs {
			if c.Key != nil && *c.Key == "pending" {
				return c.Count, nil
			}
		}
		return 0, nil
	}
	week, err := pending(now.Add(-7 * 24 * time.Hour))
	if err != nil {
		return err
	}
	recent, err := pending(now.Add(-n.Cfg.StuckAttestAfter))
	if err != nil {
		return err
	}
	stuck := max(week-recent, 0)
	raw, _, err := n.Store.KV(ctx, attestKey)
	if err != nil {
		return err
	}
	prev, _ := strconv.ParseInt(raw, 10, 64)
	if stuck == prev {
		return nil
	}
	ch := []string{n.Routes.Ops}
	if n.Routes.Ops == "" {
		ch = []string{n.Routes.Security}
	}
	retry := false
	switch {
	case stuck == 0:
		retry = n.tell(ctx, ch, "Attestations caught up", []string{"No applied change has been waiting for its attestation longer than " + n.Cfg.StuckAttestAfter.String() + "."}, 0)
	case stuck > prev:
		retry = n.tell(ctx, ch, "Attestation signing is stuck", []string{fmt.Sprintf("%d applied change(s) have waited longer than %s for a signed attestation (the signer is waiting or retrying).", stuck, n.Cfg.StuckAttestAfter)}, 0)
	}
	if retry {
		return nil // not recorded as said: the next poll says it
	}
	return n.Store.SetKV(ctx, attestKey, strconv.FormatInt(stuck, 10))
}

// -- an expiring hold --------------------------------------------------------------------------------------------

// nudge says, in each DM thread of a hold past 75% of its time to live, that it will expire. Once per change.
func (n *Notifier) nudge(ctx context.Context, c *gate.Change, msgs []Message) {
	life := c.ExpiresAt.Sub(c.CreatedAt.Time)
	if life <= 0 || n.now().Sub(c.CreatedAt.Time) < life*3/4 {
		return
	}
	key := "nudge." + c.ID
	if _, done, _ := n.Store.KV(ctx, key); done {
		return
	}
	for _, m := range msgs {
		if !strings.HasPrefix(m.Dest, "dm:") {
			continue
		}
		t := "This change is still holding and expires " + slackDate(c.ExpiresAt.Time) + "."
		if _, err := n.Slack.Post(ctx, m.Channel, t, []any{section(t)}, m.TS); err != nil {
			n.Log.Warn("an expiry nudge failed", "change", c.ID, "error", err.Error())
			return
		}
	}
	_ = n.Store.SetKV(ctx, key, "1")
}
