package slack

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func scope(name string, sources ...[2]string) map[string]any { // each source: name, now
	var srcs []any
	for _, s := range sources {
		// state is the worst in the window: blind. What the alert reads is now.
		srcs = append(srcs, map[string]any{"source": s[0], "state": "blind", "now": s[1], "stale": s[1] == "blind"})
	}
	return map[string]any{"scope": name, "health": map[string]any{"sources": srcs}}
}

func texts(f *fakeSlack, channel string) []string {
	var out []string
	for _, c := range f.called("chat.postMessage") {
		if c.Body["channel"] == channel {
			out = append(out, fmt.Sprint(c.Body["text"]))
		}
	}
	return out
}

func TestCoverageAlertsUseEachSourcesNowNotTheWindowsWorst(t *testing.T) {
	r := newRig(t, testRoutes)
	n := r.svc.Notifier
	// the window's worst state is blind for this source, but it is healthy now: nothing to say
	r.clr.coverage = []map[string]any{scope("acct-1", [2]string{"cloudtrail", "healthy"})}
	if err := n.alertCoverage(bg); err != nil {
		t.Fatal(err)
	}
	if len(r.slack.called("chat.postMessage")) != 0 {
		t.Fatalf("a recovered scope alarmed: %v", r.slack.calls)
	}
	// degraded now: the scope's channel and the security channel, once
	r.clr.coverage = []map[string]any{scope("acct-1", [2]string{"cloudtrail", "degraded"}, [2]string{"config", "healthy"})}
	n.alertCoverage(bg)
	n.alertCoverage(bg)
	for _, ch := range []string{"C_SCOPE", "C_SEC"} {
		got := texts(r.slack, ch)
		if len(got) != 1 || got[0] != "Coverage degraded: acct-1" {
			t.Fatalf("%s: %v", ch, got)
		}
	}
	if b := blocksText(r.slack.called("chat.postMessage")[0]); !strings.Contains(b, "cloudtrail: degraded") || strings.Contains(b, "config") {
		t.Errorf("the message names the unhealthy source only: %s", b)
	}
	// blind is worse: a new alert; then healthy: a recovery
	r.slack.reset()
	r.clr.coverage = []map[string]any{scope("acct-1", [2]string{"cloudtrail", "blind"})}
	n.alertCoverage(bg)
	if got := texts(r.slack, "C_SEC"); len(got) != 1 || got[0] != "Coverage blind: acct-1" {
		t.Fatalf("blind: %v", got)
	}
	r.slack.reset()
	r.clr.coverage = []map[string]any{scope("acct-1", [2]string{"cloudtrail", "healthy"})}
	n.alertCoverage(bg)
	if got := texts(r.slack, "C_SEC"); len(got) != 1 || got[0] != "Coverage recovered: acct-1" {
		t.Fatalf("recovered: %v", got)
	}
	// a scope nothing watches is blind, and a state this does not know is not healthy
	r.slack.reset()
	r.clr.coverage = []map[string]any{scope("acct-2"), scope("acct-3", [2]string{"x", "mystery"})}
	n.alertCoverage(bg)
	if got := texts(r.slack, "C_SEC"); len(got) != 2 {
		t.Fatalf("unwatched and unknown: %v", got)
	}
}

func TestScopeNow(t *testing.T) {
	for name, tc := range map[string]struct {
		s    ScopeStatement
		want string
	}{
		"healthy":   {ScopeStatement{}, "blind"},
		"all good":  {st("healthy", "healthy"), "healthy"},
		"one slow":  {st("healthy", "degraded"), "degraded"},
		"one blind": {st("degraded", "blind", "healthy"), "blind"},
	} {
		if got, _ := scopeNow(tc.s); got != tc.want {
			t.Errorf("%s: %s", name, got)
		}
	}
}

func st(nows ...string) ScopeStatement {
	var s ScopeStatement
	for i, n := range nows {
		s.Health.Sources = append(s.Health.Sources, SourceHealth{Source: fmt.Sprint("s", i), Now: n})
	}
	return s
}

func exc(seq int, tool, kind, app string) map[string]any {
	m := map[string]any{"seq": seq, "tool": tool, "app": app, "principal": "user:ann", "ts": "2026-11-13T10:00:00Z", "target": "acme/web@0123456"}
	if kind != "" {
		m["exception"] = map[string]any{"kind": kind}
	}
	return m
}

func TestExceptionAndBreakGlassAlerts(t *testing.T) {
	r := newRig(t, testRoutes)
	n := r.svc.Notifier
	r.clr.excs = []map[string]any{exc(10, "deploy.exception", "drift", "web")}
	n.alertExceptions(bg)
	if len(r.slack.called("chat.postMessage")) != 0 {
		t.Fatal("history is not news: the first poll posts nothing")
	}
	r.clr.excs = []map[string]any{ // newest first
		exc(14, "deploy.exception", "monitoring-protection", "web"),
		exc(13, "deploy.exception", "drift", "web"),
		exc(12, "breakglass.close", "", "web"),
		exc(11, "breakglass.open", "", "web"),
		exc(10, "deploy.exception", "drift", "web"),
	}
	n.alertExceptions(bg)
	sec, web := texts(r.slack, "C_SEC"), texts(r.slack, "C_WEB")
	if strings.Join(sec, "|") != "Break-glass opened|Break-glass closed|Exception: monitoring-protection" {
		t.Errorf("security channel, oldest first: %v", sec)
	}
	if len(web) != 4 {
		t.Errorf("the app's channel gets all of them: %v", web)
	}
	// only a resolvable kind offers Resolve; break-glass never does
	for _, c := range r.slack.called("chat.postMessage") {
		ids := actionIDs(c)
		isDrift := fmt.Sprint(c.Body["text"]) == "Exception: drift"
		if isDrift != (len(ids) == 1 && ids[0] == ActResolve) {
			t.Errorf("buttons on %q: %v", c.Body["text"], ids)
		}
		if isDrift && !strings.Contains(blocksText(c), `"value":"13"`) {
			t.Errorf("Resolve names the record: %s", blocksText(c))
		}
	}
	// nothing new: nothing posted
	r.slack.reset()
	n.alertExceptions(bg)
	if len(r.slack.called("chat.postMessage")) != 0 {
		t.Error("an alert was repeated")
	}
	// the watermark survives a restart
	r2 := &Notifier{Cfg: n.Cfg, Routes: n.Routes, Store: r.store, Slack: n.Slack, Clear: n.Clear, Log: n.Log}
	r2.alertExceptions(bg)
	if len(r.slack.called("chat.postMessage")) != 0 {
		t.Error("a restart repeated alerts")
	}
}

func TestStuckAttestationsAreCountedByAgeAndSaidOnce(t *testing.T) {
	r := newRig(t, testRoutes)
	n := r.svc.Notifier
	pendingBefore := int64(5)
	// 5 applied-and-unattested in the last week; 2 of them within the last 30 minutes: 3 are stuck
	r.clr.countFn = func(since string) map[string]int64 {
		at, _ := time.Parse("2006-01-02T15:04:05Z", since)
		if r.now.Sub(at) > 24*time.Hour {
			return map[string]int64{"pending": pendingBefore, "attested": 90}
		}
		return map[string]int64{"pending": 2, "attested": 1}
	}
	n.alertAttestations(bg)
	n.alertAttestations(bg)
	got := texts(r.slack, "C_OPS")
	if len(got) != 1 || got[0] != "Attestation signing is stuck" || !strings.Contains(blocksText(r.slack.called("chat.postMessage")[0]), "3 applied change(s)") {
		t.Fatalf("%v %s", got, r.slack.calls)
	}
	r.slack.reset()
	pendingBefore = 2 // all caught up
	n.alertAttestations(bg)
	if got := texts(r.slack, "C_OPS"); len(got) != 1 || got[0] != "Attestations caught up" {
		t.Fatalf("recovery: %v", got)
	}
	r.slack.reset()
	n.alertAttestations(bg)
	if len(r.slack.calls) != 0 {
		t.Error("a quiet state was repeated")
	}
}

func TestTheStreamResumesFromTheSavedCursor(t *testing.T) {
	r := newRig(t, testRoutes, func(c *Config) { c.ReconcileInterval = 50 * time.Millisecond })
	ev := func(id int, name string) string {
		return fmt.Sprintf("id: %d\nevent: %s\ndata: {\"seq\":%d,\"tool\":\"deploy.request\",\"change\":{\"id\":\"c-1\",\"state\":\"holding\"}}\n\n", id, name, id)
	}
	r.clr.streamEv = []string{ev(5, "clearance"), ev(6, "clearance"), ev(7, "record")} // a record event is not a change's
	run := func() context.CancelFunc {
		ctx, cancel := context.WithCancel(bg)
		go r.svc.Notifier.Run(ctx)
		return cancel
	}
	stop := run()
	waitFor(t, "the cursor to be saved", func() bool { v, _, _ := r.store.KV(bg, cursorKey); return v == "6" })
	stop()
	r.clr.mu.Lock()
	first := r.clr.streamLast[0]
	r.clr.mu.Unlock()
	if first != "" {
		t.Errorf("a first start has no cursor: %q", first)
	}
	// a new process: it asks the server to resume after what it last handled
	r.clr.mu.Lock()
	r.clr.streamLast = nil
	r.clr.streamEv = nil
	r.clr.mu.Unlock()
	stop = run()
	defer stop()
	waitFor(t, "a resumed stream", func() bool { r.clr.mu.Lock(); defer r.clr.mu.Unlock(); return len(r.clr.streamLast) > 0 })
	r.clr.mu.Lock()
	defer r.clr.mu.Unlock()
	if r.clr.streamLast[0] != "6" {
		t.Errorf("resumed with Last-Event-ID %q", r.clr.streamLast[0])
	}
}

func TestTheStreamCursorIsNotSavedUntilThePassSucceeds(t *testing.T) {
	r := newRig(t, testRoutes, func(c *Config) { c.ReconcileInterval = 30 * time.Millisecond })
	r.clr.streamEv = []string{"id: 9\nevent: clearance\ndata: {}\n\n"}
	r.clr.mu.Lock()
	r.clr.token = "not-the-token" // clearance-api refuses everything: no pass can succeed
	r.clr.mu.Unlock()
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	go r.svc.Notifier.Run(ctx)
	time.Sleep(400 * time.Millisecond)
	if v, ok, _ := r.store.KV(bg, cursorKey); ok && v != "" {
		t.Errorf("the cursor moved to %q though no pass succeeded: an event would be lost", v)
	}
}

func TestAnAlertIsNotRecordedAsSaidUntilSlackTookIt(t *testing.T) {
	r := newRig(t, testRoutes)
	n := r.svc.Notifier
	r.clr.coverage = []map[string]any{scope("acct-1", [2]string{"cloudtrail", "degraded"})}
	r.slack.failNext["chat.postMessage"] = 503 // Slack is briefly unavailable
	n.alertCoverage(bg)
	if v, ok, _ := r.store.KV(bg, "coverage.acct-1"); ok {
		t.Fatalf("recorded as said (%q) though the post failed: the alert would never be sent", v)
	}
	r.slack.reset()
	n.alertCoverage(bg) // the next poll says it
	if got := texts(r.slack, "C_SEC"); len(got) != 1 || got[0] != "Coverage degraded: acct-1" {
		t.Fatalf("the retry: %v", got)
	}
	if v, _, _ := r.store.KV(bg, "coverage.acct-1"); v != "degraded" {
		t.Errorf("recorded after it was said: %q", v)
	}

	// attestations and exceptions hold back the same way
	r.clr.countFn = func(since string) map[string]int64 {
		if at, _ := time.Parse("2006-01-02T15:04:05Z", since); r.now.Sub(at) > 24*time.Hour {
			return map[string]int64{"pending": 4}
		}
		return map[string]int64{}
	}
	r.slack.failNext["chat.postMessage"] = 503
	n.alertAttestations(bg)
	if _, ok, _ := r.store.KV(bg, attestKey); ok {
		t.Error("stuck attestations recorded as said after a failed post")
	}
	n.alertAttestations(bg)
	if v, _, _ := r.store.KV(bg, attestKey); v != "4" {
		t.Errorf("after the retry: %q", v)
	}

	r.clr.excs = []map[string]any{exc(10, "deploy.exception", "drift", "web")}
	n.alertExceptions(bg) // the watermark: 10
	r.clr.excs = []map[string]any{exc(12, "breakglass.open", "", "web"), exc(11, "deploy.exception", "drift", "web"), exc(10, "deploy.exception", "drift", "web")}
	r.slack.reset()
	r.slack.failNext["chat.postMessage"] = 503 // the first alert (11) cannot be sent
	n.alertExceptions(bg)
	if v, _, _ := r.store.KV(bg, exceptionsKey); v != "10" {
		t.Fatalf("the watermark moved to %q past an alert that was not sent", v)
	}
	r.slack.reset()
	n.alertExceptions(bg)
	if v, _, _ := r.store.KV(bg, exceptionsKey); v != "12" || len(texts(r.slack, "C_WEB")) != 2 {
		t.Errorf("the next poll sends both: watermark %q, %v", v, texts(r.slack, "C_WEB"))
	}
}

func TestARouteSlackRefusesDoesNotBlockLaterAlerts(t *testing.T) {
	r := newRig(t, testRoutes)
	n := r.svc.Notifier
	r.slack.errCode["chat.postMessage"] = "not_in_channel" // the bot was never invited: it will say so every time
	r.clr.excs = []map[string]any{exc(10, "deploy.exception", "drift", "web")}
	n.alertExceptions(bg)
	r.clr.excs = []map[string]any{exc(11, "breakglass.open", "", "web"), exc(10, "deploy.exception", "drift", "web")}
	n.alertExceptions(bg)
	if v, _, _ := r.store.KV(bg, exceptionsKey); v != "11" {
		t.Errorf("a permanent refusal held the watermark at %q: every later alert would be lost", v)
	}
}
