package slack

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testRoutes = `
groups:
  "group:default/payments": C_PAY
  "group:default/admins": C_ADM
default: C_DEF
security: C_SEC
ops: C_OPS
apps:
  web: C_WEB
scopes:
  acct-1: C_SCOPE
`

func posted(f *fakeSlack) map[string][]slackCall {
	out := map[string][]slackCall{}
	for _, c := range f.called("chat.postMessage") {
		ch, _ := c.Body["channel"].(string)
		out[ch] = append(out[ch], c)
	}
	return out
}

func blocksText(c slackCall) string {
	b, _ := json_(c.Body["blocks"])
	return string(b)
}

func actionIDs(c slackCall) []string {
	var ids []string
	bl, _ := c.Body["blocks"].([]any)
	for _, b := range bl {
		m := b.(map[string]any)
		if m["type"] != "actions" {
			continue
		}
		for _, e := range m["elements"].([]any) {
			ids = append(ids, e.(map[string]any)["action_id"].(string))
		}
	}
	return ids
}

func setupPeople(r *rig) {
	r.link("T1", "U1", "user:ann", time.Now().Unix()-60)
	r.link("T1", "U2", "user:pat", 0) // the proposer
	r.link("T1", "U3", "user:bob", 0) // another team
	r.link("T1", "U4", "user:cyd", 0) // same team, DMs off
	r.store.SetDM(bg, "T1", "U4", false)
	r.clr.setPerson("user:ann", []string{"group:default/payments"}, false)
	r.clr.setPerson("user:pat", []string{"group:default/payments"}, false)
	r.clr.setPerson("user:bob", []string{"group:default/other"}, false)
	r.clr.setPerson("user:cyd", []string{"group:default/payments"}, false)
	r.clr.setPerson("user:ada", []string{"group:default/admins"}, true)
}

func TestAHoldGoesToTheOwnerChannelAndToThePeopleWhoMayClearIt(t *testing.T) {
	r := newRig(t, testRoutes)
	setupPeople(r)
	r.clr.setChanges(change("c-1", "web", "prod", 2, "group:default/payments", nil))
	if err := r.svc.Notifier.Reconcile(bg); err != nil {
		t.Fatal(err)
	}
	got := posted(r.slack)
	// the owner group's channel, and a DM to ann only: pat proposed it, bob is another team, cyd turned DMs off
	if len(got) != 2 || len(got["C_PAY"]) != 1 || len(got["DU1"]) != 1 {
		t.Fatalf("posts by channel: %v", keys(got))
	}
	root := got["C_PAY"][0]
	if ids := actionIDs(root); strings.Join(ids, ",") != ActClear+","+ActDeny {
		t.Errorf("a tier 2 hold offers Clear and Deny: %v", ids)
	}
	for _, want := range []string{"web / prod", "tier 2", "user:pat", "Rollout/web", "kind:Rollout", "1 from group:default/payments"} {
		if !strings.Contains(blocksText(root), want) {
			t.Errorf("the message lacks %q: %s", want, blocksText(root))
		}
	}
	// a second pass changes nothing: one thread per change, not one message per pass
	r.slack.reset()
	if err := r.svc.Notifier.Reconcile(bg); err != nil {
		t.Fatal(err)
	}
	if n := len(r.slack.called("chat.postMessage")) + len(r.slack.called("chat.update")); n != 0 {
		t.Errorf("a pass with nothing new posted or updated %d times", n)
	}
	msgs, _ := r.store.Messages(bg, "c-1")
	if len(msgs) != 2 || !msgs[0].Open {
		t.Errorf("stored: %+v", msgs)
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestATierThreeHoldWaitsOnTheOwnerThenOnAnOutsider(t *testing.T) {
	r := newRig(t, testRoutes)
	setupPeople(r)
	r.link("T1", "U5", "user:ada", 0)
	c := change("c-3", "web", "prod", 3, "group:default/payments", []string{"group:default/admins"})
	r.clr.setChanges(c)
	r.svc.Notifier.Reconcile(bg)
	got := posted(r.slack)
	if len(got["C_ADM"]) != 0 || len(got["DU5"]) != 0 {
		t.Fatalf("the outsider is told only once the owner has cleared: %v", keys(got))
	}
	if ids := actionIDs(got["C_PAY"][0]); strings.Join(ids, ",") != ActOpen+","+ActDeny {
		t.Errorf("a tier 3 hold offers Deny and a link out, not Clear: %v", ids)
	}
	if !strings.Contains(blocksText(got["C_PAY"][0]), "https://clearance-web.example/changes/c-3") {
		t.Errorf("the message links to the web page where a tier 3 clear is made: %s", blocksText(got["C_PAY"][0]))
	}

	// the owner clears: the outside person is DMed at once, and the thread says so
	r.slack.reset()
	c["approvals"] = []map[string]any{approval("user:ann", "owner", r.now)}
	r.clr.setChanges(c)
	r.svc.Notifier.Reconcile(bg)
	got = posted(r.slack)
	if len(got["DU5"]) != 1 || len(got["C_ADM"]) != 0 {
		t.Fatalf("after the owner: %v", keys(got))
	}
	var reply bool
	for _, p := range got["C_PAY"] {
		reply = reply || (p.Body["thread_ts"] != nil && strings.Contains(fmt.Sprint(p.Body["text"]), "user:ann approved (owner)"))
	}
	if !reply || len(r.slack.called("chat.update")) == 0 {
		t.Errorf("the owner's approval updates the root and replies in its thread: %v", r.slack.calls)
	}

	// past the wait, the outside group's channel is told too
	r.slack.reset()
	r.now = r.now.Add(16 * time.Minute)
	r.svc.Notifier.Reconcile(bg)
	if got = posted(r.slack); len(got["C_ADM"]) != 1 {
		t.Fatalf("after the wait: %v", keys(got))
	}
}

func TestAChangeThatStopsHoldingShowsHowItEnded(t *testing.T) {
	r := newRig(t, testRoutes)
	setupPeople(r)
	c := change("c-1", "web", "prod", 2, "group:default/payments", nil)
	r.clr.setChanges(c)
	r.svc.Notifier.Reconcile(bg)
	r.slack.reset()

	by := "user:ann"
	c["state"], c["cleared_by"] = "cleared", by
	c["approvals"] = []map[string]any{approval(by, "owner", r.now)}
	r.clr.setChanges(c)
	if err := r.svc.Notifier.Reconcile(bg); err != nil {
		t.Fatal(err)
	}
	ups := r.slack.called("chat.update")
	if len(ups) != 2 { // the channel root and ann's DM
		t.Fatalf("updates: %d", len(ups))
	}
	for _, u := range ups {
		if len(actionIDs(u)) != 0 || !strings.Contains(blocksText(u), "Cleared by user:ann") {
			t.Errorf("an ended change has no buttons and says how it ended: %s", blocksText(u))
		}
	}
	var note bool
	for _, p := range r.slack.called("chat.postMessage") {
		note = note || (p.Body["thread_ts"] != nil && fmt.Sprint(p.Body["text"]) == "Cleared by user:ann.")
	}
	if !note {
		t.Error("the thread gets a one-line reply when the change ends")
	}
	if open, _ := r.store.OpenMessages(bg); len(open) != 0 {
		t.Errorf("still tracked as open: %+v", open)
	}
	// and a later pass leaves it alone
	r.slack.reset()
	r.svc.Notifier.Reconcile(bg)
	if len(r.slack.calls) != 0 {
		t.Errorf("an ended change was touched again: %v", r.slack.calls)
	}
}

func TestADeniedChangeShowsTheReason(t *testing.T) {
	r := newRig(t, testRoutes)
	setupPeople(r)
	c := change("c-1", "web", "prod", 2, "group:default/payments", nil)
	r.clr.setChanges(c)
	r.svc.Notifier.Reconcile(bg)
	r.slack.reset()
	c["state"], c["denied_by"], c["deny_reason"] = "denied", "user:ann", "not on a Friday"
	r.clr.setChanges(c)
	r.svc.Notifier.Reconcile(bg)
	if u := r.slack.called("chat.update"); len(u) == 0 || !strings.Contains(blocksText(u[0]), "not on a Friday") {
		t.Errorf("the denial's reason: %v", u)
	}
}

func TestNoRouteMeansDMsOnly(t *testing.T) {
	r := newRig(t, "")
	setupPeople(r)
	r.clr.setChanges(change("c-1", "web", "prod", 2, "group:default/payments", nil))
	r.svc.Notifier.Reconcile(bg)
	if got := posted(r.slack); len(got) != 1 || len(got["DU1"]) != 1 {
		t.Fatalf("with no routes only the DM: %v", keys(got))
	}
}

func TestAStaleLinkGetsNoDM(t *testing.T) {
	r := newRig(t, testRoutes)
	setupPeople(r)
	r.now = r.now.Add(31 * 24 * time.Hour) // every link is past 30 days
	r.clr.setChanges(change("c-1", "web", "prod", 2, "group:default/payments", nil))
	r.svc.Notifier.Reconcile(bg)
	if got := posted(r.slack); len(got["DU1"]) != 0 {
		t.Fatalf("a stale link is not messaged: %v", keys(got))
	}
}

func TestAnExpiringHoldNudgesTheDMThreadOnce(t *testing.T) {
	r := newRig(t, testRoutes)
	setupPeople(r)
	c := change("c-1", "web", "prod", 2, "group:default/payments", nil)
	r.clr.setChanges(c)
	r.svc.Notifier.Reconcile(bg)
	r.slack.reset()
	r.now = r.now.Add(60 * time.Hour) // 60 of 72 hours: past 75 percent
	r.svc.Notifier.Reconcile(bg)
	r.svc.Notifier.Reconcile(bg)
	var nudges int
	for _, p := range r.slack.called("chat.postMessage") {
		if p.Body["channel"] == "DU1" && p.Body["thread_ts"] != nil && strings.Contains(fmt.Sprint(p.Body["text"]), "expires") {
			nudges++
		}
	}
	if nudges != 1 {
		t.Fatalf("nudges: %d", nudges)
	}
}

func TestPostsAreRateLimitedAndRetried(t *testing.T) {
	r := newRig(t, testRoutes)
	setupPeople(r)
	var slept []time.Duration
	r.svc.Slack.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	r.slack.failNext["chat.postMessage"] = 429 // Slack says slow down once
	r.clr.setChanges(change("c-1", "web", "prod", 2, "group:default/payments", nil))
	if err := r.svc.Notifier.Reconcile(bg); err != nil {
		t.Fatal(err)
	}
	if len(slept) == 0 || slept[0] != time.Second {
		t.Errorf("Retry-After was not honored: %v", slept)
	}
	if got := posted(r.slack); len(got["C_PAY"]) != 2 { // the refused try and the retry
		t.Errorf("posts: %v", keys(got))
	}
	// a burst of new holds is spread over passes, not posted in one
	var cs []map[string]any
	for i := 0; i < maxNewPerRun+10; i++ {
		cs = append(cs, change(fmt.Sprintf("b-%d", i), "web", "prod", 2, "group:default/payments", nil))
	}
	r.clr.setChanges(cs...)
	r.slack.reset()
	r.svc.Notifier.Reconcile(bg)
	if n := len(r.slack.called("chat.postMessage")); n > maxNewPerRun*2 {
		t.Errorf("one pass posted %d messages", n)
	}
}

func TestChannelPostsArePacedPerChannel(t *testing.T) {
	r := newRig(t, "")
	a := r.svc.Slack
	a.MinInterval = 1100 * time.Millisecond
	var slept []time.Duration
	a.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	for i := 0; i < 3; i++ {
		a.Post(bg, "C1", "x", nil, "")
	}
	a.Post(bg, "C2", "x", nil, "")
	if len(slept) != 4 || slept[1] < 900*time.Millisecond || slept[2] < 1900*time.Millisecond || slept[3] > 100*time.Millisecond {
		t.Errorf("pacing: %v", slept)
	}
}
