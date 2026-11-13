package slack

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

var trigSeq int

func inbound(t *testing.T, kind string, v map[string]any) Inbound {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return Inbound{Kind: kind, Payload: b}
}

func (r *rig) click(action, value, user, channel string) {
	r.t.Helper()
	trigSeq++
	r.svc.Handle(bg, inbound(r.t, "interactive", map[string]any{"type": "block_actions", "trigger_id": fmt.Sprintf("trig-%d", trigSeq),
		"team": map[string]any{"id": "T1"}, "user": map[string]any{"id": user, "name": "admin", "username": "someone-else"},
		"container": map[string]any{"channel_id": channel, "message_ts": "1700000000.000001"},
		"actions":   []any{map[string]any{"action_id": action, "value": value}}}))
}

func (r *rig) modal() map[string]any {
	r.t.Helper()
	waitFor(r.t, "a modal", func() bool { return len(r.slack.called("views.open")) > 0 })
	calls := r.slack.called("views.open")
	return calls[len(calls)-1].Body["view"].(map[string]any)
}

func (r *rig) submit(modal map[string]any, user string, values map[string]string) any {
	r.t.Helper()
	vs := map[string]any{}
	for k, v := range values {
		if k == "state" || k == "cause" {
			vs[k] = map[string]any{k: map[string]any{"selected_option": map[string]any{"value": v}}}
		} else {
			vs[k] = map[string]any{k: map[string]any{"value": v}}
		}
	}
	return r.svc.Handle(bg, inbound(r.t, "interactive", map[string]any{"type": "view_submission", "trigger_id": "sub-" + fmt.Sprint(time.Now().UnixNano()),
		"team": map[string]any{"id": "T1"}, "user": map[string]any{"id": user},
		"view": map[string]any{"id": fmt.Sprint(time.Now().UnixNano()), "callback_id": modal["callback_id"], "private_metadata": modal["private_metadata"],
			"state": map[string]any{"values": vs}}}))
}

func (r *rig) lastEphemeral() string {
	r.t.Helper()
	waitFor(r.t, "an ephemeral message", func() bool { return len(r.slack.called("chat.postEphemeral")) > 0 })
	calls := r.slack.called("chat.postEphemeral")
	return fmt.Sprint(calls[len(calls)-1].Body["text"])
}

func (r *rig) quiet() {
	r.t.Helper()
	time.Sleep(100 * time.Millisecond) // async handlers have had time to act
}

func actionRig(t *testing.T) *rig {
	r := newRig(t, testRoutes)
	setupPeople(r)
	r.clr.setChanges(change("c-1", "web", "prod", 2, "group:default/payments", nil))
	return r
}

func TestClearFromSlackNamesTheLinkedPersonAndTheMessage(t *testing.T) {
	r := actionRig(t)
	authTime := time.Now().Unix() - 60
	r.link("T1", "U1", "user:ann", authTime)
	r.click(ActClear, "c-1", "U1", "C_PAY")
	m := r.modal()
	if m["callback_id"] != ModalClear {
		t.Fatalf("modal: %v", m["callback_id"])
	}
	// the form shows what is being cleared: the app, the tier, the head
	if txt := fmt.Sprint(m["blocks"]); !strings.Contains(txt, "0123456789abcdef") || !strings.Contains(txt, "tier 2") {
		t.Errorf("the modal shows the change and its head: %s", txt)
	}
	if r.clr.writeCount() != 0 {
		t.Fatal("clicking Clear writes nothing: the form comes first")
	}
	if resp := r.submit(m, "U1", map[string]string{"reason": "reviewed the diff"}); resp != nil {
		t.Fatalf("a good submission closes the form: %v", resp)
	}
	waitFor(t, "the write", func() bool { return r.clr.writeCount() == 1 })
	w := r.clr.lastWrite()
	if w.Path != "/v1/clearances/c-1/clear" {
		t.Errorf("path %s", w.Path)
	}
	h := w.Header
	if h.Get("X-Clearance-On-Behalf-Of") != "user:ann" { // from the link, not from anything Slack sent
		t.Errorf("on behalf of %q", h.Get("X-Clearance-On-Behalf-Of"))
	}
	if h.Get("X-Clearance-Via") != "slack" || h.Get("X-Clearance-Surface-Ref") != "https://acme.slack.com/archives/C_PAY/p1700000000000001" {
		t.Errorf("surface: %q %q", h.Get("X-Clearance-Via"), h.Get("X-Clearance-Surface-Ref"))
	}
	if h.Get("X-Clearance-Auth-Time") != fmt.Sprint(authTime) {
		t.Errorf("auth time %q: the link's proven IdP sign-in", h.Get("X-Clearance-Auth-Time"))
	}
	if h.Get("Authorization") != "Bearer sa-token-value" || w.Body["reason"] != "reviewed the diff" {
		t.Errorf("auth %q body %v", h.Get("Authorization"), w.Body)
	}
	if e := r.lastEphemeral(); !strings.Contains(e, "You cleared web / prod") || !strings.Contains(e, "cleared") {
		t.Errorf("the person is told: %s", e)
	}
}

func TestTheAuthTimeIsForwardedOnlyWhenItIsProven(t *testing.T) {
	for name, tc := range map[string]struct {
		authTime int64
		forward  bool
		want     string
	}{"the link has none": {0, true, ""}, "forwarding is off": {12345, false, ""}} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, testRoutes, func(c *Config) { c.ForwardAuthTime = tc.forward })
			setupPeople(r)
			r.clr.setChanges(change("c-1", "web", "prod", 2, "group:default/payments", nil))
			r.link("T1", "U1", "user:ann", tc.authTime)
			r.click(ActClear, "c-1", "U1", "C_PAY")
			r.submit(r.modal(), "U1", map[string]string{"reason": ""})
			waitFor(t, "the write", func() bool { return r.clr.writeCount() == 1 })
			if got := r.clr.lastWrite().Header.Get("X-Clearance-Auth-Time"); got != tc.want {
				t.Errorf("X-Clearance-Auth-Time %q", got)
			}
			if body := r.clr.lastWrite().Body; body != nil && body["reason"] != nil {
				t.Errorf("an empty note is not sent: %v", body)
			}
		})
	}
}

func TestSlackCannotNameAPerson(t *testing.T) {
	r := actionRig(t)
	// U9 is in the workspace and calls itself whatever it likes, but has no link
	r.click(ActClear, "c-1", "U9", "C_PAY")
	if e := r.lastEphemeral(); !strings.Contains(e, "/clearance link") {
		t.Errorf("an unlinked user is told to link: %s", e)
	}
	r.quiet()
	if len(r.slack.called("views.open")) != 0 || r.clr.writeCount() != 0 {
		t.Fatal("an unlinked user got a form or a write")
	}
	// a submission from an unlinked user is refused the same way (a modal can be forged by replaying its payload)
	r.link("T1", "U1", "user:ann", 0)
	r.click(ActClear, "c-1", "U1", "C_PAY")
	m := r.modal()
	r.slack.reset()
	r.submit(m, "U9", map[string]string{"reason": "x"})
	r.quiet()
	if r.clr.writeCount() != 0 {
		t.Fatal("a submission from another Slack user wrote")
	}
	// and a link of the same Slack user in another workspace does not apply: links are per workspace
	r.svc.Handle(bg, inbound(t, "interactive", map[string]any{"type": "block_actions", "trigger_id": "other-team", "team": map[string]any{"id": "T2"},
		"user": map[string]any{"id": "U1"}, "container": map[string]any{"channel_id": "C_PAY", "message_ts": "1.1"},
		"actions": []any{map[string]any{"action_id": ActClear, "value": "c-1"}}}))
	if e := r.lastEphemeral(); !strings.Contains(e, "not linked") {
		t.Errorf("the same user id in another workspace: %s", e)
	}
}

func TestAStaleLinkMustBeMadeAgain(t *testing.T) {
	r := actionRig(t)
	r.link("T1", "U1", "user:ann", 0)
	r.now = r.now.Add(31 * 24 * time.Hour)
	r.click(ActClear, "c-1", "U1", "C_PAY")
	if e := r.lastEphemeral(); !strings.Contains(e, "older than 30 days") || !strings.Contains(e, "/clearance link") {
		t.Errorf("stale: %s", e)
	}
	r.quiet()
	if len(r.slack.called("views.open")) != 0 {
		t.Fatal("a stale link opened a form")
	}
}

func TestTierThreeIsNeverClearedFromSlackButCanBeDenied(t *testing.T) {
	r := newRig(t, testRoutes)
	setupPeople(r)
	r.link("T1", "U1", "user:ann", 0)
	r.clr.setChanges(change("c-3", "web", "prod", 3, "group:default/payments", []string{"group:default/admins"}))
	r.click(ActClear, "c-3", "U1", "C_PAY") // forged: the message offers no such button
	e := r.lastEphemeral()
	if !strings.Contains(e, "tier 3") || !strings.Contains(e, "https://clearance-web.example/changes/c-3") {
		t.Errorf("a tier 3 clear is a link-out: %s", e)
	}
	r.quiet()
	if len(r.slack.called("views.open")) != 0 || r.clr.writeCount() != 0 {
		t.Fatal("a tier 3 clear was offered or sent")
	}
	// deny, at tier 3, in place
	r.slack.reset()
	r.click(ActDeny, "c-3", "U1", "C_PAY")
	m := r.modal()
	if m["callback_id"] != ModalDeny {
		t.Fatalf("deny modal: %v", m["callback_id"])
	}
	// a reason is required, shown next to the field; nothing is sent
	resp := r.submit(m, "U1", map[string]string{"reason": "  "})
	rm, _ := resp.(map[string]any)
	if rm["response_action"] != "errors" || r.clr.writeCount() != 0 {
		t.Fatalf("an empty reason: %v", resp)
	}
	r.submit(m, "U1", map[string]string{"reason": "wrong window"})
	waitFor(t, "the deny", func() bool { return r.clr.writeCount() == 1 })
	w := r.clr.lastWrite()
	if w.Path != "/v1/clearances/c-3/deny" || w.Body["reason"] != "wrong window" || w.Header.Get("X-Clearance-Via") != "slack" ||
		w.Header.Get("X-Clearance-On-Behalf-Of") != "user:ann" || w.Header.Get("X-Clearance-Surface-Ref") == "" {
		t.Errorf("deny: %s %v %v", w.Path, w.Body, w.Header)
	}
}

func TestTheTierPolicyIsAppliedAgainWhenTheFormIsSubmitted(t *testing.T) {
	r := actionRig(t)
	r.link("T1", "U1", "user:ann", 0)
	r.click(ActClear, "c-1", "U1", "C_PAY")
	m := r.modal() // opened on a tier 2 change
	// the change is re-tiered to 3 while the form is open (a push that touches a secret)
	c := change("c-1", "web", "prod", 3, "group:default/payments", []string{"group:default/admins"})
	r.clr.setChanges(c)
	r.submit(m, "U1", map[string]string{"reason": "ok"})
	if e := r.lastEphemeral(); !strings.Contains(e, "tier 3") {
		t.Errorf("%s", e)
	}
	r.quiet()
	if r.clr.writeCount() != 0 {
		t.Fatal("a tier 3 change was cleared from a form that showed tier 2")
	}
	// a head that moved is not the change the form showed
	r.slack.reset()
	c = change("c-1", "web", "prod", 2, "group:default/payments", nil)
	c["head"] = "fedcba9876543210"
	r.clr.setChanges(c)
	r.submit(m, "U1", map[string]string{"reason": "ok"})
	if e := r.lastEphemeral(); !strings.Contains(e, "moved") {
		t.Errorf("%s", e)
	}
	r.quiet()
	if r.clr.writeCount() != 0 {
		t.Fatal("a moved head was cleared")
	}
	// a change that is no longer holding is not written to
	r.slack.reset()
	c = change("c-1", "web", "prod", 2, "group:default/payments", nil)
	c["state"] = "cleared"
	r.clr.setChanges(c)
	r.submit(m, "U1", map[string]string{"reason": "ok"})
	if e := r.lastEphemeral(); !strings.Contains(e, "now cleared") {
		t.Errorf("%s", e)
	}
}

func TestWhoMayClearIsTheGatesRuleNotSlacks(t *testing.T) {
	r := actionRig(t)
	r.link("T1", "U2", "user:pat", 0) // the proposer
	r.click(ActClear, "c-1", "U2", "C_PAY")
	if e := r.lastEphemeral(); !strings.Contains(e, "proposer") {
		t.Errorf("the proposer: %s", e)
	}
	r.slack.reset()
	r.click(ActClear, "c-1", "U3", "C_PAY")
	r.link("T1", "U3", "user:bob", 0)
	r.click(ActClear, "c-1", "U3", "C_PAY")
	waitFor(t, "two messages", func() bool { return len(r.slack.called("chat.postEphemeral")) >= 2 })
	if e := r.lastEphemeral(); !strings.Contains(e, "neither group:default/payments nor an outside group") {
		t.Errorf("another team: %s", e)
	}
	r.quiet()
	if len(r.slack.called("views.open")) != 0 || r.clr.writeCount() != 0 {
		t.Fatal("a person the gate would refuse got a form")
	}
}

func TestWhatTheCoreRefusesIsShownPlainly(t *testing.T) {
	for name, tc := range map[string]struct {
		spec CallErrorSpec
		want []string
	}{
		"a stale sign-in": {CallErrorSpec{401, map[string]any{"error": "your sign-in is 2h0m0s old; this action needs one at most 30m0s old", "rule": "DG-AUTH-NOT-FRESH", "max_age": "30m0s", "age": "2h0m0s"}},
			[]string{"sign-in is too old", "30m0s", "/clearance link", "https://clearance-web.example/changes/c-1", "Nothing was changed"}},
		"already approved": {CallErrorSpec{409, map[string]any{"error": "user:ann already cleared this change", "rule": "DG-TWICE", "hint": "A second person is needed."}},
			[]string{"already cleared this change", "A second person is needed", "Nothing was changed"}},
		"not allowed from slack": {CallErrorSpec{403, map[string]any{"error": "not allowed", "rule": "DG-PERSON-ALLOWED"}},
			[]string{"not allowed to act from Slack", "Nothing was changed"}},
		"the core is down": {CallErrorSpec{503, map[string]any{"error": "db down"}}, []string{"unavailable", "Nothing was changed"}},
		"a missing change": {CallErrorSpec{404, map[string]any{"error": "no such change"}}, []string{"no such change", "Nothing was changed"}},
	} {
		t.Run(name, func(t *testing.T) {
			r := actionRig(t)
			r.link("T1", "U1", "user:ann", 0)
			r.click(ActClear, "c-1", "U1", "C_PAY")
			m := r.modal()
			r.clr.failWrite = &tc.spec
			r.submit(m, "U1", map[string]string{"reason": "x"})
			e := r.lastEphemeral()
			for _, w := range tc.want {
				if !strings.Contains(e, w) {
					t.Errorf("the message lacks %q: %s", w, e)
				}
			}
			if strings.Contains(e, "sa-token-value") {
				t.Error("a credential in a message")
			}
		})
	}
}

func TestResolveAnExceptionNeedsAnAdminAndTheRightFields(t *testing.T) {
	r := actionRig(t)
	r.link("T1", "U1", "user:ann", 0)
	r.link("T1", "U5", "user:ada", 0)
	r.click(ActResolve, "77", "U1", "C_WEB")
	if e := r.lastEphemeral(); !strings.Contains(e, "administrator") {
		t.Errorf("a non-admin: %s", e)
	}
	r.quiet()
	if len(r.slack.called("views.open")) != 0 {
		t.Fatal("a non-admin got the resolve form")
	}
	r.slack.reset()
	r.click(ActResolve, "77", "U5", "C_WEB")
	m := r.modal()
	if m["callback_id"] != ModalResolve {
		t.Fatalf("%v", m["callback_id"])
	}
	for name, vals := range map[string]map[string]string{
		"no state":                     {"note": "x"},
		"reverted without a cause":     {"state": "reverted"},
		"a cause that is not reverted": {"state": "ratified", "cause": "agent-caused"},
		"a state that is not one":      {"state": "obliterated"},
	} {
		if resp, _ := r.submit(m, "U5", vals).(map[string]any); resp["response_action"] != "errors" {
			t.Errorf("%s was accepted", name)
		}
	}
	if r.clr.writeCount() != 0 {
		t.Fatal("an invalid resolution was sent")
	}
	r.submit(m, "U5", map[string]string{"state": "reverted", "cause": "human-initiated", "note": "rolled back by ada"})
	waitFor(t, "the resolution", func() bool { return r.clr.writeCount() == 1 })
	w := r.clr.lastWrite()
	if w.Path != "/v1/observations/77/resolution" || w.Body["state"] != "reverted" || w.Body["cause"] != "human-initiated" || w.Body["note"] != "rolled back by ada" ||
		w.Header.Get("X-Clearance-Via") != "slack" || w.Header.Get("X-Clearance-On-Behalf-Of") != "user:ada" || w.Header.Get("X-Clearance-Surface-Ref") == "" {
		t.Errorf("resolution: %s %v %v", w.Path, w.Body, w.Header)
	}
}

func TestADoubleClickOpensOneForm(t *testing.T) {
	r := actionRig(t)
	r.link("T1", "U1", "user:ann", 0)
	payload := inbound(t, "interactive", map[string]any{"type": "block_actions", "trigger_id": "same", "team": map[string]any{"id": "T1"},
		"user": map[string]any{"id": "U1"}, "container": map[string]any{"channel_id": "C_PAY", "message_ts": "1.1"},
		"actions": []any{map[string]any{"action_id": ActClear, "value": "c-1"}}})
	r.svc.Handle(bg, payload)
	r.svc.Handle(bg, payload)
	r.modal()
	r.quiet()
	if n := len(r.slack.called("views.open")); n != 1 {
		t.Errorf("forms opened: %d", n)
	}
}

func TestSlashCommands(t *testing.T) {
	r := newRig(t, "")
	cmd := func(text string) string {
		resp := r.svc.Handle(bg, inbound(t, "slash_commands", map[string]any{"team_id": "T1", "user_id": "U1", "text": text, "command": "/clearance"}))
		return fmt.Sprint(resp.(map[string]any)["text"])
	}
	if got := cmd("status"); !strings.Contains(got, "Not linked") {
		t.Errorf("status: %s", got)
	}
	if got := cmd("dm off"); !strings.Contains(got, "Link your account first") {
		t.Errorf("dm: %s", got)
	}
	if got := cmd("link"); !strings.Contains(got, "https://clearance-slack.example/link?t=") {
		t.Errorf("link: %s", got)
	}
	r.link("T1", "U1", "user:ann", 0)
	if got := cmd("status"); !strings.Contains(got, "Linked as user:ann") || !strings.Contains(got, "Direct messages are on") {
		t.Errorf("status: %s", got)
	}
	cmd("dm off")
	if l, _ := r.store.GetLink(bg, "T1", "U1"); l.DM {
		t.Error("dm off")
	}
	if got := cmd("unlink"); !strings.Contains(got, "Unlinked") {
		t.Errorf("unlink: %s", got)
	}
	if l, _ := r.store.GetLink(bg, "T1", "U1"); l != nil {
		t.Error("still linked")
	}
	if got := cmd(""); !strings.Contains(got, "/clearance link") {
		t.Errorf("help: %s", got)
	}
}

func TestADeactivatedSlackAccountLosesItsLink(t *testing.T) {
	r := newRig(t, "")
	r.link("T1", "UGONE", "user:gone", 0)
	r.link("T1", "U1", "user:ann", 0)
	r.link("T1", "UEVT", "user:evt", 0)
	ev := map[string]any{"type": "event_callback", "event_id": "Ev1", "team_id": "T1",
		"event": map[string]any{"type": "user_change", "user": map[string]any{"id": "UEVT", "team_id": "T1", "deleted": true}}}
	r.svc.Handle(bg, inbound(t, "events_api", ev))
	if l, _ := r.store.GetLink(bg, "T1", "UEVT"); l != nil {
		t.Error("a deactivated user_change event keeps the link")
	}
	// a profile change that is not a deactivation keeps it
	ev["event_id"] = "Ev2"
	ev["event"] = map[string]any{"type": "user_change", "user": map[string]any{"id": "U1", "team_id": "T1", "deleted": false}}
	r.svc.Handle(bg, inbound(t, "events_api", ev))
	if l, _ := r.store.GetLink(bg, "T1", "U1"); l == nil {
		t.Error("a profile change removed a link")
	}
	// the sweep is the backstop for a missed event
	r.svc.SweepDeactivated(bg)
	if l, _ := r.store.GetLink(bg, "T1", "UGONE"); l != nil {
		t.Error("the sweep missed a deactivated account")
	}
	if l, _ := r.store.GetLink(bg, "T1", "U1"); l == nil {
		t.Error("the sweep removed an active account")
	}
}
