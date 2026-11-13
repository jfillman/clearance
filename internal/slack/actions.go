package slack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/observe"
)

// The actions: Clear and Deny on a change, Resolve on an exception. Every one runs the same way:
//
//  1. The Slack user must have a current identity link; the person named to the core is the link's, never Slack's.
//  2. The tier policy is applied here (clear up to ClearMaxTier, default 2; deny at any tier; break-glass and bulk
//     resolution are not offered), and again when the modal is submitted, on a fresh read of the change.
//  3. The write goes to the core as the delegate naming that person, with X-Clearance-Via: slack and the message's
//     permalink as the surface ref. The core decides (who may clear, DG-TWICE, freshness) and records.
//  4. Whatever the core says is shown to the person alone, with what to do about it.

type interaction struct {
	ids
	Type      string `json:"type"`
	TriggerID string `json:"trigger_id"`
	Container struct {
		ChannelID string `json:"channel_id"`
		MessageTS string `json:"message_ts"`
	} `json:"container"`
	Channel struct {
		ID string `json:"id"`
	} `json:"channel"`
	Message struct {
		TS string `json:"ts"`
	} `json:"message"`
	Actions []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
	View struct {
		ID              string `json:"id"`
		CallbackID      string `json:"callback_id"`
		PrivateMetadata string `json:"private_metadata"`
		State           struct {
			Values map[string]map[string]struct {
				Value          string `json:"value"`
				SelectedOption *struct {
					Value string `json:"value"`
				} `json:"selected_option"`
			} `json:"values"`
		} `json:"state"`
	} `json:"view"`
}

func (i *interaction) field(block string) string {
	if v, ok := i.View.State.Values[block][block]; ok {
		if v.SelectedOption != nil {
			return v.SelectedOption.Value
		}
		return strings.TrimSpace(v.Value)
	}
	return ""
}

// modalMeta travels in a modal's private_metadata: where the click was and what the modal showed.
type modalMeta struct {
	ID      string `json:"id,omitempty"`  // a change id
	Seq     int64  `json:"seq,omitempty"` // an exception's record seq
	Channel string `json:"ch"`
	TS      string `json:"ts"`
	Link    string `json:"link"` // the message's permalink: the surface ref
	Head    string `json:"head,omitempty"`
	Tier    int    `json:"tier,omitempty"`
}

func (s *Service) interactive(ctx context.Context, raw json.RawMessage) any {
	var in interaction
	if json.Unmarshal(raw, &in) != nil {
		return nil
	}
	if in.TriggerID != "" && s.Dedupe != nil && !s.Dedupe.First("trig:"+in.TriggerID+":"+in.View.ID) {
		return nil
	}
	switch in.Type {
	case "block_actions":
		if len(in.Actions) == 0 {
			return nil
		}
		a := in.Actions[0]
		ch, ts := in.Container.ChannelID, in.Container.MessageTS
		if ch == "" {
			ch = in.Channel.ID
		}
		if ts == "" {
			ts = in.Message.TS
		}
		click := click{team: in.Team.ID, user: in.User.ID, trigger: in.TriggerID, channel: ch, ts: ts, value: a.Value}
		switch a.ActionID {
		case ActClear:
			s.async(func(ctx context.Context) { s.openChange(ctx, click, true) })
		case ActDeny:
			s.async(func(ctx context.Context) { s.openChange(ctx, click, false) })
		case ActResolve:
			s.async(func(ctx context.Context) { s.openResolve(ctx, click) })
		}
	case "view_submission":
		return s.submit(ctx, &in)
	}
	return nil
}

type click struct {
	team, user, trigger, channel, ts, value string
}

// tell shows text to the person alone, where they clicked.
func (s *Service) tell(ctx context.Context, channel, user, text string) {
	if channel == "" {
		var err error
		if channel, err = s.Slack.OpenDM(ctx, user); err != nil {
			return
		}
	}
	if err := s.Slack.Ephemeral(ctx, channel, user, text); err != nil {
		s.Log.Warn("an ephemeral message failed", "error", err.Error())
	}
}

// linked is the person's current link, or the reason there is none (already shown to them).
func (s *Service) linked(ctx context.Context, team, user, channel string) *Link {
	l, err := s.Store.GetLink(ctx, team, user)
	switch {
	case err != nil:
		s.tell(ctx, channel, user, "Clearance could not check your link just now; nothing was done. Try again.")
		return nil
	case l == nil:
		s.tell(ctx, channel, user, "This Slack account is not linked to a Clearance sign-in, so Clearance does not know who you are. Run `/clearance link` (once), then try again.")
		return nil
	case l.Stale(s.now(), s.Cfg.RelinkAfter):
		s.tell(ctx, channel, user, "Your link is older than "+humanDays(s.Cfg.RelinkAfter)+" and must be verified again before you can act from Slack. Run `/clearance link`, then try again.")
		return nil
	}
	return l
}

// stepUp is the text for an action that needs a fresh sign-in somewhere else.
func (s *Service) stepUp(c *gate.Change) string {
	if u := webLink(s.Cfg.WebURL, c.ID); u != "" {
		return fmt.Sprintf("Open <%s|the change> and sign in again to clear it.", u)
	}
	return fmt.Sprintf("Use the CLI: `clearance changes clear %s` (it signs you in again first).", c.ID)
}

// explain turns a failed call into what a person should read: what happened and what to do. Never a token, never
// more than the server's own (already redacted) message.
func (s *Service) explain(err error, c *gate.Change) string {
	var ce *CallError
	if errors.As(err, &ce) {
		hint := ""
		if ce.Hint != "" {
			hint = " " + ce.Hint
		}
		switch {
		case ce.Status == 401 && ce.Rule == gate.RuleAuthNotFresh:
			how := "Run `/clearance link` to sign in again and try again"
			if c != nil {
				how += ". Or: " + s.stepUp(c)
			}
			lim := ""
			if ce.MaxAge != "" {
				lim = " (this action needs a sign-in at most " + ce.MaxAge + " old)"
			}
			return "Your sign-in is too old for this action" + lim + ". Nothing was changed. " + how
		case ce.Status == 401:
			return "Clearance did not accept this service's own credential, so nothing was done. Tell a Clearance administrator."
		case ce.Status == 403 && ce.Rule == "DG-PERSON-ALLOWED":
			return "You are not allowed to act from Slack. Nothing was changed. Use the CLI or the web page."
		case ce.Status == 403:
			return "Clearance refused: " + ce.Message + "." + hint + " Nothing was changed."
		case ce.Status == 404:
			return "Clearance has no such change for you (it may be gone, or not yours to see). Nothing was changed."
		case ce.Status == 409:
			return "That cannot be done now: " + ce.Message + "." + hint + " Nothing was changed."
		case ce.Status == 400 || ce.Status == 422:
			return "Clearance did not accept that: " + ce.Message + ". Nothing was changed."
		case ce.Status == 429 || ce.Status >= 500:
			return "Clearance is unavailable right now. Nothing was changed. Try again shortly, or use the CLI."
		}
		return fmt.Sprintf("Clearance answered %d: %s. Nothing was changed.", ce.Status, ce.Message)
	}
	return "Clearance could not be reached. Nothing was changed. Try again shortly, or use the CLI."
}

// permalink is the message's permalink, or a stable fallback naming it (the surface ref is claimed, not checked).
func (s *Service) permalink(ctx context.Context, team, channel, ts string) string {
	if channel == "" || ts == "" {
		return "slack:" + team
	}
	if p, err := s.Slack.Permalink(ctx, channel, ts); err == nil && p != "" {
		return p
	}
	return fmt.Sprintf("slack://%s/%s/%s", team, channel, ts)
}

// -- clear and deny ----------------------------------------------------------------------------------------------

func (s *Service) openChange(ctx context.Context, ck click, clear bool) {
	l := s.linked(ctx, ck.team, ck.user, ck.channel)
	if l == nil {
		return
	}
	c, err := s.Clear.Change(ctx, ck.value, l.Person)
	if err != nil {
		s.tell(ctx, ck.channel, ck.user, s.explain(err, nil))
		return
	}
	if c.State != gate.StateHolding {
		s.tell(ctx, ck.channel, ck.user, fmt.Sprintf("This change is already %s; there is nothing to do.", c.State))
		return
	}
	if clear {
		if msg := s.clearRefusal(ctx, c, l); msg != "" {
			s.tell(ctx, ck.channel, ck.user, msg)
			return
		}
	}
	meta := modalMeta{ID: c.ID, Channel: ck.channel, TS: ck.ts, Link: s.permalink(ctx, ck.team, ck.channel, ck.ts), Head: c.Head, Tier: c.Tier}
	view := changeModal(c, meta, clear)
	if err := s.Slack.OpenModal(ctx, ck.trigger, view); err != nil {
		s.Log.Warn("opening a modal failed", "error", err.Error())
		s.tell(ctx, ck.channel, ck.user, "Slack could not open the form (it must open within three seconds of the click). Click the button again.")
	}
}

// clearRefusal is why this person may not clear this change from Slack, or "". The tier policy first, then the gate's
// own rule for the person (applied to the groups the api reports for them), so that the form is not offered for a
// clear the core is certain to refuse. The core still decides on submit.
func (s *Service) clearRefusal(ctx context.Context, c *gate.Change, l *Link) string {
	if c.Tier > s.Cfg.ClearMaxTier {
		return fmt.Sprintf("A tier %d change is not cleared from Slack: it needs a fresh sign-in. %s", c.Tier, s.stepUp(c))
	}
	pi, err := s.Notifier.Person(ctx, l.Person)
	if err != nil {
		return s.explain(err, c)
	}
	if _, err := gate.RoleFor(l.Person, pi.groups, c); err != nil {
		var ge *gate.Error
		if errors.As(err, &ge) {
			return "You cannot clear this change: " + ge.Message + "." + hintOf(ge.Hint)
		}
		return "You cannot clear this change."
	}
	return ""
}

func hintOf(h string) string {
	if h == "" {
		return ""
	}
	return " " + h
}

func changeModal(c *gate.Change, m modalMeta, clear bool) map[string]any {
	meta, _ := json.Marshal(m)
	summary := fmt.Sprintf("*%s / %s*, tier %d\nTarget: %s\nHead: `%s`\nWhy this tier: %s\nApproved by: %s",
		mrkdwn(c.App), mrkdwn(c.Env), c.Tier, mrkdwn(c.Target), mrkdwn(clip(c.Head, 40)), whyTier(c), approvers(c))
	blocks := []any{section(summary)}
	title, submit, cb := "Deny change", "Deny", ModalDeny
	label, optional := "Reason (recorded with the denial)", false
	if clear {
		title, submit, cb = "Clear change", "Clear", ModalClear
		label, optional = "Note (optional, recorded with your approval)", true
		blocks = append(blocks, context_("You are clearing this as yourself. Clearance records you, this Slack message and the head above."))
	}
	blocks = append(blocks, map[string]any{"type": "input", "block_id": "reason", "optional": optional,
		"label":   map[string]any{"type": "plain_text", "text": label},
		"element": map[string]any{"type": "plain_text_input", "action_id": "reason", "multiline": true, "max_length": gate.MaxReason}})
	return map[string]any{"type": "modal", "callback_id": cb, "private_metadata": string(meta),
		"title": map[string]any{"type": "plain_text", "text": title}, "submit": map[string]any{"type": "plain_text", "text": submit},
		"close": map[string]any{"type": "plain_text", "text": "Cancel"}, "blocks": blocks}
}

// -- resolve -----------------------------------------------------------------------------------------------------

func (s *Service) openResolve(ctx context.Context, ck click) {
	l := s.linked(ctx, ck.team, ck.user, ck.channel)
	if l == nil {
		return
	}
	seq := int64(0)
	if _, err := fmt.Sscanf(ck.value, "%d", &seq); err != nil || seq <= 0 {
		return
	}
	pi, err := s.Notifier.Person(ctx, l.Person)
	if err != nil {
		s.tell(ctx, ck.channel, ck.user, s.explain(err, nil))
		return
	}
	if !pi.admin {
		s.tell(ctx, ck.channel, ck.user, "Only an administrator resolves an exception. You are linked as "+l.Person+".")
		return
	}
	meta, _ := json.Marshal(modalMeta{Seq: seq, Channel: ck.channel, TS: ck.ts, Link: s.permalink(ctx, ck.team, ck.channel, ck.ts)})
	opt := func(v string) any {
		return map[string]any{"text": map[string]any{"type": "plain_text", "text": v}, "value": v}
	}
	var states, causes []any
	for _, v := range observe.ResolutionStates {
		states = append(states, opt(v))
	}
	for _, v := range observe.RevertCauses {
		causes = append(causes, opt(v))
	}
	in := func(id, label string, optional bool, el map[string]any) map[string]any {
		el["action_id"] = id
		return map[string]any{"type": "input", "block_id": id, "optional": optional, "label": map[string]any{"type": "plain_text", "text": label}, "element": el}
	}
	view := map[string]any{"type": "modal", "callback_id": ModalResolve, "private_metadata": string(meta),
		"title":  map[string]any{"type": "plain_text", "text": "Resolve exception"},
		"submit": map[string]any{"type": "plain_text", "text": "Resolve"}, "close": map[string]any{"type": "plain_text", "text": "Cancel"},
		"blocks": []any{
			section(fmt.Sprintf("Record %d. A resolution is appended to the evidence, naming you; the newest one wins.", seq)),
			in("state", "Resolution", false, map[string]any{"type": "static_select", "options": states}),
			in("cause", "Cause (only when reverted)", true, map[string]any{"type": "static_select", "options": causes}),
			in("note", "Note (optional)", true, map[string]any{"type": "plain_text_input", "multiline": true, "max_length": 1000}),
		}}
	if err := s.Slack.OpenModal(ctx, ck.trigger, view); err != nil {
		s.tell(ctx, ck.channel, ck.user, "Slack could not open the form. Click the button again.")
	}
}

// -- submissions -------------------------------------------------------------------------------------------------

func errorsResp(block, msg string) map[string]any {
	return map[string]any{"response_action": "errors", "errors": map[string]string{block: msg}}
}

// submit validates a modal synchronously (what Slack can show next to the field) and does the write after the
// acknowledgement.
func (s *Service) submit(_ context.Context, in *interaction) any {
	var m modalMeta
	if json.Unmarshal([]byte(in.View.PrivateMetadata), &m) != nil {
		return nil
	}
	team, user := in.Team.ID, in.User.ID
	switch in.View.CallbackID {
	case ModalDeny:
		reason := in.field("reason")
		if reason == "" {
			return errorsResp("reason", "A reason is required; it is recorded.")
		}
		s.async(func(ctx context.Context) { s.doChange(ctx, team, user, m, reason, false) })
	case ModalClear:
		reason := in.field("reason")
		s.async(func(ctx context.Context) { s.doChange(ctx, team, user, m, reason, true) })
	case ModalResolve:
		state, cause, note := in.field("state"), in.field("cause"), in.field("note")
		switch {
		case !slices.Contains(observe.ResolutionStates, state):
			return errorsResp("state", "Choose a resolution.")
		case state == "reverted" && !slices.Contains(observe.RevertCauses, cause):
			return errorsResp("cause", "A reverted exception needs its cause.")
		case state != "reverted" && cause != "":
			return errorsResp("cause", "A cause is only for a reverted exception.")
		}
		s.async(func(ctx context.Context) { s.doResolve(ctx, team, user, m, state, cause, note) })
	}
	return nil
}

func (s *Service) doChange(ctx context.Context, team, user string, m modalMeta, reason string, clear bool) {
	l := s.linked(ctx, team, user, m.Channel)
	if l == nil {
		return
	}
	// The change as the person sees it now: it may have moved since the form opened.
	c, err := s.Clear.Change(ctx, m.ID, l.Person)
	if err != nil {
		s.tell(ctx, m.Channel, user, s.explain(err, nil))
		return
	}
	switch {
	case c.State != gate.StateHolding:
		s.tell(ctx, m.Channel, user, fmt.Sprintf("This change is now %s; nothing was done.", c.State))
		return
	case c.Head != m.Head:
		s.tell(ctx, m.Channel, user, "The change moved while the form was open (a new head). Nothing was done; look at it again.")
		return
	}
	verb, path, body := "denied", "/deny", map[string]any{"reason": reason}
	if clear {
		if msg := s.clearRefusal(ctx, c, l); msg != "" { // the tier policy, on the tier as it is now
			s.tell(ctx, m.Channel, user, msg)
			return
		}
		verb, path, body = "cleared", "/clear", nil
		if reason != "" {
			body = map[string]any{"reason": reason}
		}
	}
	var out struct {
		State    string `json:"state"`
		AuditSeq any    `json:"audit_seq"`
	}
	err = s.Clear.Post(ctx, "/v1/clearances/"+url.PathEscape(c.ID)+path, body, l.Person, s.Clear.WriteHeaders(m.Link, l), &out)
	if err != nil {
		s.Log.Info("a write from slack was refused", "change", c.ID, "person", l.Person, "error", err.Error())
		s.tell(ctx, m.Channel, user, s.explain(err, c))
		return
	}
	s.Log.Info("a write from slack", "change", c.ID, "person", l.Person, "action", verb)
	next := "The change is now " + out.State + "."
	if out.State == gate.StateHolding {
		next = "Your approval is recorded; the change is still holding for more."
	}
	s.tell(ctx, m.Channel, user, "You "+verb+" "+c.App+" / "+c.Env+". "+next)
	s.Notifier.Poke()
}

func (s *Service) doResolve(ctx context.Context, team, user string, m modalMeta, state, cause, note string) {
	l := s.linked(ctx, team, user, m.Channel)
	if l == nil {
		return
	}
	body := map[string]any{"state": state}
	if cause != "" {
		body["cause"] = cause
	}
	if note != "" {
		body["note"] = note
	}
	err := s.Clear.Post(ctx, fmt.Sprintf("/v1/observations/%d/resolution", m.Seq), body, l.Person, s.Clear.WriteHeaders(m.Link, l), nil)
	if err != nil {
		s.Log.Info("a resolution from slack was refused", "seq", m.Seq, "person", l.Person, "error", err.Error())
		s.tell(ctx, m.Channel, user, s.explain(err, nil))
		return
	}
	s.tell(ctx, m.Channel, user, fmt.Sprintf("Recorded: exception %d is %s.", m.Seq, state))
}
