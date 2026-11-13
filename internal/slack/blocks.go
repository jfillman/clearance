package slack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/gate"
)

// Action and callback ids.
const (
	ActClear   = "clr_clear"
	ActDeny    = "clr_deny"
	ActResolve = "clr_resolve"
	ActOpen    = "clr_open" // a URL button: Slack still sends the click, which is ignored

	ModalClear   = "clr_clear_modal"
	ModalDeny    = "clr_deny_modal"
	ModalResolve = "clr_resolve_modal"
)

// RenderOpts are what a message is rendered with.
type RenderOpts struct {
	ClearMaxTier int
	WebURL       string // "https://host/changes/{id}"
	Now          time.Time
}

func webLink(tmpl, id string) string {
	if tmpl == "" {
		return ""
	}
	return strings.ReplaceAll(tmpl, "{id}", id)
}

func mrkdwn(s string) string {
	// Slack control characters; the rest of what a change carries is data, not markup.
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func slackDate(t time.Time) string {
	return fmt.Sprintf("<!date^%d^{date_short_pretty} {time}|%s>", t.Unix(), t.UTC().Format("2006-01-02 15:04 UTC"))
}

func section(text string) map[string]any {
	return map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": clip(text, 2900)}}
}

func context_(text string) map[string]any {
	return map[string]any{"type": "context", "elements": []any{map[string]any{"type": "mrkdwn", "text": clip(text, 2900)}}}
}

func button(actionID, label, value, style string) map[string]any {
	b := map[string]any{"type": "button", "action_id": actionID, "text": map[string]any{"type": "plain_text", "text": label}, "value": value}
	if style != "" {
		b["style"] = style
	}
	return b
}

func urlButton(label, u string) map[string]any {
	return map[string]any{"type": "button", "action_id": ActOpen, "text": map[string]any{"type": "plain_text", "text": label}, "url": u}
}

// whyTier is the first three reasons for the tier, then how many more.
func whyTier(c *gate.Change) string {
	if len(c.Reasons) == 0 {
		return "no reason recorded"
	}
	var parts []string
	for i, r := range c.Reasons {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("and %d more", len(c.Reasons)-3))
			break
		}
		parts = append(parts, fmt.Sprintf("`%s` (%s)", mrkdwn(clip(r.Subject, 80)), mrkdwn(clip(r.Rule, 60))))
	}
	return strings.Join(parts, ", ")
}

func approvers(c *gate.Change) string {
	if len(c.Approvals) == 0 {
		return "none yet"
	}
	var p []string
	for _, a := range c.Approvals {
		p = append(p, fmt.Sprintf("%s (%s)", mrkdwn(a.Person), mrkdwn(a.Role)))
	}
	return strings.Join(p, ", ")
}

// RenderChange is the thread root of a change: what it is, why this tier, who must clear it and who has, and the
// buttons that fit the tier policy. A change that is no longer holding shows how it ended and no buttons. Nothing
// secret-bearing is shown: only what the api's redacted view of a change carries (ids, tier reasons, groups, people).
func RenderChange(c *gate.Change, o RenderOpts) (string, []any) {
	title := fmt.Sprintf("%s / %s", c.App, c.Env)
	text := fmt.Sprintf("Clearance: %s, tier %d, %s", title, c.Tier, c.State)
	head := fmt.Sprintf("*%s*  |  tier %d  |  %s", mrkdwn(title), c.Tier, c.State)
	if u := webLink(o.WebURL, c.ID); u != "" {
		head = fmt.Sprintf("*<%s|%s>*  |  tier %d  |  %s", u, mrkdwn(title), c.Tier, c.State)
	}
	var b []any
	b = append(b, section(head))
	var fields []any
	add := func(k, v string) {
		fields = append(fields, map[string]any{"type": "mrkdwn", "text": clip("*"+k+"*\n"+v, 1900)})
	}
	add("Change", "`"+mrkdwn(c.ID)+"`")
	add("Proposer", mrkdwn(c.Proposer))
	add("Target", mrkdwn(c.Target))
	if c.Requirement != nil {
		add("Needs", mrkdwn(c.Requirement.Words()))
	}
	add("Approved by", approvers(c))
	if c.State == gate.StateHolding {
		add("Expires", slackDate(c.ExpiresAt.Time))
	}
	b = append(b, map[string]any{"type": "section", "fields": fields})
	b = append(b, context_("Why this tier: "+whyTier(c)))
	switch c.State {
	case gate.StateHolding:
		var acts []any
		switch {
		case c.Tier <= o.ClearMaxTier:
			acts = append(acts, button(ActClear, "Clear", c.ID, "primary"))
		default:
			if u := webLink(o.WebURL, c.ID); u != "" {
				acts = append(acts, urlButton("Open to clear (sign in again)", u))
			} else {
				b = append(b, context_(fmt.Sprintf("A tier %d change is cleared with a fresh sign-in, not from Slack: `clearance changes clear %s`", c.Tier, mrkdwn(c.ID))))
			}
		}
		acts = append(acts, button(ActDeny, "Deny...", c.ID, "danger"))
		b = append(b, map[string]any{"type": "actions", "elements": acts})
	case gate.StateCleared:
		who := ""
		if c.ClearedBy != nil {
			who = " by " + mrkdwn(*c.ClearedBy)
		}
		b = append(b, context_("Cleared"+who))
	case gate.StateDenied:
		s := "Denied"
		if c.DeniedBy != nil {
			s += " by " + mrkdwn(*c.DeniedBy)
		}
		if c.DenyReason != nil {
			s += ": " + mrkdwn(clip(*c.DenyReason, 300))
		}
		b = append(b, context_(s))
	default:
		b = append(b, context_("Ended: "+c.State))
	}
	return text, b
}

// Digest is a short hash of what a message shows.
func Digest(text string, blocks []any) string {
	raw, _ := json.Marshal([]any{text, blocks})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// RenderAlert is a message about something that is not a change: an exception, break-glass, coverage, attestations.
// resolveSeq, when positive, adds the Resolve button (exceptions a person may resolve).
func RenderAlert(title string, lines []string, resolveSeq int64) (string, []any) {
	b := []any{section("*" + mrkdwn(title) + "*")}
	if len(lines) > 0 {
		var esc []string
		for _, l := range lines {
			esc = append(esc, mrkdwn(l))
		}
		b = append(b, section(strings.Join(esc, "\n")))
	}
	if resolveSeq > 0 {
		b = append(b, map[string]any{"type": "actions", "elements": []any{button(ActResolve, "Resolve...", fmt.Sprint(resolveSeq), "")}})
	}
	return title, b
}
