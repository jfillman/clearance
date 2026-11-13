package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Service is the Slack side of Clearance: it takes what Slack sends (commands, interactions, events) and does what
// the tier policy and the identity link allow, through the core as a delegate.
type Service struct {
	Cfg      *Config
	Store    Store
	Slack    *API
	Clear    *Client
	Link     *LinkFlow
	Notifier *Notifier
	Log      *slog.Logger
	Dedupe   *Dedupe
	Now      func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// async runs slow work after the three-second acknowledgement, detached from the request, with its own deadline.
func (s *Service) async(f func(ctx context.Context)) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error("a Slack handler panicked", "panic", fmt.Sprint(r))
			}
		}()
		f(ctx)
	}()
}

type ids struct {
	Team struct {
		ID string `json:"id"`
	} `json:"team"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
}

// Handle routes one Inbound.
func (s *Service) Handle(ctx context.Context, in Inbound) any {
	switch in.Kind {
	case "slash_commands":
		return s.command(ctx, in.Payload)
	case "interactive":
		return s.interactive(ctx, in.Payload)
	case "events_api":
		s.event(ctx, in.Payload)
	}
	return nil
}

func ephemeral(text string) map[string]any {
	return map[string]any{"response_type": "ephemeral", "text": text}
}

// -- the slash command -------------------------------------------------------------------------------------------

const helpText = "`/clearance link` links this Slack account to your Clearance sign-in (once; repeated every 30 days)\n" +
	"`/clearance status` shows who you are linked as\n" +
	"`/clearance dm on|off` turns direct messages about changes waiting on you on or off\n" +
	"`/clearance unlink` removes the link"

func (s *Service) command(ctx context.Context, raw json.RawMessage) any {
	var c struct {
		Team string `json:"team_id"`
		User string `json:"user_id"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Team == "" || c.User == "" {
		return ephemeral("That was not a command Clearance understands.")
	}
	f := strings.Fields(strings.ToLower(c.Text))
	if len(f) == 0 {
		return ephemeral(helpText)
	}
	switch f[0] {
	case "link":
		u := s.Link.NewURL(c.Team, c.User)
		return ephemeral(fmt.Sprintf("Open this link to sign in with Slack and then with your Clearance identity provider; it works once, for ten minutes:\n<%s|Link my account>", u))
	case "unlink":
		ok, err := s.Store.DeleteLink(ctx, c.Team, c.User)
		switch {
		case err != nil:
			return ephemeral("Could not unlink just now; try again.")
		case ok:
			return ephemeral("Unlinked. Clearance no longer acts for this Slack account. `/clearance link` links it again.")
		}
		return ephemeral("This Slack account was not linked.")
	case "status":
		l, err := s.Store.GetLink(ctx, c.Team, c.User)
		switch {
		case err != nil:
			return ephemeral("Could not read the link just now; try again.")
		case l == nil:
			return ephemeral("Not linked. `/clearance link` links this Slack account to your Clearance sign-in.")
		}
		stale := ""
		if l.Stale(s.now(), s.Cfg.RelinkAfter) {
			stale = " The link is older than " + humanDays(s.Cfg.RelinkAfter) + " and must be made again before you can act: `/clearance link`."
		}
		dm := "on"
		if !l.DM {
			dm = "off"
		}
		return ephemeral(fmt.Sprintf("Linked as %s (verified %s). Direct messages are %s.%s", l.Person, l.VerifiedAt.UTC().Format("2006-01-02"), dm, stale))
	case "dm":
		if len(f) != 2 || (f[1] != "on" && f[1] != "off") {
			return ephemeral("`/clearance dm on` or `/clearance dm off`")
		}
		if err := s.Store.SetDM(ctx, c.Team, c.User, f[1] == "on"); err != nil {
			if err == ErrNotFound {
				return ephemeral("Link your account first: `/clearance link`.")
			}
			return ephemeral("Could not save that just now; try again.")
		}
		return ephemeral("Direct messages are " + f[1] + ".")
	}
	return ephemeral(helpText)
}

func humanDays(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d days", int(d/(24*time.Hour)))
	}
	return d.String()
}

// -- events ------------------------------------------------------------------------------------------------------

func (s *Service) event(ctx context.Context, raw json.RawMessage) {
	var e struct {
		EventID string `json:"event_id"`
		TeamID  string `json:"team_id"`
		Event   struct {
			Type string `json:"type"`
			User struct {
				ID      string `json:"id"`
				TeamID  string `json:"team_id"`
				Deleted bool   `json:"deleted"`
			} `json:"user"`
		} `json:"event"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return
	}
	if e.EventID != "" && s.Dedupe != nil && !s.Dedupe.First("evt:"+e.EventID) {
		return
	}
	switch e.Event.Type {
	case "user_change":
		// A deactivated account loses its link at once; reactivation needs the link flow again.
		if e.Event.User.Deleted {
			team := e.Event.User.TeamID
			if team == "" {
				team = e.TeamID
			}
			if ok, err := s.Store.DeleteLink(ctx, team, e.Event.User.ID); err == nil && ok {
				s.Log.Info("slack account deactivated: link removed", "team", team, "slack_user", e.Event.User.ID)
			}
		}
	case "tokens_revoked", "app_uninstalled":
		s.Log.Warn("slack revoked this app's access", "event", e.Event.Type)
	}
}

// SweepDeactivated removes the links of Slack accounts that are deactivated: the periodic backstop for a missed
// user_change event.
func (s *Service) SweepDeactivated(ctx context.Context) {
	links, err := s.Store.ListLinks(ctx)
	if err != nil {
		return
	}
	for _, l := range links {
		deleted, err := s.Slack.UserDeleted(ctx, l.User)
		if IsErrorCode(err, "user_not_found") {
			deleted, err = true, nil
		}
		if err != nil {
			continue
		}
		if deleted {
			if _, err := s.Store.DeleteLink(ctx, l.Team, l.User); err == nil {
				s.Log.Info("slack account deactivated: link removed", "team", l.Team, "slack_user", l.User)
			}
		}
	}
}
