package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// API is the Slack Web API client: the few methods the service uses, each a JSON POST with the bot token. It paces
// posts per channel (Slack allows about one message a second to a channel) and honors 429 Retry-After.
type API struct {
	Base     string // https://slack.com/api
	BotToken string
	// BotTokenFn, when set, supplies the bot token on each call (read from the mounted secret, never held).
	BotTokenFn func() string
	HTTP       *http.Client
	// MinInterval is the least time between two posts to one channel.
	MinInterval time.Duration
	Sleep       func(context.Context, time.Duration) error // test hook

	mu   sync.Mutex
	next map[string]time.Time // channel -> earliest next post
}

// NewAPI is a client for base with the bot token.
func NewAPI(base, botToken string, min time.Duration) *API {
	return &API{Base: strings.TrimRight(base, "/"), BotToken: botToken, MinInterval: min,
		HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		next: map[string]time.Time{}}
}

// Error is Slack's {"ok": false, "error": code}.
type Error struct {
	Method, Code string
}

func (e *Error) Error() string { return "slack " + e.Method + ": " + e.Code }

func (a *API) bot() string {
	if a.BotTokenFn != nil {
		return a.BotTokenFn()
	}
	return a.BotToken
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (a *API) sleep(ctx context.Context, d time.Duration) error {
	if a.Sleep != nil {
		return a.Sleep(ctx, d)
	}
	return sleep(ctx, d)
}

// pace waits for the channel's turn.
func (a *API) pace(ctx context.Context, channel string) error {
	if a.MinInterval <= 0 || channel == "" {
		return nil
	}
	a.mu.Lock()
	now := time.Now()
	at := a.next[channel]
	if at.Before(now) {
		at = now
	}
	a.next[channel] = at.Add(a.MinInterval)
	a.mu.Unlock()
	return a.sleep(ctx, time.Until(at))
}

// call POSTs a JSON body to method with token and decodes the answer into out. A 429 waits Retry-After and tries
// again, up to three times.
func (a *API) call(ctx context.Context, token, method string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	for try := 0; ; try++ {
		req, err := http.NewRequestWithContext(ctx, "POST", a.Base+"/"+method, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := a.HTTP.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			return fmt.Errorf("slack %s: %w", method, err)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests && try < 3 {
			wait, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
			if wait < 1 {
				wait = 1
			}
			if err := a.sleep(ctx, time.Duration(wait)*time.Second); err != nil {
				return err
			}
			continue
		}
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("slack %s: HTTP %d", method, resp.StatusCode)
		}
		var env struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return fmt.Errorf("slack %s: not JSON", method)
		}
		if !env.OK {
			return &Error{Method: method, Code: env.Error}
		}
		if out != nil {
			return json.Unmarshal(raw, out)
		}
		return nil
	}
}

// Posted is a message's place: its conversation and ts.
type Posted struct {
	Channel string `json:"channel"`
	TS      string `json:"ts"`
}

// Post sends blocks (text is the notification fallback) to channel, in a thread when threadTS is set.
func (a *API) Post(ctx context.Context, channel, text string, blocks []any, threadTS string) (Posted, error) {
	if err := a.pace(ctx, channel); err != nil {
		return Posted{}, err
	}
	body := map[string]any{"channel": channel, "text": text, "blocks": blocks, "unfurl_links": false, "unfurl_media": false}
	if threadTS != "" {
		body["thread_ts"] = threadTS
	}
	var out Posted
	err := a.call(ctx, a.bot(), "chat.postMessage", body, &out)
	return out, err
}

// Update replaces a message's text and blocks.
func (a *API) Update(ctx context.Context, channel, ts, text string, blocks []any) error {
	if err := a.pace(ctx, channel); err != nil {
		return err
	}
	return a.call(ctx, a.bot(), "chat.update", map[string]any{"channel": channel, "ts": ts, "text": text, "blocks": blocks}, nil)
}

// Ephemeral shows text only to user in channel.
func (a *API) Ephemeral(ctx context.Context, channel, user, text string) error {
	return a.call(ctx, a.bot(), "chat.postEphemeral", map[string]any{"channel": channel, "user": user, "text": text}, nil)
}

// OpenModal opens view with a trigger id (valid for three seconds).
func (a *API) OpenModal(ctx context.Context, triggerID string, view map[string]any) error {
	return a.call(ctx, a.bot(), "views.open", map[string]any{"trigger_id": triggerID, "view": view}, nil)
}

// OpenDM opens (or finds) the direct message conversation with user.
func (a *API) OpenDM(ctx context.Context, user string) (string, error) {
	var out struct {
		Channel struct {
			ID string `json:"id"`
		} `json:"channel"`
	}
	err := a.call(ctx, a.bot(), "conversations.open", map[string]any{"users": user}, &out)
	return out.Channel.ID, err
}

// Permalink is the permanent link of a message.
func (a *API) Permalink(ctx context.Context, channel, ts string) (string, error) {
	var out struct {
		Permalink string `json:"permalink"`
	}
	err := a.call(ctx, a.bot(), "chat.getPermalink", map[string]any{"channel": channel, "message_ts": ts}, &out)
	return out.Permalink, err
}

// UserDeleted says whether the Slack account is deactivated.
func (a *API) UserDeleted(ctx context.Context, user string) (bool, error) {
	var out struct {
		User struct {
			Deleted bool `json:"deleted"`
		} `json:"user"`
	}
	err := a.call(ctx, a.bot(), "users.info", map[string]any{"user": user}, &out)
	return out.User.Deleted, err
}

// ConnectionsOpen asks for a Socket Mode websocket URL with the app-level token.
func (a *API) ConnectionsOpen(ctx context.Context, appToken string) (string, error) {
	var out struct {
		URL string `json:"url"`
	}
	err := a.call(ctx, appToken, "apps.connections.open", map[string]any{}, &out)
	return out.URL, err
}

// IsErrorCode says whether err is a Slack error with code.
func IsErrorCode(err error, code string) bool {
	var se *Error
	return errors.As(err, &se) && se.Code == code
}
