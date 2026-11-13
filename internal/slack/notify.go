package slack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/gate"
)

// Notifier keeps Slack's view of the gate's changes: one message (a thread root) per change per destination, a DM to
// each linked person who may clear it now, the owner group's channel, and a reply when it moves. Clearance's own API
// is the only source of truth: the stream wakes the notifier and carries the resume cursor, and every pass re-reads
// the holding changes, so a missed event, a restart or a Slack outage loses nothing that the next pass does not
// repair.
//
// G5 (who is waiting on whom without naming each person): the service is a `notifier` of clearance-api and reads every
// change; who may clear is the gate's own rule (gate.RoleFor) applied to each linked person's groups, which the
// service asks the api for as a delegate (G7). The owner group's channel comes from the routes file.
type Notifier struct {
	Cfg    *Config
	Routes Routes
	Store  Store
	Slack  *API
	Clear  *Client
	// StreamClear is Clear with no overall request timeout, for the long-lived stream (nil: Clear).
	StreamClear *Client
	Log         *slog.Logger
	Now         func() time.Time

	wakeOnce sync.Once
	wake     chan struct{}

	mu      sync.Mutex
	persons map[string]personInfo
}

type personInfo struct {
	groups map[string]bool
	admin  bool
	at     time.Time
}

const (
	cursorKey    = "stream.cursor"
	personTTL    = 5 * time.Minute
	maxHolding   = 1000
	maxNewPerRun = 60 // posts started per pass: the rest wait for the next one
)

func (n *Notifier) now() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now()
}

func (n *Notifier) opts() RenderOpts {
	return RenderOpts{ClearMaxTier: n.Cfg.ClearMaxTier, WebURL: n.Cfg.WebURL, Now: n.now()}
}

// Person is the groups (and admin flag) of a linked person, as the api reports them for that person; cached for a
// few minutes. An error is not cached.
func (n *Notifier) Person(ctx context.Context, person string) (personInfo, error) {
	n.mu.Lock()
	if n.persons == nil {
		n.persons = map[string]personInfo{}
	}
	if p, ok := n.persons[person]; ok && n.now().Sub(p.at) < personTTL {
		n.mu.Unlock()
		return p, nil
	}
	n.mu.Unlock()
	w, err := n.Clear.Person(ctx, person)
	if err != nil {
		return personInfo{}, err
	}
	p := personInfo{groups: map[string]bool{}, admin: w.Admin, at: n.now()}
	for _, g := range w.Groups {
		p.groups[g] = true
	}
	n.mu.Lock()
	n.persons[person] = p
	n.mu.Unlock()
	return p, nil
}

// Run follows the stream and reconciles until ctx ends: a pass at start, one per burst of events (coalesced) and one
// every ReconcileInterval whatever happens.
func (n *Notifier) Run(ctx context.Context) {
	n.wakeCh()
	var seenSeq int64 // the highest stream seq received, saved once a pass that started after it succeeds
	var mu sync.Mutex
	go n.stream(ctx, func(seq int64) {
		mu.Lock()
		if seq > seenSeq {
			seenSeq = seq
		}
		mu.Unlock()
		select {
		case n.wakeCh() <- struct{}{}:
		default:
		}
	})
	t := time.NewTicker(n.Cfg.ReconcileInterval)
	defer t.Stop()
	for {
		mu.Lock()
		upTo := seenSeq
		mu.Unlock()
		if err := n.Reconcile(ctx); err != nil {
			n.Log.Warn("reconcile failed", "error", err.Error())
		} else if upTo > 0 {
			if err := n.Store.SetKV(ctx, cursorKey, strconv.FormatInt(upTo, 10)); err != nil {
				n.Log.Warn("saving the stream cursor failed", "error", err.Error())
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-n.wakeCh():
			select { // coalesce a burst
			case <-time.After(750 * time.Millisecond):
			case <-ctx.Done():
				return
			}
		case <-t.C:
		}
	}
}

// stream holds /v1/stream open, resuming from the saved cursor, and calls got with each clearance event's seq. The
// server ends a stream after ten minutes and a deploy can restart it: it reconnects with Last-Event-ID, with backoff
// on errors.
func (n *Notifier) stream(ctx context.Context, got func(seq int64)) {
	wait := time.Second
	for ctx.Err() == nil {
		last, _, _ := n.Store.KV(ctx, cursorKey)
		started := time.Now()
		sc := n.StreamClear
		if sc == nil {
			sc = n.Clear
		}
		body, err := sc.OpenStream(ctx, last)
		if err == nil {
			err = ReadSSE(body, func(e SSEEvent) error {
				if e.Event != "clearance" {
					return nil
				}
				if seq, perr := strconv.ParseInt(e.ID, 10, 64); perr == nil {
					got(seq)
				}
				return nil
			})
			body.Close()
		}
		var ce *CallError
		if errors.As(err, &ce) && ce.Status == 400 && last != "" {
			// The server does not know the cursor: start from the head. The reconcile pass has the state.
			n.Log.Warn("stream cursor refused; starting at the head", "cursor", last)
			_ = n.Store.SetKV(ctx, cursorKey, "")
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			n.Log.Warn("stream ended", "error", err.Error(), "retry_in", wait.String())
		}
		lived := time.Since(started)
		if lived > 30*time.Second {
			wait = time.Second
		}
		if err == nil && lived > time.Second { // an ordinary end (the 10 minute limit): straight back
			continue
		}
		if sleep(ctx, wait) != nil {
			return
		}
		if wait *= 2; wait > 30*time.Second {
			wait = 30 * time.Second
		}
	}
}

// destination is where a change's message goes.
type destination struct {
	key     string // channel:<id> or dm:<team>:<user>
	channel string // "" for a DM until it is opened
	user    string // a DM's Slack user
	person  string
}

// Reconcile makes Slack show the gate's holding changes and the end of those that stopped holding.
func (n *Notifier) Reconcile(ctx context.Context) error {
	holding, err := n.Clear.Changes(ctx, url.Values{"state": {gate.StateHolding}}, maxHolding)
	if err != nil {
		return err
	}
	links, err := n.Store.ListLinks(ctx)
	if err != nil {
		return err
	}
	posted := 0
	still := map[string]bool{}
	for i := range holding {
		c := &holding[i]
		still[c.ID] = true
		if _, err := n.syncChange(ctx, c, links, &posted); err != nil {
			n.Log.Warn("syncing a change failed", "change", c.ID, "error", err.Error())
			continue
		}
		if msgs, err := n.Store.Messages(ctx, c.ID); err == nil {
			n.nudge(ctx, c, msgs)
		}
	}
	// Changes that had a message and are not holding any more: show how they ended.
	open, err := n.Store.OpenMessages(ctx)
	if err != nil {
		return err
	}
	byChange := map[string][]Message{}
	var ids []string
	for _, m := range open {
		if still[m.ChangeID] {
			continue
		}
		if _, ok := byChange[m.ChangeID]; !ok {
			ids = append(ids, m.ChangeID)
		}
		byChange[m.ChangeID] = append(byChange[m.ChangeID], m)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := n.finish(ctx, id, byChange[id]); err != nil {
			n.Log.Warn("finishing a change's messages failed", "change", id, "error", err.Error())
		}
	}
	return nil
}

// finish finds the change that stopped holding and updates every message about it.
func (n *Notifier) finish(ctx context.Context, id string, msgs []Message) error {
	ref := msgs[0].Ref
	app, env, _ := strings.Cut(ref, "|")
	q := url.Values{}
	if app != "" {
		q.Set("app", app)
	}
	if env != "" {
		q.Set("env", env)
	}
	cs, err := n.Clear.Changes(ctx, q, 400)
	if err != nil {
		return err
	}
	for i := range cs {
		if cs[i].ID != id {
			continue
		}
		c := &cs[i]
		if c.State == gate.StateHolding {
			return nil // it came back (it cannot): leave it to the next pass
		}
		for _, m := range msgs {
			if err := n.render(ctx, c, m); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("change %s is not among the latest of %s", id, ref)
}

func stateKey(c *gate.Change) string { return fmt.Sprintf("%s|%d", c.State, len(c.Approvals)) }

// outsideWaiting says whether the change now waits on the outside requirement: it has one and the owner requirement
// is filled. Qualifying outsiders are then told by DM.
func outsideWaiting(c *gate.Change) bool {
	req := c.RequirementObj()
	if req == nil || req.Outside == 0 {
		return false
	}
	owner := 0
	for _, a := range c.Approvals {
		if a.Role == "owner" {
			owner++
		}
	}
	return owner >= req.Owner
}

// outsideEscalated says whether it has waited on the outside requirement longer than Tier3OutsideAfter, counted
// from the last approval (or the change's creation when no owner is needed): then the outside group's channel is told
// too, not only its members.
func (n *Notifier) outsideEscalated(c *gate.Change) bool {
	if !outsideWaiting(c) {
		return false
	}
	since := c.CreatedAt.Time
	for _, a := range c.Approvals {
		if t, err := time.Parse(time.RFC3339, a.At); err == nil && t.After(since) {
			since = t
		}
	}
	return n.now().Sub(since) >= n.Cfg.Tier3OutsideAfter
}

// destinations are the channel(s) and linked people a holding change is told to.
func (n *Notifier) destinations(ctx context.Context, c *gate.Change, links []Link) []destination {
	var out []destination
	seen := map[string]bool{}
	add := func(d destination) {
		if d.key != "" && !seen[d.key] {
			seen[d.key] = true
			out = append(out, d)
		}
	}
	req := c.RequirementObj()
	owner := c.Owner
	if req != nil && req.OwnerGroup != "" {
		owner = req.OwnerGroup
	}
	if ch := n.Routes.ForGroup(owner); ch != "" {
		add(destination{key: "channel:" + ch, channel: ch})
	}
	outside := outsideWaiting(c)
	if n.outsideEscalated(c) && req != nil {
		for _, g := range req.OutsideGroups {
			if ch := n.Routes.Groups[g]; ch != "" {
				add(destination{key: "channel:" + ch, channel: ch})
			} else if ch := n.Routes.Security; ch != "" {
				add(destination{key: "channel:" + ch, channel: ch})
			}
		}
	}
	now := n.now()
	for _, l := range links {
		if !l.DM || l.Stale(now, n.Cfg.RelinkAfter) {
			continue
		}
		pi, err := n.Person(ctx, l.Person)
		if err != nil {
			n.Log.Warn("could not read a linked person's groups", "person", l.Person, "error", err.Error())
			continue
		}
		role, err := gate.RoleFor(l.Person, pi.groups, c)
		if err != nil || (role == "outside" && !outside) {
			continue
		}
		add(destination{key: "dm:" + l.Team + ":" + l.User, user: l.User, person: l.Person})
	}
	return out
}

// syncChange posts or updates a holding change's messages.
func (n *Notifier) syncChange(ctx context.Context, c *gate.Change, links []Link, posted *int) (int, error) {
	existing, err := n.Store.Messages(ctx, c.ID)
	if err != nil {
		return 0, err
	}
	have := map[string]Message{}
	for _, m := range existing {
		have[m.Dest] = m
	}
	dests := n.destinations(ctx, c, links)
	var firstErr error
	for _, d := range dests {
		m, ok := have[d.key]
		if !ok {
			if *posted >= maxNewPerRun {
				continue
			}
			*posted++
			if err := n.post(ctx, c, d); err != nil {
				n.Log.Warn("posting failed", "change", c.ID, "dest", d.key, "error", err.Error())
				firstErr = err
			}
			continue
		}
		if err := n.render(ctx, c, m); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// A message whose destination no longer applies (the person cleared it, or stopped qualifying) is still kept
	// current, so its buttons never show a stale state.
	for k, m := range have {
		still := false
		for _, d := range dests {
			if d.key == k {
				still = true
			}
		}
		if !still {
			if err := n.render(ctx, c, m); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return len(dests), firstErr
}

func (n *Notifier) post(ctx context.Context, c *gate.Change, d destination) error {
	channel := d.channel
	if d.user != "" {
		ch, err := n.Slack.OpenDM(ctx, d.user)
		if err != nil {
			return err
		}
		channel = ch
	}
	text, blocks := RenderChange(c, n.opts())
	p, err := n.Slack.Post(ctx, channel, text, blocks, "")
	if err != nil {
		return err
	}
	return n.Store.PutMessage(ctx, Message{ChangeID: c.ID, Dest: d.key, Channel: p.Channel, TS: p.TS,
		Rendered: Digest(text, blocks), StateKey: stateKey(c), Ref: c.App + "|" + c.Env, Open: c.State == gate.StateHolding})
}

// render brings an existing message up to date with c, and adds a thread reply when its state or approvals moved.
func (n *Notifier) render(ctx context.Context, c *gate.Change, m Message) error {
	text, blocks := RenderChange(c, n.opts())
	dg := Digest(text, blocks)
	sk := stateKey(c)
	if dg == m.Rendered && sk == m.StateKey && m.Open == (c.State == gate.StateHolding) {
		return nil
	}
	if dg != m.Rendered {
		if err := n.Slack.Update(ctx, m.Channel, m.TS, text, blocks); err != nil {
			if IsErrorCode(err, "message_not_found") || IsErrorCode(err, "channel_not_found") {
				m.Open = false // the message is gone: stop tracking it
				return n.Store.PutMessage(ctx, m)
			}
			return err
		}
	}
	if sk != m.StateKey && strings.HasPrefix(m.Dest, "channel:") {
		if r := threadNote(c, m.StateKey); r != "" {
			if _, err := n.Slack.Post(ctx, m.Channel, r, []any{section(mrkdwn(r))}, m.TS); err != nil {
				return err
			}
		}
	}
	m.Rendered, m.StateKey, m.Open = dg, sk, c.State == gate.StateHolding
	return n.Store.PutMessage(ctx, m)
}

// threadNote is the one-line reply for what changed since the message was last rendered.
func threadNote(c *gate.Change, was string) string {
	prevState, prevN, _ := strings.Cut(was, "|")
	switch {
	case c.State == gate.StateCleared && prevState != c.State:
		who := "policy"
		if c.ClearedBy != nil {
			who = *c.ClearedBy
		}
		return "Cleared by " + who + "."
	case c.State == gate.StateDenied && prevState != c.State:
		s := "Denied"
		if c.DeniedBy != nil {
			s += " by " + *c.DeniedBy
		}
		if c.DenyReason != nil {
			s += ": " + clip(*c.DenyReason, 300)
		}
		return s + "."
	case c.State != gate.StateHolding && prevState != c.State:
		return "Change is now " + c.State + "."
	case c.State == gate.StateHolding && len(c.Approvals) > 0 && strconv.Itoa(len(c.Approvals)) != prevN:
		a := c.Approvals[len(c.Approvals)-1]
		need := ""
		if c.Requirement != nil {
			need = " Needs " + c.Requirement.Words() + "."
		}
		return a.Person + " approved (" + a.Role + ")." + need
	}
	return ""
}

// Poke asks for a pass soon (after a write, so the messages show it without waiting for the stream).
func (n *Notifier) Poke() {
	select {
	case n.wakeCh() <- struct{}{}:
	default:
	}
}

func (n *Notifier) wakeCh() chan struct{} {
	n.wakeOnce.Do(func() { n.wake = make(chan struct{}, 1) })
	return n.wake
}
