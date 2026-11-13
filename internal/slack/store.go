package slack

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Link binds a Slack identity (workspace and user) to a person at the IdP. It holds ids only: no token, no email,
// no display name. The person every write names comes from here, never from anything Slack sends.
type Link struct {
	Team, User string // Slack workspace (team) id and user id, the pair Sign in with Slack proves
	Issuer     string // the IdP issuer the person signed in at
	Subject    string // the ID token's sub
	Person     string // the principal the core knows them as: user:<login>
	// AuthTime is the IdP sign-in time (unix seconds) the verified ID token carried; 0 when it carried none. It is
	// what X-Clearance-Auth-Time forwards, and it is as old as the link.
	AuthTime   int64
	LinkedAt   time.Time
	VerifiedAt time.Time // the last time both proofs were made (the link flow again): a link is stale after RelinkAfter
	DM         bool      // wants DMs for changes waiting on them (default true)
}

// Message is a Slack message the service posted about a change: the thread root of one destination.
type Message struct {
	ChangeID string
	Dest     string // "channel:<id>" or "dm:<team>:<user>"
	Channel  string // the conversation id the message is in
	TS       string
	Link     string // the permalink ("" until fetched)
	Rendered string // a digest of what it shows, to skip an update that changes nothing
	StateKey string // the change's state and approval count when last rendered: a change in it is a thread reply
	Ref      string // "app|env": where to find the change once it is no longer holding
	Open     bool   // the change was still holding when last rendered
}

// Store is the service's own state in Postgres: the link table, the messages it posted, and small key/values (the
// stream cursor, alert states, nudges sent).
type Store interface {
	Migrate(ctx context.Context) error
	GetLink(ctx context.Context, team, user string) (*Link, error)
	PutLink(ctx context.Context, l Link) error
	DeleteLink(ctx context.Context, team, user string) (bool, error)
	ListLinks(ctx context.Context) ([]Link, error)
	SetDM(ctx context.Context, team, user string, on bool) error
	Messages(ctx context.Context, changeID string) ([]Message, error)
	PutMessage(ctx context.Context, m Message) error
	OpenMessages(ctx context.Context) ([]Message, error)
	KV(ctx context.Context, key string) (string, bool, error)
	SetKV(ctx context.Context, key, value string) error
}

// ErrNotFound is a missing row.
var ErrNotFound = errors.New("slack: not found")

// MemStore is an in-memory Store (tests, and a dry run).
type MemStore struct {
	mu    sync.Mutex
	links map[[2]string]Link
	msgs  map[[2]string]Message
	kv    map[string]string
}

// NewMemStore is an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{links: map[[2]string]Link{}, msgs: map[[2]string]Message{}, kv: map[string]string{}}
}

func (s *MemStore) Migrate(context.Context) error { return nil }

func (s *MemStore) GetLink(_ context.Context, team, user string) (*Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[[2]string{team, user}]
	if !ok {
		return nil, nil
	}
	return &l, nil
}

func (s *MemStore) PutLink(_ context.Context, l Link) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.links[[2]string{l.Team, l.User}] = l
	return nil
}

func (s *MemStore) DeleteLink(_ context.Context, team, user string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := [2]string{team, user}
	_, ok := s.links[k]
	delete(s.links, k)
	return ok, nil
}

func (s *MemStore) ListLinks(context.Context) ([]Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Link
	for _, l := range s.links {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Team+out[i].User < out[j].Team+out[j].User })
	return out, nil
}

func (s *MemStore) SetDM(_ context.Context, team, user string, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := [2]string{team, user}
	l, ok := s.links[k]
	if !ok {
		return ErrNotFound
	}
	l.DM = on
	s.links[k] = l
	return nil
}

func (s *MemStore) Messages(_ context.Context, id string) ([]Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Message
	for k, m := range s.msgs {
		if k[0] == id {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dest < out[j].Dest })
	return out, nil
}

func (s *MemStore) PutMessage(_ context.Context, m Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs[[2]string{m.ChangeID, m.Dest}] = m
	return nil
}

func (s *MemStore) OpenMessages(context.Context) ([]Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Message
	for _, m := range s.msgs {
		if m.Open {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChangeID+out[i].Dest < out[j].ChangeID+out[j].Dest })
	return out, nil
}

func (s *MemStore) KV(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.kv[key]
	return v, ok, nil
}

func (s *MemStore) SetKV(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kv[key] = value
	return nil
}
