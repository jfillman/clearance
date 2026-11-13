package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// Sessions live in this process's memory and nowhere else: never a file, a database or a log. A restart loses them
// all and everyone signs in again. The map is bounded; at the bound the expired go first, then the one idle longest.

const (
	sessionCookie = "__Host-clearance_session"
	loginCookie   = "__Host-clearance_login"
	idBytes       = 32 // 256 bits
)

// newID is 256 random bits, base64url without padding (43 characters).
func newID() (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// parseID accepts only what newID makes: exactly 43 base64url characters that decode to 32 bytes. Anything else in
// a cookie is not a session id, and never reaches the map.
func parseID(s string) (string, bool) {
	if len(s) != base64.RawURLEncoding.EncodedLen(idBytes) {
		return "", false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != idBytes {
		return "", false
	}
	return s, true
}

// idKey is the map key: the hash of the id, so the map holds nothing a cookie could be made from.
func idKey(id string) [32]byte { return sha256.Sum256([]byte(id)) }

// Session is one signed-in browser.
type Session struct {
	Token     string // the person's ID token: the bearer on forwarded calls. Never leaves this struct except in that header.
	User      string // display name from the token's claims
	CSRF      string // the synchronizer token the page echoes on every non-GET
	Expires   time.Time
	LastSeen  time.Time
	AuthTime  time.Time // when the person last proved themselves at the IdP (auth_time, else sign-in time)
	CreatedAt time.Time
}

// Store is the bounded in-memory session map.
type Store struct {
	mu      sync.Mutex
	m       map[[32]byte]*Session
	max     int
	idle    time.Duration
	now     func() time.Time
	Evicted int // sessions pushed out at the bound (for tests and the log)
}

// NewStore is a store of at most max sessions, each idle at most idle.
func NewStore(max int, idle time.Duration, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{m: map[[32]byte]*Session{}, max: max, idle: idle, now: now}
}

func (s *Store) live(x *Session, t time.Time) bool {
	return t.Before(x.Expires) && t.Sub(x.LastSeen) < s.idle
}

// Create stores a session and returns its new id (a fresh id on every sign-in, so none is ever fixed in advance).
func (s *Store) Create(x Session) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	csrf, err := newID()
	if err != nil {
		return "", err
	}
	t := s.now()
	x.CSRF, x.LastSeen, x.CreatedAt = csrf, t, t
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= s.max {
		s.sweepLocked(t)
	}
	for len(s.m) >= s.max {
		var oldest [32]byte
		var at time.Time
		first := true
		for k, v := range s.m {
			if first || v.LastSeen.Before(at) {
				oldest, at, first = k, v.LastSeen, false
			}
		}
		delete(s.m, oldest)
		s.Evicted++
	}
	s.m[idKey(id)] = &x
	return id, nil
}

func (s *Store) sweepLocked(t time.Time) {
	for k, v := range s.m {
		if !s.live(v, t) {
			delete(s.m, k)
		}
	}
}

// Get returns a copy of the live session for id and counts the request as activity; an expired or idle one is
// deleted and not returned.
func (s *Store) Get(id string) (Session, bool) {
	id, ok := parseID(id)
	if !ok {
		return Session{}, false
	}
	t := s.now()
	k := idKey(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[k]
	if !ok {
		return Session{}, false
	}
	if !s.live(x, t) {
		delete(s.m, k)
		return Session{}, false
	}
	x.LastSeen = t
	return *x, true
}

// Delete removes a session (sign-out).
func (s *Store) Delete(id string) {
	if id, ok := parseID(id); ok {
		s.mu.Lock()
		delete(s.m, idKey(id))
		s.mu.Unlock()
	}
}

// Len is how many sessions are held (expired ones not yet swept included).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// Sweep drops the expired and idle.
func (s *Store) Sweep() {
	t := s.now()
	s.mu.Lock()
	s.sweepLocked(t)
	s.mu.Unlock()
}

func equalStrings(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// flow is one sign-in in progress, between /auth/login and /auth/callback.
type flow struct {
	Verifier string
	Nonce    string
	Binding  string // the value of the login cookie: ties the callback to the browser that began it
	Return   string
	MaxAge   time.Duration // > 0: a fresh login was asked for; auth_time must be within it
	Expires  time.Time
}

// flows is the bounded map of sign-ins in progress, keyed by state, each single-use and short-lived.
type flows struct {
	mu  sync.Mutex
	m   map[[32]byte]*flow
	max int
	now func() time.Time
	ttl time.Duration
}

func newFlows(max int, ttl time.Duration, now func() time.Time) *flows {
	return &flows{m: map[[32]byte]*flow{}, max: max, ttl: ttl, now: now}
}

func (f *flows) put(state string, x flow) {
	t := f.now()
	x.Expires = t.Add(f.ttl)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.m) >= f.max {
		for k, v := range f.m {
			if !t.Before(v.Expires) {
				delete(f.m, k)
			}
		}
	}
	for len(f.m) >= f.max {
		var oldest [32]byte
		var at time.Time
		first := true
		for k, v := range f.m {
			if first || v.Expires.Before(at) {
				oldest, at, first = k, v.Expires, false
			}
		}
		delete(f.m, oldest)
	}
	f.m[idKey(state)] = &x
}

// take removes and returns the flow for state: a state works once.
func (f *flows) take(state string) (flow, bool) {
	state, ok := parseID(state)
	if !ok {
		return flow{}, false
	}
	k := idKey(state)
	f.mu.Lock()
	defer f.mu.Unlock()
	x, ok := f.m[k]
	if !ok {
		return flow{}, false
	}
	delete(f.m, k)
	if !f.now().Before(x.Expires) {
		return flow{}, false
	}
	return *x, true
}
