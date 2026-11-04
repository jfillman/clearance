// Package memory is store.Store in memory, for `clearance core --memory` and other packages' tests. It keeps
// store/pg's semantics: one Atomic at a time, a transaction's writes (chain records included) visible inside it
// and to no one else until it commits, and all of them gone, the chain head with them, if it fails.
//
// Records are kept as the canonical bytes that were hashed and decoded afresh on every read, so a caller can
// neither mutate the chain through a returned map nor see different value types than store/pg returns.
package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
)

// Store is an in-memory store.Store.
type Store struct {
	write sync.Mutex // one Atomic at a time, like store/pg's writer connection

	mu      sync.RWMutex // guards the committed state below
	records [][]byte     // canonical record bytes, by seq
	head    evidence.Checkpoint
	changes map[string]store.Change
	defs    []store.Definition
	tokens  map[string]store.Token
	keys    map[string]store.SigningKey
	feeds   map[string]store.Feed
	closed  bool
}

var _ store.Store = (*Store)(nil)

// ErrClosed is returned after Close.
var ErrClosed = errors.New("memory: store closed")

// ErrTxDone is returned by a Tx used after its Atomic returned.
var ErrTxDone = errors.New("memory: transaction is finished")

// New returns an empty store.
func New() *Store {
	return &Store{head: evidence.Start, changes: map[string]store.Change{}, tokens: map[string]store.Token{},
		keys: map[string]store.SigningKey{}, feeds: map[string]store.Feed{}}
}

// Load returns a store holding an existing chain, verified from genesis like store/pg's Open.
func Load(records []store.Record) (*Store, error) {
	s := New()
	v := evidence.NewVerifier()
	for _, r := range records {
		if err := v.Add(r); err != nil {
			return nil, err
		}
		c, err := canon.Canonical(r)
		if err != nil {
			return nil, err
		}
		s.records = append(s.records, c)
	}
	s.head = v.Checkpoint()
	return s, nil
}

// Close marks the store closed.
func (s *Store) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}

// Atomic runs fn as one transaction.
func (s *Store) Atomic(ctx context.Context, fn func(tx store.Tx) error) (err error) {
	s.write.Lock()
	defer s.write.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	closed, head := s.closed, s.head
	s.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	t := &tx{s: s, head: head, changes: map[string]store.Change{}, tokens: map[string]store.Token{},
		feeds: map[string]store.Feed{}}
	defer func() {
		t.mu.Lock()
		t.done = true
		t.mu.Unlock()
	}()
	if err := fn(t); err != nil {
		return err // nothing staged reaches the committed state
	}
	if err := ctx.Err(); err != nil {
		return err // a commit after the deadline would be one the caller has given up on
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, t.records...)
	s.head = t.head
	for id, c := range t.changes {
		s.changes[id] = c
	}
	if t.defs != nil {
		s.defs = *t.defs
	}
	for id, tk := range t.tokens {
		s.tokens[id] = tk
	}
	for c, f := range t.feeds {
		s.feeds[c] = f
	}
	if t.keys != nil {
		s.keys = t.keys
	}
	return nil
}

// tx stages writes; reads see the committed state overlaid with them.
type tx struct {
	s       *Store
	mu      sync.Mutex
	done    bool
	head    evidence.Checkpoint
	records [][]byte
	changes map[string]store.Change
	defs    *[]store.Definition
	tokens  map[string]store.Token
	feeds   map[string]store.Feed
	keys    map[string]store.SigningKey // nil: unchanged
}

func (t *tx) lock() error {
	t.mu.Lock()
	if t.done {
		t.mu.Unlock()
		return ErrTxDone
	}
	return nil
}

func (t *tx) Append(ctx context.Context, event store.Event, w evidence.Writer) (store.Record, error) {
	if err := t.lock(); err != nil {
		return nil, err
	}
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec, full, err := evidence.Seal(t.head, event, w)
	if err != nil {
		return nil, err
	}
	t.records = append(t.records, full)
	t.head = evidence.Checkpoint{Count: t.head.Count + 1, Head: rec["hash"].(string)}
	return rec, nil
}

func (t *tx) PutChange(ctx context.Context, c store.Change) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	if !json.Valid(c.Record) {
		return errors.New("memory: change record is not JSON")
	}
	c.Record = bytes.Clone(c.Record)
	// pg.py's upsert: an existing change keeps its app, env, repo, pr and head; state, expiry and record move.
	if old, ok := t.change(c.ID); ok {
		old.State, old.ExpiresAt, old.Record = c.State, c.ExpiresAt, c.Record
		c = old
	}
	t.changes[c.ID] = c
	return nil
}

func (t *tx) ReplaceDefinitions(ctx context.Context, defs []store.Definition) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	seen := map[[2]string]bool{}
	out := make([]store.Definition, 0, len(defs))
	for _, d := range defs {
		k := [2]string{d.Name, d.State}
		if seen[k] {
			return fmt.Errorf("memory: duplicate definition %s/%s", d.Name, d.State) // the (name, state) primary key
		}
		if !json.Valid(d.Record) {
			return errors.New("memory: definition record is not JSON")
		}
		seen[k] = true
		d.Record = bytes.Clone(d.Record)
		out = append(out, d)
	}
	t.defs = &out
	return nil
}

func (t *tx) PutToken(ctx context.Context, tk store.Token) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	if tk.ChangeID == "" || !json.Valid(tk.Envelope) {
		return errors.New("memory: a token needs a change id and a JSON envelope")
	}
	t.tokens[tk.ChangeID] = cloneToken(tk)
	return nil
}

func (t *tx) UseSigningKey(ctx context.Context, k store.SigningKey, now time.Time) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	if k.KeyID == "" || !json.Valid(k.JWK) {
		return errors.New("memory: a signing key needs an id and a JWK")
	}
	keys := t.keys
	if keys == nil {
		t.s.mu.RLock()
		keys = make(map[string]store.SigningKey, len(t.s.keys)+1)
		for id, x := range t.s.keys {
			keys[id] = x
		}
		t.s.mu.RUnlock()
	}
	for id, x := range keys {
		if id != k.KeyID && x.RetiredAt == nil {
			at := now
			x.RetiredAt = &at
			keys[id] = x
		}
	}
	if old, ok := keys[k.KeyID]; ok {
		old.RetiredAt = nil
		keys[k.KeyID] = old
	} else {
		keys[k.KeyID] = store.SigningKey{KeyID: k.KeyID, JWK: bytes.Clone(k.JWK), CreatedAt: now}
	}
	t.keys = keys
	return nil
}

func (t *tx) PutFeed(ctx context.Context, f store.Feed) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	if f.Cluster == "" || !json.Valid(f.Envelope) || !json.Valid(f.Tokens) {
		return errors.New("memory: a feed needs a cluster, a JSON envelope and JSON tokens")
	}
	t.feeds[f.Cluster] = cloneFeed(f)
	return nil
}

func cloneFeed(f store.Feed) store.Feed {
	f.Envelope, f.Tokens = bytes.Clone(f.Envelope), bytes.Clone(f.Tokens)
	return f
}

func cloneToken(tk store.Token) store.Token {
	tk.Envelope = bytes.Clone(tk.Envelope)
	if tk.RevokedAt != nil {
		at := *tk.RevokedAt
		tk.RevokedAt = &at
	}
	return tk
}

// change looks a change up in the overlay, then the committed state. Callers hold t.mu.
func (t *tx) change(id string) (store.Change, bool) {
	if c, ok := t.changes[id]; ok {
		return c, true
	}
	t.s.mu.RLock()
	defer t.s.mu.RUnlock()
	c, ok := t.s.changes[id]
	return c, ok
}

// view is the state a reader sees.
type view struct {
	head    evidence.Checkpoint
	records [][]byte
	changes map[string]store.Change
	defs    []store.Definition
	tokens  map[string]store.Token
	keys    map[string]store.SigningKey
	feeds   map[string]store.Feed
}

func (s *Store) view() (view, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return view{}, ErrClosed
	}
	tokens := make(map[string]store.Token, len(s.tokens))
	for k, v := range s.tokens {
		tokens[k] = v
	}
	feeds := make(map[string]store.Feed, len(s.feeds))
	for k, v := range s.feeds {
		feeds[k] = v
	}
	return view{head: s.head, records: s.records[:len(s.records):len(s.records)], changes: maps(s.changes), defs: s.defs,
		tokens: tokens, keys: s.keys, feeds: feeds}, nil
}

func maps(m map[string]store.Change) map[string]store.Change {
	out := make(map[string]store.Change, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (t *tx) view() (view, error) {
	if err := t.lock(); err != nil {
		return view{}, err
	}
	defer t.mu.Unlock()
	v, err := t.s.view()
	if err != nil {
		return v, err
	}
	v.head = t.head
	v.records = append(v.records, t.records...)
	for id, c := range t.changes {
		v.changes[id] = c
	}
	if t.defs != nil {
		v.defs = *t.defs
	}
	for id, tk := range t.tokens {
		v.tokens[id] = tk
	}
	for c, f := range t.feeds {
		v.feeds[c] = f
	}
	if t.keys != nil {
		v.keys = t.keys
	}
	return v, nil
}

// The Reader methods, on the committed state (Store) or the transaction's (tx).

func (s *Store) Head(ctx context.Context) (int64, string, error) {
	return withView(s.view, view.headOf)
}
func (t *tx) Head(ctx context.Context) (int64, string, error) { return withView(t.view, view.headOf) }

func withView(get func() (view, error), f func(view) (int64, string, error)) (int64, string, error) {
	v, err := get()
	if err != nil {
		return 0, "", err
	}
	return f(v)
}

func (v view) headOf() (int64, string, error) { return v.head.Count - 1, v.head.Head, nil }

func (s *Store) Records(ctx context.Context, from int64, limit int) ([]store.Record, error) {
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	return v.recordsFrom(from, limit)
}

func (t *tx) Records(ctx context.Context, from int64, limit int) ([]store.Record, error) {
	v, err := t.view()
	if err != nil {
		return nil, err
	}
	return v.recordsFrom(from, limit)
}

func decode(b []byte) store.Record {
	v, err := canon.Parse(b)
	if err != nil {
		panic("memory: stored record does not parse: " + err.Error()) // Seal produced it
	}
	return v.(map[string]any)
}

func (v view) recordsFrom(from int64, limit int) ([]store.Record, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("store: limit %d", limit)
	}
	if from < 0 {
		from = 0
	}
	out := []store.Record{}
	for i := from; i < int64(len(v.records)) && len(out) < limit; i++ {
		out = append(out, decode(v.records[i]))
	}
	return out, nil
}

func (s *Store) Receipts(ctx context.Context, repo string, pr int, tools []string) ([]store.Record, error) {
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	return v.receipts(repo, pr, tools), nil
}

func (t *tx) Receipts(ctx context.Context, repo string, pr int, tools []string) ([]store.Record, error) {
	v, err := t.view()
	if err != nil {
		return nil, err
	}
	return v.receipts(repo, pr, tools), nil
}

// text is Postgres ->> on a jsonb value: a string's text, a number's literal; nil for null, objects and arrays
// (which ->> prints as JSON text; no receipt field holds one).
func text(x any) (string, bool) {
	switch v := x.(type) {
	case string:
		return v, true
	case json.Number:
		return string(v), true
	case bool:
		return strconv.FormatBool(v), true
	}
	return "", false
}

// receipts matches pg's query: record->>'tool' = ANY(tools) AND effect->>'repo' = repo AND effect->>'pr' = pr.
func (v view) receipts(repo string, pr int, tools []string) []store.Record {
	out := []store.Record{}
	want := strconv.Itoa(pr)
	for _, b := range v.records {
		r := decode(b)
		tool, ok := text(r["tool"])
		if !ok || !slices.Contains(tools, tool) {
			continue
		}
		eff, ok := r["effect"].(map[string]any)
		if !ok {
			continue
		}
		if er, ok := text(eff["repo"]); !ok || er != repo {
			continue
		}
		if ep, ok := text(eff["pr"]); !ok || ep != want {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (s *Store) Assurance(ctx context.Context, seq int64) (string, error) {
	v, err := s.view()
	if err != nil {
		return "", err
	}
	return v.assurance(seq)
}

func (t *tx) Assurance(ctx context.Context, seq int64) (string, error) {
	v, err := t.view()
	if err != nil {
		return "", err
	}
	return v.assurance(seq)
}

// assurance: the in-memory store has no ledger, so every record is recorded-not-checkpointed (the pg default).
func (v view) assurance(seq int64) (string, error) {
	if seq < 0 || seq >= int64(len(v.records)) {
		return "", store.ErrNotFound
	}
	return "recorded-not-checkpointed", nil
}

func (s *Store) Change(ctx context.Context, id string) (store.Change, error) {
	v, err := s.view()
	if err != nil {
		return store.Change{}, err
	}
	return v.change(id)
}

func (t *tx) Change(ctx context.Context, id string) (store.Change, error) {
	v, err := t.view()
	if err != nil {
		return store.Change{}, err
	}
	return v.change(id)
}

func (v view) change(id string) (store.Change, error) {
	c, ok := v.changes[id]
	if !ok {
		return store.Change{}, store.ErrNotFound
	}
	c.Record = bytes.Clone(c.Record)
	return c, nil
}

func (s *Store) ChangesForPR(ctx context.Context, repo string, pr int) ([]store.Change, error) {
	return s.changesWhere(func(c store.Change) bool { return c.Repo == repo && c.PR == pr })
}

func (t *tx) ChangesForPR(ctx context.Context, repo string, pr int) ([]store.Change, error) {
	return t.changesWhere(func(c store.Change) bool { return c.Repo == repo && c.PR == pr })
}

func (s *Store) ChangesForHead(ctx context.Context, repo, head string) ([]store.Change, error) {
	return s.changesWhere(func(c store.Change) bool { return c.Repo == repo && c.Head == head })
}

func (t *tx) ChangesForHead(ctx context.Context, repo, head string) ([]store.Change, error) {
	return t.changesWhere(func(c store.Change) bool { return c.Repo == repo && c.Head == head })
}

func (s *Store) ChangesHolding(ctx context.Context) ([]store.Change, error) {
	return s.changesWhere(func(c store.Change) bool { return c.State == "holding" })
}

func (t *tx) ChangesHolding(ctx context.Context) ([]store.Change, error) {
	return t.changesWhere(func(c store.Change) bool { return c.State == "holding" })
}

func (s *Store) ChangesUndelivered(ctx context.Context) ([]store.Change, error) {
	return s.changesWhere(store.Undelivered)
}

func (t *tx) ChangesUndelivered(ctx context.Context) ([]store.Change, error) {
	return t.changesWhere(store.Undelivered)
}

func (s *Store) changesWhere(keep func(store.Change) bool) ([]store.Change, error) {
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	return v.changesWhere(keep), nil
}

func (t *tx) changesWhere(keep func(store.Change) bool) ([]store.Change, error) {
	v, err := t.view()
	if err != nil {
		return nil, err
	}
	return v.changesWhere(keep), nil
}

// changesWhere orders as pg does: by record->>'created_at' (missing last), then id for a stable tie-break.
func (v view) changesWhere(keep func(store.Change) bool) []store.Change {
	out := []store.Change{}
	for _, c := range v.changes {
		if keep(c) {
			c.Record = bytes.Clone(c.Record)
			out = append(out, c)
		}
	}
	created := func(c store.Change) (string, bool) {
		var r struct {
			CreatedAt *string `json:"created_at"`
		}
		if json.Unmarshal(c.Record, &r) != nil || r.CreatedAt == nil {
			return "", false
		}
		return *r.CreatedAt, true
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, aok := created(out[i])
		b, bok := created(out[j])
		if aok != bok {
			return aok // NULLs last, as Postgres sorts ASC
		}
		if a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *Store) Definitions(ctx context.Context) ([]store.Definition, error) {
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	return v.definitions(), nil
}

func (t *tx) Definitions(ctx context.Context) ([]store.Definition, error) {
	v, err := t.view()
	if err != nil {
		return nil, err
	}
	return v.definitions(), nil
}

// definitions orders as pg does: by state, then name (byte order; pg uses COLLATE "C").
func (v view) definitions() []store.Definition {
	out := make([]store.Definition, len(v.defs))
	for i, d := range v.defs {
		d.Record = bytes.Clone(d.Record)
		out[i] = d
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].State != out[j].State {
			return out[i].State < out[j].State
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *Store) Token(ctx context.Context, changeID string) (store.Token, error) {
	v, err := s.view()
	if err != nil {
		return store.Token{}, err
	}
	return v.token(changeID)
}

func (t *tx) Token(ctx context.Context, changeID string) (store.Token, error) {
	v, err := t.view()
	if err != nil {
		return store.Token{}, err
	}
	return v.token(changeID)
}

func (v view) token(id string) (store.Token, error) {
	tk, ok := v.tokens[id]
	if !ok {
		return store.Token{}, store.ErrNotFound
	}
	return cloneToken(tk), nil
}

func (s *Store) TokensDue(ctx context.Context, due time.Time, keyID string, limit int) ([]store.Token, error) {
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	return v.tokensDue(due, keyID, limit), nil
}

func (t *tx) TokensDue(ctx context.Context, due time.Time, keyID string, limit int) ([]store.Token, error) {
	v, err := t.view()
	if err != nil {
		return nil, err
	}
	return v.tokensDue(due, keyID, limit), nil
}

func (v view) tokensDue(due time.Time, keyID string, limit int) []store.Token {
	out := []store.Token{}
	for _, tk := range v.tokens {
		if tk.RevokedAt == nil && (tk.ExpiresAt.Before(due) || tk.KeyID != keyID) {
			out = append(out, cloneToken(tk))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ExpiresAt.Equal(out[j].ExpiresAt) {
			return out[i].ExpiresAt.Before(out[j].ExpiresAt)
		}
		return out[i].ChangeID < out[j].ChangeID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Store) SigningKeys(ctx context.Context, since time.Time) ([]store.SigningKey, error) {
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	return v.signingKeys(since), nil
}

func (t *tx) SigningKeys(ctx context.Context, since time.Time) ([]store.SigningKey, error) {
	v, err := t.view()
	if err != nil {
		return nil, err
	}
	return v.signingKeys(since), nil
}

func (v view) signingKeys(since time.Time) []store.SigningKey {
	out := []store.SigningKey{}
	for _, k := range v.keys {
		if k.RetiredAt == nil || k.RetiredAt.After(since) {
			k.JWK = bytes.Clone(k.JWK)
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].KeyID < out[j].KeyID
	})
	return out
}

func (s *Store) LiveTokens(ctx context.Context, cluster string, now time.Time, limit int) ([]store.Token, error) {
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	return v.liveTokens(cluster, now, limit), nil
}

func (t *tx) LiveTokens(ctx context.Context, cluster string, now time.Time, limit int) ([]store.Token, error) {
	v, err := t.view()
	if err != nil {
		return nil, err
	}
	return v.liveTokens(cluster, now, limit), nil
}

func (v view) liveTokens(cluster string, now time.Time, limit int) []store.Token {
	out := []store.Token{}
	for _, tk := range v.tokens {
		if tk.Cluster == cluster && tk.RevokedAt == nil && tk.ExpiresAt.After(now) {
			out = append(out, cloneToken(tk))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChangeID < out[j].ChangeID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Store) Feed(ctx context.Context, cluster string) (store.Feed, error) {
	v, err := s.view()
	if err != nil {
		return store.Feed{}, err
	}
	return v.feed(cluster)
}

func (t *tx) Feed(ctx context.Context, cluster string) (store.Feed, error) {
	v, err := t.view()
	if err != nil {
		return store.Feed{}, err
	}
	return v.feed(cluster)
}

func (v view) feed(cluster string) (store.Feed, error) {
	f, ok := v.feeds[cluster]
	if !ok {
		return store.Feed{}, store.ErrNotFound
	}
	return cloneFeed(f), nil
}

func (s *Store) FeedClusters(ctx context.Context) ([]string, error) {
	v, err := s.view()
	if err != nil {
		return nil, err
	}
	return v.feedClusters(), nil
}

func (t *tx) FeedClusters(ctx context.Context) ([]string, error) {
	v, err := t.view()
	if err != nil {
		return nil, err
	}
	return v.feedClusters(), nil
}

func (v view) feedClusters() []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(c string) {
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, tk := range v.tokens {
		add(tk.Cluster)
	}
	for c := range v.feeds {
		add(c)
	}
	sort.Strings(out)
	return out
}
