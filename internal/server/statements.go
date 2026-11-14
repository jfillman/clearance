package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/statement"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
	"github.com/jfillman/clearance/internal/verify"
)

// The verification statement (P-3). An admin cuts a statement from a published packet (POST /v1/statements) and may revoke
// it (POST /v1/statements/{id}/revoke); both are records, written before the answer, and both are idempotent. Anyone holding a
// statement's id may read its public summary and run the seven checks on the separate, off-by-default public listener
// (verifypage.go). Nothing anonymous ever writes to the chain.

// Record kinds the statement routes write.
const (
	ToolStatementIssue  = "statement.issue"
	ToolStatementRevoke = "statement.revoke"
)

// Limits.
const (
	MaxStatementBody = 4 << 10
	// MaxStatements is how many statements one core keeps: each is a record and an index entry, and an admin who needs more
	// is no longer sending monthly statements to prospects.
	MaxStatements = 5000
	// MaxRevokeReason is the longest reason a revocation records (it is not published).
	MaxRevokeReason = 200
	// statementTailEvery is how often a replica re-reads the chain's tail for statement records another replica wrote: the
	// bound on how stale a public page's view of revocation can be.
	statementTailEvery = time.Second
	// statementMaxStale is how old the index may be before the public page stops answering (503): a store that cannot be read
	// for this long is not a state the page may speak for.
	statementMaxStale = 10 * time.Second
	// statementRefreshTimeout bounds one read of the chain's tail.
	statementRefreshTimeout = 3 * time.Second
)

var statementVerified = union(packetVerified, "statement")

// StatementRequest is POST /v1/statements's body. The packet fixes the period and the observed scopes; the subscriber chooses
// how the scope is printed and which policy version the statement says it was cleared under. Nothing in the request can
// remove a total, a coverage state, an exception class or the unreconciled count: there is no field for it.
type StatementRequest struct {
	// Packet is a published packet (POST /v1/packets) of the packet view: its period, its observed scopes and the records it
	// carries are what the statement summarises.
	Packet string `json:"packet" contract:"required"`
	// Scope is the scope as the statement prints it (1 to 120 letters, digits, spaces and . , : / ( ) & + -). It is the
	// subscriber's own label: the names of the accounts and clusters stay in the packet.
	Scope string `json:"scope" contract:"required"`
	// PolicyVersion is the policy version the statement says the changes were cleared under (1 to 64 letters, digits, dots,
	// underscores, hyphens).
	PolicyVersion string `json:"policy_version" contract:"required"`
	// Profile is standard (default) or insurer.
	Profile string `json:"profile,omitempty"`
	// Supersedes is the id of the statement this one corrects: the old one then verifies as superseded and names this one.
	Supersedes string `json:"supersedes,omitempty"`
	// Reissue is the id of a REVOKED statement this one issues again with the same content. Without it, a request that matches
	// a revoked statement is refused (409): a revoked statement is not quietly answered as if it were current. The new
	// statement is a new id, and its record says which revoked one it replaces.
	Reissue string `json:"reissue,omitempty"`
}

// StatementLinks are the public paths of a statement, on the verify listener.
type StatementLinks struct {
	Page      string `json:"page" contract:"required"`
	Statement string `json:"statement" contract:"required"`
	Status    string `json:"status" contract:"required"`
}

// StatementIssued is POST /v1/statements's answer.
type StatementIssued struct {
	ID string `json:"id" contract:"required"`
	// Created is false when the same request had already been answered: the statement is the one issued then, and nothing
	// was recorded.
	Created bool   `json:"created" contract:"required"`
	State   string `json:"state" contract:"required"`
	Profile string `json:"profile" contract:"required"`
	Packet  string `json:"packet" contract:"required"`
	// Digest is the SHA-256 of the signed document's canonical JSON.
	Digest     string         `json:"digest" contract:"required"`
	Supersedes string         `json:"supersedes,omitempty"`
	Seq        int64          `json:"seq" contract:"required"`
	Hash       string         `json:"hash" contract:"required"`
	Links      StatementLinks `json:"links" contract:"required"`
}

// StatementRevokeRequest is POST /v1/statements/{id}/revoke's body.
type StatementRevokeRequest struct {
	// Reason is recorded in the chain and never published (1 to 200 printable characters).
	Reason string `json:"reason" contract:"required"`
}

// StatementRevoked is its answer.
type StatementRevoked struct {
	ID      string `json:"id" contract:"required"`
	Created bool   `json:"created" contract:"required"`
	State   string `json:"state" contract:"required"`
	Seq     int64  `json:"seq" contract:"required"`
	Hash    string `json:"hash" contract:"required"`
}

// stmtEntry is a statement as the chain holds it. It holds no envelope: that is read from its record when it is wanted, so the
// index is bounded by MaxStatements small entries however large the statements are.
type stmtEntry struct {
	id         string
	digest     string
	kid        string // the key that signed it
	packetID   string
	profile    string
	scope      string // the printed scope label and the policy label: what a reissue must repeat
	policy     string
	supersedes string
	reissues   string
	reqKey     string
	seq        int64
	hash       string
	// current state: set as the chain's records about the statement are read.
	supersededBy string
	reissuedBy   string
	revoked      bool
	revokedAt    string
	revokeSeq    int64
	revokeHash   string
}

func (e *stmtEntry) state() string {
	switch {
	case e.revoked:
		return statement.StateRevoked
	case e.supersededBy != "":
		return statement.StateSuperseded
	}
	return statement.StateValid
}

// stmtIndex is the statement records of the chain, by id, kept current by one background goroutine (StartStatements) that
// re-reads the chain's tail about once a second. Requests only READ the snapshot: they never wait on the store, a write or a
// refresh. A snapshot that was never completed (cold) or is older than statementMaxStale is not served (the page answers 503).
// A refresh applies each page it reads as it goes, so a read that times out in a long chain resumes where it stopped.
type stmtIndex struct {
	mu      sync.RWMutex
	byID    map[string]*stmtEntry
	byReq   map[string]string
	synced  time.Time // when the last COMPLETE read BEGAN: the state is as of then, never later
	warmed  bool
	loop    bool
	restart bool // a start was asked for while the loop was ending: it starts again as it ends
	lctx    context.Context
	stop    context.CancelFunc

	refreshMu sync.Mutex // one reader of the chain's tail at a time; guards next
	next      int64
	writeMu   sync.Mutex // serialises issue and revoke
}

// statementPageSize is how many records one read of the chain takes (a variable so a test can make a short chain long).
var statementPageSize = 2000

var (
	errStatementsCold  = errors.New("the statement index is not warm yet")
	errStatementsStale = errors.New("the statement index is older than it may be served")
)

type stmtEvent struct {
	issue     *stmtEntry
	revokeID  string
	revokedAt string
	seq       int64
	hash      string
}

func (x *stmtIndex) initLocked() {
	if x.byID == nil {
		x.byID, x.byReq = map[string]*stmtEntry{}, map[string]string{}
	}
}

// refreshLocked reads the chain from next on and folds in every statement.issue and statement.revoke, a page at a time, each page
// applied under the write lock and next advanced with it. The caller holds refreshMu. started (the clock before the first read) is
// the time the state is as of.
func (s *Server) refreshLocked(ctx context.Context, x *stmtIndex) error {
	started := s.opt.Clock()
	if head, _, err := s.opt.Store.Head(ctx); err != nil {
		return err
	} else if head < x.next {
		// Nothing new since the last read: confirmed current, at the cost of one indexed read.
		x.mu.Lock()
		x.initLocked()
		x.synced, x.warmed = started, true
		x.mu.Unlock()
		return nil
	}
	for {
		recs, err := s.opt.Store.Records(ctx, x.next, statementPageSize)
		if err != nil {
			return err
		}
		var evs []stmtEvent
		next := x.next
		for _, r := range recs {
			seq, _ := gate.SeqInt(r["seq"])
			next = seq + 1
			tool, _ := r["tool"].(string)
			if (tool != ToolStatementIssue && tool != ToolStatementRevoke) || r["decision"] != "allow" || !coreStatementRecord(r) {
				continue
			}
			st, _ := r["statement"].(map[string]any)
			id, _ := st["id"].(string)
			if !statement.ValidID(id) {
				continue
			}
			if tool == ToolStatementRevoke {
				evs = append(evs, stmtEvent{revokeID: id, revokedAt: fmt.Sprint(r["ts"]), seq: seq, hash: fmt.Sprint(r["hash"])})
				continue
			}
			pk, _ := r["packet"].(map[string]any)
			e := &stmtEntry{id: id, digest: fmt.Sprint(st["payload_sha256"]), packetID: fmt.Sprint(pk["id"]), profile: fmt.Sprint(st["profile"]),
				scope: fmt.Sprint(st["scope"]), policy: fmt.Sprint(st["policy_version"]),
				reqKey: fmt.Sprint(st["request_sha256"]), seq: seq, hash: fmt.Sprint(r["hash"]), kid: envelopeKid(st["envelope"])}
			if sup, _ := st["supersedes"].(string); statement.ValidID(sup) {
				e.supersedes = sup
			}
			if re, _ := st["reissues"].(string); statement.ValidID(re) {
				e.reissues = re
			}
			evs = append(evs, stmtEvent{issue: e})
		}
		x.mu.Lock()
		x.initLocked()
		for _, ev := range evs {
			x.applyLocked(ev)
		}
		x.next = next
		last := len(recs) < statementPageSize
		if last {
			x.synced, x.warmed = started, true
		}
		x.mu.Unlock()
		if last {
			return nil
		}
	}
}

// applyLocked folds one record into the index. The caller holds x.mu.
func (x *stmtIndex) applyLocked(ev stmtEvent) {
	if ev.issue == nil {
		if e := x.byID[ev.revokeID]; e != nil && !e.revoked {
			e.revoked, e.revokedAt, e.revokeSeq, e.revokeHash = true, ev.revokedAt, ev.seq, ev.hash
		}
		return
	}
	e := ev.issue
	if x.byID[e.id] != nil {
		return
	}
	x.byID[e.id], x.byReq[e.reqKey] = e, e.id
	x.linkLocked(e)
}

// linkLocked records what a new statement replaces: a statement is superseded by this one if it stood unreplaced, or if its
// replacement was itself revoked (then a correction may be made again); a revoked statement it reissues remembers it.
func (x *stmtIndex) linkLocked(e *stmtEntry) {
	if old := x.byID[e.supersedes]; e.supersedes != "" && old != nil {
		if succ := x.byID[old.supersededBy]; old.supersededBy == "" || (succ != nil && succ.revoked) {
			old.supersededBy = e.id
		}
	}
	if old := x.byID[e.reissues]; e.reissues != "" && old != nil {
		old.reissuedBy = e.id
	}
}

// chainEndRevokedLocked is true when the statements that replaced e, followed to the last, end in a revoked one: nothing in the
// chain is current. The caller holds x.mu.
func (x *stmtIndex) chainEndRevokedLocked(e *stmtEntry) bool {
	cur := e
	for i := 0; i < 64; i++ {
		if cur.supersededBy == "" {
			return cur != e && cur.revoked
		}
		next := x.byID[cur.supersededBy]
		if next == nil {
			return false
		}
		cur = next
	}
	return false
}

func envelopeKid(env any) string {
	m, _ := env.(map[string]any)
	sigs, _ := m["signatures"].([]any)
	if len(sigs) == 0 {
		return ""
	}
	sg, _ := sigs[0].(map[string]any)
	k, _ := sg["keyid"].(string)
	return k
}

// refreshForWrite is the authenticated path's refresh (and the background goroutine's): it waits its turn.
func (s *Server) refreshForWrite(ctx context.Context) error {
	x := &s.stmts
	x.refreshMu.Lock()
	defer x.refreshMu.Unlock()
	return s.refreshLocked(ctx, x)
}

// stmtLive is a statement's current state as of the snapshot that gave it.
type stmtLive struct {
	entry            *stmtEntry // a copy: nothing in it changes after the lock is released
	asOf             time.Time  // when the read behind the snapshot began
	successorRevoked bool       // the replacements of this statement, followed to the last, end in a revoked one
}

// lookupStatement is the public read: the statement by id, with its current state, from the snapshot alone. It never touches
// the store, never scans the chain and never waits: a cold snapshot is errStatementsCold and one older than statementMaxStale
// errStatementsStale (the page answers 503: it must not say valid on a state it could not read). found is false for an id the
// chain holds no statement of.
func (s *Server) lookupStatement(id string) (stmtLive, bool, error) {
	x := &s.stmts
	x.mu.RLock()
	defer x.mu.RUnlock()
	if !x.warmed {
		return stmtLive{}, false, errStatementsCold
	}
	if s.opt.Clock().Sub(x.synced) > statementMaxStale {
		return stmtLive{}, false, errStatementsStale
	}
	e := x.byID[id]
	if e == nil {
		return stmtLive{asOf: x.synced}, false, nil
	}
	cp := *e
	return stmtLive{entry: &cp, asOf: x.synced, successorRevoked: x.chainEndRevokedLocked(e)}, true, nil
}

// coreStatementRecord says whether a record is one the core wrote as a statement record: its provider is the core's own, its boundary is
// deployment, and the core marked both the tool and the statement as fields IT verified (issueStatement and revokeStatement set them).
// A record with the right tool name and none of that (a registered provider may write kinds of its own through POST /v1/records) is not
// a statement and is ignored.
func coreStatementRecord(r store.Record) bool {
	pv, _ := r["provider"].(map[string]any)
	if pv["name"] != evidence.CoreProviderName || r["boundary"] != "deployment" {
		return false
	}
	vs, _ := r["verified"].([]any)
	tool, stmt := false, false
	for _, v := range vs {
		switch v {
		case "tool":
			tool = true
		case "statement":
			stmt = true
		}
	}
	return tool && stmt
}

// StartStatements starts the one goroutine that keeps the statement index current: it reads the chain's tail about once a second until
// the core stops. It is started from exactly these places: the startup pass when the chain already holds a statement, an admin's
// issue, revoke or list, the verify listener being enabled, never from an anonymous request. After StopStatements nothing starts it.
// A start that finds the loop on its way out is not lost: the loop starts again as it ends.
func (s *Server) StartStatements() {
	x := &s.stmts
	x.mu.Lock()
	defer x.mu.Unlock()
	if s.life.Err() != nil {
		return
	}
	if x.loop {
		if x.lctx != nil && x.lctx.Err() != nil {
			x.restart = true
		}
		return
	}
	x.loop = true
	x.restart = false
	lctx, cancel := context.WithCancel(s.life)
	x.lctx, x.stop = lctx, cancel
	go s.statementLoop(lctx)
}

func (s *Server) statementLoop(lctx context.Context) {
	x := &s.stmts
	defer func() {
		x.mu.Lock()
		x.loop = false
		again := x.restart && s.life.Err() == nil
		x.restart = false
		x.mu.Unlock()
		if again {
			s.StartStatements()
		}
	}()
	var lastLog time.Time
	for {
		rctx, c := context.WithTimeout(lctx, 10*time.Second)
		err := s.refreshForWrite(rctx)
		c()
		wait := statementTailEvery
		if err != nil && lctx.Err() == nil {
			wait = 2 * time.Second
			if now := time.Now(); now.Sub(lastLog) > time.Minute {
				lastLog = now
				s.log.Warn("statements: the chain's tail could not be read; the page serves 503 once its snapshot is too old", "error", err.Error())
			}
		}
		select {
		case <-lctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// StopStatements ends the goroutine for good: the core is closing, and nothing starts it again.
func (s *Server) StopStatements() {
	s.lifeStop()
}

// statementKeys are the keys statements are verified with, and they are NOT the token keys: GET /v1/keys is unchanged and carries
// only the keys a token may be signed with, for the window a token can live. A statement's key is published here (every
// key that signed a statement that stands, and the one in use) and, for one statement, at /s/<id>/keys.json. No verifier of a
// token, a packet credential, a feed or an attestation reads this set, so a key that left the token window does not become
// acceptable for any of them by appearing in it.
func (s *Server) statementKeyRows(ctx context.Context) ([]store.SigningKey, error) {
	x := &s.stmts
	x.mu.RLock()
	warmed, synced := x.warmed, x.synced
	live := map[string]bool{}
	for _, e := range x.byID {
		if !e.revoked && e.kid != "" {
			live[e.kid] = true
		}
	}
	x.mu.RUnlock()
	if !warmed {
		return nil, errStatementsCold
	}
	if s.opt.Clock().Sub(synced) > statementMaxStale {
		return nil, errStatementsStale
	}
	rows, err := s.opt.Store.SigningKeys(ctx, time.Time{})
	if err != nil {
		return nil, err
	}
	out := rows[:0:0]
	for _, k := range rows {
		if k.RetiredAt == nil || live[k.KeyID] {
			out = append(out, k)
		}
	}
	return out, nil
}

// statementKeyFor is the key with this id, whatever its state (a statement is verified with the key that signed it, revoked or
// not). The JWK of a key id never changes, so it is kept after the first read.
func (s *Server) statementKeyFor(ctx context.Context, kid string) (token.JWK, bool, error) {
	s.keyMu.Lock()
	raw, ok := s.kidKeys[kid]
	s.keyMu.Unlock()
	if !ok {
		rows, err := s.opt.Store.SigningKeys(ctx, time.Time{})
		if err != nil {
			return token.JWK{}, false, err
		}
		s.keyMu.Lock()
		if s.kidKeys == nil {
			s.kidKeys = map[string]json.RawMessage{}
		}
		for _, k := range rows {
			s.kidKeys[k.KeyID] = k.JWK
		}
		raw, ok = s.kidKeys[kid]
		s.keyMu.Unlock()
		if !ok {
			return token.JWK{}, false, nil
		}
	}
	var j token.JWK
	if json.Unmarshal(raw, &j) != nil {
		return token.JWK{}, false, nil
	}
	return j, true, nil
}

// statementKeys is GET /v1/statement-keys: the statement verification keys (a JWKS), public like /v1/keys. It is anonymous and starts
// nothing: while the chain is not known to hold a statement the answer is the key in use (the whole set, since no statement exists to need
// another) and it touches neither the index nor the store. Once statements exist the index is kept by the background loop, and a cold or
// stale index is 503, never an empty set.
func (s *Server) statementKeys(w http.ResponseWriter, r *http.Request) {
	out := token.JWKS{Keys: []token.JWK{}}
	if !s.stmtSeen.Load() {
		signer, _, err := s.opt.Gate.Credentials()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "no signing key")
			return
		}
		j, err := token.PublicJWK(signer.Public())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "no signing key")
			return
		}
		out.Keys = append(out.Keys, j)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, out)
		return
	}
	rows, err := s.statementKeyRows(r.Context())
	if err != nil {
		if errors.Is(err, errStatementsCold) || errors.Is(err, errStatementsStale) {
			w.Header().Set("Retry-After", "2")
			writeError(w, http.StatusServiceUnavailable, "the statements are not read yet: try again shortly")
		} else {
			writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		}
		return
	}
	for _, k := range rows {
		var j token.JWK
		if json.Unmarshal(k.JWK, &j) == nil {
			out.Keys = append(out.Keys, j)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// StatementListItem is one statement in GET /v1/statements.
type StatementListItem struct {
	ID      string `json:"id" contract:"required"`
	State   string `json:"state" contract:"required"`
	Profile string `json:"profile" contract:"required"`
	Packet  string `json:"packet" contract:"required"`
	Key     string `json:"key" contract:"required"`
	Seq     int64  `json:"seq" contract:"required"`
}

// StatementList is GET /v1/statements's answer.
type StatementList struct {
	Items []StatementListItem `json:"items" contract:"required"`
}

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// listStatements is GET /v1/statements?key=<key id>: an admin lists the statements signed by one key, whatever their state: what
// retiring that key for compromise has to deal with (docs/statement.md).
func (s *Server) listStatements(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.subscriber(w, r); !ok {
		return
	}
	s.StartStatements()
	q := r.URL.Query()
	for k := range q {
		if k != "key" {
			writeError(w, http.StatusBadRequest, "unknown parameter "+k+" (key only)")
			return
		}
	}
	kid := q.Get("key")
	if !keyIDPattern.MatchString(kid) {
		writeError(w, http.StatusBadRequest, "key is a signing key id")
		return
	}
	if err := s.refreshForWrite(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	x := &s.stmts
	x.mu.RLock()
	out := StatementList{Items: []StatementListItem{}}
	for _, e := range x.byID {
		if e.kid == kid {
			out.Items = append(out.Items, StatementListItem{ID: e.id, State: e.state(), Profile: e.profile, Packet: e.packetID, Key: e.kid, Seq: e.seq})
		}
	}
	x.mu.RUnlock()
	slices.SortFunc(out.Items, func(a, b StatementListItem) int { return int(a.Seq - b.Seq) })
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// statementEnvelope is the signed envelope of a statement, read from its issue record.
func (s *Server) statementEnvelope(ctx context.Context, e *stmtEntry) ([]byte, error) {
	if b := s.envelopes.get(e.id, e.digest); b != nil {
		return b, nil
	}
	b, err := s.readEnvelope(ctx, e)
	if err == nil {
		s.envelopes.put(e.id, e.digest, b)
	}
	return b, err
}

// envelopeCache keeps the envelopes of the last few statements read (a statement is immutable), so repeated downloads and checks do
// not read the store: the oldest entry out first, at most envelopeCacheSize.
type envelopeCache struct {
	mu    sync.Mutex
	by    map[string]cachedEnvelope
	order []string
}

type cachedEnvelope struct {
	digest string
	raw    []byte
}

const envelopeCacheSize = 64

func (c *envelopeCache) get(id, digest string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.by[id]; ok && e.digest == digest {
		return e.raw
	}
	return nil
}

func (c *envelopeCache) put(id, digest string, raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.by == nil {
		c.by = map[string]cachedEnvelope{}
	}
	if _, ok := c.by[id]; !ok {
		for len(c.order) >= envelopeCacheSize {
			delete(c.by, c.order[0])
			c.order = c.order[1:]
		}
		c.order = append(c.order, id)
	}
	c.by[id] = cachedEnvelope{digest: digest, raw: raw}
}

func (s *Server) readEnvelope(ctx context.Context, e *stmtEntry) ([]byte, error) {
	recs, err := s.opt.Store.Records(ctx, e.seq, 1)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, store.ErrNotFound
	}
	r := recs[0]
	if seq, _ := gate.SeqInt(r["seq"]); seq != e.seq || r["tool"] != ToolStatementIssue {
		return nil, store.ErrNotFound
	}
	st, _ := r["statement"].(map[string]any)
	if id, _ := st["id"].(string); id != e.id {
		return nil, store.ErrNotFound
	}
	raw, err := json.Marshal(st["envelope"])
	if err != nil || len(raw) > statement.MaxEnvelopeBytes {
		return nil, errors.New("the stored statement is unreadable")
	}
	return raw, nil
}

// checkpointRule says why a packet cannot carry a statement ("" when it can).
func checkpointRule(files map[string][]byte, logKeys []byte) string {
	var pj struct {
		Verification struct {
			Ledger struct {
				State string `json:"state"`
			} `json:"ledger"`
		} `json:"verification"`
	}
	if json.Unmarshal(files["packet.json"], &pj) != nil {
		return "packet.json is not readable"
	}
	switch pj.Verification.Ledger.State {
	case "checkpointed":
	default:
		return "the packet stands on no witnessed ledger checkpoint (its ledger state is " + strconv.Quote(pj.Verification.Ledger.State) + "): every cited record must be under one"
	}
	if len(bytes.TrimSpace(files[packet.FileProofs])) == 0 || len(bytes.TrimSpace(files[packet.FileCheckpoint])) == 0 {
		return "the packet says it is checkpointed and does not carry its inclusion proofs and its checkpoint"
	}
	if len(bytes.TrimSpace(logKeys)) == 0 {
		return "this deployment has no log keys configured (CLEARANCE_STATEMENT_LOG_KEYS_FILE): the checkpoint and the proofs cannot be checked, so no statement is signed over them"
	}
	return ""
}

func statementRequestKey(packetDigest string, req StatementRequest, profile string) (string, error) {
	c, err := canon.Canonical(map[string]any{"packet_digest": packetDigest, "profile": profile, "scope": req.Scope,
		"policy_version": req.PolicyVersion, "supersedes": req.Supersedes, "reissue": req.Reissue})
	if err != nil {
		return "", err
	}
	return canon.SHA256Hex(c), nil
}

func statementLinks(id string) StatementLinks {
	return StatementLinks{Page: "/s/" + id, Statement: "/s/" + id + "/statement.json", Status: "/s/" + id + "/status.json"}
}

func (s *Server) issued(e *stmtEntry, created bool) StatementIssued {
	return StatementIssued{ID: e.id, Created: created, State: e.state(), Profile: e.profile, Packet: e.packetID, Digest: e.digest, Supersedes: e.supersedes,
		Seq: e.seq, Hash: e.hash, Links: statementLinks(e.id)}
}

// statementVerifyOptions are the trust inputs of the statement checks that this deployment holds: the log keys, the witness
// policy, the recipients' registered keys and the witnesses it declares independent. Keys and the live state are the caller's.
func (s *Server) statementVerifyOptions(files map[string][]byte) verify.StatementOptions {
	opt := s.statementOpts()
	so := verify.StatementOptions{DeclaredIndependent: opt.IndependentWitnesses, PacketFiles: files, Options: verify.Options{Now: s.opt.Clock}}
	so.LogKeys, so.LogKeysSrc = opt.LogKeys, "this deployment's configured log keys"
	so.WitnessPolicy, so.WitnessPolicySrc = opt.WitnessPolicy, "this deployment's configured witness policy"
	so.RecipientKeys, so.RecipientKeysSrc = map[string][]byte{}, map[string]string{}
	for _, p := range s.opt.Providers {
		if p.Assurance() && len(p.Keys) > 0 {
			so.RecipientKeys[p.Name] = []byte(strings.Join(p.Keys, "\n"))
			so.RecipientKeysSrc[p.Name] = "registered with this core"
		}
	}
	return so
}

// issueStatement is POST /v1/statements: an admin cuts a signed statement from a published packet. The core builds it with
// statement.Build (the function the verifier recomputes it with), runs checks 3 to 6 on it against the packet (a statement the
// packet does not support is never signed: 422), signs it with its clearance key, and records it (statement.issue) before it
// answers. The same request again is the same statement and records nothing. The packet parse, the checks and the signature
// are done outside every lock the public page takes; the write lock is held only for the re-check and the record.
func (s *Server) issueStatement(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.subscriber(w, r)
	if !ok {
		return
	}
	s.StartStatements()
	raw, ok := readBody(w, r, MaxStatementBody)
	if !ok {
		return
	}
	var req StatementRequest
	if err := strictDecode(bytes.NewReader(raw), &req); err != nil {
		writeError(w, http.StatusBadRequest, "the body is {packet, scope, policy_version, profile?, supersedes?, reissue?}: "+err.Error())
		return
	}
	profile := orString(req.Profile, statement.ProfileStandard)
	switch {
	case !packet.ValidID(req.Packet):
		writeError(w, http.StatusBadRequest, "packet is a packet id (pk-...)")
		return
	case profile != statement.ProfileStandard && profile != statement.ProfileInsurer:
		writeError(w, http.StatusBadRequest, "profile is standard or insurer")
		return
	case !statement.ValidLabel(req.Scope):
		writeError(w, http.StatusBadRequest, fmt.Sprintf("scope is 1 to %d letters, digits, spaces and . , : / ( ) & + -", statement.MaxLabel))
		return
	case !statement.ValidPolicyVersion(req.PolicyVersion):
		writeError(w, http.StatusBadRequest, fmt.Sprintf("policy_version is 1 to %d letters, digits, dots, underscores and hyphens", statement.MaxPolicyVersion))
		return
	case req.Supersedes != "" && !statement.ValidID(req.Supersedes):
		writeError(w, http.StatusBadRequest, "supersedes is a statement id (st-...)")
		return
	case req.Reissue != "" && !statement.ValidID(req.Reissue):
		writeError(w, http.StatusBadRequest, "reissue is a statement id (st-...)")
		return
	case req.Reissue != "" && req.Supersedes != "":
		writeError(w, http.StatusBadRequest, "supersedes and reissue are different acts: a correction replaces a statement that stands, a reissue replaces one that was revoked")
		return
	}
	ctx := r.Context()
	signer, issuer, err := s.opt.Gate.Credentials()
	if err != nil {
		if !gateFail(w, err) {
			writeError(w, http.StatusServiceUnavailable, "no signer")
		}
		return
	}
	if !statement.ValidIssuer(issuer) {
		writeError(w, http.StatusConflict, "CLEARANCE_TOKEN_ISSUER is not a public label or an https URL with a public host: a statement prints it, so an internal name is refused (docs/statement.md)")
		return
	}
	pk, err := s.opt.Store.Packet(ctx, req.Packet)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such packet: publish it first (POST /v1/packets)")
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	b := s.bundles.get(pk.ID, pk.Digest)
	if b == nil {
		if b, err = packet.LoadBundle(pk.Bundle); err != nil {
			s.log.ErrorContext(ctx, "statement: the stored packet is unreadable", "packet", pk.ID, "error", err.Error())
			writeError(w, http.StatusServiceUnavailable, "the stored packet could not be read")
			return
		}
		s.bundles.put(b)
	}
	if b.Meta.View != packet.ViewPacket {
		writeError(w, http.StatusBadRequest, "a statement is cut from a packet of the packet view, not a freeze or an incident")
		return
	}
	reqKey, err := statementRequestKey(pk.Digest, req, profile)
	if err != nil {
		writeError(w, http.StatusBadRequest, "the request cannot be keyed")
		return
	}
	x := &s.stmts
	if err := s.refreshForWrite(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	// answered is the early answer: the same request already answered (idempotent), or refused for what it names.
	answered := func() bool {
		x.mu.RLock()
		defer x.mu.RUnlock()
		if id := x.byReq[reqKey]; id != "" {
			e := x.byID[id]
			if e.revoked {
				writeError(w, http.StatusConflict, "this request was answered by statement "+e.id+", which was revoked: a revoked statement is not answered as if it stood. To issue the same content again as a new statement, send reissue: "+e.id)
				return true
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, s.issued(e, false))
			return true
		}
		if len(x.byID) >= MaxStatements {
			writeError(w, http.StatusConflict, fmt.Sprintf("this core already holds %d statements", MaxStatements))
			return true
		}
		if req.Supersedes != "" {
			old := x.byID[req.Supersedes]
			switch {
			case old == nil:
				writeError(w, http.StatusNotFound, "no such statement to supersede")
			case old.revoked:
				writeError(w, http.StatusConflict, "that statement is revoked: a revoked statement stays revoked; to issue its content again send reissue, or issue a new one without supersedes")
			case old.supersededBy != "" && !(x.byID[old.supersededBy] != nil && x.byID[old.supersededBy].revoked):
				writeError(w, http.StatusConflict, "that statement has already been superseded")
			default:
				return false
			}
			return true
		}
		if req.Reissue != "" {
			old := x.byID[req.Reissue]
			switch {
			case old == nil:
				writeError(w, http.StatusNotFound, "no such statement to reissue")
			case !old.revoked:
				writeError(w, http.StatusConflict, "that statement is not revoked: a statement that stands is corrected with supersedes")
			case old.packetID != req.Packet || old.scope != req.Scope || old.policy != req.PolicyVersion || old.profile != profile:
				writeError(w, http.StatusConflict, "a reissue repeats the revoked statement's content (the same packet, scope, policy version and profile): to change any of them, issue a new statement without reissue")
			case old.reissuedBy != "" && x.byID[old.reissuedBy] != nil && !x.byID[old.reissuedBy].revoked:
				writeError(w, http.StatusConflict, "that statement was already reissued as "+old.reissuedBy+", which stands: one live reissue per revoked statement")
			default:
				return false
			}
			return true
		}
		return false
	}
	if answered() {
		return
	}
	var id string
	if c, err := statement.NewID(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "no randomness")
		return
	} else {
		id = c
	}
	now := s.opt.Clock().UTC().Truncate(time.Second)
	doc, err := statement.Build(statement.Input{ID: id, Issuer: issuer, IssuedAt: pycompat.ISO(now), Profile: profile, ScopeLabel: req.Scope,
		PolicyVersion: req.PolicyVersion, Supersedes: req.Supersedes, IndependentWitnesses: s.statementOpts().IndependentWitnesses,
		PacketID: pk.ID, PacketDigest: pk.Digest, PacketJSON: b.Files["packet.json"], RecordsJSONL: b.Files[packet.FileRecords]})
	if err != nil {
		writeError(w, http.StatusBadRequest, "the packet cannot be summarised: "+err.Error())
		return
	}
	// The packet is the admin's to publish, so what it says is checked before anything is signed. A packet that says it is
	// checkpointed must carry its proofs and its checkpoint, and this deployment must hold the log keys to check them with: a
	// statement is not signed over proofs nobody checked. A packet on no checkpoint is refused: a statement's third check is
	// that every cited record is under one, and it could never pass.
	if why := checkpointRule(b.Files, s.statementOpts().LogKeys); why != "" {
		writeError(w, http.StatusUnprocessableEntity, "the packet does not support a statement, so none was signed: "+why)
		return
	}
	checks := verify.StatementPacketChecks(doc, s.statementVerifyOptions(b.Files))
	for i, c := range checks {
		// Checks 3 to 6. A failure is a refusal; so is a check 3 that is anything but a pass or "records after the checkpoint".
		if c.Status == verify.Fail || (i == 0 && c.Status != verify.Pass && c.Status != verify.NotCheckpointed) {
			writeError(w, http.StatusUnprocessableEntity, "the packet does not support the statement, so none was signed: "+c.Name+" ("+string(c.Status)+")")
			return
		}
	}
	payload, err := doc.Canonical()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the statement cannot be encoded")
		return
	}
	env, err := token.SignDSSE(ctx, signer, statement.PayloadType, payload)
	if err != nil {
		s.log.ErrorContext(ctx, "statement: signing failed", "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the statement could not be signed")
		return
	}
	envJSON, err := json.Marshal(env)
	if err != nil || len(envJSON) > statement.MaxEnvelopeBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "the statement is over the size cap")
		return
	}
	digest := canon.SHA256Hex(payload)
	var envObj any
	if err := json.Unmarshal(envJSON, &envObj); err != nil {
		writeError(w, http.StatusInternalServerError, "the statement cannot be encoded")
		return
	}

	// Only now the write lock: another writer may have answered the same request, or changed what this one names.
	x.writeMu.Lock()
	defer x.writeMu.Unlock()
	if err := s.refreshForWrite(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	if answered() {
		return
	}
	x.mu.RLock()
	taken := x.byID[id] != nil
	x.mu.RUnlock()
	if taken {
		writeError(w, http.StatusServiceUnavailable, "the statement id collided: try again")
		return
	}
	var rec store.Record
	err = s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		st := map[string]any{"id": id, "profile": profile, "scope": req.Scope, "policy_version": req.PolicyVersion, "request_sha256": reqKey, "payload_sha256": digest, "envelope": envObj}
		if req.Supersedes != "" {
			st["supersedes"] = req.Supersedes
		}
		if req.Reissue != "" {
			st["reissues"] = req.Reissue
		}
		var err error
		rec, err = tx.Append(ctx, store.Event{"ts": pycompat.ISO(now), "task_id": nil, "session": nil, "parent": nil,
			"principal": sub.Person, "agent": nil, "tool": ToolStatementIssue, "tier": nil, "decision": "allow", "rule": nil,
			"target": "statement:" + id, "args_sha256": digest, "boundary": "deployment",
			"result":    fmt.Sprintf("statement %s issued (%s, packet %s)", id, profile, pk.ID),
			"initiator": initiator(sub), "delegate": viaString(sub.Via), "packet": map[string]any{"id": pk.ID, "digest": pk.Digest}, "statement": st},
			s.coreWriter(statementVerified))
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "statement: the issue could not be recorded", "statement", id, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the statement could not be recorded")
		return
	}
	s.stmtSeen.Store(true) // from now a statement exists: the statement keys are no longer just the key in use
	seq, _ := gate.SeqInt(rec["seq"])
	e := &stmtEntry{id: id, digest: digest, kid: signer.KeyID(), packetID: pk.ID, profile: profile, scope: req.Scope, policy: req.PolicyVersion,
		supersedes: req.Supersedes, reissues: req.Reissue, reqKey: reqKey, seq: seq, hash: fmt.Sprint(rec["hash"])}
	x.mu.Lock()
	// The background refresh may have read this very record already, and folded a revocation of it in: it is not overwritten.
	x.initLocked()
	x.applyLocked(stmtEvent{issue: e})
	cp := *x.byID[id]
	x.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.issued(&cp, true))
}

// revokeStatement is POST /v1/statements/{id}/revoke: from now on the statement verifies as revoked. The revocation is a
// record (statement.revoke), written before the answer; revoking a revoked statement is the same answer and writes nothing.
func (s *Server) revokeStatement(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.subscriber(w, r)
	if !ok {
		return
	}
	s.StartStatements()
	id := r.PathValue("id")
	if !statement.ValidID(id) {
		writeError(w, http.StatusNotFound, "no such statement")
		return
	}
	raw, ok := readBody(w, r, MaxStatementBody)
	if !ok {
		return
	}
	var req StatementRevokeRequest
	if err := strictDecode(bytes.NewReader(raw), &req); err != nil {
		writeError(w, http.StatusBadRequest, "the body is {reason}: "+err.Error())
		return
	}
	if !cleanText(req.Reason, MaxRevokeReason) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("reason is 1 to %d printable characters", MaxRevokeReason))
		return
	}
	ctx := r.Context()
	x := &s.stmts
	x.writeMu.Lock()
	defer x.writeMu.Unlock()
	if err := s.refreshForWrite(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	x.mu.RLock()
	e := x.byID[id]
	var cp stmtEntry
	if e != nil {
		cp = *e
	}
	x.mu.RUnlock()
	if e == nil {
		writeError(w, http.StatusNotFound, "no such statement")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if cp.revoked {
		writeJSON(w, http.StatusOK, StatementRevoked{ID: id, Created: false, State: statement.StateRevoked, Seq: cp.revokeSeq, Hash: cp.revokeHash})
		return
	}
	now := s.opt.Clock().UTC().Truncate(time.Second)
	var rec store.Record
	err := s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		var err error
		rec, err = tx.Append(ctx, store.Event{"ts": pycompat.ISO(now), "task_id": nil, "session": nil, "parent": nil,
			"principal": sub.Person, "agent": nil, "tool": ToolStatementRevoke, "tier": nil, "decision": "allow", "rule": nil,
			"target": "statement:" + id, "args_sha256": cp.digest, "boundary": "deployment",
			"result":    "statement " + id + " revoked: " + req.Reason,
			"initiator": initiator(sub), "delegate": viaString(sub.Via), "packet": map[string]any{"id": cp.packetID},
			"statement": map[string]any{"id": id, "reason": req.Reason, "payload_sha256": cp.digest}}, s.coreWriter(statementVerified))
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "statement: the revocation could not be recorded", "statement", id, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the revocation could not be recorded")
		return
	}
	seq, _ := gate.SeqInt(rec["seq"])
	hash := fmt.Sprint(rec["hash"])
	x.mu.Lock()
	e.revoked, e.revokedAt, e.revokeSeq, e.revokeHash = true, pycompat.ISO(now), seq, hash
	x.mu.Unlock()
	writeJSON(w, http.StatusOK, StatementRevoked{ID: id, Created: true, State: statement.StateRevoked, Seq: seq, Hash: hash})
}
