package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/canon"
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
	supersedes string
	reissues   string
	reqKey     string
	seq        int64
	hash       string
	// current state: set as the chain's records about the statement are read.
	supersededBy string
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

// stmtIndex is the statement records of the chain, by id, read once (warm) and then kept current by re-reading the chain's tail:
// the one writer's own writes land in it at once, and another replica's land within statementTailEvery. Public readers take
// only the read lock and never wait on a write or on the store: a refresh is single-flight (a reader that finds one running
// uses the snapshot), and a snapshot older than statementMaxStale is not served.
type stmtIndex struct {
	mu     sync.RWMutex
	byID   map[string]*stmtEntry
	byReq  map[string]string
	synced time.Time
	warmed bool

	refreshMu sync.Mutex // one reader of the chain's tail at a time; guards next
	next      int64
	writeMu   sync.Mutex // serialises issue and revoke
	warming   bool       // guarded by mu: a background warm loop is running
}

var (
	errStatementsCold  = errors.New("the statement index is not warm yet")
	errStatementsStale = errors.New("the statement index could not be refreshed in time")
)

type stmtEvent struct {
	issue     *stmtEntry
	revokeID  string
	revokedAt string
	seq       int64
	hash      string
}

// refreshLocked reads the chain from next on and folds in every statement.issue and statement.revoke. The caller holds
// refreshMu; the read takes no other lock, and the result is applied under the write lock in one step.
func (s *Server) refreshLocked(ctx context.Context, x *stmtIndex) error {
	const page = 2000
	var evs []stmtEvent
	next := x.next
	for {
		recs, err := s.opt.Store.Records(ctx, next, page)
		if err != nil {
			return err
		}
		for _, r := range recs {
			seq, _ := gate.SeqInt(r["seq"])
			next = seq + 1
			tool, _ := r["tool"].(string)
			if (tool != ToolStatementIssue && tool != ToolStatementRevoke) || r["decision"] != "allow" {
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
				reqKey: fmt.Sprint(st["request_sha256"]), seq: seq, hash: fmt.Sprint(r["hash"]), kid: envelopeKid(st["envelope"])}
			if sup, _ := st["supersedes"].(string); statement.ValidID(sup) {
				e.supersedes = sup
			}
			if re, _ := st["reissues"].(string); statement.ValidID(re) {
				e.reissues = re
			}
			evs = append(evs, stmtEvent{issue: e})
		}
		if len(recs) < page {
			break
		}
	}
	x.mu.Lock()
	if x.byID == nil {
		x.byID, x.byReq = map[string]*stmtEntry{}, map[string]string{}
	}
	for _, ev := range evs {
		switch {
		case ev.issue != nil:
			e := ev.issue
			if x.byID[e.id] != nil {
				continue
			}
			x.byID[e.id], x.byReq[e.reqKey] = e, e.id
			if old := x.byID[e.supersedes]; e.supersedes != "" && old != nil && old.supersededBy == "" {
				old.supersededBy = e.id
			}
		default:
			if e := x.byID[ev.revokeID]; e != nil && !e.revoked {
				e.revoked, e.revokedAt, e.revokeSeq, e.revokeHash = true, ev.revokedAt, ev.seq, ev.hash
			}
		}
	}
	x.next, x.synced, x.warmed = next, s.opt.Clock(), true
	x.mu.Unlock()
	return nil
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

// refreshForWrite is the authenticated path's refresh: it waits its turn, and the first call on a cold index reads the chain.
func (s *Server) refreshForWrite(ctx context.Context) error {
	x := &s.stmts
	x.refreshMu.Lock()
	defer x.refreshMu.Unlock()
	return s.refreshLocked(ctx, x)
}

// stmtLive is a statement's current state as of the read that gave it.
type stmtLive struct {
	entry            *stmtEntry // a copy: nothing in it changes after the lock is released
	asOf             time.Time  // when the index was last read from the chain
	successorRevoked bool       // the statement that replaced this one was itself revoked
}

// lookupStatement is the public read: the statement by id, with its current state. It never scans the chain and never waits on a
// write: a cold index is errStatementsCold (the page answers 503 until the background warm finishes), and a snapshot older than
// statementMaxStale that could not be refreshed is errStatementsStale (503: it must not say valid on a state it could not
// read). found is false for an id the chain holds no statement of.
func (s *Server) lookupStatement(ctx context.Context, id string) (stmtLive, bool, error) {
	x := &s.stmts
	x.mu.RLock()
	warmed, synced := x.warmed, x.synced
	x.mu.RUnlock()
	if !warmed {
		return stmtLive{}, false, errStatementsCold
	}
	if now := s.opt.Clock(); now.Sub(synced) >= statementTailEvery {
		if x.refreshMu.TryLock() {
			rctx, cancel := context.WithTimeout(ctx, statementRefreshTimeout)
			err := s.refreshLocked(rctx, x)
			cancel()
			x.refreshMu.Unlock()
			if err != nil && now.Sub(synced) > statementMaxStale {
				return stmtLive{}, false, err
			}
		} else if now.Sub(synced) > statementMaxStale {
			return stmtLive{}, false, errStatementsStale
		}
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	e := x.byID[id]
	if e == nil {
		return stmtLive{asOf: x.synced}, false, nil
	}
	cp := *e
	live := stmtLive{entry: &cp, asOf: x.synced}
	if succ := x.byID[e.supersededBy]; succ != nil && succ.revoked {
		live.successorRevoked = true
	}
	return live, true, nil
}

// liveStatementKids are the signing keys of every statement not revoked: GET /v1/keys keeps each for as long as its statement
// stands, so a statement does not stop verifying when its key leaves the retirement window.
func (s *Server) liveStatementKids() map[string]bool {
	x := &s.stmts
	x.mu.RLock()
	defer x.mu.RUnlock()
	out := map[string]bool{}
	for _, e := range x.byID {
		if !e.revoked && e.kid != "" {
			out[e.kid] = true
		}
	}
	return out
}

// publishedKeys are the signing keys GET /v1/keys and the verify page's checks use: the one in use, those retired since
// `since`, and every key that signed a statement still standing.
func (s *Server) publishedKeys(ctx context.Context, since time.Time) ([]store.SigningKey, error) {
	rows, err := s.opt.Store.SigningKeys(ctx, time.Time{})
	if err != nil {
		return nil, err
	}
	live := s.liveStatementKids()
	out := rows[:0:0]
	for _, k := range rows {
		if k.RetiredAt == nil || k.RetiredAt.After(since) || live[k.KeyID] {
			out = append(out, k)
		}
	}
	return out, nil
}

// WarmStatements reads the statement records of the chain once, so no public request does. A failure starts a background
// retry (every few seconds) and returns the error; until a read succeeds the public page answers 503 and reads nothing.
func (s *Server) WarmStatements(ctx context.Context) error {
	x := &s.stmts
	x.mu.RLock()
	warm := x.warmed
	x.mu.RUnlock()
	if warm {
		return nil
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := s.refreshForWrite(wctx)
	cancel()
	if err == nil {
		return nil
	}
	x.mu.Lock()
	start := !x.warming
	x.warming = true
	x.mu.Unlock()
	if start {
		go func() {
			for {
				time.Sleep(5 * time.Second)
				rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				e := s.refreshForWrite(rctx)
				cancel()
				if e == nil {
					x.mu.Lock()
					x.warming = false
					x.mu.Unlock()
					return
				}
			}
		}()
	}
	return err
}

// statementEnvelope is the signed envelope of a statement, read from its issue record.
func (s *Server) statementEnvelope(ctx context.Context, e *stmtEntry) ([]byte, error) {
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
			case old.supersededBy != "":
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
	// The packet is the admin's to publish; the counts in it are checked here, with the checks the page runs, before anything is
	// signed. A check whose input is missing is not a refusal (the page shows it NOT CHECKED); one that FAILS is.
	for _, c := range verify.StatementPacketChecks(doc, s.statementVerifyOptions(b.Files)) {
		if c.Status == verify.Fail {
			writeError(w, http.StatusUnprocessableEntity, "the packet does not support the statement, so none was signed: "+c.Name)
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
		st := map[string]any{"id": id, "profile": profile, "request_sha256": reqKey, "payload_sha256": digest, "envelope": envObj}
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
	seq, _ := gate.SeqInt(rec["seq"])
	e := &stmtEntry{id: id, digest: digest, kid: signer.KeyID(), packetID: pk.ID, profile: profile, supersedes: req.Supersedes, reissues: req.Reissue, reqKey: reqKey, seq: seq, hash: fmt.Sprint(rec["hash"])}
	x.mu.Lock()
	x.byID[id], x.byReq[reqKey] = e, id
	if req.Supersedes != "" {
		x.byID[req.Supersedes].supersededBy = id
	}
	cp := *e
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
