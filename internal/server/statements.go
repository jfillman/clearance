package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/statement"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
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

// stmtEntry is a statement as the chain holds it.
type stmtEntry struct {
	id         string
	envelope   []byte // the DSSE envelope as signed
	digest     string
	packetID   string
	profile    string
	supersedes string
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

// stmtIndex is the statement records of the chain, by id, read once and then kept current by re-reading the chain's tail:
// the one writer's own writes land in it at once, and another replica's land within statementTailEvery.
type stmtIndex struct {
	mu     sync.Mutex
	byID   map[string]*stmtEntry
	byReq  map[string]string
	next   int64 // the next seq to read
	synced time.Time
}

// refresh reads the chain from next on and folds in every statement.issue and statement.revoke. The caller holds x.mu.
func (s *Server) refreshStatements(ctx context.Context, x *stmtIndex) error {
	if x.byID == nil {
		x.byID, x.byReq = map[string]*stmtEntry{}, map[string]string{}
	}
	const page = 2000
	for {
		recs, err := s.opt.Store.Records(ctx, x.next, page)
		if err != nil {
			return err
		}
		for _, r := range recs {
			seq, _ := gate.SeqInt(r["seq"])
			x.next = seq + 1
			tool, _ := r["tool"].(string)
			if (tool != ToolStatementIssue && tool != ToolStatementRevoke) || r["decision"] != "allow" {
				continue
			}
			st, _ := r["statement"].(map[string]any)
			id, _ := st["id"].(string)
			if !statement.ValidID(id) {
				continue
			}
			switch tool {
			case ToolStatementIssue:
				if x.byID[id] != nil {
					continue
				}
				env, err := json.Marshal(st["envelope"])
				if err != nil || len(env) > statement.MaxEnvelopeBytes {
					continue
				}
				pk, _ := r["packet"].(map[string]any)
				e := &stmtEntry{id: id, envelope: env, digest: fmt.Sprint(st["payload_sha256"]), packetID: fmt.Sprint(pk["id"]), profile: fmt.Sprint(st["profile"]),
					reqKey: fmt.Sprint(st["request_sha256"]), seq: seq, hash: fmt.Sprint(r["hash"])}
				if sup, _ := st["supersedes"].(string); statement.ValidID(sup) {
					e.supersedes = sup
					if old := x.byID[sup]; old != nil && old.supersededBy == "" {
						old.supersededBy = id
					}
				}
				x.byID[id] = e
				x.byReq[e.reqKey] = id
			case ToolStatementRevoke:
				if e := x.byID[id]; e != nil && !e.revoked {
					e.revoked, e.revokedAt, e.revokeSeq, e.revokeHash = true, fmt.Sprint(r["ts"]), seq, fmt.Sprint(r["hash"])
				}
			}
		}
		if len(recs) < page {
			break
		}
	}
	x.synced = s.opt.Clock()
	return nil
}

// stmtLive is a statement's current state as of the read that gave it.
type stmtLive struct {
	entry *stmtEntry // a copy: nothing in it changes after the lock is released
	asOf  time.Time
}

// lookupStatement is the public read: the statement by id, with its current state, after a tail read at most
// statementTailEvery old. found is false for an id the chain holds no statement of; err is a store that could not be read
// (the caller fails closed: it must not say valid on a state it could not read).
func (s *Server) lookupStatement(ctx context.Context, id string) (live stmtLive, found bool, err error) {
	x := &s.stmts
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.byID == nil || s.opt.Clock().Sub(x.synced) >= statementTailEvery {
		if err := s.refreshStatements(ctx, x); err != nil {
			return stmtLive{}, false, err
		}
	}
	e := x.byID[id]
	if e == nil {
		return stmtLive{asOf: x.synced}, false, nil
	}
	cp := *e
	return stmtLive{entry: &cp, asOf: x.synced}, true, nil
}

// WarmStatements reads the statement records of the chain, so the first public request does not.
func (s *Server) WarmStatements(ctx context.Context) error {
	x := &s.stmts
	x.mu.Lock()
	defer x.mu.Unlock()
	return s.refreshStatements(ctx, x)
}

func statementRequestKey(packetDigest string, req StatementRequest, profile string) (string, error) {
	c, err := canon.Canonical(map[string]any{"packet_digest": packetDigest, "profile": profile, "scope": req.Scope,
		"policy_version": req.PolicyVersion, "supersedes": req.Supersedes})
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

// issueStatement is POST /v1/statements: an admin cuts a signed statement from a published packet. The core builds it with
// statement.Build (the function the verifier recomputes it with), signs it with its clearance key, and records it
// (statement.issue) before it answers. The same request again is the same statement and records nothing.
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
		writeError(w, http.StatusBadRequest, "the body is {packet, scope, policy_version, profile?, supersedes?}: "+err.Error())
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
	}
	ctx := r.Context()
	signer, issuer, err := s.opt.Gate.Credentials()
	if err != nil {
		if !gateFail(w, err) {
			writeError(w, http.StatusServiceUnavailable, "no signer")
		}
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
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := s.refreshStatements(ctx, x); err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	if id := x.byReq[reqKey]; id != "" {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, s.issued(x.byID[id], false))
		return
	}
	if len(x.byID) >= MaxStatements {
		writeError(w, http.StatusConflict, fmt.Sprintf("this core already holds %d statements", MaxStatements))
		return
	}
	if req.Supersedes != "" {
		old := x.byID[req.Supersedes]
		switch {
		case old == nil:
			writeError(w, http.StatusNotFound, "no such statement to supersede")
			return
		case old.revoked:
			writeError(w, http.StatusConflict, "that statement is revoked: a revoked statement stays revoked; issue a new one without supersedes")
			return
		case old.supersededBy != "":
			writeError(w, http.StatusConflict, "that statement has already been superseded")
			return
		}
	}
	var id string
	for i := 0; i < 4 && id == ""; i++ {
		c, err := statement.NewID()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "no randomness")
			return
		}
		if x.byID[c] == nil {
			id = c
		}
	}
	if id == "" {
		writeError(w, http.StatusServiceUnavailable, "no statement id could be made")
		return
	}
	now := s.opt.Clock().UTC().Truncate(time.Second)
	doc, err := statement.Build(statement.Input{ID: id, Issuer: issuer, IssuedAt: pycompat.ISO(now), Profile: profile, ScopeLabel: req.Scope,
		PolicyVersion: req.PolicyVersion, Supersedes: req.Supersedes, IndependentWitnesses: s.statementOpts().IndependentWitnesses,
		PacketID: pk.ID, PacketDigest: pk.Digest, PacketJSON: b.Files["packet.json"], RecordsJSONL: b.Files[packet.FileRecords]})
	if err != nil {
		writeError(w, http.StatusBadRequest, "the packet cannot be summarised: "+err.Error())
		return
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
	var rec store.Record
	err = s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		st := map[string]any{"id": id, "profile": profile, "request_sha256": reqKey, "payload_sha256": digest, "envelope": envObj}
		if req.Supersedes != "" {
			st["supersedes"] = req.Supersedes
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
	e := &stmtEntry{id: id, envelope: envJSON, digest: digest, packetID: pk.ID, profile: profile, supersedes: req.Supersedes, reqKey: reqKey, seq: seq, hash: fmt.Sprint(rec["hash"])}
	x.byID[id], x.byReq[reqKey] = e, id
	if req.Supersedes != "" {
		x.byID[req.Supersedes].supersededBy = id
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.issued(e, true))
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
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := s.refreshStatements(ctx, x); err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	e := x.byID[id]
	if e == nil {
		writeError(w, http.StatusNotFound, "no such statement")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if e.revoked {
		writeJSON(w, http.StatusOK, StatementRevoked{ID: id, Created: false, State: statement.StateRevoked, Seq: e.revokeSeq, Hash: e.revokeHash})
		return
	}
	now := s.opt.Clock().UTC().Truncate(time.Second)
	var rec store.Record
	err := s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		var err error
		rec, err = tx.Append(ctx, store.Event{"ts": pycompat.ISO(now), "task_id": nil, "session": nil, "parent": nil,
			"principal": sub.Person, "agent": nil, "tool": ToolStatementRevoke, "tier": nil, "decision": "allow", "rule": nil,
			"target": "statement:" + id, "args_sha256": e.digest, "boundary": "deployment",
			"result":    "statement " + id + " revoked: " + req.Reason,
			"initiator": initiator(sub), "delegate": viaString(sub.Via), "packet": map[string]any{"id": e.packetID},
			"statement": map[string]any{"id": id, "reason": req.Reason, "payload_sha256": e.digest}}, s.coreWriter(statementVerified))
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "statement: the revocation could not be recorded", "statement", id, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the revocation could not be recorded")
		return
	}
	seq, _ := gate.SeqInt(rec["seq"])
	e.revoked, e.revokedAt, e.revokeSeq, e.revokeHash = true, pycompat.ISO(now), seq, fmt.Sprint(rec["hash"])
	writeJSON(w, http.StatusOK, StatementRevoked{ID: id, Created: true, State: statement.StateRevoked, Seq: seq, Hash: e.revokeHash})
}
