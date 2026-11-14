package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
)

// Revocation of the W6 assurance surface: a delivery (and so its credential), a recipient's registered key, and one of the
// core's own retired token keys. Every revocation is a chain record written before the answer, idempotent, and admin-only.
//
// A delivery and a recipient key are revoked by a record alone: the state is the chain's, read back into revIndex. The
// index is never trusted past revMaxAge: a read (or a receipt) that finds it older than that reads the chain's tail first
// (one indexed Head read when nothing is new), and when the chain cannot be read the request is refused (503): a revocation
// that cannot be read is never taken as absent. A token key is revoked in the key table too (a row flag), because that table is
// what GET /v1/keys, clearance-api's copy of it and UseSigningKey read.
//
// Ordering inside one process: a read holds revIndex.gate for reading from the check of the revocation until its fetch (or
// sampling) record is written; a revoke holds it for writing from its own read of the chain until its record is written and
// folded in. So a read is either recorded before the revocation record or refused: no read is recorded after the
// revocation was acknowledged.

// Record kinds the revocation routes write.
const (
	ToolPacketRevoke       = "packet.revoke"
	ToolRecipientKeyRevoke = "assurance.key.revoke"
	ToolTokenKeyRevoke     = "token.key.revoke"
)

// The refusal rules revocation adds.
const (
	RulePacketRevoked    = "PK-REVOKED"     // the delivery was revoked
	RuleRecipientKeyGone = "PK-KEY-REVOKED" // the receipt's key was revoked
)

// revMaxAge is the oldest the revocation index may be when a request relies on it. A request that finds it older reads the
// chain's tail first, so a revocation written by anyone is seen by every replica within this plus one store read: the bound
// the access-grant card asks for (5 seconds) with a wide margin.
const revMaxAge = time.Second

var (
	deliveryIDRe = regexp.MustCompile(`^dl-[0-9]{1,18}$`)
	keyIDRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// revocationVerified marks the fields the core checked on a revocation record.
var revocationVerified = union(packetVerified, "revocation")

// revInfo is what the chain says of one revocation.
type revInfo struct {
	at     string // the record's ts
	asOf   string // recipient keys: the time the key is revoked as of
	reason string
	seq    int64
	hash   string
}

type revIndex struct {
	// gate orders reads against revokes (see the package comment above).
	gate sync.RWMutex

	refreshMu sync.Mutex // one reader of the chain's tail at a time; guards next
	next      int64

	mu         sync.RWMutex
	deliveries map[string]revInfo
	keys       map[string]revInfo // recipient + "\x00" + key id
	synced     time.Time          // when the last COMPLETE read of the chain's tail began
	warmed     bool
}

func (x *revIndex) initLocked() {
	if x.deliveries == nil {
		x.deliveries, x.keys = map[string]revInfo{}, map[string]revInfo{}
	}
}

func keyRevKey(recipient, kid string) string { return recipient + "\x00" + kid }

// readLock is held by a request from the check of a revocation until the record that commits it is written. The returned
// func releases it and may be called more than once.
func (x *revIndex) readLock() func() {
	x.gate.RLock()
	var once sync.Once
	return func() { once.Do(x.gate.RUnlock) }
}

// coreRecordWith is true for a record the core wrote itself as a record of this field: its provider is the core, its boundary is
// deployment, and the tool and the field are among the fields the core marked as verified. A registered provider cannot write
// one (the kinds it may write do not include these), and a hand-made record without the marks is ignored.
func coreRecordWith(r store.Record, field string) bool {
	pv, _ := r["provider"].(map[string]any)
	if pv["name"] != evidence.CoreProviderName || r["boundary"] != "deployment" {
		return false
	}
	vs, _ := r["verified"].([]any)
	tool, f := false, false
	for _, v := range vs {
		switch v {
		case "tool":
			tool = true
		case field:
			f = true
		}
	}
	return tool && f
}

// revokePageSize is how many records one read of the chain's tail takes (a variable so a test can make it short).
var revokePageSize = 2000

// refreshRevocations reads the chain from next on and folds every revocation record in, a page at a time (each page applied as
// it is read, so a read that timed out resumes). The caller holds refreshMu.
func (s *Server) refreshRevocations(ctx context.Context) error {
	x := &s.rev
	started := s.opt.Clock()
	if head, _, err := s.opt.Store.Head(ctx); err != nil {
		return err
	} else if head < x.next {
		x.mu.Lock()
		x.initLocked()
		x.synced, x.warmed = started, true
		x.mu.Unlock()
		return nil
	}
	for {
		recs, err := s.opt.Store.Records(ctx, x.next, revokePageSize)
		if err != nil {
			return err
		}
		type fold struct {
			delivery bool
			id       string
			info     revInfo
		}
		var folds []fold
		next := x.next
		for _, r := range recs {
			seq, _ := gate.SeqInt(r["seq"])
			next = seq + 1
			tool, _ := r["tool"].(string)
			if (tool != ToolPacketRevoke && tool != ToolRecipientKeyRevoke) || r["decision"] != "allow" || !coreRecordWith(r, "revocation") {
				continue
			}
			rv, _ := r["revocation"].(map[string]any)
			info := revInfo{at: fmt.Sprint(r["ts"]), reason: fmt.Sprint(rv["reason"]), seq: seq, hash: fmt.Sprint(r["hash"])}
			switch tool {
			case ToolPacketRevoke:
				d, _ := r["delivery"].(map[string]any)
				if id, _ := d["id"].(string); rv["kind"] == "delivery" && deliveryIDRe.MatchString(id) {
					folds = append(folds, fold{delivery: true, id: id, info: info})
				}
			case ToolRecipientKeyRevoke:
				rc, _ := rv["recipient"].(string)
				kid, _ := rv["key_id"].(string)
				asOf, _ := rv["as_of"].(string)
				if _, err := time.Parse(time.RFC3339, asOf); rv["kind"] == "recipient-key" && providerName.MatchString(rc) && keyIDRe.MatchString(kid) && err == nil {
					info.asOf = asOf
					folds = append(folds, fold{id: keyRevKey(rc, kid), info: info})
				}
			}
		}
		x.mu.Lock()
		x.initLocked()
		for _, f := range folds {
			m := x.keys
			if f.delivery {
				m = x.deliveries
			}
			if _, ok := m[f.id]; !ok { // the first revocation stands
				m[f.id] = f.info
			}
		}
		x.next = next
		last := len(recs) < revokePageSize
		if last {
			x.synced, x.warmed = started, true
		}
		x.mu.Unlock()
		if last {
			return nil
		}
	}
}

// freshRevocations makes the index no older than revMaxAge, reading the chain's tail when it is. An error means the state
// could not be read: the caller refuses the request.
func (s *Server) freshRevocations(ctx context.Context) error {
	x := &s.rev
	x.mu.RLock()
	age := s.opt.Clock().Sub(x.synced)
	ok := x.warmed && age >= 0 && age < revMaxAge
	x.mu.RUnlock()
	if ok {
		return nil
	}
	x.refreshMu.Lock()
	defer x.refreshMu.Unlock()
	// Another request may have refreshed while this one waited.
	x.mu.RLock()
	age = s.opt.Clock().Sub(x.synced)
	ok = x.warmed && age >= 0 && age < revMaxAge
	x.mu.RUnlock()
	if ok {
		return nil
	}
	return s.refreshRevocations(ctx)
}

// deliveryRevocation is the delivery's revocation, if there is one, from an index no older than revMaxAge.
func (s *Server) deliveryRevocation(ctx context.Context, delivery string) (revInfo, bool, error) {
	if err := s.freshRevocations(ctx); err != nil {
		return revInfo{}, false, err
	}
	s.rev.mu.RLock()
	defer s.rev.mu.RUnlock()
	info, ok := s.rev.deliveries[delivery]
	return info, ok, nil
}

// recipientKeyRevocation is the key's revocation, if there is one, from an index no older than revMaxAge.
func (s *Server) recipientKeyRevocation(ctx context.Context, recipient, kid string) (revInfo, bool, error) {
	if err := s.freshRevocations(ctx); err != nil {
		return revInfo{}, false, err
	}
	s.rev.mu.RLock()
	defer s.rev.mu.RUnlock()
	info, ok := s.rev.keys[keyRevKey(recipient, kid)]
	return info, ok, nil
}

// revocationUnreadable is what a request answers when the revocation state could not be read.
func (s *Server) revocationUnreadable(w http.ResponseWriter, r *http.Request, err error) {
	s.log.ErrorContext(r.Context(), "revocation: the state could not be read", "error", err.Error())
	writeError(w, http.StatusServiceUnavailable, "the revocation state could not be read, so nothing was served")
}

// RevokeRequest is the body of the three revoke routes: why. A recipient key may also say the time it is revoked as of.
type RevokeRequest struct {
	// Reason is recorded in the chain (1 to 200 printable characters). Do not put a secret in it: it is carried in packets.
	Reason string `json:"reason" contract:"required"`
}

// RecipientKeyRevokeRequest is POST /v1/assurance/recipients/{recipient}/keys/{kid}/revoke's body.
type RecipientKeyRevokeRequest struct {
	Reason string `json:"reason" contract:"required"`
	// AsOf is the time from which the key is not trusted (RFC 3339): a receipt signed at or after it fails `clearance verify`.
	// Default now; a past time says the key was compromised since then; never in the future.
	AsOf string `json:"as_of,omitempty"`
}

// DeliveryRevoked is POST /v1/packets/{id}/deliveries/{delivery}/revoke's answer.
type DeliveryRevoked struct {
	ID        string `json:"id" contract:"required"`
	PacketID  string `json:"packet_id" contract:"required"`
	Recipient string `json:"recipient" contract:"required"`
	State     string `json:"state" contract:"required"`
	// Created is false when the delivery was already revoked: nothing was written, and the rest is the first revocation.
	Created   bool   `json:"created" contract:"required"`
	RevokedAt string `json:"revoked_at" contract:"required"`
	Reason    string `json:"reason" contract:"required"`
	Seq       int64  `json:"seq" contract:"required"`
	Hash      string `json:"hash" contract:"required"`
}

// RecipientKeyRevoked is the recipient key revoke route's answer.
type RecipientKeyRevoked struct {
	Recipient string `json:"recipient" contract:"required"`
	KeyID     string `json:"key_id" contract:"required"`
	State     string `json:"state" contract:"required"`
	Created   bool   `json:"created" contract:"required"`
	AsOf      string `json:"as_of" contract:"required"`
	RevokedAt string `json:"revoked_at" contract:"required"`
	Reason    string `json:"reason" contract:"required"`
	Seq       int64  `json:"seq" contract:"required"`
	Hash      string `json:"hash" contract:"required"`
}

// TokenKeyRevoked is POST /v1/keys/{kid}/revoke's answer.
type TokenKeyRevoked struct {
	KeyID     string `json:"key_id" contract:"required"`
	State     string `json:"state" contract:"required"`
	Created   bool   `json:"created" contract:"required"`
	RevokedAt string `json:"revoked_at" contract:"required"`
	Seq       *int64 `json:"seq"`
	Hash      string `json:"hash,omitempty"`
}

const stateRevoked = "revoked"

func decodeRevoke(w http.ResponseWriter, r *http.Request, into any, shape string) bool {
	raw, ok := readBody(w, r, MaxRevokeBody)
	if !ok {
		return false
	}
	if err := strictDecode(bytes.NewReader(raw), into); err != nil {
		writeError(w, http.StatusBadRequest, "the body is "+shape+": "+err.Error())
		return false
	}
	return true
}

func badReason(w http.ResponseWriter, reason string) bool {
	if !cleanText(reason, MaxRevokeReason) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("reason is 1 to %d printable characters", MaxRevokeReason))
		return true
	}
	return false
}

// MaxRevokeBody caps the revoke routes' bodies.
const MaxRevokeBody = 4 << 10

// revokeDelivery is POST /v1/packets/{id}/deliveries/{delivery}/revoke: from the record on, every read, sample and receipt under
// the delivery's credential is refused PK-REVOKED. The record is written before the answer; revoking a revoked delivery is the
// same answer and writes nothing; a revoked delivery is never un-revoked (a new delivery is the remedy).
func (s *Server) revokeDelivery(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.subscriber(w, r)
	if !ok {
		return
	}
	id, did := r.PathValue("id"), r.PathValue("delivery")
	if !packet.ValidID(id) || !deliveryIDRe.MatchString(did) {
		writeError(w, http.StatusNotFound, "no such delivery")
		return
	}
	var req RevokeRequest
	if !decodeRevoke(w, r, &req, "{reason}") || badReason(w, req.Reason) {
		return
	}
	ctx := r.Context()
	x := &s.rev
	x.gate.Lock()
	defer x.gate.Unlock()
	if err := s.freshRevocationsLocked(ctx); err != nil {
		s.revocationUnreadable(w, r, err)
		return
	}
	dseq, _ := strconv.ParseInt(strings.TrimPrefix(did, "dl-"), 10, 64)
	drecs, err := s.opt.Store.Records(ctx, dseq, 1)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	var dl store.Record
	if len(drecs) == 1 {
		dl = drecs[0]
	}
	d, _ := dl["delivery"].(map[string]any)
	dp, _ := dl["packet"].(map[string]any)
	if dl == nil || dl["tool"] != ToolPacketDeliver || fmt.Sprint(dl["seq"]) != strconv.FormatInt(dseq, 10) || !coreRecordWith(dl, "delivery") ||
		fmt.Sprint(dp["id"]) != id {
		writeError(w, http.StatusNotFound, "no such delivery")
		return
	}
	rcp := fmt.Sprint(d["recipient"])
	w.Header().Set("Cache-Control", "no-store")
	x.mu.RLock()
	have, revoked := x.deliveries[did]
	x.mu.RUnlock()
	if revoked {
		writeJSON(w, http.StatusOK, DeliveryRevoked{ID: did, PacketID: id, Recipient: rcp, State: stateRevoked, Created: false,
			RevokedAt: have.at, Reason: have.reason, Seq: have.seq, Hash: have.hash})
		return
	}
	now := s.opt.Clock().UTC().Truncate(time.Second)
	var rec store.Record
	err = s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		var err error
		rec, err = tx.Append(ctx, store.Event{"ts": pycompat.ISO(now), "task_id": nil, "session": nil, "parent": nil,
			"principal": sub.Person, "agent": nil, "tool": ToolPacketRevoke, "tier": nil, "decision": "allow", "rule": nil,
			"target": "packet:" + id, "args_sha256": dp["digest"], "boundary": "deployment",
			"result":    fmt.Sprintf("delivery %s of packet %s to %s revoked: %s", did, id, rcp, req.Reason),
			"initiator": initiator(sub), "delegate": viaString(sub.Via), "packet": map[string]any{"id": id, "digest": dp["digest"]},
			"delivery":   map[string]any{"id": did, "recipient": rcp, "packet": id},
			"revocation": map[string]any{"kind": "delivery", "reason": req.Reason}}, s.coreWriter(revocationVerified))
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "revocation: the delivery's revocation could not be recorded", "packet", id, "delivery", did, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the revocation could not be recorded")
		return
	}
	seq, _ := gate.SeqInt(rec["seq"])
	info := revInfo{at: pycompat.ISO(now), reason: req.Reason, seq: seq, hash: fmt.Sprint(rec["hash"])}
	x.mu.Lock()
	x.deliveries[did] = info // folded in before the lock is released: no later read in this process misses it
	x.mu.Unlock()
	writeJSON(w, http.StatusOK, DeliveryRevoked{ID: did, PacketID: id, Recipient: rcp, State: stateRevoked, Created: true,
		RevokedAt: info.at, Reason: info.reason, Seq: seq, Hash: info.hash})
}

// freshRevocationsLocked is freshRevocations for a caller that already holds the gate for writing: it always reads the chain's
// tail (a revoke decides on what the chain holds now, never on a cache).
func (s *Server) freshRevocationsLocked(ctx context.Context) error {
	x := &s.rev
	x.refreshMu.Lock()
	defer x.refreshMu.Unlock()
	return s.refreshRevocations(ctx)
}

// revokeRecipientKey is POST /v1/assurance/recipients/{recipient}/keys/{kid}/revoke: a key a recipient registered is revoked as
// of a time. From then a receipt signed with it is refused at submit; receipts already recorded stay, and `clearance verify` fails
// one signed at or after the as-of time and prints the revocation on one signed before it.
func (s *Server) revokeRecipientKey(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.subscriber(w, r)
	if !ok {
		return
	}
	name, kid := r.PathValue("recipient"), r.PathValue("kid")
	rcp := recipient(s.opt.Providers, name)
	if !providerName.MatchString(name) || !keyIDRe.MatchString(kid) || rcp == nil {
		writeError(w, http.StatusNotFound, "no such recipient key")
		return
	}
	keys, err := rcp.RecipientKeys()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the recipient's keys could not be read")
		return
	}
	if _, ok := keys[kid]; !ok {
		writeError(w, http.StatusNotFound, "no such recipient key")
		return
	}
	var req RecipientKeyRevokeRequest
	if !decodeRevoke(w, r, &req, "{reason, as_of?}") || badReason(w, req.Reason) {
		return
	}
	now := s.opt.Clock().UTC().Truncate(time.Second)
	asOf := now
	if req.AsOf != "" {
		t, err := time.Parse(time.RFC3339, req.AsOf)
		if err != nil {
			writeError(w, http.StatusBadRequest, "as_of is an RFC 3339 time")
			return
		}
		if t.After(now.Add(DefaultMaxClockSkew)) {
			writeError(w, http.StatusBadRequest, "as_of is in the future: a revocation takes effect now or earlier")
			return
		}
		asOf = t.UTC().Truncate(time.Second)
	}
	ctx := r.Context()
	x := &s.rev
	x.gate.Lock()
	defer x.gate.Unlock()
	if err := s.freshRevocationsLocked(ctx); err != nil {
		s.revocationUnreadable(w, r, err)
		return
	}
	k := keyRevKey(name, kid)
	w.Header().Set("Cache-Control", "no-store")
	x.mu.RLock()
	have, revoked := x.keys[k]
	x.mu.RUnlock()
	if revoked {
		writeJSON(w, http.StatusOK, RecipientKeyRevoked{Recipient: name, KeyID: kid, State: stateRevoked, Created: false, AsOf: have.asOf,
			RevokedAt: have.at, Reason: have.reason, Seq: have.seq, Hash: have.hash})
		return
	}
	var rec store.Record
	err = s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		var err error
		rec, err = tx.Append(ctx, store.Event{"ts": pycompat.ISO(now), "task_id": nil, "session": nil, "parent": nil,
			"principal": sub.Person, "agent": nil, "tool": ToolRecipientKeyRevoke, "tier": nil, "decision": "allow", "rule": nil,
			"target": "recipient:" + name, "args_sha256": nil, "boundary": "deployment",
			"result":    fmt.Sprintf("key %s of recipient %s revoked as of %s: %s", kid, name, pycompat.ISO(asOf), req.Reason),
			"initiator": initiator(sub), "delegate": viaString(sub.Via),
			"revocation": map[string]any{"kind": "recipient-key", "recipient": name, "key_id": kid, "as_of": pycompat.ISO(asOf), "reason": req.Reason}},
			s.coreWriter(revocationVerified))
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "revocation: the key's revocation could not be recorded", "recipient", name, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the revocation could not be recorded")
		return
	}
	seq, _ := gate.SeqInt(rec["seq"])
	info := revInfo{at: pycompat.ISO(now), asOf: pycompat.ISO(asOf), reason: req.Reason, seq: seq, hash: fmt.Sprint(rec["hash"])}
	x.mu.Lock()
	x.keys[k] = info
	x.mu.Unlock()
	writeJSON(w, http.StatusOK, RecipientKeyRevoked{Recipient: name, KeyID: kid, State: stateRevoked, Created: true, AsOf: info.asOf,
		RevokedAt: info.at, Reason: info.reason, Seq: seq, Hash: info.hash})
}

// revokeTokenKey is POST /v1/keys/{kid}/revoke: a RETIRED token signing key is revoked. From the commit, GET /v1/keys no longer
// lists it and no packet credential it signed verifies (the credential's check reads the key table on every request, so this is
// immediate in every replica); a clearance token or grant feed it signed no longer verifies at a consumer that re-reads GET /v1/keys,
// and the core re-signs them with the key in use (it does so at once here, and its minute loop does it anyway). The key in use cannot
// be revoked (409: rotate first), and a revoked key is never used again (the core refuses to start with it). The record and the
// key's flag commit together. Statement keys are a separate set and are not touched.
func (s *Server) revokeTokenKey(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.subscriber(w, r)
	if !ok {
		return
	}
	kid := r.PathValue("kid")
	if !keyIDRe.MatchString(kid) {
		writeError(w, http.StatusNotFound, "no such key")
		return
	}
	var req RevokeRequest
	if !decodeRevoke(w, r, &req, "{reason}") || badReason(w, req.Reason) {
		return
	}
	signer, _, err := s.opt.Gate.Credentials()
	if err != nil {
		if !gateFail(w, err) {
			writeError(w, http.StatusServiceUnavailable, "no signer")
		}
		return
	}
	if signer.KeyID() == kid {
		writeError(w, http.StatusConflict, "this is the key the core signs with now: start the core with another signing key first (rotate), then revoke this one")
		return
	}
	ctx := r.Context()
	x := &s.rev
	now := s.opt.Clock().UTC().Truncate(time.Second)
	var rec store.Record
	var key store.SigningKey
	x.gate.Lock() // in-flight reads under a credential finish (and are recorded) first; later ones read the key table without the key
	err = s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		k, changed, err := tx.RevokeSigningKey(ctx, kid, now)
		if err != nil {
			return err
		}
		key = k
		if !changed {
			return nil
		}
		rec, err = tx.Append(ctx, store.Event{"ts": pycompat.ISO(now), "task_id": nil, "session": nil, "parent": nil,
			"principal": sub.Person, "agent": nil, "tool": ToolTokenKeyRevoke, "tier": nil, "decision": "allow", "rule": nil,
			"target": "key:" + kid, "args_sha256": nil, "boundary": "deployment",
			"result":    fmt.Sprintf("token signing key %s revoked: %s", kid, req.Reason),
			"initiator": initiator(sub), "delegate": viaString(sub.Via),
			"revocation": map[string]any{"kind": "token-key", "key_id": kid, "reason": req.Reason}}, s.coreWriter(revocationVerified))
		return err
	})
	x.gate.Unlock()
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such key")
		return
	case errors.Is(err, store.ErrKeyInUse):
		writeError(w, http.StatusConflict, "this is the key the core signs with now: start the core with another signing key first (rotate), then revoke this one")
		return
	case err != nil:
		s.log.ErrorContext(ctx, "revocation: the key's revocation could not be recorded", "key", kid, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the revocation could not be recorded")
		return
	}
	out := TokenKeyRevoked{KeyID: kid, State: stateRevoked, Created: rec != nil}
	if key.RevokedAt != nil {
		out.RevokedAt = pycompat.ISO(*key.RevokedAt)
	}
	if rec != nil {
		seq, _ := gate.SeqInt(rec["seq"])
		out.Seq, out.Hash = &seq, fmt.Sprint(rec["hash"])
		// Tokens and feeds the revoked key signed are re-signed with the key in use now, not at the next tick (best effort: the
		// minute loop does it anyway, and a read of a token re-issues one signed by another key).
		if _, _, err := s.opt.Gate.Refresh(ctx); err != nil {
			s.log.WarnContext(ctx, "revocation: re-issuing tokens after a key revocation failed", "error", err.Error())
		}
		if _, err := s.opt.Gate.RefreshFeeds(ctx); err != nil {
			s.log.WarnContext(ctx, "revocation: re-signing feeds after a key revocation failed", "error", err.Error())
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}
