package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/receipt"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
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
// The index is first read by a goroutine New starts, a page at a time (a scan that fails resumes where it stopped and the index is warm
// only after the last page). Until it is warm, the credentialed routes and the revoke routes wait a short while for it and then answer 503
// with Retry-After: never a scan inside a request, and never a read served on a state that was not read.
//
// Ordering inside one process: a read does its expensive work (loading and cutting the packet, drawing a sample) WITHOUT the gate, then
// takes revIndex.gate for reading, re-runs the checks a revoke could have changed (the credential's key, the delivery's revocation) and
// writes its fetch (or sampling) record, and releases it. A revoke holds the gate for writing from its own read of the chain until its
// record is written and folded in. So a read is either recorded before the revocation record or refused, and the gate covers one
// check and one Append, not a read's slow part. Every wait for the gate, and for the mutexes beside it, ends with the request's context.

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

// warmGrace is how long a request on a core that has not finished reading its indexes waits for them before answering 503 with Retry-After.
const warmGrace = 2 * time.Second

// BackdateAfter is how far back an as_of may be without the caller saying so (backdate: true).
const BackdateAfter = 24 * time.Hour

var (
	deliveryIDRe = regexp.MustCompile(`^dl-[0-9]{1,18}$`)
	keyIDRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// revocationVerified marks the fields the core checked on a revocation record.
var revocationVerified = union(packetVerified, "revocation")

// errRevCold is the revocation index not being read yet (a slow store or a long chain at start).
var errRevCold = errors.New("the revocation state is not read yet")

// revInfo is what the chain says of one revocation.
type revInfo struct {
	at     string // the record's ts
	asOf   string // recipient keys: the time the key is revoked as of
	reason string
	seq    int64
	hash   string
}

// recordedReceipt is a receipt the core recorded: when, and what its signer said.
type recordedReceipt struct{ recorded, signed time.Time }

type revIndex struct {
	// gate orders reads against revokes (see the package comment above).
	gate ctxGate

	refreshMu ctxMutex // one reader of the chain's tail at a time; guards next
	next      int64

	mu         sync.RWMutex
	deliveries map[string]revInfo
	keys       map[string]revInfo // recipient + "\x00" + key id
	// firstDelivery is the time of the first packet.deliver the core recorded to each recipient: before it, no credential of the
	// recipient's existed, so a key cannot be revoked as of an earlier time. keyReceipts are the receipts the core recorded, by recipient
	// and key id: how many a back-dated revocation would fail.
	firstDelivery map[string]time.Time
	keyReceipts   map[string][]recordedReceipt
	synced        time.Time // when the last COMPLETE read of the chain's tail began
	warmed        bool

	warmOnce sync.Once
	warmCh   chan struct{} // closed when the index is first warm
}

func (x *revIndex) initLocked() {
	if x.deliveries == nil {
		x.deliveries, x.keys = map[string]revInfo{}, map[string]revInfo{}
		x.firstDelivery, x.keyReceipts = map[string]time.Time{}, map[string][]recordedReceipt{}
	}
}

func (x *revIndex) warmChan() chan struct{} {
	x.warmOnce.Do(func() { x.warmCh = make(chan struct{}) })
	return x.warmCh
}

func keyRevKey(recipient, kid string) string { return recipient + "\x00" + kid }

// cleanTextStrict is cleanText for the revoke routes' reasons: it also refuses every control character (the C1 range too), the format
// characters that hide text (bidirectional controls, zero-width and joiner characters: category Cf), and the line and paragraph separators.
// cleanText itself is unchanged (see its callers: an engagement or a statement reason with a zero-width joiner in it is still accepted).
func cleanTextStrict(v string, max int) bool {
	if !cleanText(v, max) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return false
		}
	}
	return utf8.ValidString(v)
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

// refreshRevocations reads the chain from next on and folds in every revocation record (and the deliveries and receipts a back-dated
// revocation is checked against), a page at a time (each page applied as it is read, so a read that timed out resumes and the index is
// warm only after the last page). The caller holds refreshMu.
func (s *Server) refreshRevocations(ctx context.Context) error {
	x := &s.rev
	started := s.opt.Clock()
	markWarm := func() {
		x.initLocked()
		x.synced, x.warmed = started, true
		x.warmChan()
		select {
		case <-x.warmCh:
		default:
			close(x.warmCh)
		}
	}
	if head, _, err := s.opt.Store.Head(ctx); err != nil {
		return err
	} else if head < x.next {
		x.mu.Lock()
		markWarm()
		x.mu.Unlock()
		return nil
	}
	for {
		recs, err := s.opt.Store.Records(ctx, x.next, revokePageSize)
		if err != nil {
			return err
		}
		type fold struct {
			kind string // "delivery", "key", "first", "receipt"
			id   string
			info revInfo
			t, u time.Time
		}
		var folds []fold
		next := x.next
		for _, r := range recs {
			seq, _ := gate.SeqInt(r["seq"])
			next = seq + 1
			tool, _ := r["tool"].(string)
			if r["decision"] != "allow" {
				continue
			}
			ts, _ := time.Parse(time.RFC3339, fmt.Sprint(r["ts"]))
			switch tool {
			case ToolPacketDeliver:
				if d, _ := r["delivery"].(map[string]any); coreRecordWith(r, "delivery") && !ts.IsZero() {
					if rc, _ := d["recipient"].(string); rc != "" {
						folds = append(folds, fold{kind: "first", id: rc, t: ts})
					}
				}
			case packet.ToolReceipt:
				rc, _ := r["receipt"].(map[string]any)
				dl, _ := r["delivery"].(map[string]any)
				kid, _ := rc["key_id"].(string)
				if recip, _ := dl["recipient"].(string); coreRecordWith(r, "receipt") && kid != "" && recip != "" && !ts.IsZero() {
					if raw, err := json.Marshal(rc["envelope"]); err == nil {
						if pl, err := receipt.Read(raw); err == nil {
							signed, _ := time.Parse(time.RFC3339, pl.SignedAt)
							folds = append(folds, fold{kind: "receipt", id: keyRevKey(recip, kid), t: ts, u: signed})
						}
					}
				}
			case ToolPacketRevoke, ToolRecipientKeyRevoke:
				if !coreRecordWith(r, "revocation") {
					continue
				}
				rv, _ := r["revocation"].(map[string]any)
				info := revInfo{at: fmt.Sprint(r["ts"]), reason: fmt.Sprint(rv["reason"]), seq: seq, hash: fmt.Sprint(r["hash"])}
				if tool == ToolPacketRevoke {
					d, _ := r["delivery"].(map[string]any)
					if id, _ := d["id"].(string); rv["kind"] == "delivery" && deliveryIDRe.MatchString(id) {
						folds = append(folds, fold{kind: "delivery", id: id, info: info})
					}
					continue
				}
				rc, _ := rv["recipient"].(string)
				kid, _ := rv["key_id"].(string)
				asOf, _ := rv["as_of"].(string)
				if _, err := time.Parse(time.RFC3339, asOf); rv["kind"] == "recipient-key" && providerName.MatchString(rc) && keyIDRe.MatchString(kid) && err == nil {
					info.asOf = asOf
					folds = append(folds, fold{kind: "key", id: keyRevKey(rc, kid), info: info})
				}
			}
		}
		x.mu.Lock()
		x.initLocked()
		for _, f := range folds {
			switch f.kind {
			case "delivery":
				if _, ok := x.deliveries[f.id]; !ok { // the first revocation stands
					x.deliveries[f.id] = f.info
				}
			case "key":
				if _, ok := x.keys[f.id]; !ok {
					x.keys[f.id] = f.info
				}
			case "first":
				if old, ok := x.firstDelivery[f.id]; !ok || f.t.Before(old) {
					x.firstDelivery[f.id] = f.t
				}
			case "receipt":
				x.keyReceipts[f.id] = append(x.keyReceipts[f.id], recordedReceipt{recorded: f.t, signed: f.u})
			}
		}
		x.next = next
		last := len(recs) < revokePageSize
		if last {
			markWarm()
		}
		x.mu.Unlock()
		if last {
			return nil
		}
	}
}

// startWarm reads the revocation index and the receipt index in the background, until both are warm or the server stops. A failed read
// is retried a second later and resumes where it stopped.
func (s *Server) startWarm() {
	go func() {
		for s.life.Err() == nil {
			ok := true
			for _, step := range []struct {
				what string
				fn   func(context.Context) error
			}{{"revocation", s.warmRevocations}, {"receipt", s.warmReceipts}} {
				if err := step.fn(s.life); err != nil {
					s.warmFails.Add(1)
					ok = false
					// A core that cannot read its indexes refuses the packet routes (503) while staying ready: say so loudly once it has gone on for a minute.
					if time.Since(s.warmSince) > time.Minute {
						s.log.Error("the "+step.what+" index has not been read for over a minute: credentialed and revoke routes answer 503", "error", err.Error(), "failed_attempts", s.warmFails.Load())
					} else {
						s.log.Warn("reading the "+step.what+" index failed; trying again", "error", err.Error())
					}
				}
			}
			if ok {
				return
			}
			select {
			case <-s.life.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
}

func (s *Server) warmRevocations(ctx context.Context) error {
	x := &s.rev
	if err := x.refreshMu.Lock(ctx); err != nil {
		return err
	}
	defer x.refreshMu.Unlock()
	x.mu.RLock()
	done := x.warmed
	x.mu.RUnlock()
	if done {
		return nil
	}
	return s.refreshRevocations(ctx)
}

// waitWarm waits for the revocation index (and, when receipts is set, the receipt index) to be read, for at most warmGrace and the
// request's context; errRevCold otherwise.
func (s *Server) waitWarm(ctx context.Context, receipts bool) error {
	t := time.NewTimer(warmGrace)
	defer t.Stop()
	for _, ch := range []chan struct{}{s.rev.warmChan(), s.receiptWarm()} {
		if ch == s.receiptWarm() && !receipts {
			continue
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return errRevCold
		case <-t.C:
			return errRevCold
		}
	}
	return nil
}

// freshRevocations makes the index no older than revMaxAge, reading the chain's tail when it is. An error means the state
// could not be read: the caller refuses the request.
func (s *Server) freshRevocations(ctx context.Context) error {
	x := &s.rev
	if err := s.waitWarm(ctx, false); err != nil {
		return err
	}
	x.mu.RLock()
	age := s.opt.Clock().Sub(x.synced)
	ok := x.warmed && age >= 0 && age < revMaxAge
	x.mu.RUnlock()
	if ok {
		return nil
	}
	if err := x.refreshMu.Lock(ctx); err != nil {
		return err
	}
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

// revocationUnreadable is what a request answers when the revocation state could not be read, or is not read yet.
func (s *Server) revocationUnreadable(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errRevCold) {
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusServiceUnavailable, "the revocation state is not read yet, so nothing was served: try again shortly")
		return
	}
	s.log.ErrorContext(r.Context(), "revocation: the state could not be read", "error", err.Error())
	writeError(w, http.StatusServiceUnavailable, "the revocation state could not be read, so nothing was served")
}

// gateBusy is what a request answers when it could not take the revocation gate before its own context ended.
func (s *Server) gateBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusServiceUnavailable, "the core is busy recording another request: try again")
}

// RevokeRequest is the body of the delivery and token-key revoke routes: why.
type RevokeRequest struct {
	// Reason is recorded in the chain (1 to 200 printable characters: no control, format or separator characters). Do not put a secret
	// in it: it is carried in packets.
	Reason string `json:"reason" contract:"required"`
}

// RecipientKeyRevokeRequest is POST /v1/assurance/recipients/{recipient}/keys/{kid}/revoke's body.
type RecipientKeyRevokeRequest struct {
	Reason string `json:"reason" contract:"required"`
	// AsOf is the time from which the key is not trusted (RFC 3339): a receipt the core recorded at or after it, or signed at or after it
	// where no record is carried, fails `clearance verify`. Default now. It may be at most the core's clock-skew allowance (5 minutes)
	// ahead of the core's clock, never earlier than the first delivery the core recorded to the recipient (422), and more than 24 hours
	// back only with backdate: true.
	AsOf string `json:"as_of,omitempty"`
	// Backdate says the caller means an as_of more than 24 hours before now. Without it that as_of is refused (409), and the refusal says
	// how many receipts already recorded would fail.
	Backdate bool `json:"backdate,omitempty"`
}

// BackdateRefusal is the 409 of an as_of more than 24 hours back sent without backdate: true.
type BackdateRefusal struct {
	Error string `json:"error" contract:"required"`
	Rule  string `json:"rule,omitempty"`
	// AffectedReceipts is how many receipts the core already recorded with this key that would fail verification with this as_of.
	AffectedReceipts int `json:"affected_receipts" contract:"required"`
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
	// AsOf is the time the key is revoked as of; RevokedAt is when the core recorded the revocation (its own clock).
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
	// Statements are the ids of the verification statements that stand (not revoked, not superseded) and were signed by this key. A revoked
	// key is revoked for statements too: each now verifies as failed ("signing key revoked"), and the admin revokes it
	// (POST /v1/statements/{id}/revoke) and issues it again (reissue) under the key in use.
	Statements []string `json:"statements" contract:"required"`
	// StatementsError is set, and Statements is empty, when the statement index could not be read: list them with GET /v1/statements?key=.
	StatementsError string `json:"statements_error,omitempty"`
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
	if !cleanTextStrict(reason, MaxRevokeReason) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("reason is 1 to %d printable characters (no control, format or separator characters)", MaxRevokeReason))
		return true
	}
	return false
}

// MaxRevokeBody caps the revoke routes' bodies.
const MaxRevokeBody = 4 << 10

// freshRevocationsLocked is freshRevocations for a caller that already holds the gate for writing: it always reads the chain's
// tail (a revoke decides on what the chain holds now, never on a cache).
func (s *Server) freshRevocationsLocked(ctx context.Context) error {
	x := &s.rev
	if err := s.waitWarm(ctx, false); err != nil {
		return err
	}
	if err := x.refreshMu.Lock(ctx); err != nil {
		return err
	}
	defer x.refreshMu.Unlock()
	return s.refreshRevocations(ctx)
}

// commitGate is taken by a read (or a sample, or a receipt) when its expensive work is done: it takes the gate for reading and, for a
// read under a credential, re-checks that the credential's key is still one the core accepts, so a key revoked since the first check is
// refused. ok is false when the answer has been written (503 busy, or the bare 401). release must be called, once the record is written.
func (s *Server) commitGate(w http.ResponseWriter, r *http.Request, credential bool) (release func(), ok bool) {
	rel, err := s.rev.gate.Read(r.Context())
	if err != nil {
		s.gateBusy(w)
		return nil, false
	}
	if credential {
		keys, err := s.accessKeys(r)
		if err != nil {
			rel()
			writeError(w, http.StatusServiceUnavailable, "the store could not be read")
			return nil, false
		}
		_, issuer, gerr := s.opt.Gate.Credentials()
		claims, perr := token.ParseAccess(bearer(r), keys)
		if gerr != nil || perr != nil || claims.Issuer != issuer {
			rel()
			writeError(w, http.StatusUnauthorized, "not a packet credential this core issued")
			return nil, false
		}
	}
	return rel, true
}

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
	if err := s.waitWarm(ctx, false); err != nil {
		s.revocationUnreadable(w, r, err)
		return
	}
	release, err := x.gate.Write(ctx)
	if err != nil {
		s.gateBusy(w)
		return
	}
	defer release()
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
	x.deliveries[did] = info // folded in before the gate is released: no later read in this process misses it
	x.mu.Unlock()
	writeJSON(w, http.StatusOK, DeliveryRevoked{ID: did, PacketID: id, Recipient: rcp, State: stateRevoked, Created: true,
		RevokedAt: info.at, Reason: info.reason, Seq: seq, Hash: info.hash})
}

// revokeRecipientKey is POST /v1/assurance/recipients/{recipient}/keys/{kid}/revoke: a key a recipient registered is revoked as
// of a time. From then a receipt signed with it is refused at submit; receipts already recorded stay, and `clearance verify` fails
// one the core recorded at or after the as-of time and prints the revocation on one recorded before it.
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
	if !decodeRevoke(w, r, &req, "{reason, as_of?, backdate?}") || badReason(w, req.Reason) {
		return
	}
	now := s.opt.Clock().UTC().Truncate(time.Second) // whole seconds at the door: the stored as_of, the affected count and the verifier use one instant
	asOf := now
	if req.AsOf != "" {
		t, err := time.Parse(time.RFC3339, req.AsOf)
		if err != nil {
			writeError(w, http.StatusBadRequest, "as_of is an RFC 3339 time")
			return
		}
		if t.After(now.Add(DefaultMaxClockSkew)) {
			writeError(w, http.StatusBadRequest, "as_of is more than the clock-skew allowance ("+DefaultMaxClockSkew.String()+") ahead of the core's clock: a revocation takes effect now or earlier")
			return
		}
		asOf = t.UTC().Truncate(time.Second)
	}
	ctx := r.Context()
	x := &s.rev
	if err := s.waitWarm(ctx, false); err != nil {
		s.revocationUnreadable(w, r, err)
		return
	}
	release, err := x.gate.Write(ctx)
	if err != nil {
		s.gateBusy(w)
		return
	}
	defer release()
	if err := s.freshRevocationsLocked(ctx); err != nil {
		s.revocationUnreadable(w, r, err)
		return
	}
	k := keyRevKey(name, kid)
	w.Header().Set("Cache-Control", "no-store")
	x.mu.RLock()
	have, revoked := x.keys[k]
	first, hasFirst := x.firstDelivery[name]
	affected := 0
	for _, rr := range x.keyReceipts[k] {
		if !rr.recorded.Before(asOf) { // the verifier judges a carried receipt by the core's record time
			affected++
		}
	}
	x.mu.RUnlock()
	if revoked {
		writeJSON(w, http.StatusOK, RecipientKeyRevoked{Recipient: name, KeyID: kid, State: stateRevoked, Created: false, AsOf: have.asOf,
			RevokedAt: have.at, Reason: have.reason, Seq: have.seq, Hash: have.hash})
		return
	}
	// The bounds on a back-dated as-of: more than a day back only when asked, and never before the core recorded the first delivery to this
	// recipient (the core does not record when a key was registered: until a delivery, no credential of the recipient's existed).
	backdated := asOf.Before(now.Add(-BackdateAfter)) // compared in whole seconds
	if !hasFirst && backdated {
		writeJSON(w, http.StatusUnprocessableEntity, PacketError{Error: "the core has recorded no delivery to " + name + ": no receipt can exist, so there is nothing to back-date (an as_of within 24 hours is accepted)"})
		return
	}
	if backdated && !req.Backdate {
		writeJSON(w, http.StatusConflict, BackdateRefusal{Error: "as_of is more than " + BackdateAfter.String() + " before now: send backdate: true to mean it. " +
			strconv.Itoa(affected) + " receipt(s) already recorded with this key would fail verification", Rule: "PK-BACKDATE", AffectedReceipts: affected})
		return
	}
	if hasFirst && asOf.Before(first.Truncate(time.Second)) {
		writeJSON(w, http.StatusUnprocessableEntity, PacketError{Error: "as_of is before the first delivery the core recorded to " + name + " (" + pycompat.ISO(first) + "): the key cannot have been used through this core before then"})
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
			"revocation": map[string]any{"kind": "recipient-key", "recipient": name, "key_id": kid, "as_of": pycompat.ISO(asOf),
				"recorded_at": pycompat.ISO(now), "backdated": backdated, "reason": req.Reason}},
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
// and the core re-signs them with the key in use (it does so at once here, and its minute loop does it anyway). A verification statement
// it signed verifies as failed, and its key is no longer published as a statement key: the answer lists the statements that stood.
// The key in use cannot be revoked (409: rotate first), and a revoked key is never used again (the core refuses to start with it).
// The record and the key's flag commit together.
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
	release, err := x.gate.Write(ctx) // in-flight reads under a credential finish (and are recorded) first; later ones read the key table without the key
	if err != nil {
		s.gateBusy(w)
		return
	}
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
	release()
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
	s.markStatementKeyRevoked(kid)
	out := TokenKeyRevoked{KeyID: kid, State: stateRevoked, Created: rec != nil, Statements: []string{}}
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
	if ids, err := s.standingStatementsOf(ctx, kid); err != nil {
		s.log.WarnContext(ctx, "revocation: listing the statements of a revoked key failed", "key", kid, "error", err.Error())
		out.StatementsError = "the statement index could not be read: list them with GET /v1/statements?key=" + kid
	} else {
		out.Statements = ids
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}
