package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/receipt"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
	"github.com/jfillman/clearance/internal/vocab"
)

// Assurance providers and the packet routes (P-1). A subscriber publishes an evidence packet to the core
// (POST /v1/packets), opens it to a registered recipient for a window (POST /v1/packets/{id}/deliveries, which mints a
// time-boxed credential), the recipient reads it under that credential (GET /v1/packets/{id}) and signs a receipt with
// its own key (POST /v1/packets/{id}/receipts). Every step is a record in the chain; none needs a Clearance account
// for the recipient. Clearance never submits a packet on anyone's behalf and never pays a recipient: the subscriber
// names the recipient, and the core records that it did.

// Record kinds the packet routes write (the receipt's is packet.ToolReceipt).
const (
	ToolPacketPublish = "packet.publish"
	ToolPacketDeliver = "packet.deliver"
	ToolPacketFetch   = "packet.fetch"
)

// How the recipient routes authenticate (the bearer-token middleware does not).
const (
	// AuthCredential is a packet access credential in the bearer header (token.AccessClaims), signed by the core.
	AuthCredential = "packet-credential"
	// AuthRecipientKey is a receipt signed by a key the recipient registered: the signature is the authentication.
	AuthRecipientKey = "recipient-signature"
)

// The refusal rules of a packet read, in the record's `rule` and the answer's.
const (
	RulePacketScope     = "PK-SCOPE"     // the credential opens another packet, or not this part
	RulePacketExpired   = "PK-EXPIRED"   // past the delivery's window
	RulePacketNotYet    = "PK-NOT-YET"   // before the delivery's window
	RulePacketRecipient = "PK-RECIPIENT" // the recipient is no longer registered
	RulePacketGone      = "PK-GONE"      // the packet is not held (or is not the one the credential names)
)

// Route bodies and caps.
const (
	MaxPacketBody   = packet.MaxBundleBytes + 4096
	MaxDeliveryBody = 8 << 10
	// MaxDeliveryWindow is the longest a credential lives (token.MaxAccessLifetime), MinDeliveryWindow the shortest.
	MaxDeliveryWindow = token.MaxAccessLifetime
	MinDeliveryWindow = time.Minute
	// maxRefusalRecords is how many refusals of one delivery are recorded in an hour: past it the refusal is still
	// answered, and counted, but no longer written (a leaked credential must not be a way to fill the chain).
	maxRefusalRecords = 60
)

// PacketBundle is a packet as the core keeps and serves it: the packet directory as one JSON document, the files
// exactly as the packet job wrote them (base64). `clearance receipt pull` unpacks it; the SHA-256 of the manifest
// file is the packet's digest.
type PacketBundle struct {
	Schema string            `json:"schema"`
	Files  map[string]string `json:"files"`
}

// PacketPublished is POST /v1/packets's answer.
type PacketPublished struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	// Created is false when the core already held this packet (its id is its content's address): nothing was recorded.
	Created bool        `json:"created"`
	Seq     *int64      `json:"seq"`
	Packet  packet.Meta `json:"packet"`
	Hash    string      `json:"hash,omitempty"`
	Links   PacketLinks `json:"links"`
}

// PacketLinks are the paths of a packet's routes.
type PacketLinks struct {
	Deliveries string `json:"deliveries"`
	Fetch      string `json:"fetch"`
}

// DeliveryWindow is the time a credential is good: from (default now) to (required, within 30 days of from).
type DeliveryWindow struct {
	From string `json:"from,omitempty"`
	To   string `json:"to" contract:"required"`
}

// DeliveryRequest is POST /v1/packets/{id}/deliveries's body.
type DeliveryRequest struct {
	// Recipient is a registered assurance provider (CLEARANCE_PROVIDERS, class assurance).
	Recipient string `json:"recipient" contract:"required"`
	// Scope is the parts of the packet the recipient may read: summary, evidence. Default: both.
	Scope  []string       `json:"scope,omitempty"`
	Window DeliveryWindow `json:"window" contract:"required"`
	// Engagement, when set, is the engagement the receipt must name: a subscriber who opened a packet for one audit
	// engagement does not accept a receipt for another.
	Engagement string `json:"engagement,omitempty"`
}

// Delivery is what the subscriber got back: the record of the grant and, once, the credential.
type Delivery struct {
	ID         string         `json:"id"`
	PacketID   string         `json:"packet_id"`
	Recipient  string         `json:"recipient"`
	Scope      []string       `json:"scope"`
	Window     DeliveryWindow `json:"window"`
	Engagement string         `json:"engagement,omitempty"`
	Seq        int64          `json:"seq"`
	Hash       string         `json:"hash"`
	// Credential is the bearer credential the recipient presents to GET /v1/packets/{id}. It is returned here and
	// nowhere else: the core keeps the record of the delivery, not the secret. Hand it to the recipient over a channel
	// you trust; a second delivery is a second credential.
	Credential string `json:"credential"`
	Fetch      string `json:"fetch"`
}

// ReceiptRecorded is POST /v1/packets/{id}/receipts's answer.
type ReceiptRecorded struct {
	Seq           int64  `json:"seq"`
	Hash          string `json:"hash"`
	PacketID      string `json:"packet_id"`
	Recipient     string `json:"recipient"`
	Verdict       string `json:"verdict"`
	PayloadSHA256 string `json:"payload_sha256"`
}

// packetErrorBody is a packet route's refusal: the usual error and, for a refused read, the rule.
type PacketError struct {
	Error string `json:"error"`
	Rule  string `json:"rule,omitempty"`
}

var packetVerified = union(evidence.ProviderVerified, "ts", "tool", "decision", "rule", "target", "principal", "initiator", "args_sha256",
	"result", "packet", "delivery", "receipt", "fetch", "delegate", "task_id", "session", "parent", "agent", "tier")

// refusals counts the refusals recorded per delivery in the hour (maxRefusalRecords).
type refusals struct {
	mu sync.Mutex
	by map[string]refusalCount
}

type refusalCount struct {
	hour int64
	n    int
}

// allow says whether a refusal of this delivery may be recorded now, and counts it.
func (r *refusals) allow(delivery string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.by == nil || len(r.by) > 10000 {
		r.by = map[string]refusalCount{}
	}
	h := now.Unix() / 3600
	c := r.by[delivery]
	if c.hour != h {
		c = refusalCount{hour: h}
	}
	c.n++
	r.by[delivery] = c
	return c.n <= maxRefusalRecords
}

func packetPath(id string) string { return "/v1/packets/" + id }

func gateFail(w http.ResponseWriter, err error) bool {
	var ge *gate.Error
	if errors.As(err, &ge) {
		writeJSON(w, ge.Status, gate.ErrorBody{Error: ge.Message, Rule: ge.Rule, Hint: ge.Hint})
		return true
	}
	return false
}

// subscriber is the admin behind the request, or a written refusal.
func (s *Server) subscriber(w http.ResponseWriter, r *http.Request) (gate.Subscriber, bool) {
	g := s.opt.Gate
	if g == nil {
		writeError(w, http.StatusNotFound, "this core keeps no packets")
		return gate.Subscriber{}, false
	}
	p, ok := authn.From(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "a bearer token is required")
		return gate.Subscriber{}, false
	}
	sub, err := g.Subscriber(r.Context(), p, r.Header.Get(vocab.Get().OnBehalfOfHeader))
	if err != nil {
		if !gateFail(w, err) {
			s.log.ErrorContext(r.Context(), "packet: subscriber check failed", "error", err.Error())
			writeError(w, http.StatusServiceUnavailable, "the request could not be checked")
		}
		return gate.Subscriber{}, false
	}
	return sub, true
}

func initiator(sub gate.Subscriber) map[string]any {
	return map[string]any{"sub": sub.Sub, "iss": sub.Iss}
}

func viaString(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}

// readBody reads the whole body within the route's cap.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
		} else {
			writeError(w, http.StatusBadRequest, "the body could not be read")
		}
		return nil, false
	}
	if int64(len(raw)) > limit {
		writeError(w, http.StatusRequestEntityTooLarge, "body too large")
		return nil, false
	}
	return raw, true
}

func cleanText(v string, max int) bool {
	if v == "" || utf8.RuneCountInString(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// publishPacket is POST /v1/packets: an admin publishes the packet `clearance packet` wrote, as a bundle. The core
// checks the bundle is the packet its manifest says (every file, every SHA-256), that it was read from this chain
// (its head is the hash the core holds at that count), keeps it and records the publication. The same packet again is
// the same id and records nothing: the id is the content's address.
func (s *Server) publishPacket(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.subscriber(w, r)
	if !ok {
		return
	}
	raw, ok := readBody(w, r, MaxPacketBody)
	if !ok {
		return
	}
	b, err := packet.ParseBundle(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	if n := b.Meta.ChainCount; n < 1 {
		writeError(w, http.StatusBadRequest, "the packet names no chain: it was read from an empty one")
		return
	} else if recs, err := s.opt.Store.Records(ctx, n-1, 1); err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	} else if len(recs) == 0 || fmt.Sprint(recs[0]["hash"]) != b.Meta.ChainHead {
		writeError(w, http.StatusConflict, "this packet was not read from this chain: record "+strconv.FormatInt(n-1, 10)+" is not the head the packet names")
		return
	}
	out := PacketPublished{ID: b.ID, Digest: b.Digest, Size: int64(len(b.JSON)), Packet: b.Meta,
		Links: PacketLinks{Deliveries: packetPath(b.ID) + "/deliveries", Fetch: packetPath(b.ID)}}
	err = s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		if _, err := tx.Packet(ctx, b.ID); err == nil {
			return nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		meta, err := json.Marshal(b.Meta)
		if err != nil {
			return err
		}
		if err := tx.PutPacket(ctx, store.Packet{ID: b.ID, Digest: b.Digest, Meta: meta, Bundle: b.JSON}); err != nil {
			return err
		}
		pk := map[string]any{"id": b.ID, "digest": b.Digest, "size": json.Number(strconv.Itoa(len(b.JSON))), "view": b.Meta.View,
			"from": b.Meta.From, "to": b.Meta.To, "mappings": toAny(b.Meta.Mappings),
			"chain": map[string]any{"count": json.Number(strconv.FormatInt(b.Meta.ChainCount, 10)), "head": b.Meta.ChainHead}}
		if b.Meta.Title != "" {
			pk["title"] = b.Meta.Title
		}
		if c := b.Meta.Checkpoint; c != nil {
			pk["checkpoint"] = map[string]any{"origin": c.Origin, "size": json.Number(strconv.FormatInt(c.Size, 10)), "root": c.Root}
		}
		rec, err := tx.Append(ctx, store.Event{"ts": pycompat.ISO(s.opt.Clock()), "task_id": nil, "session": nil, "parent": nil,
			"principal": sub.Person, "agent": nil, "tool": ToolPacketPublish, "tier": nil, "decision": "allow", "rule": nil,
			"target": "packet:" + b.ID, "args_sha256": b.Digest, "boundary": "deployment",
			"result":    fmt.Sprintf("packet %s published (%s, %s to %s)", b.ID, b.Meta.View, b.Meta.From, b.Meta.To),
			"initiator": initiator(sub), "delegate": viaString(sub.Via), "packet": pk}, s.coreWriter(packetVerified))
		if err != nil {
			return err
		}
		seq, _ := gate.SeqInt(rec["seq"])
		out.Created, out.Seq, out.Hash = true, &seq, fmt.Sprint(rec["hash"])
		return nil
	})
	if err != nil {
		s.log.ErrorContext(ctx, "packet: publishing failed", "packet", b.ID, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the packet could not be recorded")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// deliverPacket is POST /v1/packets/{id}/deliveries: an admin opens one packet to one registered recipient for a window,
// scoped to parts of it. The delivery is the record (packet.deliver); the answer carries the credential, once.
func (s *Server) deliverPacket(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.subscriber(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !packet.ValidID(id) {
		writeError(w, http.StatusNotFound, "no such packet")
		return
	}
	raw, ok := readBody(w, r, MaxDeliveryBody)
	if !ok {
		return
	}
	var req DeliveryRequest
	if err := strictDecode(bytes.NewReader(raw), &req); err != nil {
		writeError(w, http.StatusBadRequest, "the body is {recipient, scope?, window: {from?, to}, engagement?}: "+err.Error())
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
	rcp := recipient(s.opt.Providers, req.Recipient)
	if rcp == nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("%q is not a registered assurance provider (CLEARANCE_PROVIDERS, class %s)", req.Recipient, ClassAssurance))
		return
	}
	scope := req.Scope
	if len(scope) == 0 {
		scope = slices.Clone(packet.Parts)
	}
	slices.Sort(scope)
	scope = slices.Compact(scope)
	for _, p := range scope {
		if !slices.Contains(packet.Parts, p) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("scope is parts of a packet: %v", packet.Parts))
			return
		}
	}
	if req.Engagement != "" && !cleanText(req.Engagement, receipt.MaxEngagement) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("engagement is 1 to %d printable characters", receipt.MaxEngagement))
		return
	}
	now := s.opt.Clock().UTC().Truncate(time.Second)
	from, err := time.Parse(time.RFC3339, orString(req.Window.From, pycompat.ISO(now)))
	to, err2 := time.Parse(time.RFC3339, req.Window.To)
	switch {
	case err != nil || err2 != nil:
		writeError(w, http.StatusBadRequest, "window.from and window.to are RFC 3339 times")
		return
	case !to.After(now):
		writeError(w, http.StatusBadRequest, "window.to is in the past: the credential would never be good")
		return
	case to.Sub(from) < MinDeliveryWindow || to.Sub(from) > MaxDeliveryWindow:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("a window is %s to %s long", MinDeliveryWindow, MaxDeliveryWindow))
		return
	}
	from, to = from.UTC().Truncate(time.Second), to.UTC().Truncate(time.Second)
	var out Delivery
	err = s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		pk, err := tx.Packet(ctx, id)
		if err != nil {
			return err
		}
		dl := map[string]any{"recipient": req.Recipient, "scope": toAny(scope), "from": pycompat.ISO(from), "to": pycompat.ISO(to)}
		if req.Engagement != "" {
			dl["engagement"] = req.Engagement
		}
		rec, err := tx.Append(ctx, store.Event{"ts": pycompat.ISO(now), "task_id": nil, "session": nil, "parent": nil,
			"principal": sub.Person, "agent": nil, "tool": ToolPacketDeliver, "tier": nil, "decision": "allow", "rule": nil,
			"target": "packet:" + id, "args_sha256": pk.Digest, "boundary": "deployment",
			"result": fmt.Sprintf("packet %s opened to %s until %s", id, req.Recipient, pycompat.ISO(to)), "initiator": initiator(sub),
			"delegate": viaString(sub.Via), "packet": map[string]any{"id": id, "digest": pk.Digest}, "delivery": dl}, s.coreWriter(packetVerified))
		if err != nil {
			return err
		}
		seq, _ := gate.SeqInt(rec["seq"])
		did := "dl-" + strconv.FormatInt(seq, 10)
		cred, err := token.IssueAccess(ctx, signer, token.AccessClaims{Type: token.AccessType, Issuer: issuer, Audience: token.AccessAudience, Subject: did, Packet: id,
			Digest: pk.Digest, Recipient: req.Recipient, Scope: scope, IssuedAt: now.Unix(), NotBefore: from.Unix(), Expires: to.Unix()})
		if err != nil {
			return err
		}
		out = Delivery{ID: did, PacketID: id, Recipient: req.Recipient, Scope: scope, Window: DeliveryWindow{From: pycompat.ISO(from), To: pycompat.ISO(to)},
			Engagement: req.Engagement, Seq: seq, Hash: fmt.Sprint(rec["hash"]), Credential: cred, Fetch: packetPath(id)}
		return nil
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such packet: publish it first (POST /v1/packets)")
		return
	case err != nil:
		s.log.ErrorContext(ctx, "packet: the delivery could not be recorded", "packet", id, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the delivery could not be recorded")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func orString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// accessKeys is the key set packet credentials verify against: the clearance token keys (GET /v1/keys).
func (s *Server) accessKeys(r *http.Request) (token.KeySet, error) {
	rows, err := s.opt.Store.SigningKeys(r.Context(), s.opt.Clock().Add(-KeysWindow-token.MaxAccessLifetime))
	if err != nil {
		return nil, err
	}
	ks := token.KeySet{}
	for _, k := range rows {
		var j token.JWK
		if json.Unmarshal(k.JWK, &j) != nil {
			continue
		}
		if pub, err := j.Public(); err == nil {
			ks[j.Kid] = pub
		}
	}
	return ks, nil
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// getPacket is GET /v1/packets/{id}: the recipient reads the packet under the credential its delivery minted. The
// credential is checked for its signature first (something the core did not sign is a bare 401 and nothing is
// recorded: the caller is nobody). From there every answer is a record, written before the answer: an allowed read
// (packet.fetch, decision allow) is recorded before a byte is served, and a refusal (expired, not yet good, another
// packet, a part outside its scope) is recorded with the rule that refused it.
func (s *Server) getPacket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	for k, vs := range q {
		if k != "part" || len(vs) != 1 {
			writeError(w, http.StatusBadRequest, "the only query parameter is part (once): "+strings.Join(packet.Parts, " or "))
			return
		}
	}
	part := q.Get("part")
	if part != "" && !slices.Contains(packet.Parts, part) {
		writeError(w, http.StatusBadRequest, "part is "+strings.Join(packet.Parts, " or "))
		return
	}
	cred := bearer(r)
	if cred == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="clearance-packet"`)
		writeError(w, http.StatusUnauthorized, "a packet credential is required (the one the delivery returned)")
		return
	}
	g := s.opt.Gate
	if g == nil {
		writeError(w, http.StatusNotFound, "this core keeps no packets")
		return
	}
	_, issuer, err := g.Credentials()
	if err != nil {
		if !gateFail(w, err) {
			writeError(w, http.StatusServiceUnavailable, "no signer")
		}
		return
	}
	keys, err := s.accessKeys(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	claims, err := token.ParseAccess(cred, keys)
	if err != nil || claims.Issuer != issuer {
		writeError(w, http.StatusUnauthorized, "not a packet credential this core issued")
		return
	}
	id := r.PathValue("id")
	now := s.opt.Clock()
	rule, msg, status := "", "", 0
	switch {
	case id != claims.Packet:
		rule, msg, status = RulePacketScope, "this credential opens packet "+claims.Packet+", not "+id, http.StatusForbidden
	case part != "" && !slices.Contains(claims.Scope, part):
		rule, msg, status = RulePacketScope, "this credential's scope is "+strings.Join(claims.Scope, ", ")+": it does not open the "+part+" part", http.StatusForbidden
	case now.Before(time.Unix(claims.NotBefore, 0)):
		rule, msg, status = RulePacketNotYet, "this credential is not good until "+pycompat.ISO(time.Unix(claims.NotBefore, 0)), http.StatusForbidden
	case !now.Before(time.Unix(claims.Expires, 0)):
		rule, msg, status = RulePacketExpired, "this credential expired at "+pycompat.ISO(time.Unix(claims.Expires, 0))+": ask the subscriber for a new delivery", http.StatusUnauthorized
	case recipient(s.opt.Providers, claims.Recipient) == nil:
		rule, msg, status = RulePacketRecipient, claims.Recipient+" is no longer a registered recipient", http.StatusForbidden
	}
	var pk store.Packet
	if rule == "" {
		pk, err = s.opt.Store.Packet(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound) || (err == nil && pk.Digest != claims.Digest):
			rule, msg, status = RulePacketGone, "the core does not hold the packet this credential names", http.StatusNotFound
		case err != nil:
			writeError(w, http.StatusServiceUnavailable, "the store could not be read")
			return
		}
	}
	if rule != "" {
		s.refusePacketRead(w, r, claims, id, part, rule, msg, status, now)
		return
	}
	b, err := packet.LoadBundle(pk.Bundle)
	if err != nil {
		s.log.ErrorContext(ctx, "packet: the stored bundle is unreadable", "packet", id, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the stored packet could not be read")
		return
	}
	scope := claims.Scope
	if part != "" {
		scope = []string{part}
	}
	body, err := b.Restrict(scope)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the stored packet could not be read")
		return
	}
	// Recorded before a byte is served: a read that could not be recorded is not made.
	err = s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		_, err := tx.Append(ctx, s.fetchEvent(claims, id, part, scope, "allow", "", fmt.Sprintf("packet %s read by %s (%s, %d bytes)", id, claims.Recipient, strings.Join(scope, "+"), len(body)), now, len(body)), s.coreWriter(packetVerified))
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "packet: the read could not be recorded", "packet", id, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the read could not be recorded, so it was not served")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Clearance-Packet-Digest", pk.Digest)
	w.Header().Set("X-Clearance-Packet-Scope", strings.Join(scope, ","))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) fetchEvent(c *token.AccessClaims, id, part string, scope []string, decision, rule, result string, now time.Time, n int) store.Event {
	fetch := map[string]any{"scope": toAny(scope), "bytes": json.Number(strconv.Itoa(n))}
	if part != "" {
		fetch["part"] = part
	}
	var ru any
	if rule != "" {
		ru = rule
	}
	return store.Event{"ts": pycompat.ISO(now), "task_id": nil, "session": nil, "parent": nil, "principal": "recipient:" + c.Recipient,
		"agent": nil, "tool": ToolPacketFetch, "tier": nil, "decision": decision, "rule": ru, "target": "packet:" + id,
		"args_sha256": c.Digest, "boundary": "deployment", "result": result,
		"packet": map[string]any{"id": id}, "delivery": map[string]any{"id": c.Subject, "recipient": c.Recipient, "packet": c.Packet}, "fetch": fetch}
}

// refusePacketRead records a refusal of a credential the core signed, then answers it. The record carries the rule;
// the answer does too. A flood of refusals of one delivery is recorded up to maxRefusalRecords an hour.
func (s *Server) refusePacketRead(w http.ResponseWriter, r *http.Request, c *token.AccessClaims, id, part, rule, msg string, status int, now time.Time) {
	ctx := r.Context()
	if !s.refused.allow(c.Subject, now) {
		w.Header().Set("Retry-After", "3600")
		writeJSON(w, http.StatusTooManyRequests, PacketError{Error: "this delivery has been refused " + strconv.Itoa(maxRefusalRecords) + " times this hour: " + msg, Rule: rule})
		return
	}
	err := s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		_, err := tx.Append(ctx, s.fetchEvent(c, id, part, c.Scope, "deny", rule, "refused: "+msg, now, 0), s.coreWriter(packetVerified))
		return err
	})
	if err != nil {
		// The refusal stands whether or not it could be written down; the read did not happen.
		s.log.ErrorContext(ctx, "packet: a refusal could not be recorded", "packet", id, "rule", rule, "error", err.Error())
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="clearance-packet", error="invalid_token"`)
	}
	writeJSON(w, status, PacketError{Error: msg, Rule: rule})
}

// acceptReceipt is POST /v1/packets/{id}/receipts: the recipient's acceptance receipt, a DSSE envelope signed with a
// key the recipient registered. The signature is the authentication (no bearer token, no credential: a firm signs
// offline and submits later). The core checks the key, the delivery the receipt answers, and that the receipt binds
// this packet's digest, mappings and checkpoint, and notes only rows the packet's mappings have; then it records it.
func (s *Server) acceptReceipt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	raw, ok := readBody(w, r, receipt.MaxEnvelopeBytes)
	if !ok {
		return
	}
	pl, err := receipt.Read(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "not an acceptance receipt: "+err.Error())
		return
	}
	id := r.PathValue("id")
	if pl.PacketID != id {
		writeError(w, http.StatusBadRequest, "the receipt is for packet "+pl.PacketID+", not "+id)
		return
	}
	rcp := recipient(s.opt.Providers, pl.Recipient)
	if rcp == nil {
		writeError(w, http.StatusForbidden, pl.Recipient+" is not a registered assurance provider")
		return
	}
	keys, err := rcp.RecipientKeys()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the recipient's keys could not be read")
		return
	}
	v, err := receipt.Verify(raw, keys)
	switch {
	case errors.Is(err, token.ErrUnknownKey) || errors.Is(err, token.ErrSignature):
		writeError(w, http.StatusForbidden, "the receipt is not signed by a key registered for "+pl.Recipient)
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, "not an acceptance receipt: "+err.Error())
		return
	}
	pk, err := s.opt.Store.Packet(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such packet")
		return
	} else if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	var meta packet.Meta
	if err := json.Unmarshal(pk.Meta, &meta); err != nil {
		writeError(w, http.StatusServiceUnavailable, "the stored packet could not be read")
		return
	}
	dseq, _ := strconv.ParseInt(strings.TrimPrefix(pl.Delivery, "dl-"), 10, 64)
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
	if dl == nil || dl["tool"] != ToolPacketDeliver || fmt.Sprint(dl["seq"]) != strconv.FormatInt(dseq, 10) ||
		fmt.Sprint(dp["id"]) != id || fmt.Sprint(d["recipient"]) != pl.Recipient {
		writeError(w, http.StatusBadRequest, pl.Delivery+" is not a delivery of this packet to "+pl.Recipient)
		return
	}
	if msg := checkReceiptBinding(pl, pk, meta, d, s.opt.Clock()); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	jwk, err := token.PublicJWK(keys[v.KeyID])
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the recipient's key could not be read")
		return
	}
	jraw, _ := json.Marshal(jwk)
	var jm, em any
	_ = json.Unmarshal(jraw, &jm)
	if err := json.Unmarshal(raw, &em); err != nil {
		writeError(w, http.StatusBadRequest, "the receipt is not JSON")
		return
	}
	var out ReceiptRecorded
	err = s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		rec, err := tx.Append(ctx, store.Event{"ts": pycompat.ISO(s.opt.Clock()), "task_id": nil, "session": nil, "parent": nil,
			"principal": "recipient:" + pl.Recipient, "agent": nil, "tool": packet.ToolReceipt, "tier": nil, "decision": "allow", "rule": nil,
			"target": "packet:" + id, "args_sha256": v.PayloadSHA256, "boundary": "deployment",
			"result": fmt.Sprintf("%s: acceptance receipt from %s for packet %s", pl.Verdict, pl.Recipient, id),
			"packet": map[string]any{"id": id, "digest": pk.Digest}, "delivery": map[string]any{"id": pl.Delivery, "recipient": pl.Recipient},
			"receipt": map[string]any{"verdict": pl.Verdict, "engagement": pl.Engagement, "payload_sha256": v.PayloadSHA256, "key_id": v.KeyID,
				"key": jm, "envelope": em}}, s.coreWriter(packetVerified))
		if err != nil {
			return err
		}
		seq, _ := gate.SeqInt(rec["seq"])
		out = ReceiptRecorded{Seq: seq, Hash: fmt.Sprint(rec["hash"]), PacketID: id, Recipient: pl.Recipient, Verdict: pl.Verdict, PayloadSHA256: v.PayloadSHA256}
		return nil
	})
	if err != nil {
		s.log.ErrorContext(ctx, "packet: the receipt could not be recorded", "packet", id, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the receipt could not be recorded")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// checkReceiptBinding says what is wrong with a receipt's claims about the packet and its delivery ("" when nothing).
func checkReceiptBinding(pl *receipt.Payload, pk store.Packet, meta packet.Meta, d map[string]any, now time.Time) string {
	if pl.PacketDigest != pk.Digest {
		return "the receipt's packet_digest is not this packet's digest"
	}
	if !slices.Equal(pl.Mappings, meta.Mappings) {
		return fmt.Sprintf("the receipt's framework_mapping_versions %v are not the packet's %v", pl.Mappings, meta.Mappings)
	}
	switch c := meta.Checkpoint; {
	case c == nil && pl.Checkpoint != nil:
		return "the packet stood on no ledger checkpoint, and the receipt names one"
	case c != nil && (pl.Checkpoint == nil || pl.Checkpoint.Origin != c.Origin || pl.Checkpoint.Size != c.Size || pl.Checkpoint.Root != c.Root):
		return "the receipt's checkpoint is not the checkpoint the packet stood on"
	}
	if e, _ := d["engagement"].(string); e != "" && e != pl.Engagement {
		return fmt.Sprintf("the delivery was opened for engagement %q, and the receipt is for %q", e, pl.Engagement)
	}
	for k := range pl.ControlNotes {
		if !slices.Contains(meta.Assertions, k) && !slices.Contains(meta.Controls, k) {
			return fmt.Sprintf("control note %q is not a row of the packet's mappings (a control id or an assertion id)", k)
		}
	}
	signed, _ := time.Parse(time.RFC3339, pl.SignedAt)
	if signed.After(now.Add(DefaultMaxClockSkew)) {
		return "the receipt is signed in the future"
	}
	if from, err := time.Parse(time.RFC3339, fmt.Sprint(d["from"])); err == nil && signed.Before(from.Add(-DefaultMaxClockSkew)) {
		return "the receipt was signed before the delivery's window began"
	}
	return ""
}
