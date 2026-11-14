// Package receipt is the signed acceptance receipt (P-1): what an assurance recipient (an audit firm, a GRC hub, a
// customer's reviewer) signs, with a key it registered, to say what it made of a packet it was given.
//
// A receipt is a DSSE envelope (the signing path the clearance token, the grant feed and the change attestation
// share) over a small canonical JSON payload. It binds the packet (its id, which is the content address of the packet's
// manifest, and the manifest's digest), the engagement, the framework and mapping versions the recipient reviewed
// against and the ledger checkpoint the packet stood on, and carries the verdict and the notes the recipient wrote, keyed
// to the mapping's assertion ids.
//
// The package is small on purpose: the offline verifier (internal/verify) imports it, so it holds no store, no
// network and no clock.
package receipt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/token"
)

// Type is the payload's _type; PayloadType its DSSE payloadType.
const (
	Type        = "clearance.acceptance-receipt/v1"
	PayloadType = "application/vnd.clearance.acceptance-receipt.v1+json"
)

// The verdicts a recipient may give, in the order they are listed.
const (
	Accepted          = "accepted"
	AcceptedWithNotes = "accepted-with-notes"
	Questioned        = "questioned"
	Rejected          = "rejected"
)

// Verdicts are the four verdicts.
var Verdicts = []string{Accepted, AcceptedWithNotes, Questioned, Rejected}

// Limits.
const (
	MaxEnvelopeBytes = 256 << 10
	MaxNotes         = 500
	MaxNoteBytes     = 2000
	MaxEngagement    = 200
	MaxMappings      = 16
)

var (
	packetIDRx  = regexp.MustCompile(`^pk-[0-9a-f]{32}$`)
	deliveryRx  = regexp.MustCompile(`^dl-[0-9]{1,18}$`)
	recipientRx = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	digestRx    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	mappingRx   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}/[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
	controlRx   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
)

// ErrInvalid is a receipt whose payload breaks a rule; the message says which.
var ErrInvalid = errors.New("receipt: invalid")

// Checkpoint is the ledger checkpoint a packet stood on: the log's origin, tree size and root.
type Checkpoint struct {
	Origin string `json:"origin"`
	Size   int64  `json:"size"`
	Root   string `json:"root"`
}

// Payload is what the recipient signs.
type Payload struct {
	Type string `json:"_type"`
	// PacketID and PacketDigest name the packet: the id is derived from the digest, and the digest is the SHA-256 of
	// the packet's MANIFEST.json, which lists the SHA-256 of every other file.
	PacketID     string `json:"packet_id"`
	PacketDigest string `json:"packet_digest"`
	// Delivery is the subscriber's grant this receipt answers (dl-<seq of the packet.deliver record>).
	Delivery  string `json:"delivery"`
	Recipient string `json:"recipient"`
	// Engagement is the recipient's own label for the review (an audit engagement, a questionnaire, a ticket).
	Engagement string `json:"engagement"`
	// Mappings are the framework and mapping versions the packet carried and the recipient reviewed against.
	Mappings []string `json:"framework_mapping_versions"`
	// Checkpoint is the ledger checkpoint the packet carried; null when the packet had none.
	Checkpoint *Checkpoint `json:"checkpoint"`
	Verdict    string      `json:"verdict"`
	// ControlNotes are the recipient's notes keyed to the mapping's assertion ids (the packet's control_assertions).
	ControlNotes map[string]string `json:"control_notes"`
	SignedAt     string            `json:"signed_at"`
}

// Check is what Sign and Verify require of the payload itself.
func (p *Payload) Check() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(f, a...)) }
	switch {
	case p.Type != Type:
		return bad("_type is %q", p.Type)
	case !packetIDRx.MatchString(p.PacketID):
		return bad("packet_id is pk- and 32 hex digits")
	case !digestRx.MatchString(p.PacketDigest):
		return bad("packet_digest is a SHA-256 in hex")
	case p.PacketID != "pk-"+p.PacketDigest[:32]:
		return bad("packet_id is not derived from packet_digest")
	case !deliveryRx.MatchString(p.Delivery):
		return bad("delivery is dl- and a record seq")
	case !recipientRx.MatchString(p.Recipient):
		return bad("recipient is a registered recipient's name")
	case p.Engagement == "" || utf8.RuneCountInString(p.Engagement) > MaxEngagement || !printable(p.Engagement):
		return bad("engagement is 1 to %d printable characters", MaxEngagement)
	case !slices.Contains(Verdicts, p.Verdict):
		return bad("verdict is one of %v", Verdicts)
	case len(p.Mappings) == 0 || len(p.Mappings) > MaxMappings:
		return bad("framework_mapping_versions names 1 to %d mappings", MaxMappings)
	case len(p.ControlNotes) > MaxNotes:
		return bad("at most %d control notes", MaxNotes)
	case p.Verdict == AcceptedWithNotes && len(p.ControlNotes) == 0:
		return bad("a verdict of %s carries at least one control note", AcceptedWithNotes)
	}
	for _, m := range p.Mappings {
		if !mappingRx.MatchString(m) {
			return bad("mapping %q is framework/version", m)
		}
	}
	if c := p.Checkpoint; c != nil && (c.Origin == "" || len(c.Origin) > 256 || c.Size < 0 || !digestRx.MatchString(c.Root)) {
		return bad("checkpoint is {origin, size, root (SHA-256 hex)} or null")
	}
	for k, v := range p.ControlNotes {
		if !controlRx.MatchString(k) {
			return bad("control note key %q is not a mapping assertion id", k)
		}
		if len(v) > MaxNoteBytes || v == "" || !utf8.ValidString(v) {
			return bad("the note for %q is 1 to %d bytes of UTF-8", k, MaxNoteBytes)
		}
	}
	if _, err := time.Parse(time.RFC3339, p.SignedAt); err != nil {
		return bad("signed_at is an RFC 3339 time")
	}
	return nil
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return utf8.ValidString(s)
}

// Sign makes the receipt: the payload (checked, with a non-nil notes object) as a DSSE envelope signed by s, the
// recipient's own key. It returns the envelope's JSON.
func Sign(ctx context.Context, s token.Signer, p Payload) ([]byte, error) {
	if p.Type == "" {
		p.Type = Type
	}
	if p.ControlNotes == nil {
		p.ControlNotes = map[string]string{}
	}
	if err := p.Check(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	env, err := token.SignDSSE(ctx, s, PayloadType, payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(env)
}

// Verified is a receipt whose signature held.
type Verified struct {
	Payload Payload
	// KeyID is the thumbprint of the key that signed it.
	KeyID string
	// PayloadSHA256 is the hex SHA-256 of the signed payload bytes: the receipt's content address.
	PayloadSHA256 string
}

// Verify checks the envelope raw against keys and returns the receipt. The payload is decoded strictly and checked;
// the keys are whatever the caller trusts for the recipient (the core's registration; a verifier's own file).
func Verify(raw []byte, keys token.KeySet) (*Verified, error) {
	if len(raw) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: over %d bytes", token.ErrMalformed, MaxEnvelopeBytes)
	}
	payload, kid, err := token.VerifyDSSE(raw, PayloadType, keys)
	if err != nil {
		return nil, err
	}
	p, err := parse(payload)
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256(payload)
	return &Verified{Payload: *p, KeyID: kid, PayloadSHA256: hex.EncodeToString(d[:])}, nil
}

// Read decodes the envelope's payload WITHOUT checking any signature, so a caller can see whom a receipt names (to
// choose the keys to verify it with). Never act on what it returns without Verify.
func Read(raw []byte) (*Payload, error) {
	if len(raw) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: over %d bytes", token.ErrMalformed, MaxEnvelopeBytes)
	}
	var env token.Envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.PayloadType != PayloadType {
		return nil, fmt.Errorf("%w: not an acceptance receipt envelope", token.ErrMalformed)
	}
	b, err := decode(env.Payload)
	if err != nil {
		return nil, err
	}
	return parse(b)
}

func parse(payload []byte) (*Payload, error) {
	var p Payload
	dec := json.NewDecoder(bytesReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", token.ErrMalformed, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the payload", token.ErrMalformed)
	}
	if err := p.Check(); err != nil {
		return nil, err
	}
	return &p, nil
}
