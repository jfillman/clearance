// Package assurance is the recipient's side of the packet routes (P-1): what an assurance provider (an audit firm, a
// GRC hub, a customer's reviewer, or a lab's fake) does with the credential a subscriber gave it. It pulls the packet
// (GET /v1/packets/{id}), builds the acceptance receipt from the packet it was given, signs it with its own key and
// submits it (POST /v1/packets/{id}/receipts). `clearance receipt pull | sign | submit` are this package on a command
// line, for firms that have no system to sign from.
//
// It needs no Clearance account and no token of the authenticator's: the credential and the recipient's own key are
// everything. It never calls anything else of the core.
package assurance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/receipt"
	"github.com/jfillman/clearance/internal/sampling"
)

// Client reaches a core's packet routes.
type Client struct {
	// Base is the core's URL ("https://clearance.example"), without a trailing path.
	Base string
	HTTP *http.Client
	// UserAgent defaults to "clearance-recipient".
	UserAgent string
}

// Error is a refusal by the core: its status, message and, for a refused read, the rule (PK-EXPIRED, PK-SCOPE, ...).
type Error struct {
	Status        int
	Message, Rule string
}

func (e *Error) Error() string {
	if e.Rule != "" {
		return fmt.Sprintf("%d %s: %s", e.Status, e.Rule, e.Message)
	}
	return fmt.Sprintf("%d: %s", e.Status, e.Message)
}

// MaxResponse caps what a client reads of the core's answer.
const MaxResponse = packet.MaxBundleBytes + 1<<20

func (c *Client) do(ctx context.Context, method, path string, body []byte, credential string) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	ua := c.UserAgent
	if ua == "" {
		ua = "clearance-recipient"
	}
	req.Header.Set("User-Agent", ua)
	h := c.HTTP
	if h == nil {
		h = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxResponse {
		return nil, errors.New("assurance: the core's answer is over the cap")
	}
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error, Rule string }
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
			if len(e.Error) > 200 {
				e.Error = e.Error[:200]
			}
		}
		return nil, &Error{Status: resp.StatusCode, Message: e.Error, Rule: e.Rule}
	}
	return raw, nil
}

// Pull reads a packet under a credential. part ("", "summary" or "evidence") asks for one part. The bundle is
// validated against its own manifest; a part is a partial bundle, and says so by its missing files.
func (c *Client) Pull(ctx context.Context, packetID, credential, part string) (*packet.Bundle, error) {
	path := "/v1/packets/" + url.PathEscape(packetID)
	if part != "" {
		path += "?part=" + url.QueryEscape(part)
	}
	raw, err := c.do(ctx, http.MethodGet, path, nil, credential)
	if err != nil {
		return nil, err
	}
	b, err := packet.LoadBundle(raw)
	if err != nil {
		return nil, err
	}
	if b.ID != packetID {
		return nil, fmt.Errorf("assurance: asked for %s and the core sent %s", packetID, b.ID)
	}
	return b, nil
}

// SampleRequest is what a sample call asks for (P-2): zero N is the core's default (25), an empty Stratify uniform. The Seed
// is required: the auditor chooses it once the packet's digest is fixed.
type SampleRequest struct {
	N        int
	Seed     string
	Stratify string
}

// Sample draws a sample of a packet's cleared changes under a credential. The document is parsed and its packet checked to
// be the one asked for; the raw bytes are returned too, to write to a file for `clearance verify --sample`.
func (c *Client) Sample(ctx context.Context, packetID, credential string, r SampleRequest) (*sampling.Document, []byte, error) {
	if !sampling.ValidSeed(r.Seed) {
		return nil, nil, errors.New("assurance: a sample needs a seed (1 to 64 letters, digits, dots, underscores or hyphens)")
	}
	q := url.Values{}
	if r.N != 0 {
		q.Set("n", fmt.Sprint(r.N))
	}
	q.Set("seed", r.Seed)
	if r.Stratify != "" {
		q.Set("stratify", r.Stratify)
	}
	path := "/v1/packets/" + url.PathEscape(packetID) + "/sample"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	raw, err := c.do(ctx, http.MethodGet, path, nil, credential)
	if err != nil {
		return nil, nil, err
	}
	var d sampling.Document
	if err := json.Unmarshal(raw, &d); err != nil || d.Schema != sampling.Schema {
		return nil, nil, errors.New("assurance: the core's answer is not a sample document")
	}
	if d.Packet.ID != packetID {
		return nil, nil, fmt.Errorf("assurance: asked for a sample of %s and the core sent one of %s", packetID, d.Packet.ID)
	}
	return &d, raw, nil
}

// Recorded is the core's answer to an accepted receipt.
type Recorded struct {
	Seq           int64  `json:"seq"`
	Hash          string `json:"hash"`
	PacketID      string `json:"packet_id"`
	Recipient     string `json:"recipient"`
	Verdict       string `json:"verdict"`
	PayloadSHA256 string `json:"payload_sha256"`
	// Created is false when the core already held this signed receipt.
	Created bool `json:"created"`
}

// Submit posts a signed receipt (the DSSE envelope's JSON).
func (c *Client) Submit(ctx context.Context, packetID string, envelope []byte) (*Recorded, error) {
	raw, err := c.do(ctx, http.MethodPost, "/v1/packets/"+url.PathEscape(packetID)+"/receipts", envelope, "")
	if err != nil {
		return nil, err
	}
	var out Recorded
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("assurance: the core's answer is not a receipt record: %w", err)
	}
	return &out, nil
}

// Review is what a recipient says of a packet.
type Review struct {
	Delivery   string
	Recipient  string
	Engagement string
	Verdict    string
	Notes      map[string]string
	// Now is the signing time (zero: the clock).
	Now time.Time
}

// Payload is the receipt payload for b: it binds the packet's id and digest, the framework and mapping versions and the
// checkpoint the packet's own packet.json states, so a receipt cannot be written about a packet the recipient was not
// given. It fails when b carries no packet.json (a delivery scoped to the evidence part): the recipient then names the
// binding itself or asks for the summary.
func Payload(b *packet.Bundle, r Review) (receipt.Payload, error) {
	if _, ok := b.Files["packet.json"]; !ok {
		return receipt.Payload{}, errors.New("assurance: this bundle has no packet.json (the delivery's scope is the evidence part): a receipt binds the packet's mappings and checkpoint, which are read from it")
	}
	now := r.Now
	if now.IsZero() {
		now = time.Now()
	}
	p := receipt.Payload{Type: receipt.Type, PacketID: b.ID, PacketDigest: b.Digest, Delivery: r.Delivery, Recipient: r.Recipient,
		Engagement: r.Engagement, Mappings: b.Meta.Mappings, Verdict: r.Verdict, ControlNotes: r.Notes, SignedAt: now.UTC().Format(time.RFC3339)}
	if c := b.Meta.Checkpoint; c != nil {
		p.Checkpoint = &receipt.Checkpoint{Origin: c.Origin, Size: c.Size, Root: c.Root}
	}
	if p.ControlNotes == nil {
		p.ControlNotes = map[string]string{}
	}
	return p, p.Check()
}
