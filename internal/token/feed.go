package token

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// The signed grant feed (C-10): the core's statement, per protected cluster, of every clearance token live there at
// one moment. A grant-sync agent (G-ARGO-3) verifies it as a whole, with the keys of GET /v1/keys, before it
// creates, updates or removes a single ClearanceGrant: the signature says the core wrote it, the cluster that it is
// this cluster's, exp that it is fresh, seq that it is not an older feed replayed, and the entries that the tokens
// served beside it are exactly the set the core signed (nothing withheld, nothing added).
//
// It is a DSSE envelope over a JSON Feed, signed by the token Signer (the same key, the same keyid): one signing
// path serves tokens, feeds and (C-2) attestations. docs/gate.md, "The signed grant feed", is the reader's guide.

// FeedType is the feed's _type; FeedPayloadType its DSSE payloadType.
const (
	FeedType        = "clearance.grant-feed/v1"
	FeedPayloadType = "application/vnd.clearance.grant-feed.v1+json"
)

// Feed limits. MaxFeedLifetime bounds exp - iat whoever signed it; a feed lists at most MaxFeedEntries tokens.
const (
	MaxFeedLifetime = 15 * time.Minute
	MaxFeedEntries  = 2000
)

// The feed errors VerifyFeed and Feed.Match return. Each means: do not act on this feed; keep the grants as they are
// and let them expire (fail closed).
var (
	ErrFeedReplay     = errors.New("token: grant feed older than one already accepted (seq went back)")
	ErrFeedCluster    = errors.New("token: grant feed is another cluster's")
	ErrFeedIncomplete = errors.New("token: the tokens served are not the set the feed lists")
)

// Feed is the signed document: one cluster's live clearance tokens when the core signed it.
type Feed struct {
	Type    string `json:"_type"`
	Issuer  string `json:"iss"`
	Cluster string `json:"cluster"`
	// Seq is the cluster's feed number: one more than the feed it replaces, never reused. A reader keeps the highest
	// it accepted and refuses a lower one.
	Seq int64 `json:"seq"`
	// IssuedAt and Expires are NumericDate seconds. The core re-signs a cluster's feed whenever one of its tokens is
	// issued, re-issued or revoked, and at least every few minutes otherwise, so a reader holding an expired feed
	// knows the core (or the path to it) is down, not that nothing changed.
	IssuedAt int64 `json:"iat"`
	Expires  int64 `json:"exp"`
	// RecordsSeq is the evidence chain's last seq when the feed was signed (-1 on an empty chain): every deploy.*
	// record at or below it is reflected in the entries.
	RecordsSeq int64 `json:"records_seq"`
	// Entries are the live tokens, by change id ascending.
	Entries []FeedEntry `json:"entries"`
}

// FeedEntry is one live token of the feed.
type FeedEntry struct {
	ChangeID string `json:"change_id"`
	Nonce    string `json:"nonce"`
	Expires  int64  `json:"exp"`
	// PayloadSHA256 is the hex SHA-256 of the token's DSSE payload (the claims bytes as signed): it binds the entry
	// to that exact issuance of the token, so a refreshed or altered token does not match.
	PayloadSHA256 string `json:"payload_sha256"`
}

// Check is what SignFeed and VerifyFeed require of the feed itself.
func (f *Feed) Check() error {
	switch {
	case f.Type != FeedType:
		return fmt.Errorf("%w: _type is %q", ErrMalformed, f.Type)
	case f.Issuer == "" || f.Cluster == "":
		return fmt.Errorf("%w: iss and cluster are required", ErrMalformed)
	case f.Seq < 1:
		return fmt.Errorf("%w: seq starts at 1", ErrMalformed)
	case f.IssuedAt <= 0 || f.Expires <= f.IssuedAt:
		return fmt.Errorf("%w: exp must follow iat", ErrMalformed)
	case time.Duration(f.Expires-f.IssuedAt)*time.Second > MaxFeedLifetime:
		return fmt.Errorf("%w: a grant feed lives at most %s", ErrMalformed, MaxFeedLifetime)
	case len(f.Entries) > MaxFeedEntries:
		return fmt.Errorf("%w: over %d entries", ErrMalformed, MaxFeedEntries)
	}
	seen := map[string]bool{}
	for i, e := range f.Entries {
		if e.ChangeID == "" || e.Nonce == "" || len(e.PayloadSHA256) != 64 {
			return fmt.Errorf("%w: entry %d needs change_id, nonce and a payload_sha256", ErrMalformed, i)
		}
		if seen[e.ChangeID] || (i > 0 && f.Entries[i-1].ChangeID > e.ChangeID) {
			return fmt.Errorf("%w: entries are by change_id ascending, each once", ErrMalformed)
		}
		seen[e.ChangeID] = true
	}
	return nil
}

// PayloadDigest is the hex SHA-256 of a token envelope's decoded payload: what a FeedEntry lists.
func PayloadDigest(env Envelope) (string, error) {
	payload, err := decodeB64(env.Payload)
	if err != nil {
		return "", fmt.Errorf("%w: payload is not base64", ErrMalformed)
	}
	d := sha256.Sum256(payload)
	return hex.EncodeToString(d[:]), nil
}

// signDSSE signs payload as a DSSE envelope of payloadType with s.
func signDSSE(ctx context.Context, s Signer, payloadType string, payload []byte) (Envelope, error) {
	d := sha256.Sum256(PAE(payloadType, payload))
	der, err := s.Sign(ctx, d[:])
	if err != nil {
		return Envelope{}, fmt.Errorf("token: signing: %w", err)
	}
	return Envelope{PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(der)}}}, nil
}

// SignFeed signs f (its entries sorted by change id first) as a DSSE envelope.
func SignFeed(ctx context.Context, s Signer, f Feed) (Envelope, error) {
	if f.Entries == nil {
		f.Entries = []FeedEntry{}
	}
	sort.Slice(f.Entries, func(i, j int) bool { return f.Entries[i].ChangeID < f.Entries[j].ChangeID })
	if err := f.Check(); err != nil {
		return Envelope{}, err
	}
	payload, err := json.Marshal(f)
	if err != nil {
		return Envelope{}, err
	}
	return signDSSE(ctx, s, FeedPayloadType, payload)
}

// FeedOptions are a feed verification's inputs. Issuer and Cluster are required.
type FeedOptions struct {
	Issuer  string
	Cluster string
	// MinSeq is the highest seq the reader accepted before (0: none): a feed below it is a replay. The same seq is
	// the same feed read again, and is accepted.
	MinSeq int64
	Now    func() time.Time // nil: time.Now
	Leeway time.Duration    // 0: DefaultLeeway; negative: none
}

// VerifyFeed checks a grant feed envelope (its JSON) against keys and opts and returns the feed.
func VerifyFeed(raw []byte, keys KeySet, opts FeedOptions) (*Feed, error) {
	env, err := parseEnvelope(raw, FeedPayloadType)
	if err != nil {
		return nil, err
	}
	payload, err := decodeB64(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64", ErrMalformed)
	}
	d := sha256.Sum256(PAE(env.PayloadType, payload))
	if err := keys.verifyAny(env.Signatures, d[:]); err != nil {
		return nil, err
	}
	var f Feed
	if err := strictJSON(payload, &f); err != nil {
		return nil, fmt.Errorf("%w: feed: %v", ErrMalformed, err)
	}
	if err := f.Check(); err != nil {
		return nil, err
	}
	if opts.Issuer == "" || f.Issuer != opts.Issuer {
		return nil, fmt.Errorf("%w: %q", ErrIssuer, f.Issuer)
	}
	if opts.Cluster == "" || f.Cluster != opts.Cluster {
		return nil, fmt.Errorf("%w: %q", ErrFeedCluster, f.Cluster)
	}
	if f.Seq < opts.MinSeq {
		return nil, fmt.Errorf("%w: %d < %d", ErrFeedReplay, f.Seq, opts.MinSeq)
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	leeway := opts.Leeway
	if leeway == 0 {
		leeway = DefaultLeeway
	} else if leeway < 0 {
		leeway = 0
	}
	t := now()
	if !t.Before(time.Unix(f.Expires, 0).Add(leeway)) {
		return nil, ErrExpired
	}
	if t.Add(leeway).Before(time.Unix(f.IssuedAt, 0)) {
		return nil, ErrNotYetValid
	}
	return &f, nil
}

// Match checks that tokens (by change id) are exactly the feed's entries: one per entry, none more, each the
// issuance the entry names (its payload digest). The tokens themselves are still each Verify's to check.
func (f *Feed) Match(tokens map[string]Envelope) error {
	if len(tokens) != len(f.Entries) {
		return fmt.Errorf("%w: %d tokens for %d entries", ErrFeedIncomplete, len(tokens), len(f.Entries))
	}
	for _, e := range f.Entries {
		env, ok := tokens[e.ChangeID]
		if !ok {
			return fmt.Errorf("%w: no token for %s", ErrFeedIncomplete, e.ChangeID)
		}
		got, err := PayloadDigest(env)
		if err != nil {
			return err
		}
		if got != e.PayloadSHA256 {
			return fmt.Errorf("%w: the token for %s is not the issuance the feed lists", ErrFeedIncomplete, e.ChangeID)
		}
	}
	return nil
}
