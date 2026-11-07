package attest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/jfillman/clearance/internal/token"
)

// Backend signs an attestation payload and logs it. It is the seam between the signer and the key custody: Keyless
// (Fulcio and Rekor) is the deployment's; Static (a key file) is for tests and labs.
type Backend interface {
	// Name is "keyless" or "static".
	Name() string
	// Sign wraps payload (an in-toto statement) in a DSSE envelope of PayloadType, signs it and logs it.
	Sign(ctx context.Context, payload []byte) (Signed, error)
}

// Signed is a signed, logged attestation.
type Signed struct {
	Bundle        Bundle
	Backend       string
	KeyID         string // static: the key's id; keyless: "" (the certificate names the identity)
	RekorLogIndex *int64
	RekorUUID     string
}

// signEnvelope is DSSE: sign the pre-authentication encoding of payload with sign (a SHA-256 digest in, an ASN.1 DER
// ECDSA signature out).
func signEnvelope(ctx context.Context, payload []byte, keyID string, sign func(ctx context.Context, digest []byte) ([]byte, error)) (token.Envelope, error) {
	d := sha256.Sum256(token.PAE(PayloadType, payload))
	der, err := sign(ctx, d[:])
	if err != nil {
		return token.Envelope{}, fmt.Errorf("attest: signing: %w", err)
	}
	return token.Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []token.Signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(der)}}}, nil
}

// logEntry logs env in rekor (when not nil) and fills s.
func logEntry(ctx context.Context, rekor *Rekor, env token.Envelope, verifierPEM []byte, s *Signed) error {
	if rekor == nil {
		return nil
	}
	te, uuid, err := rekor.Log(ctx, env, verifierPEM)
	if err != nil {
		return err
	}
	idx, err := strconv.ParseInt(te.LogIndex, 10, 64)
	if err != nil {
		return errors.New("rekor: the log index is not a number")
	}
	s.Bundle.VerificationMaterial.TlogEntries = []TlogEntry{te}
	s.RekorLogIndex, s.RekorUUID = &idx, uuid
	return nil
}

// Static signs with a key the core holds (token.LoadKeyFile's mount pattern): for tests and labs. With a Rekor it
// logs too, so a lab can run the whole path against a Rekor of its own.
type Static struct {
	Signer token.Signer
	Rekor  *Rekor // nil: not logged
}

// Name implements Backend.
func (*Static) Name() string { return "static" }

// Sign implements Backend.
func (s *Static) Sign(ctx context.Context, payload []byte) (Signed, error) {
	kid := s.Signer.KeyID()
	env, err := signEnvelope(ctx, payload, kid, s.Signer.Sign)
	if err != nil {
		return Signed{}, err
	}
	out := Signed{Backend: s.Name(), KeyID: kid, Bundle: Bundle{MediaType: BundleMediaType, DSSEEnvelope: env,
		VerificationMaterial: Material{PublicKey: &KeyHint{Hint: kid}}}}
	pemKey, err := pemPublicKey(s.Signer.Public())
	if err != nil {
		return Signed{}, err
	}
	if err := logEntry(ctx, s.Rekor, env, pemKey, &out); err != nil {
		return Signed{}, err
	}
	return out, nil
}
