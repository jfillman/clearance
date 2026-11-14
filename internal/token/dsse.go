package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// SignDSSE signs payload as a DSSE envelope of payloadType with s: the one signing path tokens, feeds, attestations
// and (P-1) acceptance receipts share.
func SignDSSE(ctx context.Context, s Signer, payloadType string, payload []byte) (Envelope, error) {
	return signDSSE(ctx, s, payloadType, payload)
}

// VerifyDSSE checks the DSSE envelope raw (its JSON, of payloadType) against keys and returns the signed payload and
// the id of the key that signed it. The envelope is parsed strictly and size-capped; a payloadType other than the
// one asked for, an unknown key and a bad signature are each an error (ErrMalformed, ErrUnknownKey, ErrSignature).
func VerifyDSSE(raw []byte, payloadType string, keys KeySet) ([]byte, string, error) {
	env, err := parseEnvelope(raw, payloadType)
	if err != nil {
		return nil, "", err
	}
	payload, err := decodeB64(env.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("%w: payload is not base64", ErrMalformed)
	}
	d := sha256.Sum256(PAE(env.PayloadType, payload))
	known := false
	for _, s := range env.Signatures {
		pub, ok := keys[s.KeyID]
		if !ok {
			continue
		}
		known = true
		der, err := decodeB64(s.Sig)
		if err != nil {
			continue
		}
		if ecdsa.VerifyASN1(pub, d[:], der) {
			return payload, s.KeyID, nil
		}
	}
	if !known {
		return nil, "", ErrUnknownKey
	}
	return nil, "", ErrSignature
}

// MaxPublicKeyBytes caps a public key file.
const MaxPublicKeyBytes = 64 << 10

// ParsePublicKeys reads ECDSA P-256 public keys: one or more PKIX "PUBLIC KEY" PEM blocks (as `openssl ec -pubout`
// writes them), or a JWKS (as GET /v1/keys serves one). The result is by key id (the RFC 7638 thumbprint).
func ParsePublicKeys(raw []byte) (KeySet, error) {
	if len(raw) > MaxPublicKeyBytes {
		return nil, fmt.Errorf("%w: public keys over %d bytes", ErrMalformed, MaxPublicKeyBytes)
	}
	ks := KeySet{}
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("%w: a %q PEM block is not a public key", ErrMalformed, block.Type)
		}
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: a public key PEM block is not PKIX", ErrMalformed)
		}
		pub, ok := k.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: the public key is not ECDSA P-256", ErrMalformed)
		}
		kid, err := KeyID(pub)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		ks[kid] = pub
	}
	if len(ks) > 0 {
		return ks, nil
	}
	ks, err := ParseJWKS(raw)
	if err != nil {
		return nil, errors.New("token: the public keys are neither PEM nor a JWKS")
	}
	if len(ks) == 0 {
		return nil, errors.New("token: no public key in the input")
	}
	return ks, nil
}
