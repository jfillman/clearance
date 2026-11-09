package attest

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// KeylessIdentity is the identity (the certificate's SAN) and the OIDC issuer a keyless bundle's leaf certificate
// records, read from the bundle itself. It is what the bundle claims about its signer: a verifier that has no
// identity of its own to pin may use it to see who the signer says it is, but must say the value came from the
// bundle. ok is false for a static-key bundle (no certificate).
func KeylessIdentity(raw []byte) (identity, issuer string, ok bool, err error) {
	b, err := ParseBundle(raw)
	if err != nil {
		return "", "", false, err
	}
	cc := b.VerificationMaterial.X509CertificateChain
	if cc == nil {
		return "", "", false, nil
	}
	if len(cc.Certificates) == 0 {
		return "", "", false, errors.New("attest: the certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cc.Certificates[0].RawBytes)
	if err != nil {
		return "", "", false, fmt.Errorf("attest: the leaf certificate: %w", err)
	}
	ids := certIdentities(leaf)
	if len(ids) == 0 {
		return "", "", false, errors.New("attest: the leaf certificate names no identity")
	}
	return ids[0], certIssuer(leaf), true, nil
}

// CheckInclusionProof checks the Rekor inclusion proof a bundle carries, offline: the audit path from the entry's
// leaf (the RFC 6962 hash of the canonicalized body) to the root the proof states, and, when the proof carries
// Rekor's checkpoint, that the checkpoint states the same size and root. present is false when the bundle carries
// no inclusion proof (then only the signed entry timestamp vouches for the entry; Verify checks that).
//
// It does not check the signature on Rekor's checkpoint: the root it proves to is the one the bundle states.
func CheckInclusionProof(raw []byte) (present bool, err error) {
	b, err := ParseBundle(raw)
	if err != nil {
		return false, err
	}
	entries := b.VerificationMaterial.TlogEntries
	if len(entries) == 0 {
		return false, nil
	}
	for i, e := range entries {
		p := e.InclusionProof
		if p == nil {
			return false, nil
		}
		present = true
		idx, err1 := strconv.ParseUint(firstNonEmpty(p.LogIndex, e.LogIndex), 10, 64)
		size, err2 := strconv.ParseUint(p.TreeSize, 10, 64)
		root, err3 := hex.DecodeString(p.RootHash)
		if err1 != nil || err2 != nil || err3 != nil || len(root) != 32 {
			return present, fmt.Errorf("attest: Rekor entry %d: the inclusion proof's index, size or root is malformed", i)
		}
		var hashes [][]byte
		for _, h := range p.Hashes {
			d, err := hex.DecodeString(h)
			if err != nil || len(d) != 32 {
				return present, fmt.Errorf("attest: Rekor entry %d: an inclusion proof hash is not a SHA-256", i)
			}
			hashes = append(hashes, d)
		}
		leaf := rfc6962.DefaultHasher.HashLeaf(e.CanonicalizedBody)
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, idx, size, leaf, hashes, root); err != nil {
			return present, fmt.Errorf("attest: Rekor entry %d: the inclusion proof does not reach the stated root: %w", i, err)
		}
		if len(p.Checkpoint) > 0 {
			if err := sameCheckpoint(p.Checkpoint, size, root); err != nil {
				return present, fmt.Errorf("attest: Rekor entry %d: %w", i, err)
			}
		}
	}
	return present, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// sameCheckpoint checks that Rekor's checkpoint text (a signed note: origin, size, base64 root) states size and root.
func sameCheckpoint(raw json.RawMessage, size uint64, root []byte) error {
	text := string(raw)
	var env struct {
		Envelope string `json:"envelope"`
	}
	if json.Unmarshal(raw, &env) == nil && env.Envelope != "" {
		text = env.Envelope
	} else {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			text = s
		}
	}
	lines := strings.Split(text, "\n")
	if len(lines) < 3 {
		return errors.New("the inclusion proof's checkpoint is malformed")
	}
	n, err := strconv.ParseUint(lines[1], 10, 64)
	r, err2 := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || err2 != nil {
		return errors.New("the inclusion proof's checkpoint is malformed")
	}
	if n != size || !bytes.Equal(r, root) {
		return errors.New("the inclusion proof and its checkpoint state different trees")
	}
	return nil
}
