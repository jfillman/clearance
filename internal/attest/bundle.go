package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/jfillman/clearance/internal/token"
)

// BundleMediaType is the Sigstore bundle format the attestation is kept in (v0.2: a certificate chain, so a
// verifier needs no intermediates of its own).
const BundleMediaType = "application/vnd.dev.sigstore.bundle+json;version=0.2"

// Bundle is a Sigstore bundle: the DSSE envelope and what verifies it.
type Bundle struct {
	MediaType            string         `json:"mediaType"`
	VerificationMaterial Material       `json:"verificationMaterial"`
	DSSEEnvelope         token.Envelope `json:"dsseEnvelope"`
}

// Material is a bundle's verification material: a Fulcio certificate chain (keyless) or a key hint (static), and
// the Rekor entries that log the envelope.
type Material struct {
	X509CertificateChain *CertChain  `json:"x509CertificateChain,omitempty"`
	PublicKey            *KeyHint    `json:"publicKey,omitempty"`
	TlogEntries          []TlogEntry `json:"tlogEntries,omitempty"`
}

// CertChain is a leaf-first chain of DER certificates (base64 in JSON).
type CertChain struct {
	Certificates []RawBytes `json:"certificates"`
}

// RawBytes is one DER certificate.
type RawBytes struct {
	RawBytes []byte `json:"rawBytes"`
}

// KeyHint names the key a static bundle was signed with (token.KeyID).
type KeyHint struct {
	Hint string `json:"hint"`
}

// TlogEntry is one Rekor entry as a Sigstore bundle writes it.
type TlogEntry struct {
	LogIndex          string      `json:"logIndex"`
	LogID             LogID       `json:"logId"`
	KindVersion       KindVersion `json:"kindVersion"`
	IntegratedTime    string      `json:"integratedTime"`
	InclusionPromise  *Promise    `json:"inclusionPromise,omitempty"`
	InclusionProof    *InclProof  `json:"inclusionProof,omitempty"`
	CanonicalizedBody []byte      `json:"canonicalizedBody"`
}

// LogID is Rekor's key id.
type LogID struct {
	KeyID []byte `json:"keyId"`
}

// KindVersion is the entry type.
type KindVersion struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

// Promise is Rekor's signed entry timestamp (SET).
type Promise struct {
	SignedEntryTimestamp []byte `json:"signedEntryTimestamp"`
}

// InclProof is Rekor's inclusion proof, kept as Rekor returned it. Verify does not check it (it checks the SET).
type InclProof struct {
	LogIndex   string          `json:"logIndex,omitempty"`
	RootHash   string          `json:"rootHash,omitempty"`
	TreeSize   string          `json:"treeSize,omitempty"`
	Hashes     []string        `json:"hashes,omitempty"`
	Checkpoint json.RawMessage `json:"checkpoint,omitempty"`
}

// EnvelopeDigest is "sha256:<hex>" of the DSSE envelope as this package serializes it (token.Envelope's JSON), the
// digest the deploy.attestation record carries and clearance-api serves.
func EnvelopeDigest(e token.Envelope) string {
	b, _ := json.Marshal(e)
	d := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(d[:])
}
