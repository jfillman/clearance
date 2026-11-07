// Package attest is the change attestation signer (C-2). After a deploy provider reports a change's outcome, the
// core assembles an in-toto Statement v1 about it (subjects: the cleared tree root or plan, the commit, the image
// digests; predicate: the clearance decision and the outcome), wraps it in a DSSE envelope, signs it through a
// Backend, logs it in Rekor, and keeps the Sigstore bundle with the change. The signer runs in the core, never in a
// provider or a CMP.
//
// Two backends: Keyless (Fulcio issues a short-lived certificate for an ephemeral key against the core's OIDC
// identity; Rekor logs the entry) and Static (a key file, for tests and labs; Rekor optional). Verify checks a
// bundle offline against a trust root. Crypto is the standard library's; there is no Sigstore dependency.
package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jfillman/clearance/internal/token"
)

// StatementType is the in-toto Statement v1 _type.
const StatementType = "https://in-toto.io/Statement/v1"

// PredicateType identifies the predicate's schema (schemas/change-attestation.schema.json).
const PredicateType = "https://clearance.hangarplatform.dev/change-attestation/v1"

// PayloadType is the DSSE payloadType an in-toto statement carries.
const PayloadType = "application/vnd.in-toto+json"

// Statement is an in-toto Statement v1.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Subject is one thing the attestation is about: a name and its digests.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Predicate is the change-attestation/v1 predicate: what the core decided and what the deploy reported.
type Predicate struct {
	Clearance  token.Clearance  `json:"clearance"`
	Target     token.Target     `json:"target"`
	Tier       int              `json:"tier"`
	Policy     token.Policy     `json:"policy"`
	Approvals  []token.Approval `json:"approvals"`
	Provenance token.Provenance `json:"provenance"`
	// Cleared is what the clearance bound (the token's subjects: tree root or plan digest, commit, images).
	Cleared token.Subjects `json:"cleared"`
	Outcome Outcome        `json:"outcome"`
	// Release is the release the deploy named (docs/gate.md "Linking a change to its release"), copied from the
	// deploy.outcome record; absent when the record names none.
	Release  *Release `json:"release,omitempty"`
	Coverage string   `json:"coverage"`
	// Limitations say what the attestation does not establish. Always present, never empty.
	Limitations []string `json:"limitations"`
}

// Release names a release by its id.
type Release struct {
	ID string `json:"id"`
}

// Outcome is the deploy.outcome record the attestation rests on.
type Outcome struct {
	Seq      int64  `json:"seq"`
	Provider string `json:"provider"`
	Applied  bool   `json:"applied"`
	// Matched says the applied digest is the cleared one; nil when the provider reported no digest.
	Matched          *bool  `json:"matched"`
	Digest           string `json:"digest,omitempty"`
	ObservedRevision string `json:"observed_revision,omitempty"`
	At               string `json:"at"`
}

// Check is the statement's shape: Verify and the signer both hold it.
func (s *Statement) Check() error {
	switch {
	case s.Type != StatementType:
		return fmt.Errorf("attest: _type is %q, want %s", s.Type, StatementType)
	case s.PredicateType != PredicateType:
		return fmt.Errorf("attest: predicateType is %q, want %s", s.PredicateType, PredicateType)
	case len(s.Subject) == 0:
		return errors.New("attest: no subject")
	case s.Predicate.Clearance.ID == "":
		return errors.New("attest: no clearance id")
	case len(s.Predicate.Limitations) == 0:
		return errors.New("attest: no limitations")
	}
	for _, sub := range s.Subject {
		if sub.Name == "" || len(sub.Digest) == 0 {
			return errors.New("attest: a subject needs a name and a digest")
		}
	}
	return nil
}

// HasSubject reports whether some subject carries digest, written "<alg>:<hex>" (sha256:..., gitCommit:...).
func (s *Statement) HasSubject(digest string) bool {
	alg, hex, ok := strings.Cut(digest, ":")
	if !ok || alg == "" || hex == "" {
		return false
	}
	for _, sub := range s.Subject {
		if sub.Digest[alg] == hex {
			return true
		}
	}
	return false
}

// decodeStatement parses payload as a Statement, strictly (unknown fields refused), and checks it.
func decodeStatement(payload []byte) (*Statement, error) {
	var st Statement
	if err := strictJSON(payload, &st); err != nil {
		return nil, fmt.Errorf("attest: the statement: %w", err)
	}
	if err := st.Check(); err != nil {
		return nil, err
	}
	return &st, nil
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
