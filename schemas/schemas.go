// Package schemas holds Clearance's published schemas, embedded so a Go route can serve the exact bytes the repo
// publishes. evidence.schema.json is clearance.evidence/v1 (docs/evidence.md); its $id is the stable URL.
package schemas

import _ "embed"

// EvidenceV1 is schemas/evidence.schema.json.
//
//go:embed evidence.schema.json
var EvidenceV1 []byte

// ChangeRequestV1 is schemas/change-request.schema.json: what a verifier registers (POST /v1/clearances), the
// shape internal/gate ParseRequest decodes.
//
//go:embed change-request.schema.json
var ChangeRequestV1 []byte

// ChangeAttestationV1 is schemas/change-attestation.schema.json: the in-toto statement the attestation signer (C-2)
// signs, whose predicate type is https://clearance.hangarplatform.dev/change-attestation/v1.
//
//go:embed change-attestation.schema.json
var ChangeAttestationV1 []byte

// StatementV1 is schemas/statement.schema.json: the verification statement (P-3) a core signs and `clearance verify
// --statement` reads, and, in $defs.status, its signed status. internal/statement decodes the same shape strictly.
//
//go:embed statement.schema.json
var StatementV1 []byte
