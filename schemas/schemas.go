// Package schemas holds Clearance's published schemas, embedded so a Go route can serve the exact bytes the repo
// publishes. evidence.schema.json is clearance.evidence/v1 (docs/evidence.md); its $id is the stable URL.
package schemas

import _ "embed"

// EvidenceV1 is schemas/evidence.schema.json.
//
//go:embed evidence.schema.json
var EvidenceV1 []byte
