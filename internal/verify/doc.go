// Package verify is the offline evidence-packet verifier (C-4): `clearance verify <packet>` and the standalone
// clearance-verify binary. It reads a packet directory written by internal/packet and checks it against keys the
// verifier's user supplies, making no network call and talking to no Clearance, database or recorder.
//
// It is deliberately a small leaf. It imports the canonical-JSON package (the record hash), the attestation
// verifier (internal/attest, which is itself free of the core and the store since the signing side moved to
// internal/attestor), the evidence vocabulary and the transparency-dev libraries; it does not import the ledger
// package (which links the store), the packet builder or the core. `go list -deps ./internal/verify` shows it.
//
// The packet is the claim; the verifier's job is to check it, so it keeps two things apart in everything it prints:
// what it checked against trust inputs the user supplied, and what it could only check against material the packet
// itself carries (a packet vouching for its own keys proves nothing, and is reported as SELF-VOUCHED).
package verify
