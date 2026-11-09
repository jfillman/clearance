// Package ledger is the evidence ledger (C-3): a transparency log of the evidence chain's record hashes and nothing
// else, checkpointed on a cadence, countersigned by witnesses Clearance does not operate, and the assurance state
// that follows from it.
//
// The pieces:
//
//   - The log is a Tessera (github.com/transparency-dev/tessera) log on its POSIX driver, one entry per chain record
//     (the record's 32-byte hash, so the log learns nothing the chain's hashes do not already publish). Entry i is
//     chain record seq i. Tessera has no PostgreSQL driver, so the tiles live on a volume, and the chain in
//     PostgreSQL stays the source of truth: the volume is a cache that Open rebuilds from the chain's record
//     hashes, in seq order, and that must reach the root a witness already signed (Service.Open).
//   - Checkpoints are C2SP tlog-checkpoints signed by the log key and countersigned (tlog-cosignature) by the
//     witnesses of the witness policy. Tessera publishes a checkpoint only when the policy is satisfied; the
//     service additionally refuses to record one that is not, and a witness that rejects a checkpoint (a log that
//     was truncated, rewritten or forked) fails the publish: nothing is published and the assurance state says why.
//   - A record's assurance state moves from recorded-not-checkpointed to checkpointed when its hash is under a
//     witnessed checkpoint (store.Ledger.PutLedgerCheckpoint, one transaction with the checkpoint's row).
//   - The tier 3 outage knob: while evidence cannot be checkpointed, Service.Hold says a tier 3 change waits
//     (gate.EvidenceGate). On by default; off only by explicit choice.
//   - The witness (Witness, cmd/clearance-witness) is the other side of the protocol: it keeps the latest
//     checkpoint it cosigned for each log it knows and cosigns a new one only when it extends that one.
//
// The ledger is off unless configured (core.Config.Ledger); with it off nothing here runs.
package ledger
