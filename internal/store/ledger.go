package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The assurance states of a record (clearance_evidence.assurance, beside the record and never hashed).
const (
	// AssuranceRecorded is a record in the chain that no witnessed checkpoint covers yet.
	AssuranceRecorded = "recorded-not-checkpointed"
	// AssuranceCheckpointed is a record whose hash is under a checkpoint the witnesses countersigned (C-3).
	AssuranceCheckpointed = "checkpointed"
)

// LedgerCheckpoint is a checkpoint of the evidence ledger (the Tessera log of record hashes) that the witness
// policy was satisfied for, kept in the same database as the chain so a lost log volume can be rebuilt and checked
// against it (internal/ledger). Root is the tree's root hash in hex; Note is the signed checkpoint with its
// countersignatures, as published.
type LedgerCheckpoint struct {
	Origin string
	Size   int64
	Root   string
	Note   []byte
	At     time.Time
}

// ErrLedgerRegress is returned by PutLedgerCheckpoint for a checkpoint that is smaller than the one held, or the
// same size with another root: a witnessed checkpoint is never replaced by a different history.
var ErrLedgerRegress = errors.New("store: ledger checkpoint would regress or fork the one held")

// Ledger is the evidence ledger's state in the store. The in-memory store and Postgres implement it; a Store that
// does not is a deployment without the ledger.
type Ledger interface {
	// LedgerCheckpoint is the latest witnessed checkpoint (ErrNotFound when none).
	LedgerCheckpoint(ctx context.Context) (LedgerCheckpoint, error)
	// PutLedgerCheckpoint records cp as the latest witnessed checkpoint and marks every record with seq < cp.Size
	// checkpointed, in one transaction. A cp larger than the chain, smaller than the held one, or the held size
	// with another root is refused.
	PutLedgerCheckpoint(ctx context.Context, cp LedgerCheckpoint) error
}

// CheckLedgerCheckpoint is the rule PutLedgerCheckpoint applies, for the implementations to share: held is the
// checkpoint now recorded (nil: none), chain the chain's length.
func CheckLedgerCheckpoint(held *LedgerCheckpoint, cp LedgerCheckpoint, chain int64) error {
	if cp.Size < 0 || cp.Size > chain {
		return fmt.Errorf("store: ledger checkpoint covers %d records, the chain holds %d", cp.Size, chain)
	}
	if held != nil && (cp.Size < held.Size || (cp.Size == held.Size && cp.Root != held.Root)) {
		return ErrLedgerRegress
	}
	return nil
}
