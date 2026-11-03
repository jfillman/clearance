// Package store is the core's durable state: the evidence chain and the deployment gate's rows, on one
// Postgres pool (store/pg) or in memory (store/memory, for `clearance core --memory` and tests).
//
// The tables and their columns are the ones the Python core created (clearance pg.py SCHEMA): the Go core takes
// over the live hangar-dev database at cutover, so a column, an index or a jsonb shape here is a migration there.
//
// One writer. Opening a writable Store takes the advisory lock the Python core takes (LockKey) and fails if another
// writer holds it, because two writers would fork the chain. On open the chain is verified from genesis.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// LockKey is pg.py's LOCK_KEY ("clr0"): one Clearance writer per database, Python or Go.
const LockKey int64 = 0x636C7230

// Genesis is the prev_hash of record 0.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// ErrWriterLocked is returned by Open when another writer holds LockKey.
var ErrWriterLocked = errors.New("store: another Clearance writer holds the database")

// ErrNotFound is returned by single-row reads.
var ErrNotFound = errors.New("store: not found")

// Event is what a caller records: its fields, before the envelope (seq, schema, boundary, coverage, verified,
// claimed, prev_hash, hash) is added. Values must be what encoding/json would produce from JSON: string, bool,
// json.Number or float64, []any, map[string]any, nil.
type Event = map[string]any

// Record is a stored chain record: the event plus its envelope, exactly the object that was hashed plus "hash".
type Record = map[string]any

// Change is one row of clearance_changes. Record is the gate's own view of the change (gate.Change), stored as
// jsonb; the other fields are its indexed columns.
type Change struct {
	ID, App, Env, State, Repo, Head string
	PR                              int
	ExpiresAt                       time.Time
	Record                          json.RawMessage
}

// Definition is one row of clearance_definitions: a cluster-pinned agent definition and its state.
type Definition struct {
	Name, State string
	Record      json.RawMessage
}

// Store is a writable core store.
type Store interface {
	Reader
	// Atomic runs fn in one transaction: every record appended and every row written through tx commits together,
	// or none does (fn's error, or a failed commit, rolls all of it back and the chain head with it).
	Atomic(ctx context.Context, fn func(tx Tx) error) error
	Close()
}

// Tx is the write side, valid only inside Atomic.
type Tx interface {
	Reader
	// Append writes event as the next chain record and returns the stored record (seq, envelope and hash added).
	Append(ctx context.Context, event Event) (Record, error)
	PutChange(ctx context.Context, c Change) error
	ReplaceDefinitions(ctx context.Context, defs []Definition) error
}

// Reader is what both a Tx and the store outside a transaction can read.
type Reader interface {
	// Head is the last record's seq and hash (-1 and Genesis on an empty chain).
	Head(ctx context.Context) (seq int64, hash string, err error)
	// Records returns up to limit records with seq >= from, in seq order.
	Records(ctx context.Context, from int64, limit int) ([]Record, error)
	// Receipts are the records whose tool is in tools and whose effect names repo and pr (provenance).
	Receipts(ctx context.Context, repo string, pr int, tools []string) ([]Record, error)
	// Assurance is the record's assurance state, kept beside it, never inside the hash.
	Assurance(ctx context.Context, seq int64) (string, error)

	Change(ctx context.Context, id string) (Change, error)
	ChangesForPR(ctx context.Context, repo string, pr int) ([]Change, error)
	ChangesForHead(ctx context.Context, repo, head string) ([]Change, error)
	ChangesHolding(ctx context.Context) ([]Change, error)
	// ChangesUndelivered are the changes with a deployment whose delivered is false (github_app.py retries them).
	ChangesUndelivered(ctx context.Context) ([]Change, error)
	Definitions(ctx context.Context) ([]Definition, error)
}
