package ledger

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"

	"github.com/jfillman/clearance/internal/store"
)

// Chain is the part of the store the ledger reads: the evidence chain's length and records.
type Chain interface {
	Head(ctx context.Context) (seq int64, hash string, err error)
	Records(ctx context.Context, from int64, limit int) ([]store.Record, error)
}

// Defaults for LogConfig.
const (
	DefaultCheckpointInterval = time.Minute
	DefaultWitnessTimeout     = 20 * time.Second
	batchSize                 = 500
	entrySize                 = 32
)

// LogConfig is the log's configuration.
type LogConfig struct {
	// Dir is the Tessera POSIX volume. Required: one writer, one volume.
	Dir string
	Key LogKey
	// Policy is the witness policy: Tessera's text form (a `witness <name> <vkey> <url>` line per witness, a
	// `group` line per quorum, a `quorum` line). At least one witness is required: a log nobody countersigns is
	// not a ledger.
	Policy []byte
	// CheckpointInterval is how often a checkpoint is signed and sent to the witnesses, if the log has grown, and
	// how often the witnesses are re-asked when it has not (default DefaultCheckpointInterval).
	CheckpointInterval time.Duration
	// WitnessTimeout bounds one round of asking the witnesses (default DefaultWitnessTimeout).
	WitnessTimeout time.Duration
	// BatchAge is the longest an entry waits to be added to the tree (default 250ms).
	BatchAge time.Duration
	// HTTPClient talks to the witnesses (default: a client with a 30s timeout).
	HTTPClient *http.Client
}

// Log is the opened ledger: a Tessera log of record hashes.
type Log struct {
	cfg      LogConfig
	origin   string
	group    tessera.WitnessGroup
	verifier []note.Verifier // log keys and witness keys, to read a checkpoint
	app      *tessera.Appender
	lr       tessera.LogReader
	shutdown func(context.Context) error
	cancel   context.CancelFunc
}

// ErrNoWitness is returned for a witness policy that names no witness.
var ErrNoWitness = errors.New("ledger: the witness policy names no witness: a log nobody countersigns is not a ledger")

// AlteredRow says which chain row no longer matches the ledger and how.
type AlteredRow struct {
	Seq           int64
	Chain, Ledger string // the record hash the chain holds now, and the one the ledger committed to (hex)
}

func (e *AlteredRow) Error() string {
	return fmt.Sprintf("ledger: chain record %d was altered: its hash is %s, the ledger committed to %s", e.Seq, e.Chain, e.Ledger)
}

// ErrChainBehind is returned when the ledger holds more records than the chain: the chain was truncated or restored
// from an older copy.
var ErrChainBehind = errors.New("ledger: the ledger holds more records than the chain")

// ErrRootMismatch is returned when the chain's records do not hash to the root a witness cosigned.
var ErrRootMismatch = errors.New("ledger: the chain does not hash to the root a witness signed")

func entryOf(hexHash string) ([]byte, error) {
	b, err := hex.DecodeString(hexHash)
	if err != nil || len(b) != entrySize {
		return nil, fmt.Errorf("ledger: %q is not a record hash", hexHash)
	}
	return b, nil
}

// eachHash calls fn with the hash of every chain record in [from, to), in seq order, in batches.
func eachHash(ctx context.Context, c Chain, from, to int64, fn func(seq int64, hash []byte) error) error {
	for from < to {
		n := min(int64(batchSize), to-from)
		recs, err := c.Records(ctx, from, int(n))
		if err != nil {
			return err
		}
		if len(recs) == 0 {
			return fmt.Errorf("ledger: the chain has no record %d", from)
		}
		for _, r := range recs {
			h, _ := r["hash"].(string)
			b, err := entryOf(h)
			if err != nil {
				return err
			}
			if err := fn(from, b); err != nil {
				return err
			}
			from++
			if from >= to {
				break
			}
		}
	}
	return nil
}

// Roots are the tree roots of the chain's first size records for each requested size (ascending, at most the
// chain's length), in one pass over the chain.
func Roots(ctx context.Context, c Chain, sizes ...int64) ([][]byte, error) {
	rf := compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	rng := rf.NewEmptyRange(0)
	out := make([][]byte, len(sizes))
	root := func() ([]byte, error) {
		if rng.End() == 0 {
			e := rfc6962.DefaultHasher.EmptyRoot()
			return e, nil
		}
		return rng.GetRootHash(nil)
	}
	var end int64
	for _, s := range sizes {
		if s > end {
			end = s
		}
	}
	next := 0
	for next < len(sizes) && sizes[next] == 0 {
		r, _ := root()
		out[next] = r
		next++
	}
	err := eachHash(ctx, c, 0, end, func(seq int64, h []byte) error {
		if err := rng.Append(rfc6962.DefaultHasher.HashLeaf(h), nil); err != nil {
			return err
		}
		for next < len(sizes) && sizes[next] == seq+1 {
			r, err := root()
			if err != nil {
				return err
			}
			out[next] = r
			next++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if next != len(sizes) {
		return nil, errors.New("ledger: sizes must ascend")
	}
	return out, nil
}

// OpenLog opens the ledger volume and brings it level with the chain:
//
//  1. The volume's size must not exceed the chain's (ErrChainBehind), and every entry it holds must be the hash of
//     the chain record of the same seq (*AlteredRow names the first that is not).
//  2. The chain's records the volume lacks are written to it from the chain, in seq order, until the volume
//     reaches the chain's length: this is also the rebuild of an empty or lost volume. The root the volume then
//     computes must equal the root computed from the chain independently (ErrRootMismatch).
//  3. The Tessera appender is opened on it and its checkpoint cadence starts.
//
// It does not look at witnessed checkpoints: Service.Open does, before it calls this.
func OpenLog(ctx context.Context, cfg LogConfig, chain Chain) (*Log, error) {
	if cfg.Dir == "" {
		return nil, errors.New("ledger: no volume directory")
	}
	if cfg.Key.Signer == nil {
		return nil, errors.New("ledger: no log key")
	}
	if cfg.CheckpointInterval <= 0 {
		cfg.CheckpointInterval = DefaultCheckpointInterval
	}
	if cfg.WitnessTimeout <= 0 {
		cfg.WitnessTimeout = DefaultWitnessTimeout
	}
	if cfg.BatchAge <= 0 {
		cfg.BatchAge = 250 * time.Millisecond
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	group, err := tessera.NewWitnessGroupFromPolicy(cfg.Policy)
	if err != nil {
		return nil, fmt.Errorf("ledger: the witness policy: %w", err)
	}
	if len(group.Endpoints()) == 0 {
		return nil, ErrNoWitness
	}
	if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("ledger: the volume: %w", err)
	}
	l := &Log{cfg: cfg, origin: cfg.Key.Origin(), group: group}
	l.verifier = append(l.verifier, cfg.Key.Verifiers...)
	for _, v := range group.Endpoints() {
		l.verifier = append(l.verifier, v)
	}

	driver, err := posix.New(ctx, posix.Config{Path: cfg.Dir, HTTPClient: cfg.HTTPClient})
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	if err := l.level(ctx, driver.(*posix.Storage), chain); err != nil {
		return nil, err
	}

	// The checkpoint publisher and the appender live as long as the log, not as long as the caller's start-up context.
	actx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(cfg.Key.Signer).
		WithBatching(256, cfg.BatchAge).
		WithCheckpointInterval(cfg.CheckpointInterval).
		WithCheckpointRepublishInterval(cfg.CheckpointInterval).
		WithWitnesses(group, &tessera.WitnessOptions{Timeout: cfg.WitnessTimeout}) // FailOpen stays false
	app, shutdown, lr, err := tessera.NewAppender(actx, driver, opts)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("ledger: opening the log: %w", err)
	}
	l.app, l.shutdown, l.lr, l.cancel = app, shutdown, lr, cancel
	return l, nil
}

// level is steps 1 and 2 of OpenLog.
func (l *Log) level(ctx context.Context, st *posix.Storage, chain Chain) error {
	mw, lr, err := st.MigrationWriter(ctx, tessera.NewMigrationOptions())
	if err != nil {
		return fmt.Errorf("ledger: opening the volume: %w", err)
	}
	seq, _, err := chain.Head(ctx)
	if err != nil {
		return err
	}
	n := seq + 1
	have, err := mw.IntegratedSize(ctx)
	if err != nil {
		return fmt.Errorf("ledger: reading the volume: %w", err)
	}
	if int64(have) > n {
		return fmt.Errorf("%w: %d against %d", ErrChainBehind, have, n)
	}
	if err := auditEntries(ctx, lr.ReadEntryBundle, chain, 0, int64(have), int64(have)); err != nil {
		return err
	}
	if int64(have) == n {
		return nil
	}
	// Write the bundles that hold entries [have, n), from the chain.
	for idx := have / layout.EntryBundleWidth; idx*layout.EntryBundleWidth < uint64(n); idx++ {
		from := int64(idx * layout.EntryBundleWidth)
		to := min(from+layout.EntryBundleWidth, n)
		var bundle bytes.Buffer
		err := eachHash(ctx, chain, from, to, func(_ int64, h []byte) error {
			bundle.Write(binary.BigEndian.AppendUint16(nil, uint16(len(h))))
			bundle.Write(h)
			return nil
		})
		if err != nil {
			return err
		}
		if err := mw.SetEntryBundle(ctx, idx, layout.PartialTileSize(0, idx, uint64(n)), bundle.Bytes()); err != nil {
			return fmt.Errorf("ledger: writing entry bundle %d: %w", idx, err)
		}
	}
	got, err := mw.AwaitIntegration(ctx, uint64(n))
	if err != nil {
		return fmt.Errorf("ledger: integrating the chain into the volume: %w", err)
	}
	want, err := Roots(ctx, chain, n)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want[0]) {
		return fmt.Errorf("%w: the volume's root for %d records differs from the chain's", ErrRootMismatch, n)
	}
	return nil
}

// auditEntries compares the ledger's entries [from, to) of a log of size records with the chain's hashes.
func auditEntries(ctx context.Context, readBundle func(context.Context, uint64, uint8) ([]byte, error), chain Chain, from, to, size int64) error {
	for from < to {
		idx := uint64(from) / layout.EntryBundleWidth
		raw, err := readBundle(ctx, idx, layout.PartialTileSize(0, idx, uint64(size)))
		if err != nil {
			return fmt.Errorf("ledger: reading entry bundle %d: %w", idx, err)
		}
		var b api.EntryBundle
		if err := b.UnmarshalText(raw); err != nil {
			return fmt.Errorf("ledger: entry bundle %d: %w", idx, err)
		}
		base := int64(idx * layout.EntryBundleWidth)
		end := min(base+int64(len(b.Entries)), to)
		err = eachHash(ctx, chain, from, end, func(seq int64, h []byte) error {
			if e := b.Entries[seq-base]; !bytes.Equal(e, h) {
				return &AlteredRow{Seq: seq, Chain: hex.EncodeToString(h), Ledger: hex.EncodeToString(e)}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if end == from {
			return fmt.Errorf("ledger: entry bundle %d holds %d entries, fewer than the log's size", idx, len(b.Entries))
		}
		from = end
	}
	return nil
}

// Audit compares every entry the ledger holds with the chain's record hashes and returns *AlteredRow for the first
// record that differs.
func (l *Log) Audit(ctx context.Context, chain Chain) error {
	size, err := l.lr.IntegratedSize(ctx)
	if err != nil {
		return err
	}
	return auditEntries(ctx, l.lr.ReadEntryBundle, chain, 0, int64(size), int64(size))
}

// Checkpoint is a parsed, verified checkpoint.
type Checkpoint struct {
	Origin string
	Size   int64
	Root   []byte
	Note   []byte
	// Witnessed is true when the witness policy is satisfied by the countersignatures on the note.
	Witnessed bool
	// Cosigned are the names of the witnesses whose countersignature verified.
	Cosigned []string
}

// ParseCheckpoint verifies a checkpoint note: the log's signature under one of the log's keys (the one in use or a
// retired one) and the witnesses' countersignatures under the policy.
func (l *Log) ParseCheckpoint(raw []byte) (Checkpoint, error) {
	return parseCheckpoint(raw, l.verifier, l.origin, l.group)
}

func parseCheckpoint(raw []byte, verifiers []note.Verifier, origin string, group tessera.WitnessGroup) (Checkpoint, error) {
	n, err := note.Open(raw, note.VerifierList(verifiers...))
	if err != nil {
		return Checkpoint{}, fmt.Errorf("ledger: checkpoint: %w", err)
	}
	var cp f_log.Checkpoint
	if _, err := cp.Unmarshal([]byte(n.Text)); err != nil {
		return Checkpoint{}, fmt.Errorf("ledger: checkpoint: %w", err)
	}
	if cp.Origin != origin {
		return Checkpoint{}, fmt.Errorf("ledger: checkpoint of log %q, this is %q", cp.Origin, origin)
	}
	var logSigned bool
	var cosigned []string
	for _, s := range n.Sigs {
		if s.Name == origin {
			logSigned = true
		} else {
			cosigned = append(cosigned, s.Name)
		}
	}
	if !logSigned {
		return Checkpoint{}, errors.New("ledger: checkpoint: not signed by the log")
	}
	return Checkpoint{Origin: cp.Origin, Size: int64(cp.Size), Root: cp.Hash, Note: raw,
		Witnessed: group.Satisfied(raw), Cosigned: cosigned}, nil
}

// Latest is the checkpoint the log published last. ok is false when it has published none.
func (l *Log) Latest(ctx context.Context) (cp Checkpoint, ok bool, err error) {
	raw, err := l.lr.ReadCheckpoint(ctx)
	if errors.Is(err, os.ErrNotExist) {
		return Checkpoint{}, false, nil
	}
	if err != nil {
		return Checkpoint{}, false, err
	}
	cp, err = l.ParseCheckpoint(raw)
	return cp, err == nil, err
}

// Size is the number of entries the log holds, whether or not a checkpoint covers them yet.
func (l *Log) Size(ctx context.Context) (int64, error) {
	n, err := l.lr.NextIndex(ctx)
	return int64(n), err
}

// Add appends the hash of chain record seq, which must be the log's next entry, and waits until it is in the tree.
func (l *Log) Add(ctx context.Context, hashes [][]byte, first int64) error {
	futures := make([]tessera.IndexFuture, len(hashes))
	for i, h := range hashes {
		futures[i] = l.app.Add(ctx, tessera.NewEntry(h))
	}
	for i, f := range futures {
		idx, err := f()
		if err != nil {
			return fmt.Errorf("ledger: adding record %d: %w", first+int64(i), err)
		}
		if int64(idx.Index) != first+int64(i) {
			return fmt.Errorf("ledger: record %d was given index %d: the ledger and the chain have diverged", first+int64(i), idx.Index)
		}
	}
	return nil
}

// Proof is an inclusion proof of one chain record in a checkpoint.
type Proof struct {
	Seq        int64
	LeafHash   []byte   // the RFC 6962 leaf hash of the record's hash entry
	Hashes     [][]byte // the audit path
	Checkpoint Checkpoint
}

// Prove builds the inclusion proof of record seq against the latest checkpoint.
func (l *Log) Prove(ctx context.Context, seq int64, hash []byte) (Proof, error) {
	cp, ok, err := l.Latest(ctx)
	if err != nil {
		return Proof{}, err
	}
	if !ok || seq >= cp.Size {
		return Proof{}, fmt.Errorf("ledger: record %d is not under a published checkpoint yet", seq)
	}
	pb, err := client.NewProofBuilder(ctx, uint64(cp.Size), l.lr.ReadTile)
	if err != nil {
		return Proof{}, err
	}
	hs, err := pb.InclusionProof(ctx, uint64(seq))
	if err != nil {
		return Proof{}, err
	}
	return Proof{Seq: seq, LeafHash: rfc6962.DefaultHasher.HashLeaf(hash), Hashes: hs, Checkpoint: cp}, nil
}

// VerifyProof checks that the proof's leaf is entry seq of the tree the checkpoint commits to.
func VerifyProof(p Proof) error {
	return proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(p.Seq), uint64(p.Checkpoint.Size), p.LeafHash, p.Hashes, p.Checkpoint.Root)
}

// Close stops the checkpoint cadence and closes the appender.
func (l *Log) Close(ctx context.Context) error {
	err := l.shutdown(ctx)
	l.cancel()
	return err
}
