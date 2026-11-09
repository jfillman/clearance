package packet

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/ledger"
	"github.com/jfillman/clearance/internal/store"
)

const pageSize = 500

// chain is the evidence chain read once, verified from genesis: every record, and its hash as an entry of the ledger's
// tree. The job holds it in memory; a packet is a batch job, not a request.
type chain struct {
	records []Record
	hashes  [][]byte
	head    evidence.Checkpoint
}

func readChain(ctx context.Context, r store.Reader) (*chain, error) {
	c := &chain{}
	v := evidence.NewVerifier()
	for from := int64(0); ; {
		recs, err := r.Records(ctx, from, pageSize)
		if err != nil {
			return nil, fmt.Errorf("packet: reading the chain: %w", err)
		}
		if len(recs) == 0 {
			break
		}
		for _, rec := range recs {
			if err := v.Add(rec); err != nil {
				return nil, fmt.Errorf("packet: the chain does not verify: %w", err)
			}
			h, err := hex.DecodeString(str(rec, "hash"))
			if err != nil || len(h) != 32 {
				return nil, fmt.Errorf("packet: record %d has no 32-byte hash", seqOf(rec))
			}
			c.records = append(c.records, rec)
			c.hashes = append(c.hashes, h)
		}
		from += int64(len(recs))
		if len(recs) < pageSize {
			break
		}
	}
	c.head = v.Checkpoint()
	return c, nil
}

// checkpointReader is the part of a store that keeps the ledger's latest witnessed checkpoint (store/pg's Reader, and
// the in-memory store).
type checkpointReader interface {
	LedgerCheckpoint(ctx context.Context) (store.LedgerCheckpoint, error)
}

// ledgerState is the ledger as read for the packet.
type ledgerState struct {
	Ledger
	cp      *store.LedgerCheckpoint
	tree    *ledger.Tree
	logKeys string
	policy  string
	raw     []byte
}

func readLedger(ctx context.Context, r store.Reader, c *chain, p Params) (*ledgerState, error) {
	ls := &ledgerState{Ledger: Ledger{State: "off"}}
	cr, ok := r.(checkpointReader)
	if !ok {
		return ls, nil
	}
	cp, err := cr.LedgerCheckpoint(ctx)
	if errors.Is(err, store.ErrNotFound) {
		ls.State = "no-checkpoint"
		return ls, nil
	}
	if err != nil {
		return nil, fmt.Errorf("packet: reading the ledger checkpoint: %w", err)
	}
	if cp.Size > int64(len(c.hashes)) {
		return nil, fmt.Errorf("packet: the ledger checkpoint covers %d records, the chain holds %d", cp.Size, len(c.hashes))
	}
	tree := ledger.NewTree(c.hashes)
	root, err := tree.Root(cp.Size)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(root) != cp.Root {
		return nil, fmt.Errorf("packet: the chain's first %d records hash to %x, the witnessed checkpoint says %s: the chain and the ledger have diverged",
			cp.Size, root, cp.Root)
	}
	ls.cp, ls.tree, ls.raw = &cp, tree, cp.Note
	ls.State, ls.Origin, ls.Size, ls.Root = "checkpointed", cp.Origin, cp.Size, cp.Root
	if len(p.LogKeys) > 0 {
		var vs []note.Verifier
		for _, k := range p.LogKeys {
			v, err := f_note.NewVerifier(strings.TrimSpace(k))
			if err != nil {
				return nil, errors.New("packet: a log key is not a signed-note verifier key")
			}
			vs = append(vs, v)
		}
		parsed, err := ledger.ParseCheckpointNote(cp.Note, vs, p.WitnessPolicy)
		if err != nil {
			return nil, fmt.Errorf("packet: the checkpoint does not verify under the keys given: %w", err)
		}
		if parsed.Size != cp.Size || hex.EncodeToString(parsed.Root) != cp.Root {
			return nil, errors.New("packet: the checkpoint note and the store's checkpoint row disagree")
		}
		ls.SignaturesChecked, ls.Witnessed, ls.Cosigned = true, parsed.Witnessed, parsed.Cosigned
		ls.logKeys = strings.Join(p.LogKeys, "\n") + "\n"
		ls.policy = string(p.WitnessPolicy)
	}
	return ls, nil
}

// assurance is the record's assurance state: checkpointed once a witnessed checkpoint covers its seq (store.Ledger's
// PutLedgerCheckpoint marks exactly the records below the checkpoint's size), else recorded-not-checkpointed.
func (ls *ledgerState) assurance(seq int64) string {
	if ls.cp != nil && seq < ls.cp.Size {
		return store.AssuranceCheckpointed
	}
	return store.AssuranceRecorded
}
