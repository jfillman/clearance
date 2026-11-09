package ledger

import (
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"golang.org/x/mod/sumdb/note"
)

// The offline half of the ledger (C-5): what a reader holding the chain's record hashes, and no log volume, can do.
//
// The log is a Tessera tile volume that is a cache of the chain (OpenLog rebuilds it from the record hashes), and it
// is not served over HTTP: Log.Prove works only in the process that has the volume open. Entry i of the tree is the
// hash of chain record i, so the same tree, and so the same RFC 6962 inclusion proof against the same witnessed
// checkpoint, can be built from the hashes alone. The evidence packet does that.

// ParseCheckpointNote verifies a checkpoint note without a log: the log's signature under one of logKeys (the key in
// use and any retired ones, all under the log's name, which is the checkpoint's origin) and the witnesses'
// countersignatures under policy (Tessera's text form; nil is a policy with no witness, so Witnessed is false).
func ParseCheckpointNote(raw []byte, logKeys []note.Verifier, policy []byte) (Checkpoint, error) {
	if len(logKeys) == 0 {
		return Checkpoint{}, errors.New("ledger: no log key to verify the checkpoint with")
	}
	var group tessera.WitnessGroup
	verifiers := append([]note.Verifier(nil), logKeys...)
	if len(policy) > 0 {
		g, err := tessera.NewWitnessGroupFromPolicy(policy)
		if err != nil {
			return Checkpoint{}, fmt.Errorf("ledger: the witness policy: %w", err)
		}
		group = g
		for _, v := range g.Endpoints() {
			verifiers = append(verifiers, v)
		}
	}
	cp, err := parseCheckpoint(raw, verifiers, logKeys[0].Name(), group)
	if err != nil {
		return cp, err
	}
	if len(policy) == 0 {
		cp.Witnessed = false
	}
	return cp, nil
}

// Tree is the Merkle tree of chain record hashes, held in memory, from which inclusion proofs are built.
type Tree struct {
	leaves [][]byte // RFC 6962 leaf hashes
	memo   map[[2]uint64][]byte
}

// NewTree builds the tree over entries: entries[i] is the 32-byte hash of chain record i.
func NewTree(entries [][]byte) *Tree {
	t := &Tree{leaves: make([][]byte, len(entries)), memo: map[[2]uint64][]byte{}}
	for i, e := range entries {
		t.leaves[i] = rfc6962.DefaultHasher.HashLeaf(e)
	}
	return t
}

// Size is the number of entries.
func (t *Tree) Size() int64 { return int64(len(t.leaves)) }

// LeafHash is the RFC 6962 leaf hash of entry seq.
func (t *Tree) LeafHash(seq int64) []byte { return t.leaves[seq] }

func (t *Tree) node(level uint, index uint64) []byte {
	if level == 0 {
		return t.leaves[index]
	}
	k := [2]uint64{uint64(level), index}
	if h, ok := t.memo[k]; ok {
		return h
	}
	h := rfc6962.DefaultHasher.HashChildren(t.node(level-1, 2*index), t.node(level-1, 2*index+1))
	t.memo[k] = h
	return h
}

// Root is the tree's root over its first size entries.
func (t *Tree) Root(size int64) ([]byte, error) {
	if size < 0 || size > t.Size() {
		return nil, fmt.Errorf("ledger: a root over %d entries, the tree holds %d", size, t.Size())
	}
	if size == 0 {
		return rfc6962.DefaultHasher.EmptyRoot(), nil
	}
	rf := compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	rng := rf.NewEmptyRange(0)
	for i := int64(0); i < size; i++ {
		if err := rng.Append(t.leaves[i], nil); err != nil {
			return nil, err
		}
	}
	return rng.GetRootHash(nil)
}

// Prove is the inclusion proof of entry seq in the tree of the first size entries (RFC 6962 audit path), which
// VerifyProof checks against a checkpoint of that size.
func (t *Tree) Prove(seq, size int64) ([][]byte, error) {
	if seq < 0 || seq >= size || size > t.Size() {
		return nil, fmt.Errorf("ledger: no inclusion proof of entry %d in a tree of %d (the tree holds %d)", seq, size, t.Size())
	}
	nodes, err := proof.Inclusion(uint64(seq), uint64(size))
	if err != nil {
		return nil, err
	}
	hs := make([][]byte, len(nodes.IDs))
	for i, id := range nodes.IDs {
		hs[i] = t.node(id.Level, id.Index)
	}
	return nodes.Rehash(hs, rfc6962.DefaultHasher.HashChildren)
}

// VerifyInclusion checks that leaf (the hash of chain record seq) is entry seq of the tree of size entries with the
// given root: what an offline verifier runs on a packet's proof.
func VerifyInclusion(seq, size int64, entryHash []byte, hashes [][]byte, root []byte) error {
	return proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(seq), uint64(size), rfc6962.DefaultHasher.HashLeaf(entryHash), hashes, root)
}
