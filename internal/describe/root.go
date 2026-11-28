package describe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/jfillman/clearance/internal/canon"
)

// Root functions. A subject kind declares one, the description and the record name it, and a kind changes its root
// function only through a new kind version: a recorded root never changes meaning.
const (
	// RootMerkle1 is the root of every new kind: sha256("clearance.subject/v1" ‖ M ‖ F), M the RFC 6962 Merkle tree
	// hash over the sorted item digests and F the sha256 of the canonical facts ({} when there are none). The core
	// recomputes it from the description, and one item's inclusion can be proved against it (ProveItem).
	RootMerkle1 = "merkle/1"
	// RootTree1 is manifest-tree's: the manifest-tree digest of the whole rendered tree, as before (Tree1). The items of
	// a manifest-tree description are the objects the change touches, not the tree, so the core cannot recompute the
	// root from them: it is the verifier's, recorded as claimed, as it always was.
	RootTree1 = "tree/1"
	// RootPlan1 is terraform-plan's: the sha256 of the saved plan file (planDigest), as before (Plan1). The core holds
	// no plan file, so the root is the verifier's.
	RootPlan1 = "plan/1"
)

// RootFns are the root functions this core knows.
var RootFns = []string{RootMerkle1, RootTree1, RootPlan1}

// SubjectDomain is merkle/1's domain separator, the first bytes hashed into every merkle/1 root.
const SubjectDomain = "clearance.subject/v1"

// Computable says whether the core can recompute a root function's root from a description alone.
func Computable(rootFn string) bool { return rootFn == RootMerkle1 }

// ItemDigest is one item's merkle/1 digest: sha256 of the canonical JSON of the item with all six members present
// ({"attrs": {}, "fields": [], "hash": "", "id", "op", "type"} when empty), so that an absent and an empty member
// hash the same in every language.
func ItemDigest(it Item) ([]byte, error) {
	fields := make([]any, 0, len(it.Fields))
	for _, f := range it.Fields {
		fields = append(fields, f)
	}
	attrs := it.Attrs
	if attrs == nil {
		attrs = map[string]any{}
	}
	w, err := wire(attrs)
	if err != nil {
		return nil, fmt.Errorf("describe: item %s %q: %w", it.Type, it.ID, err)
	}
	c, err := canon.Canonical(map[string]any{"type": it.Type, "id": it.ID, "op": it.Op, "fields": fields,
		"attrs": w, "hash": it.Hash})
	if err != nil {
		return nil, fmt.Errorf("describe: item %s %q: %w", it.Type, it.ID, err)
	}
	s := sha256.Sum256(c)
	return s[:], nil
}

// FactsDigest is F: sha256 of the canonical facts, or of {} when there are none.
func FactsDigest(facts map[string]any) ([]byte, error) {
	if facts == nil {
		facts = map[string]any{}
	}
	w, err := wire(facts)
	if err != nil {
		return nil, fmt.Errorf("describe: facts: %w", err)
	}
	c, err := canon.Canonical(w)
	if err != nil {
		return nil, fmt.Errorf("describe: facts: %w", err)
	}
	s := sha256.Sum256(c)
	return s[:], nil
}

// sortedDigests are the items' digests in byte order, the leaves of M. Two items with one digest are refused: the
// same item twice.
func sortedDigests(items []Item) ([][]byte, error) {
	ds := make([][]byte, 0, len(items))
	for _, it := range items {
		d, err := ItemDigest(it)
		if err != nil {
			return nil, err
		}
		ds = append(ds, d)
	}
	sort.Slice(ds, func(i, j int) bool { return bytes.Compare(ds[i], ds[j]) < 0 })
	for i := 1; i < len(ds); i++ {
		if bytes.Equal(ds[i-1], ds[i]) {
			return nil, bad("an item is listed twice")
		}
	}
	return ds, nil
}

// mth is RFC 6962's Merkle tree hash over leaf hashes (section 2.1): the empty tree is sha256 of nothing, one leaf is
// itself, and n > 1 splits at the largest power of two below n.
func mth(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		return rfc6962.DefaultHasher.EmptyRoot()
	case 1:
		return leaves[0]
	}
	k := splitPoint(len(leaves))
	return rfc6962.DefaultHasher.HashChildren(mth(leaves[:k]), mth(leaves[k:]))
}

func splitPoint(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func leafHashes(digests [][]byte) [][]byte {
	out := make([][]byte, len(digests))
	for i, d := range digests {
		out[i] = rfc6962.DefaultHasher.HashLeaf(d)
	}
	return out
}

// ItemsRoot is M: the RFC 6962 Merkle tree hash over the sorted item digests (each an RFC 6962 leaf).
func ItemsRoot(items []Item) ([]byte, error) {
	ds, err := sortedDigests(items)
	if err != nil {
		return nil, err
	}
	return mth(leafHashes(ds)), nil
}

func subjectRoot(m, f []byte) string {
	h := sha256.New()
	h.Write([]byte(SubjectDomain))
	h.Write(m)
	h.Write(f)
	return hex.EncodeToString(h.Sum(nil))
}

// Merkle1 is the merkle/1 root of items and facts.
func Merkle1(items []Item, facts map[string]any) (string, error) {
	m, err := ItemsRoot(items)
	if err != nil {
		return "", err
	}
	f, err := FactsDigest(facts)
	if err != nil {
		return "", err
	}
	return subjectRoot(m, f), nil
}

// TreeEntry is one rendered object in a manifest tree: its key and its object digest (internal/gate/render
// ObjectDigest).
type TreeEntry struct {
	APIVersion, Kind, Namespace, Name string
	Digest                            string
}

// Tree1 is the tree/1 root, the manifest-tree digest (docs/gate.md, "The manifest-tree digest"), unchanged: one line
// per object, "apiVersion/kind/namespace/name:" and its object digest (namespace empty when the object has none),
// the lines sorted byte-wise and joined with "\n" (no trailing newline), and the lowercase hex sha256 of that.
func Tree1(entries []TreeEntry) string {
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		lines = append(lines, strings.Join([]string{e.APIVersion, e.Kind, e.Namespace, e.Name}, "/")+":"+e.Digest)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// Plan1 is the plan/1 root: the lowercase hex sha256 of the saved plan file, the planDigest a Terraform gate sends.
func Plan1(planFile []byte) string {
	sum := sha256.Sum256(planFile)
	return hex.EncodeToString(sum[:])
}

// VerifyRoot checks the subject's root against its root function: a merkle/1 root is recomputed from the items and
// facts and must match (ErrRootMismatch); a tree/1 or plan/1 root is carried, and checked only for its form, because
// it is the digest of something the description does not hold. computed says which.
func (d *Description) VerifyRoot() (computed bool, err error) {
	switch d.Subject.RootFn {
	case RootMerkle1:
		r, err := Merkle1(d.Items, d.Subject.Facts)
		if err != nil {
			return true, err
		}
		if r != d.Subject.Root {
			return true, ErrRootMismatch
		}
		return true, nil
	case RootTree1, RootPlan1:
		if !IsSHA256(d.Subject.Root) {
			return false, bad("subject.root is a bare lowercase hex sha256")
		}
		return false, nil
	}
	return false, bad("subject.rootFn %q is not a root function this core knows (%s)", d.Subject.RootFn, strings.Join(RootFns, ", "))
}

// Inclusion proves one item is in a merkle/1 root: the item's leaf index among the sorted digests, the tree size, the
// RFC 6962 audit path, and F, the facts digest, which closes the root. A platform that enforces per item (admission)
// checks one with VerifyItem against the cleared root, holding only the item and the proof.
type Inclusion struct {
	Index       uint64   `json:"index"`
	Size        uint64   `json:"size"`
	Path        []string `json:"path"`
	FactsDigest string   `json:"factsDigest"`
}

// ProveItem is the inclusion proof of d.Items[i] in d's merkle/1 root. A description whose root is not its items' and
// facts' is ErrRootMismatch: no proof is made against a root it would not verify against.
func (d *Description) ProveItem(i int) (Inclusion, error) {
	if d.Subject.RootFn != RootMerkle1 {
		return Inclusion{}, bad("only a merkle/1 root has item inclusion proofs (this is %s)", d.Subject.RootFn)
	}
	if i < 0 || i >= len(d.Items) {
		return Inclusion{}, bad("no item %d", i)
	}
	ds, err := sortedDigests(d.Items)
	if err != nil {
		return Inclusion{}, err
	}
	want, err := ItemDigest(d.Items[i])
	if err != nil {
		return Inclusion{}, err
	}
	idx := sort.Search(len(ds), func(j int) bool { return bytes.Compare(ds[j], want) >= 0 })
	f, err := FactsDigest(d.Subject.Facts)
	if err != nil {
		return Inclusion{}, err
	}
	if subjectRoot(mth(leafHashes(ds)), f) != d.Subject.Root {
		return Inclusion{}, ErrRootMismatch // the items or facts changed since the root was computed
	}
	path := auditPath(idx, leafHashes(ds))
	inc := Inclusion{Index: uint64(idx), Size: uint64(len(ds)), Path: make([]string, len(path)), FactsDigest: hex.EncodeToString(f)}
	for j, p := range path {
		inc.Path[j] = hex.EncodeToString(p)
	}
	return inc, nil
}

// auditPath is RFC 6962's PATH(m, D[n]) (section 2.1.1), leaf to root.
func auditPath(m int, leaves [][]byte) [][]byte {
	n := len(leaves)
	if n <= 1 {
		return nil
	}
	k := splitPoint(n)
	if m < k {
		return append(auditPath(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(auditPath(m-k, leaves[k:]), mth(leaves[:k]))
}

// VerifyItem checks that item is in the merkle/1 root by its inclusion proof.
func VerifyItem(root string, item Item, inc Inclusion) error {
	d, err := ItemDigest(item)
	if err != nil {
		return err
	}
	path := make([][]byte, len(inc.Path))
	for i, p := range inc.Path {
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != sha256.Size {
			return bad("inclusion path[%d] is a sha256", i)
		}
		path[i] = b
	}
	f, err := hex.DecodeString(inc.FactsDigest)
	if err != nil || len(f) != sha256.Size {
		return bad("inclusion factsDigest is a sha256")
	}
	m, err := proof.RootFromInclusionProof(rfc6962.DefaultHasher, inc.Index, inc.Size, rfc6962.DefaultHasher.HashLeaf(d), path)
	if err != nil {
		return fmt.Errorf("describe: %w", err)
	}
	if subjectRoot(m, f) != root {
		return ErrRootMismatch
	}
	return nil
}
