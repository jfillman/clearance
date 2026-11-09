package packet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/ledger"
	"github.com/jfillman/clearance/internal/store"
)

// Files of the packet an offline verifier reads (relative to the packet directory).
const (
	FileRecords     = "evidence/records.jsonl"
	FileProofs      = "evidence/proofs.json"
	FileCheckpoint  = "ledger/checkpoint.txt"
	FileLogKeys     = "ledger/log-keys.txt"
	FilePolicy      = "ledger/witness-policy.txt"
	DirAttestations = "attestations"
	FileOSCAL       = "oscal/component-definition.json"
)

// carry picks the records the packet carries in full: every record from the first to the last in the window (so the
// chain's prev_hash links between them can be rechecked), and, beside them, the records outside that range the
// packet's statements read (the last health record before the window of each feed, and the assessments and
// resolutions of the window's observations), so a verifier can rebuild the coverage statement from the file alone.
func (b *builder) carry(ctx context.Context, res *Result, lo, hi int64) {
	seqs := map[int64]bool{}
	if lo >= 0 {
		for s := lo; s <= hi; s++ {
			seqs[s] = true
		}
	}
	lastHealth := map[string]int64{}
	for _, r := range b.c.records {
		tool, seq := str(r, "tool"), seqOf(r)
		if !isObserved(tool) || !b.scopeWanted(str(r, "scope")) {
			continue
		}
		if len(b.p.Scopes) == 0 && !contains(b.scopes, str(r, "scope")) {
			continue
		}
		switch tool {
		case evidence.KindHealth:
			if b.ts(r) < b.from {
				lastHealth[str(r, "scope")+"\x00"+str(obj(r, "source"), "name")] = seq
			}
		case evidence.KindAssessment, evidence.KindResolution:
			if a, ok := aboutSeq(r); ok && b.inWin[a] {
				seqs[seq] = true
			}
		}
	}
	for _, s := range lastHealth {
		seqs[s] = true
	}
	for s := range b.extra {
		seqs[s] = true
	}
	order := make([]int64, 0, len(seqs))
	for s := range seqs {
		order = append(order, s)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	for _, s := range order {
		res.Records = append(res.Records, b.c.records[s])
	}
	res.Packet.Header.Chain.Carried = len(res.Records)
}

func aboutSeq(r Record) (int64, bool) {
	return num(obj(r, "about")["seq"])
}

// verification fills the Verification section and the proofs, bundles and ledger files that back it.
func (b *builder) verification(ctx context.Context, pk *Packet, res *Result) {
	v := Verification{Records: FileRecords, Ledger: b.ls.Ledger}
	v.Chain = fmt.Sprintf("The job read and verified the chain from genesis: %d records, head %s. Every stored record is carried in %s as it was hashed, so its hash can be recomputed.",
		b.c.head.Count, b.c.head.Head, FileRecords)
	l := &v.Ledger
	for _, r := range res.Records {
		if b.ls.assurance(seqOf(r)) == store.AssuranceCheckpointed {
			l.Checkpointed++
		} else {
			l.NotCheckpointed++
		}
	}
	if b.ls.cp != nil {
		res.Checkpoint = b.ls.raw
		l.CheckpointFile = FileCheckpoint
		if b.ls.logKeys != "" {
			res.LogKeys, l.LogKeysFile = []byte(b.ls.logKeys), FileLogKeys
		}
		if b.ls.policy != "" {
			res.WitnessPolicy, l.WitnessPolicyFile = []byte(b.ls.policy), FilePolicy
		}
		for _, r := range res.Records {
			seq := seqOf(r)
			if seq >= b.ls.cp.Size {
				continue
			}
			path, err := b.ls.tree.Prove(seq, b.ls.cp.Size)
			if err == nil {
				err = ledger.VerifyInclusion(seq, b.ls.cp.Size, b.c.hashes[seq], path, rootBytes(b.ls.cp.Root))
			}
			if err != nil {
				// The packet is not issued with a proof that does not verify.
				b.proofErr = errors.Join(b.proofErr, fmt.Errorf("record %d: %w", seq, err))
				continue
			}
			pe := ProofEntry{Seq: seq, Hash: hex.EncodeToString(b.c.hashes[seq]), LeafHash: hex.EncodeToString(b.ls.tree.LeafHash(seq)), TreeSize: b.ls.cp.Size}
			for _, h := range path {
				pe.Path = append(pe.Path, hex.EncodeToString(h))
			}
			res.Proofs = append(res.Proofs, pe)
		}
		l.ProofsCarried = len(res.Proofs)
		v.Proofs = FileProofs
	}
	// Attestation bundles.
	for i := range pk.Changes {
		c := &pk.Changes[i]
		if c.Attestation == nil || !isChangeID(c.ID) {
			continue
		}
		at, err := b.r.Attestation(ctx, c.ID)
		if err != nil || len(at.Bundle) == 0 {
			v.AttestationsMissing = append(v.AttestationsMissing, c.ID)
			continue
		}
		var raw json.RawMessage = at.Bundle
		res.Bundles[c.ID] = raw
		c.Attestation.Bundle = DirAttestations + "/" + c.ID + ".json"
		v.Attestations++
	}
	if v.Attestations > 0 || len(v.AttestationsMissing) > 0 {
		v.AttestationDir = DirAttestations
	}
	v.Statement = b.verificationWords(v, len(res.Records))
	pk.Verification = v
}

func rootBytes(h string) []byte { r, _ := hex.DecodeString(h); return r }

func isChangeID(s string) bool {
	if len(s) != 19 || s[:3] != "ch-" {
		return false
	}
	_, err := hex.DecodeString(s[3:])
	return err == nil
}

func (b *builder) verificationWords(v Verification, carried int) string {
	l := v.Ledger
	switch {
	case b.ls.cp == nil:
		return "NOT CHECKPOINTED. This deployment's evidence ledger is off, or has not published a witnessed checkpoint, so every record in this packet is " +
			store.AssuranceRecorded + ". The records are linked in a hash chain, verified from genesis by this job, which shows the records are consistent with one another; " +
			"no independent witness has seen the chain, so it does not show the chain was not rewritten as a whole. No inclusion proofs or checkpoint are carried."
	default:
		s := fmt.Sprintf("A witnessed checkpoint of %d records (root %s, log %s) covers %d of the %d records carried; each of those has an inclusion proof in %s, built from the chain's record hashes (the log volume is a cache of the chain and is not served over HTTP).",
			l.Size, l.Root, l.Origin, l.Checkpointed, carried, FileProofs)
		if l.NotCheckpointed > 0 {
			s += fmt.Sprintf(" %d carried records come after the checkpoint: they are %s, chained but not yet seen by a witness.", l.NotCheckpointed, store.AssuranceRecorded)
		}
		if l.SignaturesChecked {
			s += fmt.Sprintf(" The job checked the checkpoint's signatures under the log keys it was given; cosigned by %v, witness policy satisfied: %v.", l.Cosigned, l.Witnessed)
		} else {
			s += " The job was not given the log's public keys, so the checkpoint's signatures were NOT checked here; the note is carried for the verifier to check under keys it trusts."
		}
		return s
	}
}
