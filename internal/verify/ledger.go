package verify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	f_log "github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"golang.org/x/mod/sumdb/note"
)

// checkpoint is a C2SP checkpoint as the verifier has it.
type checkpoint struct {
	raw      []byte
	origin   string
	size     int64
	root     []byte
	cosigned []string
}

// proofsDoc is evidence/proofs.json.
type proofsDoc struct {
	Schema   string `json:"schema"`
	Origin   string `json:"origin"`
	TreeSize int64  `json:"tree_size"`
	Root     string `json:"root"`
	Proofs   []struct {
		Seq      int64    `json:"seq"`
		Hash     string   `json:"hash"`
		LeafHash string   `json:"leaf_hash"`
		Path     []string `json:"path"`
		TreeSize int64    `json:"tree_size"`
	} `json:"proofs"`
}

// material picks a trust input: the user's, else the packet's own copy.
func (c *ctx) material(supplied []byte, packetFile string) (b []byte, t trust) {
	if len(supplied) > 0 {
		return supplied, trustSupplied
	}
	if b, err := c.read(packetFile); err == nil && len(bytes.TrimSpace(b)) > 0 {
		return b, trustPacket
	}
	return nil, trustNone
}

func trustWords(t trust) string {
	switch t {
	case trustSupplied:
		return "keys you supplied"
	case trustPacket:
		return "TAKEN FROM THE PACKET ITSELF: a packet vouching for its own keys proves nothing"
	}
	return "no key available"
}

func statusFor(t trust) Status {
	switch t {
	case trustSupplied:
		return Pass
	case trustPacket:
		return SelfVouched
	}
	return NotChecked
}

func parseVKeys(raw []byte) ([]note.Verifier, error) {
	var out []note.Verifier
	for i, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		v, err := f_note.NewVerifier(line)
		if err != nil {
			return nil, fmt.Errorf("key list line %d is not a signed-note verifier key", i+1)
		}
		out = append(out, v)
	}
	return out, nil
}

// ledgerCheck verifies the checkpoint (the log's signature, the witnesses' countersignatures) and every inclusion
// proof, or reports honestly that the packet has no witnessed checkpoint.
func (c *ctx) ledgerCheck() {
	claims := c.exists(fileProofs)
	if p := c.pk; p != nil {
		l := p.Verification.Ledger
		claims = claims || l.State == "checkpointed" || l.CheckpointFile != "" || p.Verification.Proofs != ""
	}
	if !c.exists(fileCheckpoint) {
		if claims {
			c.rep.add(Check{Name: "ledger checkpoint", Status: Fail, Detail: "the packet says it has a witnessed checkpoint (or carries proofs for one) and the checkpoint file is missing: " +
				"a checkpoint removed to make the packet look unwitnessed, or a packet cut short"})
			return
		}
		detail := "this packet has no witnessed checkpoint, so no independent witness has seen the chain these records are on. " +
			"The records are linked in a hash chain (checked above), which shows they are consistent with one another; it does not show the chain was not rewritten as a whole. " +
			"This is NOT a pass of the witness check, and no inclusion proof or countersignature was checked because none exists."
		c.rep.add(Check{Name: "ledger checkpoint and witnesses", Status: NotCheckpointed, Detail: detail})
		return
	}
	if p := c.pk; p != nil && p.Verification.Ledger.State != "checkpointed" {
		c.rep.add(Check{Name: "ledger checkpoint", Status: Fail, Detail: fmt.Sprintf("the packet carries a checkpoint and says its ledger state is %q", p.Verification.Ledger.State)})
		return
	}
	raw, err := c.read(fileCheckpoint)
	if err != nil {
		c.rep.add(Check{Name: "ledger checkpoint", Status: Fail, Detail: err.Error()})
		return
	}
	keysRaw, kt := c.material(c.opts.LogKeys, fileLogKeys)
	polRaw, pt := c.material(c.opts.WitnessPolicy, filePolicy)
	vs, err := parseVKeys(keysRaw)
	if err != nil {
		c.rep.add(Check{Name: "ledger checkpoint", Status: Fail, Trust: trustWords(kt), Detail: "the log keys: " + err.Error()})
		return
	}

	sig := Check{Name: "ledger: checkpoint signed by the log", Trust: trustWords(kt)}
	wit := Check{Name: "ledger: witness countersignatures", Trust: trustWords(pt)}
	var cp checkpoint
	if len(vs) == 0 {
		// No key to authenticate it with: read what it states, so the proofs can still be checked against it.
		cp, err = statedCheckpoint(raw)
		if err != nil {
			c.rep.add(Check{Name: "ledger checkpoint", Status: Fail, Detail: err.Error()})
			return
		}
		sig.Status, sig.Detail = NotChecked, "no log key was supplied and the packet carries none: the checkpoint's signature cannot be checked"
		wit.Status, wit.Detail = NotChecked, "the checkpoint is not authenticated, so its countersignatures cannot be either"
		c.cpTrust = trustNone
	} else {
		var group tessera.WitnessGroup
		verifiers := append([]note.Verifier(nil), vs...)
		havePolicy := len(bytes.TrimSpace(polRaw)) > 0
		if havePolicy {
			group, err = tessera.NewWitnessGroupFromPolicy(polRaw)
			if err != nil {
				c.rep.add(Check{Name: "ledger: witness policy", Status: Fail, Trust: trustWords(pt), Detail: "the witness policy does not parse: " + err.Error()})
				return
			}
			for _, v := range group.Endpoints() {
				verifiers = append(verifiers, v)
			}
		}
		// Whatever the signatures say, the checkpoint's stated size lets the figures be recounted without noise.
		if st, serr := statedCheckpoint(raw); serr == nil {
			c.cp = &st
		}
		n, err := note.Open(raw, note.VerifierList(verifiers...))
		if err != nil {
			sig.Status, sig.Detail = Fail, "the checkpoint does not verify under the log keys: "+err.Error()+
				". It was altered, or signed by a key that is not one of the log's (a key list that lacks a retired key fails here too)."
			c.rep.add(sig)
			return
		}
		var parsed f_log.Checkpoint
		if _, err := parsed.Unmarshal([]byte(n.Text)); err != nil {
			sig.Status, sig.Detail = Fail, "the signed text is not a checkpoint: "+err.Error()
			c.rep.add(sig)
			return
		}
		logSigned := false
		for _, v := range vs {
			if v.Name() == parsed.Origin {
				for _, s := range n.Sigs {
					if s.Name == parsed.Origin {
						logSigned = true
					}
				}
			}
		}
		if !logSigned {
			sig.Status, sig.Detail = Fail, fmt.Sprintf("the checkpoint is of log %q and no signature by a log key you gave verifies (after a key rotation, list the retired keys after the one in use)", parsed.Origin)
			c.rep.add(sig)
			return
		}
		cp = checkpoint{raw: raw, origin: parsed.Origin, size: int64(parsed.Size), root: parsed.Hash}
		for _, s := range n.Sigs {
			if s.Name != parsed.Origin {
				cp.cosigned = append(cp.cosigned, s.Name)
			}
		}
		sig.Status = statusFor(kt)
		sig.Detail = fmt.Sprintf("log %q, %d records, root %s", cp.origin, cp.size, hex.EncodeToString(cp.root))
		c.cpTrust = kt
		switch {
		case !havePolicy && len(cp.cosigned) == 0:
			wit.Status, wit.Detail, wit.Trust = NotChecked, "no witness policy was supplied and the packet carries none; the checkpoint carries no countersignature this verifier can check", "no policy available"
		case !havePolicy:
			wit.Status, wit.Detail, wit.Trust = NotChecked, "no witness policy was supplied and the packet carries none, so the countersignatures cannot be judged", "no policy available"
		case len(cp.cosigned) == 0 || !group.Satisfied(raw):
			wit.Status = Fail
			wit.Detail = fmt.Sprintf("WITNESS POLICY NOT SATISFIED: %d countersignature(s) verified (%s). A checkpoint signed by the log alone is exactly what a truncated or re-signed log looks like: "+
				"a witness that has seen the real log refuses to countersign it. Treat this checkpoint as unwitnessed.", len(cp.cosigned), strings.Join(cp.cosigned, ", "))
		default:
			wit.Status = statusFor(pt)
			wit.Detail = fmt.Sprintf("witness policy satisfied by %s", strings.Join(cp.cosigned, ", "))
		}
		if p := c.pk; p != nil && p.Verification.Ledger.Witnessed && wit.Status == Fail {
			wit.Findings = append(wit.Findings, "the packet states the policy was satisfied; it is not")
		}
	}
	c.cp = &cp
	c.rep.add(sig)
	c.rep.add(wit)
	c.crossCheckLedger(cp)
	c.proofsCheck(cp)
}

// statedCheckpoint reads what a checkpoint note says without authenticating it.
func statedCheckpoint(raw []byte) (checkpoint, error) {
	i := bytes.LastIndex(raw, []byte("\n\n— "))
	if i < 0 {
		return checkpoint{}, errors.New("the checkpoint file is not a signed note")
	}
	var p f_log.Checkpoint
	if _, err := p.Unmarshal(raw[:i+1]); err != nil {
		return checkpoint{}, errors.New("the checkpoint file is not a checkpoint: " + err.Error())
	}
	return checkpoint{raw: raw, origin: p.Origin, size: int64(p.Size), root: p.Hash}, nil
}

// crossCheckLedger: the packet's own statement of its ledger agrees with the checkpoint.
func (c *ctx) crossCheckLedger(cp checkpoint) {
	p := c.pk
	if p == nil {
		return
	}
	l := p.Verification.Ledger
	var bad []string
	if l.Origin != cp.origin {
		bad = append(bad, fmt.Sprintf("packet.json says the log is %q, the checkpoint says %q", l.Origin, cp.origin))
	}
	if l.Size != cp.size {
		bad = append(bad, fmt.Sprintf("packet.json says the checkpoint covers %d records, the checkpoint says %d", l.Size, cp.size))
	}
	if l.Root != hex.EncodeToString(cp.root) {
		bad = append(bad, "packet.json states a different checkpoint root than the checkpoint file")
	}
	if len(bad) > 0 {
		c.rep.add(Check{Name: "ledger: packet.json agrees with the checkpoint", Status: Fail, Findings: bad, Detail: "the packet's description of its checkpoint is not the checkpoint"})
	}
}

// proofsCheck checks every carried record under the checkpoint against its root, and that none is missing a proof.
func (c *ctx) proofsCheck(cp checkpoint) {
	chk := Check{Name: "ledger: inclusion proofs", Trust: trustWords(c.cpTrust)}
	raw, err := c.read(fileProofs)
	if err != nil {
		chk.Status, chk.Detail = Fail, fileProofs+" cannot be read: "+err.Error()
		c.rep.add(chk)
		return
	}
	var pd proofsDoc
	if err := json.Unmarshal(raw, &pd); err != nil {
		chk.Status, chk.Detail = Fail, fileProofs+" is not readable: "+err.Error()
		c.rep.add(chk)
		return
	}
	var bad []string
	if pd.Origin != cp.origin || pd.TreeSize != cp.size || pd.Root != hex.EncodeToString(cp.root) {
		bad = append(bad, "proofs.json describes a different checkpoint (origin, size or root) than the checkpoint file")
	}
	bySeq := map[int64]*rec{}
	for i := range c.recs {
		bySeq[c.recs[i].seq] = &c.recs[i]
	}
	have := map[int64]bool{}
	verified := 0
	for _, e := range pd.Proofs {
		r := bySeq[e.Seq]
		switch {
		case r == nil:
			bad = append(bad, fmt.Sprintf("a proof for seq %d, which the packet does not carry", e.Seq))
			continue
		case e.Seq >= cp.size:
			bad = append(bad, fmt.Sprintf("a proof for seq %d, which is past the checkpoint (%d records)", e.Seq, cp.size))
			continue
		case have[e.Seq]:
			bad = append(bad, fmt.Sprintf("seq %d has two proofs", e.Seq))
			continue
		case e.TreeSize != cp.size:
			bad = append(bad, fmt.Sprintf("seq %d: its proof is for a tree of %d records, the checkpoint has %d", e.Seq, e.TreeSize, cp.size))
			continue
		case e.Hash != r.computed:
			bad = append(bad, fmt.Sprintf("seq %d: the log committed to hash %s and the record now hashes to %s: the record was changed after it was logged", e.Seq, short8(e.Hash), short8(r.computed)))
			continue
		}
		have[e.Seq] = true
		entry, _ := hex.DecodeString(r.computed)
		var path [][]byte
		ok := true
		for _, h := range e.Path {
			b, good := unhex32(h)
			ok = ok && good
			path = append(path, b)
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("seq %d: a hash in its proof is not a SHA-256", e.Seq))
			continue
		}
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(e.Seq), uint64(cp.size), rfc6962.DefaultHasher.HashLeaf(entry), path, cp.root); err != nil {
			bad = append(bad, fmt.Sprintf("seq %d: NOT under the checkpoint. The record, or its proof, is not what the log committed to (%v)", e.Seq, err))
			continue
		}
		verified++
	}
	after := 0
	for _, r := range c.recs {
		switch {
		case r.seq >= cp.size:
			after++
		case !have[r.seq]:
			bad = append(bad, fmt.Sprintf("seq %d is under the checkpoint and has no valid inclusion proof", r.seq))
		}
	}
	if len(bad) > 0 {
		chk.Status, chk.Detail, chk.Findings = Fail, fmt.Sprintf("%d problem(s)", len(bad)), bad
		c.rep.add(chk)
		return
	}
	chk.Status = statusFor(c.cpTrust)
	chk.Detail = fmt.Sprintf("%d records under the checkpoint (%d records) each prove into its root", verified, cp.size)
	if c.cpTrust == trustNone {
		chk.Detail += "; the root itself was not authenticated, so this shows only that the records match the checkpoint the packet states"
	}
	if after > 0 {
		chk.Findings = append(chk.Findings, fmt.Sprintf("%d carried record(s) come after the checkpoint: recorded-not-checkpointed, chained but not seen by a witness", after))
	}
	c.rep.add(chk)
}
