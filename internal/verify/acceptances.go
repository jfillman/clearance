package verify

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/jfillman/clearance/internal/receipt"
	"github.com/jfillman/clearance/internal/token"
)

func (c *ctx) receiptCount() int {
	if c.pk == nil {
		return 0
	}
	return len(c.pk.Acceptances.Receipts)
}

// acceptancesCheck checks each acceptance receipt the packet's Acceptances section carries (P-1), offline:
//
//   - the section's printed fields are the signed payload's own (a table that says "accepted" over a receipt that
//     says "rejected" fails);
//   - the DSSE signature holds under the recipient's key: one the verifier's user supplied for the recipient
//     (--recipient-keys), else the copy the receipt carries, reported as taken from the packet (a packet vouching for the
//     key it was signed with proves nothing about who the recipient is);
//   - the receipt's content address (the SHA-256 of the signed payload) is the one the section states;
//   - when the chain record the core wrote for it (packet.receipt) is among the carried records, that record is the one
//     the section names, holds this receipt's digest and recipient, and so is bound by the packet's hash checks and
//     inclusion proofs;
//   - the revocations of recipient keys come from the section (Acceptances.KeyRevocations) and from the carried records: a core-written
//     assurance.key.revoke record for a key that signed a carried receipt must be listed in the section and equal to it (a packet cannot leave a
//     revocation it carries out), and a row that differs from its record fails. A receipt the core recorded at or after the as-of time FAILS
//     (the core's time, not the signer's signed_at), one recorded after the revocation record FAILS, and one recorded before it is valid with
//     the revocation printed. The time comes from material the packet carries, never from a live call; a revocation recorded after the packet
//     was cut is not in it;
//   - the checkpoint the receipted packet stood on is consistent with this packet's: the same log, never later, and the
//     same root where the sizes are equal (a different root at the same size is a fork).
//
// What it cannot do: the receipted packet is not here, so that the id is the digest of ITS manifest is a check for
// whoever holds it (the id is derived from the digest, and the receipt states both), and consistency between two
// checkpoints of different sizes needs a witness's cosignature, not a proof the packet carries.
func (c *ctx) acceptancesCheck() {
	p := c.pk
	if p == nil || len(p.Acceptances.Receipts) == 0 {
		return
	}
	chk := Check{Name: "acceptances: each receipt's signature and binding"}
	supplied := map[string]token.KeySet{}
	for name, raw := range c.opts.RecipientKeys {
		ks, err := token.ParsePublicKeys(raw)
		if err != nil {
			chk.Status, chk.Detail = Fail, fmt.Sprintf("--recipient-keys %s is not readable: %v", name, err)
			c.rep.add(chk)
			return
		}
		supplied[name] = ks
	}
	bySeq := map[int64]rec{}
	for _, r := range c.recs {
		bySeq[r.seq] = r
	}
	// The revocations of recipient keys, from the section AND from the carried records: a revocation record the core wrote for a key that
	// signed a carried receipt counts whether or not the section lists it, and a row that differs from its record fails.
	type revoked struct {
		seq      int64
		hash     string
		asOf     time.Time
		recorded time.Time // the core's own time for the revocation record
		bound    bool      // its chain record is among the carried ones
	}
	revs := map[string]revoked{}
	signedKeys := map[string]bool{}
	for _, r := range p.Acceptances.Receipts {
		signedKeys[r.Recipient+"\x00"+r.KeyID] = true
	}
	var bad, notes []string
	listed := map[int64]bool{}
	for _, kr := range p.Acceptances.KeyRevocations {
		who := fmt.Sprintf("the revocation of key %s of %s (record %d)", short8(kr.KeyID), kr.Recipient, kr.Seq)
		asOf, err := time.Parse(time.RFC3339, kr.AsOf)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s has no readable as_of time: %q", who, kr.AsOf))
			continue
		}
		rowAt, rerr := time.Parse(time.RFC3339, kr.RevokedAt)
		rv := revoked{seq: kr.Seq, hash: kr.RecordHash, asOf: asOf, recorded: rowAt}
		if cr, ok := bySeq[kr.Seq]; ok {
			m, _ := cr.m["revocation"].(map[string]any)
			recAt, terr := time.Parse(time.RFC3339, fmt.Sprint(cr.m["ts"]))
			switch {
			case cr.m["tool"] != "assurance.key.revoke" || cr.m["decision"] != "allow":
				bad = append(bad, fmt.Sprintf("%s names a record that is %v, not an assurance.key.revoke", who, cr.m["tool"]))
				continue
			case !coreRevocationRecord(cr.m):
				bad = append(bad, fmt.Sprintf("%s names a record the core did not write as a revocation (its provider, boundary or verified marks are not the core's)", who))
				continue
			case cr.computed != kr.RecordHash && cr.stated != kr.RecordHash:
				bad = append(bad, fmt.Sprintf("%s: the record hashes to %s, the section says %s", who, short8(cr.computed), short8(kr.RecordHash)))
				continue
			case m["recipient"] != kr.Recipient || m["key_id"] != kr.KeyID || m["as_of"] != kr.AsOf:
				bad = append(bad, fmt.Sprintf("%s: the record says another recipient, key or as-of time", who))
				continue
			case terr != nil || rerr != nil || !recAt.Equal(rowAt):
				bad = append(bad, fmt.Sprintf("%s: the section says it was recorded at %q, the record says %v", who, kr.RevokedAt, cr.m["ts"]))
				continue
			}
			rv.recorded, rv.bound = recAt, true
		} else if rerr != nil {
			bad = append(bad, fmt.Sprintf("%s has no readable revoked_at time: %q", who, kr.RevokedAt))
			continue
		}
		listed[kr.Seq] = true
		k := kr.Recipient + "\x00" + kr.KeyID
		if old, ok := revs[k]; !ok || rv.asOf.Before(old.asOf) {
			revs[k] = rv
		}
	}
	for _, cr := range c.recs {
		m, _ := cr.m["revocation"].(map[string]any)
		if cr.m["tool"] != "assurance.key.revoke" || cr.m["decision"] != "allow" || !coreRevocationRecord(cr.m) || m["kind"] != "recipient-key" {
			continue
		}
		rc, _ := m["recipient"].(string)
		kid, _ := m["key_id"].(string)
		if !signedKeys[rc+"\x00"+kid] || listed[cr.seq] {
			continue
		}
		bad = append(bad, fmt.Sprintf("record %d, which the core wrote, revokes key %s of %s, which signed a carried receipt, and the acceptances section omits it: a packet cannot leave out a revocation it carries", cr.seq, short8(kid), rc))
	}
	vouched, own, unbound := 0, 0, 0
	for i, r := range p.Acceptances.Receipts {
		name := fmt.Sprintf("receipt %d (%s from %s, record %d)", i+1, r.Verdict, r.Recipient, r.Seq)
		raw := []byte(r.Envelope)
		pl, err := receipt.Read(raw)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: not an acceptance receipt: %v", name, err))
			continue
		}
		// The printed fields are the signed ones.
		for _, d := range [][3]string{{"packet_id", r.PacketID, pl.PacketID}, {"packet_digest", r.PacketDigest, pl.PacketDigest}, {"delivery", r.Delivery, pl.Delivery},
			{"recipient", r.Recipient, pl.Recipient}, {"engagement", r.Engagement, pl.Engagement}, {"verdict", r.Verdict, pl.Verdict}, {"signed_at", r.SignedAt, pl.SignedAt}} {
			if d[1] != d[2] {
				bad = append(bad, fmt.Sprintf("%s: the section prints %s %q, the signed receipt says %q", name, d[0], d[1], d[2]))
			}
		}
		if !slices.Equal(r.Mappings, pl.Mappings) || !sameNotes(r.Notes, pl.ControlNotes) || !sameCheckpoint(r.Checkpoint, pl.Checkpoint) {
			bad = append(bad, fmt.Sprintf("%s: the section's mappings, control notes or checkpoint differ from the signed receipt's", name))
		}
		// The signature, under the best key there is.
		var keys token.KeySet
		trust := trustNone
		kid := r.KeyID
		if mine, ok := supplied[pl.Recipient]; ok {
			// Keys were supplied for this recipient: only they vouch for it. A key supplied for another recipient, or
			// one the packet carries, does not.
			pub := mine[kid]
			if pub == nil {
				bad = append(bad, fmt.Sprintf("%s: signed by key %s, which is not one you supplied for recipient %s", name, short8(kid), pl.Recipient))
				continue
			}
			keys, trust = token.KeySet{kid: pub}, trustSupplied
		} else if r.Key != nil {
			pub, err := r.Key.Public()
			if err != nil || r.Key.Kid != kid {
				bad = append(bad, fmt.Sprintf("%s: the key the receipt carries is not a P-256 key with that id", name))
				continue
			}
			keys, trust = token.KeySet{kid: pub}, trustPacket
		} else {
			bad = append(bad, fmt.Sprintf("%s: no key to check it with (none supplied for recipient %s, none carried)", name, pl.Recipient))
			continue
		}
		v, err := receipt.Verify(raw, keys)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: the signature does not verify under %s: %v", name, trustWords(trust), err))
			continue
		}
		if trust == trustSupplied {
			own++
		} else {
			vouched++
		}
		if v.PayloadSHA256 != r.PayloadSHA256 {
			bad = append(bad, fmt.Sprintf("%s: the receipt's payload hashes to %s, the section says %s", name, short8(v.PayloadSHA256), short8(r.PayloadSHA256)))
		}
		// A revoked key. The core's own time for the receipt's record is the bound, not the signer's signed_at (a stolen key's holder writes
		// that): a receipt recorded at or after the as-of time is not trusted, and neither is one recorded after the revocation record (the
		// core refuses those). One recorded before is valid as recorded, with the revocation printed. Where the receipt's record is not carried,
		// signed_at is all there is, and the receipt is not bound to the ledger anyway (said below).
		if rv, ok := revs[pl.Recipient+"\x00"+kid]; ok {
			asOfS, recS := rv.asOf.UTC().Format(time.RFC3339), rv.recorded.UTC().Format(time.RFC3339)
			tie := rv.asOf.Equal(rv.recorded) // not back-dated: a receipt recorded in the same second before the revocation is before it
			late := func(t time.Time) bool { return t.After(rv.asOf) || (t.Equal(rv.asOf) && !tie) }
			signed, serr := time.Parse(time.RFC3339, pl.SignedAt)
			rcAt, haveRec := time.Time{}, false
			if cr, ok := bySeq[r.Seq]; ok {
				if t, err := time.Parse(time.RFC3339, fmt.Sprint(cr.m["ts"])); err == nil {
					rcAt, haveRec = t, true
				}
			}
			switch {
			case haveRec && late(rcAt):
				bad = append(bad, fmt.Sprintf("%s: the core recorded it at %s with key %s, which was revoked as of %s (record %d, recorded by the core at %s): a receipt recorded with a revoked key is not trusted, whatever signed_at says", name, rcAt.UTC().Format(time.RFC3339), short8(kid), asOfS, rv.seq, recS))
			case !haveRec && (serr != nil || late(signed)):
				bad = append(bad, fmt.Sprintf("%s: signed at %s with key %s, which was revoked as of %s (record %d): a receipt signed with a revoked key is not trusted", name, pl.SignedAt, short8(kid), asOfS, rv.seq))
			case r.Seq > rv.seq:
				bad = append(bad, fmt.Sprintf("%s: recorded as record %d, after the revocation of its key (record %d): the core refuses such a receipt", name, r.Seq, rv.seq))
			default:
				warn := ""
				if rv.recorded.Sub(rv.asOf) > 24*time.Hour {
					warn = " WARNING: the as-of time is more than a day before the core recorded the revocation (a back-dated revocation)"
				}
				notes = append(notes, fmt.Sprintf("%s: recorded before key %s was revoked: revoked as of %s, recorded by the core at %s (record %d): valid as recorded.%s", name, short8(kid), asOfS, recS, rv.seq, warn))
			}
			if !rv.bound {
				notes = append(notes, fmt.Sprintf("%s: the revocation's chain record (%d) is not among the records this packet carries: the packet's word for it, not bound to the ledger here", name, rv.seq))
			}
		}
		// The chain record, where it is carried.
		if cr, ok := bySeq[r.Seq]; ok {
			rc, _ := cr.m["receipt"].(map[string]any)
			pk, _ := cr.m["packet"].(map[string]any)
			switch {
			case cr.m["tool"] != "packet.receipt":
				bad = append(bad, fmt.Sprintf("%s: record %d is %v, not a packet.receipt", name, r.Seq, cr.m["tool"]))
			case cr.computed != r.RecordHash && cr.stated != r.RecordHash:
				bad = append(bad, fmt.Sprintf("%s: record %d hashes to %s, the section says %s", name, r.Seq, short8(cr.computed), short8(r.RecordHash)))
			case rc["payload_sha256"] != v.PayloadSHA256 || pk["id"] != pl.PacketID:
				bad = append(bad, fmt.Sprintf("%s: record %d is about another receipt or packet", name, r.Seq))
			}
		} else {
			unbound++
			notes = append(notes, fmt.Sprintf("%s: its chain record is not among the records this packet carries, so the receipt is not bound to the ledger here: only the signature was checked", name))
		}
		// Consistency with this packet's checkpoint.
		if rc, here := pl.Checkpoint, c.cp; rc != nil && here != nil {
			switch {
			case rc.Origin != here.origin:
				bad = append(bad, fmt.Sprintf("%s: the receipted packet stood on log %q, this packet's is %q", name, rc.Origin, here.origin))
			case rc.Size > here.size:
				bad = append(bad, fmt.Sprintf("%s: the receipted packet's checkpoint (%d records) is larger than this packet's (%d): a prior receipt cannot be for a later log", name, rc.Size, here.size))
			case rc.Size == here.size && rc.Root != fmt.Sprintf("%x", here.root):
				bad = append(bad, fmt.Sprintf("%s: FORK: the receipted packet's checkpoint and this packet's are the same size (%d) with different roots", name, rc.Size))
			}
		}
	}
	sort.Strings(bad)
	switch {
	case len(bad) > 0:
		chk.Status, chk.Detail, chk.Findings = Fail, strconv.Itoa(len(bad))+" finding(s) in "+strconv.Itoa(len(p.Acceptances.Receipts))+" receipt(s)", bad
	case unbound > 0:
		chk.Status, chk.Detail = NotChecked, fmt.Sprintf("%d receipt(s) carry a valid signature, but %d chain record(s) are not carried, so their binding to the ledger was not checked", own+vouched, unbound)
		chk.Findings = notes
		c.rep.add(chk)
		c.rep.note("Acceptance receipts show that a recipient signed a statement about an earlier packet, with a key it registered; they do not show the recipient's review was right.")
		return
	case vouched > 0:
		chk.Status, chk.Trust = SelfVouched, "the recipients' keys were TAKEN FROM THE PACKET ITSELF: pass --recipient-keys <recipient>=<file> with the keys each recipient gave you"
		chk.Detail = fmt.Sprintf("%d receipt(s) verify; %d under keys you supplied, %d under the packet's own copy", own+vouched, own, vouched)
	default:
		chk.Status, chk.Trust = Pass, "keys you supplied"
		chk.Detail = fmt.Sprintf("%d receipt(s) verify under keys you supplied", own)
	}
	if len(bad) == 0 {
		chk.Findings = notes
	}
	c.rep.add(chk)
	{
		c.rep.note("Acceptance receipts show that a recipient signed a statement about an earlier packet, with a key it registered; they do not show the recipient's review was right. The receipted packet's own id is the digest of its manifest: check it against the packet you hold.")
	}
}

// coreRevocationRecord is the provenance test for a carried revocation record, the one the packet builder applies: the record's provider is the
// core ("clearance"), its boundary is deployment, and "tool" and "revocation" are among the fields the core marked as verified.
func coreRevocationRecord(m map[string]any) bool {
	pv, _ := m["provider"].(map[string]any)
	if pv["name"] != "clearance" || m["boundary"] != "deployment" {
		return false
	}
	vs, _ := m["verified"].([]any)
	tool, f := false, false
	for _, v := range vs {
		switch v {
		case "tool":
			tool = true
		case "revocation":
			f = true
		}
	}
	return tool && f
}

func sameNotes(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func sameCheckpoint(a, b *receipt.Checkpoint) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
