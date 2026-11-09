package verify

import (
	"fmt"
	"strings"

	"github.com/jfillman/clearance/internal/attest"
)

// attestationsCheck verifies every change attestation the packet carries: the DSSE signature, the Fulcio chain and
// Rekor's signed entry under the trust root the user supplied (the material is the bundle's own; nothing is
// fetched, so a pre-cutover entry that the current key could re-sign is not re-read), the Rekor inclusion proof the
// bundle carries, that the statement is about the change the packet says, and that the bundle is the one the
// chain's deploy.attestation record names.
func (c *ctx) attestationsCheck() {
	p := c.pk
	if p == nil {
		return
	}
	type item struct{ id, file, digest string }
	var items []item
	for _, ch := range p.Changes {
		if ch.Attestation != nil && ch.Attestation.Bundle != "" {
			items = append(items, item{ch.ID, ch.Attestation.Bundle, ch.Attestation.Digest})
		}
	}
	// The digests the chain itself records for each change's attestation (these records are bound by the checks above).
	chainDigest := map[string]string{}
	for _, r := range c.recs {
		if t, _ := r.m["tool"].(string); t == "deploy.attestation" {
			if id := str(obj(r.m, "change"), "id"); id != "" {
				chainDigest[id] = str(obj(r.m, "attestation"), "digest")
			}
		}
	}
	if len(items) == 0 {
		if len(p.Verification.AttestationsMissing) > 0 {
			c.rep.add(Check{Name: "attestations", Status: NotChecked, Detail: fmt.Sprintf("the packet could not carry the bundle of %d change(s): %s", len(p.Verification.AttestationsMissing), strings.Join(p.Verification.AttestationsMissing, ", "))})
		}
		return
	}
	opts := attest.VerifyOptions{Identity: c.opts.Identity, Issuer: c.opts.Issuer}
	var setupErr error
	if len(c.opts.TrustRoot) > 0 {
		if strings.HasPrefix(strings.TrimSpace(string(c.opts.TrustRoot)), "{") {
			opts.Trust, setupErr = attest.ParseTrustedRoot(c.opts.TrustRoot)
		} else {
			if opts.Roots, setupErr = attest.ParseRoots(c.opts.TrustRoot); setupErr == nil && len(c.opts.RekorKey) > 0 {
				opts.RekorKey, setupErr = attest.ParseRekorKey(c.opts.RekorKey)
			}
		}
	}
	if len(c.opts.AttestKeys) > 0 && setupErr == nil {
		opts.Keys, setupErr = attest.ParseKeys(c.opts.AttestKeys)
	}
	if setupErr != nil {
		c.rep.add(Check{Name: "attestations", Status: Fail, Detail: "the trust input you supplied does not parse: " + setupErr.Error()})
		return
	}

	for _, it := range items {
		chk := Check{Name: "attestation of " + it.id}
		raw, err := c.read(it.file)
		if err != nil {
			chk.Status, chk.Detail = Fail, it.file+" cannot be read: "+err.Error()
			c.rep.add(chk)
			continue
		}
		b, err := attest.ParseBundle(raw)
		if err != nil {
			chk.Status, chk.Detail = Fail, err.Error()
			c.rep.add(chk)
			continue
		}
		var bad, notes []string
		if d := attest.EnvelopeDigest(b.DSSEEnvelope); it.digest != "" && d != it.digest {
			bad = append(bad, fmt.Sprintf("the bundle's envelope is %s and the packet says this change's attestation is %s", short8(d), short8(it.digest)))
		}
		if d, ok := chainDigest[it.id]; ok && d != "" && d != attest.EnvelopeDigest(b.DSSEEnvelope) {
			bad = append(bad, fmt.Sprintf("the bundle is not the attestation the chain records for this change (deploy.attestation names %s)", short8(d)))
		}
		identity, issuer, keyless, ierr := attest.KeylessIdentity(raw)
		if ierr != nil {
			bad = append(bad, ierr.Error())
		}
		o := opts
		pinned := o.Identity != "" && o.Issuer != ""
		trustNote := ""
		switch {
		case keyless && o.Trust == nil && o.Roots == nil:
			chk.Status = NotChecked
			chk.Detail = "keyless: no trust root was supplied, so the Fulcio chain and Rekor entry are not checked (--trust-root)"
		case !keyless && o.Keys == nil:
			chk.Status = NotChecked
			chk.Detail = "static-key: no attestation key was supplied, so the signature is not checked (--attest-key)"
		default:
			if keyless && !pinned {
				o.Identity, o.Issuer = identity, issuer
				trustNote = fmt.Sprintf("signer identity %s (issuer %s) was read from the attestation itself, not pinned: pass --identity and --issuer to check who signed", identity, issuer)
			}
			res, verr := attest.Verify(raw, o)
			if verr != nil {
				bad = append(bad, verr.Error())
			} else {
				if got := res.Statement.Predicate.Clearance.ID; got != it.id {
					bad = append(bad, fmt.Sprintf("the signed statement is about change %q, not %q: a valid attestation of another change", got, it.id))
				}
				notes = append(notes, fmt.Sprintf("%s signature verified", res.Mode))
				if res.LogVerified {
					notes = append(notes, fmt.Sprintf("Rekor entry %d: signed entry timestamp verified", *res.LogIndex))
				}
			}
		}
		present, perr := attest.CheckInclusionProof(raw)
		switch {
		case perr != nil:
			bad = append(bad, perr.Error())
		case present:
			notes = append(notes, "Rekor inclusion proof reaches its stated root (the signature on Rekor's checkpoint is not checked)")
		case keyless:
			notes = append(notes, "the bundle carries no Rekor inclusion proof; only the signed entry timestamp vouches for the log entry")
		}
		chk.Findings = append(bad, notes...)
		switch {
		case len(bad) > 0:
			chk.Status, chk.Detail = Fail, "does not verify"
			chk.Findings = bad
		case chk.Status == NotChecked:
		case trustNote != "":
			chk.Status, chk.Detail = SelfVouched, "verifies, but who signed it was taken from the attestation itself"
			chk.Trust = trustNote
		default:
			chk.Status, chk.Detail = Pass, "verifies under the trust root you supplied"
		}
		if chk.Status == Pass || chk.Status == SelfVouched {
			chk.Findings = notes
		}
		c.rep.add(chk)
	}
	if len(p.Verification.AttestationsMissing) > 0 {
		c.rep.add(Check{Name: "attestations missing from the packet", Status: NotChecked, Detail: strings.Join(p.Verification.AttestationsMissing, ", ")})
	}
}
