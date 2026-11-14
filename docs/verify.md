# Verifying a packet offline (C-4)

`clearance verify <packet-dir>` checks an [evidence packet](packet.md) on a machine that cannot reach Clearance, its
database or the recorder. It also ships as its own small binary, `clearance-verify`, so an auditor can install it
without the rest of Clearance:

```sh
go install github.com/jfillman/clearance/cmd/clearance-verify@latest
clearance-verify ./packet-2026-10 \
  --log-keys log-vkeys.txt --witness-policy witness-policy.txt \
  --trust-root trusted-root.json --identity clearance-recorder@hangar-prod --issuer https://oidc.example
```

Status: **Built** (C-4). Exit code **0** every check passed; **1** something failed (the report names it); **2** nothing
failed but something could not be established. A caller must not read 2 as a pass.

## Trust inputs: who vouches for the keys

A packet carries its own copy of the log's keys and witness policy so it can be read without asking anyone. A packet
that vouches for its own keys proves nothing: whoever forged the records could have written the keys beside them.
So the verifier takes the trust inputs from **you**, and says in the output which it used:

| Input | Flag | When you do not give it |
| --- | --- | --- |
| The log's public keys (signed-note vkeys, one per line, the key in use first, retired keys after) | `--log-keys` | The packet's `ledger/log-keys.txt` is used, and the checks that rest on it print **SELF-VOUCHED** with "TAKEN FROM THE PACKET ITSELF" |
| The witness policy | `--witness-policy` | The packet's `ledger/witness-policy.txt`, reported the same way |
| The attestation trust root: a Sigstore TrustedRoot JSON (`clearance trust-root build`), or Fulcio certificates (PEM) with `--rekor-key` | `--trust-root` | Keyless attestations are **NOT CHECKED** |
| A static-key attestation's public key (PEM or JWKS) | `--attest-key` | Static-key attestations are **NOT CHECKED** |
| Each assurance recipient's public keys (PEM or JWKS), as that recipient gave them to you | `--recipient-keys <recipient>=<file>` (repeatable) | Each acceptance receipt's own copy of its key is used and the check prints **SELF-VOUCHED** |
| Who must have signed a keyless attestation | `--identity` with `--issuer` | The signer is read from each attestation's own certificate and labelled "not pinned": the signature and chain verify, but who signed is the attestation's own claim |

The top of the report lists each input and where it came from. Only a checkpoint authenticated by log keys you
supplied is written to the note of checkpoints seen (below).

## What it checks

1. **Manifest.** Every file `MANIFEST.json` names exists with that SHA-256, and no file is in the directory that the
   manifest does not name. The manifest is not signed: it catches a changed file, not a changed file with a rewritten
   manifest. The next checks are what bind the content.
2. **Records.** Each line of `evidence/records.jsonl` is re-hashed from its original (drop `hash`, canonicalize,
   SHA-256). A line whose content does not hash to the hash it states is named ("line 12 (seq 11): ALTERED"). Where
   two carried seqs are adjacent, the later record's `prev_hash` must be the earlier one's recomputed hash, so a record
   altered together with its own hash is named by the link after it. Seqs must be strictly ascending; the last record
   of the chain must hash to the head the packet states.
3. **The checkpoint.** `ledger/checkpoint.txt` must carry a signature by one of the log keys (a key list that lacks a
   retired key fails here, which is why `--log-keys` takes the retired keys after the one in use: **key rotation leaves
   old entries verifiable**), and its witness countersignatures must satisfy the witness policy. A checkpoint signed by
   the log alone is exactly what a truncated or re-signed log looks like (the log's own key can sign any tree; only a
   witness that has seen the real one refuses), so it fails with "WITNESS POLICY NOT SATISFIED". The packet's own
   description of its checkpoint (origin, size, root) must agree with the file.
4. **Inclusion proofs.** Every carried record under the checkpoint must have an RFC 6962 audit path in
   `evidence/proofs.json` that proves its recomputed hash into the checkpoint's root. A record that was changed after
   it was logged is named; a record under the checkpoint with no proof is a failure, not a skip. Records after the
   checkpoint are `recorded-not-checkpointed`: chained, not seen by a witness, and counted as such.
5. **Counted figures.** The figures in `packet.json` are recounted from the carried records: the header's carried,
   in-window and first/last seq counts; the coverage statement's total, its counts by coverage state and by assurance
   state, their cross, and that every state is listed (at zero too); the verification section's counts under and after
   the checkpoint, proofs and attestations. A figure that no longer recomputes is named with the value the packet says
   and the value the records give. The tables and sentences of the packet (changes, assertions, exceptions) are not
   recomputed; they present the records the earlier checks bind. (The packet header records `scopes_named`, so an observed record with no scope is recounted as the builder counted it: in when no scopes were named, out when some were.)
   **Coverage statements.** Each observed scope's statement is rebuilt from the carried records with the function the
   packet and `GET /v1/coverage` use (`observe.Build`), at the clock the packet was made at, and the packet's feed state,
   `clean`, cleared and seen counts, the seconds that could not be seen and the source-integrity counts must match. A
   scope the packet calls healthy and clean over a window whose health records show the collector stopped does not pass,
   even when the file was edited and the manifest made to match.
6. **Attestations.** For each change attestation in `attestations/`: the DSSE signature; the Fulcio chain and the Rekor
   signed entry timestamp under your trust root, using the material in the bundle (nothing is fetched, so a
   pre-cutover Rekor entry that the current key could re-sign is checked as it was); the Rekor **inclusion proof** the
   bundle carries, from the entry to the root it states and, when the bundle carries Rekor's checkpoint, that
   checkpoint's size and root agree (the signature on Rekor's checkpoint is not checked; the signed entry timestamp is
   what binds the entry to Rekor's key); that the statement is about the change the packet says (a valid attestation
   of another change is refused); and that the bundle is the envelope the packet and the chain's `deploy.attestation`
   record name.
7. **Checkpoints seen.** The weak-witness behaviour. A local note (`--seen-file`, default
   `<user config dir>/clearance/verify-seen.json`, `--no-seen` to turn it off) keeps the checkpoints this verifier has
   accepted. A later packet whose checkpoint has the same size as one in the note and a different root is a **FORK**:
   one of the two trees is not the log's. A smaller or larger checkpoint is reported as such but cannot be called
   inconsistent, because the packet carries no consistency proof (a witness's cosignature is what attests that).

## Acceptance receipts

When the packet's Acceptances section carries receipts ([assurance.md](assurance.md)), one more check runs for all of them:
the section's printed fields are the signed payload's own (a table saying "accepted" over a receipt that says "rejected" fails
even when the manifest was rewritten to match); the DSSE signature holds under the recipient's key (yours from
`--recipient-keys name=file` for the recipient the receipt names, else the receipt's carried copy, **SELF-VOUCHED**; a key supplied for another recipient never vouches); the receipt hashes to the digest the section states;
when the chain record the core wrote for it is among the carried records it is the right one (so the packet's hash checks and
inclusion proofs bind it; when it is not carried the check is **NOT CHECKED**, signature only); and the checkpoint the receipted packet stood on is consistent with this packet's (same log, never
later, the same root at the same size: a different root is a **FORK**). It cannot check that the receipted packet's id is the digest
of its manifest (that packet is not here): whoever holds it can.

## Samples

`clearance verify --sample sample.json [--packet dir]` checks a sample of a packet's cleared changes ([sampling.md](sampling.md))
the same way: every record's hash, every inclusion proof under the checkpoint, the checkpoint's signatures and the witness policy,
the population's digest, that the selection is the one the rule draws from the population and seed, and, with `--packet`, that the
sample is of that packet. A missing proof, a missing or extra record, or a record outside the population **fails**; without the
log keys, the packet or the core's own `packet.sample` record (`--sample-record`) the result is SELF-VOUCHED or NOT CHECKED (exit 2), never a pass.

## No checkpoint: "NOT CHECKPOINTED"

A packet from a deployment whose ledger is off, or has not yet published a witnessed checkpoint, has no checkpoint,
proofs or countersignatures. The verifier reports that as **NOT CHECKPOINTED**, with the words that it is not a pass of
the witness check, exits 2, and still checks the records, the chain links, the figures and the attestations. A packet
that says it has a checkpoint but whose checkpoint file is missing is a **failure** (a checkpoint removed to make a
packet look unwitnessed), not a NOT CHECKPOINTED.

## Offline, and installable alone

The verifier opens only the packet directory, the key files you name and the seen-checkpoints note. The
verifier's own code imports neither `net` nor `net/http` (a test reads its sources), and it fetches nothing: not Rekor,
not Fulcio, not the recorder. (`internal/attest`, which it reuses for the signature checks, also holds the Rekor and
Fulcio clients that signing uses; the verifier never calls them.) Two more tests hold that:
`TestVerifyThirtyDayLabPacketOffline` verifies the 30-day lab packet with the HTTP transport and DNS replaced by ones
that fail the test, and `TestVerifyBinaryRunsWithNoNetwork` runs the built `clearance-verify` as a process that has no
network at all (`sandbox-exec` on macOS, `unshare -n` on Linux).

It links nothing of the core or a database. `go list -deps ./cmd/clearance-verify` shows the clearance packages it
uses: `internal/verify`, `internal/canon` (the record hash), `internal/attest` (the attestation verifier, reused:
`clearance attest verify` is the same code), `internal/token` and `internal/evidence` (vocabulary), and no store, gate,
ledger, packet builder, server, `pgx` or `database/sql`; `TestVerifierLinksNothingOfTheCoreOrADatabase` fails if one
appears. To make that true the signing side of attestations (`Attestor`, `BuildStatement`) moved from `internal/attest`
to `internal/attestor`; the verify side stayed.

## What it cannot do

- It cannot show that a record was *right*, only that it is the record the log committed to and that the packet's
  counts follow from it. A record's claimed fields are what their writers said and are labelled so in the packet.
- It cannot tell a log that never showed a witness a rewritten tree from one that did, if no witness policy it trusts
  is available: that is why a missing policy is NOT CHECKED, and a packet-supplied one SELF-VOUCHED.
- It does not check the signature on Rekor's checkpoint, nor consistency between checkpoints (no proof is carried).
- It does not recompute the packet's tables, assertions or sentences, nor read the PDF or the CSV files beyond their
  manifest hash.
