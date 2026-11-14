# The sampling call: a sample of cleared changes, with a proof per record (P-2)

An auditor testing change management does not read every change: they test a sample, and they want the population the
sample was drawn from, so they can test it first. `GET /v1/packets/{id}/sample` gives them both from a delivered
[packet](assurance.md): a sample of the packet's cleared changes, each with its clearing record and an inclusion proof
against the packet's witnessed checkpoint, and the population printed beside it. `clearance verify --sample` checks the
result offline, the way it checks a packet.

Status: **Built** (P-2). Proven against fakes: `go test ./internal/server -run TestP2SamplingGate -count=1` draws a
25-record sample of a 30-day lab packet through the real HTTP server as a fake recipient and verifies it offline.

## Guardrails

- **Same credential, same scope model as a read (P-1).** The call takes the packet credential the delivery minted and
  needs **both** parts in its scope: the population is in the summary, the records and proofs in the evidence part. A
  credential cut to one part, for another packet, expired, not yet good or for a recipient no longer registered is refused
  with its rule (`PK-SCOPE`, `PK-EXPIRED`, `PK-NOT-YET`, `PK-RECIPIENT`), and the refusal is a `packet.sample` record.
  Anything the core did not sign is a bare 401 and writes nothing. No new scope was added: there is no way to sample
  without being able to read.
- **Recorded before it is served.** An allowed sampling is one `packet.sample` record, written before a byte is
  returned; a sampling that cannot be recorded is not served (503).
- **Asking again writes nothing.** The same delivery asking for the same packet, `n`, `seed` and `stratify` again is served
  from the record that holds it (`X-Clearance-Sample-Created: false`) and appends nothing, however many times and however
  concurrently. A new delivery is a new grant and records its own sampling.
- **Caps, each answered 429 with nothing written past it.** Allowed reads per delivery per hour are P-1's
  (`CLEARANCE_PACKET_READS_PER_HOUR`, default 60, shared with `GET /v1/packets/{id}`); refusals recorded per delivery per hour
  are P-1's (60, shared); and a delivery may draw at most **20 distinct samples** (`PK-SAMPLE-LIMIT`), asked-again samples
  not counting. `n` is at most 100; the seed at most 64 characters; the query at most 256 bytes.
- **Every parameter is validated before anything is written.** The only parameters are `n`, `seed` and `stratify`, each at
  most once; the path id must be a packet id. A bad one is 400 (or 404 for the id) with no record and no credential in the
  answer.
- **The seed is required and is the auditor's.** There is no default seed: any default is a function of the packet alone,
  so the party who builds the packet could try packets until the default sample flatters them. A seed the auditor chooses
  after the packet's digest is fixed is the only one the builder cannot steer. A call without a seed is 400 and writes nothing.
- **The selection is reproducible and public.** Below: a function of the packet's digest, the seed, `n` and the
  stratification, nothing hidden.
- **A sample too large to read is not served.** The encoded answer is capped at 32 MiB (what the verifier will read); over it
  the call is 413 and nothing is recorded.
- **Only the population can be sampled.** A record that is not the clearing record of an eligible change of the packet cannot
  be drawn: not another app's record that happens to sit in the carried range, not a change that was never cleared, not a
  record with no inclusion proof. The verifier fails a sample that contains one.
- **Nothing is checked on the sample's word.** The core checks the stored packet before it samples it (every carried
  record hashes to the hash it states, every proof verifies under the checkpoint root, the checkpoint note is the one
  `packet.json` describes) and refuses a packet that does not check. The verifier checks the same again, offline.
- **A packet with no witnessed checkpoint is not sampled** (409, nothing recorded): there would be no inclusion proof to give.

## The request

```text
GET /v1/packets/{id}/sample?n=25&seed=fy26-q4&stratify=tier-month
Authorization: Bearer <the delivery's credential>
```

| Parameter | Meaning |
| --- | --- |
| `n` | the sample size, 1 to 100, default 25; at most the number of eligible changes (else 400) |
| `seed` | **required**: 1 to 64 of letters, digits, `.`, `_`, `-`, chosen by the auditor after the packet's digest is fixed |
| `stratify` | `none` (uniform, the default) or `tier-month` |

`clearance receipt sample --core URL --packet pk-... --seed fy26-q4 --n 25 --out sample.json` (credential from
`--credential-file`, `-` or `$CLEARANCE_PACKET_CREDENTIAL`, never a flag) is the same call on a command line.

## The population and the frame

The **population** is every change of the packet (the packet's scope: its app, environment and cluster filter and its window),
one row each, ordered by change id, printed with its SHA-256. A change is **eligible**, in the sampling frame, when it has a
clearing record (`deploy.clear`), that record is carried by the packet, and it has an inclusion proof under the packet's
checkpoint. A change that is not says why: `not-cleared` (denied, still holding, or an exception), `no-inclusion-proof`
(cleared after the checkpoint: recorded-not-checkpointed) or `unreadable-timestamp`. So the firm can test the population before
the sample: nothing is silently left out, and what cannot be sampled is listed with the reason. Counts of all, cleared and
eligible changes are stated, and so are the **cleared changes that are not in the frame, by reason** (`cleared_excluded`): a
cleared change with no inclusion proof (cleared after the checkpoint) could not be sampled, and the sample is of the eligible
changes, not of every cleared change. `clearance verify --sample` reports it as a finding.

The sampled record is each change's **clearing record**: the `deploy.clear` record, with the tier, the approvals and who
cleared it. The month a change belongs to is the month (UTC) of its first record.

## The selection

Everything is public, so anyone holding the packet redraws the same sample:

```text
effective seed = SHA-256("clearance.sample-seed/v1" 0x00 packet digest 0x00 seed)      (the seed is always the caller's: required)
key(change)    = SHA-256(effective seed || big-endian 64-bit seq of its clearing record)
uniform        = the n eligible changes with the smallest keys
tier-month     = group the eligible changes by (tier, month); each group gets floor(n * size / eligible) places, the
                 places left over go one each to the groups with the largest remainders (ties: the earlier group, by
                 tier then month), and each group takes its changes with the smallest keys
```

The sample is listed in clearing-record order. Uniform samples nest: the sample of 10 is inside the sample of 25 for the same
seed. A stratified sample is proportional, so a small stratum can draw nothing; every stratum is printed with its population
and its draw.

**Who controls the seed.** The auditor does, and it has to: `seed` is required. The effective seed is bound to the packet's
digest, so a seed means nothing on another packet, and the auditor should choose it **after** the packet's digest is fixed (the
subscriber publishes the packet, the digest is known, then the auditor names a seed). A seed the packet's builder could know in
advance is one the builder can steer for: build the packet, redraw, adjust, repeat. For the same reason the core has no default
seed: a default is a function of the packet alone, and so is exactly what a builder could grind. What the core cannot show is
*when* the auditor chose the seed; that is for the engagement letter, or for the auditor to publish the seed's commitment
beforehand.

What a recipient can do is try seeds until it likes a sample; what limits that is not secrecy (the recipient already holds every
record in the evidence part of the packet it was given, so the sample grants no access) but the record: every distinct sample a
delivery drew is a `packet.sample` record naming its seed and its records, at most 20 per delivery, so seed-shopping is visible
in the ledger.

## The sample document

`clearance.packet-sample/v1`: the packet (id, digest, window), the delivery and recipient, the parameters (`n`, `seed`,
`stratify`), the effective seed, the checkpoint (origin, size, root, the checkpoint note, and the packet's copies of the log keys
and witness policy), the population (counts, digest, the cleared-but-excluded counts by reason, rows), the strata, the sampled
items (the change, tier, month, the record exactly as the packet carries it, and its inclusion proof: the packet's own
`evidence/proofs.json` entry shape) and `recorded`: the seq and hash of the `packet.sample` record **and the record itself**, as
the core stored it. No route serves a record under the packet credential, so the record travels in the document; a person with
an account (or the subscriber, on the recipient's behalf) can read the same record from the core with
`GET /v1/evidence/{seq}` (clearance-api), which is what `--sample-record` is for.

The record's `sample` field holds the sample's id (`sm-` and the first 32 hex digits of the document's canonical SHA-256,
`recorded` excluded), the parameters (`seed` is what the caller gave), the effective seed, the method, the population and sample
digests, the eligible count, the checkpoint size and the sampled clearing-record seqs. A repeat request is matched on **the
draw** (the method, the population digest, the effective seed and the ordered sampled seqs), not on the document's bytes, so a
later change to the document's shape does not make earlier samplings unservable; a recorded draw that is not the draw the
inputs give now is a real inconsistency and is refused (503, logged).

## Checking it offline

```text
clearance verify --sample sample.json --packet ./packet-dir --log-keys log.pub --witness-policy witness.txt --sample-record record.json
```

Exit codes are the packet's: 0 verified, 1 failed, 2 nothing failed but something could not be established. The checks:

| Check | Fails when |
| --- | --- |
| document | not a `clearance.packet-sample/v1`; the packet id is not derived from its digest; no sampling record is carried |
| records | a record does not hash to the hash it states; a record's seq is not the item's; one is sampled twice; none is carried |
| ledger: checkpoint, witnesses, inclusion proofs | the checkpoint note does not verify under the log keys; the witness policy is not satisfied; any carried record has no proof, a proof that does not verify under the root, or a proof for a record that is not carried |
| population | the counts, the cleared-but-excluded counts or the digest do not match the rows; rows out of order or repeated; an eligible row without a clear record, or past the checkpoint. A **finding** (not a failure) when cleared changes have no inclusion proof: how many could not be sampled |
| selection | `n` is not the number of records; the seed is missing; the effective seed is not the one the rule derives; the rule, run over the printed population, draws other records than those carried (so a swapped, added or dropped record fails); a record is not the `deploy.clear` of its change, or is not an eligible change of the population |
| against the packet (`--packet`) | the packet's manifest does not match; its digest is not the one the sample names; the checkpoint is not the one the packet stood on; the sample's population is not the one rebuilt from the packet's `packet.json` (a change left out, added or altered); a sampled record is not the one the packet carries; the sampling record is older than the packet |
| the core's `packet.sample` record | the record the sample carries is not a record of this draw (hash, seq, packet, delivery, seed, population digest, effective seed, sampled seqs); with `--sample-record`, the record you read from the core differs from the carried one or is not a record of this draw |

**What exit 0 proves, and does not.** It proves: every sampled record is the one the log committed to (as far as the log keys and
witness policy you supplied vouch for the checkpoint); the population is the packet's (with `--packet`); the selection is exactly
what the public rule draws from that population and that seed; and the `packet.sample` record you read from the core names this
draw, so the core recorded it. It does not prove: that the review of these records was right; that the auditor chose the seed after
the packet's digest was fixed; that the cleared changes with no inclusion proof (listed as a finding) are in order; or anything about
changes outside the packet's scope.

The sampling record is written after the checkpoint the proofs are under, so no proof in the sample covers it, and the rule is
public, so anyone can assemble a document that is consistent with itself, `recorded` included. That is why exit 0 needs
`--sample-record`: the record read from the core is the one thing an offline forger does not have. Without it the check is
**NOT CHECKED** (exit 2). Without `--log-keys` / `--witness-policy` the checkpoint is checked against the keys the sample itself
carries and reported **SELF-VOUCHED** (exit 2). Without `--packet` the population and the digest are the sample's own claim and
the check is **NOT CHECKED** (exit 2): a population with a change quietly left out, its digest and counts recomputed, is caught
only against the packet. None is a pass.

## Threat: a leaked credential can use up a delivery's caps

The caps are per delivery. Whoever holds a delivery's credential can spend its 20 distinct samples, its hourly read budget and its
hourly refusal-recording budget, and so lock the real recipient out of that delivery until the budgets reset (the hourly ones) or for
good (the 20 samples). It cannot read more than the recipient could, and it cannot make the ledger grow past the caps. **Remedy:**
the subscriber creates a new delivery for the same recipient and packet (`clearance packet deliver`), which has fresh caps; keep
windows short. There is no revocation of the leaked credential (P-1); `TestP2ANewDeliveryHasFreshCaps` shows a new delivery
drawing normally after the old one's caps are spent.

## Known limits

- The index that makes a repeat request idempotent and counts a delivery's distinct samples is kept per core replica and
  rebuilt from the chain on restart (the core is one replica), as P-1's receipt index is. After a write whose commit is in doubt
  the index is dropped and rebuilt from the chain, so a retry finds the record instead of writing a second one.
- A repeat request is served from the existing record and is not recorded again: the record says the sample was drawn and
  served, not how many times it was read. Reads still count against the hourly cap.
- The month of a change is the month of its first record in the packet, not of its clearing record.
- Only the clearing records of changes in the packet are sampled; the sample does not test exceptions, observations or agent
  records, and it says nothing about changes that are not in the packet's scope.
- Stratification is by tier and month together, or none. Tier alone or month alone is not offered.
- A packet that fails the core's checks is refused for 30 seconds without being read again, so a bad packet cannot be used to
  make the core re-read it on every request.

## What this is not
Not a statistical opinion: the sample is a simple random (or proportionally stratified) draw from the frame, and the document
says how it was drawn so the firm can judge whether it suits the engagement. It is not a way to read less than the packet
gives, and not a test of the control: the sampled records are evidence for a firm's own procedure.
