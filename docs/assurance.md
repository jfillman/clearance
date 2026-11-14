# Assurance providers: giving a packet to a recipient and taking its receipt (P-1)

An [evidence packet](packet.md) is for someone: an audit firm, a GRC hub, a customer's security reviewer. This page is
how the subscriber opens one packet to one recipient for a window, how the recipient reads it, and how the recipient's
signed **acceptance receipt** comes back into the ledger and into the next packet.

Status: **Built** (P-1). Proven against fakes: `go test ./internal/server -run TestP1` is the whole flow (one command).

## Three rules

- **Verification, witness operation and acceptance are free and need no account.** A recipient reads a packet with
  the credential it was handed and signs a receipt with its own key. It never signs in to Clearance.
- **The subscriber grants access and Clearance records it.** Clearance never submits a packet on anyone's behalf and
  never pays a recipient. The subscriber names the recipient and hands over the credential; the core records that it did.
- **No page ever scores or ranks a subscriber.** A receipt is a recipient's statement about one packet.

"Never a Clearance account" means: no Clearance role or permission record, no password. A recipient is identified by a
key it registered (P-1) or, later, an external OIDC identity of its own (a hosted magic-link login is fine); it is never
a principal the core's authenticator maps to roles.

## The flow

```text
subscriber (admin)                       core                                recipient (no account)
 clearance packet --out dir ...
 clearance packet publish dir      -> POST /v1/packets                       (packet.publish record)
 clearance packet deliver pk-.. \  -> POST /v1/packets/{id}/deliveries       (packet.deliver record)
     --recipient firm --for 168h        returns the credential, once
 hand over credential + delivery id ------------------------------------>   GET /v1/packets/{id}   (packet.fetch record)
                                                                             sign a receipt with its own key
                                       POST /v1/packets/{id}/receipts <---   (packet.receipt record)
 clearance packet ... (next packet)    carries the receipt in Acceptances; `clearance verify` checks it offline
```

### Registering a recipient

A recipient is a provider of class `assurance` in `CLEARANCE_PROVIDERS`: a name, a version and its public keys (ECDSA
P-256, PKIX PEM, as `openssl ec -in key.pem -pubout` writes them), and nothing else:

```json
{"name": "acme-audit", "version": "1", "class": "assurance", "keys": ["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"]}
```

It has no `principals`, `kinds`, `targets` or `definitions`: it is not a caller of the core and `POST /v1/records` refuses
it. At most 8 keys (a key in use and the ones being rotated). Adding a key is how a recipient rotates.

### The packet in the core

`clearance packet` writes a directory. `clearance packet publish <dir>` (an admin: `CLEARANCE_ADMINS`, or a delegate
naming one) uploads it as a **bundle**: the directory as one JSON document (`clearance.packet-bundle/v1`, every file
base64, `MANIFEST.json` included), unchanged. The core checks every file against the manifest and that the packet was read
from **this** chain (the head it names is the hash the core holds at that count), keeps it in `clearance_packets`, and
writes `packet.publish`.

A packet's **id** is its content's address: `pk-` and the first 32 hex digits of the SHA-256 of `MANIFEST.json`, which
lists the SHA-256 of every other file. The same chain, window and parameters give the same packet, so the same id; publishing
it again records nothing. Any change to any file changes the id. That is what "forwarded unchanged" means here.

### Opening it to a recipient: the credential

`POST /v1/packets/{id}/deliveries` (admin) takes `{recipient, scope?, window: {from?, to}, engagement?}`:

- `recipient` is a registered assurance provider.
- `scope` is the parts of the packet it may read: `summary` (`packet.json`, the PDF, the CSV files) and `evidence` (the
  originals, proofs, checkpoint, attestations, OSCAL). Default both. `MANIFEST.json` goes with every part. A recipient cut
  to one part gets a partial packet, which `clearance verify` says.
- `window` is at most 30 days and at least a minute.
- `engagement`, when set, is the engagement the receipt must name.

The delivery is the `packet.deliver` record: the person (and delegate), the recipient, the scope and the window. The
answer carries the **credential**, once. It is a compact JWS (ES256) signed by the **core's own signing key** (the one
that signs clearance tokens, published at `GET /v1/keys`), `typ: clearance-packet-access+jwt`, with claims `iss`, `aud`
(`clearance-packets`: good for the packet routes and nothing else), `sub` (the delivery id, `dl-<seq of the record>`),
`packet`, `digest`, `recipient`, `scope`, `iat`, `nbf`, `exp`. The core issues it and verifies it itself, and it is
self-contained: a hosted front that only passes it through, and keeps its own register of grants, needs nothing but the
string. It is never stored: the chain holds the delivery, not the secret. A second delivery is a second credential.
A delivery can be [revoked](#revocation) before its window ends.

### Reading it

`GET /v1/packets/{id}[?part=summary|evidence]` with `Authorization: Bearer <credential>`. **Always credentialed**: there is
no public or unauthenticated read of a packet, and recipient-level detail is never served on a public route.

The credential's signature is checked first: anything the core did not sign is a bare 401 and writes nothing (the caller is
nobody). From there **every answer is a `packet.fetch` record, written before the answer**: an allowed read is recorded
before a byte is served (a read that cannot be recorded is not served: 503); a refusal is recorded with its rule, and
answered with it:

| Rule | Status | Meaning |
| --- | --- | --- |
| `PK-EXPIRED` | 401 | past the delivery's window |
| `PK-NOT-YET` | 403 | before the window |
| `PK-SCOPE` | 403 | another packet, or a part outside the credential's scope |
| `PK-REVOKED` | 403 | the delivery was [revoked](#revocation) |
| `PK-RECIPIENT` | 403 | the recipient is no longer registered |
| `PK-GONE` | 404 | the core does not hold the packet |

A request that arrives while the core cannot read the revocation state is refused 503 and written nowhere: a revocation that cannot
be read is never taken as absent. The path id must be a packet id (`pk-` and 32 hex digits): anything else is 404 with no record, before anything is read.
A leaked credential cannot fill the chain: per delivery and per hour, at most 60 refusals are recorded (past it the refusal
is answered 429 and not written) and at most `CLEARANCE_PACKET_READS_PER_HOUR` (default 60) allowed reads are served and
recorded (past it 429 with `Retry-After`, no record). The core keeps the last few validated packets in memory, so a read does
not reload and re-hash the whole bundle.

`clearance receipt pull --core URL --packet pk-... --out dir` (credential from `--credential-file`, `-` or
`$CLEARANCE_PACKET_CREDENTIAL`, never a flag) reads and unpacks it; `clearance verify dir` checks it.

### The receipt

A receipt is a DSSE envelope (`application/vnd.clearance.acceptance-receipt.v1+json`, ECDSA P-256 over the SHA-256 of the
pre-authentication encoding: the signing path tokens, grant feeds and attestations share) over this payload:

| Field | Meaning |
| --- | --- |
| `packet_id`, `packet_digest` | the packet (the id is derived from the digest) |
| `delivery`, `recipient` | the grant this answers, and the registered recipient |
| `engagement` | the recipient's own label for the review |
| `framework_mapping_versions` | the mappings the packet carried (`soc2/2017`, ...) |
| `checkpoint` | `{origin, size, root}` of the ledger checkpoint the packet stood on, or null |
| `verdict` | `accepted`, `accepted-with-notes` (at least one note), `questioned`, `rejected` |
| `control_notes` | notes keyed to a control id or an assertion id of the packet's mapping rows |
| `signed_at` | RFC 3339 |

`POST /v1/packets/{id}/receipts` takes the envelope. **The signature is the authentication** (no bearer token, no
credential: a firm signs offline and submits when it likes). The core checks that a key registered for the named recipient
signed it, that the delivery is a `packet.deliver` of this packet to that recipient, that the receipt binds this packet's
digest, mappings and checkpoint, that the engagement matches the delivery's if it set one, and that every note names a
row the packet's mappings have. Then it records `packet.receipt`: the envelope as received, the key it was checked with
and the payload's SHA-256. A receipt for a packet the recipient was not given, or signed with a key it did not register,
is refused (and not recorded: the caller is not attributable).

`clearance receipt sign --packet-dir dir --delivery dl-.. --recipient name --engagement E --verdict accepted --key key.pem`
makes one offline, for a firm with no system to sign from; `clearance receipt submit --core URL --receipt file` sends it.
A receipt is refused (403, not recorded) when its delivery is revoked (`PK-REVOKED`) or its key is revoked (`PK-KEY-REVOKED`): see
[Revocation](#revocation). Receipts are append-only statements: a later receipt for the same delivery does not replace the first; both are carried.
Submitting the same signed receipt again is idempotent: the answer is 200 with `created: false` and the record already written,
and nothing is written. Every decision and recorded field comes from the verified payload, never the unsigned envelope. A receipt
may be signed and submitted after the delivery's window ends (a firm finishes its review after its access lapses); it may not be
signed before the window began or in the future.

### The next packet

`clearance packet` carries every `packet.receipt` in the chain in its **Acceptances** section (packet.json
`acceptances`, `csv/acceptances.csv`, the PDF): each as signed, with the registered key it was checked with and its
record's seq and hash; the records themselves are carried too, so they have inclusion proofs when checkpointed.
`clearance verify` checks each receipt offline ([verify.md](verify.md#acceptance-receipts)). When a key a carried receipt was signed
with has been revoked, the packet also carries that revocation (`acceptances.key_revocations`, with its chain record): see
[Revocation](#revocation).

## Revocation

Three things can be revoked. Each is an admin call (`CLEARANCE_ADMINS`, or a delegate naming one; a recipient credential, a
recipient's signature or any other principal cannot), each writes a chain record **before** it answers, and each is idempotent:
the same call again is the first answer (`created: false`) and writes nothing. None can be undone.

| What | Call | Record | Effect |
| --- | --- | --- | --- |
| A delivery (its credential) | `POST /v1/packets/{id}/deliveries/{delivery}/revoke` `{reason}`; `clearance packet revoke <pk-id> <dl-id> --reason R` | `packet.revoke` | every read and sample under it is refused `PK-REVOKED`; a receipt for it is refused |
| A recipient's key | `POST /v1/assurance/recipients/{recipient}/keys/{kid}/revoke` `{reason, as_of?}`; `clearance packet revoke-key <recipient> <kid> --reason R [--as-of T]` | `assurance.key.revoke` | a receipt signed with it is refused at submit; `clearance verify` fails one signed at or after `as_of` |
| One of the core's retired token keys | `POST /v1/keys/{kid}/revoke` `{reason}`; `clearance keys revoke <kid> --reason R` | `token.key.revoke` | nothing it signed verifies; `GET /v1/keys` stops listing it |

`reason` is 1 to 200 printable characters. It is in the chain and in the packets that carry the record: put no secret in it.

### A delivery

After the record, a read of the packet (`GET /v1/packets/{id}`, any `part`) or a sample under the credential is answered 403 `PK-REVOKED`,
and the refusal is a `packet.fetch` (or `packet.sample`) record with that rule, like every other refusal. The refusal is subject to
the existing per-delivery caps: at most 60 refusals of a delivery are recorded an hour, and past that the answer is 429 and nothing is
written (the 429 still carries `rule: PK-REVOKED`). The check comes after the scope check, so a revoked credential asked for another
packet gets `PK-SCOPE` exactly as a live one does: the answer does not say whether a packet exists. A delivery that was never issued,
or is another packet's, is one 404 `no such delivery`.

**Receipts.** A receipt for a revoked delivery that is not recorded yet is refused `PK-REVOKED` (403, not recorded). Receipts already
recorded stay, and sending one of them again is still the same 200 `created: false`. A delivery is the subscriber's grant; revoking it
withdraws the grant, and a receipt answers a grant. A reviewer who signed offline before the revoke and submits after is refused; the
subscriber opens a new delivery for the same recipient and packet (fresh caps, a new credential) and the reviewer signs again naming it.

**How fast.** In the process that took the revoke, at once: a read holds a lock from the check of the revocation until its
`packet.fetch` record is written, and a revoke holds it from its own read of the chain until its record is written and the state updated.
So a read is recorded before the revocation record or refused, and no read begins after the answer and is served. (A read that was
already recorded may still be streaming its bytes: nothing can recall it.) In any other replica, within **one second plus one store
read**: each replica keeps the revocations it read from the chain, and a request that finds that copy older than one second reads the
chain's tail first (one indexed read when nothing is new) and folds in what it finds. A store that cannot be read refuses the request (503).
The chart runs one core, but the check never depends on one process's memory.

### A recipient's key

`as_of` is the time the key is distrusted from (RFC 3339; default now; a past time says "compromised since then"; never in the future). A
receipt signed with the key is refused `PK-KEY-REVOKED` at submit, whatever its signing time (403, not recorded). Receipts already recorded stay
recorded. Removing the key from `CLEARANCE_PROVIDERS` does not undo the revocation; the key must be a registered key of that recipient to be
revoked.

**How the offline verifier learns it.** Not from a live call. The next packet carries, in `acceptances.key_revocations`, the revocation of every
key a carried receipt was signed with: the recipient, the key id, `as_of`, and the seq and hash of the core's `assurance.key.revoke` record, which is
carried among the packet's records (so the chain checks and the inclusion proofs bind it). `clearance verify` then:

- **fails** a receipt signed (its `signed_at`) at or after `as_of`, and one the core recorded after the revocation record (the core refuses those);
- reports a receipt signed **before** `as_of` as valid as signed, and prints the revocation beside it;
- **fails** a revocation row that differs from the record it names, and says so when the record is not among the carried ones (the packet's word only).

A packet cut before the revocation does not carry it, so it verifies as it did: cut a new packet. A key that signed no carried receipt is not listed.

### One of the core's token keys

The core signs clearance tokens, packet credentials and grant feeds with one key (the key in use) and keeps the public half of
retired keys in `GET /v1/keys` for 24 hours, plus 30 days for credentials. Revoking a **retired** key (`POST /v1/keys/{kid}/revoke`) commits the record
and the key's revoked flag together. From then:

- a packet credential it signed is an unknown key: a bare 401, nothing written. The check reads the key table on every request, so it holds in every replica at once;
- `GET /v1/keys` (the core's and clearance-api's) leaves the key out. It is omitted, not flagged: a verifier that does not know a flag would go on trusting a flagged
  key, and one that does not find the `kid` refuses what it signed. A verifier that caches `GET /v1/keys` (the grant-sync agent: 5 minutes; the response says `max-age=300`)
  keeps trusting the key until its cache lapses;
- the key can never be used again: the core refuses to start with a revoked key.

The key **in use** is refused (409): rotate first (start the core with another key, [core.md](core.md)), then revoke the old one. The statement keys
(`GET /v1/statement-keys`) are a separate set read from the same rows and are not touched: a statement signed by the key stays verifiable as the statement keys say.

**Clearance tokens and the grant feed signed by the revoked key.** They are short-lived (15 minutes) and re-issued: a key that is no longer in use has had every
live token re-signed at the first refresh after the rotation (`gate.Service.Refresh` re-issues a token signed by any key but the one in use, and a read of a token does
too); the feed is re-signed by the core's minute loop for the same reason (`RefreshFeeds`). The revoke call runs both at once. Their old signatures stop verifying as soon as a
consumer re-reads `GET /v1/keys`, and the consumer holds the re-signed ones. A consumer holding a stale feed refuses it (fails closed) until it fetches the new one.

## Sampling a packet

A recipient with both parts in its scope can draw a sample of the packet's cleared changes with an inclusion proof per record,
under the same credential, caps and record-before-serve ordering: see [sampling.md](sampling.md).

## The verification statement

A subscriber who wants to hand someone a link, not a packet, cuts a [verification statement](statement.md) from a published packet: a signed public summary with
no recipient-specific detail, checked on a hosted page and by `clearance verify --statement`. The recipient detail it was cut from is this page's packet route.

## Known limits

- **A leaked credential can use up a delivery's caps** (reads and refusals per hour; the sampling call's 20 distinct samples)
  and so lock the real recipient out of that delivery. It cannot read more than the recipient could. Remedy: [revoke](#revocation) the
  delivery, and create a new one for the same recipient and packet, which has fresh caps.
- The refusal and read counters are per core replica (the core is one replica) and per wall-clock hour.
- **Revocation does not recall a packet.** A recipient who already downloaded it still has it, and a revoked delivery's earlier
  reads stay in the ledger as reads. Revoking stops further reads, samples and receipts; it cannot un-send bytes.
- The credential verifies against the core's token keys: the key in use and keys retired within the last 24 hours plus the longest
  credential life (30 days) are accepted, so a retired key keeps verifying credentials it signed until they expire **unless it is
  [revoked](#one-of-the-cores-token-keys)**. Rotating the key does not by itself invalidate credentials already issued.
- A key revocation reaches an offline verifier only through a packet cut after it (see [Revocation](#a-recipients-key)); a verifier that is
  handed an older packet cannot know.
- A delivery is not listed or read back by an admin route: the revoke answer is how its state is seen (and the `packet.revoke` records in the chain).
  No route lists deliveries yet; packets cut later carry key revocations, not deliveries.
- `Bundle.Unpack` writes slash paths as given; it has not been run on Windows file systems.
- `clearance verify --recipient-keys <recipient>=<file>` (repeatable) binds keys to recipients: a receipt naming A verifies
  only under keys supplied for A. Without a key for a recipient the receipt's own copy is used (SELF-VOUCHED). A receipt whose
  chain record the packet does not carry is NOT CHECKED (signature only).

## What this is not

- Not a review: a receipt shows a recipient signed a statement about a packet with a registered key, not that the review was right.
- No OIDC recipient identity yet: a recipient is a registered key. An external OIDC identity (keyless signing, or a hosted
  login in front of the credential) is a later step; the receipt format does not change.
- No push of a packet to a recipient's system: the subscriber hands the credential over. (What Clearance does push, a summary and a link and never the packet, is the [GRC push](grc-push.md).)
