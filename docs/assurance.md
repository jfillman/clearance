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
There is no revocation in P-1; keep windows short.

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
| `PK-RECIPIENT` | 403 | the recipient is no longer registered |
| `PK-GONE` | 404 | the core does not hold the packet |

The path id must be a packet id (`pk-` and 32 hex digits): anything else is 404 with no record, before anything is read.
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
Receipts are append-only statements: a later receipt for the same delivery does not replace the first; both are carried.
Submitting the same signed receipt again is idempotent: the answer is 200 with `created: false` and the record already written,
and nothing is written. Every decision and recorded field comes from the verified payload, never the unsigned envelope. A receipt
may be signed and submitted after the delivery's window ends (a firm finishes its review after its access lapses); it may not be
signed before the window began or in the future.

### The next packet

`clearance packet` carries every `packet.receipt` in the chain in its **Acceptances** section (packet.json
`acceptances`, `csv/acceptances.csv`, the PDF): each as signed, with the registered key it was checked with and its
record's seq and hash; the records themselves are carried too, so they have inclusion proofs when checkpointed.
`clearance verify` checks each receipt offline ([verify.md](verify.md#acceptance-receipts)).

## Sampling a packet

A recipient with both parts in its scope can draw a sample of the packet's cleared changes with an inclusion proof per record,
under the same credential, caps and record-before-serve ordering: see [sampling.md](sampling.md).

## Known limits

- The refusal and read counters are per core replica (the core is one replica) and per wall-clock hour.
- No credential revocation: keep windows short. The credential verifies against the core's token keys: the key in use and keys
  retired within the last 24 hours plus the longest credential life (30 days) are accepted, so a retired key keeps verifying
  credentials it signed until they expire; the core has no way to mark a key revoked.
- `Bundle.Unpack` writes slash paths as given; it has not been run on Windows file systems.
- `clearance verify --recipient-keys <recipient>=<file>` (repeatable) binds keys to recipients: a receipt naming A verifies
  only under keys supplied for A. Without a key for a recipient the receipt's own copy is used (SELF-VOUCHED). A receipt whose
  chain record the packet does not carry is NOT CHECKED (signature only).

## What this is not

- Not a review: a receipt shows a recipient signed a statement about a packet with a registered key, not that the review was right.
- No OIDC recipient identity yet: a recipient is a registered key. An external OIDC identity (keyless signing, or a hosted
  login in front of the credential) is a later step; the receipt format does not change.
- No credential revocation, and no push of a packet to a recipient's system: the subscriber hands the credential over.
