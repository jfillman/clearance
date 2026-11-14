# The verification statement and the hosted verify page (P-3)

A subscriber hands a prospect, a carrier or a reviewer one link. The page at that link says one word, **VERIFIED**,
**INCOMPLETE**, **FAILED**, **SUPERSEDED** or **REVOKED**, in one colour, and behind a click shows seven checks, each run
now, each with what it proves and what it does not. The statement behind it is the [evidence packet](packet.md)'s fourth
derived view: a signed, immutable public summary of one packet. Anyone can check it without Clearance:
`clearance verify --statement`.

Status: **Built** (P-3), code merged and proven against fakes: `go test ./internal/server -run TestP3StatementGate -count=1`
issues a statement for a lab change, reads it through the real public handler over a real socket with JavaScript-free
HTML, and verifies it offline. **The hosted proof on the production hostname is a later gate.**

> **The public route is not enabled until a security review pass has signed it off.** It is the first Clearance route
> reachable without an identity. It ships **off**: with `verifyPage.enabled: false` (the chart default) and
> `CLEARANCE_VERIFY_LISTEN` unset (the core's default) there is no listener, no port, no Service, no HTTPRoute and no
> NetworkPolicy rule for it. Enabling it is one value; do not set it until the review in
> [section 12 of the spec](#the-security-review-pass) is signed. The authenticated routes (issue, revoke) are not public
> and are not gated by this.

## What it does

- **A signed public summary, and nothing recipient-specific in it.** Period, the scope as the subscriber prints it, the policy
  version, counts by **every** coverage state, exceptions by **every** class and how many are unresolved, the
  observation-health summary with every **blind window**, the verification result, how many receipts were attached and
  their verdicts, and a questionnaire-mapping block. No record id, proof, exception row, person, firm, repository,
  cluster, account or host name is in it.
- **Seven checks, run on the page and offline by the same code.** The page calls `internal/verify`, the package behind
  `clearance verify`; there is no second implementation to disagree with.
- **A statement can only be complete.** The scope is the only choice. There is no field to leave out a total, a
  coverage state, an exception class or the unreconciled count, and a period the feeds could not see is printed whatever
  the subscriber would prefer. A statement from a packet that disagrees with itself is not cut.
- **Corrections supersede, withdrawals revoke.** `supersedes` on a new statement makes the old one verify as
  **SUPERSEDED**, pointing at its successor; `POST /v1/statements/{id}/revoke` makes it verify as **REVOKED**.
- **An insurer profile** (`profile: insurer`): the share of critical changes (tier 3) cleared by two independent people
  (from C-14's `kind: person`), each unresolved exception with its recorded disposition, telemetry coverage per scope as a
  share of the period, the agent share of changes, and a mapping block in carriers' words (privileged change, separation of
  duties, unauthorized-change detection).
- **It never scores or ranks.** The page prints counts and says what each is evidence for. It does not grade a subscriber.

## Guardrails

- **Off by default, one value to enable, and a separate listener.** `CLEARANCE_VERIFY_LISTEN` (chart:
  `verifyPage.enabled`) starts a second `http.Server` with its own handler. The authenticated API's port does not serve
  the page and the page's port does not serve the API (asserted in `internal/core`'s tests). Settings of the page without the
  listen address are refused at start, so a half-configured core does not look enabled.
- **Recipient detail is never on the public route.** The open route serves the public summary and two downloads (the signed
  statement, the signed status). The records, proofs, exception rows and the names of firms are the *recipient detail*:
  the subscriber opens them to a named recipient through the existing packet routes ([assurance.md](assurance.md)), which are
  credentialed and recorded. Assertions on the response bodies (`TestP3ThePublicRouteIsNoOracleAndTakesNothing`) look for a
  recipient, an approver, a repository, a cluster, a scope's real name, an actor and a resource.
- **No oracle.** An id is `st-` and 32 hex digits: **128 random bits** from `crypto/rand`, not derived from the packet and
  not sequential, so nothing can be enumerated and one in 2^128 guesses finds a statement. A malformed id, an unknown id,
  a path the listener does not serve and an id with a parameter all get the same answer for the same reason: one `404`, byte
  for byte, with the same headers (a malformed id costs the same lookup an unknown one does). The only distinctions are the
  ones the spec requires: a statement exists and shows its state (valid, superseded, revoked). There is no expiry, so there is
  no "expired" case to tell apart. A superseded statement names its successor's id, as the spec requires.
- **No parameters.** The listener takes none: a query string of any name, even an empty `?`, is `400`, whatever the id is. The path is
  validated before it reaches a lookup, a log line or a response, and nothing the request says (path, host, header) is
  reflected.
- **Abuse limits without lockout, and the right client.** A token bucket per client, in fixed memory (a keyed hash of the client's
  address picks one of 4096 buckets, so the table cannot be grown and one address cannot aim at another's bucket); past it `429`
  with `Retry-After`. A bucket refills with time: nothing is blocked longer than its refill. The per-client limit is charged to every
  request before the route is looked at, so guessing ids costs budget. A second, global bucket bounds only the work that costs
  something: a verification that must be computed (a result not yet cached) is charged to it, and refused `429` when it is spent;
  cheap answers (a 404, a cached page, a status, a download) are limited per client only, so addresses that drain the cheap paths cannot
  starve everyone else's reads. At most 2 verifications run at once (the next is `503` with `Retry-After`). Defaults: 30 requests a
  minute per client with a burst of 10; 600 a minute and a burst of 100 for computed verifications.
  **Who the client is.** Behind a Gateway the connection's address is the Gateway's, so one budget would be the whole internet's. The
  listener therefore counts `X-Forwarded-For` from the **right** by the configured number of trusted proxy hops (what a client prepends
  is never read; a header too short for the hops falls back to the connection). That is only safe if the pod is reachable from the
  Gateway alone, otherwise the header is a client's to forge. So: the core **refuses to start the listener with 0 hops** unless
  `CLEARANCE_VERIFY_DIRECT_EXPOSURE=true` says there is no proxy (and refuses that setting with hops above 0); the chart refuses to
  render with `verifyPage.limits.trustedProxyHops` below 1 (default 1) unless `verifyPage.directExposure: true`, and refuses hops above 0
  without `networkPolicy.enabled`. IPv6 clients count by their /64.
- **Anonymous traffic cannot grow the chain.** No request to the public listener writes a record, a cookie or a file
  (asserted: the chain's head is unchanged after many reads, refusals and 429s). Only the authenticated issue and revoke write,
  and both are idempotent.
- **Constant-ish work per request.** Checks 1 to 6 rest on immutable data and this deployment's trust inputs, so they are run
  **once** per statement (and again after ten minutes), single-flight, and only for an id the chain holds a statement of. An
  invented id costs a map lookup. The index of statements holds small entries only (no envelope: it is read from the statement's record
  when wanted), at most `MaxStatements` of them, and public requests take only its read lock: they never wait on an issue, a revoke
  or a slow store, and they never scan the chain (a cold index is `503` until the background warm succeeds). A run reads the packet this core already holds; **no request makes the server fetch anything**
  (no witness lookup, no URL: the core's own store is the only thing read). Check 7 and the status are read fresh each time.
- **Caching that fits a revocable object.** The page and the status are `Cache-Control: no-store`: a revoked statement is
  revoked on the next load, whoever holds an earlier copy, and no shared cache can serve it as valid. The cost is bounded by the
  limits and the result cache. The signed statement is immutable, so it is `no-cache` with a strong `ETag` (revalidated, `304`
  when unchanged); whether it is still current is the status, never a cached document.
- **Revocation is the core's current state, and the page says as of when.** The index of statements is read from the chain
  and kept current by re-reading the chain's tail at most once a second, so a revocation written by another replica, or before
  a restart, is seen within a second. If the store cannot be read (the index is older than ten seconds and cannot be refreshed) the
  page is `503`: it never says valid on a state it could not read. The page prints "State read <time>", and that time is when the index
  was last read from the chain, so neither the page nor the signed status claims to be fresher than the read behind it. A statement
  that was replaced by one that was **itself revoked** does not read as cleanly superseded: its status carries `successor_revoked`,
  the page says the correction was itself revoked and that no statement in the chain is current, and the verifier says so and exits 1.
- **What is shown is what was signed, for this id.** The page shows a statement's content only when checks 1 and 2 pass **and** the
  signed document's id is the id in the URL; otherwise it shows the failure and none of the summary.
- **A statement the packet does not support is never signed.** The packet is the admin's to publish, so at issue the core runs checks 3
  to 6 on the statement it built, against the packet, with the same code the page runs, and refuses `422` if any **fails**. A check whose
  input is missing is not a refusal (the page shows it NOT CHECKED). Nothing is recorded for a refusal: no statement exists.
- **A revoked statement is not answered as if it stood.** The same request as a revoked statement is `409` (naming the revoked statement),
  not `200 created: false`. To issue the same content again, send `reissue: <the revoked id>`: a new statement with a new id, whose record
  says which revoked one it replaces. `supersedes` is for a statement that stands; a revoked one cannot be superseded.
- **HTML with no script.** The page is server-rendered with `html/template` (contextual escaping), has no JavaScript, no inline
  script, no event handler, no cookie, no third-party asset and no user-controlled URL or attribute. The Content-Security-Policy
  is `default-src 'none'; style-src 'sha256-<the page's one style>'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`.
  Also `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and
  `Cross-Origin-Resource-Policy: same-origin`. The checks are behind a `<details>` element: it works with JavaScript off.
- **Soundness.** A check whose inputs are missing is **NOT CHECKED**, never a pass. Nothing is decided on the statement until its
  signature has verified. Keys are bound to the party they are for: the statement's own claim of who issued it is not trust.
  Revocation is checked against the issuer's current state. See [the seven checks](#the-seven-checks).
- **Issuing and revoking are authenticated, admin-gated, idempotent and recorded before they answer.** `statement.issue` and
  `statement.revoke` are chain records written before the response; the same request again is the same statement and writes
  nothing; a write that fails is not served. No credential is in a record, a log or an error.
- **Chart:** `verifyPage.enabled: false`; its own Service, HTTPRoute (the `/s/` prefix only) and an ingress-only NetworkPolicy to the
  Gateway; the hostname, the route's parents and the policy peers have **no default** (the chart refuses to render without them), and
  nothing it renders is a lab value (no `hostAliases`, no address, no `.local` host).

## The seven checks

The page and `clearance verify --statement` run these, in this order. Each is reported on its own line. The word at the top is
**VERIFIED** only when all seven passed.

| # | Check | Verified against | What a pass proves | What it does not prove |
| --- | --- | --- | --- | --- |
| 1 | Signed by the issuer's Clearance identity | The issuer's published keys (`GET /v1/keys`) you hold, and the issuer name you pin (`--statement-issuer`); on the page, this core's own keys and issuer | A key you hold for that issuer signed the statement. Without `--statement-issuer` the check is SELF-VOUCHED: the name is the statement's own claim | That the issuer is trustworthy |
| 2 | The signature is valid and the signed document is the one read | The DSSE signature over the payload, and the payload equal to the canonical form of the document it carries | Nothing in the statement was changed after it was signed, and what you read is what was signed | Anything about the content |
| 3 | Every cited record has an inclusion proof under a checkpoint | The packet the statement names (its manifest digest, its records' digest, its checkpoint), the packet's records and proofs, and **your** log keys and witness policy (`--log-keys`, `--witness-policy`) | The statement is cut from this packet; the records it cites are exactly the packet's; each one hashes to what it states, is linked in the chain, and proves into a checkpoint the log signed. A record recorded after the checkpoint is **not** a pass (NOT CHECKPOINTED): issue the statement for a period that ended before the newest checkpoint | That the records are complete before the log began |
| 4 | The checkpoint is countersigned by a witness Clearance does not run | The checkpoint's countersignatures under your witness policy, and the witnesses **you** know the issuer does not run (`--independent-witness <name>`, or `<name>=<the witness key as the policy lists it>`, which must be that key in the policy under that name) | A witness the issuer does not run has seen this log, so it cannot be rewritten or shortened unnoticed. The hosted page is the issuer, so it can verify the countersignature but not who runs the witness: on the page this row reads **PASS, INDEPENDENCE DECLARED**, names the witness, says in plain words that the independence is the issuer's declaration, and the word may be VERIFIED only with that declaration shown in the summary (not behind the click) and the command that confirms it (`--independent-witness <name>=<key>`); it is never a plain PASS. With no independent witness the check prints **NOT INDEPENDENTLY WITNESSED** ("not yet independently witnessed") and is never a pass. Without `--independent-witness`, the statement's own declaration of its independent witnesses is used and the check is SELF-VOUCHED at best | That the witness is competent or honest |
| 5 | The counts recompute from the cited records | `packet.json` and the records, by `statement.Summarize` (the function the issuer built the statement with) after the packet verifier's own recount of the packet's figures from its records and, for receipts, each receipt's signature under the recipient keys you supply | Total records, every coverage-state count, the cited-records digest, the period, the ledger result, the receipts and the insurer figures equal what the records give | That the records describe every change in the organisation |
| 6 | Exceptions and observation health are present and match | The same recomputation, and the scope statements rebuilt from the records (`observe.Build`, as the packet check does) | Every coverage state, every exception class and every observed scope is listed (a state left out would read as none); the exceptions by class and unresolved count and the health, blind windows included, equal the packet's; every exception row cites a record the packet carries | The exceptions' rows are presentation of the records (as the packet verifier already says): the class and resolution of a row are not recomputed from the records, only that they agree with the packet and cite carried records |
| 7 | Not superseded or revoked | The issuer's current state: on the page, the core's own, read now; offline, the signed status (`GET /s/<id>/status.json`) fetched now (`--status`) and no older than `--status-max-age` (default **1h**: a status that said valid an hour ago may not be now; the report prints "CURRENT STATE AS OF") | At the time printed, the statement was neither revoked nor replaced by a correction | That it is not revoked a minute later |

Exit codes of `clearance verify --statement` are those of the packet and sample verifiers: **0** only when every check was
run and passed against trust inputs you supplied; **1** when anything failed (including a revoked or superseded statement);
**2** when nothing failed but something could not be established (a trust input missing, SELF-VOUCHED, NOT CHECKPOINTED, NOT
INDEPENDENTLY WITNESSED, a stale status). A caller must not read 2 as a pass.

## Issuing a statement

```sh
# a packet of the packet view, published (POST /v1/packets), whose records all stand under a witnessed checkpoint
curl -X POST $CORE/v1/statements -H "Authorization: Bearer $ADMIN" \
  -d '{"packet":"pk-...","scope":"Production change management","policy_version":"gate-1.4","profile":"standard"}'
```

- `packet`: a published packet of the packet view. Its period, its observed scopes and its records are what the statement
  summarises. **Narrowest reading of "from a period, a scope and a policy version":** the period and the observed scopes are the
  packet's; `scope` is the subscriber's printed label (the names of the accounts and clusters stay in the packet), and
  `policy_version` is printed text.
- `profile`: `standard` (default) or `insurer`.
- `supersedes`: the id of the statement this one corrects. The old one then shows SUPERSEDED. A revoked statement cannot be
  superseded, and a statement can be superseded once.
- `reissue`: the id of a **revoked** statement this one issues again with the same content (a new statement; its record says which revoked
  one it replaces). Without it a request matching a revoked statement is `409`.
- The answer carries the id, the state, the digest and the page's paths. The same request again is the same statement
  (`created: false`) and writes nothing. To issue a new statement for the same packet, scope and policy version, supersede the old one.
- Opening the recipient detail to a reviewer is the existing packet route: `POST /v1/packets/{id}/deliveries`, which mints a
  time-boxed credential and records the grant.

`POST /v1/statements/{id}/revoke` with `{"reason": "..."}` (recorded, never published). Revoking a revoked statement
answers the same and writes nothing.

## Configuration

| Variable | What it does |
| --- | --- |
| `CLEARANCE_VERIFY_LISTEN` | The page's own listen address, e.g. `:8081`. **Unset: no listener, no public page.** Do not set it before the security review |
| `CLEARANCE_STATEMENT_LOG_KEYS_FILE` | The log's public keys (signed-note vkeys, the key in use first): the trust input of checks 3 and 4. Unset: those checks are NOT CHECKED |
| `CLEARANCE_STATEMENT_WITNESS_POLICY_FILE` | The witness policy (default: the ledger's own) |
| `CLEARANCE_STATEMENT_INDEPENDENT_WITNESSES` | Comma-separated names of the log's witnesses you assert you do **not** run. **Unset (the default, and the lab): none, so no statement can say it is independently witnessed** |
| `CLEARANCE_VERIFY_PUBLIC_URL` | An https base URL, no path, printed on the page. Never taken from a request's `Host` |
| `CLEARANCE_VERIFY_RATE_PER_CLIENT`, `_BURST_PER_CLIENT`, `_RATE_GLOBAL`, `_BURST_GLOBAL` | The limits (defaults 30/10 and 600/100) |
| `CLEARANCE_VERIFY_TRUSTED_PROXY_HOPS` | Trusted proxies in front of the listener. **0 needs `CLEARANCE_VERIFY_DIRECT_EXPOSURE=true`** (the core refuses to start otherwise); above 0 is safe only if the pod is reachable from the proxy alone |
| `CLEARANCE_VERIFY_DIRECT_EXPOSURE` | `true`: the listener is reached directly, with no proxy; refused together with hops above 0 |
| `CLEARANCE_VERIFY_MAX_CHECKS` | Verifications that may run at once (default 2) |

## Checking it offline

```sh
curl -O https://verify.example.com/s/st-.../statement.json
curl -o status.json https://verify.example.com/s/st-.../status.json      # fetched now: revocation is current state
clearance verify --statement statement.json \
  --statement-keys issuer-keys.json --statement-issuer clearance \
  --log-keys log-vkeys.txt --witness-policy witness-policy.txt --independent-witness some-witness=<its key from the witness policy> \
  --packet ./packet-the-subscriber-opened-to-you --status status.json
```

(`verify.example.com` is a placeholder.) `--packet` is the packet directory the subscriber opened to you (`clearance receipt pull`),
which is the recipient detail the statement was cut from. The **published trusted root** is what you hold from the issuer: the core's
keys, the log's keys, the witness policy and the names of the independent witnesses. Without a flag, its check is NOT CHECKED or
SELF-VOUCHED and the exit is 2 (without `--statement-keys` checks 1 and 2 cannot run, and nothing else is checked either: nothing
is decided on an unverified statement).

## The format

[schemas/statement.schema.json](https://github.com/jfillman/clearance/blob/main/schemas/statement.schema.json) is the JSON schema of the
signed document (`clearance.statement/v1`) and, in `$defs.status`, of the status. The envelope is DSSE with payload type
`application/vnd.clearance.statement.v1+json`, signed ES256 by the core's clearance key (the key `GET /v1/keys` serves); the payload is
the document's canonical JSON (keys sorted, no insignificant whitespace), so a verifier needs no Clearance code to check it: verify
the DSSE signature, then check the payload's bytes are the canonical form of the JSON they hold. The rules checks 3 to 6 apply are
those of [verify.md](verify.md) and `internal/statement`.

Numbers are integers only: the insurer profile's shares are tenths of a percent (`critical_two_approver_share_per_mille`), so no floating
point is signed. `cited_records.sha256` is the SHA-256 of `"<seq>:<record hash>\n"` for each record the packet carries, in seq order.
The log's origin (its name, which may be a host name) is not in the document, not even as a hash a guess could confirm; the checkpoint is `size` and `root`.

The questionnaire-mapping block is data shipped beside the control mappings (`internal/statement/data/questionnaire.json`): SOC 2 CC8.1 and
CC6, ISO/IEC 27001 A.8.32, NIST SP 800-53 CM-3 and CM-5, the SIG change-control and AI topics (by topic name, not question number) and, for
the insurer profile, privileged change, separation of duties and unauthorized-change detection. It is worded as evidence **for** an
objective. It is not a claim that the objective is met.

## What a statement publishes

To anyone holding its id, a statement publishes: the issuer name, the subscriber's printed scope label and policy version, the period, counts, the
observation-health summary with blind windows' times, how many receipts and their verdicts, the names of the witnesses the deployment declares
independent (and, on the page, which of them countersigned), the **packet id and digest** and the **ledger checkpoint's size and root** (the size is
how many records the whole chain held at the checkpoint, which is needed to check a proof; the root is a hash). The **issuer** is constrained at issue
to a plain label (letters, digits, spaces, hyphens: no dot) or an https URL with a public host: an `.local`, `.internal`, `.lan` or similar name, an
IP literal, a bare port or a non-https URL is refused, so choose `CLEARANCE_TOKEN_ISSUER` as a name you are content to print. A bare host name with no
dot is indistinguishable from a label and is accepted as one. Nothing else deployment-wide is in it: no record id, no origin of the log, no cluster,
account, repository, person or firm.

## Keys over time

A statement is verified with the issuer's key that signed it, and a key leaves `GET /v1/keys` a month after it retires. So the core keeps published
every key that signed a statement that has **not been revoked**, for as long as that statement exists (and the page uses the same set): rotating the
signing key does not stop an earlier statement from verifying. An offline verifier gets an old key from `GET /v1/keys` (it is there while the statement
stands) and should keep a copy of the keys file next to the statement it archives: once a statement is revoked its key may leave the list, and a
revoked statement needs no key to be read as revoked.

## What the seven checks do not prove, in one place

The statement counts clearances and shows what the observation feeds could not see. It does not judge the changes, it does not show that
the scope the subscriber chose is the whole organisation, it says nothing about a period a feed could not see (the blind window is
printed, not filled in), and it never scores or ranks a subscriber. All seven green on the hosted Cloud environment is proven at a later
gate; **in the lab the honest answer is INCOMPLETE** with check 4 "not yet independently witnessed", because the lab's only witness is
the lab's own.

## The security review pass

Section 12 of the Clearance spec makes the public verify page a surface that gets a security-review pass before its route is rendered.
This page is built to the findings of the P-1, P-2 and P-4 reviews: every path and query input is validated before it reaches a lookup,
a log or a response; the route is no oracle; limits are per client and global with `429` and bounded memory; no anonymous request writes a
record; the caching headers fit a revocable object; html/template with a strict CSP; no request makes the server fetch anything; and each
has a negative test. **That is not the review.** Enable `verifyPage` only after the pass is signed off, and then only with the hostname
and DNS and certificate the production deployment owns.

## Known limits

- **Single replica.** The core is one replica (the one writer of the chain). The index of statements is per replica, read from the chain: a
  revocation by another replica would be seen within a second (the tail read), and issuing is serialised by one writer, as for the other packet routes.
- **The public listener shares the core's process.** It is a separate listener with its own handler and limits, but a fault in it (a panic is
  recovered, a memory or CPU exhaustion is not) shares a blast radius with the core that holds the evidence chain's one writer lock. The page is
  bounded (2 concurrent verifications, fixed-memory limiter, size caps, a 10s handler timeout) and the recommendation is that the hosted deployment runs
  it as **its own process** later, reading the store with a read-only credential.
- Check results 1 to 6 are kept for ten minutes. A rotation of the log keys or the witness policy is seen after that, or after a restart.
- A statement holds at most `MaxStatements` (5000) per core.
- A statement is cut from a packet of the packet view; a freeze or incident packet is refused.
- The page's `clearance verify` command prints placeholders for the trust inputs: they are the reader's to supply.

## What this is not

Not a trust-center platform, not the auditor portal (P-5) and not part of the operational UI or the Cloud portal; it imports neither. It does
not submit anything to anyone, it does not pay anyone, and it does not score.
