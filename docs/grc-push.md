# GRC push, Vanta first (P-4)

`clearance-grc` sends a **summary** of each production change, and a daily **coverage report**, to a GRC hub as evidence items
that link back to Clearance. The signed record stays in Clearance; the hub holds a pointer, never a copy.

Status: **Built against a fake Vanta, not run against a real tenant.** `go test ./internal/server -run TestP4GRCPush` is the
whole flow in one command (a real core, a fake clearance-api and a fake Vanta). The run against a Vanta sandbox is the owner's
step: [Run it against a Vanta sandbox](#run-it-against-a-vanta-sandbox).

## The hazard this is built around

Vanta's sync **replaces the whole set**: whatever a push leaves out is deleted at Vanta. So every way the set can come out
short (a failed read, a typo in a filter, a clock error, an empty database, a cap, a parse error, an item that aged out)
would delete evidence there. `clearance-grc` therefore never sends a set it cannot vouch for. Each guard below is tested:

- **Complete source.** It reads the changes of every configured environment in the states `cleared`, `superseded` and
  `exception` page by page. A page that is not a change page (`{}`, `null`, no `items`) is an error, not an empty page; a
  record that does not parse refuses the cycle (reason `unreadable-source`, with the count); a read that stops with more
  pages available, or a set over `CLEARANCE_GRC_MAX_ITEMS`, refuses the cycle (reason `truncated`, with the counts). It never
  pushes a capped or partial set as if it were whole.
- **Never empty, never much smaller.** An empty set is never sent, and neither is one smaller than
  `CLEARANCE_GRC_MIN_SET_RATIO` (default 0.8) of the last set this process sent (reason `shrink-refused`, with both sizes in
  the log). The floor is held in memory only, so on the first cycle after a start only an **empty** set is refused. The one
  setting that turns this off is `CLEARANCE_GRC_ALLOW_SHRINK=true`; leave it false.
- **Evidence is what was cleared, whatever it is now.** A change leaves `cleared` when the next head supersedes it or an
  exception flags it, yet it was cleared and deployed. The set is every change **cleared within the window** (a change is
  cleared when `cleared_by` is set, which survives those moves; `state` is sent as the current state), so the hub holds the
  window and not just the latest change per application. A change that was superseded without ever being cleared is not
  evidence and is not sent.
- **A refusal is a record, never silence.** Each refusal and each failure is a `grc.push` or `grc.report` record with a
  `result: failed` and its reason; each pushed set is a record with how many items left the set since the last push, so a
  shrink from the window ageing items out is explainable.
- **Ageing out is expected.** Items leave when their clearance is older than `CLEARANCE_GRC_WINDOW` (90 days). Set it to the
  audit period; the signed record and the packet stay in Clearance.

## What it does

- Each change **cleared in the window** in the configured environments (default `prod`) becomes one evidence item at the hub:
  origin, tier, approver kind and count, the digest of what was cleared, the policy version, the control identifiers it is
  mapped to, and a **link back** to the change in Clearance.
- A **coverage report**, one item per environment and UTC day (whole days: the window starts on a day boundary), of counts
  only: changes decided, cleared by tier (a change since superseded still counts as cleared), denied, exceptions, degraded,
  other (expired, or superseded without being cleared), and how many were cleared by people. Every state is counted in the
  total. It is pushed every 24 hours (`CLEARANCE_GRC_REPORT_INTERVAL`) and at start, in its own loop so its retries never delay
  the evidence.
- Every push and every failure is a **ledger record** (`grc.push`, `grc.report`), so what was sent, when and whether it
  landed is itself evidence.

## Guardrails

| Guardrail | How it is held |
| --- | --- |
| **Off unless configured** | With no `CLEARANCE_GRC_TARGET` the binary says so and exits 0; nothing is sent. The chart renders none of it unless `grc.enabled`. |
| **Only what the card says leaves** | The fields below are the whole of it. A test holds every outbound body to that table (`TestNothingButDocumentedFieldsLeaves`) and checks that a change's repository, pull request, paths, proposer, approver names, checks and cluster appear in no body. |
| **Idempotent** | An item's id is `clearance-change-<change id>`; the hub replaces its set with the one sent, so a retry, a restart or a second sender leaves one item. The ledger record carries the event id `hub:item id:item digest`, so the core records an item once however often it is told. An unchanged set is sent again every `CLEARANCE_GRC_RESEND_EVERY` (6h), so data lost at the hub is restored without a restart. The report's record names the day, so two days with the same figures are two records. |
| **Bounded retries, never silent, never blocking** | A retryable failure (429 with `Retry-After`, 5xx, a network error) is retried up to `CLEARANCE_GRC_MAX_ATTEMPTS` (5) times with exponential backoff and jitter (base 2s, cap 2m). A `Retry-After` longer than the backoff cap ends the cycle at once (the next tick tries, not sooner). Then a `grc.push` record with `result: failed` and the failure class is written (one an hour per class, however many cycles fail), the cycle is logged as an error, and the next cycle starts again from clearance-api: nothing is queued in memory. A record the core refuses for one item is skipped and logged; a core that cannot take records stops that loop and it is retried next cycle. The service is a separate process that only reads clearance-api; the core never calls it and waits for nothing from it (`TestP4GRCPush` keeps clearing changes while the hub is down). |
| **The link back is configured** | `CLEARANCE_GRC_LINK_BASE` (https always) plus `/changes/<id>`. It is never built from a request, a header or a change field; a change id that is not a plain identifier (`[A-Za-z0-9._:-]`, 128 at most) is not sent. |
| **Outbound URL from config only** | The hub's origin is `CLEARANCE_GRC_VANTA_BASE_URL`: https only, no credentials, query or fragment. (A loopback http hub exists for a fake in a test, through a constructor option, never a setting.) `CLEARANCE_API_URL` and `CLEARANCE_URL`, which receive the service-account token, are https or http to an in-cluster service host (a single-label name, `*.svc`, `*.svc.cluster.local`). Redirects are never followed, and the environment's proxy settings are ignored unless `CLEARANCE_GRC_USE_PROXY=true`, so the token and payload go to the configured host only. |
| **Response bodies are capped** | At most 64 KiB of any hub answer is read, and none of it is kept: an error carries a class and a status, never the hub's text (which can echo what was sent). |
| **No token in records, logs or errors** | The client secret is a file (`CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE`, no plaintext variable), read again at each token mint; the access token is held in memory only, for its hour. Tests grep the chain, the logs and every error for the secret and the token (`TestNoTokenInRecordsLogsOrErrors`, and the chain in `TestP4GRCPush`). |
| **Narrow credentials** | The token asks for `connectors.self:write-resource`, nothing else. The service is a `notifier` of clearance-api (changes only: never a token, never an evidence record) and a provider of the core for `grc.push` and `grc.report` alone. |
| **Off the decision path** | No core route calls it; a down hub, a rate limit or a bad credential changes nothing about a clearance. |
| **The core checks its records** | `grc.push` and `grc.report` are held to their shape by the core, not trusted: `result` is `pushed` or `failed` (a failure names a reason from a fixed list), the hub a plain name, the change only an identifier, the destination only the hub, an https link and two counts, and no other field (`TestGRCRecordsAreCheckedByTheCore`). |
| **Health** | `/healthz` is the process (liveness); `/readyz` fails when the evidence or the report loop has been failing for longer than `CLEARANCE_GRC_UNREADY_AFTER` (30m), so a vendor outage takes the pod out of rotation without restarting it. |

## Every field sent

An evidence item is `displayName`, `uniqueId`, `externalUrl` and these flat properties (`customProperties`). Nothing else of a
change is read into an item.

| Property | Type | What |
| --- | --- | --- |
| `origin` | string | who made the change: `person`, `agent`, `automation` (the proposer's kind, never a name) |
| `tier` | int | the clearance tier, 0 to 3 |
| `state` | string | the change's current state: `cleared`, or `superseded` or `exception` once it was cleared and has since been replaced or flagged |
| `app`, `env` | string | the application's and environment's names |
| `approver_kind` | string | `person` when every approval was checked to be a person; `mixed` or `none` otherwise |
| `approver_count` | int | how many approvals |
| `change_digest` | string | SHA-256 of what was cleared (the manifest tree or saved plan) |
| `policy_version` | string | the policy bundle version that decided the tier |
| `controls` | string | the hub control identifiers, `framework/version:control` (default `soc2/2017:CC8.1`, from the packet mapping data) |
| `cleared_at` | timestamp | when it was cleared, UTC (decided-at while cleared; after a supersession or exception, the last approval, or for a policy clearance the registration time) |

`displayName` is `<app>/<env> change <first 12 of id> (tier N)`; `uniqueId` is `clearance-change-<id>`; `externalUrl` is the link back.

No approver identity is sent in any form, not even a hash (an unsalted hash of a person's login is reversible by dictionary and links
approver sets across items): the kind and the count only. A coverage report item (`uniqueId` `clearance-coverage-<env>-<YYYY-MM-DD>`, `externalUrl` the Clearance UI's base) carries
`period`, `env`, `changes_total`, `changes_cleared`, `changes_denied`, `changes_exception`, `changes_degraded`,
`changes_other`, `cleared_tier0` to `cleared_tier3`, `cleared_by_people` and `controls`: counts only.

The token exchange sends the application's client id and secret and the scope, to the hub's `/oauth/token`, and nothing else.

The ledger records carry the hub's name, the result, the change id, the SHA-256 of the item sent, the link and, for a failure,
its class (`auth`, `rate-limited`, `unavailable`, `rejected`, `bad-response`, `network`, `config`). They are claimed but for
the provider and the time: they say what the pusher reports it sent, not that the hub holds it.

## The hub contract (Vanta)

`Target` (`internal/grc/target.go`) is the hub interface: `PushEvidence(items)` and `PushReport(items)`, each sending the
**complete current set**. A second hub (Drata) is another implementation of it; nothing outside `vanta.go` knows Vanta's wire
format.

What `vanta.go` was written against, all from Vanta's public developer documentation:

| Step | What is coded | Source |
| --- | --- | --- |
| Token | `POST {base}/oauth/token`, `Content-Type: application/json`, body `{client_id, client_secret, scope: "connectors.self:write-resource", grant_type: "client_credentials"}`; answer `{access_token, expires_in}` (3600); one token per application: a new one invalidates the last | [Authentication](https://developer.vanta.com/docs/concepts/authentication), [Build a private integration](https://developer.vanta.com/docs/quickstart/build-private-integration) |
| Sync | `PUT {base}/v1/resources/custom_resource`, `Authorization: Bearer`, body `{resourceId, resources: [{displayName, uniqueId, externalUrl, customProperties}]}`; answer `{success: true}`. `externalUrl` must be https. | [Sync all Custom Resources](https://developer.vanta.com/api-reference/custom-resources/sync-all-custom-resources), [Resources](https://developer.vanta.com/docs/concepts/resources) |
| Semantics | A sync is the **state of the world**: it replaces the whole set for that resource, and what is missing is deleted at Vanta | the same pages |

**Assumptions** (not confirmed by the pages; each is the narrowest reading, and each is what the sandbox run checks):

1. **A custom resource is "an evidence item".** Vanta has no object called evidence item in this API; a custom resource in a
   private integration is the structured-data object it takes. It is inventory until the tenant builds a **Custom Test** over
   it ([Resources](https://developer.vanta.com/docs/concepts/resources)); only then does it count toward a control. Whether
   Vanta's structured-attestation route (the card's "unverified until tried") accepts anything richer is not answered by the
   docs, and is not built.
2. `customProperties` is where the schema fields go (the quickstart says so; the API reference lists only the three base
   fields). Property types are `string`, `int32`, `boolean` and `timestamp`, flat. A timestamp is sent as RFC 3339 UTC.
3. `source_id`, which one reference page mentions and its schema does not define, is not sent.
4. The documentation gives the `/oauth/token` limit as 25 a minute in one place and 5 in another. The service mints once and
   holds the token in memory; on a 401 it mints one more time and tries again, and no more.
5. The documentation names no error body, no `Retry-After` behaviour and no size limit. A 429 honours `Retry-After` (seconds or
   a date, capped at `CLEARANCE_GRC_BACKOFF_MAX`); any other 4xx is not retried; `CLEARANCE_GRC_MAX_ITEMS` (5000) is this
   service's own cap, newest first.
6. A `200` whose body is not `{"success": true}` is a failure (`bad-response` or `rejected`), not a success.
7. "A duplicate submission" is the same body sent twice: the documented replace makes it the same set. Vanta documents no
   409 and none is handled specially.
8. Because a sync replaces the set, **a change older than `CLEARANCE_GRC_WINDOW` (default 90 days) leaves Vanta**; the
   signed record and the packet stay in Clearance. Set the window to the audit period.

## Configuration

Environment (secrets are file mounts; no value is ever printed):

| Variable | Default | |
| --- | --- | --- |
| `CLEARANCE_GRC_TARGET` | unset: off | `vanta` |
| `CLEARANCE_GRC_VANTA_BASE_URL` | `https://api.vanta.com` | https; `https://api.vanta-gov.com` for Vanta Gov |
| `CLEARANCE_GRC_VANTA_CLIENT_ID` | required | the application's client id |
| `CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE` | required | the client secret, a file; there is no plaintext variable |
| `CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID` | required | the Resource ID of the evidence custom resource |
| `CLEARANCE_GRC_VANTA_REPORT_RESOURCE_ID` | unset: no report | the Resource ID of the report custom resource |
| `CLEARANCE_GRC_LINK_BASE` | required | https base of the Clearance UI: the link back is `<base>/changes/<id>` |
| `CLEARANCE_API_URL`, `CLEARANCE_URL` | required | clearance-api (reads) and the core (records) |
| `CLEARANCE_GRC_SA_TOKEN_FILE` | `/var/run/secrets/tokens/clearance` | the projected service-account token, read on every call |
| `CLEARANCE_GRC_PROVIDER` | `clearance-grc` | the provider name registered in the core |
| `CLEARANCE_GRC_ENVS` | `prod` | environments sent, comma separated |
| `CLEARANCE_GRC_MAPPINGS` | `soc2/2017` | packet mappings whose control ids the items name |
| `CLEARANCE_GRC_INTERVAL`, `_REPORT_INTERVAL`, `_WINDOW` | 5m, 24h, 2160h | Go durations |
| `CLEARANCE_GRC_MAX_ITEMS`, `_MAX_ATTEMPTS`, `_BACKOFF_BASE`, `_BACKOFF_MAX` | 5000, 5, 2s, 2m | per read and for the set; reaching the cap refuses the cycle |
| `CLEARANCE_GRC_MIN_SET_RATIO` | 0.8 | the least a set may be as a fraction of the last one sent |
| `CLEARANCE_GRC_ALLOW_SHRINK` | false | **allows an empty or much smaller set to replace the hub's: leave it false** |
| `CLEARANCE_GRC_RESEND_EVERY`, `_UNREADY_AFTER` | 6h, 30m | resend an unchanged set; how long a loop may fail before `/readyz` fails |
| `CLEARANCE_GRC_USE_PROXY` | false | honour the environment's HTTP proxy settings |
| `CLEARANCE_GRC_LISTEN` | `:8080` | `/healthz` |

The core registers it as a provider: `{"name": "clearance-grc", "version": "...", "principals": ["<ns>/<serviceaccount>"],
"kinds": ["grc.push", "grc.report"]}`. A provider that does not name those kinds cannot write them. The api must list the
principal in `CLEARANCE_API_NOTIFIERS`. The chart does both when `grc.enabled`
([install.md](install.md)); `ci/grc-values.yaml` is the smallest values that render it.

### Helm (off by default)

```yaml
grc:
  enabled: true
  existingSecret: clearance-grc      # key: client-secret
  linkBase: https://clearance.example.com
  vanta:
    clientId: <client id>
    evidenceResourceId: <Resource ID>
    reportResourceId: <Resource ID>  # optional
```

It needs `api.enabled`. `networkPolicy.grc.internet` (default true) opens 443 to **any public address** for the hub's API, because a NetworkPolicy has
no host names; pin it with `networkPolicy.grc.cidrs` (the hub's published addresses, which replaces that rule), or use
`extraEgress` with an egress proxy. The policy has no Postgres rule. Liveness is `/healthz`, readiness `/readyz`.

## Run it against a Vanta sandbox

The owner's step; nothing here has been run.

1. In Vanta, Settings, **Developer Console**, Create, **Build Integrations**, **Private** distribution. Name it; generate a
   client secret. Keep the client id and secret.
2. In the application's **Resources** tab add two resources with the **Custom Resource** base type and these schemas (JSON
   Type Definition, flat). Copy each **Resource ID**.

   Evidence:

   ```json
   {"properties": {"origin": {"type": "string"}, "tier": {"type": "int32"}, "state": {"type": "string"}, "app": {"type": "string"},
     "env": {"type": "string"}, "approver_kind": {"type": "string"}, "approver_count": {"type": "int32"},
     "change_digest": {"type": "string"}, "policy_version": {"type": "string"},
     "controls": {"type": "string"}, "cleared_at": {"type": "timestamp"}}}
   ```

   Report:

   ```json
   {"properties": {"period": {"type": "string"}, "env": {"type": "string"}, "changes_total": {"type": "int32"},
     "changes_cleared": {"type": "int32"}, "changes_denied": {"type": "int32"}, "changes_exception": {"type": "int32"},
     "changes_degraded": {"type": "int32"}, "changes_other": {"type": "int32"}, "cleared_tier0": {"type": "int32"}, "cleared_tier1": {"type": "int32"},
     "cleared_tier2": {"type": "int32"}, "cleared_tier3": {"type": "int32"}, "cleared_by_people": {"type": "int32"},
     "controls": {"type": "string"}}}
   ```

3. Put the client secret in the Secret named by `grc.existingSecret`, key `client-secret` (you create it; Infisical via
   ExternalSecrets as for the rest). Never paste it into values or a command.
4. Set `grc.enabled`, `grc.linkBase`, `grc.vanta.clientId`, `grc.vanta.evidenceResourceId`, `grc.vanta.reportResourceId`;
   leave `grc.envs` at `prod` or name the lab's environment. Deploy.
5. Clear a lab change. Within `grc.interval` (5 minutes) check: the evidence resource's list in the Developer Console (or
   `GET /v1/resources/custom_resource` with the Resource ID) shows `clearance-change-<id>` with its properties; its
   external URL opens the change in the Clearance UI; the ledger (clearance-api's records list) shows a `grc.push` record with `result: pushed`.
6. The report: an item `clearance-coverage-<env>-<today>` appears in the report resource within `grc.reportInterval` of the
   start (restart the pod to see it at once), and a `grc.report` record is in the ledger.
7. In Vanta, build a **Custom Test** over the evidence resource (for example, `approver_kind` equals `person` for tier 2 and
   above) so the items count toward a control; without one they are inventory only.
8. Failure drill: set a wrong client secret, see a `grc.push` record with `result: failed`, `reason: auth`, and that clearing
   changes is unaffected; restore it and the next cycle lands the set.
9. Record what differs from the [assumptions](#the-hub-contract-vanta) above. The ones most likely to: where
   `customProperties` goes, the `/oauth/token` limit, whether `externalUrl` must resolve for an unauthenticated viewer, and
   what a rate-limited answer carries.
10. Drill the guards: point `grc.envs` at an environment with no changes and see a `grc.push` record with
    `reason: shrink-refused` and the sandbox set untouched.

## Known limits

- Written against documentation, not a tenant: see the assumptions.
- The full-state replace means the hub only ever holds the window; a change outside it is gone from the hub, not from
  Clearance.
- The coverage report is change counts. The three-part telemetry coverage of a scope (O-1) is not in it: clearance-api's
  notifier role cannot read it, and widening that role is not part of this card.
- Approvers are a kind and a count, never a name or a hash. Naming them is a decision about what leaves the tenant.
- The first (and any restart's) cycle re-sends the full set and re-asks the core to record each item (the core answers
  `duplicate: true`): bounded by the window and `CLEARANCE_GRC_MAX_ITEMS`. The shrink floor is in memory: after a restart only an
  empty set is refused.
- `cleared_at` of a change that was superseded or flagged is the last approval's time (or registration, for a policy
  clearance), because the gate overwrites its decided-at with the later time. A change cleared by people through the evidence
  wait path is dated by its last approval.
- Memory: changes are decoded into a slim struct (about a dozen fields) page by page, so a full read (three states, up to
  `CLEARANCE_GRC_MAX_ITEMS` each, six for the report) is estimated (not measured under load) at under 30 MB of slim records plus the items, inside the chart's 128Mi limit; a page of 100
  changes is the largest buffer, and the read is capped at 32 MiB a page.
- One sender: a second replica would work (the push is idempotent) but Vanta keeps one token per application, so two would
  keep revoking each other's.
- Drata, the second hub, is not built; it is a new `Target`.
