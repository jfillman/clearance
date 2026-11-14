# GRC push, Vanta first (P-4)

`clearance-grc` sends a **summary** of each production change, and a daily **coverage report**, to a GRC hub as evidence items
that link back to Clearance. The signed record stays in Clearance; the hub holds a pointer, never a copy.

Status: **Built against a fake Vanta, not run against a real tenant.** `go test ./internal/server -run TestP4GRCPush` is the
whole flow in one command (a real core, a fake clearance-api and a fake Vanta). The run against a Vanta sandbox is the owner's
step: [Run it against a Vanta sandbox](#run-it-against-a-vanta-sandbox).

## What it does

- Each **cleared** change of the configured environments (default `prod`) becomes one evidence item at the hub: origin, tier,
  approver kind and count, a digest of the approvers, the digest of what was cleared, the policy version, the control
  identifiers it is mapped to, and a **link back** to the change in Clearance.
- A **coverage report**, one item per environment and UTC day, of counts only: changes decided, cleared by tier, denied,
  exceptions, degraded, and how many were cleared by people. It is pushed every 24 hours (`CLEARANCE_GRC_REPORT_INTERVAL`) and
  at start.
- Every push and every failure is a **ledger record** (`grc.push`, `grc.report`), so what was sent, when and whether it
  landed is itself evidence.

## Guardrails

| Guardrail | How it is held |
| --- | --- |
| **Off unless configured** | With no `CLEARANCE_GRC_TARGET` the binary says so and exits 0; nothing is sent. The chart renders none of it unless `grc.enabled`. |
| **Only what the card says leaves** | The fields below are the whole of it. A test holds every outbound body to that table (`TestNothingButDocumentedFieldsLeaves`) and checks that a change's repository, pull request, paths, proposer, approver names, checks and cluster appear in no body. |
| **Idempotent** | An item's id is `clearance-change-<change id>`; the hub replaces its set with the one sent, so a retry, a restart or a second sender leaves one item. The ledger record carries the event id `hub:item id:item digest`, so the core records an item once however often it is told. |
| **Bounded retries, never silent, never blocking** | A retryable failure (429 with `Retry-After`, 5xx, a network error) is retried up to `CLEARANCE_GRC_MAX_ATTEMPTS` (5) times with exponential backoff and jitter (base 2s, cap 2m). Then a `grc.push` record with `result: failed` and the failure class is written, the cycle is logged as an error, and the next cycle starts again from clearance-api: nothing is queued in memory. The service is a separate process that only reads clearance-api; the core never calls it and waits for nothing from it (`TestP4GRCPush` keeps clearing changes while the hub is down). |
| **The link back is configured** | `CLEARANCE_GRC_LINK_BASE` (https always) plus `/changes/<id>`. It is never built from a request, a header or a change field; a change id that is not a plain identifier (`[A-Za-z0-9._:-]`, 128 at most) is not sent. |
| **Outbound URL from config only** | The hub's origin is `CLEARANCE_GRC_VANTA_BASE_URL`; https is required, http only for a loopback host (a local fake). No credentials, query or fragment in it. Redirects are never followed, so the token and payload go to the configured host only. |
| **Response bodies are capped** | At most 64 KiB of any hub answer is read, and none of it is kept: an error carries a class and a status, never the hub's text (which can echo what was sent). |
| **No token in records, logs or errors** | The client secret is a file (`CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE`), read again at each token mint; the access token is held in memory only, for its hour. Tests grep the chain, the logs and every error for the secret and the token (`TestNoTokenInRecordsLogsOrErrors`, and the chain in `TestP4GRCPush`). |
| **Narrow credentials** | The token asks for `connectors.self:write-resource`, nothing else. The service is a `notifier` of clearance-api (changes only: never a token, never an evidence record) and a provider of the core for `grc.push` and `grc.report` alone. |
| **Off the decision path** | No core route calls it; a down hub, a rate limit or a bad credential changes nothing about a clearance. |

## Every field sent

An evidence item is `displayName`, `uniqueId`, `externalUrl` and these flat properties (`customProperties`). Nothing else of a
change is read into an item.

| Property | Type | What |
| --- | --- | --- |
| `origin` | string | who made the change: `person`, `agent`, `automation` (the proposer's kind, never a name) |
| `tier` | int | the clearance tier, 0 to 3 |
| `state` | string | the change's state (always `cleared`) |
| `app`, `env` | string | the application's and environment's names |
| `approver_kind` | string | `person` when every approval was checked to be a person; `mixed` or `none` otherwise |
| `approver_count` | int | how many approvals |
| `approvers_sha256` | string | SHA-256 of the sorted approver identities: it identifies them without naming them |
| `change_digest` | string | SHA-256 of what was cleared (the manifest tree or saved plan) |
| `policy_version` | string | the policy bundle version that decided the tier |
| `controls` | string | the hub control identifiers, `framework/version:control` (default `soc2/2017:CC8.1`, from the packet mapping data) |
| `cleared_at` | timestamp | when it was cleared, UTC |

`displayName` is `<app>/<env> change <first 12 of id> (tier N)`; `uniqueId` is `clearance-change-<id>`; `externalUrl` is the link back.

A coverage report item (`uniqueId` `clearance-coverage-<env>-<YYYY-MM-DD>`, `externalUrl` the Clearance UI's base) carries
`period`, `env`, `changes_total`, `changes_cleared`, `changes_denied`, `changes_exception`, `changes_degraded`,
`cleared_tier0` to `cleared_tier3`, `cleared_by_people` and `controls`: counts only.

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
| `CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE` | required | the client secret (`CLEARANCE_GRC_VANTA_CLIENT_SECRET` is a lab fallback) |
| `CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID` | required | the Resource ID of the evidence custom resource |
| `CLEARANCE_GRC_VANTA_REPORT_RESOURCE_ID` | unset: no report | the Resource ID of the report custom resource |
| `CLEARANCE_GRC_LINK_BASE` | required | https base of the Clearance UI: the link back is `<base>/changes/<id>` |
| `CLEARANCE_API_URL`, `CLEARANCE_URL` | required | clearance-api (reads) and the core (records) |
| `CLEARANCE_GRC_SA_TOKEN_FILE` | `/var/run/secrets/tokens/clearance` | the projected service-account token, read on every call |
| `CLEARANCE_GRC_PROVIDER` | `clearance-grc` | the provider name registered in the core |
| `CLEARANCE_GRC_ENVS` | `prod` | environments sent, comma separated |
| `CLEARANCE_GRC_MAPPINGS` | `soc2/2017` | packet mappings whose control ids the items name |
| `CLEARANCE_GRC_INTERVAL`, `_REPORT_INTERVAL`, `_WINDOW` | 5m, 24h, 2160h | Go durations |
| `CLEARANCE_GRC_MAX_ITEMS`, `_MAX_ATTEMPTS`, `_BACKOFF_BASE`, `_BACKOFF_MAX` | 5000, 5, 2s, 2m | |
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

It needs `api.enabled`. `networkPolicy.grc.internet` (default true) opens 443 outside the private ranges for the hub's API;
narrow it where the cluster has an egress proxy.

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
     "approvers_sha256": {"type": "string"}, "change_digest": {"type": "string"}, "policy_version": {"type": "string"},
     "controls": {"type": "string"}, "cleared_at": {"type": "timestamp"}}}
   ```

   Report:

   ```json
   {"properties": {"period": {"type": "string"}, "env": {"type": "string"}, "changes_total": {"type": "int32"},
     "changes_cleared": {"type": "int32"}, "changes_denied": {"type": "int32"}, "changes_exception": {"type": "int32"},
     "changes_degraded": {"type": "int32"}, "cleared_tier0": {"type": "int32"}, "cleared_tier1": {"type": "int32"},
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

## Known limits

- Written against documentation, not a tenant: see the assumptions.
- The full-state replace means the hub only ever holds the window; a change outside it is gone from the hub, not from
  Clearance.
- The coverage report is change counts. The three-part telemetry coverage of a scope (O-1) is not in it: clearance-api's
  notifier role cannot read it, and widening that role is not part of this card.
- Approvers are a hash and a count. Naming them is a one-line change and a decision about what leaves the tenant.
- The first (and any restart's) cycle re-sends the full set and re-asks the core to record each item (the core answers
  `duplicate: true`): bounded by the window and `CLEARANCE_GRC_MAX_ITEMS`.
- One sender: a second replica would work (the push is idempotent) but Vanta keeps one token per application, so two would
  keep revoking each other's.
- Drata, the second hub, is not built; it is a new `Target`.
