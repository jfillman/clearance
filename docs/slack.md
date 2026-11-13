# Slack (clearance-slack)

Using Clearance from Slack: a small Go service, `clearance-slack`, that tells people what is waiting on them and lets a
person whose Slack account is linked to their sign-in **clear** (up to tier 2 by default) and **deny** from the message.
It is a surface on Clearance, never a dependency: Tower, the [CLI](cli.md) and the web page work whether or not it runs, and
nothing is decided in Slack. Slack outage, a stopped service or a revoked token leaves every hold exactly where it was.

## What it does

| | |
|---|---|
| A hold waits on people | One message per change in the owner group's channel (a thread: approvals and the end are replies, the root is updated in place), and a DM to each **linked** person the gate would let clear it now. A tier 3 change waits on the owner group first; once the owner requirement is filled the outside group's members are DMed, and past `tier3OutsideAfter` (15 minutes) the outside group's channel too. A hold past 75% of its life gets one reminder in each DM thread. |
| Exceptions and break-glass | `deploy.exception` goes to the app's channel with a **Resolve** button for the kinds a person resolves (`out-of-band`, `drift`, `untraced-apply`, `digest-mismatch`); `monitoring-protection`, `attempted-refused` and every `breakglass.open` and `breakglass.close` go to the security channel as well. |
| Coverage | A scope that turns degraded or blind, and the recovery. The state is each source's `now` at the end of the window (the worst a source was an hour ago is not what is true now); a scope no source reported on is blind. |
| Attestations | The signed attestation of an applied change is stuck when it is still missing after `stuckAttestationAfter` (30 minutes): said once, with the count, and again when caught up. |
| Actions | **Clear** and **Deny...** on a change, **Resolve...** on an exception, each through a form; the person is named from the identity link, the write carries `X-Clearance-Via: slack` and the message's permalink. |

## Guardrails (what Slack can and cannot do)

| Action | From Slack | Why |
|---|---|---|
| Clear, tier 2 (one owner, not the proposer) | Yes: a form shows the change, its tier reasons and its head; the core decides | The owner group's own person, bound by the link |
| Clear, tier 3 | **No.** The message links to the web page (`slack.webUrl`) or names the CLI command | The second approver must be a verified person with a fresh sign-in; a long-lived link cannot give that |
| Deny, any tier | Yes, with a required reason | Denying cannot cause a deploy |
| Resolve one exception | Yes, for an administrator (the core re-checks) | Append-only, newest wins, recorded |
| Break-glass open or close, bulk resolve | **Never** from Slack | Rare, high blast radius, wants a deliberate step-up |

`slack.clearMaxTier` (default 2, at most 3) is the deployment's choice to loosen the first row; break-glass is not configurable.

- **The person is the link's, nothing else.** A Slack user is bound to a person by `/clearance link`, which needs **both**
  Sign in with Slack (the Slack user and workspace) and the people IdP's login (the person), in one browser session, in that
  order. The IdP's ID token is verified as the core verifies it: signature, issuer, audience and `CLEARANCE_OIDC_ALLOWED_USERS`; the
  person is `user:<CLEARANCE_OIDC_USER_CLAIM>` exactly as the core names them. A display name, email or `/clearance as ...`
  from Slack is never used. A Slack user with no link gets "link your account" and nothing else. Links are per workspace.
- **Links expire and revoke.** Re-verified every 30 days (`relinkAfter`; an older link refuses every action until `/clearance link`),
  removed on `/clearance unlink`, on a deactivated Slack account (`user_change` event, with a six-hour sweep as backstop), and
  replaced only by a new two-proof link.
- **The core still decides.** Who may clear (the gate's own rule: in the owner group or an unfilled outside group, not the
  proposer, not already an approver), `DG-TWICE`, `DG-STATE`, the freshness rule and `CLEARANCE_DELEGATE_PERSON_ALLOWED` are the
  core's. The service pre-checks the gate rule only so a form is not opened for a clear the core must refuse, and checks the
  tier policy again on a fresh read when the form is submitted (a change re-tiered, moved to a new head or already decided while
  the form was open is not written to).
- **Audit.** Every write records `surface: {via: "slack", ref: <permalink>}` (claimed, as for any surface) and the approval
  names the person and the delegate (`delegate:<ns>/<sa>`). Nothing records a Slack name.
- **Fresh sign-in.** The link's IdP sign-in time (`auth_time`, only when the IdP said it; never an `iat`) is sent as
  `X-Clearance-Auth-Time`. With the core's `CLEARANCE_FRESH_AUTH_DELEGATES=exempt` (default) the link is the identity proof and the header
  is ignored. With `require`, a Slack clear needs a sign-in no older than `CLEARANCE_FRESH_AUTH_TIER2`: the person re-runs
  `/clearance link` (a fresh IdP login) and tries again; the refusal says so. The service never invents a time.
- **Requests are authentic.** Events transport: `X-Slack-Signature` (HMAC-SHA256 over `v0:<timestamp>:<body>`), constant-time
  compare, 5-minute replay window, an exact repeat refused, event ids and trigger ids de-duplicated. Socket Mode: Slack's authenticated websocket,
  envelope ids acknowledged and de-duplicated.
- **Secrets are files.** Bot token, app token, signing secret, the two OIDC client secrets and the DSN are mounted files, never in env, never logged (the bot and app token files are re-read on every use, so a rotation needs no restart; the rest are read at start). The service holds no signing key and writes nothing to the
  evidence tables; its own `clearance_slack_*` tables hold ids only (Slack user and workspace, IdP issuer and subject,
  the principal, the sign-in time, message ids). Messages show only what the api's redacted view of a change carries.
- **Errors are shown to the person alone** (ephemeral): what the core refused, why, what to do, and "Nothing was changed".

## How it reads Clearance (the design choices)

- **G5, who is waiting on whom.** The service is a `notifier` of clearance-api, which now reads every change as a list, the
  counts and the stream's `clearance` events (whole scope, redacted like a person's view; never a token, a change by id or an evidence
  record). Without it the service would poll once per linked person. The stream wakes it and carries the resume cursor (saved in
  its store only after a pass succeeds, resumed with `Last-Event-ID`, reconnected every 10 minutes and on errors); every pass also
  re-reads the holding changes, so a lost event or a restart repairs itself on the next pass (every 60 s at most).
- **G7, who qualifies.** For each linked person the service asks clearance-api `GET /v1/whoami` as a delegate naming them (groups,
  admin; cached 5 minutes) and applies the gate's own `gate.RoleFor`, the code the core runs. It never keeps a copy of the rule.
  Which channel an owner group uses is the routes file (below); syncing it from the catalog is not built.
- **G6, stuck attestations.** `GET /v1/clearances/counts?by=attestation&since=` gives `pending` (applied, none stored). Pending of the
  last week less pending since the threshold is how many are older than it; a change is counted by when it was last updated,
  which for a pending one is its apply. No new endpoint.
- **Exceptions** are polled every 120 s by seq watermark (the first poll records the watermark and says nothing: history is not news).

## Setting it up (the owner's steps)

Nothing here is done by the service or the chart; the secrets are yours to create and are never generated or stored by Clearance.

1. **Create the Slack app** from the manifest below (Slack: *Create New App > From a manifest*). Replace `<publicUrl>`. Install it to the workspace.
   Invite the bot to each channel it posts in (or add the `chat:write.public` scope).
2. **Create the Slack tokens and put them in Infisical**: the **bot token** (`xoxb-`, *OAuth & Permissions*) and, for Socket Mode,
   an **app-level token** (`xapp-`, scope `connections:write`, *Basic Information*). For the Events transport the **signing secret** (*Basic Information*) instead of the app token.
   Sign in with Slack needs the app's **client id** (a chart value) and **client secret** (Infisical).
3. **Register the IdP client** the link page signs people in with: at people-dex a static client with the redirect URI
   `<publicUrl>/link/idp` (public client, PKCE; if you make it confidential, put its secret in Infisical and set `slack.idpClientSecret: true`).
   The issuer, user claim and allowlist are the chart's `oidc.*`, the same the core trusts. Slack's redirect URL is `<publicUrl>/link/slack` (in the manifest).
   `<publicUrl>` must be **https** and reachable from people's browsers (Slack accepts no other redirect for Sign in with Slack; this is a hard Slack requirement, also in a lab).
4. **A database role** for the service: its own role and database (or schema) on the cluster's Postgres, with no grant on the
   evidence tables; it creates its three `clearance_slack_*` tables on start. Put its DSN in Infisical.
5. **The Secret** `slack.existingSecret` (through an ExternalSecret from those Infisical entries), with the keys below.
6. **Routes** (`slack.routes` in the chart, or `CLEARANCE_SLACK_ROUTES_FILE`): channel ids (`C...`), not names.
7. **Enable it**: `slack.enabled: true` with `slack.publicUrl`, `slack.slackClientId`, `slack.idpClientId`, `slack.webUrl`, and a route
   to the service for the link pages (`httpRoutes.slack`, with `networkPolicy.slack.from` naming the gateway and `networkPolicy.slack.extraEgress` the IdP).
   The chart adds the service's service account (`<namespace>/<release>-clearance-slack`) to `delegates`, `api.notifiers` and
   `api.observationReaders`, and opens the core's and api's ingress to its pod. Outside the chart, set those three and give the service
   a projected service-account token of `CLEARANCE_AUDIENCE`.
8. **Decide the freshness rule** for Slack clears (`gate.freshAuthDelegates`: `exempt` or `require`, above) and, if you want a
   second fence, `gate.delegatePersonAllowed` (globs of the people a delegate may name).
9. **Try it**: `/clearance link` in Slack, then open a tier 2 change you did not propose.

| Secret (Infisical) | Key in the Secret | Used for |
|---|---|---|
| Slack bot token (`xoxb-`) | `bot-token` | post, update, DM, open forms, permalinks |
| Slack app-level token (`xapp-`, `connections:write`) | `app-token` | Socket Mode (default transport) |
| Slack signing secret | `signing-secret` | the Events transport's request signatures |
| Sign in with Slack client secret | `client-secret` | the link flow's first proof |
| IdP client secret (only if confidential) | `idp-client-secret` | the link flow's second proof |
| The service's Postgres DSN | `dsn` | links, message ids, the stream cursor |

### The app manifest

Written to Slack's manifest schema and **not yet imported into a workspace**: Slack's own validation at *From a manifest* is the first check. Socket Mode:

```yaml
display_information:
  name: Clearance
  description: Changes waiting on you, and clear or deny them
features:
  bot_user:
    display_name: Clearance
    always_online: true
  slash_commands:
    - command: /clearance
      description: Link your account, see who you are linked as
      usage_hint: link | status | dm on|off | unlink
      should_escape: false
oauth_config:
  redirect_urls:
    - https://<publicUrl>/link/slack
  scopes:
    bot:
      - chat:write          # post and update messages, ephemeral replies, permalinks
      - im:write            # open the DM with a linked person
      - commands            # /clearance
      - users:read          # deactivation (users.info and the user_change event)
settings:
  event_subscriptions:
    bot_events:
      - user_change
  interactivity:
    is_enabled: true
  org_deploy_enabled: false
  socket_mode_enabled: true
  token_rotation_enabled: false
```

For the Events transport set `socket_mode_enabled: false` and add `request_url: https://<publicUrl>/slack/events` under
`event_subscriptions`, `request_url: https://<publicUrl>/slack/interactive` under `interactivity` and
`url: https://<publicUrl>/slack/command` on the slash command. Sign in with Slack asks for the `openid` scope when it sends the person to Slack; nothing is declared for it.

## Routes

```yaml
groups:                          # an owner or outside group -> the channel its holds go to
  "group:default/payments": C0123456789
  "group:default/admins": C0ADMINS
apps: { web: C0WEB }             # an app -> where its exceptions go
scopes: { acct-prod: C0PROD }    # a coverage scope -> where its coverage alerts go
default: C0DEFAULT               # a group with no entry
security: C0SECURITY             # break-glass, monitoring-protection, blind or degraded coverage: always
ops: C0OPS                       # stuck attestations (security when empty)
```

No file: nothing is posted to a channel and people are told by DM only. A misspelled key is an error at start.

## Configuration

Secrets as `*_FILE`; everything else is the environment (the chart renders these from `slack.*` and `oidc.*`).

| Variable | Default | |
|---|---|---|
| `CLEARANCE_SLACK_TRANSPORT` | `socket` | `socket` or `events` |
| `CLEARANCE_SLACK_LISTEN` | `:8080` | the link pages, `/healthz`, and on `events` `/slack/events`, `/slack/interactive`, `/slack/command` |
| `CLEARANCE_SLACK_PUBLIC_URL` | required | https (loopback http allowed) |
| `CLEARANCE_SLACK_BOT_TOKEN_FILE`, `_APP_TOKEN_FILE`, `_SIGNING_SECRET_FILE`, `_CLIENT_SECRET_FILE`, `_IDP_CLIENT_SECRET_FILE`, `_DSN_FILE` | | the secrets (the bare names, without `_FILE`, work for a lab) |
| `CLEARANCE_SLACK_CLIENT_ID`, `CLEARANCE_SLACK_IDP_CLIENT_ID` | required | Sign in with Slack, the IdP client |
| `CLEARANCE_OIDC_ISSUER`, `_USER_CLAIM`, `_ALLOWED_USERS`, `_JWKS_URL` | issuer and allowlist required | the people IdP, as the core reads them |
| `CLEARANCE_API_URL`, `CLEARANCE_URL` | required | clearance-api (reads), the core (writes) |
| `CLEARANCE_SLACK_SA_TOKEN_FILE` | `/var/run/secrets/tokens/clearance` | projected token, audience `CLEARANCE_AUDIENCE`, read on every call |
| `CLEARANCE_ON_BEHALF_OF_HEADER` | `X-Clearance-On-Behalf-Of` | the deployment's name for it |
| `CLEARANCE_SLACK_ROUTES_FILE` | none | the routes above |
| `CLEARANCE_SLACK_WEB_URL` | none | `https://host/changes/{id}`: where a tier 3 clear is made |
| `CLEARANCE_SLACK_CLEAR_MAX_TIER` | `2` | 0 to 3 |
| `CLEARANCE_SLACK_FORWARD_AUTH_TIME` | `true` | send the link's proven sign-in time |
| `CLEARANCE_SLACK_RELINK_AFTER`, `_ALERT_INTERVAL`, `_RECONCILE_INTERVAL`, `_STUCK_ATTESTATION_AFTER`, `_TIER3_OUTSIDE_AFTER`, `_MIN_POST_INTERVAL` | 720h, 120s, 60s, 30m, 15m, 1.1s | Go durations |

Slash commands: `/clearance link`, `status`, `dm on|off` (direct messages about changes waiting on you), `unlink`.

## Operating it

- One replica (one Socket Mode connection, one stream cursor); a restart resumes from the saved cursor and reconciles.
- Posts are paced to one a second per channel and honor Slack's `Retry-After`; at most 60 new messages start per pass, the rest on the next.
- A message deleted in Slack stops being tracked; a change that ends has its message updated (no buttons, how it ended) and a reply.
- Rotate the Slack bot or app token: change it in Infisical; those files are read on use, no restart (the other secrets, at the next start).
- "Link your account" for someone who has linked: they are in another workspace than the link, or the link was removed (deactivation, `unlink`).
- Everything the service logs is JSON on stderr; tokens, codes and the websocket ticket are never logged.

## Not built (descoped, so you are not surprised)

- The **PR comment** on a hold (the design's P3 item) and the **email digest**: not in this release.
- Owner group to channel is the routes file; no sync from the catalog.
- **Bulk resolve** and **break-glass** are CLI/web only, by design.
- The Events transport is covered by unit tests (signature, replay, dedupe, handlers) but, like the manifest, **has not been run against a live Slack workspace**; neither has Socket Mode. Nothing here touched a workspace.
