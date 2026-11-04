# The Traefik Hub adapter (C-9)

**Status: Unverified.** The adapter is built and tested against the record format Traefik Labs publishes, but no
record from a running Traefik Hub has been read yet. The live check waits for a Hub licence with the Transparency
Logs feature, or for a partner who runs one. The second half of this page, Clearance as Hub's policy decision point,
is also **Unverified**, and as of today the answer is no: Hub cannot use Clearance's evaluation endpoint without
changes on Clearance's side ([below](#clearance-as-hubs-pdp)).

## What it does

Traefik Hub's **Sovereign Trust Plane** is a real, published product name. Traefik Labs announced it on
15 September 2026 as three capabilities in Traefik Hub:

- **Delegate**: token exchange per the IETF ID-JAG draft.
- **Authorize**: an AuthZEN middleware that asks an external policy decision point (PDP) whether a call may go
  ahead.
- **Prove**: transparency-log commitments over the gateway log and the access log, cosigned by witnesses.

The records it keeps are plain JSON log lines in the customer's own storage: one **decision record** per AuthZEN
decision in the Hub log, and one **access record** per request in the access log.

The adapter reads both files and joins each decision to its request on `trace_id`. Where it can, it correlates the
call to a `task_id`. It then posts each decision to the core as a `federated.decision` record (`POST /v1/records`,
provider `traefik-hub`), so the ledger holds what another gateway's PDP decided next to what Clearance decided
itself. Every field in these records is claimed. The core verifies only who sent the record and when it arrived.

```
Traefik Hub ──log.filePath──────► hub.log     ┐
            ──accessLog.filePath► access.log  ┴─► clearance federate traefik-hub ──POST /v1/records──► the ledger
```

## The record format it reads

These fields are copied from Traefik's Transparency Logs page. The two examples in
`internal/federate/traefikhub/testdata/published-*.log` are that page's own examples.

| Record | Where | Fields the adapter reads |
| --- | --- | --- |
| Decision (`authzen`, `authzen-mcp`) | the Hub log (`log.format: json`, `log.filePath`) | `middlewareName`, `middlewareType`, `decision` (`allow`, `deny`, `bypass`), `policy` (authzen-mcp only), `reason`, `error`, `trace_id` (tracing on), `transparency_log_id`, `gateway_id`, `time`, `message` |
| Access | the access log (`accessLog.format: json`, `accessLog.filePath`) | `RequestHost`, `RequestMethod`, `RequestPath`, `RouterName`, `ClientUsername`, `DownstreamStatus`, `request_<Header>` for each kept header, `trace_id` / `TraceId`, `transparency_log_id` |

Published behaviour the adapter follows:

- A decision record names no user, agent or resource, and an access record names no policy. They join on
  `trace_id`, which exists only when tracing is enabled. Hub generates the id even with no OpenTelemetry collector.
- A key can appear twice in a decision line when an earlier authentication middleware ran. The last occurrence is
  the one to read, and Go's `encoding/json` reads it that way (tested).
- A PDP or mapping failure writes an `error` line with no `decision`. A missing optional attribute writes a `deny`
  with an `error` field. Some refusals (PDP unreachable, body too large, token exchange failed) write only an access
  record. The adapter records decisions only: an error line and an access record with no decision are counted and
  skipped.

## The record it writes

`kind: federated.decision`, boundary `runtime`, provider `traefik-hub` (the name and version come from the
provider's registration). Verified: `provider`, `ts`. Everything else is claimed.

| Ledger field | From |
| --- | --- |
| `decision` | Hub's `decision`. `bypass` (a policy with `strategy: bypass` that never asked the PDP) is recorded as `allow` with `result: "bypass: ..."`, and Hub's own word is kept in `source.hub_decision` |
| `result` | Hub's `message` (`Request allowed`, `Request denied`), else the decision |
| `reason` | Hub's `reason`, else `error: <error>` |
| `task_id` | the correlation (next section), when there is one: a claim |
| `coverage` | always `observed-not-attributed` (next section) |
| `principal` | `ClientUsername` (when not `-`), else `--principal-header` |
| `agent` | the kept `--agent-header` (default `X-Evidence-Agent`, the header in Traefik's example) |
| `target` | `RequestHost` + `RequestPath` |
| `subject` | `{kind: tool-call, name: <target or middleware>, digests: {decisionLine, accessLine}}`: the SHA-256 of each line exactly as read |
| `source` | `system: traefik-hub`, `correlated` (true when the record carries a correlated `task_id`), `middleware`, `middleware_type`, `hub_decision`, `policy`, `trace_id`, `gateway_id`, `decision_log_id` and `access_log_id` (the two `transparency_log_id`s), `time`, `method`, `router`, `downstream_status` |

The core refuses a `federated.decision` record in these cases (`checkFederated` in `internal/server/records.go`):

- it carries a Clearance `rule` or `tier`, or an `effect`, `outcome`, `change` or `tool` (the core decided nothing);
- its coverage is anything other than `observed-not-attributed` (`authorized-and-verified` is refused, with or
  without a `task_id`).

### Correlation and coverage

`trace_id` joins a decision to an access record. Chained requests that forward `traceparent` share one trace, so a
trace can hold several decisions and several requests. A decision is **paired** with an access record (principal,
agent, target) only when its trace holds exactly one of each. Its **task** is the trace's task id.

The default correlator reads a task id header that the caller sends and Hub keeps in the access record
(`--task-header`, default `X-Clearance-Task-Id`). A trace's task id is taken only when every record in the trace
that names one names the same one. The Autopilot gateway, or any client, stamps that header on calls it makes
through Hub. `MapCorrelator` takes a trace-to-task table instead, from a gateway that recorded the `traceparent` it
sent.

Every federated record's coverage is `observed-not-attributed`, whether or not the trace correlates. Hub's PDP
authorized or refused the call, not Clearance, and the correlation is the caller's claim, carried in a header
Clearance never checked. `authorized-and-verified` would overstate what Clearance knows, so the core refuses it on
a `federated.decision`. A correlated record keeps its `task_id` as a claimed field and sets
`source.correlated: true`, so a reader can find a task's federated decisions without the coverage state saying
more than is known.

### Re-runs

The ledger is append-only, so a second run over a log that has grown must not post a line twice. `--state <file>`
keeps the key of each record already posted (the SHA-256 of its decision line), one key per line, appended as each
record lands. A run stops at the first failed post, and the next run picks up from there.

## Running it

1. Configure Hub. These are the Helm values the Transparency Logs page requires or documents:
   - `log.format: json`
   - `accessLog.format: json`
   - `log.filePath` and `accessLog.filePath` on a persistent volume
   - `log.level: INFO`
   - tracing enabled (`tracing.otlp.enabled`) so records carry `trace_id`
   - the headers the adapter reads kept in the access log:

   ```yaml
   accessLog:
     fields:
       headers:
         defaultMode: drop
         names:
           X-Clearance-Task-Id: keep
           X-Evidence-Agent: keep
   ```

2. Register the provider on the core:

   ```json
   {"name": "traefik-hub", "version": "<Hub version>", "principals": ["<ns>/<adapter service account>"],
    "kinds": ["federated.decision"]}
   ```

3. Run the adapter where it can read both files (a CronJob or a sidecar on the same volume), with an
   audience-bound projected service-account token:

   ```
   clearance federate traefik-hub --hub-log /logs/hub.log --access-log /logs/access.log \
     --core http://clearance-core.clearance-system:8080 --token-file /var/run/secrets/tokens/clearance \
     --state /state/traefik-hub.keys
   ```

   Without `--core` it prints the records as JSON lines and posts nothing (a dry run). A JSON summary goes to
   stderr: lines read, skipped, paired, correlated, posted. Exit 0 means done, 1 means a failure, 2 means a usage
   error.

Limits: each line is at most 64 KiB, each file at most 1,000,000 lines, and each string is kept to 1 KiB of valid
UTF-8 with control characters removed. A line that is not JSON is counted, not fatal. `FuzzIngest` covers the
parser.

## What is not verified

- **No real Hub line yet.** The tests run on the published examples plus lines built from the published field lists
  (`testdata/lab-*.log`; the test file says which are which). When a real Hub's lines exist, they go in
  `testdata/` and the same tests run on them.
- **Transparency-log inclusion is not checked.** The adapter keeps the SHA-256 of each line and both
  `transparency_log_id`s, so a later verifier can check a record against Hub's Tessera log and signed checkpoints.
  Traefik does not publish which hash or leaf encoding Hub uses, so it is unknown whether the line digest equals
  the leaf. Checking inclusion against a checkpoint is a follow-up and needs a real log.
- **The MCP tool is not in either record.** Hub's decision record names the policy but not the tool or resource,
  and the access record carries the path, not the JSON-RPC body. Give each policy a name that identifies the tool
  (`policy: transfer-limit`) for the ledger to show it.
- **No streaming.** The adapter reads files and does not tail them. A sidecar that tails the log, or Hub's OTLP log
  export, is a follow-up.

## Clearance as Hub's PDP

The card says a Hub customer "can point the Sovereign Trust Plane at [`POST /access/v1/evaluation`] and get
Clearance's tiers and structured denials". **Unverified, and not true today.** Here is what a customer would
configure, and where each step fails.

What a customer would configure (the shape Traefik documents for the `authzen` and `authzen-mcp` middlewares):

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata: {name: clearance-pdp, namespace: apps}
spec:
  plugin:
    authzen-mcp:
      pdpEndpoint: "http://clearance-core.clearance-system:8080/.well-known/authzen-configuration"
      clientConfig:
        timeoutSeconds: 1
        maxRetries: 1
        headers:
          Authorization: "urn:k8s:secret:clearance-pdp-token:token"   # a bearer token the core authenticates
      policies:
        - name: tool-call
          match: Equals(`mcp.method`, `tools/call`)
          mapping:
            evaluation:
              subject: {type: "principal", id: "$token.sub"}
              action: {name: "tool.call"}
              resource: {type: "tool", id: "$params.name"}
          onDenyResponse:
            status: 403
            body: '{{ .Decision | toJson }}'   # Clearance's context: rule id and hint
```

Where it fails today:

1. **Discovery.** Traefik documents `pdpEndpoint` as the PDP's AuthZEN configuration endpoint (its example is
   OpenFGA's `/.well-known/authzen-configuration/<store>`), which is AuthZEN 1.0 §9 metadata. Hub reads
   `access_evaluation_endpoint` from it (inferred from the spec: Traefik does not say which field it reads). The
   core serves no `/.well-known/authzen-configuration`, so Hub cannot find `/access/v1/evaluation`.
2. **The request.** The core's evaluation is AuthZEN-shaped but strict. It requires `subject.type: principal` with
   `properties.kind` and `properties.tier_ceiling`, `context.now`, and the gateway's session state for the rules
   that read it. Traefik's mapping has `subject.type` and `subject.id` but no `subject.properties`, and its roots
   (`token`, `request`, `params`) give no clock. Hub's default MCP mapping (`subject.type: identity`, `action.name:
   tools/call`, `context.agent` as a string) is refused outright. `premise_test.go` pins both.
3. **Authentication.** The core accepts only a registered provider's bearer token. Hub sends static headers from a
   Secret and does not refresh them, so the only fit is a long-lived token. That breaks Clearance's rule of
   audience-bound projected tokens.
4. **Failure behaviour.** A 400 from the core is a PDP error to Hub, which answers 500, not the deny response. So
   denials would not be structured even if the request got through.

What does work: the response. `{"decision": bool, "context": {...}}` is the AuthZEN 1.0 shape. If Hub tolerates the
extra top-level `decision_id` and `record` fields (Unverified), `.Decision` in `onDenyResponse` would render
Clearance's rule id and hint.

Closing the gap is a core change and a separate package. It would add three things:

- a foreign-PEP evaluation profile: plain AuthZEN 1.0 subject, action and resource; the subject's tier and kind
  resolved by the core from its directory; the clock taken from the core; no session state, so session rules are
  skipped and recorded as such;
- `/.well-known/authzen-configuration` metadata;
- an authentication path Hub can use, such as mTLS by `clientConfig.tls` or a short-lived token Hub can refresh.

This package did not build it. The core's server and its gate were being changed in parallel, and the card's done
bar is the recorded-format test.

## Sources

Every URL below was opened while writing this page (2026-11-03).

- Traefik Hub, Transparency Logs (the decision and access record formats, Helm values, linking, refusals without a
  decision record): https://doc.traefik.io/traefik-hub/api-gateway/observability/transparency-logs
- Traefik Hub, AuthZEN middleware reference (`pdpEndpoint`, `clientConfig`, `mapping`, `onDenyResponse`, the
  decision log line): https://doc.traefik.io/traefik-hub/api-gateway/reference/routing/http/middlewares/ref-authzen
- Traefik Hub, AuthZEN for MCP Gateway (policies, built-in defaults, JSON-RPC denials, early access from
  v3.21.0-ea.3): https://doc.traefik.io/traefik-hub/mcp-gateway/guides/authzen-mcp
- Traefik Hub, Configure AuthZEN Authorization for MCP Gateway (walkthrough; the deny example's fields):
  https://doc.traefik.io/traefik-hub/mcp-gateway/guides/authzen-mcp-walkthrough
- Traefik Hub, Understanding AuthZEN: https://doc.traefik.io/traefik-hub/api-gateway/guides/understanding-authzen
- Traefik Proxy, Logs and AccessLogs reference (access-log field names, `fields.headers` modes):
  https://doc.traefik.io/traefik/reference/install-configuration/observability/logs-and-accesslogs/
- Traefik Labs' Sovereign Trust Plane announcement, as reprinted (15 September 2026; Delegate, Authorize, Prove):
  https://www.01net.it/traefik-labs-introduces-the-sovereign-trust-plane-bringing-verifiable-evidence-to-ai-agent-governance/
- OpenID AuthZEN Authorization API 1.0 (Final, 11 January 2026: the evaluation shape, `/access/v1/evaluation`,
  §9 metadata discovery): https://openid.net/specs/authorization-api-1_0.html
