# G-ARGO-1 on hangar-prod: the plan for the user

Status: **Proposal, not run.** Every spike ran on hangar-dev first; the results are in [gate.md, phase 2](../../gate.md#phase-2-design-pass-g-argo-1-2026-11-03).
Two measurements only mean something on hangar-prod, and this page prepares them for the user to run. Nothing
here was applied to hangar-prod by an agent.

- **P1, spike c on prod.** How the native ValidatingAdmissionPolicy and the Kyverno ValidatingPolicy behave on
  hangar-prod over 30 minutes, where Kyverno's admission controller restarts under load (614 restarts at
  2026-11-03 23:30Z, read-only check).
- **P2, spike e on prod.** Whether a second hangar-prod workload identity (the CMP's stand-in) reaches the core on
  hangar-dev through the route and authenticates as itself.

Both run in Warn mode in one scratch namespace, `clearance-spike-prot`, and match one service account that exists
only for the spike. No Argo CD Application, no tenant namespace and no existing policy is touched. Load: one
server-side dry run every 10 seconds, plus one token and two HTTP calls.

## Before you start (read only)

```sh
kubectl --context hangar-prod -n kyverno get pods                       # note the admission controller's RESTARTS
kubectl --context hangar-prod top node                                  # skip the run if the node is pegged
kubectl --context hangar-prod get --raw /readyz
```

If the node is spiralling (the podman VM near 700% CPU), stop here: the numbers would only measure the spiral.

## P1: the two admission policies under prod load

Files: [`prod/`](prod/) and the shared CRD [`manifests/20-grant-crd.yaml`](manifests/20-grant-crd.yaml).

```sh
cd docs/spikes/g-argo-1
kubectl --context hangar-prod apply -f manifests/20-grant-crd.yaml
kubectl --context hangar-prod wait --for=condition=Established crd/clearancegrants.spike.clearance.hangar.io
kubectl --context hangar-prod apply -f prod/00-namespace.yaml           # namespace, writer + cmp SAs, Role, ConfigMap, grant
kubectl --context hangar-prod apply -f prod/30-vap.yaml                 # VAP + binding, Warn/Audit, parameterNotFoundAction Allow
kubectl --context hangar-prod apply -f prod/31-kyverno.yaml             # Kyverno ValidatingPolicy, Audit/Warn, + read ClusterRole
```

Check the blast radius before the loop. Kyverno must have registered one fine-grained webhook for this policy,
carrying the namespace selector and the match condition, and nothing wider:

```sh
kubectl --context hangar-prod get validatingwebhookconfigurations kyverno-resource-validating-webhook-cfg -o json \
  | jq '.webhooks[] | select(.name|test("spike")) | {name, failurePolicy, timeoutSeconds, namespaceSelector, matchConditions: [.matchConditions[]?.name], rules}'
```

Expected: `failurePolicy: Fail`, `timeoutSeconds: 10`, `namespaceSelector.matchLabels` `clearance.hangar.io/protected: "true"`,
`matchConditions` `[argo-controller-main-resource]`, and `rules` ConfigMaps CREATE/UPDATE only (this is what
hangar-dev showed). If the selector or the match condition is missing, go straight to rollback.

Run the loop (30 minutes, 180 dry runs as the spike writer, alternating a listed write and a wrong stamp):

```sh
CONFIRM=hangar-prod prod/run-prod-c.sh | tee /tmp/g-argo-1-prod-c.txt
kubectl --context hangar-prod -n kyverno get pods                       # RESTARTS again: how many during the run
kubectl --context hangar-prod get --raw /metrics | grep -E 'spike-clearance-protected-writes' \
  | grep -E 'admission_policy_check_duration_seconds_(sum|count)|webhook_admission_duration_seconds_(sum|count)|webhook_rejection_count'
```

Expected, from hangar-dev (2026-11-04 00:20 to 00:36Z, where Kyverno's admission controller was also crash-looping,
234 to 237 restarts):

| Line | Expected |
| --- | --- |
| `listed` | `admitted`, or `kyverno-webhook-error` while Kyverno is down (a refusal, even in Audit/Warn, because the policy is `failurePolicy: Fail`) |
| `bad-stamp` | `vap-warn` every time; `kyverno-warn` when Kyverno is up, `kyverno-webhook-error` when it is down |
| latency | the VAP adds about 1 ms (apiserver metric, 20 checks, 21 ms total on dev); the Kyverno webhook about 0.5 to 1.2 s per call when up, up to its 10 s timeout when hung |

What to send back: the tee'd file, the restart counts before and after, and the metric lines. The comparison that
matters is the share of `kyverno-webhook-error` lines (writes Argo CD could not make) against zero for the VAP.

### Rollback for P1

```sh
kubectl --context hangar-prod delete validatingpolicy.policies.kyverno.io spike-clearance-protected-writes
kubectl --context hangar-prod get validatingwebhookconfigurations kyverno-resource-validating-webhook-cfg -o json \
  | jq '[.webhooks[].name | select(test("spike"))] | length'           # repeat until 0
```

Kyverno removes the webhook only while its admission controller is running: on hangar-dev the spike's webhook stayed
for about 4 minutes after the policy was deleted, until the controller came back. While it stays it still only
matches the spike writer in `clearance-spike-prot`, so nothing else is affected; do not edit Kyverno's webhook
configuration by hand. Then:

```sh
kubectl --context hangar-prod delete -f prod/30-vap.yaml
kubectl --context hangar-prod delete namespace clearance-spike-prot     # after P2, which uses the same namespace
kubectl --context hangar-prod delete clusterrole spike-kyverno-read-clearancegrants
kubectl --context hangar-prod delete crd clearancegrants.spike.clearance.hangar.io
```

## P2: a second hangar-prod identity reaches the core

The core on hangar-dev trusts hangar-prod's public issuer (`https://hangarplatform.dev/oidc/hangar-prod`) for the
service accounts in `CLEARANCE_FOREIGN_SERVICE_ACCOUNTS`, today only `app-backstage-prod/backstage-ingestor`. The
CMP and the grant agent will be two more. P2 proves the path with the spike's `clearance-spike-cmp` account.

e1, before any config change (needs `prod/00-namespace.yaml` from P1):

```sh
CONFIRM=hangar-prod prod/probe-e.sh
```

Expected: `POST /v1/clearances -> 401` (the service account is not allowed), and `POST /v1/records -> 404` (the
route does not expose `/v1/records`; seen from the laptop on 2026-11-04, so the agent's outcome posts need the route
change below).

e2, the dev-side change (an apron PR the user merges; hangar-dev, not prod): add the spike account to the core's
foreign list.

```yaml
# apron cluster.yaml for hangar-dev, the clearance block (value name from the clearance chart 0.30.0)
clearance:
  foreignCluster:
    serviceAccounts:
      - app-backstage-prod/backstage-ingestor
      - clearance-spike-prot/clearance-spike-cmp     # G-ARGO-1 spike e only; remove in rollback
```

Render, diff-check, merge, let Argo CD sync `clearance-core`, then run `probe-e.sh` again.

Expected: `POST /v1/clearances -> 403 {"error":"hangar-prod/clearance-spike-prot/clearance-spike-cmp is not a verifier"}`.
That line is the proof: the token crossed from hangar-prod through Traefik to the core, was verified against
prod's public JWKS, and named the new principal. The empty body is refused before the gate writes anything; confirm
with the chain count from `GET /v1/evidence/verify` before and after (unchanged).

e3 (optional): also add `hangar-prod/clearance-spike-prot/clearance-spike-cmp` to `CLEARANCE_VERIFIERS`; the answer
becomes 400 (a bad change), still with nothing recorded. Not needed to accept the shape.

### Rollback for P2

Revert the apron change (and e3's), let `clearance-core` sync, and delete the namespace (P1's rollback). The token
expires on its own after 10 minutes; it was never written to a file.

## What the user decides afterwards

- Whether P1's numbers change D27 (the native VAP; see hangar decisions). They are expected to strengthen it.
- Whether to open the `/v1/records` route on `clearance.hangar-dev.local` for the agent (G-ARGO-3), or give the agent
  its own route; D29 recommends the narrow `Exact /v1/records` match.
