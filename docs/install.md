# Installing Clearance

**Status: Built and deployed.** The image (`ghcr.io/jfillman/clearance`) and the Helm chart
(`oci://ghcr.io/jfillman/charts/clearance`) are built and published by the release workflow from the first tag after
R-2 (v0.27.0). The chart's install test passes on a fresh kind cluster in CI (`.github/workflows/chart.yaml`), and
the release workflow reruns it on the published chart and image. hangar-dev runs this chart (0.29.0, Apron's
`components.clearance`, R-7) since the cutover of 2026-11-03 (R-4).

Clearance installs on any Kubernetes cluster (1.27 or newer). It needs a Postgres database and nothing else: no
Airframe, no Glidepath, no Autopilot, no Backstage. Those are integrations you can turn on with values.

## What you get

| Feature | What the chart does |
|---|---|
| **One writer** | The core (`clearance core`) is always **one replica** with the `Recreate` strategy. It holds Postgres's advisory writer lock for its whole life, so a second core fails to start instead of forking the evidence chain. There is no `core.replicas` value; setting one is an error. |
| **The read API** | clearance-api (`clearance api`), two replicas behind a PodDisruptionBudget (`minAvailable: 1`), a rolling update that never drops below that. It reads with a read-only role, never takes the lock and never writes. |
| **Hardened pods** | The image is one static Go binary on distroless static, nonroot, pinned by digest: no shell, no package manager. Every pod runs as uid 65532 with a read-only root filesystem, all capabilities dropped, no privilege escalation and seccomp `RuntimeDefault`. |
| **Default-deny network** | A NetworkPolicy denies all ingress and egress for every pod of the release. The core and the api each get only DNS, Postgres, the Kubernetes API server (TokenReview), and the callers and egress you list. With no `networkPolicy.core.from`, no pod can reach the core. |
| **Secrets by reference** | No secret value is ever a chart value. The DSN comes from a Secret you name (or the one CloudNativePG writes); the GitHub App's key and webhook secret are mounted as files from a Secret (or one an ExternalSecret creates). The chart renders no `Secret` object. |
| **Service identity** | Callers in the cluster send a projected service-account token for the audience `clearance`; the core and the api verify it by TokenReview (the chart binds `system:auth-delegator` to their service accounts, nothing more). Backstage calls carry a projected token for the `backstage` audience. |
| **Optional pieces** | A CloudNativePG `Cluster` with a read-only `clearance_reader` role, ExternalSecrets for the App and the reader's password, Gateway API `HTTPRoute`s for the core (or just its webhook) and the api. |
| **`helm test`** | Runs `clearance chain verify` against the database, read-only: the evidence chain verifies from genesis. |

## Install

```shell
kubectl create namespace clearance
# The core's DSN, as a Secret you manage (key uri). Or turn on cnpg.enabled and skip this.
kubectl -n clearance create secret generic clearance-db --from-literal=uri='postgres://clearance:...@db:5432/clearance'

helm install clearance oci://ghcr.io/jfillman/charts/clearance --version 0.27.0 -n clearance -f values.yaml
helm test clearance -n clearance --logs        # chain verify
```

A minimal `values.yaml` that lets one provider decide and record and one CI identity register changes:

```yaml
database:
  existingSecret: clearance-db
providers:
  - {name: my-gateway, version: "1.0.0", principals: ["agents/my-gateway"]}
verifiers: ["ci/deploy-gate"]
networkPolicy:
  core:
    from:
      - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: agents}}
      - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: ci}}
  postgres:
    to:
      - ipBlock: {cidr: 10.0.12.0/24}    # where your Postgres is
```

A caller's pod mounts its token for the core's audience and sends it as `Authorization: Bearer <token>`:

```yaml
volumes:
  - name: clearance-token
    projected:
      sources:
        - serviceAccountToken: {path: token, audience: clearance, expirationSeconds: 3600}
```

The core authenticates it as `<namespace>/<serviceaccount>`, which is what `providers[].principals`, `verifiers`,
`delegates` and `api.auditors` match (fnmatch globs).

Services: `<release>-core` and `<release>-api` on port 8080 (`clearance-core` and `clearance-api` when the release is
named `clearance`).

## Every value

Each value becomes one of the variables in [core.md](core.md#configuration); an empty value leaves the variable
unset, so the core's default applies. Lists are joined with commas.

### Image

| Value | Default | Meaning |
|---|---|---|
| `image.repository` | `ghcr.io/jfillman/clearance` | |
| `image.tag` | `v` + the chart's appVersion | The release that packaged the chart. |
| `image.digest` | | `sha256:...` of the image index; used instead of the tag. Pin by digest in production. |
| `image.pullPolicy`, `imagePullSecrets` | `IfNotPresent`, `[]` | |
| `nameOverride`, `fullnameOverride`, `commonLabels` | | |

### Callers and policy

| Value | Variable | Meaning |
|---|---|---|
| `providers` | `CLEARANCE_PROVIDERS` | The registered providers, `{name, version, principals, kinds?, intent_capture?, definitions?, conformance?}` ([core.md](core.md#registered-providers-clearance_providers)). Without one nobody may evaluate or record. `definitions: true` (one provider at most) may publish its cluster-pinned agent definitions. |
| `verifiers` | `CLEARANCE_VERIFIERS` | Principal globs that may register changes and ask for provenance. |
| `delegates` | `CLEARANCE_DELEGATES` | Principal globs that may act for a person they name. |
| `admins` | `CLEARANCE_ADMINS` | `user:<login>` globs that may deny any held change. |
| `policy.bundles` | `CLEARANCE_BUNDLES` | Policy bundles, each `{name, configMap, key}` (key default `bundle.json`): a ConfigMap you manage, mounted for the core and the api at `/etc/clearance/bundles/<name>/` ([core.md](core.md#policy-bundles)). Default: the core rules only. |
| `policy.sources` | `CLEARANCE_BUNDLE_SOURCES` | Where each bundle source is read at start, by name: `{url, sendToken?, tokenAudience?, tokenExpirationSeconds?}` (with `sendToken` the pod sends a projected service-account token, of `tokenAudience` or else the API server's default audience, mounted at `/var/run/clearance/sources/<name>`), or `{configMap, key?}` (a file). |
| `policy.sourceWait` | `CLEARANCE_BUNDLE_SOURCE_WAIT` | How long the start retries a source that does not answer before going on with its bundle degraded (default `10s`; [core.md](core.md#policy-bundles)). |
| `policy.egress` | | NetworkPolicy egress rules for the core and the api to reach the sources (with `networkPolicy.enabled`). |
| `policy.environments.*` | `CLEARANCE_ENV_*` | `lowerNames`, `lowerPrefixes`, `lowerProjectSuffixes`, `upperRepoPrefixes`: how arguments name an environment tier. |
| `vocabulary.*` | `CLEARANCE_ON_BEHALF_OF_HEADER`, `_TRAILER_PREFIX`, `_RUN_IDENTITY_NAMESPACE`, `_BASELINE_DENY_PATHS`, `_BASELINE_DENY_FIELDS`, `_GATE_OUTSIDE_GROUPS`, `_GATE_OWNER_FALLBACK`, `_V0_PROVIDER` | The deployment's vocabulary ([core.md](core.md#configuration)); empty values keep the core's defaults. |
| `audience` | `CLEARANCE_AUDIENCE` | Callers' token audience (default `clearance`). |
| `gate.expireSeconds` | `CLEARANCE_EXPIRE_SECONDS` | How often expired changes are swept (60). |
| `core.maxClockSkew` | `CLEARANCE_MAX_CLOCK_SKEW` | How far an evaluation's `context.now` may be from the core's clock, a Go duration (empty: `5m`; at most `24h`). The core refuses `0` (off) here: off is for `clearance core --memory` test cores. |
| `gate.agentLogins` | `AGENT_LOGINS` | GitHub logins agents open PRs as (default none). |
| `gate.modelRoutes` | `MODEL_ROUTES` | `alias=upstream` pairs a definition release may name. |
| `gate.runtimeImagesExtra` | `RUNTIME_IMAGES_EXTRA` | Globs a definition's `runtime.image` may match. |
| `gate.trustedRegistries` | `CLEARANCE_TRUSTED_REGISTRIES` | Image prefixes, each ending in `/`, a tier-1 image bump may come from; others are tier 2. Empty: any registry (the product default; Hangar sets its own in Apron). |
| `agents.configMap` | `CLEARANCE_AGENTS_DIR` | A ConfigMap of bundled agent definitions, mounted at `/etc/clearance/agents`. |

### People and other identities

| Value | Variable | Meaning |
|---|---|---|
| `oidc.issuer`, `oidc.audience` | `CLEARANCE_OIDC_ISSUER`, `CLEARANCE_OIDC_AUDIENCE` | People's OIDC issuer and audience, together or not at all. |
| `oidc.allowedUsers` | `CLEARANCE_OIDC_ALLOWED_USERS` | Required with an issuer: an issuer that federates GitHub signs in anyone. |
| `oidc.jwksURL`, `oidc.userClaim` | `CLEARANCE_OIDC_JWKS_URL`, `CLEARANCE_OIDC_USER_CLAIM` | Defaults `<issuer>/keys`, `email`. |
| `foreignCluster.issuer`, `foreignCluster.cluster`, `foreignCluster.serviceAccounts`, `foreignCluster.jwksURL` | `CLEARANCE_FOREIGN_*` | Another cluster's workloads (a portal on another cluster); cluster and service accounts are required with an issuer. |
| `githubActions.audience`, `githubActions.allowed` | `CLEARANCE_GITHUB_OIDC_AUDIENCE`, `CLEARANCE_GITHUB_OIDC_ALLOWED` | GitHub Actions callers (`clearance register` in CI); off while the audience is empty. |
| `githubApp.enabled`, `githubApp.appId` | `CLEARANCE_GITHUB_APP_ID` | The Clearance GitHub App. |
| `githubApp.existingSecret`, `githubApp.privateKeyKey`, `githubApp.webhookSecretKey` | `CLEARANCE_GITHUB_APP_KEY_FILE`, `..._WEBHOOK_SECRET_FILE` | The Secret and its keys, mounted read-only (mode 0400) at `/etc/clearance/github-app/`. |
| `githubApp.comments`, `githubApp.api` | `CLEARANCE_GITHUB_APP_COMMENTS`, `CLEARANCE_GITHUB_API` | `off` or `agent-failures`; the API base. |
| `signing.existingSecret`, `signing.key` | `CLEARANCE_SIGNING_KEY_FILE` | The clearance token signing key: an existing Secret (never created by the chart) and its key (default `signing-key.pem`), mounted read-only (mode 0400) for the core only at `/etc/clearance/signing/`. Empty: no tokens ([below](#the-clearance-token-signing-key)). |
| `signing.kms` | `CLEARANCE_SIGNING_KMS` | A KMS key reference. Reserved: the core refuses to start with it until the KMS signer is built. |
| `token.ttl`, `token.issuer` | `CLEARANCE_TOKEN_TTL`, `CLEARANCE_TOKEN_ISSUER` | Each token's life (empty: `15m`; at least four `gate.expireSeconds`) and its `iss` (empty: `clearance`). |
| `backstage.url` | `BACKSTAGE_URL`, `BACKSTAGE_TOKEN_FILE` | The group directory and app owners. Without it no person can clear a tier-2 or tier-3 change. |
| `backstage.tokenAudience`, `backstage.tokenExpirationSeconds` | | The projected token sent to Backstage (`backstage`, 3600). |

### Database

| Value | Meaning |
|---|---|
| `database.existingSecret`, `database.key` | The core's DSN (`CLEARANCE_DSN`), key `uri`. Default with `cnpg.enabled`: `<release>-pg-app`. With `externalSecrets.database.dsn`: `<release>-db`. One of the three is required. |
| `database.reader.existingSecret`, `database.reader.key` | The api's read-only DSN (`CLEARANCE_API_DSN`). Default with the CNPG reader: `<release>-pg-reader`; otherwise the core's Secret, opened read-only (prefer a reader role). |
| `cnpg.enabled`, `cnpg.instances`, `cnpg.imageName`, `cnpg.database`, `cnpg.owner`, `cnpg.storage.*`, `cnpg.resources` | A CloudNativePG `Cluster` named `<release>-pg` (needs the CNPG operator). |
| `cnpg.reader.enabled`, `cnpg.reader.name`, `cnpg.reader.passwordSecret` | The read-only role (`clearance_reader`): created at initdb with `SELECT` on the owner's tables by default privileges; CNPG manages its login from a basic-auth Secret that also carries `uri` (the api's DSN). |
| `cnpg.operatorNamespace` | Allowed to reach the instances' status port (`cnpg-system`). |

### External Secrets Operator

`externalSecrets.enabled`, `apiVersion` (`external-secrets.io/v1`), `secretStoreRef.{name,kind}` and
`refreshInterval`, then `{key, property}` pairs in your store:

| Value | Creates |
|---|---|
| `externalSecrets.githubApp.privateKey`, `.webhookSecret` | `<release>-github-app`, used by `githubApp` when `existingSecret` is empty. |
| `externalSecrets.database.dsn` | `<release>-db` (key `uri`): a Postgres outside the chart. |
| `externalSecrets.reader.password` | `<release>-pg-reader`: basic-auth for the CNPG reader role plus the api's `uri`, built from the one password. |

### Workloads

| Value | Default | Meaning |
|---|---|---|
| `core.resources` | requests 50m / 64Mi, limit 256Mi | |
| `core.startupSeconds` | 300 | The core verifies the whole chain before it listens; a long chain needs time. |
| `core.serviceAccount.{create,name,annotations}` | create | |
| `core.{podAnnotations,podLabels,nodeSelector,tolerations,affinity,priorityClassName,hostAliases,extraEnv,extraVolumes,extraVolumeMounts}` | | |
| `api.enabled` | true | |
| `api.replicas` | 2 | |
| `api.pdb.{enabled,minAvailable}` | true, 1 | |
| `api.auditors`, `api.notifiers` | | `CLEARANCE_API_AUDITORS`, `CLEARANCE_API_NOTIFIERS`. |
| `api.feedReaders` | | `CLEARANCE_API_FEED_READERS`: `[{principal, cluster}]`, who reads a cluster's grant feed (a grant-sync agent). |
| `api.pool`, `api.definitionsInterval` | 5, 30 | `CLEARANCE_API_POOL`, `CLEARANCE_API_DEFINITIONS_INTERVAL`. |
| `api.resources`, `api.serviceAccount.*`, `api.topologySpreadConstraints` and the same pod settings as the core | | |
| `service.type`, `service.port` | ClusterIP, 8080 | |
| `rbac.authDelegator` | true | Binds `system:auth-delegator` (TokenReview) to the core's and the api's service accounts. |

The api is also given `CLEARANCE_CORE_URL` (the core's Service, where writes go) and the shared identity, Backstage,
pack and definition variables above.

### NetworkPolicy

| Value | Meaning |
|---|---|
| `networkPolicy.enabled` | true: default-deny for the release, then the allows below. |
| `networkPolicy.core.from`, `networkPolicy.api.from` | NetworkPolicyPeers allowed to call each on 8080: providers, verifiers, your Gateway's namespace (for the webhook), a portal. |
| `networkPolicy.dns.{namespace,podSelector}` | `kube-system`, `k8s-app: kube-dns`. |
| `networkPolicy.kubeAPIServer.{cidrs,ports}` | The API server for TokenReview. Default `0.0.0.0/0` on 443 and 6443: narrow it to `kubectl get endpoints kubernetes`. |
| `networkPolicy.kubeAPIServer.ciliumEntity` | Default false. **On Cilium set it true**: an ipBlock never matches the API server there (it is the `kube-apiserver` entity unless the agent runs with `policy-cidr-match-mode: nodes`), so TokenReview times out and every caller answers 401. true also renders a `CiliumNetworkPolicy` (`<fullname>-kube-apiserver`, cilium.io/v2) letting the core and the api reach `toEntities: [kube-apiserver]`, nothing else. Leave it false on any other CNI (the CRD would not exist). |
| `networkPolicy.postgres.{to,port}` | Your Postgres; the chart's CNPG instances are added automatically. With `cnpg.enabled`, a policy on the instances admits only the core, the api, the test pod, each other and the operator. |
| `networkPolicy.extraEgress` | NetworkPolicyEgressRules: the OIDC JWKS, Backstage, the GitHub API. |

### Routes and tests

| Value | Meaning |
|---|---|
| `httpRoutes.core.{enabled,parentRefs,hostnames,matches}` | An HTTPRoute to the core. To expose only the GitHub App webhook: `matches: [{path: {type: Exact, value: /v1/github/webhook}}]`. |
| `httpRoutes.api.{enabled,parentRefs,hostnames,matches}` | An HTTPRoute to the api. |
| `tests.chainVerify` | The `helm test` pod (true). |

## The clearance token signing key

The core signs a clearance token for every cleared change (C-1, [core.md](core.md#the-clearance-token)) with an
ECDSA P-256 key you hold. The chart never creates the Secret and never renders a key; you make the key and the
Secret yourself, outside the chart:

```shell
# On a machine you trust; the key never goes in git, values, a log or a chat.
openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem   # SEC 1 "EC PRIVATE KEY"
kubectl -n <namespace> create secret generic clearance-signing-key --from-file=signing-key.pem=signing-key.pem
rm signing-key.pem   # once it is in the Secret (or only in your secret store)
```

or put the PEM in your secret store and sync it with an ExternalSecret you manage (the Secret's key must be the
chart's `signing.key`). Then set `signing.existingSecret: clearance-signing-key`. The core logs the key's `kid` at
start and publishes the public half at `GET /v1/keys` (the core and clearance-api).

- **Rotation**: replace the key in the Secret and restart the core. The live tokens are re-signed with the new key at
  once; the old public key stays in `GET /v1/keys` for 24 hours.
- **KMS**: `signing.kms` is reserved for a KMS-held key (the core refuses it until the KMS signer is built).

## Upgrade

```shell
helm upgrade clearance oci://ghcr.io/jfillman/charts/clearance --version <new> -n clearance -f values.yaml
helm test clearance -n clearance --logs
```

- **The core restarts, never overlaps.** `Recreate` stops the old core before the new one starts: decisions are
  refused for the seconds in between (callers fail closed; the Go and Python clients report the core unavailable).
  The new core verifies the chain from genesis before it serves; a chain that does not verify stops it from
  starting rather than being extended.
- **The api rolls.** One new pod at a time, never below `minAvailable`.
- **Schema.** The core creates its tables with `CREATE ... IF NOT EXISTS` and changes nothing else, so an upgrade
  needs no migration step. Check the release notes for any that does.
- **Read the notes first.** A minor version may change a value's meaning; the CHANGELOG says so under the release.

## The one-writer rule

The evidence chain is a hash chain: every record names the hash of the one before. Two writers would each extend
the head they saw and fork it. So:

- Only the core writes. It takes Postgres's advisory writer lock (`pg.LockKey`) on a dedicated connection when it
  opens the store, holds it until it exits, and runs every write on that connection. A second core, Go or Python,
  fails to open the store and exits.
- The chart runs exactly one core, upgraded with `Recreate`. Do not run a second release against the same database,
  and do not scale the core Deployment by hand (the second pod crash-loops on the lock; it does no harm, but it is
  not a standby).
- The api and `clearance chain verify` open the store read-only (`pg.OpenReader`): no lock, no migration, every
  session read-only. Give them a read-only role.
- High availability is the database's (CNPG instances) and the api's (replicas), not the core's: the core restarts
  in seconds, and callers fail closed meanwhile.
