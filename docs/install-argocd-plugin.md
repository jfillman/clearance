# Installing the Argo CD plugin (`clearance-cmp`)

The deployment gate's Argo CD half is a [Config Management Plugin](https://argo-cd.readthedocs.io/en/stable/operator-manual/config-management-plugins/)
that runs as a **sidecar of the `argocd-repo-server` pod**. For an Application that names it, the plugin renders the
manifests, hashes the tree, asks the Clearance core whether that tree is cleared, and stamps the objects it emits (or
holds the sync for people, or refuses). This page installs it on any Argo CD: the official `argo-cd` Helm chart or
plain manifests. Nothing here depends on a particular platform.

What the plugin is and how it decides is in [gate.md](gate.md#the-argo-cd-plugin-and-the-presync-wait-g-argo-4-and-g-argo-5-built);
this page is the install, the settings, the checks and the failure modes.

**The plugin alone does not stop a sync.** It renders, stamps and registers; a refusal shows as a `ComparisonError`
and a held change as a PreSync wait, but `argocd app sync --strategy apply` skips hooks and a cleared render can be
followed by a push. What refuses an object that no cleared grant lists is the admission policy and the Argo CD agent
([gate.md](gate.md#g-argo-2-the-grant-and-the-admission-policy-built)). Install the plugin first, watch it, then
turn enforcement on.

## Outline

1. [Prerequisites](#prerequisites)
2. [The sidecar](#the-sidecar): Helm chart values, or a patch of the plain manifests
3. [Run `doctor` first](#run-doctor-first)
4. [Every setting](#every-setting)
5. [Gating one Application](#gating-one-application), by hand or from an ApplicationSet
6. [Turning it off again](#turning-it-off-again)
7. [Verifying it works](#verifying-it-works)
8. [Troubleshooting](#troubleshooting)
9. [Upgrade and rollback](#upgrade-and-rollback)
10. [What the plugin does not do](#what-the-plugin-does-not-do)

## Prerequisites

| You need | Detail |
|---|---|
| **Argo CD 3.x** | The plugin is built and tested against **Argo CD v3.5.0**: its image ships Helm v4.2.1 and kustomize v5.8.1, the versions that release runs, and the parity suite ([gate.md](gate.md#the-parity-suite)) compared it with the repo-server's own render of every Application on 3.5.0 clusters. Older Argo CD is not tested. A render differs between Helm majors (a `null` in a values file, for one), so on any other Argo CD minor run `clearance-cmp parity` against your Applications before you rely on the stamps for them. |
| **A reachable Clearance core** | `CLEARANCE_URL`, an http(s) URL the repo-server pod can reach, ideally https terminated at a route. The core must run a release that has the deployment gate ([install.md](install.md)). The core's `NetworkPolicy` (`networkPolicy.core.from`) must allow the repo-server's namespace, and your own egress rules must let the repo-server pod reach the core and the chart repositories. |
| **A verifier token** | The plugin registers changes, which only a **verifier** may do ([core.md](core.md#configuration), `CLEARANCE_VERIFIERS`). There is no secret to create: the plugin's identity is the **repo-server's service account**, and its credential is a *projected service-account token* with the audience `clearance` (the core's `CLEARANCE_AUDIENCE`), which the kubelet mints and rotates. The core authenticates it by TokenReview as `<namespace>/<serviceaccount>` ([install.md](install.md#install), "A caller's pod mounts its token"). So the one thing to do on the core is to list that principal as a verifier, for example `argocd/argocd-repo-server` (the chart names the account `<release>-repo-server`; the plain manifests `argocd-repo-server`). A repo-server on another cluster is a "foreign" caller: set `CLEARANCE_FOREIGN_ISSUER`, `_CLUSTER`, `_SERVICE_ACCOUNTS` and `_JWKS_URL` ([core.md](core.md#configuration)). |
| **The gitops repository** | Argo CD fetches it as the plugin's source, with its own credentials. The sidecar mounts **no** repository credential. The AppProject's `sourceRepos` must list it as for any Application. |
| **The images** | `ghcr.io/jfillman/clearance-cmp:vX.Y.Z` (linux/amd64 and arm64, signed, with an SBOM; pin it by digest) and, for the PreSync wait, `ghcr.io/jfillman/clearance-wait:vX.Y.Z`. `doctor` is in the first release after 0.52.2. |
| **Chart repositories the platform trusts** | Behind the gate the **plugin**, not Argo CD, fetches the chart, so the AppProject's `sourceRepos` do not apply to it. You write the allow list yourself (`CLEARANCE_CHART_REPOS`). There is no default and no wildcard. |

## The sidecar

The sidecar is a container of the repo-server pod:

- **image**: `clearance-cmp` (git, helm, kustomize, the static `clearance-cmp` binary, and the plugin's `plugin.yaml`
  baked in, so no `argocd-cmp-cm` ConfigMap is needed);
- **command**: `/var/run/argocd/argocd-cmp-server`, the binary the repo-server's `copyutil` init container copies into the
  shared `var-files` volume;
- **user** 999, read-only root filesystem, no capabilities, no privilege escalation;
- **volumes**: `var-files` at `/var/run/argocd` and `plugins` at `/home/argocd/cmp-server/plugins` (both are defined by
  Argo CD's own repo-server; this is how the repo-server finds the plugin's socket), a writable emptyDir at `/tmp`
  (the render's work directory and the cache), and the projected token at `/var/run/secrets/tokens` (read-only);
- **settings**: environment variables (below).

Only this container mounts the clearance token. The Argo CD containers do not.

### With the official `argo-cd` Helm chart

Add this to the values of the `argo-cd` chart (value names checked against chart 10.x; `repoServer.extraContainers` and
`repoServer.volumes` are the chart's own keys, and the chart already defines the `var-files` and `plugins` volumes and
the `copyutil` init container):

```yaml
repoServer:
  extraContainers:
    - name: clearance-cmp
      image: ghcr.io/jfillman/clearance-cmp@sha256:<digest of the release you pin>
      command: [/var/run/argocd/argocd-cmp-server]
      securityContext:
        runAsNonRoot: true
        runAsUser: 999
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
        seccompProfile: {type: RuntimeDefault}
      env:
        - {name: CLEARANCE_URL, value: "https://clearance.example.test"}
        - {name: CLEARANCE_TOKEN_FILE, value: /var/run/secrets/tokens/clearance}
        # The repositories a chart may be fetched from. Required: with none, every chart is refused.
        - {name: CLEARANCE_CHART_REPOS, value: "https://git.example.test/platform/charts.git"}
        # The PreSync wait Job's image: needed the first time a change is held for people.
        - {name: CLEARANCE_WAIT_IMAGE, value: "ghcr.io/jfillman/clearance-wait@sha256:<digest>"}
        - {name: CLEARANCE_CMP_CACHE_DIR, value: /tmp/clearance-cmp-cache}
      resources:
        requests: {cpu: 50m, memory: 128Mi}
        limits: {memory: 512Mi}
      volumeMounts:
        - {name: var-files, mountPath: /var/run/argocd}
        - {name: plugins, mountPath: /home/argocd/cmp-server/plugins}
        - {name: cmp-tmp, mountPath: /tmp}
        - {name: clearance-token, mountPath: /var/run/secrets/tokens, readOnly: true}
  volumes:
    - {name: cmp-tmp, emptyDir: {}}
    - name: clearance-token
      projected:
        sources:
          - serviceAccountToken: {audience: clearance, expirationSeconds: 3600, path: clearance}
```

If the core is reached by a name your DNS does not serve, the chart's `global.hostAliases` adds the same entries to
every Argo CD pod (the chart has no repo-server-only key). `repoServer.volumes` here are pod volumes: the repo-server's
main container does not mount `cmp-tmp` or the token, because `repoServer.volumeMounts` is not set.

The repo-server is single-purpose; give it a `NetworkPolicy` that allows egress to the core, to DNS, to the gitops
host (Argo CD's own) and to the hosts in `CLEARANCE_CHART_REPOS`, if you restrict egress.

### With plain manifests or kustomize

For the upstream `install.yaml` (the Deployment `argocd-repo-server` already has the `var-files` and `plugins` emptyDir
volumes; checked against the v3.5.0 `manifests/install.yaml`, whose service account is `argocd-repo-server`), a strategic-merge patch adds the container and its two volumes. As a kustomize patch in the overlay that
includes the Argo CD manifests:

```yaml
# kustomization.yaml
resources:
  - https://raw.githubusercontent.com/argoproj/argo-cd/v3.5.0/manifests/install.yaml
patches:
  - path: repo-server-clearance-cmp.yaml
    target: {kind: Deployment, name: argocd-repo-server}
```

```yaml
# repo-server-clearance-cmp.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argocd-repo-server
spec:
  template:
    spec:
      containers:
        - name: clearance-cmp
          image: ghcr.io/jfillman/clearance-cmp@sha256:<digest of the release you pin>
          command: [/var/run/argocd/argocd-cmp-server]
          securityContext:
            runAsNonRoot: true
            runAsUser: 999
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
            seccompProfile: {type: RuntimeDefault}
          env:
            - {name: CLEARANCE_URL, value: "https://clearance.example.test"}
            - {name: CLEARANCE_TOKEN_FILE, value: /var/run/secrets/tokens/clearance}
            - {name: CLEARANCE_CHART_REPOS, value: "https://git.example.test/platform/charts.git"}
            - {name: CLEARANCE_WAIT_IMAGE, value: "ghcr.io/jfillman/clearance-wait@sha256:<digest>"}
            - {name: CLEARANCE_CMP_CACHE_DIR, value: /tmp/clearance-cmp-cache}
          resources:
            requests: {cpu: 50m, memory: 128Mi}
            limits: {memory: 512Mi}
          volumeMounts:
            - {name: var-files, mountPath: /var/run/argocd}
            - {name: plugins, mountPath: /home/argocd/cmp-server/plugins}
            - {name: cmp-tmp, mountPath: /tmp}
            - {name: clearance-token, mountPath: /var/run/secrets/tokens, readOnly: true}
      volumes:
        - {name: cmp-tmp, emptyDir: {}}
        - name: clearance-token
          projected:
            sources:
              - serviceAccountToken: {audience: clearance, expirationSeconds: 3600, path: clearance}
```

The repo-server pod's service account (`argocd/argocd-repo-server` in the stock manifests) is the principal the core
sees. Add it to `verifiers` on the core before the first render, or the first Application shows a 403.

### Network namespace for the render steps (optional, recommended)

`helm template`, `helm dependency build` and `kustomize` can run in a private network namespace so that a tenant chart
cannot reach the repo-server pod's loopback ([gate.md](gate.md#parameters-and-settings), "Private network
namespace"). It needs a container seccomp profile that allows `unshare`/`clone` with `CLONE_NEWUSER|CLONE_NEWNET`
(`RuntimeDefault` does not). Without it the default (`CLEARANCE_CMP_NETNS=try`) renders without the namespace and says so
once. `doctor` reports which you have.

## Run `doctor` first

`clearance-cmp doctor` checks the settings and everything the plugin needs from its pod, **before** any Application
names the plugin. It uses the process's own environment, so run it in the sidecar:

```shell
kubectl -n argocd exec deploy/argocd-repo-server -c clearance-cmp -- clearance-cmp doctor
```

(`kubectl exec` runs with the container's environment and its user, so it reads the token as the plugin does.) It
prints one line per check, `ok`, `warn` or `fail`, and a `fix:` for the last two, and **exits 1 if any check fails**
(0 otherwise; 2 for a usage error). It also runs anywhere else given the same environment variables, for example
`docker run --env-file ... ghcr.io/jfillman/clearance-cmp:vX.Y.Z clearance-cmp doctor`.

| Check | What it looks at | Fails when |
|---|---|---|
| `setting` | Every sidecar setting, with the same rules the plugin applies at start, **all problems at once**: `CLEARANCE_URL` present and an http(s) URL, the allow list's entries, the wait host alias and image, the durations, `CLEARANCE_CMP_NETNS`. The per-run `ARGOCD_APP_*` and `PARAM_*` variables are set by Argo CD for each render, so they are not required here (a set one is still checked). | any is missing or malformed |
| `wait-image` | `CLEARANCE_WAIT_IMAGE` | (warns) unset: a held change gets no wait Job |
| `token` | the token file exists, is readable, non-empty, one token. Its content is never printed. | missing, unreadable, empty |
| `token` (mode) | not world-readable | (warns) world-readable: a projected token is `0644` unless the volume's `defaultMode` says otherwise |
| `core` | `GET /healthz` on `CLEARANCE_URL` | unreachable, or not a Clearance core |
| `core-tls` | plain http to a non-loopback host | (warns) |
| `core-auth` | the core accepts the token: an authenticated **read** of a change that does not exist (`GET /v1/clearances/{id}`). 404 means accepted, 401 rejected. The call cannot change anything. It does not prove the principal is a *verifier* (the core checks that when the plugin registers a change), and says so. | 401 or 403, or the core errors |
| `chart-repos` | the allow list is non-empty and every entry passes the canonical rules the plugin applies (`NormalizeRepo`); each normalised form is printed | empty, or an entry is not a repository URL (the plugin refuses to start with one); duplicates warn |
| `cache` | `CLEARANCE_CMP_CACHE_DIR` can be created and written: one probe file, removed | not writable (a read-only root with no `/tmp` volume) |
| `chart-cache` | on or off, its bounds (bytes, entries), and the free space of the volume holding the cache dir | (warns) the volume has less free space than the byte bound |
| `render-cache` | on or off, its TTL, and the cleared-tree cache TTL | never |
| `git`, `helm`, `kustomize` | present on `PATH`, with their versions printed | missing |
| `netns` | the private network namespace: `on`, `off` (set so) or `unavailable` | `unavailable` while `CLEARANCE_CMP_NETNS=require`; otherwise `unavailable` warns |
| `plugin-socket`, `cmp-server` | `/home/argocd/cmp-server/plugins` exists (`--plugin-dir` changes it) and `/var/run/argocd/argocd-cmp-server` is present | (warns) either is missing, which is normal outside the sidecar |

`doctor` writes nothing except the cache directory's probe file, registers no change, and prints no token.

Sample, from a sidecar whose seccomp profile does not allow the namespace:

```text
ok    settings       every sidecar setting is present and well formed (...)
ok    token          /var/run/secrets/tokens/clearance is non-empty and readable (mode 0440); its content is never printed
ok    core           https://clearance.example.test is reachable (GET /healthz)
ok    core-auth      the core accepted the token (an authenticated read of a change that does not exist answered 404). ...
ok    chart-repos    https://git.example.test/platform/charts.git is allowed as https://git.example.test/platform/charts
ok    cache          /tmp/clearance-cmp-cache is writable
ok    git            /usr/bin/git git version 2.49.1
ok    helm           /usr/local/bin/helm v4.2.1
ok    kustomize      /usr/local/bin/kustomize v5.8.1
warn  netns          unavailable: renders run WITHOUT a private network namespace (...)  fix: optional hardening: ...
ok    plugin-socket  /home/argocd/cmp-server/plugins exists (...)
ok    cmp-server     /var/run/argocd/argocd-cmp-server is present
doctor: 11 ok, 1 warn, 0 fail
```

## Every setting

Settings are environment variables of the **sidecar container**. They are set by whoever runs the platform: a plugin
parameter would not do, because parameters come from values a tenant writes.

| Name | Required? | Default | What it does |
|---|---|---|---|
| `CLEARANCE_URL` | **yes** | none | The core's http(s) URL, with no credentials, query or fragment. |
| `CLEARANCE_TOKEN_FILE` | no | `/var/run/secrets/tokens/clearance` | The projected token, read on **every** call, so a rotated token is used at once. |
| `CLEARANCE_CHART_REPOS` | **yes, in practice** | none | Repository URLs a chart may be fetched from, separated by commas or white space: `https://`, `http://`, `ssh://`, `git://`, `git@host:o/r`, or `oci://host/path` for a registry. No wildcard and no default: unset, **every chart is refused** (a comparison error names this variable). An entry that is not a repository URL stops the plugin at start. The Application's own source repository counts as listed once a list is set. |
| `CLEARANCE_WAIT_IMAGE` | when a change can be held | none | The image of the injected PreSync wait Job (`clearance-wait`). Unset, a held change is refused with a message naming it. |
| `CLEARANCE_WAIT_HOST_ALIAS` | no | none | `ip=host[,host]`: a `hostAlias` for the wait Job's pod, when the core's name does not resolve in the destination cluster. |
| `CLEARANCE_WAIT_TIMEOUT` | no | `24h` | How long the wait Job waits for a person (a Go duration). |
| `CLEARANCE_CMP_CACHE_DIR` | no | `/tmp/clearance-cmp-cache` | The root of all three caches: the cleared-tree files (`*.json`), `charts/` and `renders/`. Must be writable. See the sizing note below. |
| `CLEARANCE_CMP_CACHE_TTL` | no | `2m` | How long a cleared, unchanged render is answered from the cache before the core is asked again. Never served past the clearance's own expiry. |
| `CLEARANCE_CMP_RENDER_CACHE_TTL` | no | `15m` | How long a rendered, stamped stream is reused without cloning or running helm and kustomize (the pre-render cache, under `renders/`). Never past the clearance's own expiry, and a hold or denial is never stored. `0` (or `0s`) turns it off. Chart mode only: the generic `sources` mode is not cached. |
| `CLEARANCE_CMP_CHART_CACHE_MAX_BYTES` | no | `512Mi` (536870912) | Total size bound of the chart fetch cache (`charts/` under the cache dir). The entry used longest ago is evicted first. `0` turns the chart cache off. A single chart larger than the bound is used for that render and not kept. |
| `CLEARANCE_CMP_CHART_CACHE_MAX_ENTRIES` | no | `32` | Number of charts kept. `0` turns the chart cache off. |
| `CLEARANCE_CMP_CALL_TIMEOUT` | no | `20s` | How long one call to the core may take. The whole render has 80 s: Argo CD kills a plugin at 90 s (`ARGOCD_EXEC_TIMEOUT`). |
| `CLEARANCE_CMP_NETNS` | no | `try` | `try`: isolate renders in a private network namespace when the kernel allows it, else render without it and warn once. `require`: refuse to render without it. `off`: never attempt it. Anything else stops the plugin at start. The render summary on stderr ends `netns=on\|unavailable\|off`. |

**Sizing the cache.** The chart cache lives under `CLEARANCE_CMP_CACHE_DIR`, which by default is on the `/tmp` emptyDir, so
the volume must fit the bound. The default is 512 MiB of charts plus the pre-render cache (at most 256 streams of at most
8 MiB each) plus the work directory of a render in progress. An emptyDir without a `sizeLimit` is bounded by the node's
disk; with one, set it above `CLEARANCE_CMP_CHART_CACHE_MAX_BYTES` with room to spare, or lower the bound. A full or
read-only cache never fails a render (it clones for itself, as without the cache) but it stops giving hits, and an
emptyDir that goes over its `sizeLimit` evicts the pod. `doctor` warns when the volume's free space is below the byte
bound. The cache is lost whenever the pod restarts (an emptyDir); nothing depends on it.

Set by Argo CD for every render (not yours to set): `ARGOCD_APP_NAME` (the Helm release name),
`ARGOCD_APP_NAMESPACE` (the destination namespace), `ARGOCD_APP_REVISION` (the commit synced; must be a full commit
id), `ARGOCD_APP_SOURCE_REPO_URL`, `ARGOCD_APP_SOURCE_PATH`, `ARGOCD_APP_PROJECT_NAME`, `KUBE_VERSION` and
`KUBE_API_VERSIONS`.

**The Application's plugin parameters** (strings; Argo CD gives them to the plugin as `PARAM_<NAME>`):

| Parameter | Required? | What it is |
|---|---|---|
| `app`, `env`, `cluster` | **yes** | The change's identity, each a DNS-1123 label. They key the cache and the registration. |
| `chartRepo` | no | The chart's git repository. Empty: the chart is in the Application's source directory. Must be on `CLEARANCE_CHART_REPOS`. |
| `chartRevision` | with `chartRepo` | The chart's tag (a pinned tag, never a branch); the peeled commit is what is recorded. |
| `chartPath` | no | The chart's directory in that repository. |
| `valueFiles` | no | Comma-separated paths in the gitops repository, in order; a missing one is skipped. |
| `valuesJson` | no | Extra values as JSON, applied last (what an ApplicationSet injects). |
| `kustomizeDir` | no | A kustomize directory in the gitops repository, rendered beside the chart. |
| `clusterScopedKinds` | no | Comma-separated extra cluster-scoped kinds (`!Kind` marks a kind namespaced). |
| `sources` | no | Generic mode: the Application's original `spec.sources` as a JSON array, rendered as Argo CD would. Set it and none of the chart parameters above except `app`, `env`, `cluster` may be set. |
| `kustomizeBuildOptions` | no | Generic mode only; an allow list (`--reorder`, `--enable-managedby-label`, `--load-restrictor LoadRestrictionsRootOnly`). |

Every path must be relative and stay inside its repository (no `..`, no leading `/`).

## Gating one Application

An Application opts in with `spec.source.plugin.name: clearance`. There is no `discover`: nothing is picked up by file
name, and the plugin has no `version`, so the name is exactly `clearance`.

### By hand

The plugin's source is the gitops repository (it holds the value files); the chart is the plugin's to fetch.

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: shop-prod
  namespace: argocd
spec:
  project: shop                        # its sourceRepos list the gitops repository
  destination: {server: https://kubernetes.default.svc, namespace: shop-prod}
  source:
    repoURL: https://git.example.test/shop/gitops.git
    targetRevision: main
    path: .
    plugin:
      name: clearance
      parameters:
        - {name: app, string: shop}
        - {name: env, string: prod}
        - {name: cluster, string: cluster-a}
        - {name: chartRepo, string: "https://git.example.test/platform/charts.git"}   # on CLEARANCE_CHART_REPOS
        - {name: chartRevision, string: v1.4.2}
        - {name: chartPath, string: charts/app}
        - {name: valueFiles, string: "cluster-a/base.yaml,cluster-a/prod/values.yaml"}
```

The release name is the Application's name and the namespace is the destination, as under Argo CD's own Helm. The
plugin is the Application's **only** generating source: a plugin source is handed only its own repository, so a
`ref:` source means nothing to it, and an object from any other source carries no stamp and is refused at admission.

To render what an Application already uses (Helm from a repository or a path, kustomize, a directory, several
sources) instead of one chart, pass the original sources as one JSON string:

```yaml
    plugin:
      name: clearance
      parameters:
        - {name: app, string: shop}
        - {name: env, string: prod}
        - {name: cluster, string: cluster-a}
        - name: sources
          string: '[{"repoURL":"https://git.example.test/platform/charts.git","path":"charts/app","targetRevision":"v1.4.2","helm":{"valueFiles":["$vals/cluster-a/prod/values.yaml"]}},{"repoURL":"https://git.example.test/shop/gitops.git","targetRevision":"main","ref":"vals"}]'
```

Every repository named there must be on `CLEARANCE_CHART_REPOS` (or be the Application's own source). Run
`clearance-cmp parity` ([gate.md](gate.md#the-parity-suite)) on your Applications first; it says which ones render
identically to Argo CD's own repo-server.

### From an ApplicationSet

A plugin source replaces the Helm source, so a `templatePatch` swaps `spec.sources` for the gated environments only.
`templatePatch` renders as one document and is merged onto the generated Application; `sources` is replaced as a whole.
A generic pattern, where each generator element carries `appName`, `env`, `chartRepo` and so on, and an optional
`gate: true`:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata: {name: apps, namespace: argocd}
spec:
  goTemplate: true
  goTemplateOptions: ["missingkey=error"]
  generators:
    - git:
        repoURL: https://git.example.test/platform/tenants.git
        revision: main
        files: [{path: "tenants/*/*/identity.yaml"}]
  template:
    metadata: {name: "{{.appName}}-{{.env}}"}
    spec:
      project: "{{.appName}}"
      destination: {server: https://kubernetes.default.svc, namespace: "{{.appName}}-{{.env}}"}
      sources:                                   # what an ungated environment renders
        - repoURL: "{{.chartRepo}}"
          targetRevision: "{{.chartRevision}}"
          path: "{{.chartPath}}"
          helm: {valueFiles: ["$vals/{{.env}}/values.yaml"]}
        - {repoURL: "{{.gitopsRepoUrl}}", targetRevision: main, ref: vals}
  templatePatch: |
    {{- if and (hasKey . "gate") .gate }}
    spec:
      sources:
        - repoURL: "{{.gitopsRepoUrl}}"
          targetRevision: main
          path: .
          plugin:
            name: clearance
            parameters:
              - {name: app, string: "{{.appName}}"}
              - {name: env, string: "{{.env}}"}
              - {name: cluster, string: "cluster-a"}
              # Written by tenants, inside single quotes: a quote is doubled so it cannot end the string and add a parameter.
              - {name: chartRepo, string: '{{ .chartRepo | replace "'" "''" }}'}
              - {name: chartRevision, string: '{{ .chartRevision | replace "'" "''" }}'}
              - {name: chartPath, string: '{{ .chartPath | replace "'" "''" }}'}
              - {name: valueFiles, string: "{{.env}}/values.yaml"}
    {{- else }}
    {}
    {{- end }}
```

The `{}` on the else branch matters: it is the unambiguous no-op patch (a bare `spec:` parses to `spec: null`). Because the
chart parameters are built from values the tenant writes, `CLEARANCE_CHART_REPOS` (which no parameter can set) is what
stops a tenant naming an arbitrary repository.

## Turning it off again

Per Application: put back its original `source` or `sources` (the chart repository, path and value files it had before; for an
ApplicationSet, make that one environment stop matching the `templatePatch` condition, for example by setting the field
the condition reads to false in that environment's generator entry; deleting the `templatePatch` itself turns the plugin
off for every environment the ApplicationSet generates). Removing `plugin.name` alone does not do it: the source would
still point at the gitops repository with plugin parameters. The Application is then an ordinary Argo CD Application
again and the plugin is never called for it. **If the admission policy is enforcing, remove the Application's protection
first** ([gate.md](gate.md#annotation-opt-in-g-argo-10c-built)), or objects without a stamp are refused.

For the whole cluster: no Application may name `clearance`; then delete the `clearance-cmp` container, the `cmp-tmp` and
`clearance-token` volumes from the repo-server (reverse the values above) and let it roll. The core keeps its records;
a verifier entry for the repo-server's account can be removed from `CLEARANCE_VERIFIERS` afterwards. Removing the
sidecar while an Application still names `clearance` leaves it with a `ComparisonError` (Argo CD cannot find the
plugin), never an un-gated sync.

## Verifying it works

1. `clearance-cmp doctor` in the sidecar: no `fail`.
2. Gate one low-risk Application and hard-refresh it. In Argo CD it has a normal diff. The sidecar's log
   (`kubectl -n argocd logs deploy/argocd-repo-server -c clearance-cmp`) has one summary line per render:

   ```text
   clearance: shop/prod rendered 14 objects, tree 3f9a1c0b27de, chart https://git.example.test/platform/charts.git@v1.4.2 (c7e846a91b0d), chart-cache=miss, netns=unavailable
   ```

   `chart-cache=` is `hit` (the chart came from the cache), `miss` (fetched, and kept) or `off`. `netns=` is `on`
   (renders are isolated), `unavailable` (`try` fell back: the kernel or seccomp profile refused) or `off`. An unchanged
   Application inside the pre-render cache's lifetime instead logs `... is unchanged ...: serving the cleared render <id>
   from the cache without a clone, helm or kustomize`; that is the cache working, not a skipped gate (the core is still
   asked once the tree cache's `CLEARANCE_CMP_CACHE_TTL` has passed).
3. The rendered objects carry `clearance.hangar.io/rendered`, `clearance.hangar.io/tree` and, once cleared,
   `clearance.hangar.io/grant` annotations: `argocd app manifests shop-prod | grep clearance.hangar.io`.
4. On the core, the change is registered (`proposer: system:argocd-cmp`, `pr: 0`). A tree nobody cleared **holds** for people:
   the sync waits at `PreSync: clearance awaiting approval`; clear it and the next render carries the grant.
5. Point a test Application's `chartRepo` at a repository that is **not** on `CLEARANCE_CHART_REPOS` and is not the Application's own source repository (that one counts as listed once a list is set): it must show a
   `ComparisonError` naming `CLEARANCE_CHART_REPOS`. That is the allow list refusing, working. (A tag that does not exist
   in a listed repository is a different failure, `fetch the chart at <tag>`, and does not test the allow list.)

## Troubleshooting

Argo CD shows the plugin's stderr as the Application's `ComparisonError` (`CMP processing failed ... clearance-cmp: <message>`).
These are the messages in the code, with their fixes. A configuration error exits 2, a refusal or a failed render exits 1.

| ComparisonError says | Meaning | Fix |
|---|---|---|
| `refused: CLEARANCE_CHART_REPOS is not set on the plugin sidecar, so no chart repository may be fetched (<repo>)` | The allow list is empty. | Set `CLEARANCE_CHART_REPOS` on the sidecar (every chart is refused without it, including the Application's own repository). |
| `refused: the chart repository <repo> is not one of the repositories this cluster's platform allows (CLEARANCE_CHART_REPOS)` | The repository the Application names is not listed (after normalising scheme, host, user, `.git`, trailing `/`). | Add it to the list, or fix the Application's `chartRepo`. `doctor` prints each entry's normalised form. |
| `refused: the chart repository "<repo>" ... is not a repository URL` / `the scheme "x" is not allowed` / `has no repository path` / `has an empty, "." or ".." path segment` | The `chartRepo` is not a remote repository URL (a local path, `file://`, `ext::`, an option, a query). | Use an `https`, `http`, `ssh`, `git` or scp-style URL. |
| `refused: the chart repository <repo> is listed as an OCI registry but is not one` | An `oci://` entry matched a git `chartRepo`. | The chart-parameter mode fetches git only; use generic mode (`sources`) for an OCI chart. |
| `CLEARANCE_CHART_REPOS entry "<x>" is not a repository URL` | A bad list entry; the plugin refuses to start. | Fix the entry (`doctor` names it). |
| `CLEARANCE_URL is required` / `CLEARANCE_URL "<x>" is not an http(s) URL` | The sidecar's core URL is missing or wrong. | Set it (`doctor`). |
| `CLEARANCE_CMP_NETNS is one of "try", "require" or "off", got "<x>"`; `CLEARANCE_CMP_CACHE_TTL is a positive duration, got "<x>"` (and `CLEARANCE_WAIT_TIMEOUT`, `CLEARANCE_CMP_CALL_TIMEOUT`) | A malformed setting. | Fix it. |
| `CLEARANCE_WAIT_HOST_ALIAS "<x>" is ip=host[,host]` / `CLEARANCE_WAIT_IMAGE "<x>" is not an image reference` | A malformed setting. | Fix it. |
| `PARAM_APP is required` (and `PARAM_ENV`, `PARAM_CLUSTER`, `ARGOCD_APP_NAME`, `ARGOCD_APP_NAMESPACE`) | The Application passes no such plugin parameter, or has no destination namespace. | Add `app`, `env`, `cluster` to `plugin.parameters`; give the Application a destination namespace. |
| `PARAM_APP "<x>" is not a DNS-1123 label` | Upper case, underscore or over 63 characters. | Use a lower-case label. |
| `PARAM_CHARTREVISION is required with PARAM_CHARTREPO` / `PARAM_CHARTREVISION "<x>" is not a tag name` / `PARAM_CHARTREPO must not start with '-'` | A chart is fetched at a pinned tag. | Set `chartRevision` to a tag. |
| `path "<x>" must be relative and stay inside its repository` | A `..` or absolute path in `chartPath`, `valueFiles` or `kustomizeDir`. | Use a relative path with no `..`. |
| `PARAM_<X> is set with PARAM_SOURCES: the plugin renders either the Airframe chart parameters or the Application's original sources, not both` | Both modes were given. | Remove the chart parameters, or `sources`. |
| `fetch the chart at <tag>: git clone: ...` | The tag does not exist, the repository is private (the sidecar has **no** git credential), or the pod cannot reach the host. | Check the tag; make the chart repository readable without a credential; check egress. |
| `refused: value file <path> resolves outside the repository` / `refused: the chart: ...` / `refused: kustomize <dir>: ...` | A symlink leaves its repository. | Replace the link with a real file. |
| `helm template: ...: <helm's message>` / `kustomize build: ...` | The chart or kustomization does not render. A dependency that is not under `charts/`, or a remote kustomize base, fails because renders run with the network off. | Fix the chart; vendor dependencies under `charts/`; keep kustomize bases in the repository. |
| `unsupported by the Clearance plugin (source N): <feature>` | Generic mode refuses a source feature it cannot guarantee to match Argo CD (see [gate.md](gate.md#what-fails-closed)). | Change the source, or leave that Application ungated. |
| `the render holds no objects: nothing to clear` / `the render holds N objects, more than the gate's 2000` / `two objects of one identity once the destination namespace is set` | The tree cannot be hashed. | Fix the render. |
| `<kind> "<name>" reads differently as YAML 1.1 (the hash) and YAML 1.2 (Argo CD) ...: refusing to stamp it` | A scalar such as `yes`, `1:30` or a bare `=` is ambiguous. | Quote it. |
| `ARGOCD_APP_REVISION "<x>" is not a commit: the plugin registers the commit Argo CD syncs` | Argo CD gave the plugin something other than a full 40-character commit id. | Refresh the Application; the plugin registers the commit Argo CD syncs, so it needs the resolved id. |
| `clearance refused the change: clearance core refused registerChange: HTTP 401` | The core rejected the token. | Check the projected token's audience (`clearance` = the core's `CLEARANCE_AUDIENCE`) and that the core can authenticate this cluster's accounts; `doctor` `core-auth`. |
| `clearance refused the change: clearance core refused registerChange: HTTP 403: ...` | The repo-server's account is not a verifier (or a verifier named `app-<app>-cicd/<sa>` registering for another app, `DG-VERIFIER-APP`). | Add `<namespace>/<serviceaccount>` to the core's `verifiers`. |
| `clearance outage hold: the core is unreachable and tree <t> has no cleared, allow-and-record entry` | The core did not answer and nothing cleared is remembered for this tree. | Restore the core and the path to it; `doctor` `core`. A cleared tree whose tier allows it is served from the cache for a while. |
| `change <id> is denied (tier N): <reason>; nothing syncs` (`expired`, `superseded`, `exception`, `degraded`) | The core's decision. | Not a fault: a person or a policy refused it; see the change on the core. |
| `a change is held for people but CLEARANCE_WAIT_IMAGE is not set: the PreSync wait Job cannot be injected` | A tree is waiting for a person and the sidecar cannot add the wait Job. | Set `CLEARANCE_WAIT_IMAGE`. |
| `refusing to run helm: cannot create a private network namespace (...). CLEARANCE_CMP_NETNS=require needs ...` | `require` is set and the kernel or seccomp profile refuses the namespace. | Allow `unshare`/`clone` with `CLONE_NEWUSER\|CLONE_NEWNET` in the container's seccomp profile, or set `CLEARANCE_CMP_NETNS=try`. |
| `context deadline exceeded` after about 80 s | A slow fetch plus a slow core call. | Check egress to the chart repository and the core; see `CLEARANCE_CMP_CALL_TIMEOUT`. |
| `could not find cmp-server plugin with name "clearance" supporting the given repository` (Argo CD's own message, `util/app/discovery/discovery.go` in v3.5.0; a `: <cause>` may follow, and the name is whatever `plugin.name` says) | The repo-server found no socket `<name>.sock` in `plugins`: the sidecar is not running or crashed, `plugins` is not mounted at `/home/argocd/cmp-server/plugins` in both containers, or the Application names another name (a plugin with a `version` is `<name>-<version>`). | `kubectl -n argocd get pod -l app.kubernetes.io/name=argocd-repo-server` should show all containers ready; check `var-files` and `plugins` are mounted at the two paths above and `plugin.name: clearance`. |

## Upgrade and rollback

Read [CHANGELOG.md](../CHANGELOG.md) from your running version to the new one, and every **"Upgrading from ..."**
bullet in it, before you roll out. Examples from 0.50 onward: 0.52.0 made `CLEARANCE_CHART_REPOS` required, refused helm
network dependencies and kustomize remote bases, and refused symlinks that leave the source; 0.52.1 fixed value files
being refused (skip 0.52.0); 0.52.2 refused kustomize build options outside an allow list; the release after it adds
`CLEARANCE_CMP_NETNS` and the `doctor` command. A release that adds a setting names it in its upgrade note.

The order is **settings before image**:

1. Run the new image's `doctor` with the settings you intend to use. The easiest way is a canary sidecar of the new image
   (below), which has the token and volumes already, then `kubectl exec` into it. A separate one-off pod must be given
   what the sidecar has: the **repo-server's own service account** (not another account: `core-auth` proves only that the
   core accepts the token, not that the account is in `CLEARANCE_VERIFIERS`, so a different account can pass the preflight
   while the real sidecar is then refused when it registers a change), the projected `clearance` token mounted at
   `CLEARANCE_TOKEN_FILE`, a writable `/tmp`, user 999 and the same environment. Fix every `fail`.
2. Change the sidecar's **environment** first when the notes say a setting is required: the old image ignores a setting it
   does not know, so settings added ahead of the image are harmless.
3. Then pin the new image (by digest), and let the repo-server roll.
4. **Hard-refresh every gated Application once the new sidecar is ready.** Argo CD's manifest cache is keyed by the
   source and its parameters, not by the sidecar's image, so an Application keeps the previous image's render until the
   cache expires or it is refreshed ([gate.md](gate.md#rolling-out-a-plugin-release)).
5. To try a release on one Application before the rest, run it as a second sidecar under the canary plugin name
   ([gate.md](gate.md#rolling-out-a-plugin-release)): the image ships `config-canary/plugin.yaml` for it.

**Rollback** is the reverse: re-pin the previous image digest, wait for the repo-server, hard-refresh the Applications.
The plugin keeps no database and a schema is not involved; the core is not changed by a sidecar rollback. A setting the
old image does not know is ignored. If you rolled the **settings** forward (a new required one), keeping them is harmless.

## What the plugin does not do

From [gate.md](gate.md#the-argo-cd-plugin-and-the-presync-wait-g-argo-4-and-g-argo-5-built) and "Rendering any source":

- **It is not a control by itself.** It renders, hashes, registers and stamps. Refusal of an unstamped or ungranted object
  is the admission policy's; the PreSync wait is not a control (`argocd app sync --strategy apply` skips hooks).
- **No private chart repository and no credentials.** The sidecar holds no git or registry credential
  (`helm.passCredentials` is accepted and ignored). A private chart repository, or a registry that needs
  `helm registry login`, is not supported: the fetch fails and the error says so.
- **OCI charts** are rendered only in generic mode (`sources`), listed as `oci://host/path`. The chart-parameter mode
  fetches a git repository.
- **No network after the fetch.** Helm network dependencies and kustomize remote bases are refused: vendor them under
  `charts/` (generic mode alone also accepts a `file://` dependency inside the source).
- **No version ranges.** A chart version or git revision must be exact (no `1.*`, `^1.2`, `tagPrefix`).
- Not built: `.argocd-source.yaml`, kustomize `patches`, jsonnet, git submodules, a `plugin:` source (another plugin),
  Applications with no destination namespace, and a remote value-file URL.
- **A chart that is not deterministic** (a clock or random value in its output) renders a new tree on every refresh and so
  holds every time; a chart that renders `annotations:` with no value (`null`) cannot be enforced reliably yet.
- **Argo CD's manifest cache does not see the sidecar image or the original chart repository.** Hard-refresh after an upgrade
  (above), and expect a change in a chart repository's branch to wait for a refresh.
- Loopback in the pod is closed to renders only where the kernel allows the namespace; `git` and `helm pull` stay outside
  it, and the plugin's own fetch is as wide as the repository you listed. See [gate.md](gate.md#parameters-and-settings).
