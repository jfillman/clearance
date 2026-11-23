# Installing the Argo CD plugin (`clearance-cmp`)

The deployment gate's Argo CD half is a [Config Management Plugin](https://argo-cd.readthedocs.io/en/stable/operator-manual/config-management-plugins/)
that runs as a **sidecar of the `argocd-repo-server` pod**. For an Application that names it, the plugin renders the
manifests, hashes the tree, asks the Clearance core whether that tree is cleared, and stamps the objects it emits (or
holds the sync for people, or refuses). This page installs it on any Argo CD: the official `argo-cd` Helm chart or
plain manifests. Nothing here depends on a particular platform.

What the plugin is and how it decides is in [gate.md](gate.md#the-argo-cd-plugin-and-the-presync-wait-g-argo-4-and-g-argo-5-built);
this page is the install, the settings, the checks and the failure modes.

**What it gives you, and the guardrails on it.**

- **Every failure says what kind it is.** The first line of a `ComparisonError` is one short line starting with a stable
  code: `CMP-FAULT-*` (the plugin failed), `CMP-DEP-*` (git or the chart host is unavailable), `CMP-RENDER-*` (the
  Application's inputs do not render) or `CMP-REFUSED-*` (Clearance said no). A refusal of a change links to it on the
  next line (`hold: <url>`). The codes never change meaning: alert and search on them ([Error codes](#error-codes)).
- **Last-known-good, off by default** (`CLEARANCE_CMP_LAST_KNOWN_GOOD=on`). A plugin fault or an unreachable chart host,
  for an Application whose gitops revision, chart and parameters are exactly those of a render already cleared, serves
  that render again instead of turning the app Unknown. It never answers a render error or a refusal, never a new
  revision, a moved tag or a changed parameter, and never without the core confirming the same change (or the outage
  policy allowing it). Every serve is logged and counted ([Last-known-good](#last-known-good-optional-off-by-default)).
- **No setting is required without a safe default or a preflight that names it.** A test pins the three settings
  with no default (`CLEARANCE_URL`, `CLEARANCE_CHART_REPOS`, `CLEARANCE_WAIT_IMAGE`); `doctor` names each one unset.
  An upgrade that would add a fourth fails CI ([Every setting](#every-setting)).
- **Metrics and alerts, off by default** (`CLEARANCE_CMP_METRICS_DIR`, `CLEARANCE_CMP_METRICS_ADDR`). Every run counted
  by outcome, by error class and stable code, by duration and by the result of its calls to the core, served as
  Prometheus text by a small container beside the sidecar. Labels are a closed set (the plugin's version, the class, the
  code): no token, URL, Application or message is ever recorded. An example PrometheusRule alerts on the plugin's fault
  rate, its render error rate, an unreachable core and the p95 latency, and the same series gate a canary release
  ([Metrics and alerts](#metrics-and-alerts-optional-off-by-default)).

**The plugin alone does not stop a sync.** It renders, stamps and registers; a refusal shows as a `ComparisonError`
and a held change as a PreSync wait, but `argocd app sync --strategy apply` skips hooks and a cleared render can be
followed by a push. What refuses an object that no cleared grant lists is the admission policy and the Argo CD agent
([gate.md](gate.md#g-argo-2-the-grant-and-the-admission-policy-built)). Install the plugin first, watch it, then
turn enforcement on.

**What guards a render.** The chart and the kustomization are tenant input, so every `git`, `helm` and `kustomize` the
plugin runs is fenced in:

- **The token is out of a render step's reach.** Each step runs under Landlock, which lets it read only the system
  directories, its source and its own scratch directory: the mounted clearance token (and anything else under `/var` or
  `/run`) answers "permission denied". This needs no capability and no node change, only a kernel with Landlock (Linux
  5.13+ with Landlock active) and a seccomp profile that allows its three calls (`RuntimeDefault` does).
  Where the kernel has none the default renders without it and warns; `CLEARANCE_CMP_FS_SANDBOX=require` refuses instead.
- **Every render is bounded**: wall time, and per step CPU, memory and output, the render's scratch space, and how many
  renders run at once in the sidecar. Each has a default sized from measured renders; going over one stops that render
  with an error that names the bound and the setting to raise. [Render limits](#render-limits-and-the-filesystem-sandbox).
- **Render steps are kept off the network**: `helm template`, `helm dependency build` and `kustomize` get proxy settings
  that go nowhere and refuse every git transport, and a private network namespace as well where the kernel allows it
  (`CLEARANCE_CMP_NETNS`; with the default `try` and no namespace they can still reach the pod's loopback). The plugin's
  own fetches (`git`, `helm pull`) run outside the namespace and reach only the allow-listed chart repositories
  (below). No step gets a credential in its environment or reads a symlink out of its repository.

## Outline

1. [Prerequisites](#prerequisites)
2. [The sidecar](#the-sidecar): Helm chart values, or a patch of the plain manifests
3. [Run `doctor` first](#run-doctor-first)
4. [Every setting](#every-setting), [last-known-good](#last-known-good-optional-off-by-default), and
   [metrics and alerts](#metrics-and-alerts-optional-off-by-default)
5. [Gating one Application](#gating-one-application), by hand or from an ApplicationSet
6. [Turning it off again](#turning-it-off-again)
7. [Verifying it works](#verifying-it-works)
8. [Troubleshooting](#troubleshooting), by [error code](#error-codes) and by message
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
| **A kernel with Landlock (recommended)** | For the filesystem sandbox that keeps the clearance token out of a render step's reach: Linux 5.13 or later with `landlock` among the active LSMs (`cat /sys/kernel/security/lsm` on the node, or `doctor`'s `fs-sandbox` line; Ubuntu's and Fedora's stock kernels enable it, check other node images), and a container seccomp profile that allows `landlock_create_ruleset`, `landlock_add_rule` and `landlock_restrict_self` (containerd's and Docker's `RuntimeDefault` do). Nothing to install. Without it renders still work, unprotected, and `doctor` warns. |
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
| `fs-sandbox` | the filesystem sandbox of the render steps (Landlock): `on`, `off` (set so) or `unavailable` | `unavailable` while `CLEARANCE_CMP_FS_SANDBOX=require`; otherwise `unavailable` warns |
| `metrics` | off when `CLEARANCE_CMP_METRICS_DIR` is unset; otherwise the directory takes a probe file (removed) and a store already there reads. `CLEARANCE_CMP_METRICS_ADDR`, when set, is `host:port` | the directory is not writable; `CLEARANCE_CMP_METRICS_ADDR` is malformed or set without the directory. (warns) the store does not read (the next run starts it again) |
| `render-limits` | the render limits in force; whether `CLEARANCE_CMP_MAX_RENDERS` x `CLEARANCE_CMP_RENDER_MAX_MEMORY` fits the container's memory limit (cgroup `memory.max`) | (warns) it does not fit; a malformed limit fails `setting` |
| `plugin-socket`, `cmp-server` | `/home/argocd/cmp-server/plugins` exists (`--plugin-dir` changes it) and `/var/run/argocd/argocd-cmp-server` is present | (warns) either is missing, which is normal outside the sidecar |

`doctor` writes nothing except the probe files of the cache directory (and of the metrics directory, when set), registers no change, and prints no token.

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
ok    fs-sandbox     on: render steps can read only the system directories, their source and their own scratch; the token is out of their reach (Landlock, mode try)
ok    render-limits  wall 30s per render (slot wait included), per step CPU 30s, memory 512Mi, stdout 32Mi; scratch 512Mi per render; 4 renders at once; fits the container's memory limit of 2.0 GiB
ok    metrics        off: CLEARANCE_CMP_METRICS_DIR is not set, runs record nothing (and nothing listens)
ok    plugin-socket  /home/argocd/cmp-server/plugins exists (...)
ok    cmp-server     /var/run/argocd/argocd-cmp-server is present
doctor: 14 ok, 1 warn, 0 fail
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
| `CLEARANCE_CMP_CALL_TIMEOUT` | no | `20s` | How long one call to the core may take. A failure that is safe to repeat is retried once, after a jittered wait (125 to 250 ms). Both attempts must fit inside the plugin's time with the render (see `CLEARANCE_CMP_RENDER_TIMEOUT`), so an unreachable core is reported as an outage, and the outage policy's cache applies, not as a deadline. The whole `generate` has 80 s: Argo CD kills a plugin at 90 s (`ARGOCD_EXEC_TIMEOUT`). |
| `CLEARANCE_CMP_FS_SANDBOX` | no | `try` | The filesystem sandbox of the render steps (Landlock). `try`: use it when the kernel has it, else render without it and warn once. `require`: refuse to render without it. `off`: never. Anything else stops the plugin at start. The summary line ends `fs-sandbox=on\|unavailable\|off`. With it on, a `CLEARANCE_TOKEN_FILE` under `/usr`, `/bin`, `/sbin`, `/lib*`, `/etc`, `/proc`, `/sys`, `/dev` or `HOME` stops the plugin at start (those are readable by every step). |
| `CLEARANCE_CMP_RENDER_TIMEOUT` | no | `30s` | Wall time of the whole render phase: waiting for a slot, fetching the chart, helm, kustomize. The chart tag lookup before it has 5 s of its own (an optimisation: no answer in time means the render fetches). The lookup, this, 2 s for the plugin's own work after the render (hashing, the caches, the request), and two attempts of `CLEARANCE_CMP_CALL_TIMEOUT` with the wait between them must stay under 80 s, or the plugin stops at start: with the default 20 s call timeout, at most `32s`. The render's deadline keeps that time free; a render that would start with less left (after a slow pre-render confirmation) is not started and fails as `CMP-FAULT-TIMEOUT`. The 2 s is a margin, not a bound: whatever the work before it took, a call to the core still unanswered 250 ms before the run ends is treated as an outage, so the outage policy decides, never the run's deadline. |
| `CLEARANCE_CMP_RENDER_MAX_CPU` | no | `30s` | CPU time of one step (`RLIMIT_CPU`). At least `1s`. |
| `CLEARANCE_CMP_RENDER_MAX_MEMORY` | no | `512Mi` | Memory of one step: its data segment (`RLIMIT_DATA`), and `GOMEMLIMIT` at three quarters of it for helm and kustomize. At least `128Mi` (helm's Go runtime needs about 96 MiB to start). Bytes, or with `Ki`, `Mi`, `Gi`. |
| `CLEARANCE_CMP_RENDER_MAX_OUTPUT` | no | `32Mi` | Bytes one step may write to stdout, and the size of the rendered manifests. At least `1Mi`. |
| `CLEARANCE_CMP_RENDER_MAX_TEMP` | no | `512Mi` | The render's scratch directory (the chart checkout, generic sources, helm's work). During a step the kernel bounds each file at this size (`RLIMIT_FSIZE`); the directory's total is measured after every step, so a step writing many files can fill the volume before that check stops the render: size the `/tmp` volume for it. At least `16Mi`. |
| `CLEARANCE_CMP_MAX_RENDERS` | no | `4` | Renders at once in this sidecar (1 to 64). Others wait for a slot, inside their wall time. A render answered by the pre-render cache takes no slot. The slots are lock files under `CLEARANCE_CMP_CACHE_DIR/slots`; if that cannot be written the bound is lost with a warning and the render goes on. |
| `CLEARANCE_CA_FILE` | no | none | A PEM file of extra root certificates (besides the system roots) for an `https` `CLEARANCE_URL` signed by a private CA. A missing or empty file stops the plugin at start. See [tls.md](tls.md#client-side). |
| `CLEARANCE_WAIT_CA_CONFIGMAP` | no | none | A ConfigMap (key `ca.crt`) in each destination namespace that the wait Job mounts at `/etc/clearance-ca/ca.crt` as its CA. Unset, the Job trusts the system roots only. |
| `CLEARANCE_CMP_LAST_KNOWN_GOOD` | no | `off` | `on` turns on the [last-known-good](#last-known-good-optional-off-by-default) fallback for a plugin fault or an unreachable chart host. Exactly `off` or `on`; anything else stops the plugin at start. |
| `CLEARANCE_CMP_LINK_BASE` | no | none | The web UI's base URL: a refusal links `<base>/changes/<id>`. Unset, it links the core's record, `CLEARANCE_URL/v1/clearances/<id>`. An http(s) URL with no credentials, query or fragment. |
| `CLEARANCE_CMP_METRICS_DIR` | no | none | The directory each run adds its counts to (`cmp-metrics.json`, under a lock). Unset, nothing is recorded. Set it on the plugin sidecar (and the canary sidecar) and on the metrics container, all mounting one emptyDir. See [Metrics and alerts](#metrics-and-alerts-optional-off-by-default). |
| `CLEARANCE_CMP_METRICS_ADDR` | no | none | `host:port` that `clearance-cmp metrics` listens on (`/metrics`, `/healthz`). Read by the metrics container only. Unset, the command refuses to start: nothing listens. |
| `CLEARANCE_CMP_NETNS` | no | `try` | `try`: isolate renders in a private network namespace when the kernel allows it, else render without it and warn once. `require`: refuse to render without it. `off`: never attempt it. Anything else stops the plugin at start. The render summary on stderr ends `netns=on\|unavailable\|off`. |

**Sizing the cache.** The chart cache lives under `CLEARANCE_CMP_CACHE_DIR`, which by default is on the `/tmp` emptyDir, so
the volume must fit the bound. The default is 512 MiB of charts plus the pre-render cache (at most 256 streams of at most
8 MiB each) plus the work directory of a render in progress. An emptyDir without a `sizeLimit` is bounded by the node's
disk; with one, set it above `CLEARANCE_CMP_CHART_CACHE_MAX_BYTES` with room to spare, or lower the bound. A full or
read-only cache never fails a render (it clones for itself, as without the cache) but it stops giving hits, and an
emptyDir that goes over its `sizeLimit` evicts the pod. `doctor` warns when the volume's free space is below the byte
bound. The cache is lost whenever the pod restarts (an emptyDir); nothing depends on it.

**The rule for settings (F8).** No setting is required without a safe default, or a preflight refusal that names it:
0.52.0 added `CLEARANCE_CHART_REPOS` with neither, and every chart behind a sidecar upgraded without it was refused.
`providers/argocd/cmp/settings.go` lists every setting with what it does unset, and `settings_test.go` enforces it:
every `CLEARANCE_*` name the plugin reads is listed and has a row above; a setting with a default parses exactly the
same set to that default as unset (so this table cannot drift from the code); `doctor` names each setting with no
default when it is unset; and the settings with no default are pinned to `CLEARANCE_URL`, `CLEARANCE_CHART_REPOS` and
`CLEARANCE_WAIT_IMAGE`. The audit for this rule found two settings missing from this table (`CLEARANCE_CA_FILE`,
`CLEARANCE_WAIT_CA_CONFIGMAP`, both optional); they are above now.

### Last-known-good (optional, off by default)

`CLEARANCE_CMP_LAST_KNOWN_GOOD=on`. Without it, any failure of the plugin turns every Application it renders from
Synced to Unknown with a `ComparisonError`, even when nothing about the app changed. With it:

| The run | What happens |
|---|---|
| A **plugin fault** (`CMP-FAULT-*`: a panic, a tool that cannot start or is killed, its own I/O, the render's deadline, the sandbox under `require`) or an **unavailable dependency** (`CMP-DEP-*`: git or the chart host cannot be reached, or the clone fails after the tag resolved), before the decision | looks up the render last **cleared** for exactly these inputs |
| an entry exists, and the tree cache says cleared for the same change within `CLEARANCE_CMP_CACHE_TTL` | serves it, no core call |
| an entry exists, and the core answers the stored registration `cleared` as the **same** change | serves it |
| the core is unreachable | the outage policy: served only for an `allow-and-record` tier, otherwise `CMP-REFUSED-OUTAGE-HOLD` |
| the core says anything else (another change, held, denied) | drops the entry; the fault stands |
| a **render error** (`CMP-RENDER-*`) or a **refusal** (`CMP-REFUSED-*`) | never falls back |
| no entry for these exact inputs | the fault stands (fail closed) |

"These inputs" is everything the output depends on: the Application, the gitops revision (`ARGOCD_APP_REVISION`, a full
commit), the commit the chart's tag resolves to on this run (looked up on the remote, never the tag's name), every
plugin parameter, the destination's Kubernetes and API versions, and the core's URL. Not the plugin's own version: a
plugin upgrade that breaks rendering still serves what the previous one rendered and was cleared, which is the case
this is for. A new revision, a moved tag, a changed parameter, a tag the remote says it does not have, generic mode
(`sources`), or a revision that is not a commit has no entry. When the chart's host **cannot be reached at all**, the
commit is the one this tag last resolved to when these exact inputs were cleared: what is running now, so a tag moved
during the outage is seen when the host is back, not before. A hold or denial of the tree drops its entries.

Every serve prints `clearance: LAST-KNOWN-GOOD served: <app>/<env> hit <code> (...)` on stderr with the fault's code,
the revision, chart commit, change and a running count `lkg-serves=N`, kept in `lkg/served` under the cache directory;
`doctor` reports the count and warns when it is above zero. Every miss prints why (`last-known-good not served ...;
failing closed`). The render's deadline is always the run's less the core call's whole budget (both attempts of
`CLEARANCE_CMP_CALL_TIMEOUT` and the wait between them), and the tag lookup is bounded at 5 s, so a slow fault still
leaves time to confirm.

The store is `lkg/` under `CLEARANCE_CMP_CACHE_DIR`, separate from the pre-render cache and its bounds: at most 1024
entries and 256 MiB, the entry used longest ago going first, and no lifetime of its own (the core's confirmation is the
lifetime). A cleared full render rewrites its entry and a pre-render hit marks it used. **It is on the cache volume:**
on the default `/tmp` emptyDir it is empty after the pod restarts, so it covers faults within a pod's life (a tool
crash, a full disk, a flaky chart host) but not the first renders after an upgrade restarts the pod. To cover an
upgrade, put `CLEARANCE_CMP_CACHE_DIR` on a volume that outlives the pod, writable only by the sidecar.

**Why off by default.** It changes what a failure looks like: an Application stays Synced on bytes the running plugin did
not produce, so a broken plugin is visible only in the log line, the counter and `doctor`. Turn it on where Unknown apps
cost more than that, and alert on `LAST-KNOWN-GOOD served`.

### Render limits and the filesystem sandbox

Every `git`, `helm` and `kustomize` the plugin runs is started through the plugin binary's own shim, which sets the
step's limits and its Landlock rules and then execs the tool, so both are in force from the tool's first instruction and
are inherited by anything it starts. The plugin's own bounds (the wall time, stdout, the scratch directory, the slots)
hold everywhere; the kernel's (CPU, memory, file size, Landlock) on Linux, which is where the sidecar runs.

**The defaults and why.** Measured on the parity fixture (`providers/argocd/cmp/testdata/parity-gate-api`, a real
Application's render: 5.7 KB of manifests from the Airframe application chart) with the image's helm v4.2.1 and kustomize
v5.8.1:

| Bound | Default | Measured | Why this default |
|---|---|---|---|
| Wall time, whole render | 30 s | helm 0.06 s; a chart clone a few seconds | 500x the render. With the 5 s chart lookup, 2 s for the plugin's own work after the render, and both 20 s attempts of the core call (77.25 s) it fits the plugin's 80 s, under Argo CD's 90 s, so a core that does not answer is an outage, not a deadline. The existing 80 s deadline is unchanged. |
| CPU, per step | 30 s | helm 0.05 s | Only a runaway template or a tight loop reaches it; wall time alone would let a multi-threaded step burn many cores' worth. |
| Memory, per step | 512 MiB | helm 45 MB peak RSS, but needs about 96 MiB of data segment to start; kustomize about 48 MiB | 5x helm's floor. It bounds one step; with several steps at once the container's own limit can be reached first, and then the kernel's OOM killer acts instead of this bound (see below). |
| Stdout per step, and the manifests | 32 MiB | 5.7 KB | Over 5000x the fixture; 4x the pre-render cache's 8 MiB stream cap. |
| Scratch per render | 512 MiB | a shallow checkout of the chart repository, about 50 MB | 10x the checkout; the same order as the chart cache's own 512 MiB bound. Measured after each step, and per file during it (above). |
| Renders at once | 4 | | Above the `reposerver.parallelism.limit` many installs set (2), so it never queues them; on an unlimited repo-server it stops a refresh storm from running every render at once. |

`doctor`'s `render-limits` line prints the bounds in force and warns when `CLEARANCE_CMP_MAX_RENDERS` times
`CLEARANCE_CMP_RENDER_MAX_MEMORY` is above the container's memory limit (with 4 x 512 MiB against a 512Mi limit it does). The data
segment counts address space the Go runtime reserves, well above what a step uses (96 MiB against 45 MB resident for the
fixture), so this is a worst case: raise the container's limit, lower one of the two, or accept that a pathological step
may meet the kernel's OOM killer (a `signal: killed` error) rather than the plugin's bound.

**A render that goes over** stops with one of the [error codes](#error-codes), naming the bound and the setting, for example:

```text
CMP-RENDER-LIMIT-MEMORY: helm template went over its memory bound (CLEARANCE_CMP_RENDER_MAX_MEMORY=512Mi)
detail: render limit exceeded: helm template ran out of memory (bound CLEARANCE_CMP_RENDER_MAX_MEMORY=512Mi); the render was stopped; nothing it rendered syncs. ...
```

The CPU, memory, output and scratch bounds are render errors (`CMP-RENDER-LIMIT-*`): the same inputs reach them again,
so last-known-good never answers them. The wall time (`CMP-FAULT-TIMEOUT`) and a render that waited its whole wall time
for a slot (`CMP-FAULT-BUSY`) are faults: a slow network or a busy sidecar can cause them.

**What the filesystem sandbox is, and is not.** With `fs-sandbox=on` the isolation is enforced by the kernel: a step
cannot open the token file or anything else outside the directories listed under `CLEARANCE_CMP_FS_SANDBOX`, cannot
read the plugin's memory or environment, and cannot lift the rules (no capability, `no_new_privs`). The step and everything it starts are one process group, killed when the step returns or is stopped; the plugin is also a child subreaper (`PR_SET_CHILD_SUBREAPER`, unprivileged), so a descendant that detaches into a session of its own (`setsid`), whatever it does to its environment, is re-parented to the plugin. The plugin runs its steps one at a time and, after each, kills and reaps every child it has (a chain of them, each in its own session, is followed to its end; the sweep succeeds only when no child is left at all, and a leftover that cannot be stopped within 5 s fails the step; if the kernel refuses to make the plugin a subreaper, or `/proc` cannot be read, the plugin refuses to start, `CMP-FAULT-SANDBOX`): at that moment each one is a leftover of the step that just ended, because the plugin starts processes only through its steps. (The `parity` tool, which runs steps beside its own `argocd` commands on an operator's machine, does not sweep, so there a descendant that detaches is not followed.) Whether a step is retried without the sandbox (in `try`, when the kernel refuses the rules) is decided only by a setup channel the shim closes before the tool runs, never by what the tool prints or how it exits. On a kernel whose Landlock ABI is below 3 (before Linux 6.2) a step can still truncate a file its user may write outside its scratch, such as one in the source directory (reads are refused all the same); `doctor` warns with the ABI. `doctor` reports `on` only after a probe has installed a ruleset in a child process (the plugin binary itself, so nothing else need be on `PATH`), so a seccomp profile that allows creating rules but not applying them shows as `unavailable`. The tests show a fake
step, the real `kustomize` and the real `helm` (through a symlinked template) each reading the token without the sandbox and
failing to with it, and CI's image smoke test shows the same in the built image under Docker's default seccomp profile. It
does not hide what every step may read (the system directories, `HOME`, the source directory: nothing secret is kept
there), and it does not restrict network access (the network namespace, `CLEARANCE_CMP_NETNS`, does that). With
`fs-sandbox=unavailable` (a kernel without Landlock, or a seccomp profile that refuses it) there is no filesystem
isolation at all: the token is readable by every step, as it was before this release. Run `doctor` to see which you have,
and set `CLEARANCE_CMP_FS_SANDBOX=require` once it says `on`, so a node that loses it fails renders instead of silently
losing the protection.

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

## Metrics and alerts (optional, off by default)

The plugin is not a server: the cmp-server starts `clearance-cmp` once per render and the process ends when it answers,
so no render can hold a counter for the next. The counts live in a **file-backed store** instead, and a small
long-lived process serves it:

- each run, as it ends, adds itself to `cmp-metrics.json` in `CLEARANCE_CMP_METRICS_DIR`: its outcome, its error's class
  and code, its wall time, and the results of its calls to the core;
- `clearance-cmp metrics`, in a container of its own in the repo-server pod (the same image, the same directory mounted
  **read-only**), serves the store on `CLEARANCE_CMP_METRICS_ADDR`, reading it on every scrape.

**Why this design.**

- *Correctness with concurrent renders.* The read-modify-write is serialised by an exclusive `flock` on
  `cmp-metrics.lock` beside it. Renders are separate processes on one kernel (`CLEARANCE_CMP_MAX_RENDERS` of them, and
  the canary sidecar's too when it mounts the same volume), so no run's count is lost; a test runs several processes at
  once and checks the total.
- *Crash safety.* A run writes a temporary file and renames it over the store, so a reader and the next writer always
  see a whole file. A run killed mid-write leaves only a stray temporary file, which the next writer removes while it
  holds the lock, and the kernel releases a dead process's lock. A store that does not parse (it should not happen) is
  started again and counted in `clearance_cmp_metrics_store_resets_total`: a counter reset, never a broken scrape.
- *A render never depends on its metrics.* Recording needs nothing running: no server to reach, so none can slow a
  render or lose a count by being down. A run waits at most 1 s for the lock; past that, or on any write error, it
  prints a `WARNING` and drops its own count, and its answer to Argo CD is unchanged. The server is stateless, so it
  can restart or crash without losing or double-counting anything; the store lives as long as the emptyDir (the pod's
  life), and a new pod is a counter reset that `rate()` already handles.
- *Nothing secret.* The store holds a closed set of labels: the plugin's build version, the outcome, the error class and
  its stable code, the core call's result. Never the token, a URL, an Application, a repository or an error message.
  The metrics container mounts no token and reads no other setting, and it writes only label values that are plain
  identifiers even though the store is the plugin's own.
- *Bounded.* At most 8 plugin versions are kept (the one updated longest ago is dropped for a ninth); every other label is
  a fixed set, so the store stays a few KiB.

**The series.** Every one carries `version`, the image's build version, so the default and canary sidecars (different
releases) are told apart even when they share the store.

| Series | Type | Labels | What it counts |
|---|---|---|---|
| `clearance_cmp_renders_total` | counter | `version`, `outcome` | Runs (`generate`), by `cleared`, `held` or `error`. A run answered from the plugin's caches counts too. |
| `clearance_cmp_render_errors_total` | counter | `version`, `class`, `code` | Failed runs, by [class](#error-codes) (`fault`, `dependency`, `render`, `refusal`) and stable code. A sidecar setting that stops the plugin at start is a `fault` too, and so is a panic. |
| `clearance_cmp_render_duration_seconds` | histogram | `version` | A run's wall time, start to answer. Buckets 0.05 s to 80 s (the plugin's whole run). |
| `clearance_cmp_core_calls_total` | counter | `version`, `result` | Calls to the core: `ok` (a decision), `unavailable` (unreachable or no answer in time: the outage policy decides), `error` (a refusal of the request, an answer the plugin cannot read). |
| `clearance_cmp_last_run_timestamp_seconds` | gauge | `version` | When a run of that version was last recorded. |
| `clearance_cmp_metrics_store_up` | gauge | | 1 when the store reads (or has no run yet). |
| `clearance_cmp_metrics_store_resets_total` | counter | | Times the store did not parse and was started again. |

**Turning it on.** Add one emptyDir, the setting and mount on the plugin sidecar, and the metrics container. With the
`argo-cd` Helm chart, beside the `clearance-cmp` container of [The sidecar](#the-sidecar):

```yaml
repoServer:
  extraContainers:
    - name: clearance-cmp
      # ... as above, plus:
      env:
        - {name: CLEARANCE_CMP_METRICS_DIR, value: /var/run/clearance-cmp-metrics}
      volumeMounts:
        - {name: cmp-metrics, mountPath: /var/run/clearance-cmp-metrics}
    - name: clearance-cmp-metrics
      image: ghcr.io/jfillman/clearance-cmp@sha256:<the same digest>
      command: [/usr/local/bin/clearance-cmp, metrics]
      securityContext:
        runAsNonRoot: true
        runAsUser: 999
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
        seccompProfile: {type: RuntimeDefault}
      env:
        - {name: CLEARANCE_CMP_METRICS_DIR, value: /var/run/clearance-cmp-metrics}
        - {name: CLEARANCE_CMP_METRICS_ADDR, value: ":9464"}
      ports:
        - {name: cmp-metrics, containerPort: 9464}
      readinessProbe:
        httpGet: {path: /healthz, port: cmp-metrics}
      resources:
        requests: {cpu: 5m, memory: 16Mi}
        limits: {memory: 64Mi}
      volumeMounts:
        - {name: cmp-metrics, mountPath: /var/run/clearance-cmp-metrics, readOnly: true}
  volumes:
    - {name: cmp-metrics, emptyDir: {sizeLimit: 16Mi}}
```

For plain manifests, add the same container, env, mount and volume to the patch. A canary sidecar
([gate.md](gate.md#rolling-out-a-plugin-release)) mounts the same `cmp-metrics` volume with the same setting: the store
is the one thing the two sidecars share, and it is safe to (the lock and the `version` label), unlike `/tmp`. A canary
of a release before this one records nothing. Run `doctor` in the plugin sidecar to check the directory (`metrics`).
The port is any free one in the pod; the repo-server's own are 8081 and 8084.

**Scraping.** With the Prometheus Operator, a PodMonitor in the Argo CD namespace (the label is the stock repo-server's):

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: clearance-cmp
  namespace: argocd
spec:
  selector:
    matchLabels: {app.kubernetes.io/name: argocd-repo-server}
  podMetricsEndpoints:
    - {port: cmp-metrics, path: /metrics, interval: 30s}
```

Without the operator, a scrape job on the pod's `cmp-metrics` port does the same. With more than one repo-server replica
each pod has its own store; the rules below sum across them.

**Alerts.** An example PrometheusRule; tune the thresholds to your volume (a ratio over a handful of renders is noisy,
so each alert also asks for a minimum render rate):

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: clearance-cmp
  namespace: argocd
spec:
  groups:
    - name: clearance-cmp.rules
      rules:
        - record: clearance_cmp:renders:rate10m
          expr: sum by (version) (rate(clearance_cmp_renders_total[10m]))
        - record: clearance_cmp:fault_ratio:rate10m
          expr: |
            sum by (version) (rate(clearance_cmp_render_errors_total{class="fault"}[10m]))
              / clearance_cmp:renders:rate10m
        - record: clearance_cmp:render_error_ratio:rate10m
          expr: |
            sum by (version) (rate(clearance_cmp_render_errors_total{class="render"}[10m]))
              / clearance_cmp:renders:rate10m
        - record: clearance_cmp:duration_seconds:p95_10m
          expr: histogram_quantile(0.95, sum by (version, le) (rate(clearance_cmp_render_duration_seconds_bucket[10m])))
    - name: clearance-cmp
      rules:
        - alert: ClearanceCmpPluginFaultRate
          # CMP-FAULT-*: the plugin itself failed (a panic, a tool, a timeout, a sidecar setting).
          expr: (clearance_cmp:fault_ratio:rate10m > 0.05) and (clearance_cmp:renders:rate10m > 0.01)
          for: 10m
          labels: {severity: critical}
          annotations:
            summary: "clearance-cmp {{ $labels.version }}: {{ $value | humanizePercentage }} of renders fail with a plugin fault"
            description: "Read the codes: sum by (code) (rate(clearance_cmp_render_errors_total{class=\"fault\"}[10m])). Error codes: docs/install-argocd-plugin.md."
        - alert: ClearanceCmpRenderErrorRate
          # CMP-RENDER-*: the Application's inputs do not render. One app is its owner's; many at once is usually a
          # plugin release or a sidecar setting (0.52.0 refused every value file).
          expr: (clearance_cmp:render_error_ratio:rate10m > 0.25) and (clearance_cmp:renders:rate10m > 0.01)
          for: 30m
          labels: {severity: warning}
          annotations:
            summary: "clearance-cmp {{ $labels.version }}: {{ $value | humanizePercentage }} of renders fail as render errors"
        - alert: ClearanceCmpCoreUnreachable
          # The outage policy decides while this fires: allow-and-record trees are served from the cache, the rest hold.
          expr: |
            (sum by (version) (rate(clearance_cmp_core_calls_total{result="unavailable"}[5m]))
              / sum by (version) (rate(clearance_cmp_core_calls_total[5m])) > 0.5)
            and (sum by (version) (rate(clearance_cmp_core_calls_total[5m])) > 0.01)
          for: 5m
          labels: {severity: critical}
          annotations:
            summary: "clearance-cmp {{ $labels.version }}: the Clearance core is unreachable for most calls"
        - alert: ClearanceCmpRenderLatencyP95
          # The whole run has 80 s and Argo CD kills a plugin at 90 s.
          expr: (clearance_cmp:duration_seconds:p95_10m > 30) and (clearance_cmp:renders:rate10m > 0.01)
          for: 15m
          labels: {severity: warning}
          annotations:
            summary: "clearance-cmp {{ $labels.version }}: p95 render time is {{ $value | humanizeDuration }}"
        - alert: ClearanceCmpMetricsStoreDown
          # Per pod: one replica's healthy store must not hide another's broken one.
          expr: clearance_cmp_metrics_store_up == 0
          for: 15m
          labels: {severity: warning}
          annotations:
            summary: "clearance-cmp metrics store on {{ $labels.pod }} does not read"
        - alert: ClearanceCmpMetricsNotScraped
          # The PodMonitor's job is "<namespace>/<name>" by default; per target, and absent when no target is found.
          expr: up{job="argocd/clearance-cmp"} == 0 or absent(up{job="argocd/clearance-cmp"})
          for: 15m
          labels: {severity: warning}
          annotations:
            summary: "clearance-cmp metrics are not being scraped (a metrics container is down, or none is found)"
```

**Gating a canary on the alerts.** A release goes to the canary sidecar first (`clearance-canary`,
[gate.md](gate.md#rolling-out-a-plugin-release)); its runs carry its own `version`, so the same series judge it beside
the default sidecar's. Before **Promote**, after the canary app was hard-refreshed on the new image, take a soak window
(an hour, or long enough for the canary to render a few dozen times; a pre-render cache hit counts as a render, so
hard-refresh it more than once if it is quiet) and promote only when every one of these holds for `V`, the canary's
version, and `D`, the default's:

1. it rendered: `sum(clearance_cmp_renders_total{version="V"}) >= 20` (a canary with no renders has not passed);
2. no plugin fault: `sum(clearance_cmp_render_errors_total{version="V",class="fault"})` is 0 or has no series;
3. no render error the canary's apps did not already have: `sum by (code) (clearance_cmp_render_errors_total{version="V",class="render"})`
   is 0 or has no series, or every such error is one the same Application showed on `D` before it moved (its
   ComparisonError in Argo CD). The series carry no Application, so the store cannot compare the same apps itself;
4. no slower, as a fleet-level heuristic: `clearance_cmp:duration_seconds:p95_10m{version="V"}` at most 1.5 times
   `{version="D"}` (the two sidecars render different apps, so read a gap here against what those apps are);
5. none of the alerts above firing with `version="V"`, and `ClearanceCmpMetricsNotScraped` not firing: its `up`
   series carry no `version` label, so the check above does not cover it, and a replica that is not scraped drops its
   canary counts (its faults among them) out of steps 1 to 3 while the other replicas can still meet step 1. And
   every replica is scraped: `count(up{job="argocd/clearance-cmp"} == 1)` equals the repo-server's ready replicas
   (`kubectl -n argocd get deploy argocd-repo-server -o jsonpath='{.status.readyReplicas}'`, or
   `kube_deployment_status_replicas_ready` from kube-state-metrics). A replica that target discovery misses has no
   `up` series at all, so the alert cannot see it.

Steps 1 to 3 read the **cumulative** counters, not `increase()`: a fresh version's series appear only with its first
run (and an error series only with its first error), so `increase()` over the window would miss that first count. A
version is fresh in the store when its canary starts. The counters are per pod and a restarted pod's store starts
empty, so **if any repo-server pod restarts during the soak, the soak starts again from fresh stores on every pod**:
roll every repo-server pod (each gets a new emptyDir), hard-refresh the canary app, and start the window. Otherwise
step 1 could pass on renders the other pods recorded before the restart, with none after it. **Before** rolling the
pods, check what the canary did so far: run steps 2 and 3 with a range from the canary's start to now, for example
`sum(max_over_time(clearance_cmp_render_errors_total{version="V",class="fault"}[<time since the canary started>]))`
(and the same for `class="render"`). A non-zero fault there fails the canary: roll back instead of restarting the soak.
That result does not carry into the new soak's queries, so record it when you take it. A series that does not exist
means zero, not a failure.

Any failure is the **Roll back** step: remove the app from the canary and hard-refresh it. The gate is these queries
read by the person promoting; nothing here blocks the promotion by itself. To automate it, run the five queries from
the job that pins the new image and stop when one fails.

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
   clearance: shop/prod rendered 14 objects, tree 3f9a1c0b27de, chart https://git.example.test/platform/charts.git@v1.4.2 (c7e846a91b0d), chart-cache=miss, netns=unavailable, fs-sandbox=on
   ```

   `chart-cache=` is `hit` (the chart came from the cache), `miss` (fetched, and kept) or `off`. `netns=` is `on`
   (renders are isolated), `unavailable` (`try` fell back: the kernel or seccomp profile refused) or `off`. `fs-sandbox=` is the
   same for the filesystem sandbox: `on` means no render step could read the token. An unchanged
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
The message is `<code>: <one short line>`, then `hold: <url>` when a change was refused or held, then `detail: <the
full message>`. A configuration error exits 2, anything else 1.

### Error codes

Each code is stable: it is never renamed or given another meaning. The class says whose problem it is and whether
[last-known-good](#last-known-good-optional-off-by-default) may answer it (fault and dependency only, and only before
the decision).

| Code | Class | Means | Do |
|---|---|---|---|
| `CMP-FAULT-PANIC` | fault | The plugin panicked (a bug); it was recovered. | Report it with the detail line. |
| `CMP-FAULT-INTERNAL` | fault | The plugin's own failure with no more specific code: its scratch files, writing the output, an unexpected error. | Check the pod's `/tmp` (full, read-only); report it if it persists. |
| `CMP-FAULT-TOOL` | fault | `helm`, `kustomize` or `git` could not be started, or was killed by a signal (out of memory). | Check the image and the container's memory limit. |
| `CMP-FAULT-TIMEOUT` | fault | The render ran out of time: its wall time (`CLEARANCE_CMP_RENDER_TIMEOUT`), or the time left before the core's reserved call. | Check egress to the chart repository; see `CLEARANCE_CMP_RENDER_TIMEOUT` and `CLEARANCE_CMP_CALL_TIMEOUT`. |
| `CMP-FAULT-SANDBOX` | fault | `CLEARANCE_CMP_NETNS=require` and the private network namespace cannot be created, or `CLEARANCE_CMP_FS_SANDBOX=require` and Landlock is unavailable, or (at start) the render steps' processes cannot be contained (`PR_SET_CHILD_SUBREAPER` refused, `/proc` unreadable). | Fix the seccomp profile or the kernel, or set `try`. |
| `CMP-FAULT-BUSY` | fault | Every render slot (`CLEARANCE_CMP_MAX_RENDERS`) stayed busy for the render's whole wall time. | Raise `CLEARANCE_CMP_MAX_RENDERS` or the repo-server's resources; check for slow renders. |
| `CMP-FAULT-CONFIG` | fault | A sidecar setting is missing or malformed (including `CLEARANCE_CHART_REPOS` unset). | Run `doctor`; fix the named setting. |
| `CMP-FAULT-TOKEN` | fault | The token file could not be read; nothing was sent. | Check the projected token volume; `doctor` `token`. |
| `CMP-FAULT-CORE-RESPONSE` | fault | The core answered something the plugin cannot read. | Check `CLEARANCE_URL` points at the core, not a proxy page. |
| `CMP-FAULT-WAIT-IMAGE` | fault | A change is held for people but `CLEARANCE_WAIT_IMAGE` is not set, so no wait Job. | Set `CLEARANCE_WAIT_IMAGE`; the `hold:` line links the change. |
| `CMP-DEP-CHART-UNREACHABLE` | dependency | `git` or the chart's host could not be reached to resolve the tag, and the fetch failed. | Check the chart host and egress. |
| `CMP-DEP-CHART-FETCH` | dependency | The chart's tag resolved on the remote but the fetch then failed. | Check the chart host; retry. |
| `CMP-RENDER-PARAMS` | render | A plugin parameter (`PARAM_*`) or Argo CD variable is missing or malformed. | Fix the Application's `plugin.parameters`. |
| `CMP-RENDER-REFUSED` | render | A source the platform does not allow, or a symlink or path that leaves its repository. | Fix the source or list it in `CLEARANCE_CHART_REPOS`. |
| `CMP-RENDER-FETCH` | render | The chart's tag does not exist on its repository (or no lookup ran and the clone failed). | Check `chartRevision`; the sidecar has no git credential. |
| `CMP-RENDER-HELM` | render | `helm template` failed on the chart and values. | Fix the chart or values; vendor dependencies under `charts/`. |
| `CMP-RENDER-KUSTOMIZE` | render | `kustomize build` failed. | Fix the kustomization; keep bases in the repository. |
| `CMP-RENDER-SOURCES` | render | Generic mode: the Application's sources do not render, or use a feature the plugin refuses. Generic mode does not tell an unreachable host from a bad source. | Fix the source, or leave the app ungated. |
| `CMP-RENDER-TREE` | render | The render cannot be hashed: no objects, too many, a duplicate, an ambiguous YAML scalar. | Fix the render; quote the scalar. |
| `CMP-RENDER-REVISION` | render | `ARGOCD_APP_REVISION` is not a full commit, or the source repository has no owner/name. | Refresh the Application. |
| `CMP-RENDER-LIMIT-CPU` | render | A render step used more CPU time than `CLEARANCE_CMP_RENDER_MAX_CPU`. | Fix a runaway template, or raise the setting. |
| `CMP-RENDER-LIMIT-MEMORY` | render | A render step needed more memory than `CLEARANCE_CMP_RENDER_MAX_MEMORY`. | Raise the setting (and the container's memory limit), or shrink the render. |
| `CMP-RENDER-LIMIT-OUTPUT` | render | A step's output, or the rendered manifests, went over `CLEARANCE_CMP_RENDER_MAX_OUTPUT`. | Shrink the render, or raise the setting. |
| `CMP-RENDER-LIMIT-TEMP` | render | The render's scratch space, or one file in it, went over `CLEARANCE_CMP_RENDER_MAX_TEMP`. | Shrink the chart repository's checkout, or raise the setting. |
| `CMP-REFUSED-DENIED` | refusal | The change is denied. | Open the `hold:` link. |
| `CMP-REFUSED-EXPIRED` | refusal | The change's clearance expired. | Open the `hold:` link; clear it again. |
| `CMP-REFUSED-SUPERSEDED` | refusal | A newer change replaced it. | Sync the newer commit. |
| `CMP-REFUSED-EXCEPTION` | refusal | The change is under a deploy exception, not cleared. | Open the `hold:` link. |
| `CMP-REFUSED-DEGRADED` | refusal | The change is in degraded mode, not cleared. | Open the `hold:` link. |
| `CMP-REFUSED-STATE` | refusal | The change is in another state that does not sync. | Open the `hold:` link. |
| `CMP-REFUSED-OUTAGE-HOLD` | refusal | The core is unreachable and nothing cleared and `allow-and-record` is remembered for the tree. | Restore the core; `doctor` `core`. |
| `CMP-REFUSED-BY-CORE` | refusal | The core refused the registration (4xx): the token's audience, not a verifier, a bad request. | See the messages below; `doctor` `core-auth`. |

The links go to `CLEARANCE_CMP_LINK_BASE/changes/<id>` (the web UI) when that is set, else to the core's
`CLEARANCE_URL/v1/clearances/<id>`.

### By message

The `detail:` line is the message in the code; these are the common ones, with their fixes.

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
| `CMP-RENDER-LIMIT-*`, `CMP-FAULT-BUSY` or `CMP-FAULT-TIMEOUT`: `... went over its <bound> bound (<SETTING>=<value>)` | A render went over one of its bounds (wall time, CPU, memory, output, scratch space, or it waited too long for a slot). Nothing it rendered syncs; for the two faults (`CMP-FAULT-BUSY`, `CMP-FAULT-TIMEOUT`) last-known-good, when on, may serve the same already cleared render after the core confirms it. | If the render is legitimately that large or slow, raise the named setting on the sidecar; otherwise fix the chart (a runaway template, a huge generated object). For `concurrency`, raise `CLEARANCE_CMP_MAX_RENDERS` or the repo-server's resources. |
| `refusing to run helm: the filesystem sandbox is unavailable (...) and CLEARANCE_CMP_FS_SANDBOX=require` | `require` is set and the kernel has no Landlock, or the seccomp profile refuses it. | Run on a kernel with Landlock active, use a seccomp profile that allows its calls (`RuntimeDefault` does), or set `CLEARANCE_CMP_FS_SANDBOX=try`. |
| `CLEARANCE_TOKEN_FILE <path> is under <dir>, which every render step may read` | The token is mounted where the sandbox cannot hide it. | Mount it under `/var/run/secrets` (the default path), or set `CLEARANCE_CMP_FS_SANDBOX=off` knowing it is unprotected. |
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
- **The token is hidden from render steps only where the kernel has Landlock** (`fs-sandbox=on`); elsewhere the default
  renders without the sandbox, and says so.
- Loopback in the pod is closed to renders only where the kernel allows the namespace; `git` and `helm pull` stay outside
  it, and the plugin's own fetch is as wide as the repository you listed. See [gate.md](gate.md#parameters-and-settings).
