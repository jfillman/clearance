# Changelog

What each Clearance release shipped. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions are [semantic](https://semver.org/spec/v2.0.0.html): a `vX.Y.Z` tag on `main` after green CI. A tag
publishes a GitHub Release whose notes are that version's section here (`.github/workflows/release.yaml`), so a
release PR adds its section before the tag is pushed.

Entries before v0.26.1 were reconstructed on 2026-11-02 from the commits between tags and their pull requests.

## [Unreleased]

### Added
- Flight recorder fields and cost accounting (A-4: AP-C1, AP-C2); evidence schema revision 3, additive. A model
  call's outcome (`POST /v1/decisions/{id}/outcome`) takes `model_version` (the model that answered) and `usage`
  (`input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`, `charged_tokens`: what
  the gateway's model proxy charged the session), refused on any other tool's outcome. A run's provider records
  (`session.open`, `run.launch`, `run.finish`, `run.delete`) take `model_version` and `preflight` {result
  pass|fail|not-run, definition, cases}, and `run.finish` takes `cost` (the run's summary: tokens, model and tool
  calls, wall seconds, compute class). All claimed. The Go client and the Python client (`clearance-core-client`)
  carry the new fields (`Usage`, `Preflight`, `Cost`).
- clearance-api `GET /v1/evidence/counts?by=cost&per=task|session|agent|principal`: the model-call outcomes'
  usage and the run.finish records' runs and wall seconds summed per task tree, run, agent or principal, with the
  list's filters and scoping; each item carries `cost`, the answer `per` and the summed `cost`.
- Subject kind `model-call` (evidence schema revision 3): a `model.call` record's derived subject is
  `{kind: model-call, name: <target, the model alias>, digests: {sha256: args_sha256}}`, from `tool`, `target` and
  `args_sha256`, for records written from now on (the decision and its outcome). A stored v0-draft row is still
  projected with its `tool-call` subject.
- Postgres: the partial index `clearance_evidence_cost` on the records that carry `usage` or `cost` (created by the
  core's migration, `CREATE INDEX IF NOT EXISTS`).

## [0.30.0] - 2026-11-03

R-3: the Python package is gone. Breaking for anyone who installs `clearance` from this repository with pip (or
`uv`), imports it, or runs its `clearance` console script: there is no Python `clearance` any more. Clearance is the
Go module and its one binary; the gateway half of the old package is Autopilot's. Nothing deployed changes: hangar-dev
has run the Go core and clearance-api, and the Autopilot gateway's own copies of the gateway modules, since the
cutover of 2026-11-03.

### Removed
- `src/clearance`, the Python package (last at v0.29.0), its tests (`tests/*.py`), `pyproject.toml` and `uv.lock`.
  Where each module went:
  - **To Autopilot** (`src/autopilot/engine/`, R-3a to R-3c): the MCP surface (`server.py`), sessions, the run tree,
    budgets and spend (`dispatch.py`, `session.py`, `limits.py`), the tool registry (`tiers.py`; the tier vocabulary
    stays shared), the model proxy (`modelproxy.py`), the backend protocols (`backends.py`), agent definitions and
    their schema (`profile.py`, `schemas/agent-definition.schema.json`, `definitions.py`'s loader), the runtime
    catalog (`runtimes.py`), the human inbox (`inbox.py`), person controls (`control.py`), run results
    (`results.py`), trigger history (`events.py`), artifacts and the gateway's tables (`pg.py`'s runtime half,
    `src/autopilot/engine/pg.py`), and the runtime's reads of `api.py` (`src/autopilot/read_api.py`, served by
    `autopilot-gateway api`).
  - **To the Go core** (this repository): policy, scope and the CEL rules (`policy.py`, `scope.py` to
    `internal/decide`, `internal/scope`), the evidence record and recorder (`audit.py`, `pg.py`'s evidence half to
    `internal/evidence`, `internal/store`), the deployment gate (`gate.py` to `internal/gate`), definition review
    and pins as a gate subject (`review.py`, `definitions.py` to `internal/review`, `internal/definitions`,
    `internal/profile`), provenance (`provenance.py` to `internal/provenance`), the GitHub App (`github_app.py` to
    `internal/githubapp`), who is calling (`auth.py` to `internal/authn`, `internal/directory`), Clearance's reads
    (`api.py` to `clearance api`, `internal/api`) and `clearance register` (`register.py` to
    `cmd/clearance/register.go`).
  - **To a policy bundle** (R-5): packs (`pack.py`, `packs/hangar`) are policy bundles a deployment loads; Hangar's
    ships with Autopilot (`policy/hangar/bundle.json`).
- The Python recorders that imported the package: `tools/golden/export_bundle.py`, `record.py`,
  `golden_recorder.py`, `test_fixture_calls.py`, `tools/api-golden/golden_py.py` and
  `internal/evidence/testdata/python_chain.py`. What they recorded stays as frozen fixtures (the golden corpus, the
  evidence chains, the API answers); they are at v0.29.0 for anyone who needs to re-record against the Python engine.
  `tools/golden/gen_vectors.py` and `internal/canon/testdata/gen_vectors.py` stay (standard library and PyYAML only).
- The `test` workflow (the pytest job) and the release's `clearance` wheel.

### Changed
- `register/action.yml` builds the Go `clearance` binary from the action's own checkout at its ref (`actions/setup-go`
  with the repo's `go.mod`) and runs `clearance register`, instead of pip-installing the Python package. Its inputs and
  outputs are unchanged. `args` reaches the Go command, which refuses `--paths-from-git` (only the Python command had
  it). A workflow pinned to an older tag (for example `@v0.24.1`) keeps installing that tag's Python package.
- The release version is the `VERSION` file (was `pyproject.toml`'s `[project].version`): `tools/pyclient` reads it for
  the Python client's `_version.py`, and the release workflow checks the tag against it.
- The release notes come from `go run ./tools/releasenotes` (was `tools/release_notes.py`), which also checks the tag
  (`-check-tag`); `internal/release`'s test is the changelog check `tests/test_release.py` was.
- The release ships the Python client's wheel and sdist (`clearance_core_client-X.Y.Z`) with `SHA256SUMS`, and checks
  the client was generated at the tag's version.
- The agent-definition schema check (`internal/profile`) compares the embedded copy with Autopilot's
  (`CLEARANCE_AGENT_SCHEMA`; CI checks out jfillman/autopilot), not with the Python package's.

### Added
- `internal/boundary`: the core holds no session store, MCP server or tool dispatch. `go list -deps` of the core names
  no MCP or model-provider SDK; no package is named for a gateway part; no identifier is a session store, dispatcher,
  MCP handler, tool registry, model proxy or inbox; no literal is the `/mcp` endpoint, an MCP method or a model API
  route. R-5's check that the core names no Hangar product (`tests/test_boundary.py`) is ported here, unchanged in
  what it checks.
- CI: a `register-action` job builds and dry-runs the register action.

## [0.29.0] - 2026-11-03

R-5: policy bundles and Hangar's vocabulary out of the core. Breaking for a deployment of the Go
core: `CLEARANCE_PACKS`, `CLEARANCE_FLIGHT_REGISTRIES` and `TOWER_*` are gone (set, the first two stop the start).

### Added
- Policy bundles (`clearance.policy/v1`, [docs/core.md](docs/core.md#policy-bundles)): a deployment's tools, CEL rules,
  CEL context (vars, argument checks, the recorded app) and document field scope (`internal/docscope`), loaded from
  `CLEARANCE_BUNDLES` by the core and clearance-api. A bundle's sources (for example a CI system's `GET /v1/contract`)
  are fetched at start from `CLEARANCE_BUNDLE_SOURCES` (HTTP(S) with a projected token, or a file), with a
  compatible-version check (a version the bundle does not list fails the start). No fallback copy: a source that
  does not answer within `CLEARANCE_BUNDLE_SOURCE_WAIT` (default 10s) leaves its bundle degraded. Its tools and the
  checks that need the source are denied R000 naming the bundle, with no denial charged. `/readyz` names it in
  `degraded`, still 200, and the gate and records keep working. A background loader retries with backoff (2s to
  60s) and loads it whole once the source answers; the load is logged and named in later decisions
  (`policy.bundles[].status`).
- Every decision names its policy: `context.policy.bundles` (each bundle's name, version, digest and the sources it
  read), and each decision record carries `policy: {ref, version, engine}` (the evidence schema's Decision group).
- The deployment's vocabulary as configuration (`internal/vocab`): `CLEARANCE_ON_BEHALF_OF_HEADER`,
  `CLEARANCE_TRAILER_PREFIX`, `CLEARANCE_RUN_IDENTITY_NAMESPACE`, `CLEARANCE_BASELINE_DENY_PATHS`,
  `CLEARANCE_BASELINE_DENY_FIELDS`, `CLEARANCE_GATE_OUTSIDE_GROUPS`, `CLEARANCE_GATE_OWNER_FALLBACK`,
  `CLEARANCE_V0_PROVIDER`, and the environment naming `CLEARANCE_ENV_*`; chart values `policy.*` and `vocabulary.*`.
- The Go client's `Options.OnBehalfOfHeader` and the Python client's `on_behalf_of_header`.
- `tests/test_boundary.py`: a data-level check that the Go core's source names no Hangar product.

### Changed
- The Hangar pack (`internal/decide/packs/hangar`, its vendored Glidepath scope) is gone from the Go core. Its policy
  is a bundle (Autopilot's `policy/hangar/bundle.json`); the corpus replays identically with it
  (`testdata/bundles/hangar` is the test fixture).
- Defaults are product-neutral: on-behalf-of header `X-Clearance-On-Behalf-Of` (was `X-Hangar-On-Behalf-Of`), trailer
  prefix `Clearance-` (was `Hangar-`), run namespace `agent-runs` (was `autopilot-runs`), baseline deny paths
  `CODEOWNERS`, `**/CODEOWNERS`, `.github/**` (the Tekton, AppProject and release-file globs and the deny fields are
  Hangar's to set), no outside group or owner fallback (was `group:default/admins`), no `AGENT_LOGINS` (was
  `hangar-autopilot-agents[bot]`), v0 rows projected as `unrecorded` (was `autopilot-gateway`), and the environment
  naming knows only `dev`, `development`, `sandbox`, `scratch` (the `pr-`/`agent-` prefixes, `-lower` projects and
  `gitops-` repos are Hangar's to set).
- `CLEARANCE_FLIGHT_REGISTRIES` is `CLEARANCE_TRUSTED_REGISTRIES` (chart `gate.trustedRegistries`, gate policy
  `trustedRegistries`, rule `image:not-trusted-registry`); `TOWER_*` are `CLEARANCE_FOREIGN_*` (chart
  `foreignCluster.*`).

## [0.28.0] - 2026-11-03

What the Autopilot gateway needs of the core before the hangar-dev cutover (R-3e).

### Added
- `POST /v1/records` takes the kinds the gateway held in its outbox: `run.finish`, `session.end`, `trigger.release`,
  and `tool.call` with `coverage: coverage-unavailable`, the outage policy's replay of a T0 read the gateway ran
  while the core was unreachable (`tool` names a T0 tool the core knows; no rule, subject, effect or outcome; all
  claimed). Required fields are what the Python gateway recorded for each at v0.26.1
  ([docs/provider-protocol.md](docs/provider-protocol.md#record-kinds)).
- `PUT /v1/definitions` (operation `publishDefinitions`): the provider registered with `"definitions": true` in
  `CLEARANCE_PROVIDERS` (at most one) publishes its cluster-pinned agent definitions, its Agent XR loader's pins and
  rejections. The core decides each pin again with its own schema (`definitions.FromPin`, `internal/profile`),
  replaces the stored set and records each change once through `definitions.Service.Apply` (`definition.load`,
  `definition.unload`, `definition.reject`, sealed by the core with `caller`; the pin's fields claimed). Provenance
  reads the published set at once and a restarted core reads it back. Go client `PublishDefinitions`, Python client
  `publish_definitions`.
- A person's run on `session.open`: `action.properties.run` and `via` (the delegate). The record is Gateway.run_agent's
  at v0.26.1: `args_sha256({"via": ...})` and `opened to run[ via <delegate>]`.
- An outcome may carry `refusal: {rule, message}`, a handler's refusal after the core allowed the call, recorded as
  `refusal` (claimed) beside the decision's own `decision` and `rule`. Evidence schema `x-clearance-revision` 2.
- `CLEARANCE_MAX_CLOCK_SKEW` (a Go duration, default `5m`, at most `24h`; chart value `core.maxClockSkew`) and
  `clearance core --max-clock-skew`. `0` turns the check off and is accepted only with `--memory`.
- `clearance core --memory --insecure-dev-auth` serves the in-memory chain at `GET /v1/dev/records` (dev only, not
  in the contract), so autopilot's tests run against the unmodified binary instead of a `go build -overlay` test
  core.

### Changed
- `definition.load`, `definition.unload` and `definition.reject` are the core's records only: `POST /v1/records`
  refuses them (it never accepted them).

## [0.27.1] - 2026-11-03

### Added
- Chart values `core.hostAliases` and `api.hostAliases` (a portal hostname with no DNS, as Hangar's lab reaches Tower).

### Fixed
- `GET /v1/clearances/counts` refuses an unknown `state` or a non-ISO `since` with 400, as `GET /v1/clearances` does (#45).

## [0.27.0] - 2026-11-03

### Added
- `CHANGELOG.md` (this file) and a release workflow: a `v*` tag on `main` builds the wheel and publishes a GitHub
  Release with this file's section for the version as its notes, and fails when the section is missing.
- Clearance's own image and Helm chart (R-2): `Dockerfile` (static `CGO_ENABLED=0 -trimpath` build onto
  `gcr.io/distroless/static-debian12:nonroot` pinned by digest, uid 65532) and `charts/clearance` (the core as one
  `Recreate` replica, clearance-api with 2 replicas and a PodDisruptionBudget, Services, default-deny NetworkPolicy,
  optional CloudNativePG cluster with a read-only role, ExternalSecrets and HTTPRoutes, `helm test` chain verify,
  a value for every core variable). The release workflow now pushes `ghcr.io/jfillman/clearance:vX.Y.Z` (amd64 and
  arm64, SPDX SBOM, keyless signature) and `oci://ghcr.io/jfillman/charts/clearance`, and reruns the install test on
  them. Chart CI (`.github/workflows/chart.yaml`): lint, render tests (`tools/charttest`), kubeconform, and an install
  test on kind (`tools/chart-install-test`, `tools/installtest`). See [docs/install.md](docs/install.md).
- `clearance api` (R-2b): Clearance's read API in Go (`internal/api`), on the read-only Postgres store: evidence
  (filters, `seq` cursor, chain verify, counts), receipts and provenance verdicts, the gate's changes and policy, the
  policy as data and the dry-run explainer (`decide.(*Engine).Trace`), and the new `GET /v1/definitions`. Same paths,
  parameters, answers and codes as api.py for every route kept, identical on the 612-record hangar-dev chain; the
  runtime's reads move to the gateway (R-3). Counts exclude the core's outcome records by default (`outcomes`).
  `contract/clearance-api.json` is now generated from the Go handlers, and `tools/gen_api_contract.py` is gone
  ([docs/clearance-api.md](docs/clearance-api.md)).
- `CLEARANCE_FLIGHT_REGISTRIES` (chart value `gate.flightRegistries`): the image prefixes a tier-1 image bump may come
  from; unset, the default, is any registry. Hangar sets `ghcr.io/riley-roooo/` from the R-4 cutover.
- `tools/release_notes.py`: print one version's section (the workflow's notes; exits 1 when there is none).
- The Go core (R-1): one `clearance` binary (`core [--memory]`, `chain verify`, `register`, `conformance`, `version`); the
  decision engine on cel-go with a golden corpus replayed from the Python engine; the Postgres store extending the
  same chain byte for byte; the deployment gate, provenance and GitHub App ported; `POST /access/v1/evaluation`,
  `POST /v1/decisions/{id}/outcome`, `POST /v1/records` for registered providers (`CLEARANCE_PROVIDERS`);
  `contract/clearance-core.json`; Go (`client/`) and Python (`clients/python`) clients; the provider protocol and
  `clearance conformance` ([docs/core.md](docs/core.md)). Built, not deployed.
- Evidence record v1 (R-6): `schemas/evidence.schema.json`, `clearance.evidence/v1`, with `provider` and `subject`;
  v0-draft rows are projected on read by clearance-api ([docs/evidence.md](docs/evidence.md)).

### Changed
- `clearance.__version__` comes from the installed package's metadata (pyproject's version), not a hard-coded
  `0.1.0.dev0`.
- The durable evidence log (`pg.PgAuditLog`) verifies the chain at start through a server-side cursor, 1000 rows a
  round trip, instead of loading every record into memory.
- A `Gateway` given an inbox refuses `human.request` or `human.request.get` handlers too (for example
  `core_handlers(human=...)`): the inbox used to replace them silently. Pass one or the other.

### Fixed
- Docs status: `docs/index.md`, `catalog-info.yaml`, and the status lines of `docs/gate.md` and
  `docs/provenance-app.md` say what is built at v0.26.1 (the gate's core, the GitHub App phases 1, 2a and 2b),
  not "designed" and "not built".

## [0.26.1] - 2026-11-02

### Changed
- `catalog.read`: the tool description says which query form filters (#41).

## [0.26.0] - 2026-11-01

### Added
- Model proxy: streaming Messages. Server-sent events are relayed as they arrive and their usage is charged when
  the stream ends, however it ends; Claude Code and the Agent SDK always stream (#40).

### Changed
- The client's `anthropic-beta` header is forwarded, less OAuth's betas (#40).

## [0.25.0] - 2026-11-01

### Added
- Run results: an in-cluster run hands back its answer with `run_finish`, kept 30 days (`results.py`); sessions keep
  their `input` and `outcome`, and clearance-api serves `GET /v1/sessions/{id}/result` (#39).

## [0.24.2] - 2026-11-01

### Fixed
- GitHub Actions OIDC: match the immutable-ID subject by repository name (#38).

## [0.24.1] - 2026-11-01

### Changed
- `clearance register` sends its own User-Agent and says when a refusal did not come from Clearance (#37).

## [0.24.0] - 2026-11-01

### Added
- Hangar pack: glidepath live, release-run, evidence, tests, events and previews tools (#36).

## [0.23.0] - 2026-11-01

### Added
- `clearance register`: a workflow registers its deployment with the gate, authenticated by its GitHub Actions OIDC
  token, for its own repository only (provenance App phase 2b, #34).
- Agent definitions carry a one-line `description`, and `runs_in` follows from the runtime (`cluster` or `client`);
  a person's Run (#35).

### Changed
- `run_agent`: the person's input is the runtime's prompt, with the definition's instructions (#35).

### Fixed
- CI: the wheel check names the vendored `glidepath-scope.json` (renamed in v0.20.3).

## [0.22.0] - 2026-11-01

### Added
- The deployment protection rule: the GitHub App answers GitHub Actions deployments from the deployment gate's
  change: approved, rejected, or waiting on people (provenance App phase 2a, #33).
- The Clearance logo, for the GitHub App (#32).

### Changed
- Hangar's App is named "Hangar Clearance": "Clearance" is taken on GitHub (#32).

## [0.21.0] - 2026-11-01

### Added
- The Clearance GitHub App, phase 1: signature-checked PR webhooks, a one-repo read-only installation token, and
  Clearance's own `Clearance / agent-identity` and `Clearance / agent-scope` check runs (#31).
- `docs/provenance-app.md`: decisions 1 and 2 (#30).

## [0.20.3] - 2026-10-31

### Changed
- Vendor only the scope section of Glidepath's contract, as `packs/hangar/vendor/glidepath-scope.json` (#28).
- `docs/provenance-app.md`: the provenance App design pass (#29).

## [0.20.2] - 2026-10-31

### Changed
- Re-vendor Glidepath's contract 0.9.0 after glidepath#213 (#27).

## [0.20.1] - 2026-10-31

### Changed
- Re-vendor Glidepath's contract after glidepath#208 (glidepath-api 0.8.0) (#26).

## [0.20.0] - 2026-10-31

### Added
- Definition review: validate a definition, tier its change and gate its release through the deployment gate
  (`review.py`) (#25).
- The runtime catalog: the deployment's agent images, allowed for `runtime.image` and listed at `GET /v1/runtimes`
  (#25).

## [0.19.0] - 2026-10-31

### Added
- The deployment gate's core: a change to a protected environment classified 0 to 3 from its rendered diff, cleared
  by policy or by people, recorded in the deployment boundary (`gate.py`) (#24).
- TechDocs: `mkdocs.yml` over `docs/`, a home page, and the catalog Component (#22).
- `docs/gate.md`: decisions 1 to 5 recorded (#22, #23).

### Changed
- Re-vendor Glidepath's contract after glidepath#207 (the clearance-gate guardrail).

## [0.18.0] - 2026-10-31

### Added
- Definitions pinned by `Agent` XRs: the live set, `from_pin`, evidence per change, and `source` and `rejected` in
  the API (`definitions.py`) (#20, #21).
- `docs/gate.md`: the deployment gate design pass (#18).

### Changed
- Re-vendor Glidepath's contract after glidepath#202 (cicd validations endpoint).

## [0.17.0] - 2026-10-31

### Added
- Person controls: freeze and end a session, hold and release an agent's triggers, through the delegate model
  (`control.py`) (#17).

## [0.16.0] - 2026-10-31

### Added
- `glidepath.cicd.validate` and `glidepath.cicd.propose`: a cicd.yaml change as a PR tool (#19).

## [0.15.0] - 2026-10-31

### Added
- Event history: what the trigger bridge received and did, served as `GET /v1/events` (`events.py`) (#16).

## [0.14.0] - 2026-10-31

### Added
- clearance-api: the policy as data, a dry-run explainer (`Policy.trace`) and evidence counts (#15).

## [0.13.0] - 2026-10-30

### Added
- clearance-api phase 1: the read API as a separate read-only process, `app` on every record that names one, and
  its contract `contract/clearance-api.json` (#13, #14).

## [0.12.0] - 2026-10-30

### Added
- Human inbox: a non-blocking `human.request`, `human.request.get` and the people API (#12).
- `ForeignWorkloadAuthenticator`: another cluster's service accounts verified by its public issuer (Tower as a
  delegate).

## [0.11.0] - 2026-10-30

### Added
- `PgArtifacts`: `artifact.put` and `artifact.get` on Postgres, per task, bounded and expiring (#11).

### Changed
- Re-vendor Glidepath's contract (the agent-gates release guardrail, glidepath#198).

## [0.10.0] - 2026-10-30

### Added
- OIDC sign-in only for the allowed people (#9).

### Changed
- Re-vendor Glidepath's contract (glidepath-api release records and events) (#10).

## [0.9.0] - 2026-10-30

### Added
- PR provenance: receipts on `repo.pr.open` and `POST /v1/provenance` for the agent gates (#8).

### Changed
- Re-vendor Glidepath's contract (glidepath 977ed7c, P6b).

## [0.8.0] - 2026-10-29

### Changed
- Token efficiency: cached tokens weighted in the model budget; `repo.file.get` lists the repository root (#7).

## [0.7.0] - 2026-10-29

### Changed
- `tools_list(session)`: only the tools the caller's own session may run (#6).

## [0.6.0] - 2026-10-29

### Added
- `repo.file.get`: a T0 read of a file or directory in an allowed repository (#5).

## [0.5.0] - 2026-10-29

### Added
- Runs act as their session; the model proxy forwarder (#4).
- Agent definitions: `runtime.instructions`, passed in a run's input; Glidepath event triggers.

### Changed
- Re-vendor Glidepath's contract 0.4.0 (#4).

## [0.4.0] - 2026-10-29

### Added
- `Gateway.expire`: delete expired sessions' runs, with a record each (Hangar D20) (#3).

## [0.3.0] - 2026-10-29

### Added
- The durable store and evidence sink on Postgres (`pg.py`, AP-A2) (#2).

## [0.2.0] - 2026-10-29

### Added
- HTTP transport and interim authentication (AP-A2) (#1).

## [0.1.0] - 2026-10-29

### Added
- Clearance as its own repository (Hangar decision D16), with its history from the `clearance` package in
  jfillman/autopilot: the Hangar-free core, packs and the boundary test (AP-A2); tiers and tripwires, path and field
  scope, narrow-only limits, CEL policy, sessions, the hash-chained audit log and the gateway; the Hangar pack's
  `glidepath.*` and `airframe.*` tools over glidepath-api and a GET-only Kubernetes adapter.

[Unreleased]: https://github.com/jfillman/clearance/compare/v0.30.0...HEAD
[0.30.0]: https://github.com/jfillman/clearance/compare/v0.29.0...v0.30.0
[0.29.0]: https://github.com/jfillman/clearance/compare/v0.28.0...v0.29.0
[0.28.0]: https://github.com/jfillman/clearance/compare/v0.27.1...v0.28.0
[0.27.1]: https://github.com/jfillman/clearance/compare/v0.27.0...v0.27.1
[0.27.0]: https://github.com/jfillman/clearance/compare/v0.26.1...v0.27.0
[0.26.1]: https://github.com/jfillman/clearance/compare/v0.26.0...v0.26.1
[0.26.0]: https://github.com/jfillman/clearance/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/jfillman/clearance/compare/v0.24.2...v0.25.0
[0.24.2]: https://github.com/jfillman/clearance/compare/v0.24.1...v0.24.2
[0.24.1]: https://github.com/jfillman/clearance/compare/v0.24.0...v0.24.1
[0.24.0]: https://github.com/jfillman/clearance/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/jfillman/clearance/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/jfillman/clearance/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/jfillman/clearance/compare/v0.20.3...v0.21.0
[0.20.3]: https://github.com/jfillman/clearance/compare/v0.20.2...v0.20.3
[0.20.2]: https://github.com/jfillman/clearance/compare/v0.20.1...v0.20.2
[0.20.1]: https://github.com/jfillman/clearance/compare/v0.20.0...v0.20.1
[0.20.0]: https://github.com/jfillman/clearance/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/jfillman/clearance/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/jfillman/clearance/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/jfillman/clearance/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/jfillman/clearance/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/jfillman/clearance/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/jfillman/clearance/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/jfillman/clearance/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/jfillman/clearance/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/jfillman/clearance/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/jfillman/clearance/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/jfillman/clearance/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/jfillman/clearance/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/jfillman/clearance/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jfillman/clearance/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jfillman/clearance/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jfillman/clearance/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jfillman/clearance/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jfillman/clearance/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jfillman/clearance/releases/tag/v0.1.0
