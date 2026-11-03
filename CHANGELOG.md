# Changelog

What each Clearance release shipped. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions are [semantic](https://semver.org/spec/v2.0.0.html): a `vX.Y.Z` tag on `main` after green CI. A tag
publishes a GitHub Release whose notes are that version's section here (`.github/workflows/release.yaml`), so a
release PR adds its section before the tag is pushed.

Entries before v0.26.1 were reconstructed on 2026-11-02 from the commits between tags and their pull requests.

## [Unreleased]

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

[Unreleased]: https://github.com/jfillman/clearance/compare/v0.27.0...HEAD
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
