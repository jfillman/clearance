# Clearance

Clearance is change assurance in the path of every change. It decides and records; it enforces nothing itself and
is not a gateway. An AI agent gateway (Autopilot's) asks it for a decision before every tool call, model call, session
open and spawn, and writes each outcome through it; a deployment gate's providers (the Argo CD sync, the GitHub App's
deployment protection rule, `clearance register` in CI) ask it whether a change may land in a protected environment.
Every decision carries a stable rule id and a fix hint, and every record goes into one hash-chained evidence chain.

It is a Hangar product (https://hangarplatform.dev). Autopilot, Hangar's agent gateway and runtime, is its native
consumer, but Clearance installs alone: the core knows nothing about Airframe, Glidepath, Autopilot or any other
platform, and imports nothing from them.

## The core

**Built and deployed** (on hangar-dev since 2026-11-03). One Go module (`go.mod`), one static binary `clearance` with
the subcommands `core` (the HTTP API: decisions, outcomes, provider records, the gate, provenance, the GitHub App),
`api` (clearance-api, the read-only API), `attest verify`, `trust-root build`, `chain verify`, `packet`, `verify`, `ledger keygen`, `register`, `conformance`
([docs/provider-protocol.md](docs/provider-protocol.md)) and `version`, plus the Go and Python clients (`client`,
`clients/python`). Its contract is [`contract/clearance-core.json`](contract/clearance-core.json). See
[docs/core.md](docs/core.md).

There is no Python Clearance any more. The Python package (`src/clearance`) left in v0.30.0: its gateway half
(the MCP surface, sessions, the run tree, limits, tool dispatch, the model proxy, the inbox, person controls, run
results, runtimes) is Autopilot's (`src/autopilot/engine/`, R-3), and its decision, record, gate and provenance
half is this Go module. [CHANGELOG.md](CHANGELOG.md) (0.30.0) maps each module to where it went. The one Python
here is the generated client, `clients/python` (`clearance-core-client`).

## Install

**Built and deployed** (hangar-dev runs chart 0.29.0 since 2026-11-03). Clearance ships as one image,
`ghcr.io/jfillman/clearance` (amd64 and arm64, a static Go binary on distroless nonroot, under 40 MB, with an SPDX
SBOM and a keyless signature), and one Helm chart,
`oci://ghcr.io/jfillman/charts/clearance`. It installs on any cluster with a Postgres database: no Airframe,
Glidepath or Autopilot.

```shell
helm install clearance oci://ghcr.io/jfillman/charts/clearance --version <X.Y.Z> -n clearance --create-namespace \
  --set database.existingSecret=clearance-db -f values.yaml
helm test clearance -n clearance --logs     # the evidence chain verifies, read-only
```

The chart runs the core as exactly one replica (the one writer of the evidence chain; `Recreate`), clearance-api as
two behind a PodDisruptionBudget, a default-deny NetworkPolicy, and optionally a CloudNativePG cluster with a
read-only role, ExternalSecrets and Gateway API routes. Every pod is uid 65532, read-only root, no capabilities,
seccomp `RuntimeDefault`; no secret value is a chart value. Every value, upgrades and the one-writer rule:
[docs/install.md](docs/install.md). CI (`.github/workflows/chart.yaml`) lints and render-tests the chart and runs an
install test on a fresh kind cluster (Postgres, the chart, a fake provider: health, a decision recorded, a change
cleared by policy, chain verify, the image size and the core's idle memory).

## What it decides and records

| Piece | Where | What it does |
|---|---|---|
| The decision service | `internal/decide`, `internal/scope`, `internal/docscope`, `POST /access/v1/evaluation` | An AuthZEN-shaped evaluation for `tool.call`, `model.call`, `session.open` and `session.spawn`: the shared tier vocabulary (T0 to T3, tripwires), path, repo and field scope, the narrow-only rule, CEL deny rules with ids, an explicit order and fix hints (core rules plus a deployment's [policy bundles](#policy-bundles)); anything that fails to evaluate denies (R000). A pure function: the caller's request carries the state it reads, and the answer carries the spend the gateway applies |
| Agent definitions as a subject | `internal/profile`, `internal/definitions`, `internal/review` | Validates a definition against the agent-definition schema (Autopilot's, embedded byte for byte), decides each cluster pin, and tiers a definition change (`POST /v1/definitions/review`) |
| The evidence record and the recorder | `internal/evidence`, `internal/store`, `schemas/evidence.schema.json` | One record per decision, outcome and provider record, in the clearance.evidence/v1 shape ([docs/evidence.md](docs/evidence.md)), hash-chained; Postgres with one writer (an advisory lock), verified from genesis on start; `clearance chain verify` offline |
| The evidence packet (C-5) | `internal/packet`, `clearance packet` | A date range and scope to canonical JSON, CSV and a PDF: the coverage statement (every coverage and assurance state, degraded windows, per-scope observation health, never a clean list on a blind window), control assertions that rest on verified fields only (SOC 2 CC8.1 and CC7.1 first, as signed OSCAL), changes with Argo CD and Terraform subjects side by side, human-cleared changes, exceptions in seven classes, and the records, inclusion proofs and checkpoint an offline verifier needs ([docs/packet.md](docs/packet.md)) |
| The offline packet verifier (C-4) | `internal/verify`, `clearance verify`, `clearance-verify` | Checks a packet with no call to Clearance: record hashes recomputed and the altered line named, the checkpoint's signatures and witness countersignatures against keys you supply (keys taken from the packet are labelled self-vouched), an inclusion proof for every record, the counted figures recounted, each attestation's Sigstore signature and Rekor proof, and a local note of checkpoints seen that catches a fork; a packet without a witnessed checkpoint reports NOT CHECKPOINTED, never a pass. Installable alone, with no core or database in its dependencies ([docs/verify.md](docs/verify.md)) |
| The evidence ledger (C-3, off unless configured) | `internal/ledger`, `cmd/clearance-witness`, `charts/clearance-witness` | A Tessera log of the chain's record hashes, checkpointed and countersigned by a witness Clearance does not operate: a truncated or rewritten ledger is refused by the witness, an altered row is named, a lost volume is rebuilt from the chain and must reach the root a witness signed, and a tier 3 change waits while evidence cannot be checkpointed ([docs/core.md](docs/core.md#the-evidence-ledger-c-3)) |
| The deployment gate | `internal/gate`, `POST /v1/clearances` | A change to a protected environment, tiered 0 to 3 from its rendered diff against a baseline a repo's `clearance.yaml` may only tighten; tiers 0 and 1 cleared by policy, 2 and 3 held for the owner group and an outside group. Which environments are protected is the deployment's list (empty: all). One state machine with `degraded` and `exception` side states, a tighten-only outage policy (0 and 1 allow-and-record, 2 and 3 hold), `deploy.exception` and `deploy.degraded` reports from providers, and admin-only break-glass recorded before it covers anything and reconciled at its TTL ([docs/gate.md](docs/gate.md)) |
| Provenance and the GitHub App | `internal/provenance`, `internal/githubapp` | Agent-identity and agent-scope verdicts for a PR from the receipts in the chain; Clearance's own GitHub App: check runs and the deployment protection rule ([docs/provenance-app.md](docs/provenance-app.md)) |
| `clearance register` | `cmd/clearance/register.go`, `register/action.yml` | A customer's CI registers what it deploys with the gate, authenticated by the workflow's GitHub Actions OIDC token; the GitHub Action builds the Go binary at its own ref |
| `clearance hold` / `release` / `report` | `cmd/clearance/terraform.go`, `internal/tfplan`, `terraform/action.yml` | A customer's CI holds a saved Terraform plan for the gate (digests computed locally, the plan never uploaded), proves it is the cleared plan before the apply, and reports the apply's outcome ([docs/terraform-gate.md](docs/terraform-gate.md)) |
| The HCP Terraform run task | `internal/hcprun`, `POST /v1/terraform/run-task` | HCP Terraform asks the gate whether a plan may be applied: the HMAC-signed request is verified, the plan JSON read with the run's token, the plan registered as a terraform-plan change, and `passed` or `failed` reported to HCP Terraform when it clears or is denied; off unless configured; not live-verified ([docs/terraform-gate.md](docs/terraform-gate.md#the-hcp-terraform-run-task-g-tf-6-built-not-live-verified)) |
| clearance-api | `internal/api`, `contract/clearance-api.json` | The read-only API over evidence, receipts and verdicts, clearances, the policy and its explainer, definitions, the signed grant feed, the record stream and the App's installations; OpenAPI 3.1 ([docs/clearance-api.md](docs/clearance-api.md)) |
| The Traefik Hub adapter (Unverified) | `internal/federate/traefikhub`, `clearance federate traefik-hub` | Reads Traefik Hub's Sovereign Trust Plane decision and access records, joins them on `trace_id`, correlates a `task_id` where it can, and records each as a claimed `federated.decision` (provider `traefik-hub`); built against the published format, no live Hub yet ([docs/federate-traefik-hub.md](docs/federate-traefik-hub.md)) |
| Who is calling | `internal/authn`, `internal/directory` | Service-account tokens by TokenReview, people's OIDC ID tokens, GitHub Actions OIDC, another cluster's workloads; groups from a Backstage catalog |

What Clearance does not hold, by design and checked by `internal/boundary`: no session store, no MCP server, no tool
registry or dispatch, no model proxy, no inbox, no runtime catalog. Those are the gateway's.

## Policy bundles

The Go core (v0.29.0) has no packs. A deployment's own policy, such as the tools only it has, the rules about them,
their argument checks, and field scope over a file its CI owns (read live from that CI system's contract), is a
**policy bundle**: a `clearance.policy/v1` JSON file the core loads from configuration (`CLEARANCE_BUNDLES`) and
names, with its version, in every decision. The deployment's other names (the on-behalf-of header, the commit-trailer
prefix, baseline deny paths, environment naming, group refs) are configuration too. The core's source carries no
platform's names; `internal/boundary` checks that. See [docs/core.md, Policy bundles](docs/core.md#policy-bundles).
Hangar's bundle ships with Autopilot (`policy/hangar/bundle.json`) and Apron deploys it.

## Tests

```shell
go test -race ./...      # the Postgres tests use CLEARANCE_TEST_DSN and skip without it
tools/fuzz-all.sh 10s
cd clients/python && pip install -e '.[test]' && CLEARANCE_BIN=... pytest -q   # the Python client, against a real core
```

No cluster is needed. `internal/profile`'s schema check compares with Autopilot's copy when `CLEARANCE_AGENT_SCHEMA`
names it (CI checks Autopilot out) and skips without it.

## Releases

A `vX.Y.Z` tag on `main`, cut after the version-bump PR merges and CI is green, runs `.github/workflows/release.yaml`:
it checks that the tag, the `VERSION` file and `CHANGELOG.md` agree (`tools/releasenotes`) and that the Python
client was generated at that version, builds the Python client's wheel and sdist, builds and pushes the multi-arch
image (SPDX SBOM, keyless cosign signature), packages and pushes the chart at the tag's version, reruns the install
test on the published chart and image, and publishes a GitHub Release whose notes are the version's section of
[CHANGELOG.md](CHANGELOG.md) (no section, no release) plus the image index and chart digests. The version-bump PR
edits `VERSION`, runs `go run ./tools/pyclient` and adds that section; `internal/release`'s test fails without it.

## History

This code was the `clearance` package inside https://github.com/jfillman/autopilot until 2026-10-29 (Hangar decision
D16); its history came with it. The Go core replaced the Python core in W1 (R-1 to R-5), and the gateway half went
back to Autopilot in R-3 (decision of 2026-11-02: Clearance decides and records, the gateway enforces). Design: Hangar's `docs/autopilot/design.md`, section 0.1.

## Docs

The TechDocs site is `mkdocs.yml` over `docs/` (home, the Go core, clearance-api, the deployment gate, the evidence
record, the provider protocol and `clearance conformance`, installing, the provenance App, the Traefik Hub adapter), published in Hangar's
portal from `catalog-info.yaml` (`backstage.io/techdocs-ref: dir:.`). Preview locally with `pip install
mkdocs-techdocs-core && mkdocs serve`.

## Specs

- [clearance-api](docs/clearance-api.md): the read API, the Go port and the design as built in Python (v0.13.0 to v0.25.0).
- [The deployment gate](docs/gate.md), [the evidence record](docs/evidence.md), [the provider protocol](docs/provider-protocol.md).

## License

Copyright 2026 James Fillman. Licensed under the [Apache License, Version 2.0](LICENSE).
See [NOTICE](NOTICE) for attribution and trademark notes, and [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute.
