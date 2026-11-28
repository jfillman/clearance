# The change description and subject kinds (SDK-1)

Status: **Built** (SDK-1): the description, the `clearance.kind/v1` format, the root functions and the golden
vectors, and the built-in kinds tiered through the description. **Not built yet:** loading kinds from signed policy
bundles, compiling and running their CEL, protected targets (SDK-2); the Go gate SDK (SDK-3); conformance per kind
(SDK-4); the generic CLI gate (SDK-8); the CEL library, `clearance kinds lint`, `gate test` and
`POST /v1/clearance-policy/explain` (SDK-9). Until SDK-2, the core tiers only its built-in kinds, `manifest-tree` and
`terraform-plan`, and a third party cannot add one.

A **subject kind** is what a change binds to: a rendered manifest tree, a saved Terraform plan, a database
migration. (Glidepath's **change kinds**, which pick the CI gates a pull request runs, are a different thing; this
page means subject kinds throughout.) Until SDK-1 the subject kinds were a closed list in the core's code. SDK-1
makes a change one shape whatever its subject kind, and a subject kind a document: a schema and CEL, never an
executable.

## Placeholder names

Two names in this format wait for Clearance's own product domain (Y-55; N-7 renames the API group and predicate
domain), and both are set in one file, `schemas/naming.go`:

- **The schema base URL**, `SchemaBase`, now `https://clearance.hangarplatform.dev/schemas/`. It is a **placeholder**.
  The `$id` of `change-description.schema.json` and `kind.schema.json` is `SchemaBase + name + "/v1.json"`, and the
  contract's `x-clearance-published-schemas` is read from those files. `TestTheSchemaIDsComeFromTheBase` and
  `TestContractIsCurrent` fail when either drifts from the constant.
- **The first-party kind prefix**, `FirstPartyPrefix`, now `dev.clearance.`. It is a **placeholder**.

The switch: edit `schemas/naming.go`, run `go test ./schemas -update` (it rewrites the two `$id`s), then
`go generate ./internal/server`. The schemas published before SDK-1 keep their own `$id` until N-7.

## The description

`schemas/change-description.schema.json` (`clearance.change-description/v1`), `internal/describe`, and in the core's
contract as the `DescribeDescription` component (listed under `x-clearance-published-schemas`;
`TestPublishedSchemasMatchTheContract` holds the two equal):

```json
{
  "subject": {"kind": "io.example.db-migration", "version": 1, "rootFn": "merkle/1",
              "root": "<sha256>", "facts": {"engine": "postgres"}},
  "target": {"scope": "db-main", "environment": "prod"},
  "items": [
    {"type": "table", "id": "public.users", "op": "update", "fields": ["/columns/email"],
     "attrs": {"rows": 1200}, "hash": "<sha256 of the item's redacted content>"}
  ],
  "source": {"repo": "example/migrations", "commit": "<40 hex>", "pr": 3},
  "describedBy": {"provider": "example-gate", "version": "1.0.0"}
}
```

| Member | What it is |
|---|---|
| `subject.kind`, `subject.version` | The subject kind (reverse-DNS, `io.acme.db-migration`; the built-in kinds keep their names) and the kind's version. |
| `subject.rootFn`, `subject.root` | The root function the kind declares and the root it gives (bare lowercase hex sha256). |
| `subject.facts` | Change-level facts the kind's `subjectSchema` declares: Terraform's workspace, versions, `-target`. |
| `target` | `scope` (a cluster, an account, a database; empty when there is none), `environment`, and `app`, whose owner group clears the change. |
| `items[]` | One per thing the change touches: `type` (as the kind's `itemTypes` name it), `id` (unique per type), `op` (`create`, `update`, `delete`, `replace`, nothing else), `fields` (JSON pointers of what an update changes: names, never values), `attrs` (only what the kind declares for the type), `hash` (the item's content hash, when there is one). |
| `source` | The repository, the commit, the base, the pull request (0 or absent: a pushed commit). |
| `describedBy` | The provider that described the change, and its version. `clearance-core` means the core mapped a built-in kind's request. |

**The core derives every summary from the items** (create, update, delete and replace counts, and the ids deleted)
and never takes one from a caller, so a summary cannot say something the items do not. Parsing is strict: unknown
members are refused, and so is an item listed twice. An optional member is absent or has a value: `null` is refused,
as the schema refuses it. `fields` are RFC 6901 JSON pointers (`~` only as `~0` or `~1`). A number with no finite
value (`1e400`) is refused. Facts and attrs are hashed in the form they are written in (a Go `float64(1)` hashes as
the `1` it serializes to), so a `merkle/1` root a gate computes is the root the core recomputes. (`tree/1` and
`plan/1` roots are carried: the core checks their form only, as the table below says.) Kind versions run from 1 to
1048576. Limits: 2000 items (a larger change will page its items;
`merkle/1` makes that possible, paging is not built), 400 fields per item, 64 attrs and 64 facts.

## Root functions

A subject's root is computed by the root function its kind declares, and the description names it. A kind changes
its root function only through a new kind version, never in place, so a recorded root keeps its meaning.

| Root function | Kinds | Root | Recomputed by the core |
|---|---|---|---|
| `merkle/1` | every new kind | `sha256("clearance.subject/v1" ‖ M ‖ F)` | yes, from the items and facts |
| `tree/1` | `manifest-tree` | the [manifest-tree digest](gate.md#the-manifest-tree-digest-built), unchanged | no: it is the digest of the whole render, the items are the objects that change |
| `plan/1` | `terraform-plan` | `planDigest`, the sha256 of the saved plan file, unchanged | no: the core holds no plan file |

**`merkle/1`**, byte for byte:

1. Each item's digest is the sha256 of the canonical JSON (below) of the item with all six members present:
   `{"attrs": {}, "fields": [], "hash": "", "id": ..., "op": ..., "type": ...}` when empty. An absent member and an
   empty one hash the same.
2. `M` is the RFC 6962 Merkle tree hash over the item digests sorted byte-wise, each taken as an RFC 6962 leaf
   (`sha256(0x00 ‖ digest)`; interior nodes `sha256(0x01 ‖ left ‖ right)`; no items: `sha256("")`). The order a gate
   lists items in does not matter; two items with one digest are refused.
3. `F` is the sha256 of the canonical facts, or of `{}` when there are none.
4. The root is the hex sha256 of the 20 ASCII bytes `clearance.subject/v1`, then the 32 bytes of `M`, then the 32
   bytes of `F`.

An item's inclusion is proved against a cleared root by its index among the sorted digests, the tree size, the RFC
6962 audit path, and `F` (`Description.ProveItem`, `describe.VerifyItem`). A platform that enforces per item, such as
admission, holds only the item and its proof. Per-item enforcement itself is not built (it is W-34 X3's).

## Canonicalization and the golden vectors

Everything that hashes uses `internal/canon`, the canonical JSON the evidence chain already uses: Python's
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`, keys sorted by code point, floats as
Python's `repr`, only `"`, `\` and control characters escaped. It is the reference.

`schemas/vectors/canon-v1.json` and `schemas/vectors/merkle-v1.json` are the golden vectors every SDK, in any
language, must reproduce byte for byte: canonical JSON and its sha256 for inputs given as JSON text (number literals
are part of a case), and for `merkle/1` the item digests, `M`, `F`, the root and every item's inclusion proof.
`internal/describe` checks them in Go; `clients/python/tests/test_vectors.py` checks them again in Python from the
standard library alone, written from this page. A vector is added, never changed: a changed value breaks every SDK.

## `clearance.kind/v1`

`schemas/kind.schema.json`, `internal/kinds`. A worked third-party kind:

```json
{
  "apiVersion": "clearance.kind/v1",
  "name": "io.example.db-migration",
  "version": 1,
  "root": "merkle/1",
  "defaultTier": 1,
  "itemTypes": [
    {"type": "table", "attrs": {"type": "object", "additionalProperties": false,
                                "properties": {"rows": {"type": "integer", "minimum": 0}}}},
    {"type": "index", "ops": ["create", "delete"]},
    {"type": "grant.*"}
  ],
  "subjectSchema": {"type": "object", "additionalProperties": false, "required": ["engine"],
                    "properties": {"engine": {"enum": ["postgres", "mysql"]}, "targeted": {"type": "boolean"}}},
  "itemRules": [
    {"name": "db:drop", "types": ["table"], "when": "item.op == 'delete'", "tier": 3, "class": ["data-integrity"]},
    {"name": "db:index", "types": ["index"], "when": "true", "tier": 2}
  ],
  "changeRules": [
    {"name": "db:targeted", "when": "change.subject.facts.targeted", "raise": 1, "floor": 2}
  ],
  "consistency": [
    {"name": "db:engine", "expr": "has(change.subject.facts.engine)", "message": "the engine is named"}
  ],
  "tests": [
    {"name": "a drop is tier 3", "description": {}, "expect": {"tier": 3, "rules": ["db:drop"]}}
  ]
}
```

- **`name`** is reverse-DNS. `dev.clearance.*` is reserved for first-party kinds. **It is a placeholder** for the
  reversed product domain, which the owner has not decided yet (`kinds.FirstPartyPrefix`, set in
  `schemas/naming.go`).
  `manifest-tree` and `terraform-plan` are the built-in kinds' names.
- **`root`** is `merkle/1` for every kind but the built-ins: `manifest-tree` version 1 declares `tree/1`, and
  `terraform-plan` version 1 declares `plan/1`.
- **`itemTypes`** lists the types an item may have, as fnmatch globs if needed (`aws_iam_*`), each with the ops it
  allows (default: all four) and the JSON Schema (2020-12) of its `attrs`, an object schema with
  `"additionalProperties": false`. A type with no `attrs` schema takes none. `"*"` is allowed only with a
  `defaultTier` of at least 2, so an unexpected type is never cleared by policy.
- **Items not in the kind are refused.** An item whose type the kind does not list, whose op is not one of the four
  (or not one its type allows), or whose attrs the schema does not declare, is refused `DG-UNBOUND`
  (`Compiled.Bind`). It is never given `defaultTier`, so a mapping bug cannot under-tier a change.
- **`subjectSchema`** is the JSON Schema of `subject.facts`, an object schema that refuses undeclared facts. A schema
  may not reference anything outside itself.
- **`defaultTier`** is the tier of a known item no item rule fires on: 1, 2 or 3, never 0.
- **`itemRules`**: CEL over `item` and `change`. An item's tier is the highest tier of the rules that fire on it, or
  `defaultTier` when none does. `types` limits a rule to some item types. `class` names operational classes from
  I-1's versioned list (checked at load by SDK-2).
- **`changeRules`**: CEL over the whole description. They run after the item maximum and only raise it. A rule with
  `tier` makes the change at least that tier (1 to 3). The rules with `raise` that fire then lift it by their largest
  `raise`, to at least their largest `floor`, at most 3. Terraform's "`-target`: one tier up, at least 2" is
  `{"raise": 1, "floor": 2}`. A change rule never lowers a tier, and the core invariants run last.
- **`consistency`**: CEL that must hold, or the description is refused with `message`.
- **`tests`**: fixture tests, a description and the tier and rules it must give, or the refusal it must get. SDK-9
  runs them.
- **`builtin: true`** says the kind's tiers are the core's Go code, not rules. Only a built-in kind may say so, and
  then it has no rules. SDK-6 moves Terraform's tier table into rules and drops it.

`kinds.Parse` checks everything here that needs no CEL: names, the root function, the types and globs, the schemas
(they compile), tiers, the shape of every rule, and rule names unique across the kind. It returns `DG-KIND` for a
malformed kind. Compiling and evaluating the CEL, loading a kind from a signed policy bundle, and the trust rules for
third-party signers are SDK-2.

## The built-in kinds on the description

The embedded first-party kinds are `internal/kinds/builtin/manifest-tree.json` and `terraform-plan.json`. A verifier
still registers in the request it always sent (`schemas/change-request.schema.json`). The core maps the request onto a
description (`internal/gate` `Describe`) and tiers its items:

| | manifest-tree | terraform-plan |
|---|---|---|
| item | an object the change adds, changes or removes (`create`, `update`, `delete`); an object listed as `unchanged` is in the tree, not the change, and is not an item | a resource change; `no-op` and `read` change nothing and are not items |
| `type`, `id` | `apiVersion/Kind`, `namespace/name` (the name alone when cluster-scoped; `/` and `~` inside a part are escaped as in a JSON pointer, `~1` and `~0`, which no real object needs) | the resource type, the address |
| `op` | `added`, `changed`, `removed` as `create`, `update`, `delete` | `delete` for a destroy, `replace` for either replace order |
| `attrs` | `images`; `digest` only when the object's digest is not a bare sha256 (a sha256 is the item's `hash`) | `actions` (Terraform's list), `actionReason` |
| facts | none | `workspace`, `versions`, `targeted`, `planJsonDigest`, `variableSetDigest` |
| root | `tree/1`: the request's `treeDigest` | `plan/1`: `planDigest` |

There is no behaviour change. `testdata/golden/subjects.jsonl` holds 56 manifest-tree and terraform-plan
registrations recorded at v0.57.3, before the mapping: each one's tier, decision, reasons, why, requirement, change id,
recorded subject and token subjects. `TestSubjectCorpus` replays them through the mapping and fails on any
difference. `TestTheBuiltinKindsMapOntoTheDescription` checks that every mapped description is valid, matches the
schema, binds to its built-in kind and maps back to exactly what tiering reads. The one visible difference: a
terraform-plan change stores the summary the core derives, so its `destroyedAddresses` are in resource order rather
than the order the caller sent. The caller's summary is still required and still refused when it differs.

An agent definition's release (`definition`) is not on the description. `review.Classify` tiers it as before.

The evidence record's subject (`{kind, name, digests}`) is unchanged. For a built-in kind the root function is fixed
by the kind and its version 1, so a record names it implicitly. The record field for the kind's version and pack
digest is SDK-2's.

### Replaying a chain

`TestReplayStoredChanges` re-describes and re-tiers a live core's recorded changes. Export the changes table and
point the test at it:

```sh
psql "$DSN" -Atc "select record from changes" > changes.jsonl
CLEARANCE_SUBJECT_REPLAY=$PWD/changes.jsonl go test -run TestReplayStoredChanges -v ./internal/gate
```

Every manifest-tree and terraform-plan change must give its stored root, tier and reasons under the lab baseline. A
change registered with a `clearance.yaml` or a provenance reason is skipped and counted, because neither is stored in
full. A change re-tiered under an older baseline shows as a difference to read, not as a mapping failure. The replay
over hangar-dev's and hangar-prod's recorded changes is still owed. Then `clearance chain verify` over the same chain
(SDK-1 writes nothing to it).
