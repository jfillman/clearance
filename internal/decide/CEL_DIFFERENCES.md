# Where cel-python and cel-go differ, and where Python and Go differ

Status: Built (R-1a). Evidence: `go test ./internal/decide/...` over `testdata/golden/corpus.jsonl` (749 lines,
recorded by `tools/golden/record.py` from the whole Python test suite plus `tools/golden/test_fixture_calls.py`).

## 1. Rules: none evaluates differently

No rule needed a change. Every rule in the core set (R001-R020) and the Hangar pack (R021-R023), and R000,
evaluates identically under cel-go for every request in the corpus. The reason is structural: the Go engine
declares every CEL variable with its type (`tool.tier int`, `effective.tools list(string)`, `ctx.repo_ok bool`,
...) and type-checks every rule at load, and the request's fields are typed, so a rule only ever sees the types
cel-python sees for the same request.

The edges were probed with targeted corpus cases (`tools/golden/test_fixture_calls.py`):

| Edge | Probe | Result |
|---|---|---|
| Integer overflow | definitions with `toolCalls` 2^63, 2^63-1, `githubCalls` 2^64, `openPrs` 2^63+5 | identical: celpy's `json_to_cel` raises `ValueError('overflow')` outside int64 (R000 "ValueError"); Go holds budgets exactly (`Int`) and fails the same way; 2^63-1 is allowed by both |
| Model-token estimates past int64 | `est_tokens` 10^30, 2^63, 2^63-1, -1 | identical (M007; compared exactly, not in CEL) |
| int vs double vs bool | `limit: 5.0`, `sinceHours: true`, `timeoutSeconds: 10**30` | identical (bad arguments, R008) |
| `in` on a list | `!(tool.name in effective.tools)` over every fixture agent's tools | identical |
| Strings | trailing newline in repo, path and app (`$` in `re.match`), `İ` and final `Σ` lowercasing in `app`, `\x1c`/`　` in `strip()`, code-point `len` of a 1 MiB+1 artifact | identical |
| Map/list equality | YAML field diffs: `1` vs `1.0`, `yes` vs `true`, NaN in and out of lists, merge keys, duplicate keys, `{1: x, true: y}` | identical |
| Timestamps | YAML dates and datetimes with offsets, naive vs aware | identical |
| Null | `a: ~` vs `a: null`, `"tier_ceiling": ""` in requested limits | identical |

## 2. Ill-typed contexts: the only cel-python / cel-go differences

A Python context altered by hand after `build_context` (as `tests/test_policy.py` does to prove R000) can put a
value of the wrong type under a variable. A Go request cannot carry these (its fields are typed), so they are not
reachable through `POST /access/v1/evaluation`; they are replayed through `Engine.EvaluateActivation` by
`TestCELTypeProbes`, which requires the Go engine never to allow what Python denies. Nothing was changed in the
rules for them: under typed requests they cannot occur.

| Rule reached | Altered value | cel-python | cel-go | Note |
|---|---|---|---|---|
| R007 `tool.tier > effective.tier` | `tool.tier = True` | allow (bool compared as a number) | deny R000 (no `bool > int` overload) | Python fails open here; Go fails closed |
| R008 `ctx.missing_args > 0` | `ctx.missing_args = False` | allow | deny R000 | Python fails open here; Go fails closed |
| R006 `!(tool.name in effective.tools)` | `tool.name = 5` | deny R000 | deny R006 (heterogeneous `in` is false) | both deny |
| R006 | `effective.tools = "catalog.read"` (a string) | deny R006 | deny R000 (no `in` on a string) | both deny |
| R000 | `tool.tier = None`, `ctx.known = None` | deny R000 | deny R000 | identical |
| R007 | `tool.tier = 1.5` | deny R007 | deny R007 (cross-type numeric comparison) | identical |
| R009 | `session.tool_calls_left = 0.5` or `-2**63` | deny R009 | deny R009 | identical |
| R000 | `tool.tier = 2**63` | deny R000 ValueError | deny R000 ValueError | identical |
| R019 | `ctx.artifact_bytes = 1048577.0` | deny R019 | deny R019 | identical |

R000's message names the Python exception class (`CELEvalError` for a rule that fails to evaluate, including the
cost limit; `ValueError` for a value the policy cannot hold), so records read the same whichever engine decided.

## 3. Where the Python engine raises and the Go engine decides

These inputs make the Python gateway raise an uncaught exception (an HTTP 500 and no record), so they cannot be in
the corpus. The Go engine fails closed instead, and the R-1d route records the decision.

| Input | Python | Go |
|---|---|---|
| A YAML date that does not exist (`a: 2024-02-30`) in a file's `before`/`content` | `ValueError` from PyYAML, uncaught | deny R000 "ValueError" (tested: `TestNonYAMLErrorFailsClosed`; the corpus probe asserts the Python raise) |
| A YAML document past 200,000 nodes (an alias bomb) or nested past 256 | evaluates (slowly) or `RecursionError` | deny R000 "ValueError" (never treated as unparseable, which would skip field scope) |
| Requested limits of the wrong JSON type (`"tool_calls": "x"`, `"tools": "abc"`, `"tier_ceiling": "T9"`, a non-object) | `TypeError`/`KeyError` uncaught, or coerced (`True` as 1, a string as its characters) | deny R008 with a message naming the field |
| Arguments that are not a JSON object | `AttributeError` uncaught | the request does not decode (400) |
| A lone surrogate (`"\ud800"`) in arguments | `UnicodeEncodeError` hashing the arguments, uncaught | encoding/json reads it as U+FFFD; decided normally |
| `!!binary`, `!!set`, `!!omap`, `!!pairs` tags in YAML | constructed | treated as a YAML error (file unparseable for field scope; a whole-file GP-SCOPE-001 for cicd.yaml) |
| An fnmatch class Go's regexp cannot compile (a reversed range `[z-a]`) in an app allowlist | Python drops the empty range | matches nothing (the schema forbids `[` in app patterns) |
