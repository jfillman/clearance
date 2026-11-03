"""Write the Go engine's embedded bundles from the Python rule set, so rule text, hints and the tool registry are
the Python ones character for character:

    PYTHONPATH=src python tools/golden/export_bundle.py

internal/decide/core.json (core rules, core tools, tripwires, PR tools, lower environments) and
internal/decide/packs/hangar/hangar.json (the Hangar pack's tools and rules). The golden corpus's first line carries
the same export, and the Go replay test fails if the embedded bundles drift from it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from clearance import policy, provenance, tiers
from clearance.packs.hangar import RULES as HANGAR_RULES, TOOLS as HANGAR_TOOLS

ROOT = Path(__file__).resolve().parents[2]


def rule(r: policy.Rule) -> dict:
    return {"id": r.id, "name": r.name, "expr": r.expr, "message": r.message, "hint": r.hint, "order": r.order}


def tool(t: tiers.ToolSpec) -> dict:
    return {"name": t.name, "tier": int(t.tier), "description": t.description, "required_args": list(t.required_args),
            "github_cost": t.github_cost, "target": t.target, "propose_only": t.propose_only,
            "writes_files": t.writes_files, "reads_repo": t.reads_repo, "receipt": list(t.receipt)}


def core() -> dict:
    return {"name": "clearance-core", "rules": [rule(r) for r in policy.RULES],
            "tools": [tool(t) for t in tiers.CORE_TOOLS], "tripwires": sorted(tiers.TRIPWIRES),
            "pr_tools": list(provenance.PR_TOOLS), "lower_envs": sorted(policy.LOWER_ENVS)}


def hangar() -> dict:
    return {"name": "hangar", "rules": [rule(r) for r in HANGAR_RULES], "tools": [tool(t) for t in HANGAR_TOOLS]}


def main() -> int:
    for path, doc in ((ROOT / "internal/decide/core.json", core()),
                      (ROOT / "internal/decide/packs/hangar/hangar.json", hangar())):
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
