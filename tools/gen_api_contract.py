#!/usr/bin/env python3
"""Write contract/clearance-api.json from clearance.api.ROUTES (docs/clearance-api.md "The contract").

    python3 tools/gen_api_contract.py           write it
    python3 tools/gen_api_contract.py --check   exit 1 if the committed file is stale (CI, tests/test_api.py)
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from clearance.api import contract  # noqa: E402

OUT = ROOT / "contract" / "clearance-api.json"


def render() -> str:
    return json.dumps(contract(), indent=2, sort_keys=False) + "\n"


if __name__ == "__main__":
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != render():
            print(f"{OUT.relative_to(ROOT)} is stale: run python3 tools/gen_api_contract.py and commit it")
            sys.exit(1)
        print(f"{OUT.relative_to(ROOT)} is current")
    else:
        OUT.write_text(render())
        print(f"wrote {OUT.relative_to(ROOT)}")
