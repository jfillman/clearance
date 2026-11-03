"""Record the golden corpus: run the whole Python test suite, plus the fixture agents' calls, under the recorder.

    .venv/bin/python tools/golden/record.py          (from the repo root; HANGAR_TECH defaults to ../)

Writes testdata/golden/corpus.jsonl. The Go replay (internal/decide/golden) requires identical decisions.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main() -> int:
    os.chdir(HERE)
    sys.path[:0] = [str(HERE), str(ROOT / "src"), str(ROOT / "tests")]
    os.environ.setdefault("HANGAR_TECH", str(ROOT.parent))
    import pytest
    return pytest.main(["-q", "-p", "golden_recorder", "--rootdir", str(ROOT), "-c", str(ROOT / "pyproject.toml"),
                        str(ROOT / "tests"), str(HERE / "test_fixture_calls.py"), *sys.argv[1:]])


if __name__ == "__main__":
    sys.exit(main())
