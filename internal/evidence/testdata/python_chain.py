"""Fixtures for the Go port of audit.py, written and checked by the Python code itself.

  python3 python_chain.py write   > python-chain.jsonl   # a chain written by audit.AuditLog
  python3 python_chain.py verify  go-extended.jsonl      # audit.verify over the chain Go extended (TestExtendPythonChain)

Run from this directory; it imports src/clearance/audit.py from the repo, nothing else.
"""
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "src"))
from clearance import audit  # noqa: E402

EVENTS = [
    {"ts": "2026-11-02T10:00:00Z", "tool": "session.open", "agent": "fixture", "principal": "ns/fixture",
     "decision": "allow", "rule": None, "tier": None, "target": None, "session": "s-1", "task_id": "t-1",
     "parent": None, "args_sha256": audit.args_digest({"b": 1, "a": [1.0, 2]}), "result": "opened"},
    {"ts": "2026-11-02T10:00:01Z", "tool": "model.call", "decision": "allow", "spend": {"usd": 0.0123, "tokens": 1500},
     "ratio": 1e-05, "big": 123456789012345678901234567890, "note": "café   \U0001f600 <&> \x7f \t\n\"\\"},
    {"ts": "2026-11-02T10:00:02Z", "tool": "repo.pr.open", "effect": {"repo": "jfillman/x", "pr": 7}, "app": "x",
     "boundary": "runtime", "coverage": "observed", "nested": [[], {}, [None, True, False], {"￿": 1, "\U00010000": 2}]},
    {"ts": "2026-11-02T10:00:03Z", "tool": "deploy.request", "boundary": "deployment", "change": "c-1",
     "floats": [0.1, 1.5, 100.0, 1e-7, 2.5e-300, 9999999999999998.0]},
]

if sys.argv[1] == "write":
    with tempfile.TemporaryDirectory() as d:
        log = audit.AuditLog(pathlib.Path(d) / "a.jsonl")
        for e in EVENTS:
            log.append(e)
        sys.stdout.write((pathlib.Path(d) / "a.jsonl").read_text())
elif sys.argv[1] == "verify":
    # split on "\n" only: str.splitlines() also splits on U+2028, which canonical JSON writes raw.
    records = [json.loads(l) for l in pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").split("\n") if l.strip()]
    ok, bad = audit.verify(records)
    print("ok" if ok else f"bad at {bad}", len(records), records[-1]["hash"] if records else audit.GENESIS)
    sys.exit(0 if ok else 1)
