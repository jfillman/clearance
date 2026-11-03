"""Fixtures for the Go port of audit.py, written and checked by the Python code itself.

  python3 python_chain.py write-v1 > python-v1.jsonl       # python-chain.jsonl extended by audit.AuditLog with v1-events.jsonl
  python3 python_chain.py project  > python-projected.jsonl # audit.project of every python-chain.jsonl row
  python3 python_chain.py verify go-extended.jsonl         # audit.verify (and the v1 schema) over a chain Go extended

python-chain.jsonl is frozen: four clearance.evidence/v0-draft records the v0-draft AuditLog wrote (git history
has that writer). It stands in for the hangar-dev rows written before the freeze, which stay as written.
v1-events.jsonl holds events and the Writer that seals each, read by this script and by evidence_test.go, so both
languages seal the same input and must produce the same bytes (TestPythonV1Identical).

Run from this directory with the repo's environment (uv run python ...); it imports src/clearance/audit.py.
"""
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
from clearance import audit  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent


def lines(p):
    # split on "\n" only: str.splitlines() also splits on U+2028, which canonical JSON writes raw.
    return [json.loads(l) for l in pathlib.Path(p).read_text(encoding="utf-8").split("\n") if l.strip()]


def writer(w):
    verified = {"gateway": audit.GATEWAY_VERIFIED, "provider": audit.PROVIDER_VERIFIED}[w.get("verified", "gateway")]
    return audit.Writer(audit.Provider(w["provider"]["name"], w["provider"]["version"]),
                        intent_capture=w.get("intent_capture", "redacted"), verified=verified)


def emit(records):
    for r in records:
        sys.stdout.buffer.write(audit.canonical(r) + b"\n")


if sys.argv[1] == "write-v1":
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "a.jsonl"
        p.write_text((HERE / "python-chain.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
        log = audit.AuditLog(p)
        for line in lines(HERE / "v1-events.jsonl"):
            log.writer = writer(line["writer"])
            log.append(line["event"])
        emit(log.records)
elif sys.argv[1] == "project":
    emit(audit.project(r) for r in lines(HERE / "python-chain.jsonl"))
elif sys.argv[1] == "verify":
    records = lines(sys.argv[2])
    ok, bad = audit.verify(records)
    msg = "ok" if ok else f"bad at {bad}"
    v1 = [r for r in records if r.get("schema") == audit.EVIDENCE_SCHEMA]
    if ok and len(sys.argv) > 3 and sys.argv[3] == "--schema":
        import jsonschema
        schema = json.loads((ROOT / "schemas" / "evidence.schema.json").read_text())
        for r in v1:
            jsonschema.validate(r, schema)
        msg += f" schema-valid-v1 {len(v1)}"
    print(msg, len(records), records[-1]["hash"] if records else audit.GENESIS)
    sys.exit(0 if ok else 1)
