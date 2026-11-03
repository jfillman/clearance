"""Hash-chained audit log.

Each record carries the hash of the one before it, so editing, deleting or reordering a
record breaks the chain. That proves consistency, not completeness: truncating the tail
leaves a valid chain. Completeness comes from anchoring `checkpoint()` somewhere the
writer cannot rewrite (WORM storage, the self-hosted Rekor) and comparing later.

Arguments are never stored, only their hash, so a secret that slips into a tool call
does not land in the log.

Each record is a clearance.evidence/v1 record (schemas/evidence.schema.json, docs/evidence.md): the event's own
fields, flat, plus the envelope built here and nowhere else in Python (`seal`): `schema`, `boundary` (`runtime`, or
`deployment` for the gate's deploy.* records), `coverage`, `provider` (the registered provider that wrote it), `subject`
(what the record is about: its kind and digests), `intent` when the event has one (redacted by default), and the
`verified` / `claimed` tag lists: a field is verified when the writer established it itself, claimed when something
else asserted it. The assurance state (whether a record's hash has reached a witnessed checkpoint) changes after the
record is written, so it is kept beside the record, never inside the hash.

v1 is a superset of the v0-draft envelope the first 612 hangar-dev records carry, and the chain rule is the same for
both: those rows stay exactly as written (they are hashed) and `project` gives a reader their v1 shape.
The Go core builds the same bytes for the same event (internal/evidence); internal/evidence/testdata holds the check.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
EVIDENCE_SCHEMA = "clearance.evidence/v1"
SCHEMA_V0 = "clearance.evidence/v0-draft"
SCHEMAS = (SCHEMA_V0, EVIDENCE_SCHEMA)
BOUNDARIES = ("runtime", "deployment")
COVERAGE = ("authorized-and-verified", "observed-not-attributed", "out-of-band-detected", "coverage-unavailable")
ASSURANCE = ("checkpointed", "recorded-not-checkpointed", "not-recorded")
SUBJECT_KINDS = ("tool-call", "manifest-tree", "terraform-plan", "definition")
INTENT_CAPTURE = ("redacted", "full")
# What the gateway establishes itself for a runtime decision: the caller (authenticated), the session and run tree
# it issued, the decision it made, the hash of the arguments it saw, and the effect of a write it made itself (the
# receipt of a PR its own call opened: provenance.py). The v0-draft set, unchanged.
VERIFIED = frozenset({"ts", "task_id", "session", "parent", "principal", "agent", "tool", "tier", "decision",
                      "rule", "target", "args_sha256", "result", "effect", "app"})
# v1 adds provider, which the writer sets from its own registration, never from the event.
GATEWAY_VERIFIED = VERIFIED | {"provider"}
# A registered provider's own records (the core's POST /v1/records): only who sent them is the core's to verify.
PROVIDER_VERIFIED = frozenset({"provider"})
# Not tagged: the chain's own fields and the tag lists themselves.
ENVELOPE = frozenset({"seq", "schema", "boundary", "coverage", "verified", "claimed", "prev_hash", "hash"})
# What an event may not set: the envelope except boundary and coverage, and the writer's provider.
RESERVED = (ENVELOPE - {"boundary", "coverage"}) | {"provider"}
# Read-side annotations a reader adds beside a record (the api): never stored, never hashed.
ANNOTATIONS = frozenset({"assurance", "projected"})
# Every v0-draft row was written by the Python gateway process (gateway, gate and App webhook in one process),
# which named no version.
V0_PROVIDER = {"name": "autopilot-gateway", "version": "unrecorded"}
MAX_INTENT = 64 << 10

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_DIGEST_ALG = re.compile(r"[A-Za-z][A-Za-z0-9]{0,31}")
_PROVIDER_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}")


@dataclass(frozen=True)
class Provider:
    """The registered provider a record names: who wrote it, at what version."""
    name: str
    version: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version}


@dataclass(frozen=True)
class Writer:
    """How a writer seals its events: its provider, intent capture (redacted unless the deployment opts in to full)
    and the fields it establishes itself (verified; every other field is claimed)."""
    provider: Provider
    intent_capture: str = "redacted"
    verified: frozenset[str] = GATEWAY_VERIFIED

    def __post_init__(self):
        if not (isinstance(self.provider.name, str) and _PROVIDER_NAME.fullmatch(self.provider.name)):
            raise ValueError(f"provider name {self.provider.name!r} is not a lowercase name")
        if not (isinstance(self.provider.version, str) and 0 < len(self.provider.version) <= 64):
            raise ValueError("provider version is 1 to 64 characters")
        if self.intent_capture not in INTENT_CAPTURE:
            raise ValueError(f"intent capture is one of {', '.join(INTENT_CAPTURE)}")


def gateway_writer() -> Writer:
    """The Python gateway's writer: provider autopilot-gateway at this package's version."""
    from . import __version__
    return Writer(Provider("autopilot-gateway", __version__))


def _hex(v: Any, pat: re.Pattern) -> bool:
    return isinstance(v, str) and pat.fullmatch(v) is not None


def derive_subject(r: dict[str, Any]) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
    """What a record is about when its writer did not say, and the fields that came from: a gate record's change
    (its rendered tree, and the commit), an agent definition the gateway loaded (the digest of its pin), or the
    gateway call itself (the tool and the digest of its arguments). A deployment record with no tree (an
    unregistered deployment, or a change registered without a tree) has none."""
    ch = r.get("change")
    if isinstance(ch, dict) and _hex(ch.get("tree"), _HEX64) and ch["tree"] != GENESIS:
        d = {"sha256": ch["tree"]}
        if _hex(ch.get("head"), _HEX40):
            d["gitCommit"] = ch["head"]
        s: dict[str, Any] = {"kind": "manifest-tree", "digests": d}
        if isinstance(ch.get("app"), str) and isinstance(ch.get("env"), str):
            s["name"] = f"{ch['app']}/{ch['env']}"
        return s, ("change",)
    if r.get("boundary", "runtime") != "runtime":
        return None, ()
    tool, a = r.get("tool"), r.get("args_sha256")
    if not (isinstance(tool, str) and tool and _hex(a, _HEX64)):
        return None, ()
    if tool.startswith("definition."):
        name = r.get("target") if isinstance(r.get("target"), str) and r.get("target") else tool
        return {"kind": "definition", "name": name, "digests": {"sha256": a}}, ("tool", "target", "args_sha256")
    return {"kind": "tool-call", "name": tool, "digests": {"sha256": a}}, ("tool", "args_sha256")


def check_subject(s: Any) -> None:
    """An event's own subject: null, or {kind, digests[, name]}."""
    if s is None:
        return
    if not isinstance(s, dict) or set(s) - {"kind", "name", "digests"} or "kind" not in s or "digests" not in s:
        raise ValueError("subject is {kind, digests[, name]}")
    if s["kind"] not in SUBJECT_KINDS:
        raise ValueError(f"subject kind is one of {', '.join(SUBJECT_KINDS)}")
    if "name" in s and not (isinstance(s["name"], str) and 0 < len(s["name"]) <= 1024):
        raise ValueError("subject name is a non-empty string")
    d = s["digests"]
    if not isinstance(d, dict) or not d or len(d) > 16:
        raise ValueError("subject digests is a non-empty object")
    for k, v in d.items():
        if not _DIGEST_ALG.fullmatch(k) or not (isinstance(v, str) and 0 < len(v) <= 256):
            raise ValueError(f"subject digest {k!r} is not an algorithm name with a string value")


def intent_of(text: Any, capture: str) -> dict[str, Any]:
    """An event's intent (free text from the agent or the change): redacted keeps only its digest; full keeps it."""
    if not isinstance(text, str) or len(text.encode()) > MAX_INTENT:
        raise ValueError(f"intent is a string of at most {MAX_INTENT} bytes")
    out: dict[str, Any] = {"capture": capture, "sha256": hashlib.sha256(text.encode()).hexdigest()}
    if capture == "full":
        out["text"] = text
    return out


def evidence(event: dict[str, Any], writer: Writer) -> dict[str, Any]:
    """The v1 envelope for an event: what `seal` adds to the event's own fields (and the intent it replaces)."""
    bad = RESERVED & set(event)
    if bad:
        raise ValueError(f"event must not set {sorted(bad)}")
    boundary, coverage = event.get("boundary", "runtime"), event.get("coverage", "authorized-and-verified")
    if boundary not in BOUNDARIES:
        raise ValueError(f"boundary is one of {', '.join(BOUNDARIES)}")
    if coverage not in COVERAGE:
        raise ValueError(f"coverage is one of {', '.join(COVERAGE)}")
    if "subject" in event:
        check_subject(event["subject"])
        subject, subject_verified = event["subject"], "subject" in writer.verified
    else:
        subject, sources = derive_subject(event)
        subject_verified = set(sources) <= writer.verified
    env: dict[str, Any] = {"schema": EVIDENCE_SCHEMA, "boundary": boundary, "coverage": coverage,
                           "provider": writer.provider.as_dict(), "subject": subject}
    if "intent" in event:
        env["intent"] = intent_of(event["intent"], writer.intent_capture)
    fields = sorted((set(event) | {"provider", "subject"}) - ENVELOPE)
    tag = {k: (subject_verified if k == "subject" else k in writer.verified) for k in fields}
    env["verified"] = [k for k in fields if tag[k]]
    env["claimed"] = [k for k in fields if not tag[k]]
    return env


def seal(seq: int, prev_hash: str, event: dict[str, Any], writer: Writer) -> dict[str, Any]:
    """The record after `prev_hash`: {"seq", **event, **evidence(event), "prev_hash"} plus its hash. The one place a
    Python writer builds a record (AuditLog, pg.PgAuditLog)."""
    rec = {"seq": seq, **event, **evidence(event, writer), "prev_hash": prev_hash}
    rec["hash"] = sha256_hex(canonical(rec))
    return rec


def project(r: dict[str, Any]) -> dict[str, Any]:
    """A stored record as a reader sees it, in the v1 shape whatever it was written as. A v0-draft row is left as
    written (it is hashed) and gains provider and subject, derived the way a v1 writer would, named in `projected`
    so a reader knows the api supplied them and the hash does not cover them. A v1 record gains `projected: []`."""
    out = dict(r)
    added: list[str] = []
    if r.get("schema") == SCHEMA_V0:
        if "provider" not in out:
            out["provider"] = dict(V0_PROVIDER)
            added.append("provider")
        if "subject" not in out:
            out["subject"] = derive_subject(r)[0]
            added.append("subject")
    out["projected"] = added
    return out


def stored(r: dict[str, Any]) -> dict[str, Any]:
    """`project`'s inverse for a hash check: the record without the read-side annotations and projected fields."""
    drop = ANNOTATIONS | set(r.get("projected") or ())
    return {k: v for k, v in r.items() if k not in drop}


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def args_digest(args: Any) -> str:
    return sha256_hex(canonical(args))


def iso(dt: datetime) -> str:
    """The one timestamp format records (and anything that names a session's expiry) use."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Checkpoint:
    count: int
    head: str


class AuditLog:
    def __init__(self, path: str | Path | None = None, writer: Writer | None = None):
        self.path = Path(path) if path else None
        self.writer = writer or gateway_writer()
        self.records: list[dict[str, Any]] = []
        if self.path and self.path.exists():
            # split on "\n" only: str.splitlines() also splits on U+2028, which a psql dump of jsonb writes raw.
            self.records = [json.loads(l) for l in self.path.read_text(encoding="utf-8").split("\n") if l.strip()]
            ok, bad = verify(self.records)
            if not ok:
                raise ValueError(f"audit log {self.path} is corrupt at record {bad}")

    @property
    def head(self) -> str:
        return self.records[-1]["hash"] if self.records else GENESIS

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        rec = seal(len(self.records), self.head, event, self.writer)
        self.records.append(rec)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
        return rec

    def checkpoint(self) -> Checkpoint:
        return Checkpoint(len(self.records), self.head)

    def receipts(self, repo: str, pr: int, tools: tuple[str, ...]) -> list[dict[str, Any]]:
        """The records whose effect is opening PR `pr` on `repo` (provenance.py)."""
        return [r for r in self.records if r.get("tool") in tools and (r.get("effect") or {}).get("repo") == repo
                and (r.get("effect") or {}).get("pr") == pr]


def verify(records: list[dict[str, Any]]) -> tuple[bool, int | None]:
    """Return (ok, index of the first bad record)."""
    prev = GENESIS
    for i, r in enumerate(records):
        if r.get("seq") != i or r.get("prev_hash") != prev:
            return False, i
        body = {k: v for k, v in r.items() if k != "hash"}
        if sha256_hex(canonical(body)) != r.get("hash"):
            return False, i
        prev = r["hash"]
    return True, None


def verify_against(records: list[dict[str, Any]], anchored: Checkpoint) -> tuple[bool, str]:
    """Check a log against a checkpoint that was anchored earlier and elsewhere."""
    ok, bad = verify(records)
    if not ok:
        return False, f"chain broken at record {bad}"
    if len(records) < anchored.count:
        return False, f"truncated: {len(records)} records, anchored {anchored.count}"
    if records[anchored.count - 1]["hash"] != anchored.head:
        return False, "history rewritten: anchored head does not match"
    return True, "ok"
