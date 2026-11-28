"""The golden vectors (schemas/vectors, SDK-1 refinement 7), reproduced in a second language from the stdlib alone.

internal/canon (Go) is the reference canonicalization; an SDK in any language must give the same bytes. This is
that check in Python, written from the published definition (docs/change-description.md), not from the Go code.
"""

from __future__ import annotations

import hashlib
import json

from conftest import REPO

VECTORS = REPO / "schemas" / "vectors"


def canonical(v: object) -> bytes:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def mth(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle tree hash over leaf hashes."""
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))


def item_digest(it: dict) -> bytes:
    return sha256(canonical({"type": it["type"], "id": it["id"], "op": it["op"], "fields": it.get("fields", []),
                             "attrs": it.get("attrs", {}), "hash": it.get("hash", "")}))


def root_from_proof(leaf: bytes, index: int, size: int, path: list[bytes]) -> bytes:
    """RFC 9162 section 2.1.3.2: the root an inclusion proof gives."""
    if not 0 <= index < size:
        raise ValueError("index out of range")
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            raise ValueError("proof too long")
        if fn % 2 == 1 or fn == sn:
            r = sha256(b"\x01" + p + r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = sha256(b"\x01" + r + p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("proof too short")
    return r


def test_canon_vectors():
    cases = json.loads((VECTORS / "canon-v1.json").read_text(encoding="utf-8"))["cases"]
    assert len(cases) >= 15
    for c in cases:
        out = canonical(json.loads(c["input"]))
        assert out.decode() == c["canonical"], c["name"]
        assert hashlib.sha256(out).hexdigest() == c["sha256"], c["name"]


def test_merkle_v1_vectors():
    cases = json.loads((VECTORS / "merkle-v1.json").read_text(encoding="utf-8"))["cases"]
    assert len(cases) >= 8
    proofs = 0
    for c in cases:
        d = c["description"]
        digests = [item_digest(it) for it in d["items"]]
        assert [x.hex() for x in digests] == c["itemDigests"], c["name"]
        m = mth([sha256(b"\x00" + x) for x in sorted(digests)])
        f = sha256(canonical(d["subject"].get("facts", {})))
        root = sha256(b"clearance.subject/v1" + m + f).hex()
        assert (m.hex(), f.hex(), root) == (c["itemsRoot"], c["factsDigest"], c["root"]), c["name"]
        assert d["subject"]["root"] == root and d["subject"]["rootFn"] == "merkle/1", c["name"]
        for dg, p in zip(digests, c["proofs"], strict=True):
            got = root_from_proof(sha256(b"\x00" + dg), p["index"], p["size"], [bytes.fromhex(x) for x in p["path"]])
            assert sha256(b"clearance.subject/v1" + got + bytes.fromhex(p["factsDigest"])).hex() == root, c["name"]
            proofs += 1
    assert proofs >= 20


def test_a_proof_index_out_of_range_is_refused():
    leaf = sha256(b"\x00" + sha256(b"x"))
    assert root_from_proof(leaf, 0, 1, []) == leaf
    for index, size in ((1, 1), (-1, 1), (0, 0)):
        try:
            root_from_proof(leaf, index, size, [])
        except ValueError:
            continue
        raise AssertionError(f"index {index} of {size} accepted")
