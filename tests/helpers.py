"""Shared test helpers: a small RFC 6962 reference tree and the real Rekor entry."""

import base64
import json
from pathlib import Path
from typing import Any

from merkle_proof import DefaultHasher

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = REPO_ROOT / "artifact.md"


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def leaves(n: int) -> list[bytes]:
    """Deterministic leaf data for a tree with n entries."""
    return [f"leaf-{i}".encode() for i in range(n)]


def tree_root(data: list[bytes]) -> bytes:
    """Merkle Tree Hash, written straight from RFC 6962 section 2.1."""
    if len(data) == 1:
        return DefaultHasher.hash_leaf(data[0])
    k = _split(len(data))
    return DefaultHasher.hash_children(tree_root(data[:k]), tree_root(data[k:]))


def inclusion_path(m: int, data: list[bytes]) -> list[bytes]:
    """Audit path for leaf m (RFC 6962 section 2.1.1)."""
    if len(data) <= 1:
        return []
    k = _split(len(data))
    if m < k:
        return inclusion_path(m, data[:k]) + [tree_root(data[k:])]
    return inclusion_path(m - k, data[k:]) + [tree_root(data[:k])]


def consistency_proof(m: int, data: list[bytes]) -> list[bytes]:
    """Proof that the first m leaves are a prefix of data (RFC 6962 2.1.2)."""

    def subproof(m: int, data: list[bytes], complete: bool) -> list[bytes]:
        n = len(data)
        if m == n:
            return [] if complete else [tree_root(data)]
        k = _split(n)
        if m <= k:
            return subproof(m, data[:k], complete) + [tree_root(data[k:])]
        return subproof(m - k, data[k:], False) + [tree_root(data[:k])]

    return [] if m in (0, len(data)) else subproof(m, data, True)


def hexlist(hashes: list[bytes]) -> list[str]:
    """Hex-encode hashes, the way the Rekor API returns them."""
    return [h.hex() for h in hashes]


def b64_to_hex(value: str) -> str:
    return base64.b64decode(value).hex()


def real_rekor_entry() -> dict[str, Any]:
    """The Rekor entry for artifact.md, rebuilt from artifact.bundle.

    The bundle stores hashes in base64, while the Rekor API returns hex,
    so they are converted to look exactly like an API response.
    """
    bundle = json.loads((REPO_ROOT / "artifact.bundle").read_text())
    tlog = bundle["verificationMaterial"]["tlogEntries"][0]
    proof = tlog["inclusionProof"]
    return {
        "body": tlog["canonicalizedBody"],
        "logIndex": int(tlog["logIndex"]),
        "verification": {
            "inclusionProof": {
                "logIndex": int(proof["logIndex"]),
                "treeSize": int(proof["treeSize"]),
                "rootHash": b64_to_hex(proof["rootHash"]),
                "hashes": [b64_to_hex(h) for h in proof["hashes"]],
            }
        },
    }
