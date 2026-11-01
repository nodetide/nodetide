"""Merkle tree over event hashes (RFC 6962 style), for committing to a prefix of an identity's content events.

Leaves are 32-byte hashes; a leaf is hashed as sha256(0x00 || leaf), an inner node as sha256(0x01 || left || right).
The tree over n leaves splits at the largest power of two below n, so a proof is O(log n) and a prefix has one root.
"""

from __future__ import annotations

import hashlib

EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def _leaf(h: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + h).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return _leaf(leaves[0])
    k = _split(len(leaves))
    return _node(_root(leaves[:k]), _root(leaves[k:]))


def merkle_root(hashes: list[str]) -> str:
    """Root (hex) over event hashes (hex)."""
    if not hashes:
        return EMPTY_ROOT
    return _root([bytes.fromhex(h) for h in hashes]).hex()


def _path(leaves: list[bytes], index: int) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return _path(leaves[:k], index) + [_root(leaves[k:])]
    return _path(leaves[k:], index - k) + [_root(leaves[:k])]


def merkle_proof(hashes: list[str], index: int) -> list[str]:
    """Audit path (hex siblings, leaf upwards) for the leaf at `index`."""
    if not 0 <= index < len(hashes):
        raise IndexError("no such leaf")
    return [p.hex() for p in _path([bytes.fromhex(h) for h in hashes], index)]


def verify_proof(leaf_hash: str, index: int, count: int, path: list[str], root: str) -> bool:
    """Does `leaf_hash` sit at `index` of a tree of `count` leaves with the given root?"""
    if not 0 <= index < count or not isinstance(path, list):
        return False
    try:
        siblings = [bytes.fromhex(p) for p in path]
        node = _leaf(bytes.fromhex(leaf_hash))
    except ValueError:
        return False

    def climb(index: int, count: int, siblings: list[bytes]) -> bytes | None:
        # walk down to know the shape, then fold the siblings back up
        if count == 1:
            return node if not siblings else None
        if not siblings:
            return None
        k = _split(count)
        *rest, top = siblings
        if index < k:
            sub = climb(index, k, rest)
            return None if sub is None else _node(sub, top)
        sub = climb(index - k, count - k, rest)
        return None if sub is None else _node(top, sub)

    computed = climb(index, count, siblings)
    return computed is not None and computed.hex() == root
