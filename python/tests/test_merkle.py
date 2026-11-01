import hashlib

import pytest

from nodetide.core.merkle import EMPTY_ROOT, merkle_proof, merkle_root, verify_proof


def hashes(n):
    return [hashlib.sha256(str(i).encode()).hexdigest() for i in range(n)]


def test_empty_and_single():
    assert merkle_root([]) == EMPTY_ROOT
    h = hashes(1)
    assert merkle_proof(h, 0) == [] and verify_proof(h[0], 0, 1, [], merkle_root(h))


@pytest.mark.parametrize("n", [2, 3, 4, 5, 7, 8, 9, 16, 17, 33])
def test_every_leaf_proves_and_nothing_else_does(n):
    # (the tree size is bound by the signed commitment {count, root}, not by the root alone)
    h = hashes(n)
    root = merkle_root(h)
    for i in range(n):
        path = merkle_proof(h, i)
        assert verify_proof(h[i], i, n, path, root)
        assert not verify_proof(h[(i + 1) % n], i, n, path, root) or n == 1   # another leaf at that place
        if n > 1:
            assert not verify_proof(h[i], (i + 1) % n, n, path, root)            # right leaf, wrong place
    assert not verify_proof(h[0], 0, n, merkle_proof(h, 0)[:-1], root) or n == 1  # truncated path


def test_a_prefix_has_its_own_root_and_roots_differ():
    h = hashes(10)
    assert merkle_root(h[:5]) != merkle_root(h[:6]) != merkle_root(h)
    assert merkle_root(h[:5]) == merkle_root(hashes(5))
    assert verify_proof(h[3], 3, 5, merkle_proof(h[:5], 3), merkle_root(h[:5]))
