"""Unit tests for merkle_proof.py. Pure functions, no network."""

import base64
import hashlib

import pytest

from merkle_proof import (
    DefaultHasher,
    RootMismatchError,
    compute_leaf_hash,
    root_from_inclusion_proof,
    verify_consistency,
    verify_inclusion,
)
from tests.helpers import (
    consistency_proof,
    hexlist,
    inclusion_path,
    leaves,
    real_rekor_entry,
    tree_root,
)

SIZES = [1, 2, 3, 4, 5, 7, 8, 13]


def test_hasher_uses_rfc6962_prefixes() -> None:
    # leaves are hashed with a 0x00 prefix, inner nodes with 0x01
    assert DefaultHasher.hash_leaf(b"a") == hashlib.sha256(b"\x00a").digest()
    assert DefaultHasher.hash_children(b"l", b"r") == hashlib.sha256(b"\x01lr").digest()
    assert DefaultHasher.empty_root() == hashlib.sha256(b"").digest()
    assert DefaultHasher.size() == 32


def test_compute_leaf_hash() -> None:
    body = base64.b64encode(b"entry").decode()
    assert compute_leaf_hash(body) == DefaultHasher.hash_leaf(b"entry").hex()


@pytest.mark.parametrize("size", SIZES)
def test_inclusion_valid_for_every_leaf(size: int) -> None:
    data = leaves(size)
    root = tree_root(data).hex()
    for index in range(size):
        leaf = DefaultHasher.hash_leaf(data[index]).hex()
        proof = hexlist(inclusion_path(index, data))
        verify_inclusion(DefaultHasher, index, size, leaf, proof, root)


def test_inclusion_real_rekor_entry() -> None:
    entry = real_rekor_entry()
    proof = entry["verification"]["inclusionProof"]
    verify_inclusion(
        DefaultHasher,
        proof["logIndex"],
        proof["treeSize"],
        compute_leaf_hash(entry["body"]),
        proof["hashes"],
        proof["rootHash"],
    )


def test_inclusion_wrong_root_raises() -> None:
    data = leaves(8)
    leaf = DefaultHasher.hash_leaf(data[3]).hex()
    proof = hexlist(inclusion_path(3, data))
    wrong_root = tree_root(leaves(9)).hex()
    with pytest.raises(RootMismatchError):
        verify_inclusion(DefaultHasher, 3, 8, leaf, proof, wrong_root)


def test_root_from_inclusion_proof_rejects_bad_input() -> None:
    leaf = DefaultHasher.hash_leaf(b"a")
    with pytest.raises(ValueError, match="beyond size"):
        root_from_inclusion_proof(DefaultHasher, 5, 5, leaf, [])
    with pytest.raises(ValueError, match="unexpected size"):
        root_from_inclusion_proof(DefaultHasher, 0, 2, b"short", [leaf])
    with pytest.raises(ValueError, match="wrong proof size"):
        root_from_inclusion_proof(DefaultHasher, 0, 4, leaf, [leaf])


@pytest.mark.parametrize("size2", SIZES)
def test_consistency_valid_for_every_prefix(size2: int) -> None:
    data = leaves(size2)
    root2 = tree_root(data).hex()
    for size1 in range(1, size2 + 1):
        root1 = tree_root(data[:size1]).hex()
        proof = hexlist(consistency_proof(size1, data))
        verify_consistency(DefaultHasher, size1, size2, proof, root1, root2)


def test_consistency_tampered_proof_raises() -> None:
    data = leaves(7)
    proof = consistency_proof(3, data)
    proof[0] = DefaultHasher.hash_leaf(b"evil")
    root1, root2 = tree_root(data[:3]).hex(), tree_root(data).hex()
    with pytest.raises(RootMismatchError):
        verify_consistency(DefaultHasher, 3, 7, hexlist(proof), root1, root2)


def test_consistency_rejects_bad_input() -> None:
    root = tree_root(leaves(4)).hex()
    with pytest.raises(ValueError, match="size2"):
        verify_consistency(DefaultHasher, 5, 4, [], root, root)
    with pytest.raises(ValueError, match="not empty"):
        verify_consistency(DefaultHasher, 4, 4, [root], root, root)
    with pytest.raises(ValueError, match="expected empty proof"):
        verify_consistency(DefaultHasher, 0, 4, [root], root, root)
    with pytest.raises(ValueError, match="empty bytearray_proof"):
        verify_consistency(DefaultHasher, 2, 4, [], root, root)


def test_consistency_same_size_compares_roots() -> None:
    root = tree_root(leaves(4)).hex()
    verify_consistency(DefaultHasher, 4, 4, [], root, root)
    with pytest.raises(RootMismatchError):
        verify_consistency(DefaultHasher, 4, 4, [], root, tree_root(leaves(3)).hex())


# Regression tests: both messages were broken during the ruff clean-up.
def test_root_mismatch_message_is_readable() -> None:
    message = str(RootMismatchError(b"\x01\x02", b"\x03\x04"))
    assert message == "calculated root:\n0304\n does not match expected root:\n0102"


def test_wrong_proof_size_message_shows_numbers() -> None:
    root = tree_root(leaves(4)).hex()
    with pytest.raises(ValueError, match="want 3") as error:
        verify_consistency(DefaultHasher, 3, 4, [root], root, root)
    assert "{" not in str(error.value)
