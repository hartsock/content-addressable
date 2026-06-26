"""Tests for the `content_addressable` Python extension.

These tests exercise the PyO3 face of the `content-addressable` crate. The
contract they pin down:

- Content addressing is **deterministic**: the same value always names itself
  the same way, and different values name themselves differently.
- A `ContentId` round-trips through both its byte form and its string form.
- Canonicalization is a property of the *codec*, not caller field order: two
  dicts built in different insertion orders encode to identical bytes.
- Python and the Rust core share one canonicalizer + one hasher, so the
  `ContentId` of a value equals the id of its own canonical bytes.
- dag-cbor encode/decode is a true round-trip for representable values.
"""

import hashlib

import pytest

import content_addressable as ca
from content_addressable import (
    ContentId,
    content_id,
    from_canonical_dagcbor,
    to_canonical_dagcbor,
)


def _blake3_digest(data: bytes):
    """Return a 32-byte BLAKE3 digest using whatever is available, or None.

    Prefers stdlib `hashlib.blake3` (CPython 3.13+); falls back to the `blake3`
    PyPI package; returns None if neither is present (then the cross-language
    wire-shape test is skipped rather than forcing a test-only dependency).
    """
    try:
        return hashlib.blake3(data).digest()  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    try:
        import blake3 as _blake3

        return _blake3.blake3(data).digest()
    except ImportError:
        return None


# --------------------------------------------------------------------------- #
# Determinism of content addressing
# --------------------------------------------------------------------------- #


def test_content_id_is_deterministic():
    """Same value -> same ContentId string, every time."""
    value = {"name": "alpha", "attrs": {"zeta": 26, "alpha": 1}}
    id_a = content_id(value)
    id_b = content_id(value)
    assert str(id_a) == str(id_b)
    assert id_a == id_b
    assert hash(id_a) == hash(id_b)


def test_content_id_differs_for_different_values():
    """Distinct values -> distinct ContentIds."""
    a = content_id({"name": "hello"})
    b = content_id({"name": "world"})
    assert a != b
    assert str(a) != str(b)


def test_content_id_usable_as_dict_key():
    """__hash__/__eq__ agree, so a ContentId works as a set/dict key."""
    a1 = content_id({"k": 1})
    a2 = content_id({"k": 1})
    b = content_id({"k": 2})
    s = {a1, a2, b}
    assert len(s) == 2  # a1 and a2 collapse to one entry


# --------------------------------------------------------------------------- #
# ContentId round-trips
# --------------------------------------------------------------------------- #


def test_content_id_bytes_roundtrip():
    """to_bytes / from_bytes is a lossless round-trip."""
    original = content_id({"x": [1, 2, 3]})
    raw = original.to_bytes()
    assert isinstance(raw, bytes)
    restored = ContentId.from_bytes(raw)
    assert restored == original
    assert str(restored) == str(original)


def test_content_id_string_roundtrip():
    """str / parse is a lossless round-trip."""
    original = content_id({"x": [1, 2, 3]})
    text = str(original)
    restored = ContentId.parse(text)
    assert restored == original
    assert restored.to_bytes() == original.to_bytes()


def test_content_id_repr():
    cid = content_id({"a": 1})
    r = repr(cid)
    assert r.startswith("ContentId('")
    assert str(cid) in r


def test_content_id_v1_base32_string_shape():
    """CIDv1 default multibase string is base32-lower, prefixed 'b'."""
    cid = content_id({"a": 1})
    s = str(cid)
    assert s.startswith("b")  # base32-lower multibase prefix


# --------------------------------------------------------------------------- #
# Canonical dag-cbor: order independence (canonical sorting reaches Python)
# --------------------------------------------------------------------------- #


def test_canonical_dagcbor_is_insertion_order_independent():
    """Same dict built two ways -> identical canonical bytes."""
    one = {}
    one["alpha"] = 1
    one["zeta"] = 26

    two = {}
    two["zeta"] = 26
    two["alpha"] = 1

    assert to_canonical_dagcbor(one) == to_canonical_dagcbor(two)
    # ...and therefore the same ContentId.
    assert content_id(one) == content_id(two)


def test_canonical_dagcbor_nested_order_independent():
    a = {"outer": {"b": 2, "a": 1}, "k": [1, 2, 3]}
    b = {"k": [1, 2, 3], "outer": {"a": 1, "b": 2}}
    assert to_canonical_dagcbor(a) == to_canonical_dagcbor(b)


# --------------------------------------------------------------------------- #
# Cross-language consistency: one Rust core under both paths
# --------------------------------------------------------------------------- #


def test_content_id_equals_hash_of_its_own_canonical_bytes():
    """content_id(x) == ContentId.from_canonical_bytes(to_canonical_dagcbor(x)).

    This proves the helper, the codec, and the hasher all share one Rust core:
    canonicalizing then hashing by hand reproduces the helper's id exactly.
    """
    value = {"name": "alpha", "attrs": {"zeta": 26, "alpha": 1}, "n": 7}
    canon = to_canonical_dagcbor(value)
    by_hand = ContentId.from_canonical_bytes(canon)
    via_helper = content_id(value)
    assert by_hand == via_helper
    assert str(by_hand) == str(via_helper)


def test_content_id_matches_independent_blake3_cidv1():
    """The CID is BLAKE3(canonical bytes) wrapped as a CIDv1 dag-cbor link.

    Reconstruct the multihash + CIDv1 binary form from a stdlib BLAKE3 digest
    and assert it equals ContentId.to_bytes(). This pins the exact wire shape:
    codec 0x71 (dag-cbor), multihash code 0x1e (BLAKE3), 32-byte digest.
    """
    value = {"hello": "world", "n": [1, 2, 3]}
    canon = to_canonical_dagcbor(value)

    digest = _blake3_digest(canon)
    if digest is None:
        pytest.skip("no BLAKE3 implementation available (need py3.13+ or `blake3`)")
    assert len(digest) == 32

    # multihash = varint(code=0x1e) || varint(len=32) || digest
    multihash = bytes([0x1E, 0x20]) + digest
    # CIDv1 = varint(version=1) || varint(codec=0x71) || multihash
    cid_bytes = bytes([0x01, 0x71]) + multihash

    cid = content_id(value)
    assert cid.to_bytes() == cid_bytes
    # And the round-trip from those bytes lands on the same id.
    assert ContentId.from_bytes(cid_bytes) == cid


# --------------------------------------------------------------------------- #
# dag-cbor encode/decode round-trip
# --------------------------------------------------------------------------- #


def test_dagcbor_roundtrip_values():
    for value in [
        None,
        True,
        False,
        0,
        -1,
        42,
        "hello",
        b"\x00\x01\x02bytes",
        [1, "two", [3, 4], None],
        {"a": 1, "b": [True, False], "c": {"nested": "map"}},
        {},
        [],
    ]:
        encoded = to_canonical_dagcbor(value)
        assert isinstance(encoded, bytes)
        decoded = from_canonical_dagcbor(encoded)
        assert decoded == value, f"round-trip mismatch for {value!r}"


def test_dagcbor_float_roundtrip():
    value = {"pi": 3.14159, "e": 2.71828}
    decoded = from_canonical_dagcbor(to_canonical_dagcbor(value))
    assert decoded == value


def test_bytes_decode_as_python_bytes():
    """A bytes value decodes back as `bytes`, not a list of ints."""
    decoded = from_canonical_dagcbor(to_canonical_dagcbor(b"raw"))
    assert decoded == b"raw"
    assert isinstance(decoded, bytes)


def test_tuple_encodes_like_list():
    """Tuples are dag-cbor lists; they decode back as lists."""
    assert to_canonical_dagcbor((1, 2, 3)) == to_canonical_dagcbor([1, 2, 3])
    assert from_canonical_dagcbor(to_canonical_dagcbor((1, 2, 3))) == [1, 2, 3]


# --------------------------------------------------------------------------- #
# Error handling
# --------------------------------------------------------------------------- #


def test_parse_invalid_cid_string_raises_value_error():
    with pytest.raises(ValueError):
        ContentId.parse("not-a-cid")


def test_from_bytes_invalid_raises_value_error():
    with pytest.raises(ValueError):
        ContentId.from_bytes(b"\xff\xff\xff not a cid")


def test_unsupported_type_raises_type_error():
    class Custom:
        pass

    with pytest.raises(TypeError):
        to_canonical_dagcbor(Custom())  # a custom object is not representable


# --------------------------------------------------------------------------- #
# Module surface
# --------------------------------------------------------------------------- #


def test_module_all_and_doc():
    assert set(ca.__all__) == {
        "ContentId",
        "to_canonical_dagcbor",
        "from_canonical_dagcbor",
        "content_id",
    }
    assert ca.__doc__
