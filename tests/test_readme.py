"""Execute the README's ``## Python`` usage example so it cannot rot (issue #16).

The README ships on BOTH crates.io and PyPI; its Python section is the first
thing a Python user runs. This test mirrors that example verbatim so CI's
``python`` job (``maturin develop`` + ``pytest -q``) proves every documented
call still works and emits what the prose claims — the same "examples are
tested" discipline the byte-contract gate expects.

If you edit the ``## Python`` block in README.md, update this test to match (and
vice versa).
"""

from content_addressable import (
    ContentId,
    content_id,
    from_canonical_dagcbor,
    to_canonical_dagcbor,
)


def test_readme_python_example():
    """The exact runnable example from README.md's ``## Python`` section."""
    # A value's content id (CIDv1, dag-cbor + BLAKE3). Key order is irrelevant.
    record = {"name": "alpha", "attrs": {}}
    cid = content_id(record)

    # The prose claims a base32-lower multibase string (leading 'b'), a 64-char
    # bare-digest-hex, and that to_canonical_dagcbor returns canonical bytes.
    assert str(cid).startswith("b")
    assert len(cid.digest_hex()) == 64
    assert isinstance(to_canonical_dagcbor(record), bytes)

    # Canonical bytes round-trip; equal values -> equal bytes -> equal ids.
    raw = to_canonical_dagcbor(record)
    assert content_id(record) == ContentId.from_canonical_bytes(raw)
    assert from_canonical_dagcbor(raw) == record
    assert content_id({"attrs": {}, "name": "alpha"}) == cid  # order-independent

    # Parse an id back from its string / binary forms.
    assert ContentId.parse(str(cid)) == cid
    assert ContentId.from_bytes(cid.to_bytes()) == cid

    # Wrap an already-computed 32-byte BLAKE3 digest with NO re-hash.
    assert ContentId.from_blake3_content_digest(cid.digest_bytes()) == cid

    # digest_bytes() is the raw 32-byte BLAKE3 hash.
    assert len(cid.digest_bytes()) == 32
