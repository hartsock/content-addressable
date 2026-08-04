"""Foreign CIDs are rejected at every Python ingress path.

The Rust core validates the frozen CID profile — CIDv1 + dag-cbor (0x71) + BLAKE3
(0x1e) + a 32-byte digest — on ``from_bytes`` / ``FromStr`` / ``TryFrom<Cid>`` /
binary ``Deserialize``. The Python face inherits it: ``ContentId.from_bytes`` and
``ContentId.parse`` delegate to the core parsers, and a decoded IPLD (tag-42) link
is converted through the fallible ``TryFrom``. A well-formed but foreign CID must
raise ``ValueError`` — never reach a presentation accessor (``digest_bytes`` /
``digest_hex``) and panic.
"""

import pytest

from content_addressable import ContentId, content_id, from_canonical_dagcbor

# A CIDv1 dag-cbor **SHA-256** (not BLAKE3), 32-byte digest — well-formed, wrong
# profile (BLAKE3 CIDs render as ``bafyr4i…``; this SHA-256 one is ``bafyrei…``).
FOREIGN_CID_BYTES = bytes.fromhex(
    "017112200707070707070707070707070707070707070707070707070707070707070707"
)
FOREIGN_CID_STR = "bafyreiaha4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4"
# A dag-cbor tag-42 link wrapping that foreign CID.
FOREIGN_LINK_DAGCBOR = bytes.fromhex(
    "d82a582500017112200707070707070707070707070707070707070707"
    "070707070707070707070707070707"
)


def test_from_bytes_rejects_a_foreign_cid():
    with pytest.raises(ValueError):
        ContentId.from_bytes(FOREIGN_CID_BYTES)


def test_parse_rejects_a_foreign_cid():
    with pytest.raises(ValueError):
        ContentId.parse(FOREIGN_CID_STR)


def test_from_canonical_dagcbor_rejects_a_foreign_cid_link():
    with pytest.raises(ValueError):
        from_canonical_dagcbor(FOREIGN_LINK_DAGCBOR)


def test_an_on_profile_id_still_round_trips():
    cid = content_id({"name": "alpha"})
    assert ContentId.from_bytes(cid.to_bytes()) == cid
    assert ContentId.parse(str(cid)) == cid
