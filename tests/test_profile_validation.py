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

from content_addressable import (
    ContentId,
    content_id,
    from_canonical_dagcbor,
    from_canonical_dagcbor_checked,
)

# A CIDv1 dag-cbor **SHA-256** (not BLAKE3), 32-byte digest — well-formed, wrong
# profile (BLAKE3 CIDs render as ``bafyr4i…``; this SHA-256 one is ``bafyrei…``).
FOREIGN_CID_BYTES = bytes.fromhex(
    "017112200707070707070707070707070707070707070707070707070707070707070707"
)
FOREIGN_CID_STR = "bafyreiaha4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4"
# A dag-cbor tag-42 link wrapping that foreign CID:
#   d8 2a     tag 42 (IPLD link)
#   58 25     byte string, one-byte length 0x25 = 37
#   00        the multibase identity prefix a CID carries inside a link
#   ..36..    FOREIGN_CID_BYTES
# = 4 + 37 = 41 bytes. It carried 3 surplus 0x07 bytes until 0.1.2, which made
# every decode of it fail with ``TrailingData`` *before* reaching the profile
# check — so the test below passed without ever exercising what it names.
FOREIGN_LINK_DAGCBOR = bytes.fromhex(
    "d82a5825" "00" "017112200707070707070707070707070707070707070707070707070707070707070707"
)


def test_the_foreign_link_fixture_is_a_well_formed_cbor_item():
    """Structural guard, so the fixture cannot silently go malformed again.

    A tag-42 byte string whose declared length does not match the bytes present
    fails in the codec, which looks exactly like a successful profile rejection
    from the outside.
    """
    assert FOREIGN_LINK_DAGCBOR[:2] == b"\xd8\x2a", "must be an IPLD tag-42 link"
    declared = FOREIGN_LINK_DAGCBOR[3]
    assert len(FOREIGN_LINK_DAGCBOR) == 4 + declared, (
        f"byte string declares {declared} bytes but "
        f"{len(FOREIGN_LINK_DAGCBOR) - 4} are present"
    )
    assert FOREIGN_LINK_DAGCBOR[5:] == FOREIGN_CID_BYTES, "must wrap the foreign CID"


def test_from_bytes_rejects_a_foreign_cid():
    with pytest.raises(ValueError):
        ContentId.from_bytes(FOREIGN_CID_BYTES)


def test_parse_rejects_a_foreign_cid():
    with pytest.raises(ValueError):
        ContentId.parse(FOREIGN_CID_STR)


@pytest.mark.parametrize(
    "decode", [from_canonical_dagcbor, from_canonical_dagcbor_checked]
)
def test_decoding_a_foreign_cid_link_is_rejected_at_both_doors(decode):
    """The profile law applies to the checked door too.

    These bytes ARE canonical dag-cbor, so the canonicality stage has nothing to
    say; the refusal has to come from the ``ContentId`` conversion. The message is
    asserted so a codec-level failure (the pre-0.1.2 malformed fixture) can no
    longer masquerade as a profile rejection.
    """
    with pytest.raises(ValueError, match="not the content-addressable profile"):
        decode(FOREIGN_LINK_DAGCBOR)


def test_an_on_profile_id_still_round_trips():
    cid = content_id({"name": "alpha"})
    assert ContentId.from_bytes(cid.to_bytes()) == cid
    assert ContentId.parse(str(cid)) == cid
