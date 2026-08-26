//! The typed decode that proves its own round trip (issue #90).
//!
//! [`canonical::from_canonical_dagcbor`] is a bare `serde_ipld_dagcbor::from_slice`:
//! it never compares the bytes it was handed against the canonical encoding of
//! the value it returns. Two hazards follow, and this file pins both plus the
//! refusal that closes them.
//!
//! 1. **The typed decode drops information.** `serde` ignores unknown map keys,
//!    so a record carrying a field the target type does not name decodes fine —
//!    with the field gone. Re-encoding the value then yields *different* bytes,
//!    so the value the caller holds has a different [`ContentId`] than the bytes
//!    it came from. Only a **typed** round trip can see this: the generic
//!    [`ContentId::from_canonical_bytes_checked`] re-encodes as `Ipld`, which
//!    keeps every key.
//! 2. **Non-canonical bytes are accepted.** Valid-but-non-canonical CBOR
//!    (reordered map keys, non-minimal integers) decodes and re-encodes
//!    differently.
//!
//! Every refusal here is paired with its **anti-vacuous twin**: the same bytes
//! going through the unchecked door and being accepted. Without the twin, a test
//! that merely observes an error cannot tell whether the check refused the bytes
//! or the codec did.

use content_addressable::{canonical, ContentAddressable, ContentError};
use serde::{Deserialize, Serialize};

/// The shape actually written to the wire: two fields.
#[derive(Serialize)]
struct WireWithExtra {
    alpha: u64,
    zeta: u64,
}

/// The shape we decode into: one field. `serde` silently discards `zeta`.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct OnlyAlpha {
    alpha: u64,
}

/// Canonical dag-cbor for a record whose `zeta` field `OnlyAlpha` cannot hold.
fn wire_with_extra_field() -> Vec<u8> {
    canonical::to_canonical_dagcbor(&WireWithExtra { alpha: 1, zeta: 26 })
        .expect("the fixture must encode")
}

/// `{"bb": 1, "a": 2}` with the keys emitted in the WRONG order — valid CBOR,
/// not canonical dag-cbor (canonical is length-first, then bytewise).
const REORDERED_KEYS: [u8; 8] = [0xa2, 0x62, 0x62, 0x62, 0x01, 0x61, 0x61, 0x02];

/// `{"a": 1}` with `1` written in the two-byte uint8 form (`0x18 0x01`) instead
/// of the smallest form (`0x01`) — valid CBOR, not canonical dag-cbor.
const NON_MINIMAL_INT: [u8; 5] = [0xa1, 0x61, 0x61, 0x18, 0x01];

// ----------------------------------------------------------- lossy typed decode

#[test]
fn checked_refuses_a_typed_decode_that_drops_a_field() {
    let bytes = wire_with_extra_field();
    let err = canonical::from_canonical_dagcbor_checked::<OnlyAlpha>(&bytes)
        .expect_err("a decode that drops `zeta` must be refused");
    assert!(
        matches!(err, ContentError::LossyDecode),
        "a lossy typed decode must be LossyDecode (the TYPE is to blame, not the \
         bytes — they are canonical), got {err:?}"
    );
}

#[test]
fn unchecked_accepts_the_lossy_bytes_the_checked_decoder_refuses() {
    // The anti-vacuous twin: the bytes are perfectly decodable, so the refusal
    // above is the CHECK talking, not the codec.
    let bytes = wire_with_extra_field();
    let value: OnlyAlpha =
        canonical::from_canonical_dagcbor(&bytes).expect("the unchecked door accepts them");
    assert_eq!(
        value,
        OnlyAlpha { alpha: 1 },
        "the unchecked decode succeeds, silently short one field"
    );
    // ...and this is exactly why it is a hazard: the value now re-encodes to
    // different bytes, so it carries a DIFFERENT identity than its own source.
    let reencoded = canonical::to_canonical_dagcbor(&value).expect("re-encode");
    assert_ne!(
        reencoded, bytes,
        "the dropped field is what makes the identity shift"
    );
}

#[test]
fn a_lossy_decode_is_canonical_so_the_generic_check_cannot_catch_it() {
    // Structural proof that LossyDecode is NOT reachable through the generic
    // door: the very same bytes pass `from_canonical_bytes_checked`, because
    // re-encoding them as `Ipld` keeps every key. Only a typed round trip sees it.
    let bytes = wire_with_extra_field();
    content_addressable::ContentId::from_canonical_bytes_checked(&bytes)
        .expect("the bytes ARE canonical dag-cbor — the generic check is blind here");
}

// ------------------------------------------------------------ non-canonical bytes

#[test]
fn checked_refuses_reordered_map_keys() {
    let err = canonical::from_canonical_dagcbor_checked::<ipld_core::ipld::Ipld>(&REORDERED_KEYS)
        .expect_err("non-canonical key order must be refused");
    assert!(
        matches!(err, ContentError::NonCanonical),
        "reordered keys must be NonCanonical (the BYTES are to blame), got {err:?}"
    );
}

#[test]
fn checked_refuses_a_non_minimal_integer() {
    let err = canonical::from_canonical_dagcbor_checked::<ipld_core::ipld::Ipld>(&NON_MINIMAL_INT)
        .expect_err("a non-minimal integer must be refused");
    assert!(
        matches!(err, ContentError::NonCanonical),
        "a non-minimal int must be NonCanonical (the BYTES are to blame), got {err:?}"
    );
}

#[test]
fn unchecked_accepts_the_non_canonical_bytes_the_checked_decoder_refuses() {
    // Both anti-vacuous twins in one place: these bytes decode, so the refusals
    // above are the canonicality check, not the codec's own strictness. (Codec
    // strictness has drifted between releases; this is what keeps the two
    // refusals honest if it drifts again.)
    let reordered: ipld_core::ipld::Ipld = canonical::from_canonical_dagcbor(&REORDERED_KEYS)
        .expect("reordered keys are valid CBOR and decode");
    assert_ne!(
        canonical::to_canonical_dagcbor(&reordered).expect("re-encode"),
        REORDERED_KEYS.to_vec(),
        "the reordered fixture must genuinely differ from its canonical form"
    );
    let non_minimal: ipld_core::ipld::Ipld = canonical::from_canonical_dagcbor(&NON_MINIMAL_INT)
        .expect("a non-minimal int is valid CBOR and decodes");
    assert_ne!(
        canonical::to_canonical_dagcbor(&non_minimal).expect("re-encode"),
        NON_MINIMAL_INT.to_vec(),
        "the non-minimal fixture must genuinely differ from its canonical form"
    );
}

// ------------------------------------------------------------------- happy path

#[test]
fn checked_accepts_a_faithful_round_trip() {
    let value = OnlyAlpha { alpha: 7 };
    let bytes = canonical::to_canonical_dagcbor(&value).expect("encode");
    let back: OnlyAlpha =
        canonical::from_canonical_dagcbor_checked(&bytes).expect("a faithful decode is accepted");
    assert_eq!(back, value);
}

#[test]
fn checked_reports_non_cbor_garbage_as_a_decoding_error() {
    let err = canonical::from_canonical_dagcbor_checked::<ipld_core::ipld::Ipld>(&[
        0xff, 0xff, 0xff, 0xff,
    ])
    .expect_err("garbage is not dag-cbor");
    assert!(
        matches!(err, ContentError::DecodingError { .. }),
        "garbage must stay a DecodingError, got {err:?}"
    );
}

// ------------------------------------------- the ergonomic path is the safe one

/// A [`ContentAddressable`] whose canonical form IS its dag-cbor encoding — the
/// recommended one-line implementation.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Node {
    alpha: u64,
}

impl ContentAddressable for Node {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        canonical::to_canonical_dagcbor(self)
    }
}

/// A [`ContentAddressable`] whose canonical form is deterministic but is **not**
/// its serde encoding: it wraps the value in an envelope. Its serde round trip is
/// perfectly faithful, so only a check that re-encodes through `canonical_form`
/// — the function that actually defines this type's identity — can see that the
/// bytes do not name it.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Enveloped {
    alpha: u64,
}

impl ContentAddressable for Enveloped {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        canonical::to_canonical_dagcbor(&("envelope", self.alpha))
    }
}

#[test]
fn from_canonical_form_refuses_a_decode_that_drops_a_field() {
    let bytes = wire_with_extra_field();
    let err = Node::from_canonical_form(&bytes)
        .expect_err("the trait's decode must refuse a lossy round trip too");
    assert!(
        matches!(err, ContentError::LossyDecode),
        "the ergonomic path must be the safe one, got {err:?}"
    );
}

#[test]
fn from_canonical_form_refuses_non_canonical_bytes() {
    let err = Node::from_canonical_form(&REORDERED_KEYS)
        .expect_err("non-canonical bytes must be refused before any T is trusted");
    assert!(
        matches!(err, ContentError::NonCanonical),
        "the bytes are to blame here, got {err:?}"
    );
}

#[test]
fn from_canonical_form_returns_a_value_named_by_the_bytes() {
    // The guarantee, stated as an equation: what comes back re-derives the very
    // identity the bytes have. That is the whole point of the door.
    let bytes = canonical::to_canonical_dagcbor(&Node { alpha: 7 }).expect("encode");
    let node = Node::from_canonical_form(&bytes).expect("a faithful round trip is accepted");
    assert_eq!(node, Node { alpha: 7 });
    assert_eq!(
        node.content_id().expect("content_id"),
        content_addressable::ContentId::from_canonical_bytes(&bytes),
        "from_canonical_form(b) must return the value that b NAMES"
    );
}

#[test]
fn from_canonical_form_re_encodes_through_canonical_form_not_serde() {
    // `Enveloped`'s serde round trip is faithful, so a check that re-encoded with
    // `to_canonical_dagcbor` would accept these bytes and hand back a value whose
    // content_id is something else entirely. Re-encoding through `canonical_form`
    // is what refuses them.
    let serde_bytes = canonical::to_canonical_dagcbor(&Enveloped { alpha: 7 }).expect("encode");
    // Anti-vacuous twin: the serde round trip really is faithful.
    assert_eq!(
        canonical::from_canonical_dagcbor_checked::<Enveloped>(&serde_bytes)
            .expect("the serde-level checked decode accepts these bytes"),
        Enveloped { alpha: 7 },
    );
    let err = Enveloped::from_canonical_form(&serde_bytes)
        .expect_err("these bytes do not name an Enveloped");
    assert!(
        matches!(err, ContentError::LossyDecode),
        "the trait door must re-encode through canonical_form, got {err:?}"
    );

    // ...and the bytes that DO name one are accepted.
    let own = Enveloped { alpha: 7 }
        .canonical_form()
        .expect("canonical_form");
    // (Its own canonical form is an envelope, which does not decode as the
    // struct — so this type simply has no readable canonical form. That is a
    // property of the type, correctly reported, not of the door.)
    assert!(
        matches!(
            Enveloped::from_canonical_form(&own),
            Err(ContentError::DecodingError { .. })
        ),
        "an envelope does not decode as the struct — a DecodingError, not a silent value"
    );
}

#[test]
fn content_addressable_stays_dyn_compatible() {
    // `from_canonical_form` takes no `self` and would leave the vtable, so it
    // carries `where Self: Sized`. Lock that: `Box<dyn ContentAddressable>` is
    // an advertised form (`NodeStoreExt::put_node` takes `T: ... + ?Sized`).
    let boxed: Box<dyn ContentAddressable> = Box::new(Node { alpha: 1 });
    let id = boxed.content_id().expect("content_id through dyn");
    assert!(boxed.verify(&id).expect("verify through dyn"));
}
