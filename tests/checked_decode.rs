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
        "a typed round-trip mismatch must be LossyDecode (the bytes are canonical, \
         so the mismatch is with the TYPE's representation of them), got {err:?}"
    );
}

#[test]
// The unverified door is deprecated (issue #90) and is exactly what this test is
// about: it must keep accepting the bytes the checked door refuses, or the
// refusal proves nothing.
#[allow(deprecated)]
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
// Same: the deprecated door is the control arm of the experiment.
#[allow(deprecated)]
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

/// A **lawful** [`ContentAddressable`] whose canonical form is deliberately not
/// its serde encoding: it wraps the value in an envelope.
///
/// Nothing about this is a defect — its identity is well defined, deterministic
/// and reproducible, so `canonical_form` is lawful. Two things follow, one per
/// test below: only a stage 3 that re-encodes through `canonical_form` can see
/// that its *serde* bytes do not name it, and its *own* canonical bytes are not
/// directly deserializable as `Self`, which is why `from_canonical_form` is
/// checked ingress rather than a universal inverse.
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
    // The ENFORCED guarantee is byte equality — that is what the implementation
    // actually checks, and it never calls content_id.
    let bytes = canonical::to_canonical_dagcbor(&Node { alpha: 7 }).expect("encode");
    let node = Node::from_canonical_form(&bytes).expect("a faithful round trip is accepted");
    assert_eq!(node, Node { alpha: 7 });
    assert_eq!(
        node.canonical_form().expect("canonical_form"),
        bytes,
        "the enforced invariant: the decoded value re-encodes to exactly the input"
    );

    // Identity equality is a COROLLARY, and only for a lawful implementation —
    // one whose content_id() obeys the trait law, as `Node`'s default does.
    // content_id is overridable and the door never calls it, so an unlawful
    // override would break this while the invariant above still held.
    assert_eq!(
        node.content_id().expect("content_id"),
        content_addressable::ContentId::from_canonical_bytes(&bytes),
        "for a lawful impl, byte equality gives identity equality"
    );
}

/// A type whose skipped field is not part of its canonical representation. Two
/// values, one canonical form, one id.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Skipped {
    alpha: u64,
    #[serde(skip)]
    hidden: u64,
}

impl ContentAddressable for Skipped {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        canonical::to_canonical_dagcbor(self)
    }
}

#[test]
fn the_decoded_value_need_not_equal_the_encoded_one() {
    // `Serialize + DeserializeOwned` does NOT establish decode(encode(v)) == v,
    // so the door cannot promise it and does not. `hidden` is not part of the
    // canonical representation: two distinct values encode to the same bytes and
    // share one identity, and the decode returns the default rather than the
    // value that was encoded.
    let encoded = Skipped {
        alpha: 7,
        hidden: 99,
    };
    let bytes = encoded.canonical_form().expect("canonical_form");

    let decoded = Skipped::from_canonical_form(&bytes).expect("accepted — correctly");
    assert_ne!(
        decoded, encoded,
        "the in-memory value is NOT recovered — that is the claim the docs must not make"
    );
    assert_eq!(
        decoded,
        Skipped {
            alpha: 7,
            hidden: 0
        }
    );

    // ...and accepting it is right, because the enforced invariant still holds:
    // these bytes ARE the canonical representation of what came back.
    assert_eq!(
        decoded.canonical_form().expect("canonical_form"),
        bytes,
        "byte equality holds even though the value differs"
    );
    assert_eq!(
        decoded.content_id().expect("content_id"),
        encoded.content_id().expect("content_id"),
        "one canonical form, one identity — the skipped field is outside it"
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
}

#[test]
fn a_custom_canonical_form_is_lawful_but_not_directly_deserializable() {
    // The other half, and the reason `from_canonical_form` is documented as a
    // PARTIAL inverse. `Enveloped` is lawful — its canonical form is
    // deterministic and its identity well defined — but its own canonical bytes
    // are an envelope, which does not decode as the struct. Prerequisite 2 (the
    // bytes are directly deserializable as `Self`) fails, and the door says so
    // instead of guessing.
    let node = Enveloped { alpha: 7 };
    let own = node.canonical_form().expect("canonical_form");

    // Lawful: content_id IS the id of its canonical form, and it verifies.
    let id = node.content_id().expect("content_id");
    assert_eq!(
        id,
        content_addressable::ContentId::from_canonical_bytes(&own),
        "the type IS lawful — this is not a broken implementation"
    );
    assert!(node.verify(&id).expect("verify"));

    // ...and yet its own canonical form is not readable back through this door.
    let err = Enveloped::from_canonical_form(&own)
        .expect_err("an envelope does not decode as the struct");
    assert!(
        matches!(err, ContentError::DecodingError { .. }),
        "a custom canonical form with no matching Deserialize must fail at the \
         TYPED DECODE — not silently, and not as a round-trip mismatch — got {err:?}"
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

// ------------------------------------------------------- the deprecated door

#[test]
fn the_deprecated_door_points_at_its_successor() {
    // A deprecation whose note does not name the successor just sends readers
    // hunting. The note is compile-time metadata with no runtime face, so
    // guarding the source text is the only way to assert it — the same shape as
    // tests/stability_doc.rs, which reads Cargo.toml and docs/STABILITY.md.
    //
    // Anchored to the FUNCTION, not to the first `#[deprecated(` in the file: a
    // second deprecated item added above would otherwise silently become what
    // this test checks, and renaming the door away would leave it checking that
    // other item's note. Three things can fail here, and each is a real signal.
    const DOOR: &str = "pub fn from_canonical_dagcbor<T: DeserializeOwned>(";
    let src = include_str!("../src/canonical.rs");
    let door = src
        .find(DOOR)
        .expect("the deprecated door must still exist under this exact signature");
    let before = &src[..door];
    let start = before
        .rfind("#[deprecated(")
        .expect("`from_canonical_dagcbor` must carry a deprecation attribute");
    let end = before[start..]
        .find(")]")
        .map(|i| start + i)
        .expect("the attribute must terminate");
    // Nothing but doc comments and other attributes may sit between the two, or
    // the attribute we found belongs to some other item.
    let between = &before[end + 2..];
    assert!(
        !between.contains("fn ") && !between.contains("struct ") && !between.contains("enum "),
        "the nearest #[deprecated(…) is not attached to {DOOR}; found an item between them: \
         {between:?}"
    );
    let attr = before[start..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        attr.contains(r#"since = "0.1.2""#),
        "the deprecation must state the release that made it: {attr}"
    );
    assert!(
        attr.contains("from_canonical_dagcbor_checked"),
        "the note must name the successor a caller should move to: {attr}"
    );
}
