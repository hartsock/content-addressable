//! Crate-root integration tests — the determinism, round-trip, and CID-shape
//! behaviours that exercise the public API exactly as a downstream consumer
//! would. Relocated verbatim out of `src/lib.rs` so the crate root is a pure
//! manifest (composition-roots doctrine) and coverage of `src/` measures only
//! shipped code.

use std::collections::BTreeMap;

use content_addressable::content_id::{BLAKE3_HASH_CODE, DAG_CBOR_CODEC};
use content_addressable::{canonical, ContentAddressable, ContentError, ContentId};
use ipld_core::cid::Version;
use serde::{Deserialize, Serialize};

/// A small content-addressable type with a map field, used to demonstrate
/// that determinism is a property of the codec (not caller field ordering).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Sample {
    name: String,
    attrs: BTreeMap<String, u64>,
}

impl ContentAddressable for Sample {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        canonical::to_canonical_dagcbor(self)
    }
}

fn sample_a() -> Sample {
    let mut attrs = BTreeMap::new();
    attrs.insert("zeta".to_string(), 26);
    attrs.insert("alpha".to_string(), 1);
    Sample {
        name: "hello".to_string(),
        attrs,
    }
}

fn sample_b() -> Sample {
    Sample {
        name: "world".to_string(),
        attrs: BTreeMap::new(),
    }
}

#[test]
fn same_value_same_content_id() {
    let a1 = sample_a().content_id().unwrap();
    let a2 = sample_a().content_id().unwrap();
    assert_eq!(a1, a2, "equal values must produce equal content ids");
}

#[test]
fn map_insertion_order_does_not_matter() {
    // Insert the same keys in opposite order; dag-cbor canonicalizes both.
    let mut one = BTreeMap::new();
    one.insert("alpha".to_string(), 1u64);
    one.insert("zeta".to_string(), 26u64);
    let mut two = BTreeMap::new();
    two.insert("zeta".to_string(), 26u64);
    two.insert("alpha".to_string(), 1u64);

    let s1 = Sample {
        name: "x".into(),
        attrs: one,
    };
    let s2 = Sample {
        name: "x".into(),
        attrs: two,
    };
    assert_eq!(s1.content_id().unwrap(), s2.content_id().unwrap());
}

#[test]
fn different_value_different_content_id() {
    let a = sample_a().content_id().unwrap();
    let b = sample_b().content_id().unwrap();
    assert_ne!(a, b, "distinct values must produce distinct content ids");
}

#[test]
fn verify_roundtrip_true_and_false() {
    let a = sample_a();
    let id_a = a.content_id().unwrap();
    assert!(
        a.verify(&id_a).unwrap(),
        "value must verify against its own id"
    );

    let b = sample_b();
    assert!(
        !b.verify(&id_a).unwrap(),
        "a different value must not verify against another value's id"
    );
}

#[test]
fn ensure_content_id_ok_on_match_err_on_mismatch() {
    // Issue #8: the strict helper. On a match it returns Ok(()); on a
    // mismatch it returns Err(VerificationFailed) carrying both ids as their
    // Display (base32-lower) strings — making VerificationFailed a real,
    // constructed, tested error path (no longer dead surface).
    let a = sample_a();
    let id_a = a.content_id().unwrap();
    assert!(
        a.ensure_content_id(&id_a).is_ok(),
        "ensure_content_id must return Ok(()) when the value matches its id"
    );

    let b = sample_b();
    let id_b = b.content_id().unwrap();
    let err = b
        .ensure_content_id(&id_a)
        .expect_err("ensure_content_id must Err when the value does not match");
    match err {
        ContentError::VerificationFailed { expected, computed } => {
            // The fields are the two ids' Display strings, exactly.
            assert_eq!(
                expected,
                id_a.to_string(),
                "expected field is the expected id's Display string"
            );
            assert_eq!(
                computed,
                id_b.to_string(),
                "computed field is the value's own (computed) id Display string"
            );
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
}

#[test]
fn verify_and_ensure_agree_and_both_surface_underlying_errors() {
    // verify and ensure_content_id agree on the match/mismatch boolean, and
    // both surface the SAME underlying error when canonical_form fails. A
    // type whose canonical_form always errors models that path.
    struct AlwaysFails;
    impl ContentAddressable for AlwaysFails {
        fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
            // dag-cbor forbids non-finite floats, so this is a real encode
            // failure surfaced through content_id().
            canonical::to_canonical_dagcbor(&f64::NAN)
        }
    }

    let any_id = sample_a().content_id().unwrap();
    assert!(
        matches!(
            AlwaysFails.verify(&any_id),
            Err(ContentError::EncodingError { .. })
        ),
        "verify must surface the content_id() encoding error"
    );
    assert!(
        matches!(
            AlwaysFails.ensure_content_id(&any_id),
            Err(ContentError::EncodingError { .. })
        ),
        "ensure_content_id must surface the same content_id() encoding error"
    );
}

#[test]
fn canonical_dagcbor_roundtrip() {
    let a = sample_a();
    let bytes = canonical::to_canonical_dagcbor(&a).unwrap();
    let back: Sample = canonical::from_canonical_dagcbor(&bytes).unwrap();
    assert_eq!(
        a, back,
        "value must survive a dag-cbor encode/decode roundtrip"
    );
}

#[test]
fn content_id_string_roundtrip() {
    let id = sample_a().content_id().unwrap();
    let s = id.to_string();
    let parsed: ContentId = s.parse().unwrap();
    assert_eq!(
        id, parsed,
        "ContentId must roundtrip through its string form"
    );
}

#[test]
fn content_id_bytes_roundtrip() {
    let id = sample_a().content_id().unwrap();
    let bytes = id.to_bytes();
    let parsed = ContentId::from_bytes(&bytes).unwrap();
    assert_eq!(id, parsed, "ContentId must roundtrip through its byte form");
}

#[test]
fn cid_shape_is_v1_dagcbor_blake3() {
    let id = sample_a().content_id().unwrap();
    let cid = id.as_cid();
    assert_eq!(cid.version(), Version::V1, "must be a CIDv1");
    assert_eq!(cid.codec(), DAG_CBOR_CODEC, "codec must be dag-cbor (0x71)");
    assert_eq!(
        cid.hash().code(),
        BLAKE3_HASH_CODE,
        "multihash must be BLAKE3 (0x1e)"
    );
    assert_eq!(
        cid.hash().digest().len(),
        32,
        "BLAKE3 digest must be 32 bytes"
    );
}
