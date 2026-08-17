//! Rust side of the raw-profile byte-parity gate (issue #84).
//!
//! Reads `tests/raw_vectors.json` (authored by `tests/gen_raw_vectors.rs`) and
//! asserts the current core reproduces every pinned form of a `RawContentId`,
//! that the legacy adapters map onto it byte-for-byte, and that the pinned
//! dag-cbor identity over the *same digest* is a *different* identity (law 6).
//! The Python gate consumes the same file.

mod common;

use common::hex_to_bytes;
use content_addressable::content_id::BLAKE3_HASH_CODE;
use content_addressable::raw_id::RAW_CODEC;
use content_addressable::{ClassifiedCid, ContentId, RawContentId};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    content_hex: String,
    raw_content_id_str: String,
    raw_content_id_bytes_hex: String,
    digest_hex: String,
    content_id_of_same_digest_str: String,
}

fn load() -> Vec<Vector> {
    let text = include_str!("raw_vectors.json");
    serde_json::from_str(text).expect("tests/raw_vectors.json must be valid JSON")
}

#[test]
fn raw_vectors_reproduce() {
    let vectors = load();
    assert!(!vectors.is_empty());
    for v in &vectors {
        let content = hex_to_bytes(&v.content_hex);
        let id = RawContentId::from_content(&content);
        assert_eq!(id.to_string(), v.raw_content_id_str, "{}: str", v.name);
        assert_eq!(
            id.to_bytes(),
            hex_to_bytes(&v.raw_content_id_bytes_hex),
            "{}: bytes",
            v.name
        );
        assert_eq!(id.digest_hex(), v.digest_hex, "{}: digest_hex", v.name);
        assert!(id.verify(&content), "{}: verify", v.name);
        // Profile is exactly CIDv1 raw/blake3/32.
        assert!(
            v.raw_content_id_bytes_hex.starts_with("01551e20"),
            "{}: envelope prefix",
            v.name
        );
        assert_eq!(id.as_cid().codec(), RAW_CODEC);
        assert_eq!(id.as_cid().hash().code(), BLAKE3_HASH_CODE);
        // Every ingress path agrees.
        assert_eq!(v.raw_content_id_str.parse::<RawContentId>().unwrap(), id);
        assert_eq!(
            RawContentId::from_bytes(&hex_to_bytes(&v.raw_content_id_bytes_hex)).unwrap(),
            id
        );
        assert_eq!(
            RawContentId::from_blake3_digest(
                hex_to_bytes(&v.digest_hex).try_into().expect("32 bytes")
            ),
            id
        );
        assert_eq!(
            ClassifiedCid::from_bytes(&id.to_bytes()).unwrap(),
            ClassifiedCid::Raw(id)
        );
    }
}

/// Law 6, pinned: the dag-cbor identity over the identical digest is a
/// different identity — different string, different bytes, rejected by the raw
/// ingress — while the digest accessors agree.
#[test]
fn same_digest_other_profile_is_a_different_identity() {
    for v in load() {
        let raw: RawContentId = v.raw_content_id_str.parse().unwrap();
        let dag: ContentId = v.content_id_of_same_digest_str.parse().unwrap();
        assert_eq!(raw.digest_hex(), dag.digest_hex(), "{}", v.name);
        assert_ne!(raw.to_string(), dag.to_string(), "{}", v.name);
        assert_ne!(raw.to_bytes(), dag.to_bytes(), "{}", v.name);
        assert!(v
            .content_id_of_same_digest_str
            .parse::<RawContentId>()
            .is_err());
        assert!(v.raw_content_id_str.parse::<ContentId>().is_err());
        assert_ne!(ClassifiedCid::from(raw), ClassifiedCid::from(dag));
    }
}

/// The legacy adapters land on the pinned ids byte-for-byte.
#[cfg(feature = "unstable-legacy")]
#[test]
fn legacy_adapters_land_on_pinned_ids() {
    use content_addressable::legacy;
    for v in load() {
        let id: RawContentId = v.raw_content_id_str.parse().unwrap();
        // kyln: hex of the whole envelope.
        assert_eq!(
            legacy::kyln::parse(&v.raw_content_id_bytes_hex).unwrap(),
            id,
            "{}",
            v.name
        );
        // nessie: "blake3:<hex>".
        assert_eq!(
            legacy::nessie::parse(&format!("blake3:{}", v.digest_hex)).unwrap(),
            ClassifiedCid::Raw(id),
            "{}",
            v.name
        );
        // bare digest hex.
        assert_eq!(
            legacy::bare_blake3::parse(&v.digest_hex).unwrap(),
            id,
            "{}",
            v.name
        );
    }
}
