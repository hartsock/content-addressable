//! # content-addressable
//!
//! **Data carries its own proof of integrity, intrinsically.**
//!
//! A content address is not a name assigned to data by some authority — it is
//! *derived from the data itself*. Hand someone the bytes and the address, and
//! they can recompute the address and know, with no trusted third party, that
//! the bytes are exactly what the address names. The proof travels with the
//! data. That is the whole idea, and this crate is the smallest honest tool for
//! it.
//!
//! ## IPLD-native
//!
//! This crate does not invent its own identifier format or its own
//! canonicalization. It speaks the multiformats / IPLD stack so its artifacts
//! interoperate with the wider content-addressed world:
//!
//! - [`ContentId`] wraps an IPLD [`Cid`](ipld_core::cid::Cid) — a real CIDv1.
//! - Identities are **BLAKE3** multihashes (code `0x1e`).
//! - The codec is **canonical dag-cbor** (`0x71`): deterministic by
//!   construction (see [`canonical`]).
//!
//! ## Usage
//!
//! Implement [`ContentAddressable`] by providing `canonical_form`; you get
//! `content_id` and `verify` for free:
//!
//! ```
//! use content_addressable::{canonical, ContentAddressable, ContentError};
//! use serde::Serialize;
//! use std::collections::BTreeMap;
//!
//! #[derive(Serialize)]
//! struct Record {
//!     name: String,
//!     attrs: BTreeMap<String, u64>,
//! }
//!
//! impl ContentAddressable for Record {
//!     fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
//!         canonical::to_canonical_dagcbor(self)
//!     }
//! }
//!
//! let r = Record { name: "alpha".into(), attrs: BTreeMap::new() };
//! let id = r.content_id().unwrap();
//! assert!(r.verify(&id).unwrap());
//! ```
//!
//! ## Stability
//!
//! This is `0.1.0-alpha.1`: an explicitly **non-frozen** alpha. The exact
//! bytes — especially the serde representation of [`ContentId`] — are **not a
//! stability contract yet**. There is an open byte/wire "must-fix gate" to
//! settle before `0.1.0`. Do not treat alpha output as a durable format.

#![warn(missing_docs)]

pub mod canonical;
pub mod content_id;
pub mod error;
pub mod trait_def;

pub use content_id::{ContentId, BLAKE3_HASH_CODE, DAG_CBOR_CODEC};
pub use error::ContentError;
pub use trait_def::ContentAddressable;

#[cfg(test)]
mod tests {
    use super::*;
    use ipld_core::cid::Version;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

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

    #[test]
    fn content_id_serializes_as_dagcbor_link() {
        // A struct holding a ContentId should encode/decode it as a tag-42
        // link inside dag-cbor. This is the (alpha, non-frozen) serde repr.
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct HasLink {
            link: ContentId,
        }

        let id = sample_a().content_id().unwrap();
        let value = HasLink { link: id };
        let bytes = canonical::to_canonical_dagcbor(&value).unwrap();
        let back: HasLink = canonical::from_canonical_dagcbor(&bytes).unwrap();
        assert_eq!(value, back, "a ContentId field must roundtrip via dag-cbor");

        // CBOR tag 42 is encoded as major-type-6 head 0xd8 0x2a. Confirm the
        // link is actually emitted as an IPLD link, not a plain byte string.
        assert!(
            bytes.windows(2).any(|w| w == [0xd8, 0x2a]),
            "ContentId must be encoded as a dag-cbor tag-42 link"
        );
    }

    #[test]
    fn invalid_cid_string_errors() {
        let err = "not-a-cid".parse::<ContentId>().unwrap_err();
        assert!(matches!(err, ContentError::InvalidCid { .. }));
    }
}
