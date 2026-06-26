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
//! This is `0.1.0-alpha.1`, working toward `0.1.0`. Most items of the byte/wire
//! "must-fix gate" are now **frozen** — a stability contract across the `0.1.x`
//! line, where changing them is a major version bump:
//!
//! - The [`ContentId`] serde representation (binary dag-cbor tag-42 link +
//!   multibase base32-lower text form) and the CID parameters (CIDv1, dag-cbor
//!   `0x71`, BLAKE3 `0x1e`, 32-byte digest).
//! - **Non-canonical input behavior** (gate #6):
//!   [`ContentId::from_canonical_bytes`] stays the fast, *unchecked* primitive
//!   with a normative "MUST pass canonical dag-cbor" precondition; the opt-in
//!   [`ContentId::from_canonical_bytes_checked`] re-encode-validates foreign
//!   bytes and errors with [`ContentError::NonCanonical`].
//! - **Error-variant stability** (gate #7): [`ContentError`] is frozen
//!   `#[non_exhaustive]` with boxed codec sources and a sourced `InvalidCid`;
//!   see the [`error`] module docs for the operation→variant map.
//! - **`verify` mismatch contract** (gate #8): both the return contracts of
//!   [`ContentAddressable::verify`] (`Ok(false)` on mismatch, never an `Err`)
//!   and its strict sibling [`ContentAddressable::ensure_content_id`]
//!   (`Err(`[`ContentError::VerificationFailed`]`)` on mismatch) are part of the
//!   frozen `0.1.0` API surface — distinct from, but alongside, the byte/wire
//!   gate.
//!
//! The last two byte/wire gate items are now also settled: the **crate-root
//! re-export surface** and the **MSRV/edition policy** (gate items #9/#10 — see
//! the [public API surface](#public-api-surface-frozen-at-010) section below).
//! The frozen bytes are pinned by `tests/vectors.json` and the in-crate golden
//! tests.
//!
//! # Public API surface (FROZEN at 0.1.0)
//!
//! The crate-root re-export surface is itself a **stability contract** for the
//! `0.1.x` line, just like the wire bytes (gate item #9). Once `0.1.0` ships,
//! removing or narrowing any of these is a **SemVer-breaking** event (a major
//! bump); *adding* a new re-export is allowed additively. The frozen crate-root
//! surface is exactly:
//!
//! - [`ContentId`] — the self-certifying identity (re-exported from
//!   [`content_id`]).
//! - [`ContentAddressable`] — the one trait a type implements (from
//!   [`trait_def`]).
//! - [`ContentError`] — the crate's error type (from [`error`]).
//! - the [`canonical`] module — `to_canonical_dagcbor` /
//!   `from_canonical_dagcbor` are reached as [`canonical::to_canonical_dagcbor`]
//!   etc., **not** re-exported at the root (one name per function, matching the
//!   doctests above and the PyO3 face).
//! - [`MerkleNode`] — re-exported **only** when the default-off, experimental
//!   `merkle` feature is enabled; its bytes are not yet frozen (see [`merkle`]).
//!
//! The codec/hash codes [`DAG_CBOR_CODEC`](content_id::DAG_CBOR_CODEC) /
//! [`BLAKE3_HASH_CODE`](content_id::BLAKE3_HASH_CODE) stay `pub` inside
//! [`content_id`] (so `content_addressable::content_id::DAG_CBOR_CODEC`
//! resolves) but are **deliberately not re-exported at the crate root**:
//! promoting their numeric codes to the root would signal a permanence the
//! crate has not committed to, and the conservative default at a freeze is the
//! smaller surface. `BLAKE3_DIGEST_LEN` stays private. The newer public items
//! ([`ContentId::from_canonical_bytes_checked`], [`ContentId::digest_bytes`],
//! [`ContentId::digest_hex`], [`ContentId::from_blake3_content_digest`],
//! [`ContentAddressable::ensure_content_id`]) are intentional and individually
//! documented at their definitions.
//!
//! # MSRV / edition policy (FROZEN at 0.1.0)
//!
//! - **MSRV: Rust `1.85`** (gate item #10). 1.85 is the Rust 2024 edition
//!   baseline, pulled in transitively because `blake3 >= 1.6` depends on
//!   `cpufeatures 0.3` (an edition2024 crate). It is declared as
//!   `rust-version = "1.85"` in `Cargo.toml` and pinned by a dedicated CI job
//!   (`dtolnay/rust-toolchain@1.85`,
//!   build + test) so a transitive dependency cannot raise the real floor while
//!   CI stays green. A bump is an **intentional, documented, SemVer-relevant**
//!   change, never a silent side effect of `cargo update`.
//! - **Edition: `2021`** (gate item #10). The crate stays on the 2021 edition
//!   for the `0.1.x` line; an edition jump is a deliberate minor/major decision,
//!   not an alpha change.

#![warn(missing_docs)]

pub mod canonical;
pub mod content_id;
pub mod error;
#[cfg(feature = "merkle")]
pub mod merkle;
pub mod trait_def;

// FROZEN crate-root re-export surface (gate item #9) — see the "Public API
// surface (FROZEN at 0.1.0)" section in the crate docs above. Keep this set
// minimal and explicit: removing or narrowing an entry is a major version bump.
// The codec/hash consts (DAG_CBOR_CODEC / BLAKE3_HASH_CODE) are intentionally
// NOT re-exported here; they stay reachable via `content_id::`.
pub use content_id::ContentId;
pub use error::ContentError;
#[cfg(feature = "merkle")]
pub use merkle::MerkleNode;
pub use trait_def::ContentAddressable;

#[cfg(test)]
mod tests {
    use super::*;
    // The codec/hash codes are no longer re-exported at the crate root (gate
    // item #9: smaller frozen surface). The cid-shape test reaches them via the
    // `content_id` module, where they remain `pub`.
    use content_id::{BLAKE3_HASH_CODE, DAG_CBOR_CODEC};
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

    #[test]
    fn embedded_content_id_serde_is_frozen_full_byte_golden() {
        // FROZEN serde contract (issue #3): a struct embedding a ContentId
        // field must serialize to the EXACT committed bytes below. This is the
        // embedded-link case that the cross-language tests/vectors.json gate
        // deliberately defers (its subset excludes the not-yet-frozen-at-the-
        // time link repr); pin it here as a full-byte golden so any drift in
        // ipld-core / serde_ipld_dagcbor / cid / blake3 fails loudly.
        //
        // The id is taken from the documented fixed input: the empty-map
        // canonical dag-cbor (0xa0), the same id as the `empty_map` vector.
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct HasLink {
            link: ContentId,
        }

        let id = ContentId::from_canonical_bytes(&[0xa0]);
        // The fixed id agrees with the empty_map conformance vector.
        assert_eq!(
            id.to_string(),
            "bafyr4ia7stf7ge5tzyrsk6tskhva7sk2erkw5jqr4t4pi5pfjglrxlw3ai",
            "the fixed embedded id must be the empty-map ContentId (base32 string)"
        );

        let value = HasLink { link: id };

        // --- dag-cbor (binary) golden -------------------------------------
        // a1                      map(1)
        // 64 6c696e6b             text(4) "link"
        // d8 2a                   tag(42)  <- the IPLD link head
        // 58 25                   bytes(37)
        // 00                      multibase identity prefix for a binary CID
        // 01711e20 1f94...db02    the 36-byte CIDv1 binary form
        let dagcbor = canonical::to_canonical_dagcbor(&value).unwrap();
        let expected_dagcbor = "a1646c696e6bd82a58250001711e201f94cbf313b3ce23257a7251ea0fc95a24556ea611e4f8f475e549971baedb02";
        assert_eq!(
            hex(&dagcbor),
            expected_dagcbor,
            "frozen dag-cbor encoding of an embedded ContentId drifted"
        );
        // The tag-42 link head must be present, followed by the 37-byte string
        // (0x58 0x25) whose first byte is the 0x00 multibase-identity prefix.
        let tag_pos = dagcbor
            .windows(2)
            .position(|w| w == [0xd8, 0x2a])
            .expect("ContentId must be encoded as a dag-cbor tag-42 link");
        assert_eq!(
            &dagcbor[tag_pos..tag_pos + 5],
            &[0xd8, 0x2a, 0x58, 0x25, 0x00],
            "tag-42 head must be followed by a 37-byte string with the 0x00 prefix"
        );

        // It must still round-trip.
        let back: HasLink = canonical::from_canonical_dagcbor(&dagcbor).unwrap();
        assert_eq!(value, back, "a ContentId field must roundtrip via dag-cbor");

        // --- JSON golden ---------------------------------------------------
        // FROZEN (issue #3): in a human-readable serializer a ContentId is the
        // multibase base32 CID string, NOT a byte array. The crate's serde impl
        // branches on `is_human_readable` so JSON/config carry a readable,
        // portable CID. The dag-cbor (IPLD) form above is unchanged (tag-42).
        let json = serde_json::to_string(&value).unwrap();
        let expected_json =
            "{\"link\":\"bafyr4ia7stf7ge5tzyrsk6tskhva7sk2erkw5jqr4t4pi5pfjglrxlw3ai\"}";
        assert_eq!(
            json, expected_json,
            "frozen JSON encoding of an embedded ContentId drifted"
        );
        // It must round-trip through JSON too.
        let back_json: HasLink = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value, back_json,
            "a ContentId field must roundtrip via JSON"
        );
    }

    /// Lowercase hex of a byte slice, for the golden assertions above.
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn invalid_cid_string_errors() {
        let err = "not-a-cid".parse::<ContentId>().unwrap_err();
        assert!(matches!(err, ContentError::InvalidCid { .. }));
    }
}
