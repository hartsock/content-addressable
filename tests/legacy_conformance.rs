//! Rust side of the **portable legacy-dialect** gate (issue #84).
//!
//! Reads `tests/legacy_vectors.json` (authored by `tests/gen_legacy_vectors.rs`)
//! and asserts:
//!
//! - with `unstable-legacy`: each adapter converts its dialect to exactly the
//!   pinned identity — kyln envelope-hex → `RawContentId`, `blake3:<hex>` →
//!   `ClassifiedCid::Raw`, bare hex → `RawContentId`, and `sha2-256:<hex>` →
//!   `ClassifiedCid::Foreign` with the pinned foreign CID;
//! - without the feature: the same structural facts the Python gate checks, so
//!   the vectors are meaningful in a default build too.
//!
//! The Python gate consumes the same file and additionally re-derives the
//! SHA-256 digests with `hashlib`, which is what makes the `sha2-256` rows
//! genuine nessie interop data rather than a shape test.

mod common;

use common::hex_to_bytes;
use content_addressable::{ClassifiedCid, ContentId, RawContentId};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    content_hex: String,
    kyln_envelope_hex: String,
    nessie_blake3_text: String,
    bare_blake3_hex: String,
    expect_raw_content_id_str: String,
    nessie_sha256_text: String,
    expect_foreign_cid_str: String,
    expect_foreign_cid_bytes_hex: String,
}

fn load() -> Vec<Vector> {
    serde_json::from_str(include_str!("legacy_vectors.json"))
        .expect("tests/legacy_vectors.json must be valid JSON")
}

/// The dialects agree with the core, feature or no feature: every legacy
/// spelling of an identity is a rendering of the same `RawContentId`.
#[test]
fn dialect_payloads_agree_with_the_core() {
    let vectors = load();
    assert!(vectors.len() >= 4, "need a few vectors");
    for v in &vectors {
        let id = RawContentId::from_content(&hex_to_bytes(&v.content_hex));
        assert_eq!(id.to_string(), v.expect_raw_content_id_str, "{}", v.name);
        // kyln envelope-hex IS the CID envelope, hex-encoded.
        assert_eq!(
            v.kyln_envelope_hex,
            hex::encode_local(&id.to_bytes()),
            "{}: kyln envelope",
            v.name
        );
        // nessie blake3 text and the bare hex carry the bare digest.
        assert_eq!(
            v.nessie_blake3_text,
            format!("blake3:{}", id.digest_hex()),
            "{}: nessie blake3",
            v.name
        );
        assert_eq!(v.bare_blake3_hex, id.digest_hex(), "{}: bare hex", v.name);
        // The sha2-256 row is a foreign identity: parseable, classified
        // Foreign, and refused by both mintable parsers (fail-closed).
        let foreign: ClassifiedCid = v.expect_foreign_cid_str.parse().expect("foreign parses");
        assert!(!foreign.is_mintable(), "{}", v.name);
        assert_eq!(foreign.hash_code(), 0x12, "{}: sha2-256", v.name);
        assert_eq!(
            foreign.to_bytes(),
            hex_to_bytes(&v.expect_foreign_cid_bytes_hex),
            "{}: foreign bytes",
            v.name
        );
        assert!(v.expect_foreign_cid_str.parse::<RawContentId>().is_err());
        assert!(v.expect_foreign_cid_str.parse::<ContentId>().is_err());
        // The foreign envelope is CIDv1 raw + sha2-256 + 32 bytes, and its
        // digest is the payload of the nessie text.
        let sha_payload = v.nessie_sha256_text.split_once(':').expect("algo:hex").1;
        assert_eq!(
            v.expect_foreign_cid_bytes_hex,
            format!("01551220{sha_payload}"),
            "{}: foreign envelope",
            v.name
        );
    }
}

/// With the adapters compiled in: every dialect converts to the pinned identity.
#[cfg(feature = "unstable-legacy")]
#[test]
fn adapters_convert_dialects_to_the_pinned_identities() {
    use content_addressable::legacy;
    for v in load() {
        let id: RawContentId = v.expect_raw_content_id_str.parse().unwrap();
        assert_eq!(
            legacy::kyln::parse(&v.kyln_envelope_hex).unwrap(),
            id,
            "{}: kyln",
            v.name
        );
        assert_eq!(
            legacy::nessie::parse(&v.nessie_blake3_text).unwrap(),
            ClassifiedCid::Raw(id),
            "{}: nessie blake3",
            v.name
        );
        assert_eq!(
            legacy::bare_blake3::parse(&v.bare_blake3_hex).unwrap(),
            id,
            "{}: bare hex",
            v.name
        );
        // The sha2-256 conversion: Foreign, byte-identical to the pinned CID,
        // and never mintable.
        let foreign = legacy::nessie::parse(&v.nessie_sha256_text).unwrap();
        assert_eq!(
            foreign.to_string(),
            v.expect_foreign_cid_str,
            "{}: nessie sha2-256",
            v.name
        );
        assert_eq!(
            foreign.to_bytes(),
            hex_to_bytes(&v.expect_foreign_cid_bytes_hex),
            "{}: foreign bytes",
            v.name
        );
        assert!(!foreign.is_mintable(), "{}", v.name);
        assert!(foreign.as_foreign().is_some(), "{}", v.name);
    }
}

/// ADVERSARIAL: the adapters are parse-only and fail closed. They never widen
/// the canonical text surface (a base32 CID string is not a legacy dialect),
/// never mint a foreign profile as a recognized one, and reject malformed or
/// ambiguous input rather than guessing.
#[cfg(feature = "unstable-legacy")]
#[test]
fn adapters_fail_closed_and_do_not_widen() {
    use content_addressable::legacy;
    let id = RawContentId::from_content(b"adversarial");
    let dag = ContentId::from_dag_cbor_digest(id.digest_bytes());

    // A dag-cbor envelope is not a raw identity: kyln parse must refuse it
    // rather than re-profile it (law 6).
    assert!(legacy::kyln::parse(&hex::encode_local(&dag.to_bytes())).is_err());
    // Canonical base32 text is NOT a legacy dialect on any adapter.
    assert!(legacy::kyln::parse(&id.to_string()).is_err());
    assert!(legacy::bare_blake3::parse(&id.to_string()).is_err());
    assert!(legacy::nessie::parse(&id.to_string()).is_err());
    // Malformed dialect input.
    for bad in [
        "",
        "blake3:",
        "blake3",
        "sha2-256:zz",
        "md5:00",
        ":",
        "blake3::",
    ] {
        assert!(
            legacy::nessie::parse(bad).is_err(),
            "nessie accepted {bad:?}"
        );
    }
    for bad in ["", "zz", "0155"] {
        assert!(legacy::kyln::parse(bad).is_err(), "kyln accepted {bad:?}");
        assert!(
            legacy::bare_blake3::parse(bad).is_err(),
            "bare_blake3 accepted {bad:?}"
        );
    }
    // Wrong digest length is refused, not padded.
    assert!(legacy::bare_blake3::parse(&"a".repeat(63)).is_err());
    assert!(legacy::bare_blake3::parse(&"a".repeat(65)).is_err());
    // A sha2-256 payload can never come back as a mintable identity.
    let foreign = legacy::nessie::parse(&format!("sha2-256:{}", "11".repeat(32))).unwrap();
    assert!(!foreign.is_mintable());
    assert!(foreign.as_raw().is_none() && foreign.as_content().is_none());
}

/// Minimal local hex encoder: the crate has no `hex` dependency, and the test
/// helpers only ship a decoder plus `bytes_to_hex` for `&[u8]`.
mod hex {
    pub fn encode_local(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
