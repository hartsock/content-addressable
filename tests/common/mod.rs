//! Shared support for the golden-vector generator and the conformance gate.
//!
//! Both `tests/gen_vectors.rs` (the authority that *writes* `tests/vectors.json`)
//! and `tests/conformance.rs` (the gate that *reads* it) need the exact same
//! decoding of a vector's JSON `value` into an [`Ipld`] tree. Keeping that one
//! conversion here guarantees the file the generator emits is parsed identically
//! to the way the gate validates it.
//!
//! ## The JSON-expressible dag-cbor subset
//!
//! A vector's `value` is a plain JSON document restricted to the subset that
//! round-trips faithfully through *both* the serde data model and Python natives:
//! `null`, `bool`, integers (kept within `i64` range), strings, arrays, and
//! objects with string keys. JSON cannot faithfully carry CBOR byte strings or
//! distinguish them from text, so bytes are written as a tagged escape object
//! `{"$bytes": "<hex>"}` that *both* loaders (this one and the Python one)
//! expand into a real byte string. Non-integer floats are deliberately excluded
//! (JSON float ambiguity + dag-cbor float rules make them a separate concern),
//! as are `Link`/`ContentId` values (their serde representation is not frozen
//! during `0.1.0-alpha`). Those language-specific cases stay in the per-language
//! suites; this shared file pins only the currently-stable, cross-language
//! subset.

#![allow(dead_code)]

use ipld_core::ipld::Ipld;
use std::collections::BTreeMap;

/// The reserved key that escapes a CBOR byte string inside JSON.
///
/// A single-key object `{"$bytes": "<hex>"}` decodes to [`Ipld::Bytes`]; the hex
/// payload is the raw bytes. Both this loader and the Python loader recognize it.
pub const BYTES_TAG: &str = "$bytes";

/// Decode a hex string into raw bytes. Test-only; panics on malformed input so a
/// bad vector fails loudly rather than silently mis-encoding.
pub fn hex_to_bytes(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have even length: {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

/// Encode raw bytes as a lowercase hex string (no separators).
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Convert a vector's JSON `value` into the [`Ipld`] tree it denotes.
///
/// This is the heart of the shared contract: the same JSON produces the same
/// `Ipld`, so the generator and the gate canonicalize identical inputs. The
/// `{"$bytes": "<hex>"}` escape becomes [`Ipld::Bytes`]; everything else maps
/// structurally. Integers must fit `i64` (the JSON-expressible subset); floats
/// are rejected (excluded by design).
pub fn json_value_to_ipld(value: &serde_json::Value) -> Ipld {
    use serde_json::Value;
    match value {
        Value::Null => Ipld::Null,
        Value::Bool(b) => Ipld::Bool(*b),
        Value::Number(n) => {
            let i = n
                .as_i64()
                .unwrap_or_else(|| panic!("vector integers must fit i64 (no floats): {n}"));
            Ipld::Integer(i128::from(i))
        }
        Value::String(s) => Ipld::String(s.clone()),
        Value::Array(items) => Ipld::List(items.iter().map(json_value_to_ipld).collect()),
        Value::Object(map) => {
            // The single-key `$bytes` escape decodes to a CBOR byte string.
            if map.len() == 1 {
                if let Some(Value::String(hex)) = map.get(BYTES_TAG) {
                    return Ipld::Bytes(hex_to_bytes(hex));
                }
            }
            let mut out = BTreeMap::new();
            for (k, v) in map {
                assert_ne!(
                    k, BYTES_TAG,
                    "a multi-key object must not use the reserved {BYTES_TAG:?} key"
                );
                out.insert(k.clone(), json_value_to_ipld(v));
            }
            Ipld::Map(out)
        }
    }
}
