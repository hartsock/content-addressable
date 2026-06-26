//! Generator for the shared golden-vector file `tests/vectors.json`.
//!
//! **Rust is the authority.** The Python face delegates to this same core, so
//! the vectors are computed *from Rust* and consumed verbatim by both the Rust
//! gate (`tests/conformance.rs`) and the Python gate
//! (`tests/test_content_addressable.py`). Generating from Python instead would
//! let a Python-only bug define the "golden" — rejected.
//!
//! ## How to (re)generate
//!
//! This is an `#[ignore]`-gated test so it never runs in the normal suite (it
//! *writes* a tracked file). Materialize the file on demand with:
//!
//! ```sh
//! cargo test --test gen_vectors -- --ignored gen_vectors
//! ```
//!
//! Running it on an unchanged tree leaves `tests/vectors.json` byte-identical,
//! so CI/review can detect drift. Regenerating after an *intentional* byte
//! change is the explicit, reviewable signal that a major version bump is due.

mod common;

use common::{bytes_to_hex, json_value_to_ipld};
use content_addressable::{canonical, ContentId};

/// One input case: a stable `name` and the raw JSON text of its `value`.
///
/// The `value` is kept as raw text (not a parsed structure) so it is emitted
/// into the file *verbatim* — crucially, the out-of-order-keys case stays
/// out-of-order on disk, proving canonical key-sorting happens in the encoder,
/// not in the file.
struct Input {
    name: &'static str,
    value_json: &'static str,
}

/// The committed vector inputs.
///
/// Covers the issue's required cases: empty map, empty list, the scalars
/// (null/true/false/int/string), nested maps, the order-independence pair
/// (`zeta` before `alpha`), an ints/strings/bytes mix, and a case mirroring the
/// Rust unit tests' `sample_a()` fixture. Deliberately excludes floats and any
/// value depending on the not-yet-frozen `ContentId` serde representation.
fn inputs() -> Vec<Input> {
    vec![
        Input {
            name: "empty_map",
            value_json: "{}",
        },
        Input {
            name: "empty_list",
            value_json: "[]",
        },
        Input {
            name: "null",
            value_json: "null",
        },
        Input {
            name: "bool_true",
            value_json: "true",
        },
        Input {
            name: "bool_false",
            value_json: "false",
        },
        Input {
            name: "integer",
            value_json: "42",
        },
        Input {
            name: "string",
            value_json: "\"hello\"",
        },
        Input {
            name: "map_order_independent",
            // Keys written OUT of sorted order on purpose: `zeta` before
            // `alpha`. dag-cbor sorts them in the bytes, so this vector proves
            // canonical key-sorting reaches the wire.
            value_json: "{\"zeta\": 1, \"alpha\": 2}",
        },
        Input {
            name: "nested_map",
            value_json: "{\"outer\": {\"b\": 2, \"a\": 1}, \"k\": [1, 2, 3]}",
        },
        Input {
            name: "mixed_list",
            value_json: "[1, \"two\", [3, 4], null, true]",
        },
        Input {
            name: "ints_strings_bytes_mix",
            // The `$bytes` escape expands to a CBOR byte string in both loaders.
            value_json: "{\"n\": 7, \"s\": \"raw\", \"b\": {\"$bytes\": \"000102ff\"}}",
        },
        Input {
            name: "sample_a",
            // Mirrors the Rust unit tests' sample_a(): name="hello",
            // attrs={zeta:26, alpha:1}. Cross-checks the old in-module tests.
            value_json: "{\"name\": \"hello\", \"attrs\": {\"zeta\": 26, \"alpha\": 1}}",
        },
        Input {
            name: "deeply_nested",
            value_json: "{\"a\": {\"b\": {\"c\": {\"d\": [1, [2, [3, [4]]]]}}}}",
        },
    ]
}

/// Render the array of vectors as a stable, pretty-printed JSON string.
///
/// Hand-rolled (rather than `serde_json::to_string_pretty`) so the `value`
/// field is emitted verbatim from its raw text — preserving out-of-order keys —
/// while the computed fields are JSON-escaped string literals.
fn render(entries: &[Entry]) -> String {
    let mut out = String::new();
    out.push_str("[\n");
    for (i, e) in entries.iter().enumerate() {
        out.push_str("  {\n");
        out.push_str(&format!("    \"name\": {},\n", json_string(e.name)));
        out.push_str(&format!("    \"value\": {},\n", e.value_json));
        out.push_str(&format!(
            "    \"canonical_dagcbor_hex\": {},\n",
            json_string(&e.canonical_dagcbor_hex)
        ));
        out.push_str(&format!(
            "    \"content_id_str\": {},\n",
            json_string(&e.content_id_str)
        ));
        out.push_str(&format!(
            "    \"content_id_bytes_hex\": {},\n",
            json_string(&e.content_id_bytes_hex)
        ));
        // Presentation contract (issue #6): the "bare-digest-hex" form — 64-char
        // lower-hex of the raw 32-byte BLAKE3 digest, NO envelope/prefix. This
        // is hex of `digest_bytes()`; it equals the tail of `content_id_bytes_hex`
        // after the 8-char `01711e20` CID prefix. Pinned in BOTH language gates.
        out.push_str(&format!(
            "    \"digest_hex\": {}\n",
            json_string(&e.digest_hex)
        ));
        if i + 1 < entries.len() {
            out.push_str("  },\n");
        } else {
            out.push_str("  }\n");
        }
    }
    out.push_str("]\n");
    out
}

/// Minimal JSON string escaping for the values we emit (names + hex + base32).
fn json_string(s: &str) -> String {
    serde_json::to_string(s).expect("string is always JSON-encodable")
}

/// A fully computed vector entry.
struct Entry {
    name: &'static str,
    value_json: &'static str,
    canonical_dagcbor_hex: String,
    content_id_str: String,
    content_id_bytes_hex: String,
    digest_hex: String,
}

#[test]
#[ignore = "writes tests/vectors.json; run explicitly with --ignored to regenerate"]
fn gen_vectors() {
    let entries: Vec<Entry> = inputs()
        .into_iter()
        .map(|input| {
            let value: serde_json::Value =
                serde_json::from_str(input.value_json).expect("vector value_json must be valid");
            let ipld = json_value_to_ipld(&value);
            let bytes = canonical::to_canonical_dagcbor(&ipld).expect("vector must encode");
            let id = ContentId::from_canonical_bytes(&bytes);
            Entry {
                name: input.name,
                value_json: input.value_json,
                canonical_dagcbor_hex: bytes_to_hex(&bytes),
                content_id_str: id.to_string(),
                content_id_bytes_hex: bytes_to_hex(&id.to_bytes()),
                digest_hex: id.digest_hex(),
            }
        })
        .collect();

    let rendered = render(&entries);
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json");
    std::fs::write(path, rendered).expect("write tests/vectors.json");
    eprintln!("wrote {} vectors to {path}", entries.len());
}
