//! Generator for the **portable legacy-dialect** vector file
//! `tests/legacy_vectors.json` (issue #84).
//!
//! **Rust is the authority**, as for `tests/vectors.json` and
//! `tests/raw_vectors.json`. This file pins the *conversions* the legacy
//! adapters perform, so they are conformance data rather than Rust-only unit
//! tests: the Rust gate (`tests/legacy_conformance.rs`) checks the adapters
//! land on the pinned ids, and the Python gate
//! (`tests/test_content_addressable.py`) checks the same file with the API it
//! has — proving the *identities* agree across languages even though the
//! adapters themselves stay a default-off Rust-only seam (they are parsers for
//! a shrinking legacy surface; exposing them to Python would widen it).
//!
//! ## What a vector pins
//!
//! For one input byte string:
//!
//! | Field | Dialect | Converts to |
//! |---|---|---|
//! | `kyln_envelope_hex` | kyln-core `ContentId::to_hex()` — hex of the whole CID envelope | `RawContentId` (`expect_raw_content_id_str`) |
//! | `nessie_blake3_text` | nessie-store `Digest` text, `blake3:<hex>` | `ClassifiedCid::Raw` (same id) |
//! | `bare_blake3_hex` | bare `blake3::Hash::to_hex()` (agent-mesh `payload_cid`, agent-store `content_hash`) | `RawContentId` (same id) |
//! | `nessie_sha256_text` | nessie-store `Digest` text, `sha2-256:<hex>` — a **real** SHA-256 of `content_hex` | `ClassifiedCid::Foreign` (`expect_foreign_cid_str`), never mintable |
//!
//! The SHA-256 digests are literals (this crate has no `sha2` dependency and
//! will not grow one to hash test inputs); the **Python gate re-derives them
//! with `hashlib`**, so a wrong literal fails loudly rather than pinning a
//! synthetic value. That is what makes the `sha2-256` row a genuine nessie
//! interop vector rather than a shape test.
//!
//! ## How to (re)generate
//!
//! ```sh
//! cargo test --test gen_legacy_vectors -- --ignored gen_legacy_vectors
//! ```

mod common;

use common::bytes_to_hex;
use content_addressable::{ClassifiedCid, RawContentId};
use ipld_core::cid::multihash::Multihash;
use ipld_core::cid::Cid;

/// Multicodec `raw`; multihash `sha2-256`. Local copies: the crate deliberately
/// exposes neither as a `sha2`-flavored constant.
const RAW_CODEC: u64 = 0x55;
const SHA2_256: u64 = 0x12;

struct Input {
    name: &'static str,
    content: Vec<u8>,
    /// Real SHA-256 of `content`, verified by the Python gate via `hashlib`.
    sha256_hex: &'static str,
}

fn inputs() -> Vec<Input> {
    vec![
        Input {
            name: "empty",
            content: vec![],
            sha256_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        Input {
            name: "hello",
            content: b"hello".to_vec(),
            sha256_hex: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        },
        Input {
            name: "quick_brown_fox",
            content: b"The quick brown fox jumps over the lazy dog".to_vec(),
            sha256_hex: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        },
        Input {
            name: "kyln_projection",
            content: b"kyln projection".to_vec(),
            sha256_hex: "277bf7eb392799e17d61a63e4b08fd7a761cafcf36b5f4d61b6dde731a21db2f",
        },
        Input {
            name: "all_byte_values",
            content: (0u8..=255).collect(),
            sha256_hex: "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880",
        },
    ]
}

struct Entry {
    name: &'static str,
    content_hex: String,
    kyln_envelope_hex: String,
    nessie_blake3_text: String,
    bare_blake3_hex: String,
    expect_raw_content_id_str: String,
    nessie_sha256_text: String,
    expect_foreign_cid_str: String,
    expect_foreign_cid_bytes_hex: String,
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).expect("string is always JSON-encodable")
}

fn render(entries: &[Entry]) -> String {
    let mut out = String::from("[\n");
    for (i, e) in entries.iter().enumerate() {
        out.push_str("  {\n");
        for (key, val) in [
            ("name", e.name.to_string()),
            ("content_hex", e.content_hex.clone()),
            ("kyln_envelope_hex", e.kyln_envelope_hex.clone()),
            ("nessie_blake3_text", e.nessie_blake3_text.clone()),
            ("bare_blake3_hex", e.bare_blake3_hex.clone()),
            (
                "expect_raw_content_id_str",
                e.expect_raw_content_id_str.clone(),
            ),
            ("nessie_sha256_text", e.nessie_sha256_text.clone()),
            ("expect_foreign_cid_str", e.expect_foreign_cid_str.clone()),
        ] {
            out.push_str(&format!(
                "    {}: {},\n",
                json_string(key),
                json_string(&val)
            ));
        }
        out.push_str(&format!(
            "    \"expect_foreign_cid_bytes_hex\": {}\n",
            json_string(&e.expect_foreign_cid_bytes_hex)
        ));
        out.push_str(if i + 1 < entries.len() {
            "  },\n"
        } else {
            "  }\n"
        });
    }
    out.push_str("]\n");
    out
}

#[test]
#[ignore = "writes tests/legacy_vectors.json; run explicitly with --ignored to regenerate"]
fn gen_legacy_vectors() {
    let entries: Vec<Entry> = inputs()
        .into_iter()
        .map(|input| {
            let raw = RawContentId::from_content(&input.content);
            let digest_hex = raw.digest_hex();

            let sha_bytes: Vec<u8> = (0..input.sha256_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&input.sha256_hex[i..i + 2], 16).expect("hex"))
                .collect();
            let sha_mh = Multihash::wrap(SHA2_256, &sha_bytes).expect("32-byte digest fits");
            let foreign = ClassifiedCid::from_cid(Cid::new_v1(RAW_CODEC, sha_mh));
            assert!(
                !foreign.is_mintable(),
                "a sha2-256 CID must classify as Foreign"
            );

            Entry {
                name: input.name,
                content_hex: bytes_to_hex(&input.content),
                // kyln-core renders `hex::encode(cid.to_bytes())` — the whole
                // envelope, which for its hand-rolled CIDv1 is byte-identical
                // to this crate's raw profile.
                kyln_envelope_hex: bytes_to_hex(&raw.to_bytes()),
                nessie_blake3_text: format!("blake3:{digest_hex}"),
                bare_blake3_hex: digest_hex.clone(),
                expect_raw_content_id_str: raw.to_string(),
                nessie_sha256_text: format!("sha2-256:{}", input.sha256_hex),
                expect_foreign_cid_str: foreign.to_string(),
                expect_foreign_cid_bytes_hex: bytes_to_hex(&foreign.to_bytes()),
            }
        })
        .collect();

    let rendered = render(&entries);
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/legacy_vectors.json");
    std::fs::write(path, rendered).expect("write tests/legacy_vectors.json");
    eprintln!("wrote {} legacy vectors to {path}", entries.len());
}
