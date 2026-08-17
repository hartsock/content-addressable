//! Generator for the raw-profile golden-vector file `tests/raw_vectors.json`
//! (issue #84).
//!
//! **Rust is the authority**, exactly as for `tests/vectors.json`
//! (`tests/gen_vectors.rs`): the vectors are computed here and consumed verbatim
//! by the Rust gate (`tests/raw_conformance.rs`) and the Python gate
//! (`tests/test_content_addressable.py`). Kept in a *separate* file from
//! `vectors.json` because that file's schema is per-*value* (dag-cbor profile)
//! and this one is per-*byte-string* (raw profile); mixing them would break the
//! frozen loader on both sides.
//!
//! ## What each vector pins
//!
//! For one input byte string (`content_hex`):
//! - `raw_content_id_str` — `RawContentId` canonical text (base32-lower `b…`);
//! - `raw_content_id_bytes_hex` — the CID envelope; **also exactly kyln-core's
//!   `ContentId::to_hex()`** for the same bytes (kyln's hand-rolled CIDv1 emits
//!   the standard octets), so this doubles as the kyln legacy round-trip vector;
//! - `digest_hex` — the bare 32-byte BLAKE3 digest, which is also the tail of
//!   the envelope after the 8-char `01551e20` prefix, and the payload of the
//!   nessie `blake3:<hex>` and bare-hex legacy forms;
//! - `content_id_of_same_digest_str` — `ContentId::from_dag_cbor_digest(digest)`:
//!   the *other* profile over the *same* digest. Pinned so both language gates
//!   assert law 6 (`docs/adr/0003`): same digest, different profile ⇒ different
//!   identity (`!= raw_content_id_str`).
//!
//! ## How to (re)generate
//!
//! ```sh
//! cargo test --test gen_raw_vectors -- --ignored gen_raw_vectors
//! ```
//!
//! Running it on an unchanged tree leaves the file byte-identical.

mod common;

use common::bytes_to_hex;
use content_addressable::{ContentId, RawContentId};

struct Input {
    name: &'static str,
    content: Vec<u8>,
}

fn inputs() -> Vec<Input> {
    vec![
        Input {
            name: "empty",
            content: vec![],
        },
        Input {
            name: "single_zero_byte",
            content: vec![0x00],
        },
        Input {
            name: "hello",
            content: b"hello".to_vec(),
        },
        Input {
            name: "quick_brown_fox",
            content: b"The quick brown fox jumps over the lazy dog".to_vec(),
        },
        Input {
            name: "all_byte_values",
            content: (0u8..=255).collect(),
        },
        Input {
            name: "thirty_two_ff",
            content: vec![0xff; 32],
        },
        Input {
            name: "kib_of_zeros",
            content: vec![0u8; 1024],
        },
        // The canonical dag-cbor of `{}` (a0). Under the raw profile it is just
        // one byte, and its RawContentId must differ from the ContentId of the
        // value `{}` even though the digests are identical — the sharpest law-6
        // case, since the input really IS canonical dag-cbor.
        Input {
            name: "dagcbor_empty_map_as_raw_bytes",
            content: vec![0xa0],
        },
    ]
}

struct Entry {
    name: &'static str,
    content_hex: String,
    raw_content_id_str: String,
    raw_content_id_bytes_hex: String,
    digest_hex: String,
    content_id_of_same_digest_str: String,
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).expect("string is always JSON-encodable")
}

fn render(entries: &[Entry]) -> String {
    let mut out = String::from("[\n");
    for (i, e) in entries.iter().enumerate() {
        out.push_str("  {\n");
        out.push_str(&format!("    \"name\": {},\n", json_string(e.name)));
        out.push_str(&format!(
            "    \"content_hex\": {},\n",
            json_string(&e.content_hex)
        ));
        out.push_str(&format!(
            "    \"raw_content_id_str\": {},\n",
            json_string(&e.raw_content_id_str)
        ));
        out.push_str(&format!(
            "    \"raw_content_id_bytes_hex\": {},\n",
            json_string(&e.raw_content_id_bytes_hex)
        ));
        out.push_str(&format!(
            "    \"digest_hex\": {},\n",
            json_string(&e.digest_hex)
        ));
        out.push_str(&format!(
            "    \"content_id_of_same_digest_str\": {}\n",
            json_string(&e.content_id_of_same_digest_str)
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

#[test]
#[ignore = "writes tests/raw_vectors.json; run explicitly with --ignored to regenerate"]
fn gen_raw_vectors() {
    let entries: Vec<Entry> = inputs()
        .into_iter()
        .map(|input| {
            let raw = RawContentId::from_content(&input.content);
            let dag = ContentId::from_dag_cbor_digest(raw.digest_bytes());
            Entry {
                name: input.name,
                content_hex: bytes_to_hex(&input.content),
                raw_content_id_str: raw.to_string(),
                raw_content_id_bytes_hex: bytes_to_hex(&raw.to_bytes()),
                digest_hex: raw.digest_hex(),
                content_id_of_same_digest_str: dag.to_string(),
            }
        })
        .collect();
    let rendered = render(&entries);
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/raw_vectors.json");
    std::fs::write(path, rendered).expect("write tests/raw_vectors.json");
    eprintln!("wrote {} raw vectors to {path}", entries.len());
}
