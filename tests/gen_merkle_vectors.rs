//! Generator for `tests/merkle_vectors.json`, the frozen `MerkleNode` byte layout.
//!
//! Rust is the authority (same stance as `gen_vectors.rs`); the file is consumed
//! verbatim by `tests/merkle_conformance.rs` and `tests/test_content_addressable.py`.
//! Regenerate (intentional layout change only) with
//! `MERKLE_VECTORS_REGENERATE=1 cargo test --test gen_merkle_vectors -- --ignored`. A diff
//! after an unchanged tree means the node layout moved: that is a major bump.

mod common;

use common::{bytes_to_hex, json_value_to_ipld};
use content_addressable::{canonical, ContentId, MerkleNode};
use ipld_core::ipld::Ipld;

fn cid_of(json: &str) -> ContentId {
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    ContentId::from_canonical_bytes(
        &canonical::to_canonical_dagcbor(&json_value_to_ipld(&v)).unwrap(),
    )
}

#[test]
#[ignore = "writes tests/merkle_vectors.json; run explicitly with --ignored"]
fn gen_merkle_vectors() {
    // The vectors are immutable regression fixtures. Overwriting them is a
    // format change (a major bump), so it needs an explicit, deliberate opt-in,
    // and `tests/merkle_adversarial.rs` pins the file's digest besides.
    assert!(
        std::env::var_os("MERKLE_VECTORS_REGENERATE").is_some(),
        "refusing to overwrite tests/merkle_vectors.json; set MERKLE_VECTORS_REGENERATE=1 \
         ONLY for an intentional layout change, then update the digest pin"
    );
    let (p1, p2, p3) = (cid_of("\"p1\""), cid_of("\"p2\""), cid_of("\"p3\""));
    // (name, payload json, parents in the order GIVEN to the constructor)
    let cases: Vec<(&str, &str, Vec<ContentId>)> = vec![
        ("no_parents", "\"genesis\"", vec![]),
        ("one_parent", "{\"n\": 1}", vec![p1]),
        ("several_parents_shuffled", "{\"n\": 2}", vec![p3, p1, p2]),
        ("duplicate_parents", "{\"n\": 3}", vec![p1, p2, p1, p2]),
        (
            "nested_payload",
            "{\"k\": \"v\", \"a\": {\"b\": [1, {\"c\": null}]}}",
            vec![p2],
        ),
    ];
    let out: Vec<serde_json::Value> = cases
        .into_iter()
        .map(|(name, payload, parents)| {
            let pv: serde_json::Value = serde_json::from_str(payload).unwrap();
            let node: MerkleNode<Ipld> =
                MerkleNode::new(json_value_to_ipld(&pv), parents.iter().copied());
            let bytes = canonical::to_canonical_dagcbor(&node).unwrap();
            serde_json::json!({
                "name": name,
                "payload": pv,
                "parents": parents.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "canonical_dagcbor_hex": bytes_to_hex(&bytes),
                "content_id_str": ContentId::from_canonical_bytes(&bytes).to_string(),
            })
        })
        .collect();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/merkle_vectors.json");
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
}
