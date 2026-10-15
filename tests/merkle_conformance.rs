//! Rust side of the `MerkleNode` byte-parity gate (issue #112).
//!
//! Reads `tests/merkle_vectors.json` (authored by `gen_merkle_vectors.rs`) and
//! asserts every vector's exact dag-cbor bytes and CID. The Python gate reads
//! the same file and rebuilds the bytes by hand, so a layout change fails both.

mod common;

use common::{bytes_to_hex, json_value_to_ipld};
use content_addressable::{canonical, ContentId, MerkleNode};
use ipld_core::ipld::Ipld;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    payload: serde_json::Value,
    parents: Vec<String>,
    canonical_dagcbor_hex: String,
    content_id_str: String,
}

#[test]
fn merkle_vectors_reproduce() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("merkle_vectors.json")).expect("valid JSON");
    let names: Vec<&str> = vectors.iter().map(|v| v.name.as_str()).collect();
    for required in [
        "no_parents",
        "one_parent",
        "several_parents_shuffled",
        "duplicate_parents",
        "nested_payload",
    ] {
        assert!(names.contains(&required), "missing vector {required}");
    }
    for v in &vectors {
        let parents = v.parents.iter().map(|s| s.parse::<ContentId>().unwrap());
        let node: MerkleNode<Ipld> = MerkleNode::new(json_value_to_ipld(&v.payload), parents);
        let bytes = canonical::to_canonical_dagcbor(&node).unwrap();
        assert_eq!(
            bytes_to_hex(&bytes),
            v.canonical_dagcbor_hex,
            "{}: bytes",
            v.name
        );
        assert_eq!(
            node.id().unwrap().to_string(),
            v.content_id_str,
            "{}: cid",
            v.name
        );
    }
}
