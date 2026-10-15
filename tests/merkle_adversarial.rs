//! Hardening for the frozen `MerkleNode` bytes (PR #113, operator brief).
//!
//! Three things the golden vectors alone cannot give:
//! 1. **Properties** — any permutation / duplication of a parent set yields the
//!    same bytes and CID, and those bytes equal an independent encoder written
//!    from `docs/MERKLE_WIRE.md` (not from `src/merkle.rs`).
//! 2. **A fixture pin** — `merkle_vectors.json` cannot be regenerated quietly.
//! 3. **Malformed input** — which layer (decoder vs CID verification) refuses
//!    what, as written in the "Who rejects what" table of the wire spec.

mod common;

use common::json_value_to_ipld;
use content_addressable::{canonical, ContentAddressable, ContentError, ContentId, MerkleNode};
use ipld_core::ipld::Ipld;
use proptest::prelude::*;

type Node = MerkleNode<Ipld>;

fn cid_of(n: u8) -> ContentId {
    ContentId::from_canonical_bytes(
        &canonical::to_canonical_dagcbor(&Ipld::Integer(n.into())).unwrap(),
    )
}

/// Independent encoder, straight from docs/MERKLE_WIRE.md §2: map(2), key
/// "parents" then "payload"; parents = array of `d8 2a 58 25 00 || cid`,
/// sorted ascending by CID bytes, deduplicated.
fn spec_bytes(payload: &Ipld, parents: &[ContentId]) -> Vec<u8> {
    let mut cids: Vec<Vec<u8>> = parents.iter().map(ContentId::to_bytes).collect();
    cids.sort();
    cids.dedup();
    let mut out = vec![0xa2, 0x67];
    out.extend_from_slice(b"parents");
    // §2: minimal definite-length array header.
    match cids.len() {
        n if n < 24 => out.push(0x80 | n as u8),
        n if n < 256 => out.extend_from_slice(&[0x98, n as u8]),
        n => out.extend_from_slice(&[0x99, (n >> 8) as u8, n as u8]),
    }
    for c in &cids {
        out.extend_from_slice(&[0xd8, 0x2a, 0x58, 0x25, 0x00]);
        out.extend_from_slice(c);
    }
    out.extend_from_slice(&[0x67]);
    out.extend_from_slice(b"payload");
    out.extend(canonical::to_canonical_dagcbor(payload).unwrap());
    out
}

// ------------------------------------------------------------- 1. properties

fn payload_strategy() -> impl Strategy<Value = Ipld> {
    let leaf = prop_oneof![
        Just(Ipld::Null),
        any::<bool>().prop_map(Ipld::Bool),
        any::<i32>().prop_map(|n| Ipld::Integer(n.into())),
        "[a-z]{0,6}".prop_map(Ipld::String),
        proptest::collection::vec(any::<u8>(), 0..6).prop_map(Ipld::Bytes),
    ];
    leaf.prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Ipld::List),
            proptest::collection::btree_map("[a-z]{0,4}", inner, 0..4).prop_map(Ipld::Map),
        ]
    })
}

proptest! {
    /// Order and duplication of parents never change bytes or CID, and the bytes
    /// are the spec's bytes.
    #[test]
    fn parent_permutation_and_duplication_are_invisible(
        payload in payload_strategy(),
        picks in proptest::collection::vec(0u8..8, 0..16),
    ) {
        let given: Vec<ContentId> = picks.iter().map(|&n| cid_of(n)).collect();
        let mut reversed = given.clone();
        reversed.reverse();
        let mut doubled = given.clone();
        doubled.extend(given.iter().copied());

        let a: Node = MerkleNode::new(payload.clone(), given.iter().copied());
        let b: Node = MerkleNode::new(payload.clone(), reversed);
        let c: Node = MerkleNode::new(payload.clone(), doubled);
        let ba = canonical::to_canonical_dagcbor(&a).unwrap();
        prop_assert_eq!(&ba, &canonical::to_canonical_dagcbor(&b).unwrap());
        prop_assert_eq!(&ba, &canonical::to_canonical_dagcbor(&c).unwrap());
        prop_assert_eq!(&ba, &spec_bytes(&payload, &given));
        prop_assert_eq!(a.id().unwrap(), b.id().unwrap());
        prop_assert_eq!(a.id().unwrap(), c.id().unwrap());
        prop_assert_eq!(a.id().unwrap(), ContentId::from_canonical_bytes(&ba));
    }

    /// Decode -> re-encode of valid canonical bytes keeps bytes and CID.
    #[test]
    fn checked_decode_then_reencode_preserves_identity(
        payload in payload_strategy(),
        picks in proptest::collection::vec(0u8..8, 0..8),
    ) {
        let node: Node = MerkleNode::new(payload, picks.iter().map(|&n| cid_of(n)));
        let bytes = canonical::to_canonical_dagcbor(&node).unwrap();
        let back: Node = canonical::from_canonical_dagcbor_checked(&bytes).unwrap();
        prop_assert_eq!(&back, &node);
        prop_assert_eq!(canonical::to_canonical_dagcbor(&back).unwrap(), bytes);
        prop_assert_eq!(back.id().unwrap(), node.id().unwrap());
    }
}

// -------------------------------------------------------- 2. fixture pin

/// BLAKE3 of the committed `tests/merkle_vectors.json`. Regenerating the file
/// changes this; updating it is a conscious, reviewable act in the same diff.
const VECTORS_BLAKE3: &str = "2ea59ff2aaa5c28173a346d6ad969f58525952d7e3eb60f77a0ec0f3ecfed005";

#[test]
fn committed_vector_file_is_pinned() {
    let got = blake3::hash(include_bytes!("merkle_vectors.json"))
        .to_hex()
        .to_string();
    assert_eq!(
        got, VECTORS_BLAKE3,
        "tests/merkle_vectors.json changed. If the frozen layout really moved, \
         that is a major version bump: update this digest in the same diff and say so."
    );
}

// ------------------------------------------------------ 3. malformed input

fn good() -> Vec<u8> {
    spec_bytes(
        &json_value_to_ipld(&serde_json::json!({"n": 1})),
        &[cid_of(1), cid_of(2)],
    )
}

fn checked(bytes: &[u8]) -> Result<Node, ContentError> {
    canonical::from_canonical_dagcbor_checked::<Node>(bytes)
}

/// Anti-vacuous twin: the unchecked decoder's verdict on the same bytes.
#[allow(deprecated)] // the unchecked door is the point of the twin
fn unchecked_accepts(bytes: &[u8]) -> bool {
    canonical::from_canonical_dagcbor::<Node>(bytes).is_ok()
}

#[test]
fn the_good_node_is_accepted() {
    let n = checked(&good()).unwrap();
    assert_eq!(n.parents().len(), 2);
}

#[test]
fn truncated_link_is_a_decode_error() {
    let g = good();
    let cut = &g[..20]; // ends inside the first tag-42 link
    assert!(
        matches!(checked(cut), Err(ContentError::DecodingError { .. })),
        "{:?}",
        checked(cut)
    );
    assert!(!unchecked_accepts(cut));
}

#[test]
fn link_without_the_leading_zero_byte_is_refused() {
    let mut g = good();
    // d8 2a 58 25 00 <cid>  ->  d8 2a 58 24 <cid>  (drop the 0x00, shorten by one)
    let i = g
        .windows(5)
        .position(|w| w == [0xd8, 0x2a, 0x58, 0x25, 0x00])
        .unwrap();
    g[i + 3] = 0x24;
    g.remove(i + 4);
    assert!(
        matches!(checked(&g), Err(ContentError::DecodingError { .. })),
        "{:?}",
        checked(&g)
    );
    assert!(!unchecked_accepts(&g));
}

#[test]
fn link_to_a_foreign_cid_profile_is_refused() {
    // sha2-256 / dag-pb style CID: 01 70 12 20 <32>
    let mut link = vec![0xd8, 0x2a, 0x58, 0x25, 0x00, 0x01, 0x70, 0x12, 0x20];
    link.extend([7u8; 32]);
    let mut b = vec![0xa2, 0x67];
    b.extend(b"parents");
    b.push(0x81);
    b.extend(link);
    b.push(0x67);
    b.extend(b"payload");
    b.push(0xf6);
    assert!(
        matches!(checked(&b), Err(ContentError::DecodingError { .. })),
        "{:?}",
        checked(&b)
    );
    assert!(!unchecked_accepts(&b));
}

#[test]
fn map_keys_out_of_canonical_order_are_non_canonical() {
    let mut b = vec![0xa2, 0x67];
    b.extend(b"payload");
    b.push(0xf6);
    b.push(0x67);
    b.extend(b"parents");
    b.push(0x80);
    assert!(
        matches!(checked(&b), Err(ContentError::NonCanonical)),
        "{:?}",
        checked(&b)
    );
    assert!(unchecked_accepts(&b), "twin: the plain decoder takes it");
}

#[test]
fn non_minimal_integer_in_payload_is_non_canonical() {
    let mut b = vec![0xa2, 0x67];
    b.extend(b"parents");
    b.push(0x80);
    b.push(0x67);
    b.extend(b"payload");
    b.extend([0x18, 0x01]); // 1 as uint8
    assert!(
        matches!(checked(&b), Err(ContentError::NonCanonical)),
        "{:?}",
        checked(&b)
    );
    assert!(unchecked_accepts(&b));
}

#[test]
fn duplicate_map_key_is_refused() {
    let mut b = vec![0xa2, 0x67];
    b.extend(b"parents");
    b.push(0x80);
    b.push(0x67);
    b.extend(b"parents");
    b.push(0x80);
    assert!(
        matches!(checked(&b), Err(ContentError::DecodingError { .. })),
        "{:?}",
        checked(&b)
    );
    assert!(!unchecked_accepts(&b));
}

#[test]
fn unknown_field_is_a_lossy_decode() {
    let mut b = vec![0xa3, 0x65];
    b.extend(b"extra");
    b.push(0x01);
    b.push(0x67);
    b.extend(b"parents");
    b.push(0x80);
    b.push(0x67);
    b.extend(b"payload");
    b.push(0xf6);
    // canonical order: "extra"(5) < "parents"(7) = "payload"(7)
    assert!(
        matches!(checked(&b), Err(ContentError::LossyDecode)),
        "{:?}",
        checked(&b)
    );
    assert!(unchecked_accepts(&b), "twin: serde silently drops `extra`");
}

#[test]
fn missing_field_is_a_decode_error() {
    let mut b = vec![0xa1, 0x67];
    b.extend(b"payload");
    b.push(0xf6);
    assert!(
        matches!(checked(&b), Err(ContentError::DecodingError { .. })),
        "{:?}",
        checked(&b)
    );
}

#[test]
fn unsorted_or_duplicated_parent_array_is_a_lossy_decode() {
    let (lo, hi) = {
        let mut v = [cid_of(1).to_bytes(), cid_of(2).to_bytes()];
        v.sort();
        (v[0].clone(), v[1].clone())
    };
    let link = |c: &[u8]| {
        let mut l = vec![0xd8, 0x2a, 0x58, 0x25, 0x00];
        l.extend(c);
        l
    };
    let wrap = |links: Vec<Vec<u8>>| {
        let mut b = vec![0xa2, 0x67];
        b.extend(b"parents");
        b.push(0x80 | links.len() as u8);
        for l in links {
            b.extend(l);
        }
        b.push(0x67);
        b.extend(b"payload");
        b.push(0xf6);
        b
    };
    for (what, bytes) in [
        ("descending", wrap(vec![link(&hi), link(&lo)])),
        ("duplicate", wrap(vec![link(&lo), link(&lo)])),
    ] {
        assert!(
            matches!(checked(&bytes), Err(ContentError::LossyDecode)),
            "{what}: {:?}",
            checked(&bytes)
        );
        assert!(unchecked_accepts(&bytes), "twin {what}");
    }
}

#[test]
fn a_claimed_cid_that_does_not_match_the_bytes_fails_verification_not_decoding() {
    let node = checked(&good()).unwrap();
    // Decoding has no notion of a claimed id; verification is where it fails.
    assert!(!node.verify(&cid_of(9)).unwrap());
    assert!(node.verify(&node.id().unwrap()).unwrap());
}

/// The spec encoder reproduces every committed vector, including the 0x98 and
/// 0x99 array-header boundaries (24 and 256 parents).
#[test]
fn spec_encoder_reproduces_every_committed_vector() {
    #[derive(serde::Deserialize)]
    struct V {
        name: String,
        payload: serde_json::Value,
        parents: Vec<String>,
        canonical_dagcbor_hex: String,
    }
    let vs: Vec<V> = serde_json::from_str(include_str!("merkle_vectors.json")).unwrap();
    for v in &vs {
        let parents: Vec<ContentId> = v.parents.iter().map(|s| s.parse().unwrap()).collect();
        let got = spec_bytes(&json_value_to_ipld(&v.payload), &parents);
        let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, v.canonical_dagcbor_hex, "{}", v.name);
    }
    let names: Vec<&str> = vs.iter().map(|v| v.name.as_str()).collect();
    assert!(names.contains(&"parents_24_header_98") && names.contains(&"parents_256_header_99"));
}
