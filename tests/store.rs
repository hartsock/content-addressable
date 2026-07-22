//! The node-store seam's whole test suite — separated from source
//! (`src/store.rs` carries production code only, so coverage of `src/`
//! measures exactly the shipped seam).
//!
//! Layout mirrors the module's laws: PO-STORE-1 (put derives the address),
//! PO-STORE-2 (verify-on-read soundness, incl. adversarial backends),
//! PO-STORE-3 (grow-only monotonicity), plus the dyn-compatibility lock and
//! the `store`+`merkle` (root CID, store)-determines-the-DAG integration.
#![cfg(feature = "store")]

use content_addressable::store::{
    get_typed, put_node, MemoryStore, NodeStore, NodeStoreExt, StoreError,
};
use content_addressable::{canonical, ContentAddressable, ContentError, ContentId};

/// Canonical dag-cbor bytes for a small map value, via the crate's own
/// codec (so the fixture can never drift from the canonical form).
fn canonical_map(n: u64) -> Vec<u8> {
    let ipld: ipld_core::ipld::Ipld =
        serde_json::from_value(serde_json::json!({"n": n, "name": "node"})).expect("json -> ipld");
    canonical::to_canonical_dagcbor(&ipld).expect("encode canonical")
}

/// The non-canonical-but-valid-CBOR fixture from the issue-#5 tests: a
/// two-key map with keys emitted in the wrong (non-canonical) order.
const NON_CANONICAL: [u8; 8] = [0xa2, 0x62, 0x62, 0x62, 0x01, 0x61, 0x61, 0x02];

// ---------------------------------------------------------------- PO-STORE-1

#[test]
fn put_derives_the_address() {
    // PO-STORE-1: put(b) == from_canonical_bytes(b). The store never mints
    // identity; it materializes the identity the bytes already have.
    let mut store = MemoryStore::new();
    for n in 0..8 {
        let bytes = canonical_map(n);
        let id = store.put(&bytes).expect("put succeeds");
        assert_eq!(
            id,
            ContentId::from_canonical_bytes(&bytes),
            "put must return exactly the content-derived id"
        );
    }
}

#[test]
fn put_node_equals_content_id() {
    // PO-STORE-1 corollary: put_node(n) == n.content_id() — storing and
    // addressing are the same pure function of content.
    #[derive(serde::Serialize)]
    struct Rec {
        k: String,
    }
    impl ContentAddressable for Rec {
        fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
            canonical::to_canonical_dagcbor(self)
        }
    }
    let mut store = MemoryStore::new();
    let rec = Rec { k: "value".into() };
    let via_store = put_node(&mut store, &rec).expect("put_node succeeds");
    let via_trait = rec.content_id().expect("content_id succeeds");
    assert_eq!(
        via_store, via_trait,
        "put_node(n) must equal n.content_id()"
    );
}

// ---------------------------------------------------------------- round-trip

#[test]
fn get_returns_exactly_what_was_put() {
    let mut store = MemoryStore::new();
    let bytes = canonical_map(1);
    let id = store.put(&bytes).expect("put succeeds");
    let back = store.get(&id).expect("verified get succeeds");
    assert_eq!(back, bytes, "get must return the exact stored bytes");
}

#[test]
fn get_typed_round_trips_a_value() {
    let mut store = MemoryStore::new();
    let ipld: ipld_core::ipld::Ipld =
        serde_json::from_value(serde_json::json!({"alpha": 1, "zeta": 26})).expect("json -> ipld");
    let bytes = canonical::to_canonical_dagcbor(&ipld).expect("encode");
    let id = store.put(&bytes).expect("put succeeds");
    let back: ipld_core::ipld::Ipld = get_typed(&store, &id).expect("get_typed succeeds");
    assert_eq!(back, ipld, "get_typed must decode the stored value");
}

#[test]
fn get_typed_surfaces_decode_failure_for_wrong_type() {
    // Verified bytes that are a map do not decode as a u64: the error must
    // be a DecodingError inside StoreError::Content, not a panic or wrong
    // value.
    let mut store = MemoryStore::new();
    let id = store.put(&canonical_map(1)).expect("put succeeds");
    let err = get_typed::<u64>(&store, &id).expect_err("wrong type must fail to decode");
    assert!(
        matches!(err, StoreError::Content(ContentError::DecodingError { .. })),
        "wrong-type decode must surface as Content(DecodingError), got {err:?}"
    );
}

// ---------------------------------------------------------------- NotFound

#[test]
fn get_missing_is_not_found_carrying_the_id() {
    let store = MemoryStore::new();
    let id = ContentId::from_canonical_bytes(&canonical_map(42));
    let err = store.get(&id).expect_err("missing id must be NotFound");
    match err {
        StoreError::NotFound(missing) => {
            assert_eq!(missing, id, "NotFound must carry the requested id")
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

// ---------------------------------------------------------------- PO-STORE-2

/// An adversarial backend that *substitutes* different (but themselves
/// canonical) bytes for whatever id is requested — a hostile peer serving
/// the wrong node.
struct SubstitutingStore {
    wrong_bytes: Vec<u8>,
}

impl NodeStore for SubstitutingStore {
    fn get_unverified(&self, _id: &ContentId) -> Result<Vec<u8>, StoreError> {
        Ok(self.wrong_bytes.clone())
    }
    fn put(&mut self, bytes: &[u8]) -> Result<ContentId, StoreError> {
        Ok(ContentId::from_canonical_bytes(bytes))
    }
}

/// An adversarial backend that returns the right bytes with one bit
/// flipped — silent disk corruption.
struct CorruptingStore {
    inner: MemoryStore,
}

impl NodeStore for CorruptingStore {
    fn get_unverified(&self, id: &ContentId) -> Result<Vec<u8>, StoreError> {
        let mut bytes = self.inner.get_unverified(id)?;
        *bytes.last_mut().expect("stored nodes are non-empty") ^= 0x01;
        Ok(bytes)
    }
    fn put(&mut self, bytes: &[u8]) -> Result<ContentId, StoreError> {
        self.inner.put(bytes)
    }
}

#[test]
fn verified_get_rejects_substituted_bytes() {
    // PO-STORE-2: an adversarial backend serving the WRONG node must
    // surface as VerificationFailed carrying both ids — never wrong bytes.
    let wrong = canonical_map(999);
    let store = SubstitutingStore {
        wrong_bytes: wrong.clone(),
    };
    let requested = ContentId::from_canonical_bytes(&canonical_map(1));
    let err = store
        .get(&requested)
        .expect_err("substituted bytes must fail verification");
    match err {
        StoreError::Content(ContentError::VerificationFailed { expected, computed }) => {
            assert_eq!(expected, requested.to_string(), "expected = requested id");
            assert_eq!(
                computed,
                ContentId::from_canonical_bytes(&wrong).to_string(),
                "computed = the substituted bytes' real id"
            );
        }
        other => panic!("expected Content(VerificationFailed), got {other:?}"),
    }
}

#[test]
fn verified_get_rejects_corrupted_bytes() {
    // PO-STORE-2: a single flipped bit must fail verification.
    let mut store = CorruptingStore {
        inner: MemoryStore::new(),
    };
    let bytes = canonical_map(7);
    let id = store.put(&bytes).expect("put succeeds");
    let err = store
        .get(&id)
        .expect_err("corrupted bytes must fail verification");
    assert!(
        matches!(
            err,
            StoreError::Content(ContentError::VerificationFailed { .. })
        ),
        "corruption must surface as Content(VerificationFailed), got {err:?}"
    );
}

// ---------------------------------------------------------------- put_checked

#[test]
fn put_checked_accepts_canonical_and_matches_put() {
    // The checked door changes fallibility, never the id.
    let bytes = canonical_map(3);
    let mut a = MemoryStore::new();
    let mut b = MemoryStore::new();
    let via_checked = a.put_checked(&bytes).expect("canonical bytes accepted");
    let via_unchecked = b.put(&bytes).expect("put succeeds");
    assert_eq!(
        via_checked, via_unchecked,
        "put_checked(canonical) must equal put(canonical)"
    );
    assert_eq!(a, b, "both stores must hold identical state");
}

#[test]
fn put_checked_rejects_non_canonical_cbor() {
    let mut store = MemoryStore::new();
    let err = store
        .put_checked(&NON_CANONICAL)
        .expect_err("non-canonical CBOR must be rejected");
    assert!(
        matches!(err, StoreError::Content(ContentError::NonCanonical)),
        "non-canonical valid CBOR must map to Content(NonCanonical), got {err:?}"
    );
    assert!(store.is_empty(), "rejected bytes must not be stored");
}

#[test]
fn put_checked_rejects_non_cbor_garbage() {
    let mut store = MemoryStore::new();
    let err = store
        .put_checked(&[0xff, 0xff, 0xff, 0xff])
        .expect_err("garbage must be rejected");
    assert!(
        matches!(err, StoreError::Content(ContentError::DecodingError { .. })),
        "garbage must map to Content(DecodingError), got {err:?}"
    );
    assert!(store.is_empty(), "rejected bytes must not be stored");
}

// ---------------------------------------------------------------- PO-STORE-3

#[test]
fn put_is_idempotent_and_grow_only() {
    // PO-STORE-3: re-putting the same bytes is a no-op on state and yields
    // the same id; the map never shrinks or rebinds.
    let mut store = MemoryStore::new();
    let bytes = canonical_map(5);
    let first = store.put(&bytes).expect("first put");
    let snapshot = store.clone();
    let second = store.put(&bytes).expect("second put");
    assert_eq!(first, second, "same bytes must yield the same id");
    assert_eq!(store, snapshot, "idempotent put must not change state");
    assert_eq!(store.len(), 1, "one distinct node stored once");
    assert_eq!(
        store.get(&first).expect("get succeeds"),
        bytes,
        "the mapping is never rebound"
    );
}

#[test]
fn store_state_is_insertion_order_independent() {
    // PO-STORE-3 corollary: the store's state is a pure function of the
    // node SET, not of the order nodes arrived.
    let blobs: Vec<Vec<u8>> = (0..6).map(canonical_map).collect();
    let mut forward = MemoryStore::new();
    for b in &blobs {
        forward.put(b).expect("put succeeds");
    }
    let mut reverse = MemoryStore::new();
    for b in blobs.iter().rev() {
        reverse.put(b).expect("put succeeds");
    }
    assert_eq!(
        forward, reverse,
        "insertion order must not affect store state"
    );
}

#[test]
fn hand_rolled_value_sweep_holds_the_laws() {
    // Executable stand-in for the property suite (the dedicated
    // quality-bar issue brings proptest): a spread of value shapes, each
    // checked for PO-STORE-1 (address derivation), round-trip, and
    // PO-STORE-3 (idempotence).
    let values = [
        serde_json::json!({}),
        serde_json::json!([]),
        serde_json::json!(null),
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(u64::from(u32::MAX)),
        serde_json::json!("ütf-8 ünïcödé"),
        serde_json::json!({"nested": {"deep": [1, 2, {"deeper": null}]}}),
        serde_json::json!([1, "two", [3.5], {"four": 4}]),
    ];
    let mut store = MemoryStore::new();
    for v in &values {
        let ipld: ipld_core::ipld::Ipld = serde_json::from_value(v.clone()).expect("json -> ipld");
        let bytes = canonical::to_canonical_dagcbor(&ipld).expect("encode");
        let id = store.put(&bytes).expect("put succeeds");
        assert_eq!(id, ContentId::from_canonical_bytes(&bytes), "PO-STORE-1");
        assert_eq!(store.get(&id).expect("get succeeds"), bytes, "round-trip");
        assert_eq!(store.put(&bytes).expect("re-put"), id, "idempotence");
    }
    assert_eq!(store.len(), values.len(), "each distinct value stored once");
}

// ---------------------------------------------------------------- dyn lock

#[test]
fn node_store_is_dyn_compatible_and_gets_ext_methods() {
    // Compile-time + runtime lock (in the spirit of the ContentError
    // Send+Sync lock): Box<dyn NodeStore> must be a valid type, receive
    // the sealed NodeStoreExt methods through the blanket impl, and work
    // with the free functions.
    let mut boxed: Box<dyn NodeStore> = Box::new(MemoryStore::new());
    let bytes = canonical_map(11);
    let id = boxed.put(&bytes).expect("put through dyn");
    assert_eq!(
        boxed.get(&id).expect("verified get through dyn"),
        bytes,
        "NodeStoreExt::get must work on dyn NodeStore"
    );
    let back: ipld_core::ipld::Ipld =
        get_typed(&*boxed, &id).expect("get_typed over dyn NodeStore");
    let reencoded = canonical::to_canonical_dagcbor(&back).expect("re-encode");
    assert_eq!(reencoded, bytes, "typed read round-trips through dyn");
    boxed
        .put_checked(&bytes)
        .expect("put_checked must work on dyn NodeStore");

    // The sealed verification path must hold through dyn dispatch too: a
    // substituting backend behind Box<dyn NodeStore> still fails closed.
    let hostile: Box<dyn NodeStore> = Box::new(SubstitutingStore {
        wrong_bytes: canonical_map(999),
    });
    let err = hostile
        .get(&id)
        .expect_err("substitution through dyn must fail verification");
    assert!(
        matches!(
            err,
            StoreError::Content(ContentError::VerificationFailed { .. })
        ),
        "dyn-dispatched get must verify-on-read, got {err:?}"
    );
}

#[test]
fn store_error_is_send_sync_static() {
    // Same thread-portability lock the frozen ContentError carries.
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<StoreError>();
}
#[cfg(feature = "merkle")]
mod merkle_integration {
    //! The seam's reason to exist, exercised end to end: (root CID, store)
    //! fully determines a `MerkleNode` DAG.

    use std::collections::BTreeMap;

    use super::*;
    use content_addressable::merkle::MerkleNode;

    /// Recursively fetch a `MerkleNode<String>` DAG from `root`, verifying
    /// every node on the way down (get_typed reads through the verified path;
    /// `verify` re-checks the node's own claim).
    fn reconstruct(
        store: &impl NodeStore,
        root: &ContentId,
        out: &mut BTreeMap<ContentId, MerkleNode<String>>,
    ) -> Result<(), StoreError> {
        if out.contains_key(root) {
            return Ok(());
        }
        let node: MerkleNode<String> = get_typed(store, root)?;
        assert!(
            node.verify(root).expect("verify runs"),
            "every reconstructed node must verify against the id that named it"
        );
        for parent in node.parents().clone() {
            reconstruct(store, &parent, out)?;
        }
        out.insert(*root, node);
        Ok(())
    }

    #[test]
    fn a_dag_is_fully_determined_by_root_cid_plus_store() {
        // Build a small diamond DAG:  a <- b, a <- c, {b,c} <- d.
        let mut store = MemoryStore::new();

        let a = MerkleNode::genesis("a".to_string());
        let a_id = put_node(&mut store, &a).expect("put a");
        let b = MerkleNode::new("b".to_string(), [a_id]);
        let b_id = put_node(&mut store, &b).expect("put b");
        let c = MerkleNode::new("c".to_string(), [a_id]);
        let c_id = put_node(&mut store, &c).expect("put c");
        let d = MerkleNode::new("d".to_string(), [b_id, c_id]);
        let d_id = put_node(&mut store, &d).expect("put d");

        // From the root id + the store ALONE, the whole DAG comes back.
        let mut recovered = BTreeMap::new();
        reconstruct(&store, &d_id, &mut recovered).expect("reconstruct from root");

        assert_eq!(recovered.len(), 4, "all four nodes reachable from the root");
        assert_eq!(recovered[&a_id], a);
        assert_eq!(recovered[&b_id], b);
        assert_eq!(recovered[&c_id], c);
        assert_eq!(recovered[&d_id], d);
    }

    #[test]
    fn a_missing_interior_node_fails_loudly_not_partially() {
        // Remove one interior node's bytes (simulated by a fresh store holding
        // only the root): reconstruction must fail with NotFound, not silently
        // return a partial DAG.
        let mut full = MemoryStore::new();
        let a = MerkleNode::genesis("a".to_string());
        let a_id = put_node(&mut full, &a).expect("put a");
        let b = MerkleNode::new("b".to_string(), [a_id]);
        let b_id = put_node(&mut full, &b).expect("put b");

        let mut partial = MemoryStore::new();
        let b_bytes = b.canonical_form().expect("encode b");
        partial.put(&b_bytes).expect("put only b");

        let mut recovered = BTreeMap::new();
        let err = reconstruct(&partial, &b_id, &mut recovered)
            .expect_err("missing parent must fail reconstruction");
        assert!(
            matches!(err, StoreError::NotFound(missing) if missing == a_id),
            "the failure must name exactly the missing node, got {err:?}"
        );
    }
}

#[test]
fn put_node_propagates_encoding_failure() {
    // The one fallible edge of put_node's own: canonical_form fails (dag-cbor
    // forbids NaN) and the error must surface as Content(EncodingError) —
    // nothing may be stored.
    struct Unencodable;
    impl ContentAddressable for Unencodable {
        fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
            canonical::to_canonical_dagcbor(&f64::NAN)
        }
    }
    let mut store = MemoryStore::new();
    let err = put_node(&mut store, &Unencodable).expect_err("NaN must fail to encode");
    assert!(
        matches!(err, StoreError::Content(ContentError::EncodingError { .. })),
        "encoding failure must surface as Content(EncodingError), got {err:?}"
    );
    assert!(store.is_empty(), "nothing may be stored on failure");
}

#[test]
fn store_error_display_is_legible() {
    // The Display forms are user-facing contract: NotFound names the id it
    // missed; Content is transparent (the inner ContentError's own message).
    let id = ContentId::from_canonical_bytes(&[0xa0]);
    assert_eq!(
        StoreError::NotFound(id).to_string(),
        format!("node not found: {id}"),
    );
    let inner = ContentError::NonCanonical;
    let expected = inner.to_string();
    assert_eq!(
        StoreError::Content(inner).to_string(),
        expected,
        "Content must display transparently as the inner error"
    );
}
