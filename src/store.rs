//! The CID-addressed node store seam — `get`/`put` by [`ContentId`], with
//! verify-on-read that backends cannot opt out of.
//!
//! # Why this exists
//!
//! Every Merkle structure built on this crate resolves its child/parent links
//! the same way: a [`ContentId`] goes in, canonical bytes come out. This module
//! is that one narrow seam. A structure never owns storage; it traverses a
//! [`NodeStore`], so **a root CID plus a store fully determines the structure**
//! — hand someone the root id and *any* store holding the bytes, and they can
//! reconstruct the whole structure and prove every node on the way down.
//!
//! Three properties make the seam trustworthy:
//!
//! 1. **Traversal is uniform.** All structures resolve links through this one
//!    trait — not N private storage conventions that diverge on exactly the
//!    thing that must stay uniform.
//! 2. **Verification is not optional.** Tampering happens in the backend (disk
//!    corruption, a hostile peer, a buggy cache). The verified
//!    [`get`](NodeStoreExt::get) therefore lives in [`NodeStoreExt`], a
//!    blanket-implemented extension trait sealed by coherence: a backend
//!    implements only the raw [`get_unverified`](NodeStore::get_unverified)
//!    fetch and **cannot override or opt out of** the verification path. (A
//!    *provided* trait method would not be enough — implementors can override
//!    those.)
//! 3. **Storage is replaceable.** Identity comes from the frozen CID profile,
//!    never from where bytes live: swapping the backend (memory today; disk and
//!    network as follow-ups) can never change any node's id.
//!
//! # The laws (proof obligations)
//!
//! Law minimalism: three laws, each naming a **property** — the algorithm is
//! pinned by the frozen v1 CID profile, which already self-describes codec +
//! hash, so the laws never name a hash function:
//!
//! - **PO-STORE-1 (put derives the address) \[Lean\]** — `put(b)` returns
//!   exactly [`ContentId::from_canonical_bytes`]`(b)` for canonical `b`;
//!   consequently [`put_node`]`(n)` equals `n.content_id()`. The store never
//!   mints or rebinds identity; addressing is a pure function of content.
//! - **PO-STORE-2 (verify-on-read soundness) \[Lean\]** — for **any** backend
//!   `get_unverified`, including an adversarial one,
//!   [`NodeStoreExt::get`]`(id)` returns `Ok(b)` only if
//!   `from_canonical_bytes(b) == id`. Corruption or substitution surfaces as
//!   [`ContentError::VerificationFailed`], never as wrong bytes. This holds
//!   for arbitrary backends because `get` is blanket-implemented and sealed by
//!   coherence; it is the seam-level analogue of the frozen
//!   [`ensure_content_id`](crate::ContentAddressable::ensure_content_id)
//!   contract.
//! - **PO-STORE-3 (grow-only monotonicity) \[TLA+\]** — the store's
//!   `id → bytes` map only grows and a mapping is never rebound: `put` of the
//!   same bytes is idempotent, and (given the collision-resistance property the
//!   profile names) two distinct byte strings never contend for one id. This is
//!   the invariant a future GC/eviction design must consciously renegotiate,
//!   which is why deletion is a non-goal here.
//!
//! Mechanized Lean/TLA+ artifacts land with the formal toolkit issues; this
//! module ships the laws' executable counterparts as tests (see below).
//!
//! # ⚠️ EXPERIMENTAL — default-off feature, API NON-FROZEN
//!
//! This module is gated behind the default-**off** `store` cargo feature, and
//! its trait API is **NOT frozen**: signatures may change without a breaking-
//! change ceremony until the catalog stabilizes (epic #30's release ladder).
//! The seam defines **no new wire bytes of its own** — it stores canonical
//! bytes whose layout is owned elsewhere — so nothing here is added to
//! `tests/vectors.json` (the frozen cross-language parity gate deliberately
//! excludes experimental surfaces).
//!
//! # Example
//!
//! ```
//! use content_addressable::store::{self, MemoryStore, NodeStoreExt as _};
//! use content_addressable::{canonical, ContentAddressable, ContentError};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, PartialEq, Serialize, Deserialize)]
//! struct Record {
//!     name: String,
//! }
//!
//! impl ContentAddressable for Record {
//!     fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
//!         canonical::to_canonical_dagcbor(self)
//!     }
//! }
//!
//! let mut store = MemoryStore::new();
//! let record = Record { name: "alpha".into() };
//!
//! // The store derives the address from the content (PO-STORE-1)...
//! let id = store::put_node(&mut store, &record).unwrap();
//! assert_eq!(id, record.content_id().unwrap());
//!
//! // ...and the verified read hands back exactly what the id names.
//! let back: Record = store::get_typed(&store, &id).unwrap();
//! assert_eq!(back, record);
//! ```
//!
//! With the `merkle` feature also enabled, a whole [`MerkleNode`] DAG is
//! reconstructible from its root id the same way — see the `store` + `merkle`
//! integration tests for the traversal pattern.
//!
//! [`MerkleNode`]: crate::merkle::MerkleNode

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;

use crate::canonical;
use crate::content_id::ContentId;
use crate::error::ContentError;
use crate::trait_def::ContentAddressable;

/// Store-layer errors.
///
/// Deliberately a **separate enum**, not new variants on the frozen
/// [`ContentError`] (freeze minimally — the frozen surface is untouched):
/// `NotFound` and backend failures are store concerns, while every
/// content-integrity failure is carried verbatim in the
/// [`Content`](StoreError::Content) variant so callers can still match on the
/// exact [`ContentError`] mode (verification, decoding, non-canonical, …).
///
/// `#[non_exhaustive]` because the API is experimental and follow-ups
/// (batching, async backends) may add variants additively.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The store holds no bytes for this id.
    ///
    /// Absence is a *store* fact, not a content-integrity fact — which is why
    /// it is not a [`ContentError`].
    #[error("node not found: {0}")]
    NotFound(ContentId),

    /// A content-integrity failure, carried verbatim.
    ///
    /// [`NodeStoreExt::get`] produces
    /// [`ContentError::VerificationFailed`] here on a tampered read;
    /// [`NodeStoreExt::put_checked`] produces
    /// [`ContentError::NonCanonical`] / [`ContentError::DecodingError`] on bad
    /// ingest; [`put_node`] propagates encoding failures.
    #[error(transparent)]
    Content(#[from] ContentError),

    /// The backend itself failed (I/O, connectivity, …).
    ///
    /// [`MemoryStore`] never produces this; it exists so disk/network
    /// follow-up backends have an honest place for infrastructure failures
    /// without inventing their own error types.
    #[error("store backend error: {source}")]
    Backend {
        /// The underlying backend error, type-erased (same boxing discipline
        /// as the frozen [`ContentError`] codec sources).
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

/// The narrow seam every structure traverses: raw fetch and store of canonical
/// bytes, keyed by [`ContentId`].
///
/// Backends implement **only** these two operations. The verified operations —
/// the ones structures actually call — live in [`NodeStoreExt`], which is
/// blanket-implemented and cannot be overridden, so verify-on-read
/// (PO-STORE-2) holds no matter who wrote the backend.
///
/// The trait is dyn-compatible on purpose: structures can hold
/// `&S where S: NodeStore + ?Sized` or `Box<dyn NodeStore>`, and the blanket
/// [`NodeStoreExt`] impl covers the `dyn` form too.
pub trait NodeStore {
    /// Backend fetch **without** verification.
    ///
    /// Implementors provide this; callers should never call it directly — call
    /// [`NodeStoreExt::get`], which re-derives and checks the id.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the store holds no bytes for `id`;
    /// [`StoreError::Backend`] for backend infrastructure failures.
    fn get_unverified(&self, id: &ContentId) -> Result<Vec<u8>, StoreError>;

    /// Store canonical dag-cbor bytes; returns the derived id.
    ///
    /// The id **must** be exactly [`ContentId::from_canonical_bytes`]`(bytes)`
    /// (PO-STORE-1): the store never mints identity, it materializes the
    /// identity the bytes already have.
    ///
    /// # Precondition
    ///
    /// `bytes` are canonical dag-cbor — normally guaranteed by construction
    /// via [`put_node`] (which encodes through
    /// [`canonical_form`](crate::ContentAddressable::canonical_form)). For
    /// foreign bytes you did not canonicalize yourself, use
    /// [`NodeStoreExt::put_checked`], mirroring the crate's
    /// [`from_canonical_bytes`](ContentId::from_canonical_bytes) /
    /// [`from_canonical_bytes_checked`](ContentId::from_canonical_bytes_checked)
    /// constructor pair.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] for backend infrastructure failures.
    fn put(&mut self, bytes: &[u8]) -> Result<ContentId, StoreError>;
}

/// Verified operations over any [`NodeStore`] — the methods structures call.
///
/// Blanket-implemented for every `NodeStore` and **sealed by coherence**: the
/// blanket impl below is necessarily the *only* impl (any other would overlap
/// it), so no backend can supply its own body for [`get`](Self::get) or
/// [`put_checked`](Self::put_checked). This — not a provided method, which
/// implementors *can* override — is what makes PO-STORE-2 hold for arbitrary,
/// even adversarial, backends.
pub trait NodeStoreExt: NodeStore {
    /// **Verified** fetch: re-derives the id from the fetched bytes and
    /// requires it to equal `id`.
    ///
    /// This is the seam-level analogue of the frozen
    /// [`ensure_content_id`](crate::ContentAddressable::ensure_content_id)
    /// contract: a mismatch is an error carrying both ids, never wrong bytes.
    ///
    /// # Errors
    ///
    /// - [`StoreError::NotFound`] / [`StoreError::Backend`] from the raw fetch.
    /// - [`StoreError::Content`] wrapping
    ///   [`ContentError::VerificationFailed`] (with both ids' canonical `b…`
    ///   strings) if the fetched bytes do not re-derive `id` (PO-STORE-2).
    fn get(&self, id: &ContentId) -> Result<Vec<u8>, StoreError>;

    /// Opt-in **strict ingest** for untrusted bytes: verifies the bytes are
    /// canonical dag-cbor (round-trip check) before storing.
    ///
    /// On success the returned id is byte-identical to what
    /// [`put`](NodeStore::put) would have returned — the check changes the
    /// fallibility, never the id (the same relationship the
    /// [`from_canonical_bytes_checked`](ContentId::from_canonical_bytes_checked)
    /// door has to its unchecked sibling).
    ///
    /// # Errors
    ///
    /// - [`StoreError::Content`] wrapping [`ContentError::DecodingError`]
    ///   (not dag-cbor at all) or [`ContentError::NonCanonical`] (valid CBOR,
    ///   wrong encoding).
    /// - Any error from the underlying [`put`](NodeStore::put).
    fn put_checked(&mut self, bytes: &[u8]) -> Result<ContentId, StoreError>;
}

impl<S: NodeStore + ?Sized> NodeStoreExt for S {
    fn get(&self, id: &ContentId) -> Result<Vec<u8>, StoreError> {
        let bytes = self.get_unverified(id)?;
        let computed = ContentId::from_canonical_bytes(&bytes);
        if &computed == id {
            Ok(bytes)
        } else {
            Err(StoreError::Content(ContentError::VerificationFailed {
                expected: id.to_string(),
                computed: computed.to_string(),
            }))
        }
    }

    fn put_checked(&mut self, bytes: &[u8]) -> Result<ContentId, StoreError> {
        // Prove canonicality first (typed rejection for foreign bytes), then
        // store through the ordinary door. The two ids agree by PO-STORE-1;
        // the debug_assert documents that the check changes fallibility only.
        let id = ContentId::from_canonical_bytes_checked(bytes)?;
        let stored = self.put(bytes)?;
        debug_assert_eq!(id, stored, "put must derive the same id the check did");
        Ok(stored)
    }
}

/// Fetch and decode a typed node through the **verified** read path.
///
/// A free function (kept off the traits so [`NodeStore`] stays dyn-compatible),
/// reached as `store::get_typed` — one name per function, matching the
/// [`canonical`] module's convention.
///
/// # Errors
///
/// Everything [`NodeStoreExt::get`] can return, plus [`StoreError::Content`]
/// wrapping [`ContentError::DecodingError`] if the (verified) bytes do not
/// decode as a `T`.
pub fn get_typed<T: DeserializeOwned>(
    store: &(impl NodeStore + ?Sized),
    id: &ContentId,
) -> Result<T, StoreError> {
    let bytes = store.get(id)?;
    canonical::from_canonical_dagcbor(&bytes).map_err(StoreError::from)
}

/// Encode a node canonically and store it, returning its [`ContentId`].
///
/// The returned id equals `node.content_id()` (PO-STORE-1): storing a value
/// and addressing a value are the same pure function of its content.
///
/// # Errors
///
/// [`StoreError::Content`] wrapping an encoding failure from
/// [`canonical_form`](crate::ContentAddressable::canonical_form), or any error
/// from the underlying [`put`](NodeStore::put).
pub fn put_node<T: ContentAddressable>(
    store: &mut (impl NodeStore + ?Sized),
    node: &T,
) -> Result<ContentId, StoreError> {
    let bytes = node.canonical_form()?;
    store.put(&bytes)
}

/// The in-memory reference backend: a grow-only `id → bytes` map.
///
/// This is the test substrate every structure issue builds on, and a real
/// backend for ephemeral use. It is **grow-only** (PO-STORE-3): there is no
/// deletion — a future GC/eviction design must renegotiate that law
/// explicitly, elsewhere.
///
/// Derives `PartialEq`/`Eq` so tests can assert store-state equivalence (e.g.
/// insertion-order independence) directly.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemoryStore {
    nodes: BTreeMap<ContentId, Vec<u8>>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct nodes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the store holds no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Whether the store holds bytes for `id` (no verification — presence
    /// only).
    #[must_use]
    pub fn contains(&self, id: &ContentId) -> bool {
        self.nodes.contains_key(id)
    }
}

impl NodeStore for MemoryStore {
    fn get_unverified(&self, id: &ContentId) -> Result<Vec<u8>, StoreError> {
        self.nodes.get(id).cloned().ok_or(StoreError::NotFound(*id))
    }

    fn put(&mut self, bytes: &[u8]) -> Result<ContentId, StoreError> {
        let id = ContentId::from_canonical_bytes(bytes);
        // Grow-only (PO-STORE-3): first write wins; re-putting the same bytes
        // (the only way to reach an occupied key, absent a hash collision) is
        // a no-op rather than a rebind.
        self.nodes.entry(id).or_insert_with(|| bytes.to_vec());
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical dag-cbor bytes for a small map value, via the crate's own
    /// codec (so the fixture can never drift from the canonical form).
    fn canonical_map(n: u64) -> Vec<u8> {
        let ipld: ipld_core::ipld::Ipld =
            serde_json::from_value(serde_json::json!({"n": n, "name": "node"}))
                .expect("json -> ipld");
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
            serde_json::from_value(serde_json::json!({"alpha": 1, "zeta": 26}))
                .expect("json -> ipld");
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
            let ipld: ipld_core::ipld::Ipld =
                serde_json::from_value(v.clone()).expect("json -> ipld");
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
    }

    #[test]
    fn store_error_is_send_sync_static() {
        // Same thread-portability lock the frozen ContentError carries.
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<StoreError>();
    }
}

#[cfg(all(test, feature = "merkle"))]
mod merkle_integration_tests {
    //! The seam's reason to exist, exercised end to end: (root CID, store)
    //! fully determines a `MerkleNode` DAG.

    use std::collections::BTreeMap;

    use super::*;
    use crate::merkle::MerkleNode;

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
