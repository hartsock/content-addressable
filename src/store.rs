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
//! Mechanized Lean/TLA+ artifacts land with the formal toolkit issues; the
//! laws' executable counterparts live in `tests/store.rs`.
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
//! reconstructible from its root id the same way — see `tests/store.rs` (the
//! seam's whole test suite lives there, separated from source) for the
//! traversal pattern and the laws' executable counterparts.
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
/// (a `Backend` variant for fallible disk/network stores, batching) arrive
/// additively — no variant ships before a backend can construct it.
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
    /// [`StoreError::NotFound`] if the store holds no bytes for `id`; a
    /// fallible backend surfaces its own failures through a variant added
    /// additively (the enum is `#[non_exhaustive]` for exactly that).
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
    /// Infallible for [`MemoryStore`]; fallible backends surface failures
    /// through additively-added variants.
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
    /// - [`StoreError::NotFound`] (or a backend's own variant) from the raw fetch.
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
        // store through the ordinary door. The two doors agree on the id by
        // PO-STORE-1 — a law test, not an inline assert, holds that line.
        ContentId::from_canonical_bytes_checked(bytes)?;
        self.put(bytes)
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
