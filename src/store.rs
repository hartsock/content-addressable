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
//! - **PO-STORE-1A (put derives the address) \[Lean\]** — [`NodeStoreExt::put`]`(b)`
//!   returns exactly [`ContentId::from_canonical_bytes`]`(b)` for canonical `b`;
//!   consequently [`put_node`](NodeStoreExt::put_node)`(n)` equals
//!   `n.content_id()`. Like verify-on-read, this is **sealed**: the id is
//!   derived in the blanket-implemented extension, and the backend's only write
//!   op ([`insert`](NodeStore::insert)) is handed that id — it never computes
//!   one, so no backend can mint or rebind identity. Addressing is a pure
//!   function of content — this is what the blanket impl structurally guarantees.
//! - **PO-STORE-1B (backend acknowledgement) \[TLA+, a backend law\]** — that
//!   [`insert`](NodeStore::insert) returned `Ok` means only that the backend
//!   *accepted* the mapping under its documented durability/visibility contract.
//!   The blanket impl CANNOT prove the bytes were stored, stored under that id,
//!   readable later, or that no other mapping was disturbed: a backend that drops
//!   every write and returns `Ok(())` satisfies 1A (the returned id is still
//!   correct) while storing nothing. 1B is therefore a *backend* obligation, not a
//!   seam guarantee — [`MemoryStore`] discharges it (in-memory, immediate); a
//!   disk/network backend discharges it per its own model, surfacing failures
//!   through [`StoreError::Backend`].
//! - **PO-STORE-2 (verify-on-read soundness) \[Lean\]** — for **any** backend
//!   `get_unverified`, including an adversarial one,
//!   [`NodeStoreExt::get`]`(id)` returns `Ok(b)` only if
//!   `from_canonical_bytes(b) == id` (byte-addressed: `b` hashes to `id`; it does
//!   *not* assert `b` is canonical — see [`get`](NodeStoreExt::get) and the
//!   identity-preserving [`get_node`](NodeStoreExt::get_node)). Corruption or
//!   substitution surfaces as [`ContentError::VerificationFailed`], never as wrong
//!   bytes. This holds for arbitrary backends because `get` is blanket-implemented
//!   and sealed by coherence.
//! - **PO-STORE-3 (grow-only monotonicity, fail-closed) \[TLA+\]** — the store's
//!   `id → bytes` map only grows and a mapping is never rebound: re-inserting the
//!   *same* bytes is idempotent, and inserting *different* bytes under a live id
//!   **fails closed** with [`StoreError::Collision`], leaving state unchanged. The
//!   law therefore does NOT lean on hash injectivity — a collision (or a caller
//!   passing a mismatched `(id, bytes)`) cannot silently rebind. This is the
//!   invariant a future GC/eviction design must consciously renegotiate, which is
//!   why deletion is a non-goal here.
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
//! use content_addressable::store::{MemoryStore, NodeStoreExt as _};
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
//! // The seam derives the address from the content (PO-STORE-1)...
//! let id = store.put_node(&record).unwrap();
//! assert_eq!(id, record.content_id().unwrap());
//!
//! // ...and the identity-preserving read hands back exactly what the id names.
//! let back: Record = store.get_node(&id).unwrap();
//! assert_eq!(back, record);
//! ```
//!
//! With the `merkle` feature also enabled, a whole [`MerkleNode`] DAG is
//! reconstructible from its root id the same way — see `tests/store.rs` (the
//! seam's whole test suite lives there, separated from source) for the
//! traversal pattern and the laws' executable counterparts.
//!
//! [`MerkleNode`]: crate::merkle::MerkleNode

use std::collections::btree_map::Entry;
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
    /// ingest; [`put_node`](NodeStoreExt::put_node) propagates encoding failures.
    #[error(transparent)]
    Content(#[from] ContentError),

    /// A backend I/O failure during a raw [`NodeStore`] operation.
    ///
    /// This is the variant a real disk / network / database backend needs but a
    /// downstream crate CANNOT add itself (`#[non_exhaustive]` reserves that for
    /// *this* crate). [`MemoryStore`] never produces it; a RocksDB / filesystem /
    /// S3 / HTTP backend surfaces its own error through `source`, tagged with the
    /// [`StoreOperation`] that failed. Without this the "replaceable storage seam"
    /// would be memory-only: a fallible backend would have nowhere truthful to put
    /// an I/O error.
    #[error("store backend error during {operation}")]
    Backend {
        /// The raw operation that failed.
        operation: StoreOperation,
        /// The backend's own error, preserved for the chain.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// An occupied id was asked to hold *different* bytes — a store-invariant
    /// violation (a hash collision, or a caller inserting mismatched `(id, bytes)`).
    ///
    /// The store **fails closed**: it never overwrites, so this makes the grow-only
    /// law (PO-STORE-3) hold *without* leaning on hash injectivity. Re-inserting
    /// *equal* bytes is still an idempotent success — only *divergent* bytes under a
    /// live id are a collision.
    #[error("content-id collision: {id} already holds different bytes")]
    Collision {
        /// The contested id.
        id: ContentId,
    },
}

/// The raw [`NodeStore`] operation a [`StoreError::Backend`] failure occurred in —
/// so a backend error names what it was doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreOperation {
    /// A raw fetch ([`NodeStore::get_unverified`]).
    Get,
    /// A raw store ([`NodeStore::insert`]).
    Insert,
}

impl std::fmt::Display for StoreOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Get => "get",
            Self::Insert => "insert",
        })
    }
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

    /// Store `bytes` **at the seam-derived `id`** — a dumb write.
    ///
    /// The backend does **not** compute the id: the sealed [`NodeStoreExt::put`]
    /// derives it with [`ContentId::from_canonical_bytes`] and hands both here.
    /// This is what makes PO-STORE-1 **sealed** rather than aspirational — a
    /// backend cannot mint or rebind identity because it never derives one, it
    /// only files bytes under the id it is told. (Contrast PO-STORE-2, sealed
    /// the same way: the backend does the dumb fetch, the seam does the check.)
    ///
    /// # Grow-only (PO-STORE-3)
    ///
    /// The mapping must be **write-once**: if `id` is already present, keep the
    /// existing bytes (they are equal by construction, absent a hash collision)
    /// rather than rebinding. There is no deletion.
    ///
    /// # Errors
    ///
    /// Infallible for [`MemoryStore`]; fallible backends surface failures
    /// through additively-added variants.
    fn insert(&mut self, id: ContentId, bytes: &[u8]) -> Result<(), StoreError>;
}

/// The operations structures actually call: verified reads and
/// identity-deriving writes over any [`NodeStore`].
///
/// Blanket-implemented for every `NodeStore` and **sealed by coherence**: the
/// blanket impl below is necessarily the *only* impl (any other would overlap
/// it), so no backend can supply its own body for these methods. Identity —
/// both deriving it on write ([`put`](Self::put)) and checking it on read
/// ([`get`](Self::get)) — lives here, never in a backend, so PO-STORE-1 and
/// PO-STORE-2 hold for arbitrary, even adversarial, backends. (A *provided*
/// trait method would not do: implementors can override those.)
///
/// The typed doors [`get_node`](Self::get_node) /
/// [`decode_verified_bytes`](Self::decode_verified_bytes) / [`put_node`](Self::put_node)
/// are generic methods here rather than free functions: [`NodeStore`] itself
/// stays object-safe (its two methods are non-generic), and `dyn NodeStore`
/// still receives every method on this trait through the blanket impl — a
/// generic method on an extension trait costs no object-safety on the base.
pub trait NodeStoreExt: NodeStore {
    /// **Hash-verified** raw fetch: guarantees the returned bytes re-derive `id`
    /// (PO-STORE-2), and *only* that.
    ///
    /// The contract is deliberately **byte-addressed, not canonical**: the id is
    /// re-derived with the *unchecked* [`ContentId::from_canonical_bytes`], so a
    /// hostile backend that stores valid-but-non-canonical dag-cbor under the id
    /// those exact bytes hash to will pass here. That is sound for a byte-addressed
    /// read — the bytes provably hash to `id` — but callers that need canonical
    /// bytes or an identity-preserving *typed* value must use
    /// [`get_node`](Self::get_node), which re-encodes and compares. (Raw canonical
    /// bytes on ingest are the writer's job via [`put_checked`](Self::put_checked).)
    ///
    /// This is the seam-level analogue of the frozen
    /// [`ensure_content_id`](crate::ContentAddressable::ensure_content_id)
    /// contract: a mismatch is an error carrying both ids, never wrong bytes.
    ///
    /// # Errors
    ///
    /// - [`StoreError::NotFound`] (or a backend's own [`StoreError::Backend`]) from
    ///   the raw fetch.
    /// - [`StoreError::Content`] wrapping
    ///   [`ContentError::VerificationFailed`] (with both ids' canonical `b…`
    ///   strings) if the fetched bytes do not re-derive `id` (PO-STORE-2).
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

    /// Derive the id from `bytes` and store them; returns the derived id.
    ///
    /// The id is [`ContentId::from_canonical_bytes`]`(bytes)` — computed **by
    /// the seam, not the backend** (PO-STORE-1). Precondition: `bytes` are
    /// canonical dag-cbor (normally guaranteed via [`put_node`](Self::put_node)).
    /// For foreign bytes, use [`put_checked`](Self::put_checked).
    ///
    /// # Errors
    ///
    /// Any error from the backend [`insert`](NodeStore::insert).
    fn put(&mut self, bytes: &[u8]) -> Result<ContentId, StoreError> {
        let id = ContentId::from_canonical_bytes(bytes);
        self.insert(id, bytes)?;
        Ok(id)
    }

    /// Opt-in **strict ingest** for untrusted bytes: verifies the bytes are
    /// canonical dag-cbor (round-trip check) before storing.
    ///
    /// On success the returned id is byte-identical to what
    /// [`put`](Self::put) would return — the check changes the fallibility,
    /// never the id (the same relationship the
    /// [`from_canonical_bytes_checked`](ContentId::from_canonical_bytes_checked)
    /// door has to its unchecked sibling).
    ///
    /// # Errors
    ///
    /// - [`StoreError::Content`] wrapping [`ContentError::DecodingError`] (not
    ///   dag-cbor at all), [`ContentError::NonCanonical`] (valid CBOR, wrong
    ///   encoding), or [`ContentError::EncodingError`] (the decoded value fails
    ///   to re-encode) — the full error set of
    ///   [`from_canonical_bytes_checked`](ContentId::from_canonical_bytes_checked).
    /// - Any error from the backend [`insert`](NodeStore::insert).
    fn put_checked(&mut self, bytes: &[u8]) -> Result<ContentId, StoreError> {
        let id = ContentId::from_canonical_bytes_checked(bytes)?;
        self.insert(id, bytes)?;
        Ok(id)
    }

    /// Decode the hash-verified bytes at `id` as a `T` — **without** guaranteeing
    /// the decoded value is *named by* `id`.
    ///
    /// This is the weaker, lenient door: it proves the raw bytes hash to `id`
    /// ([`get`](Self::get)) and that they decode as a `T`, but it does **not**
    /// re-encode `T` and compare. A `T` whose deserialization is lossy (dropped
    /// unknown fields, aliases, `#[serde(default)]`, flattening, a custom
    /// `Deserialize`) can decode from bytes whose canonical form — and therefore
    /// CID — differs from `id`. So `value.content_id() != id` is *possible* here.
    /// When identity must be preserved, use [`get_node`](Self::get_node).
    ///
    /// # Errors
    ///
    /// Everything [`get`](Self::get) can return, plus [`StoreError::Content`]
    /// wrapping [`ContentError::DecodingError`] if the (verified) bytes do not
    /// decode as a `T`.
    fn decode_verified_bytes<T: DeserializeOwned>(&self, id: &ContentId) -> Result<T, StoreError> {
        let bytes = self.get(id)?;
        canonical::from_canonical_dagcbor(&bytes).map_err(StoreError::from)
    }

    /// **Identity-preserving** typed read: fetch, decode as a `T`, then require the
    /// decoded value to re-encode to *exactly* the fetched bytes — so the returned
    /// value is provably the one named by `id`.
    ///
    /// This closes the gap in [`decode_verified_bytes`](Self::decode_verified_bytes):
    /// exact re-encode equality is strictly stronger than comparing hashes (it needs
    /// no collision-resistance assumption) and rejects any lossy round-trip — a map
    /// with an extra field that `T` silently discards decodes fine but re-encodes to
    /// *different* bytes, so it is rejected here rather than returned under the wrong
    /// identity.
    ///
    /// # Errors
    ///
    /// Everything [`get`](Self::get) can return; [`StoreError::Content`] wrapping
    /// [`ContentError::DecodingError`] if the bytes do not decode as a `T`,
    /// [`ContentError::EncodingError`] if the value fails to re-encode, or
    /// [`ContentError::VerificationFailed`] if the re-encoded bytes are not the
    /// bytes named by `id` (a lossy/aliased decode).
    fn get_node<T>(&self, id: &ContentId) -> Result<T, StoreError>
    where
        T: DeserializeOwned + ContentAddressable,
    {
        let original = self.get(id)?;
        let value: T = canonical::from_canonical_dagcbor(&original)?;
        let reencoded = value.canonical_form()?;
        if reencoded != original {
            // The decoded value is NOT the one named by `id`: its canonical form
            // addresses a different CID. Report that mismatch, not wrong bytes.
            let computed = ContentId::from_canonical_bytes(&reencoded);
            return Err(StoreError::Content(ContentError::VerificationFailed {
                expected: id.to_string(),
                computed: computed.to_string(),
            }));
        }
        Ok(value)
    }

    /// Encode a [`ContentAddressable`] node canonically and store it.
    ///
    /// The returned id equals `node.content_id()` (PO-STORE-1): storing a value
    /// and addressing a value are the same pure function of its content.
    ///
    /// # Errors
    ///
    /// [`StoreError::Content`] wrapping an encoding failure from
    /// [`canonical_form`](crate::ContentAddressable::canonical_form), or any
    /// error from the backend [`insert`](NodeStore::insert).
    fn put_node<T: ContentAddressable + ?Sized>(
        &mut self,
        node: &T,
    ) -> Result<ContentId, StoreError> {
        let bytes = node.canonical_form()?;
        self.put(&bytes)
    }
}

impl<S: NodeStore + ?Sized> NodeStoreExt for S {}

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

    fn insert(&mut self, id: ContentId, bytes: &[u8]) -> Result<(), StoreError> {
        // Grow-only, write-once (PO-STORE-3), FAIL-CLOSED: a vacant id takes the
        // bytes; an occupied id holding EQUAL bytes is an idempotent no-op; an
        // occupied id holding DIFFERENT bytes is a `Collision` that leaves state
        // untouched. Failing closed here means the grow-only law does not lean on
        // hash injectivity — divergent bytes under a live id can never silently win.
        match self.nodes.entry(id) {
            Entry::Vacant(slot) => {
                slot.insert(bytes.to_vec());
                Ok(())
            }
            Entry::Occupied(slot) if slot.get().as_slice() == bytes => Ok(()),
            Entry::Occupied(_) => Err(StoreError::Collision { id }),
        }
    }
}
