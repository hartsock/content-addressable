//! The CID-addressed node store seam — [`get`](NodeStoreExt::get)/[`put`](NodeStoreExt::put) by [`ContentId`], with a
//! verified read path the extension-trait implementation establishes.
//!
//! # Why this exists
//!
//! Every Merkle structure built on this crate resolves its child/parent links
//! the same way: a [`ContentId`] goes in, and **hash-verified bytes come out**
//! (identity-preserving *typed* reads additionally establish canonical
//! representation — see [`get`](NodeStoreExt::get) vs
//! [`get_node`](NodeStoreExt::get_node)). This module is that one narrow seam. A
//! structure never owns storage; it traverses a [`NodeStore`], so **a root CID
//! plus a store fully determines the structure** — hand someone the root id and
//! *any* store holding the bytes, and they can reconstruct the whole structure and
//! prove every node on the way down.
//!
//! Three properties make the seam trustworthy:
//!
//! 1. **Traversal is uniform.** All structures resolve links through this one
//!    trait — not N private storage conventions that diverge on exactly the
//!    thing that must stay uniform.
//! 2. **The verified path cannot be *re-implemented*.** Tampering happens in the
//!    backend (disk corruption, a hostile peer, a buggy cache). The verified
//!    [`get`](NodeStoreExt::get) lives in [`NodeStoreExt`], a blanket-implemented
//!    extension trait sealed by coherence: a backend implements only the raw
//!    [`get_unverified`](NodeStore::get_unverified) fetch and cannot supply a
//!    different body for the verified methods. **Caveat — this is not the same as
//!    "unskippable".** Rust prefers *inherent* methods in method-call resolution,
//!    so a concrete backend that defines its own inherent `fn get` will have
//!    ordinary `store.get(&id)` resolve to *that*, not the trait method. Code that
//!    must not be bypassed should hold a [`VerifiedStore`] (which exposes only the
//!    verified operations) or call `NodeStoreExt::get(store, id)` via UFCS.
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
//! - **PO-STORE-1A (put derives the address) \[proof target: Lean, deferred\]** —
//!   the **seam theorem** is [`put_node`](NodeStoreExt::put_node)`(n)` returns
//!   `Address(n.canonical_form())` (equivalently [`put`](NodeStoreExt::put)`(b)`
//!   returns [`ContentId::from_canonical_bytes`]`(b)`). This is **sealed**: the id
//!   is derived in the blanket-implemented extension, and the backend's only write
//!   op ([`insert`](NodeStore::insert)) receives an unforgeable [`AddressedBytes`]
//!   whose id it *cannot* have chosen — so a backend cannot influence the id [`put`](NodeStoreExt::put)
//!   returns, nor be handed bytes that do not derive their key. Addressing is a pure
//!   function of content. The corollary `put_node(n) == n.content_id()` holds
//!   **only for a lawful [`ContentAddressable`]** — one whose (overridable)
//!   [`content_id`](crate::ContentAddressable::content_id) honors `content_id() == Address(canonical_form())`; the seam
//!   cannot prove it for an arbitrary impl and does not rely on it ([`put_node`](NodeStoreExt::put_node) uses
//!   the strict [`put_checked`](NodeStoreExt::put_checked), so a non-canonical
//!   [`canonical_form`](crate::ContentAddressable::canonical_form) is a write-time error, not a mis-stamped id). (What a backend
//!   does *with* a well-formed pair — file it correctly, durably, without disturbing
//!   another entry — is PO-STORE-1B, not this law.)
//! - **PO-STORE-1B (backend acknowledgement) \[proof target: TLA+, a backend law, deferred\]** — that
//!   [`insert`](NodeStore::insert) returned `Ok` means only that the backend
//!   *accepted* the mapping under its documented durability/visibility contract.
//!   The blanket impl CANNOT prove the bytes were stored, stored under that id,
//!   readable later, or that no other mapping was disturbed: a backend that drops
//!   every write and returns `Ok(())` satisfies 1A (the returned id is still
//!   correct) while storing nothing. 1B is therefore a *backend* obligation, not a
//!   seam guarantee — [`MemoryStore`] discharges it (in-memory, immediate); a
//!   disk/network backend discharges it per its own model, surfacing failures
//!   through [`StoreError::Backend`].
//! - **PO-STORE-2 (verify-on-read soundness) \[proof target: Lean, deferred\]** — for **any** backend
//!   [`get_unverified`](NodeStore::get_unverified), including an adversarial one,
//!   [`NodeStoreExt::get`]`(id)` returns `Ok(b)` only if
//!   `from_canonical_bytes(b) == id` (byte-addressed: `b` hashes to `id`; it does
//!   *not* assert `b` is canonical — see [`get`](NodeStoreExt::get) and the
//!   identity-preserving [`get_node`](NodeStoreExt::get_node)). Corruption or
//!   substitution surfaces as [`ContentError::VerificationFailed`], never as wrong
//!   bytes. This holds for arbitrary backends because [`get`](NodeStoreExt::get) is blanket-implemented
//!   and sealed by coherence.
//! - **PO-STORE-3 (grow-only monotonicity, fail-closed) \[proof target: TLA+, a backend law, deferred\]** —
//!   a *conforming* backend's `id → bytes` map only grows and a mapping is never
//!   rebound: re-inserting the *same* bytes is idempotent, and *different* bytes
//!   under a live id **fail closed** with [`StoreError::Collision`], leaving state
//!   unchanged. Like PO-STORE-1B this is a **backend** obligation, NOT a seam
//!   theorem: [`AddressedBytes`] proves only that the pair handed to a backend is
//!   address-consistent — it cannot stop an arbitrary backend from deleting or
//!   overwriting an *unrelated* mapping, so the blanket seam / [`VerifiedStore`] do
//!   not establish grow-only for arbitrary backends. [`MemoryStore`] **discharges**
//!   it (its occupied-different branch fails closed without mutation; the law never
//!   leans on hash injectivity). This is the invariant a future GC/eviction design
//!   must consciously renegotiate, which is why deletion is a non-goal here.
//!
//! The `[proof target: …]` tags mark **deferred** obligations — the mechanized
//! Lean/TLA+ artifacts are NOT yet shipped (a follow-up stands up a forced-collision
//! TLA+ model + Lean read/insert laws). What ships today is the design plus
//! executable counterparts in `tests/store.rs` for *most* of the laws. The one
//! exception is PO-STORE-3's `Collision` branch (divergent bytes under a live id):
//! because [`AddressedBytes`] always derives a real BLAKE3 id, that branch is only
//! reachable via a genuine hash collision, so it has **no** executable Rust
//! counterpart — it is the deferred forced-collision TLA+ model's job (tracked as a
//! follow-up issue), not something `tests/store.rs` exercises.
//!
//! # ⚠️ EXPERIMENTAL — default-off feature, API NON-FROZEN
//!
//! This module is gated behind the default-**off** `unstable-store` cargo feature, and
//! its trait API is **NOT frozen**: signatures may change without a breaking-
//! change ceremony until the catalog stabilizes (epic #30's release ladder).
//! The seam defines **no new wire bytes of its own** — it stores bytes whose
//! layout is owned elsewhere (canonical dag-cbor when written through the typed
//! [`put_node`](NodeStoreExt::put_node) / [`put_checked`](NodeStoreExt::put_checked) doors; the raw [`put`](NodeStoreExt::put) is unchecked) — so nothing here is added to
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
//! With the `unstable-merkle` feature also enabled, a whole [`MerkleNode`] DAG is
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
use crate::trait_def::{checked_decode, CheckedDecode, ContentAddressable};

/// Store-layer errors.
///
/// Deliberately a **separate enum**, not new variants on the frozen
/// [`ContentError`] (freeze minimally — the frozen surface is untouched):
/// `NotFound` and backend failures are store concerns, while every
/// content-integrity failure is carried verbatim in the
/// [`Content`](StoreError::Content) variant so callers can still match on the
/// exact [`ContentError`] mode (verification, decoding, non-canonical, …).
///
/// `#[non_exhaustive]` because the API is experimental: further variants (e.g.
/// batching) may arrive additively. The [`Backend`](StoreError::Backend) variant a
/// fallible disk/network store needs is already present.
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

    /// An occupied id was asked to hold *different* bytes — reachable only by a
    /// genuine hash collision (a mismatched `(id, bytes)` is unrepresentable via the
    /// unforgeable [`AddressedBytes`]).
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

    /// A typed read decoded, but the value did NOT re-encode to the stored bytes —
    /// so it is not the value *named by* the id (a lossy/aliased deserialization).
    ///
    /// This is distinct from [`Content`](StoreError::Content)`(VerificationFailed)`:
    /// the decisive condition is exact BYTE inequality of the re-encoding, not CID
    /// inequality (under a real hash collision the two CIDs could even coincide).
    /// Produced only by [`NodeStoreExt::get_node`].
    #[error("typed read did not preserve the identity named by {id}")]
    RepresentationMismatch {
        /// The id the value was read under.
        id: ContentId,
    },
}

/// An **address-consistent** byte slice: bytes paired with the id they derive —
/// the only thing a [`NodeStore::insert`] can be handed.
///
/// It witnesses exactly one relationship — `id() == from_canonical_bytes(bytes())`
/// — and deliberately **not** canonicality. The id comes from the *unchecked*
/// [`ContentId::from_canonical_bytes`], and [`NodeStoreExt::put`] accepts any byte
/// slice, so `bytes()` may be non-canonical dag-cbor (validate ingest with
/// [`put_checked`](NodeStoreExt::put_checked); establish typed identity with
/// [`get_node`](NodeStoreExt::get_node)). A backend author must NOT infer
/// canonicality from this type.
///
/// The pair is unforgeable: the field is private and the constructor is
/// crate-internal, so *only the sealed seam* mints one (from bytes it hashes). An
/// external caller cannot construct a mismatched `(id, bytes)` pair, so a backend
/// can never be poisoned with bytes that do not derive their key. This moves
/// PO-STORE-1A's sealing from "the seam promises to derive the id" to "a backend
/// cannot even be handed a wrong one".
///
/// The unforgeability is compiler-enforced — neither of these builds downstream:
///
/// ```compile_fail
/// # use content_addressable::store::AddressedBytes;
/// // the id-deriving constructor is crate-internal:
/// let _ = AddressedBytes::new(b"anything");
/// ```
///
/// ```compile_fail
/// # use content_addressable::{ContentId, store::AddressedBytes};
/// // the fields are private, so a mismatched literal cannot be built either:
/// let _ = AddressedBytes { id: ContentId::from_canonical_bytes(b"a"), bytes: b"b" };
/// ```
#[derive(Debug, Clone, Copy)]
pub struct AddressedBytes<'a> {
    id: ContentId,
    bytes: &'a [u8],
}

impl<'a> AddressedBytes<'a> {
    /// Mint an addressed pair by DERIVING the id from `bytes` (crate-internal: the
    /// seam is the only minter, so the pair is always consistent).
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self {
            id: ContentId::from_canonical_bytes(bytes),
            bytes,
        }
    }

    /// The content id these bytes derive — the key a backend files under.
    #[must_use]
    pub fn id(&self) -> ContentId {
        self.id
    }

    /// The bytes (paired with the id they derive — not necessarily canonical; see
    /// the type docs).
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
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

/// The narrow seam every structure traverses: raw fetch and store of bytes, keyed
/// by [`ContentId`] (canonicality is the typed doors' concern, not this raw seam's).
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
    /// [`StoreError::NotFound`] if the store holds no bytes for `id`; a fallible
    /// backend surfaces its own I/O failure through [`StoreError::Backend`].
    fn get_unverified(&self, id: &ContentId) -> Result<Vec<u8>, StoreError>;

    /// File an [`AddressedBytes`] — a dumb write of address-consistent bytes under
    /// the id they derive (not necessarily canonical; see [`AddressedBytes`]).
    ///
    /// The backend does **not** compute the id and cannot be handed a wrong one:
    /// [`AddressedBytes`] is unforgeable (only the sealed seam mints it, by hashing
    /// the bytes), so `item.id()` is provably `from_canonical_bytes(item.bytes())`.
    /// A backend therefore cannot be poisoned with bytes that do not derive their
    /// key (PO-STORE-1A). What a backend does *with* an accepted, well-formed pair —
    /// whether it durably stores it, files it correctly, or disturbs another entry —
    /// is the backend's own contract (PO-STORE-1B), surfaced through
    /// [`StoreError::Backend`].
    ///
    /// # Grow-only (PO-STORE-3)
    ///
    /// The mapping is **write-once**: re-filing the same id with equal bytes is an
    /// idempotent no-op; different bytes under a live id (reachable only by a genuine
    /// hash collision, since the pair is consistent by construction) **fail closed**
    /// with [`StoreError::Collision`], never a rebind. There is no deletion.
    ///
    /// # Errors
    ///
    /// [`StoreError::Collision`] on a genuine collision; a fallible backend surfaces
    /// its own I/O failure through [`StoreError::Backend`]. Infallible-but-for-
    /// collisions for [`MemoryStore`].
    fn insert(&mut self, item: AddressedBytes<'_>) -> Result<(), StoreError>;
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
        let addressed = AddressedBytes::new(bytes);
        let id = addressed.id();
        self.insert(addressed)?;
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
        // Strict-validate canonicality first (rejects non-canonical bytes), then
        // file the addressed pair (same id — checked/unchecked agree for canonical b).
        let id = ContentId::from_canonical_bytes_checked(bytes)?;
        self.insert(AddressedBytes::new(bytes))?;
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
        // The bare decode ON PURPOSE: leniency is this door's whole contract (see
        // the doc above — it is the weaker sibling of `get_node`, and its `T` need
        // not even be `ContentAddressable`). It reaches the crate-internal
        // primitive rather than the deprecated public `from_canonical_dagcbor` so
        // the deprecation stays a signal to CALLERS choosing a door, not noise
        // inside the door that documents its own leniency.
        canonical::decode_dagcbor(&bytes).map_err(StoreError::from)
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
    /// The check is the same three stages
    /// [`ContentAddressable::from_canonical_form`] performs (issue #90), sharing
    /// one implementation with it — but this seam runs that shared body directly
    /// rather than calling the trait method, which is *defaulted* and therefore
    /// overridable. A `T` cannot hand itself a pass here.
    ///
    /// # Errors
    ///
    /// Everything [`get`](Self::get) can return, plus [`StoreError::Content`]
    /// wrapping, by stage:
    /// - **canonicality check** (the generic gate shared with
    ///   [`from_canonical_bytes_checked`](ContentId::from_canonical_bytes_checked)):
    ///   [`ContentError::DecodingError`] (not dag-cbor), [`ContentError::NonCanonical`]
    ///   (valid CBOR, non-canonical), or [`ContentError::EncodingError`] (the generic
    ///   IPLD re-encode inside the check fails) — distinct from `T::canonical_form`;
    /// - **typed decode**: [`ContentError::DecodingError`] if the bytes do not
    ///   decode as a `T`;
    /// - **`T::canonical_form`**: whatever [`ContentError`] it returns (typically
    ///   [`ContentError::EncodingError`]);
    ///
    /// and [`StoreError::RepresentationMismatch`] if the re-encoded bytes are not the
    /// bytes named by `id` (a lossy/aliased decode).
    fn get_node<T>(&self, id: &ContentId) -> Result<T, StoreError>
    where
        T: DeserializeOwned + ContentAddressable,
    {
        let original = self.get(id)?;
        // The three-stage check is the one `ContentAddressable::from_canonical_form`
        // performs (issue #90) — but this runs the SHARED BODY, not that method.
        // `from_canonical_form` is defaulted on an unsealed trait, so a `T` can
        // override it, including with a bare unverified decode; routing the seam
        // through it would hand `T` the very guarantee this seam exists to make.
        // Stages 1 and 2 (canonicality, then the typed decode) stay the seam's,
        // so they run BEFORE any `T` is trusted and cannot be turned off from
        // outside. Stage 3 necessarily consults `T::canonical_form` — that is
        // what identity means for a `ContentAddressable`.
        //
        // The lossy verdict arrives as a VALUE, so a `ContentError::LossyDecode`
        // that came out of `T::canonical_form` itself is NOT mistaken for it and
        // still propagates verbatim, as this function's error table promises.
        match checked_decode::<T>(&original)? {
            CheckedDecode::Value(value) => Ok(value),
            // Exact byte inequality is the decisive condition (stronger than
            // comparing CIDs — no collision-resistance assumption): the decoded
            // value is NOT the one named by `id`.
            CheckedDecode::Lossy => Err(StoreError::RepresentationMismatch { id: *id }),
        }
    }

    /// Encode a [`ContentAddressable`] node and store it **strictly**.
    ///
    /// Because [`ContentAddressable`] only requires *determinism* (equal values ⇒
    /// equal bytes), not canonical dag-cbor, this routes through
    /// [`put_checked`](Self::put_checked): a [`canonical_form`](crate::ContentAddressable::canonical_form) that returns
    /// non-canonical CBOR (or non-CBOR) is a **write-time error** here, not a
    /// DAG-CBOR-stamped id naming bytes that are not DAG-CBOR. So the seam does not
    /// trust a trait law it cannot enforce.
    ///
    /// The returned id is `Address(node.canonical_form())` (the seam theorem, PO-STORE-1A).
    /// It equals `node.content_id()` **only for a lawful implementation** — one whose
    /// (overridable) [`content_id`](crate::ContentAddressable::content_id) honors `content_id() == Address(canonical_form())`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Content`] wrapping, by stage: an encoding failure from
    /// [`canonical_form`](crate::ContentAddressable::canonical_form) (typically
    /// [`ContentError::EncodingError`]); then, from the strict
    /// [`put_checked`](Self::put_checked) canonicality check on that output,
    /// [`ContentError::DecodingError`] (not dag-cbor), [`ContentError::NonCanonical`]
    /// (valid CBOR, non-canonical), or [`ContentError::EncodingError`] (the check's
    /// own re-encode fails); or any error from the backend
    /// [`insert`](NodeStore::insert).
    fn put_node<T: ContentAddressable + ?Sized>(
        &mut self,
        node: &T,
    ) -> Result<ContentId, StoreError> {
        let bytes = node.canonical_form()?;
        self.put_checked(&bytes)
    }
}

impl<S: NodeStore + ?Sized> NodeStoreExt for S {}

// Forwarding impls so the verified surface composes with the advertised dynamic and
// borrowed forms: `VerifiedStore::new(Box::<dyn NodeStore>::new(..))` and
// `VerifiedStore::new(&mut backend)` both need `B: NodeStore`. (Method calls already
// worked through deref; wrapping a backend in the facade needs the trait itself.)
impl<S: NodeStore + ?Sized> NodeStore for Box<S> {
    fn get_unverified(&self, id: &ContentId) -> Result<Vec<u8>, StoreError> {
        (**self).get_unverified(id)
    }
    fn insert(&mut self, item: AddressedBytes<'_>) -> Result<(), StoreError> {
        (**self).insert(item)
    }
}

impl<S: NodeStore + ?Sized> NodeStore for &mut S {
    fn get_unverified(&self, id: &ContentId) -> Result<Vec<u8>, StoreError> {
        (**self).get_unverified(id)
    }
    fn insert(&mut self, item: AddressedBytes<'_>) -> Result<(), StoreError> {
        (**self).insert(item)
    }
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

    fn insert(&mut self, item: AddressedBytes<'_>) -> Result<(), StoreError> {
        // The (id, bytes) pair is consistent by construction (AddressedBytes is
        // unforgeable), so a VACANT slot can never be poisoned with bytes that do
        // not derive their key. Grow-only, write-once (PO-STORE-3), FAIL-CLOSED: a
        // vacant id takes the bytes; an occupied id holding EQUAL bytes is an
        // idempotent no-op; an occupied id holding DIFFERENT bytes — reachable ONLY
        // by a genuine hash collision — is a `Collision` that leaves state untouched.
        // So the grow-only law leans on neither hash injectivity nor caller honesty.
        let (id, bytes) = (item.id(), item.bytes());
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

/// A verified facade over any [`NodeStore`] backend: it exposes **only** the
/// verified operations, each dispatched to [`NodeStoreExt`] by fully-qualified
/// syntax, so a backend's own inherent method of the same name can never intercept
/// the call.
///
/// The blanket [`NodeStoreExt`] impl is sealed — a backend cannot *replace the
/// trait implementation*. But that is not the same as "unskippable": ordinary
/// `store.get(&id)` on a concrete type resolves to an inherent `fn get` if the type
/// defines one, because Rust prefers inherent methods in method-call resolution.
/// Code that must not be bypassed should therefore hold a `VerifiedStore<B>` (or
/// call `NodeStoreExt::get(store, id)` via UFCS) rather than a bare `B: NodeStore`
/// on which `.get(..)` might resolve to something unverified.
pub struct VerifiedStore<B> {
    backend: B,
}

impl<B: NodeStore> VerifiedStore<B> {
    /// Wrap a backend so only verified operations are reachable.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// **Consume** the facade, returning the raw backend — an explicit capability
    /// *downgrade*. There is deliberately no `&B` accessor: a borrow would let code
    /// holding `&VerifiedStore<_>` tunnel underneath it (`v.backend().get_unverified(..)`
    /// or a hostile inherent `v.backend().get(..)`), re-opening exactly the bypass
    /// this facade closes. Downgrading requires *ownership* and reads as one.
    pub fn into_unverified_backend(self) -> B {
        self.backend
    }

    /// Hash-verified fetch — always the sealed [`NodeStoreExt::get`].
    pub fn get(&self, id: &ContentId) -> Result<Vec<u8>, StoreError> {
        NodeStoreExt::get(&self.backend, id)
    }

    /// Identity-preserving typed read — always [`NodeStoreExt::get_node`].
    pub fn get_node<T>(&self, id: &ContentId) -> Result<T, StoreError>
    where
        T: DeserializeOwned + ContentAddressable,
    {
        NodeStoreExt::get_node(&self.backend, id)
    }

    /// Lenient typed decode — always [`NodeStoreExt::decode_verified_bytes`].
    pub fn decode_verified_bytes<T: DeserializeOwned>(
        &self,
        id: &ContentId,
    ) -> Result<T, StoreError> {
        NodeStoreExt::decode_verified_bytes(&self.backend, id)
    }

    /// Identity-deriving write — always [`NodeStoreExt::put`].
    pub fn put(&mut self, bytes: &[u8]) -> Result<ContentId, StoreError> {
        NodeStoreExt::put(&mut self.backend, bytes)
    }

    /// Strict ingest of untrusted bytes — always [`NodeStoreExt::put_checked`].
    pub fn put_checked(&mut self, bytes: &[u8]) -> Result<ContentId, StoreError> {
        NodeStoreExt::put_checked(&mut self.backend, bytes)
    }

    /// Store a [`ContentAddressable`] node — always [`NodeStoreExt::put_node`].
    pub fn put_node<T: ContentAddressable + ?Sized>(
        &mut self,
        node: &T,
    ) -> Result<ContentId, StoreError> {
        NodeStoreExt::put_node(&mut self.backend, node)
    }
}
