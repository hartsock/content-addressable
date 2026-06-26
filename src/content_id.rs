//! [`ContentId`] — the self-certifying identity of a value.
//!
//! A `ContentId` is a newtype over an IPLD [`Cid`] (content identifier, v1).
//! It is computed directly from a value's canonical bytes, so it *is* a proof
//! of integrity: anyone holding the bytes can recompute the id and confirm the
//! bytes are exactly what the id names. Nothing trusted needs to vouch for the
//! association — it is intrinsic.

use std::fmt;
use std::str::FromStr;

use ipld_core::cid::multihash::Multihash;
use ipld_core::cid::Cid;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ContentError;

/// Multicodec code for the `dag-cbor` content type (`0x71`).
///
/// This is the codec field of every [`ContentId`]'s CID: it declares that the
/// bytes the id names are canonical dag-cbor. **Frozen** for the `0.1.x` line —
/// see the [`ContentId` CID-parameters contract](ContentId#cid-parameters-frozen-at-010).
pub const DAG_CBOR_CODEC: u64 = 0x71;

/// Multihash code for BLAKE3 (`0x1e`).
///
/// This is the hash function field of every [`ContentId`]'s multihash.
/// **Frozen** for the `0.1.x` line — see the
/// [`ContentId` CID-parameters contract](ContentId#cid-parameters-frozen-at-010).
pub const BLAKE3_HASH_CODE: u64 = 0x1e;

/// Length of a BLAKE3 digest in bytes (256 bits).
///
/// Part of the **frozen** v1 CID-parameter contract: every [`ContentId`]'s
/// multihash carries exactly 32 digest bytes. Kept private (no new public
/// surface, gate item 9); the value is asserted by the CID-shape tests and is
/// implied on the wire by the `0x20` multihash length prefix. Changing it is a
/// major version bump — see the
/// [`ContentId` CID-parameters contract](ContentId#cid-parameters-frozen-at-010).
const BLAKE3_DIGEST_LEN: usize = 32;

/// The self-certifying identity of a value.
///
/// A `ContentId` wraps an IPLD CIDv1 whose codec is `dag-cbor` (`0x71`) and
/// whose multihash is BLAKE3 (`0x1e`) over the value's canonical dag-cbor
/// bytes. See [`from_canonical_bytes`](Self::from_canonical_bytes).
///
/// Ordering is defined by the CID's binary representation, which makes
/// `ContentId` usable as a key in ordered maps and sets with a stable,
/// content-derived sort.
///
/// # CID parameters (FROZEN at 0.1.0)
///
/// The three fields that determine every address this crate emits are a
/// **fixed v1 contract**, not configuration (gate items 3, 4, 5 — see
/// `README.md`):
///
/// - **CID version: `V1`** (`Cid::new_v1`). There is no v0 / agility path.
/// - **Multicodec: `dag-cbor` (`0x71`)** — see [`DAG_CBOR_CODEC`].
/// - **Multihash: `BLAKE3` (`0x1e`)** — see [`BLAKE3_HASH_CODE`] — over a
///   **fixed 32-byte digest** (`BLAKE3_DIGEST_LEN`, 256 bits).
///
/// These values are **not selectable**. [`from_canonical_bytes`](Self::from_canonical_bytes)
/// is the single mint site and always produces this shape. Changing the
/// version, codec, hash function, or digest length is a **new representation =
/// major version bump**, never a patch — every previously emitted address would
/// become unreachable. CIDs are self-describing, so a future hash/codec can
/// ship as a *new* representation under a *new* major without retrofitting
/// agility now; callers needing a different shape today can wrap a raw [`Cid`]
/// via the [`From<Cid>`](#impl-From%3CCid%3E-for-ContentId) / [`as_cid`](Self::as_cid)
/// seam.
///
/// # Serde representation (FROZEN at 0.1.0)
///
/// `ContentId` has two serde forms, chosen by the serializer via
/// `is_human_readable`, and **both are a stability contract across the entire
/// `0.1.x` line** — changing either is a **major version bump**. The committed
/// golden vectors (`tests/vectors.json`) plus the in-crate golden test pin
/// these exact bytes so a dependency bump cannot silently perturb them:
///
/// - **Binary / IPLD form (e.g. dag-cbor): a tag-42 link.** Through
///   [`serde_ipld_dagcbor`] a `ContentId` is encoded as a CBOR **tag-42 link**
///   (major-type-6 head `0xd8 0x2a`, then a byte string carrying the `0x00`
///   multibase-identity prefix followed by the CID binary form). This is the
///   natural IPLD encoding and makes `ContentId` fields inside other
///   content-addressed structures behave as real links — the crate's
///   IPLD-native thesis. See [`canonical`](crate::canonical).
/// - **Human-readable form (e.g. `serde_json`, TOML): the multibase base32
///   string.** In a human-readable serializer a `ContentId` is the
///   base32-lower `b…` CID string — the same text
///   [`Display`](fmt::Display)/[`FromStr`] produce — so JSON and config files
///   carry a readable, portable CID rather than a raw byte array. The crate
///   adds a thin `is_human_readable` branch over the inner `Cid` to guarantee
///   this; the IPLD/binary path is unchanged.
///
/// # Presentation contract (FROZEN at 0.1.0)
///
/// Whatever string and byte forms this type emits become a **byte/wire
/// contract** at `0.1.0`: changing any of them afterward is a **major version
/// bump**, never a patch (issue #6, gate item 2). The full presentation
/// surface is therefore named and frozen explicitly, with conformance vectors
/// (`tests/vectors.json` + the in-crate goldens) pinning the exact bytes. There
/// are **four** distinct presentation forms, each load-bearing for a different
/// reason — do not confuse them:
///
/// | Form | Method | What it is |
/// |------|--------|------------|
/// | **Canonical text** | [`Display`](fmt::Display) / [`to_string`](ToString::to_string) | multibase **base32-lower** (`b…`), the IPLD-canonical CID string |
/// | **Binary envelope** | [`to_bytes`](Self::to_bytes) / [`from_bytes`](Self::from_bytes) | the full **CID binary** form (version + codec + multihash + digest) |
/// | **Bare digest** | [`digest_bytes`](Self::digest_bytes) | the raw **32-byte BLAKE3** hash (no envelope) |
/// | **Bare-digest-hex** | [`digest_hex`](Self::digest_hex) | lowercase **hex of the 32-byte digest** (64 chars, no prefix) |
///
/// **Three incompatible "hex" conventions** exist in the wild for a CID; an
/// adopter must pick one, so the crate names them to end the ambiguity:
///
/// 1. **bare-digest-hex** — hex of the raw 32-byte BLAKE3 digest. *This is what
///    [`digest_hex`](Self::digest_hex) returns* (the "swarm" / kyln `to_hex()`
///    convention: shortest, hash-only).
/// 2. **full-CID-bytes-hex** — hex of [`to_bytes`](Self::to_bytes) (the whole
///    CID envelope as base16). *Deliberately **not** a method.* Convention #2 is
///    just `hex::encode(id.to_bytes())`; blessing it as `cid_hex()` would add a
///    third "hex" accessor that invites exactly the confusion this contract
///    exists to end. A caller who genuinely needs CID-bytes-as-hex hex-encodes
///    [`to_bytes`](Self::to_bytes) explicitly and owns that choice. (This
///    non-decision is recorded so it is not re-litigated; it can be added later
///    additively without breaking the frozen surface.)
/// 3. **multibase base32-lower** — the [`Display`](fmt::Display) string. Use
///    this, not a hex form, as the canonical text representation.
///
/// `Display` emits base32-lower and is the **inverse of [`FromStr`] for that
/// form**: the `Display`→`FromStr` round-trip is frozen and tested. `FromStr`
/// *also* tolerates other multibases (base58, base16, …) as a **convenience,
/// not a contract** — that tolerance may be tightened later without breaking
/// the frozen base32-lower round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentId(Cid);

impl ContentId {
    /// Compute the content id of bytes that **are already canonical dag-cbor**.
    ///
    /// This is the crate's fast, unchecked minting primitive — the hot path that
    /// [`ContentAddressable::content_id`](crate::ContentAddressable::content_id)
    /// leans on. The pipeline is, end to end:
    ///
    /// 1. `digest = BLAKE3(bytes)` — a 32-byte hash.
    /// 2. `mh = Multihash::wrap(0x1e, digest)` — tag the digest with the
    ///    BLAKE3 multihash code.
    /// 3. `cid = Cid::new_v1(0x71, mh)` — a CIDv1 declaring the bytes are
    ///    dag-cbor.
    ///
    /// # Precondition — CALLER MUST PASS CANONICAL DAG-CBOR
    ///
    /// **The bytes you pass MUST already be canonical dag-cbor** — typically the
    /// output of
    /// [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor) or, for a
    /// whole value, [`ContentAddressable::canonical_form`](crate::ContentAddressable::canonical_form).
    /// This function **does not re-canonicalize and does not validate**; it only
    /// hashes whatever it is handed and stamps the result with the `0x71`
    /// (dag-cbor) codec.
    ///
    /// Passing **non-canonical** CBOR (wrong map-key order, indefinite-length
    /// items, non-smallest integers), hand-rolled CBOR, or arbitrary non-dag-cbor
    /// bytes is a **logic error, not handled at runtime**: you get back a
    /// perfectly valid-looking [`ContentId`] whose `0x71` codec is a **lie** —
    /// the bytes it names are not canonical dag-cbor. A second party who
    /// canonicalizes "the same value" will compute a **different** id, and
    /// nothing here will have told you. This is silent and by design (validation
    /// is not free, so it is opt-in — see below), so honor the precondition.
    ///
    /// # Which door to use
    ///
    /// - **Have a value?** Use
    ///   [`ContentAddressable::content_id`](crate::ContentAddressable::content_id)
    ///   (the documented default). It canonicalizes *then* hashes, so it can
    ///   never hand this function non-canonical bytes — the precondition holds by
    ///   construction and there is no per-call validation tax on the safe path.
    /// - **Have bytes you canonicalized yourself** (via
    ///   [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor))?
    ///   This primitive is correct and fastest.
    /// - **Have foreign / untrusted bytes you did *not* canonicalize?** Use the
    ///   checked sibling
    ///   [`from_canonical_bytes_checked`](Self::from_canonical_bytes_checked),
    ///   which re-encodes and rejects non-canonical input with a typed error.
    ///
    /// # Naming (FROZEN at 0.1.0)
    ///
    /// This door keeps the name `from_canonical_bytes` (the fast primitive) and
    /// is **not** renamed to `_unchecked`; the checked variant is the explicitly
    /// suffixed [`from_canonical_bytes_checked`](Self::from_canonical_bytes_checked).
    /// This pairing is a frozen `0.1.0` decision (README gate item #6) — it
    /// cannot change cheaply after `0.1.0`.
    ///
    /// # Panics
    ///
    /// Does not panic. BLAKE3 always produces a 32-byte digest, which always
    /// fits the multihash's 64-byte capacity, so the `wrap` call cannot fail.
    #[must_use]
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        let digest = blake3::hash(bytes);
        Self::wrap_blake3_digest(*digest.as_bytes())
    }

    /// Compute the content id of bytes, **first verifying they are canonical
    /// dag-cbor**.
    ///
    /// This is the opt-in, *checked* sibling of
    /// [`from_canonical_bytes`](Self::from_canonical_bytes). It is for callers
    /// minting an id from bytes they did **not** canonicalize themselves
    /// (foreign, untrusted, hand-rolled, or stored input) and who therefore
    /// cannot rely on the precondition by construction. It closes the silent
    /// integrity hole the fast primitive leaves open, at the cost of a decode +
    /// re-encode + compare on every call — pay it only when byte provenance is
    /// not yours.
    ///
    /// The check is a **round-trip**: decode the bytes as an
    /// [`Ipld`](ipld_core::ipld::Ipld) value, re-encode that value via
    /// [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor), and
    /// require the re-encoding to equal the input byte-for-byte. Because the
    /// dag-cbor codec is canonical by construction (strict key order,
    /// definite-length, smallest-form integers — see
    /// [`canonical`](crate::canonical)), equality proves the input was *already*
    /// the unique canonical encoding of that value. On success the id is computed
    /// over the (canonical) input bytes, so it is **byte-identical** to what
    /// [`from_canonical_bytes`](Self::from_canonical_bytes) would return for the
    /// same bytes — the check changes the fallibility, never the emitted id.
    ///
    /// # Errors
    ///
    /// - [`ContentError::DecodingError`] if `bytes` are not dag-cbor at all.
    /// - [`ContentError::NonCanonical`] if `bytes` decode but are *not* the
    ///   canonical encoding (wrong map-key order, indefinite-length items,
    ///   non-smallest integers, …) — i.e. re-encoding differs from the input.
    /// - [`ContentError::EncodingError`] in the unlikely event the decoded value
    ///   cannot be re-encoded.
    pub fn from_canonical_bytes_checked(bytes: &[u8]) -> Result<Self, ContentError> {
        // 1. Decode to the generic Ipld value. Non-dag-cbor garbage fails here.
        let value: ipld_core::ipld::Ipld = crate::canonical::from_canonical_dagcbor(bytes)?;
        // 2. Re-encode canonically. The codec emits the *unique* canonical form.
        let reencoded = crate::canonical::to_canonical_dagcbor(&value)?;
        // 3. The input was canonical iff it equals its own canonical re-encoding.
        if reencoded != bytes {
            return Err(ContentError::NonCanonical);
        }
        // The bytes are proven canonical: minting over them is identical to the
        // unchecked primitive, so reuse it (no second decode/encode).
        Ok(Self::from_canonical_bytes(bytes))
    }

    /// Wrap an **already-computed** 32-byte BLAKE3 content digest as a
    /// `ContentId` — **without hashing**.
    ///
    /// This is a deliberately narrow, *unchecked* escape hatch for
    /// **BLAKE3-native upstreams** that have already hashed their content and
    /// hold only the 32-byte digest (a signature, an address) — not the
    /// original canonical bytes. For them,
    /// [`from_canonical_bytes`](Self::from_canonical_bytes) is not just
    /// wasteful, it is *impossible*: there are no bytes left to hash. This
    /// constructor takes the digest they already have and wraps it directly:
    /// `Multihash::wrap(0x1e, digest)` → `Cid::new_v1(0x71, mh)`. No BLAKE3
    /// step runs, and the result is byte-identical to what
    /// [`from_canonical_bytes`](Self::from_canonical_bytes) would have produced
    /// *had the caller hashed the real content correctly*.
    ///
    /// The `[u8; 32]` argument makes the 32-byte length a **compile-time**
    /// guarantee: it is impossible to call with a wrong-length digest, so no
    /// runtime length check, no fallible signature, and no new error variant
    /// are needed. Callers holding a `&[u8]` convert with `try_into()` and own
    /// that fallibility.
    ///
    /// # ⚠️ UNCHECKED ESCAPE HATCH — CALLER ASSERTS THE PRECONDITION ⚠️
    ///
    /// This constructor **does not hash and does not canonicalize**. It trusts
    /// the caller completely. By calling it you **assert** that `digest` is
    /// exactly `BLAKE3` over the value's **canonical dag-cbor** bytes — the same
    /// input domain [`from_canonical_bytes`](Self::from_canonical_bytes) would
    /// hash.
    ///
    /// If that assertion is false — the digest was computed over non-canonical
    /// bytes, over a different encoding, with a different hash, or is simply
    /// arbitrary — the result is a `ContentId` that **names content nothing
    /// actually hashed**. Such an id is silently wrong: there is no error, and
    /// verifying it against the real bytes returns `Ok(false)`, never an `Err`.
    ///
    /// **If you have the content bytes, use
    /// [`from_canonical_bytes`](Self::from_canonical_bytes) instead** — it
    /// hashes them for you and cannot be wrong this way. Do *not* reach for
    /// this constructor merely to avoid a hash; reach for it only when you
    /// genuinely hold a precomputed, canonical-dag-cbor BLAKE3 digest and the
    /// content itself is gone.
    ///
    /// # Motivation
    ///
    /// The kyln-lore `address.rs` bridge (`blake3_digest_to_content_id` /
    /// `signature_to_content_id`) does exactly this: a lore revision signature
    /// *is* a raw 32-byte BLAKE3 digest of the content, so it becomes a kyln
    /// `ContentId` by wrapping it — minus the `blake3::hash` step, because lore
    /// already hashed the content. That bridge is what makes a projected git
    /// commit's provenance note `content_id` *equal* the originating lore
    /// revision signature. kyln's adoption (kyln #303) and any other
    /// BLAKE3-native source needs this primitive so a system that already
    /// hashed with BLAKE3 gets an *exact* `ContentId` with no re-hash.
    ///
    /// # Panics
    ///
    /// Does not panic. A 32-byte digest always fits the multihash's 64-byte
    /// capacity, so the `wrap` call cannot fail.
    #[must_use]
    pub fn from_blake3_content_digest(digest: [u8; BLAKE3_DIGEST_LEN]) -> Self {
        Self::wrap_blake3_digest(digest)
    }

    /// Wrap a 32-byte BLAKE3 digest as a [`ContentId`]: the frozen tail shared
    /// by [`from_canonical_bytes`] (which hashes first) and
    /// [`from_blake3_content_digest`] (which does not). Keeping the
    /// `Multihash::wrap(0x1e, ..)` + `Cid::new_v1(0x71, ..)` construction in
    /// exactly one place guarantees both doors emit **byte-identical** CIDs for
    /// the same digest — the property the no-rehash bridge depends on.
    fn wrap_blake3_digest(digest: [u8; BLAKE3_DIGEST_LEN]) -> Self {
        let mh = Multihash::wrap(BLAKE3_HASH_CODE, &digest)
            .expect("BLAKE3 digest is 32 bytes and always fits a 64-byte multihash");
        ContentId(Cid::new_v1(DAG_CBOR_CODEC, mh))
    }

    /// Borrow the underlying IPLD [`Cid`].
    #[must_use]
    pub fn as_cid(&self) -> &Cid {
        &self.0
    }

    /// The raw 32-byte BLAKE3 content digest, copied out of the multihash.
    ///
    /// This is the **bare hash** — *not* the CID envelope. It is the sovereign
    /// hash an adopter joins on across systems (the same digest a BLAKE3-native
    /// upstream would hand to [`from_blake3_content_digest`](Self::from_blake3_content_digest)).
    ///
    /// The length is a **frozen invariant**: every `ContentId` carries exactly
    /// `BLAKE3_DIGEST_LEN` (32) digest bytes (see the
    /// [CID-parameters contract](ContentId#cid-parameters-frozen-at-010)), so
    /// this accessor is infallible and returns a fixed-size array. The copy
    /// (`try_into`) can never fail; the `expect` documents the invariant and is
    /// unreachable for any id this crate mints.
    ///
    /// Part of the **frozen presentation contract** — see the
    /// [presentation contract](ContentId#presentation-contract-frozen-at-010).
    #[must_use]
    pub fn digest_bytes(&self) -> [u8; BLAKE3_DIGEST_LEN] {
        self.0
            .hash()
            .digest()
            .try_into()
            .expect("a ContentId multihash always carries a 32-byte BLAKE3 digest")
    }

    /// Lowercase hex of the raw 32-byte BLAKE3 digest: 64 hex chars, **no**
    /// `0x` or multibase prefix.
    ///
    /// This is the **"bare-digest-hex"** convention (the shortest, hash-only
    /// "hex" form an adopter reaches for, e.g. kyln's `to_hex()`). It is hex of
    /// [`digest_bytes`](Self::digest_bytes) — *not* hex of the full CID. The
    /// three "hex" forms in the wild are mutually incompatible; this crate names
    /// each so they cannot be confused:
    ///
    /// - **bare-digest-hex** = this method = `digest_hex()` (64 chars, hash
    ///   only).
    /// - **full-CID-bytes-hex** = `hex::encode(id.to_bytes())` — the whole CID
    ///   envelope (version + codec + multihash header + digest) as base16.
    ///   *Deliberately not provided as a method* (see the
    ///   [presentation contract](ContentId#presentation-contract-frozen-at-010));
    ///   a caller who truly needs it hex-encodes [`to_bytes`](Self::to_bytes)
    ///   and owns that choice.
    /// - **multibase base32-lower** = the [`Display`](fmt::Display) /
    ///   [`to_string`](ToString::to_string) string (`b…`), the IPLD-canonical
    ///   text form.
    ///
    /// Part of the **frozen presentation contract** — see the
    /// [presentation contract](ContentId#presentation-contract-frozen-at-010).
    #[must_use]
    pub fn digest_hex(&self) -> String {
        let digest = self.digest_bytes();
        let mut s = String::with_capacity(digest.len() * 2);
        for b in digest {
            // Hand-rolled 32->64 lowercase hex: avoids taking a `hex` crate
            // dependency for a byte-frozen surface (issue #6: "hand-roll
            // 32->64 hex to avoid the dep — implementer's call").
            s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble < 16 is a hex digit"));
            s.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble < 16 is a hex digit"));
        }
        s
    }

    /// Encode this id as its canonical CID binary form.
    ///
    /// This is the full **CID envelope**: version + codec (`0x71`) + multihash
    /// header + digest — *not* the bare hash. It round-trips through
    /// [`from_bytes`](Self::from_bytes). For the hex of *this* form ("full-CID-
    /// bytes-hex"), a caller hex-encodes the result explicitly; the crate
    /// deliberately does not bless a `cid_hex()` method (see the
    /// [presentation contract](ContentId#presentation-contract-frozen-at-010)).
    ///
    /// Part of the **frozen presentation contract** — see the
    /// [presentation contract](ContentId#presentation-contract-frozen-at-010).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Parse an id from its canonical CID binary form.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::InvalidCid`] if the bytes are not a valid CID.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContentError> {
        Cid::read_bytes(bytes)
            .map(ContentId)
            .map_err(|e| ContentError::InvalidCid {
                reason: e.to_string(),
                source: Box::new(e),
            })
    }
}

impl From<Cid> for ContentId {
    fn from(cid: Cid) -> Self {
        ContentId(cid)
    }
}

impl From<ContentId> for Cid {
    fn from(id: ContentId) -> Self {
        id.0
    }
}

impl fmt::Display for ContentId {
    /// Render as multibase **base32-lower** (the `b…` CIDv1 string).
    ///
    /// This is the crate's **canonical text form** and is **frozen** for the
    /// `0.1.x` line — see the
    /// [presentation contract](ContentId#presentation-contract-frozen-at-010).
    /// It is the IPLD-canonical CID string and the same text the human-readable
    /// serde form emits. It is the inverse of [`FromStr`] for base32-lower:
    /// `id.to_string().parse() == Ok(id)` is a tested, frozen round-trip. A unit
    /// test and the conformance vectors pin the exact string for fixed inputs,
    /// so any drift in the inner CID's rendering fails loudly. Changing this
    /// form is a major version bump.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for ContentId {
    type Err = ContentError;

    /// Parse an id from a multibase CID string.
    ///
    /// The frozen contract is narrow: `FromStr` is the **inverse of
    /// [`Display`](fmt::Display)** for the base32-lower form, and that round-trip
    /// (`id.to_string().parse() == Ok(id)`) is the part pinned by the
    /// [presentation contract](ContentId#presentation-contract-frozen-at-010).
    /// As a **convenience (not a contract)** this also accepts other valid
    /// multibases (base58, base16, …), since the inner [`Cid::from_str`] does;
    /// that tolerance is *not* frozen and may be tightened later without
    /// breaking the frozen base32-lower round-trip — so do not depend on parsing
    /// non-base32 CID strings.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Cid::from_str(s)
            .map(ContentId)
            .map_err(|e| ContentError::InvalidCid {
                reason: e.to_string(),
                source: Box::new(e),
            })
    }
}

impl Serialize for ContentId {
    /// Serialize per the frozen serde contract: the multibase base32 string in
    /// human-readable formats (e.g. `serde_json`, TOML), the inner [`Cid`] (a
    /// dag-cbor tag-42 link) in binary/IPLD formats.
    ///
    /// This representation is **frozen** for the `0.1.x` line; see the
    /// [type-level serde contract](ContentId#serde-representation-frozen-at-010).
    /// Changing it is a major version bump.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for ContentId {
    /// Deserialize per the frozen serde contract: a multibase base32 string from
    /// human-readable formats, the inner [`Cid`] (a dag-cbor tag-42 link) from
    /// binary/IPLD formats.
    ///
    /// The accepted representation is **frozen** for the `0.1.x` line; see the
    /// [type-level serde contract](ContentId#serde-representation-frozen-at-010).
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse::<ContentId>()
                .map_err(<D::Error as serde::de::Error>::custom)
        } else {
            Cid::deserialize(deserializer).map(ContentId)
        }
    }
}

#[cfg(test)]
mod cid_param_lock_tests {
    //! Locks the frozen v1 CID parameters (issue #4) so they cannot drift
    //! silently. These assertions live in the `content_id` module itself, next
    //! to the definitions, so the freeze is self-evident at the source. They use
    //! **literal** values (`0x71`, `0x1e`, `V1`, `32`), not the crate constants,
    //! so an accidental edit to a `const` is caught by a failing test rather
    //! than silently followed.

    use super::{ContentId, BLAKE3_DIGEST_LEN, BLAKE3_HASH_CODE, DAG_CBOR_CODEC};
    use ipld_core::cid::Version;

    /// A freshly produced id, from the empty-map canonical dag-cbor (`0xa0`).
    /// This is the documented fixed input also used by the embedded-link golden
    /// and the `empty_map` conformance vector, so the three pins agree.
    fn empty_map_id() -> ContentId {
        ContentId::from_canonical_bytes(&[0xa0])
    }

    #[test]
    fn cid_params_are_literally_v1_dagcbor_blake3_32() {
        // Assert against LITERALS, not the constants: editing a `const` must
        // break this test, not be silently followed.
        let id = empty_map_id();
        let cid = id.as_cid();
        assert_eq!(cid.version(), Version::V1, "CID version is frozen at V1");
        assert_eq!(cid.codec(), 0x71, "codec is frozen at dag-cbor (0x71)");
        assert_eq!(
            cid.hash().code(),
            0x1e,
            "multihash is frozen at BLAKE3 (0x1e)"
        );
        assert_eq!(
            cid.hash().digest().len(),
            32,
            "BLAKE3 digest length is frozen at 32 bytes"
        );
    }

    #[test]
    fn frozen_constants_hold_their_documented_values() {
        // The public/private constants must equal the frozen literals, so the
        // doc and the re-exported surface cannot drift from the contract.
        assert_eq!(DAG_CBOR_CODEC, 0x71);
        assert_eq!(BLAKE3_HASH_CODE, 0x1e);
        assert_eq!(BLAKE3_DIGEST_LEN, 32);
    }

    #[test]
    fn cid_binary_prefix_is_frozen() {
        // The leading bytes of the CIDv1 binary form encode the frozen shape:
        //   0x01 = CIDv1
        //   0x71 = multicodec dag-cbor
        //   0x1e = multihash code BLAKE3
        //   0x20 = digest length 32 (varint; 0x20 == 32)
        // Pinning the prefix means the on-wire identifier head cannot drift even
        // if the digest payload changes.
        let bytes = empty_map_id().to_bytes();
        assert_eq!(
            &bytes[..4],
            &[0x01, 0x71, 0x1e, 0x20],
            "CIDv1/dag-cbor/BLAKE3/len-32 binary prefix is frozen"
        );
        assert_eq!(
            bytes.len(),
            4 + BLAKE3_DIGEST_LEN,
            "CID binary form is the 4-byte prefix plus the 32-byte digest"
        );
    }
}

#[cfg(test)]
mod no_rehash_digest_tests {
    //! Tests for [`ContentId::from_blake3_content_digest`] (issue #10): the
    //! guarded, no-rehash escape hatch that wraps an already-computed BLAKE3
    //! content digest as a `ContentId` **without hashing it again**. These pin
    //! both the produced CID shape and — critically — the *no-rehash invariant*
    //! that distinguishes this door from `from_canonical_bytes` (which hashes).

    use super::{ContentId, BLAKE3_DIGEST_LEN};
    use ipld_core::cid::Version;

    /// A non-trivial, fixed 32-byte digest (`[1, 2, 3, ..., 32]`). Deliberately
    /// not all-zero so that the no-rehash invariant below is a meaningful test.
    fn sample_digest() -> [u8; BLAKE3_DIGEST_LEN] {
        let mut d = [0u8; BLAKE3_DIGEST_LEN];
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8) + 1;
        }
        d
    }

    #[test]
    fn produces_v1_dagcbor_blake3_cid_carrying_the_exact_digest() {
        // Assert against LITERALS, matching the frozen-parameter lock tests.
        let d = sample_digest();
        let id = ContentId::from_blake3_content_digest(d);
        let cid = id.as_cid();
        assert_eq!(cid.version(), Version::V1, "must be a CIDv1");
        assert_eq!(cid.codec(), 0x71, "codec must be dag-cbor (0x71)");
        assert_eq!(cid.hash().code(), 0x1e, "multihash must be BLAKE3 (0x1e)");
        assert_eq!(
            cid.hash().digest().len(),
            BLAKE3_DIGEST_LEN,
            "digest must be 32 bytes"
        );
        // The wrapped digest bytes must be EXACTLY the input — the whole point
        // of a no-rehash door is that the digest passes through untouched.
        assert_eq!(
            cid.hash().digest(),
            &d,
            "the CID must carry the caller's digest verbatim"
        );
    }

    #[test]
    fn does_not_rehash_the_digest() {
        // THE CRITICAL INVARIANT (must-fix gate): for a non-trivial digest `d`,
        // wrapping it must NOT equal hashing it. `from_canonical_bytes(&d)`
        // computes BLAKE3(d) — a second hash — whereas
        // `from_blake3_content_digest(d)` wraps `d` as-is. If these were ever
        // equal, the constructor would secretly be re-hashing.
        let d = sample_digest();
        let wrapped = ContentId::from_blake3_content_digest(d);
        let hashed_again = ContentId::from_canonical_bytes(&d);
        assert_ne!(
            wrapped, hashed_again,
            "from_blake3_content_digest must NOT re-hash: wrapping d must differ \
             from BLAKE3(d)"
        );
        // Tighter: the wrapped id's digest is `d` itself, while the re-hashed
        // id's digest is BLAKE3(d) — explicitly different bytes.
        assert_eq!(wrapped.as_cid().hash().digest(), &d);
        assert_eq!(
            hashed_again.as_cid().hash().digest(),
            blake3::hash(&d).as_bytes(),
        );
    }

    #[test]
    fn digest_survives_a_byte_roundtrip() {
        // Building from a digest, serializing to CID bytes, and reading the
        // digest back must recover the original `d` exactly.
        let d = sample_digest();
        let id = ContentId::from_blake3_content_digest(d);

        // Via the live CID handle.
        assert_eq!(id.as_cid().hash().digest(), &d);

        // Via the full CID binary form: tail 32 bytes are the digest, and a
        // from_bytes parse lands on the same id.
        let bytes = id.to_bytes();
        assert_eq!(
            &bytes[bytes.len() - BLAKE3_DIGEST_LEN..],
            &d,
            "the trailing 32 bytes of the CID binary form are the digest"
        );
        let reparsed = ContentId::from_bytes(&bytes).expect("CID bytes must reparse");
        assert_eq!(reparsed, id);
        assert_eq!(reparsed.as_cid().hash().digest(), &d);
    }

    #[test]
    fn converges_with_from_canonical_bytes_when_caller_hashes_correctly() {
        // The two doors meet in the middle: if a caller hashes the real content
        // with BLAKE3 and feeds the digest here, they get the SAME id as
        // hashing the content via from_canonical_bytes. This is the bridge
        // property the no-rehash primitive exists to provide.
        for content in [
            &b""[..],
            &[0xa0][..], // empty-map canonical dag-cbor
            b"the quick brown fox",
            b"\x00\x01\x02\x03 arbitrary canonical bytes",
        ] {
            let digest: [u8; BLAKE3_DIGEST_LEN] = blake3::hash(content).into();
            let via_digest = ContentId::from_blake3_content_digest(digest);
            let via_hash = ContentId::from_canonical_bytes(content);
            assert_eq!(
                via_digest, via_hash,
                "from_blake3_content_digest(blake3(x)) must equal \
                 from_canonical_bytes(x)"
            );
        }
    }
}

#[cfg(test)]
mod presentation_tests {
    //! Tests for the **frozen presentation contract** (issue #6): the named,
    //! separately-frozen string/byte forms a `ContentId` emits. These pin the
    //! exact values for fixed inputs so any drift in the inner CID's rendering,
    //! the multihash digest, or the hex encoder fails loudly. The cross-language
    //! `tests/vectors.json` gate additionally pins `digest_hex` (and the base32
    //! string + CID bytes) so Python parity is enforced too; these in-crate
    //! tests assert the *accessor semantics* that the vectors cannot (the array
    //! return, the no-prefix rule, the Display/FromStr round-trip).

    use super::{ContentId, BLAKE3_DIGEST_LEN};

    /// The documented fixed input: the empty-map canonical dag-cbor (`0xa0`).
    /// This is the same id as the `empty_map` conformance vector and the
    /// embedded-link golden, so all the pins agree.
    fn empty_map_id() -> ContentId {
        ContentId::from_canonical_bytes(&[0xa0])
    }

    /// The frozen `empty_map` digest (the BLAKE3 of `0xa0`), as bare-digest-hex.
    /// Equals the tail of the `empty_map` vector's `content_id_bytes_hex`
    /// (`01711e20` CID prefix, then this 64-char digest).
    const EMPTY_MAP_DIGEST_HEX: &str =
        "1f94cbf313b3ce23257a7251ea0fc95a24556ea611e4f8f475e549971baedb02";

    #[test]
    fn display_is_frozen_base32_lower() {
        // The canonical text form is multibase base32-lower (`b…`), frozen.
        let id = empty_map_id();
        let s = id.to_string();
        assert_eq!(
            s, "bafyr4ia7stf7ge5tzyrsk6tskhva7sk2erkw5jqr4t4pi5pfjglrxlw3ai",
            "Display must be the frozen base32-lower CID string"
        );
        assert!(s.starts_with('b'), "base32-lower multibase prefix is 'b'");
    }

    #[test]
    fn display_fromstr_roundtrip_is_frozen() {
        // The frozen guarantee: Display -> FromStr lands back on the same id.
        let id = empty_map_id();
        let parsed: ContentId = id.to_string().parse().expect("base32 string must reparse");
        assert_eq!(parsed, id, "Display -> FromStr must round-trip");
    }

    #[test]
    fn digest_bytes_is_the_raw_32_byte_blake3_hash() {
        let id = empty_map_id();
        let d = id.digest_bytes();
        // It is a fixed-size 32-byte array...
        assert_eq!(d.len(), BLAKE3_DIGEST_LEN);
        // ...equal to the multihash's digest (the bare hash, no envelope)...
        assert_eq!(&d[..], id.as_cid().hash().digest());
        // ...and equal to an independent BLAKE3 of the input bytes.
        assert_eq!(d, *blake3::hash(&[0xa0]).as_bytes());
    }

    #[test]
    fn digest_hex_is_frozen_64_char_lower_hex_no_prefix() {
        let id = empty_map_id();
        let h = id.digest_hex();
        // Exactly 64 lowercase hex chars, no `0x` prefix. (A hex digest may
        // legitimately begin with the digit `b`; that is NOT the base32
        // multibase prefix, which belongs only to the Display string.)
        assert_eq!(h.len(), 64, "digest_hex is 64 chars (32 bytes)");
        assert!(!h.starts_with("0x"), "digest_hex carries no 0x prefix");
        assert!(
            h.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "digest_hex is lowercase hex only"
        );
        // The exact frozen value for the empty map.
        assert_eq!(
            h, EMPTY_MAP_DIGEST_HEX,
            "frozen empty-map digest_hex drifted"
        );
    }

    #[test]
    fn digest_hex_is_hex_of_digest_bytes_not_of_the_cid() {
        // digest_hex names convention #1 (bare-digest-hex): it is hex of the
        // bare digest, and is STRICTLY SHORTER than full-CID-bytes-hex
        // (`hex::encode(to_bytes())`), which carries the 4-byte CID prefix too.
        let id = empty_map_id();
        let digest = id.digest_bytes();
        let mut expected = String::new();
        for b in digest {
            expected.push_str(&format!("{b:02x}"));
        }
        assert_eq!(id.digest_hex(), expected);

        // The full-CID-bytes-hex (the deliberately-unmethodd convention #2) is
        // longer and ENDS WITH the digest hex, after the CID envelope prefix.
        let cid_bytes_hex: String = id.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            cid_bytes_hex.ends_with(&id.digest_hex()),
            "the full-CID-bytes-hex ends with the bare-digest-hex"
        );
        assert!(
            cid_bytes_hex.len() > id.digest_hex().len(),
            "full-CID-bytes-hex is longer than bare-digest-hex (it has the envelope)"
        );
        // Concretely: the 4-byte CIDv1/dag-cbor/BLAKE3/len-32 prefix, then digest.
        assert_eq!(cid_bytes_hex, format!("01711e20{}", id.digest_hex()));
    }
}

#[cfg(test)]
mod checked_input_tests {
    //! Tests for [`ContentId::from_canonical_bytes_checked`] (issue #5): the
    //! opt-in, round-trip-validating sibling of the fast `from_canonical_bytes`
    //! primitive. They pin the four behaviors the issue's AC names: (a) canonical
    //! bytes accepted and yielding the *same* id as the unchecked door, (b)
    //! non-canonical-but-valid CBOR rejected, (c) non-dag-cbor garbage rejected,
    //! and (d) a regression test documenting that the *unchecked* primitive still
    //! happily mints an id for non-canonical bytes (the precondition is real and
    //! unenforced by design).

    use super::ContentId;
    use crate::canonical::to_canonical_dagcbor;
    use crate::error::ContentError;

    #[test]
    fn checked_accepts_canonical_bytes_and_matches_the_unchecked_door() {
        // The always-canonical path: canonicalize a value, then both doors must
        // agree on the id (the check changes fallibility, never the bytes).
        for value in [
            &serde_json::json!({}),
            &serde_json::json!({"alpha": 1, "zeta": 26}),
            &serde_json::json!({"name": "hello", "n": [1, 2, 3], "nested": {"a": 1}}),
            &serde_json::json!([1, "two", [3, 4], null]),
        ] {
            // Drive canonical bytes through Ipld so the encoding is the codec's
            // canonical form, then assert the two doors converge.
            let ipld: ipld_core::ipld::Ipld =
                serde_json::from_value((*value).clone()).expect("json -> ipld");
            let canonical = to_canonical_dagcbor(&ipld).expect("encode canonical");

            let via_checked =
                ContentId::from_canonical_bytes_checked(&canonical).expect("canonical accepted");
            let via_unchecked = ContentId::from_canonical_bytes(&canonical);
            assert_eq!(
                via_checked, via_unchecked,
                "checked(canonical) must equal the unchecked id for the same bytes"
            );
        }
    }

    #[test]
    fn always_canonical_path_equals_from_canonical_bytes_of_to_canonical_dagcbor() {
        // The exact identity the issue calls out: the always-canonical path
        // (to_canonical_dagcbor then mint) and the checked door produce the same
        // id, and that id is from_canonical_bytes(to_canonical_dagcbor(x)).
        let ipld: ipld_core::ipld::Ipld = serde_json::from_value(serde_json::json!(
            {"alpha": 1, "zeta": 26, "list": [true, false, null]}
        ))
        .expect("json -> ipld");

        let canonical = to_canonical_dagcbor(&ipld).expect("encode canonical");
        let from_unchecked = ContentId::from_canonical_bytes(&canonical);
        let from_checked =
            ContentId::from_canonical_bytes_checked(&canonical).expect("canonical accepted");

        assert_eq!(
            from_checked, from_unchecked,
            "from_canonical_bytes_checked(to_canonical_dagcbor(x)) == \
             from_canonical_bytes(to_canonical_dagcbor(x))"
        );
    }

    #[test]
    fn checked_rejects_non_canonical_but_valid_cbor() {
        // A map with two string keys encoded in NON-canonical (descending) key
        // order. dag-cbor canonical order is by length-then-bytewise, so {"a",
        // "bb"} canonical is a2 [a] .. [bb]; we hand-build the reverse order.
        // Hand-built CBOR:
        //   a2                      map(2)
        //   62 6262                 text(2) "bb"   <- emitted FIRST (non-canonical)
        //   01                      1
        //   61 61                   text(1) "a"
        //   02                      2
        let non_canonical = [0xa2, 0x62, 0x62, 0x62, 0x01, 0x61, 0x61, 0x02];

        // Sanity: it IS valid CBOR (decodes fine), so this exercises the
        // re-encode-compare path, not the decode path.
        let decoded: ipld_core::ipld::Ipld =
            crate::canonical::from_canonical_dagcbor(&non_canonical)
                .expect("non-canonical bytes are still valid CBOR and decode");
        // And its canonical re-encoding genuinely differs (proving our fixture is
        // really non-canonical, not an accidental canonical form).
        let recanon = to_canonical_dagcbor(&decoded).expect("re-encode");
        assert_ne!(
            &recanon[..],
            &non_canonical[..],
            "fixture must actually be non-canonical"
        );

        let err = ContentId::from_canonical_bytes_checked(&non_canonical)
            .expect_err("non-canonical CBOR must be rejected");
        assert!(
            matches!(err, ContentError::NonCanonical),
            "non-canonical valid CBOR must map to ContentError::NonCanonical, got {err:?}"
        );
    }

    #[test]
    fn checked_rejects_indefinite_length_cbor() {
        // An indefinite-length CBOR array (0x9f .. 0xff) is valid CBOR but
        // forbidden in canonical dag-cbor (definite-length only). dag-cbor's
        // decoder may already refuse it; either way the checked door must error
        // (decode failure OR non-canonical), never silently mint an id.
        //   9f        array(*)  (indefinite)
        //   01 02 03  1, 2, 3
        //   ff        break
        let indefinite = [0x9f, 0x01, 0x02, 0x03, 0xff];
        let err = ContentId::from_canonical_bytes_checked(&indefinite)
            .expect_err("indefinite-length CBOR must be rejected");
        assert!(
            matches!(
                err,
                ContentError::NonCanonical | ContentError::DecodingError { .. }
            ),
            "indefinite-length CBOR must be rejected (NonCanonical or DecodingError), got {err:?}"
        );
    }

    #[test]
    fn checked_rejects_non_dagcbor_garbage() {
        // Arbitrary non-CBOR bytes must fail at the decode step.
        let garbage = [0xff, 0xff, 0xff, 0xff];
        let err = ContentId::from_canonical_bytes_checked(&garbage)
            .expect_err("non-dag-cbor garbage must be rejected");
        assert!(
            matches!(err, ContentError::DecodingError { .. }),
            "non-dag-cbor garbage must map to ContentError::DecodingError, got {err:?}"
        );
    }

    #[test]
    fn unchecked_still_mints_an_id_for_non_canonical_bytes() {
        // REGRESSION / documentation test (issue #5 AC item d): the FAST,
        // unchecked primitive does NOT validate — it mints a (misleading) id even
        // for non-canonical bytes. This pins that the precondition is real and
        // unenforced by design: the unchecked door succeeds where the checked one
        // refuses, and the two ids necessarily differ (the unchecked id hashes
        // the non-canonical bytes; the canonical bytes hash to something else).
        let non_canonical = [0xa2, 0x62, 0x62, 0x62, 0x01, 0x61, 0x61, 0x02];

        // Unchecked: succeeds, no error, no panic — mints over the raw bytes.
        let misleading = ContentId::from_canonical_bytes(&non_canonical);
        assert_eq!(
            misleading.digest_bytes(),
            *blake3::hash(&non_canonical).as_bytes(),
            "the unchecked door hashes exactly the bytes it was given"
        );

        // Checked: refuses.
        assert!(ContentId::from_canonical_bytes_checked(&non_canonical).is_err());

        // The misleading id differs from the id of the *canonical* form of the
        // same value — the silent integrity hole the precondition warns about.
        let decoded: ipld_core::ipld::Ipld =
            crate::canonical::from_canonical_dagcbor(&non_canonical).expect("valid CBOR");
        let canonical = to_canonical_dagcbor(&decoded).expect("re-encode");
        let honest = ContentId::from_canonical_bytes(&canonical);
        assert_ne!(
            misleading, honest,
            "minting over non-canonical bytes names a different id than the \
             canonical form would — exactly the hazard from_canonical_bytes warns of"
        );
    }
}
