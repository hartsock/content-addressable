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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentId(Cid);

impl ContentId {
    /// Compute the content id of already-canonical bytes.
    ///
    /// The pipeline is, end to end:
    ///
    /// 1. `digest = BLAKE3(bytes)` — a 32-byte hash.
    /// 2. `mh = Multihash::wrap(0x1e, digest)` — tag the digest with the
    ///    BLAKE3 multihash code.
    /// 3. `cid = Cid::new_v1(0x71, mh)` — a CIDv1 declaring the bytes are
    ///    dag-cbor.
    ///
    /// The input is assumed to already be canonical dag-cbor (typically the
    /// output of [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor)).
    /// This function does not re-canonicalize; it only hashes.
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

    /// Wrap an **already-computed** 32-byte BLAKE3 content digest as a
    /// `ContentId` — **without hashing**.
    ///
    /// This is a deliberately narrow, *unchecked* escape hatch for
    /// **BLAKE3-native upstreams** that have already hashed their content and
    /// hold only the 32-byte digest (a signature, an address) — not the
    /// original canonical bytes. For them, [`from_canonical_bytes`] is not just
    /// wasteful, it is *impossible*: there are no bytes left to hash. This
    /// constructor takes the digest they already have and wraps it directly:
    /// `Multihash::wrap(0x1e, digest)` → `Cid::new_v1(0x71, mh)`. No BLAKE3
    /// step runs, and the result is byte-identical to what
    /// [`from_canonical_bytes`] would have produced *had the caller hashed the
    /// real content correctly*.
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
    /// input domain [`from_canonical_bytes`] would hash.
    ///
    /// If that assertion is false — the digest was computed over non-canonical
    /// bytes, over a different encoding, with a different hash, or is simply
    /// arbitrary — the result is a `ContentId` that **names content nothing
    /// actually hashed**. Such an id is silently wrong: there is no error, and
    /// verifying it against the real bytes returns `Ok(false)`, never an `Err`.
    ///
    /// **If you have the content bytes, use [`from_canonical_bytes`] instead** —
    /// it hashes them for you and cannot be wrong this way. Do *not* reach for
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

    /// Encode this id as its canonical CID binary form.
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
    /// Render as the inner CID's default multibase string (base32-lower for
    /// CIDv1).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for ContentId {
    type Err = ContentError;

    /// Parse an id from a multibase CID string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Cid::from_str(s)
            .map(ContentId)
            .map_err(|e| ContentError::InvalidCid {
                reason: e.to_string(),
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
