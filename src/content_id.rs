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
        let mh = Multihash::wrap(BLAKE3_HASH_CODE, digest.as_bytes())
            .expect("BLAKE3 digest is 32 bytes and always fits a 64-byte multihash");
        debug_assert_eq!(digest.as_bytes().len(), BLAKE3_DIGEST_LEN);
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
