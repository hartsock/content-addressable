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
/// bytes the id names are canonical dag-cbor.
pub const DAG_CBOR_CODEC: u64 = 0x71;

/// Multihash code for BLAKE3 (`0x1e`).
///
/// This is the hash function field of every [`ContentId`]'s multihash.
pub const BLAKE3_HASH_CODE: u64 = 0x1e;

/// Length of a BLAKE3 digest in bytes (256 bits).
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
/// # Serde representation (NOT FROZEN)
///
/// `ContentId` serializes as its inner [`Cid`], i.e. as a dag-cbor **tag-42
/// link** when written through [`serde_ipld_dagcbor`]. This is the natural IPLD
/// encoding and makes `ContentId` fields inside other content-addressed
/// structures behave as real links.
///
/// **This exact wire representation is a "must-fix gate" item that must be
/// settled before the `0.1.0` release.** Until then (during `0.1.0-alpha`) the
/// bytes are explicitly *not* a stability contract and may change. Do not
/// persist `ContentId`-bearing structures as a long-term format yet.
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
    /// Serialize as the inner [`Cid`], yielding a dag-cbor tag-42 link.
    ///
    /// See the [type-level note](ContentId#serde-representation-not-frozen):
    /// this representation is not frozen during `0.1.0-alpha`.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ContentId {
    /// Deserialize the inner [`Cid`] from a dag-cbor tag-42 link.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Cid::deserialize(deserializer).map(ContentId)
    }
}
