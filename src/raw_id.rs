//! [`RawContentId`] — the identity of an **opaque byte string** (the *raw*
//! profile), sibling to [`ContentId`] (the *dag-cbor* profile).
//!
//! # Two profiles, one algebra
//!
//! This crate mints exactly two kinds of identifier, and the **type** says which:
//!
//! | Type | CID profile | Names |
//! |------|-------------|-------|
//! | [`ContentId`] | CIDv1 · `dag-cbor` (`0x71`) · BLAKE3-256 (`0x1e`) · 32 bytes | a canonical structured **value** |
//! | [`RawContentId`] | CIDv1 · `raw` (`0x55`) · BLAKE3-256 (`0x1e`) · 32 bytes | an opaque **byte string** — a file, a chunk, a binary, a payload |
//!
//! Both are real IPLD CIDs and both share the same multihash tail; they differ
//! *only* in the codec — and that difference is **semantic, not cosmetic**
//! (decision record `docs/adr/0003`, law 6). `RawContentId(x)` and
//! `ContentId(x)` are different identities even when their 32 digest bytes are
//! identical: one names *these bytes*, the other names *the value whose
//! canonical dag-cbor is these bytes*. The type system enforces that — there is
//! deliberately **no** `PartialEq` between the two, no `From` in either
//! direction, and neither ingress path accepts the other's codec.
//!
//! # Why not wrap bytes in a dag-cbor node?
//!
//! `CID(dag-cbor, blake3(encode(ChunkLeaf { data: bytes })))` is the identity
//! of a *representation containing* the bytes, not of the bytes. When a
//! capability system says "authority X permits artifact Y", Y must identify the
//! artifact itself. That is what `RawContentId` is for; it also makes every
//! BLAKE3-native identifier already in the wild (kyln's raw CIDs, bare
//! `blake3::hash` digests, `blake3:<hex>` digests) a **byte-identical**
//! `RawContentId` with no re-hash — see [`RawContentId::from_blake3_digest`] and
//! the `legacy` adapters.
//!
//! # Presentation contract
//!
//! Mirrors [`ContentId`]'s exactly (the same accessor names mean the same
//! things): `Display`/`FromStr` are the multibase base32-lower `b…` string,
//! [`to_bytes`](RawContentId::to_bytes)/[`from_bytes`](RawContentId::from_bytes)
//! are the CID binary envelope, [`digest_bytes`](RawContentId::digest_bytes)/
//! [`digest_hex`](RawContentId::digest_hex) are the bare 32-byte digest. The
//! serde form is the same as `ContentId`'s: a tag-42 link in binary/IPLD
//! formats, the base32-lower string in human-readable ones. Every ingress path
//! validates the raw profile, so a `RawContentId` (however it entered) always
//! carries it and every accessor is total.
//!
//! The bytes are fixed by the CID specification, not by this crate — a
//! CIDv1(raw, blake3-256) is the same octets everywhere. `tests/raw_vectors.json`
//! pins them across the Rust and Python faces.

use crate::content_id::{BLAKE3_DIGEST_LEN, BLAKE3_HASH_CODE};
use crate::error::ContentError;
use core::fmt;
use core::str::FromStr;
use ipld_core::cid::multihash::Multihash;
use ipld_core::cid::{Cid, Version};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Keep `ContentId` in the doc-link namespace of this module.
#[allow(unused_imports)]
use crate::content_id::ContentId;

/// Multicodec code for `raw` (`0x55`): the codec field of every
/// [`RawContentId`], declaring "these are opaque bytes; do not decode".
pub const RAW_CODEC: u64 = 0x55;

/// The identity of an opaque byte string: a CIDv1 whose codec is `raw`
/// (`0x55`) and whose multihash is BLAKE3-256 (`0x1e`) over the bytes.
///
/// See the [module docs](self) for the two-profile picture and why the codec
/// is part of the identity. Construct with
/// [`from_content`](Self::from_content) (hash bytes you hold) or
/// [`from_blake3_digest`](Self::from_blake3_digest) (wrap a digest you already
/// have, no re-hash); parse with `FromStr` / [`from_bytes`](Self::from_bytes) /
/// `TryFrom<Cid>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RawContentId(Cid);

impl RawContentId {
    /// The identity of `content`: `CIDv1(raw, BLAKE3(content))`.
    ///
    /// This is the door for bytes you hold. There is no canonicalization step
    /// and nothing to get wrong: the bytes *are* the content, so the id names
    /// exactly what was hashed. (Contrast [`ContentId::from_canonical_bytes`],
    /// whose "MUST be canonical dag-cbor" precondition exists because a
    /// dag-cbor id names a *value*, not the bytes.)
    ///
    /// Named `from_content` rather than `from_bytes` on purpose: across both
    /// profiles `from_bytes`/`to_bytes` always mean the **CID binary envelope**
    /// (the presentation contract), never "hash these bytes".
    #[must_use]
    pub fn from_content(content: &[u8]) -> Self {
        let digest = blake3::hash(content);
        Self::wrap_blake3_digest(*digest.as_bytes())
    }

    /// Wrap a precomputed 32-byte BLAKE3 digest **of some content** as a
    /// `RawContentId`, with no re-hash.
    ///
    /// This is the honest home of the "no-rehash bridge": a system that already
    /// hashed content with BLAKE3 (kyln-lore revision signatures, a bare
    /// `blake3::hash`, a `blake3:<hex>` digest) gets a byte-identical
    /// `RawContentId` by wrapping — and the `raw` codec tells the truth about
    /// what was hashed (opaque bytes). This replaces the deprecated
    /// [`ContentId::from_blake3_content_digest`], which stamped `dag-cbor` on a
    /// digest it could not know came from dag-cbor.
    ///
    /// **The digest must really be BLAKE3 over the content you mean.** This
    /// function cannot check that; a wrong digest mints an id that names
    /// nothing anyone hashed. Verify against real bytes with
    /// [`verify`](Self::verify) when you can.
    ///
    /// # Panics
    ///
    /// Does not panic: a 32-byte digest always fits the multihash's 64-byte
    /// capacity.
    #[must_use]
    pub fn from_blake3_digest(digest: [u8; BLAKE3_DIGEST_LEN]) -> Self {
        Self::wrap_blake3_digest(digest)
    }

    /// The single construction point shared by [`from_content`](Self::from_content)
    /// and [`from_blake3_digest`](Self::from_blake3_digest), so both doors emit
    /// byte-identical ids for the same digest.
    fn wrap_blake3_digest(digest: [u8; BLAKE3_DIGEST_LEN]) -> Self {
        let mh = Multihash::wrap(BLAKE3_HASH_CODE, &digest)
            .expect("BLAKE3 digest is 32 bytes and always fits a 64-byte multihash");
        RawContentId(Cid::new_v1(RAW_CODEC, mh))
    }

    /// `true` iff `content` hashes to this id.
    ///
    /// Infallible: a mismatch is `false`, never an error (the same contract as
    /// [`ContentAddressable::verify`](crate::ContentAddressable::verify)).
    #[must_use]
    pub fn verify(&self, content: &[u8]) -> bool {
        Self::from_content(content) == *self
    }

    /// Borrow the underlying IPLD [`Cid`].
    #[must_use]
    pub fn as_cid(&self) -> &Cid {
        &self.0
    }

    /// The raw 32-byte BLAKE3 digest, copied out of the multihash. Total: every
    /// ingress path validated the profile.
    #[must_use]
    pub fn digest_bytes(&self) -> [u8; BLAKE3_DIGEST_LEN] {
        let mut out = [0u8; BLAKE3_DIGEST_LEN];
        out.copy_from_slice(self.0.hash().digest());
        out
    }

    /// Lowercase hex of the raw 32-byte digest: 64 chars, **no** prefix, no
    /// envelope — the "bare-digest-hex" presentation form. Note that this is
    /// identical for `RawContentId(x)` and `ContentId(x)` when the digests
    /// match; it is a *digest* accessor, not an identity, and must never be
    /// compared as one (law 6).
    #[must_use]
    pub fn digest_hex(&self) -> String {
        let mut s = String::with_capacity(BLAKE3_DIGEST_LEN * 2);
        for b in self.digest_bytes() {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// The full CID binary envelope (version + codec + multihash + digest).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Parse an id from its CID binary form, accepting **only** the raw profile.
    ///
    /// # Errors
    ///
    /// [`ContentError::InvalidCid`] if the bytes are not a CID at all;
    /// [`ContentError::InvalidCidProfile`] if they are a CID of any other profile
    /// (including a `dag-cbor` [`ContentId`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContentError> {
        let cid = Cid::read_bytes(bytes).map_err(|e| ContentError::InvalidCid {
            reason: e.to_string(),
            source: Box::new(e),
        })?;
        validate_raw_profile(&cid)?;
        Ok(RawContentId(cid))
    }
}

/// Reject any [`Cid`] that is not the raw profile: CIDv1 + `raw` (`0x55`) +
/// BLAKE3 (`0x1e`) + a 32-byte digest. Every ingress path routes through this.
pub(crate) fn validate_raw_profile(cid: &Cid) -> Result<(), ContentError> {
    if cid.version() != Version::V1 {
        return Err(ContentError::InvalidCidProfile {
            reason: format!("expected CIDv1, got {:?}", cid.version()),
        });
    }
    if cid.codec() != RAW_CODEC {
        return Err(ContentError::InvalidCidProfile {
            reason: format!(
                "expected raw codec 0x{RAW_CODEC:x}, got 0x{:x}",
                cid.codec()
            ),
        });
    }
    if cid.hash().code() != BLAKE3_HASH_CODE {
        return Err(ContentError::InvalidCidProfile {
            reason: format!(
                "expected BLAKE3 multihash 0x{BLAKE3_HASH_CODE:x}, got 0x{:x}",
                cid.hash().code()
            ),
        });
    }
    let digest_len = cid.hash().digest().len();
    if digest_len != BLAKE3_DIGEST_LEN {
        return Err(ContentError::InvalidCidProfile {
            reason: format!("expected a {BLAKE3_DIGEST_LEN}-byte digest, got {digest_len} bytes"),
        });
    }
    Ok(())
}

impl TryFrom<Cid> for RawContentId {
    type Error = ContentError;

    /// Wrap a [`Cid`] **iff** it is the raw profile; anything else — including a
    /// `dag-cbor` [`ContentId`]'s CID — is rejected with
    /// [`ContentError::InvalidCidProfile`].
    fn try_from(cid: Cid) -> Result<Self, Self::Error> {
        validate_raw_profile(&cid)?;
        Ok(RawContentId(cid))
    }
}

impl From<RawContentId> for Cid {
    fn from(id: RawContentId) -> Self {
        id.0
    }
}

impl fmt::Display for RawContentId {
    /// Multibase **base32-lower** (`b…`) — the canonical text form, the inverse
    /// of `FromStr` for that form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for RawContentId {
    type Err = ContentError;

    /// Parse a multibase CID string, accepting **only** the raw profile. As with
    /// [`ContentId`], base32-lower is the contract; other multibases are a
    /// convenience of the inner parser, not a promise. Legacy dialects (kyln
    /// envelope-hex, `blake3:<hex>`, bare digest hex) are deliberately **not**
    /// accepted here — they live behind the explicit `legacy` adapters.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cid = Cid::from_str(s).map_err(|e| ContentError::InvalidCid {
            reason: e.to_string(),
            source: Box::new(e),
        })?;
        validate_raw_profile(&cid)?;
        Ok(RawContentId(cid))
    }
}

impl Serialize for RawContentId {
    /// Same shape as [`ContentId`]: the base32-lower string in human-readable
    /// formats, the inner [`Cid`] (a dag-cbor tag-42 link) in binary/IPLD ones.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for RawContentId {
    /// Inverse of [`Serialize`]; a link of any other profile is rejected at the
    /// boundary, never later in an accessor.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse::<RawContentId>()
                .map_err(<D::Error as serde::de::Error>::custom)
        } else {
            let cid = Cid::deserialize(deserializer)?;
            RawContentId::try_from(cid).map_err(<D::Error as serde::de::Error>::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_id::ContentId;

    #[test]
    fn profile_bytes_are_cidv1_raw_blake3() {
        let id = RawContentId::from_content(b"");
        let bytes = id.to_bytes();
        // 0x01 = CIDv1, 0x55 = raw, 0x1e = blake3, 0x20 = 32-byte digest.
        assert_eq!(&bytes[..4], &[0x01, 0x55, 0x1e, 0x20]);
        assert_eq!(bytes.len(), 4 + 32);
        assert_eq!(id.as_cid().codec(), RAW_CODEC);
        assert_eq!(id.as_cid().hash().code(), BLAKE3_HASH_CODE);
    }

    #[test]
    fn from_content_and_from_digest_converge() {
        let content = b"hello, raw world";
        let via_content = RawContentId::from_content(content);
        let via_digest = RawContentId::from_blake3_digest(*blake3::hash(content).as_bytes());
        assert_eq!(via_content, via_digest);
        assert!(via_content.verify(content));
        assert!(!via_content.verify(b"other"));
    }

    #[test]
    fn display_is_base32_lower_and_roundtrips() {
        let id = RawContentId::from_content(b"abc");
        let s = id.to_string();
        assert!(
            s.starts_with('b'),
            "base32-lower CIDv1 strings start with 'b': {s}"
        );
        assert_eq!(s.parse::<RawContentId>().unwrap(), id);
        assert_eq!(RawContentId::from_bytes(&id.to_bytes()).unwrap(), id);
    }

    /// Law 6: the codec is part of the identity. Same digest, different profile,
    /// different identity — different bytes, different strings, and each
    /// profile's ingress rejects the other's CID.
    #[test]
    fn same_digest_different_profile_is_a_different_identity() {
        let digest = *blake3::hash(b"same bytes").as_bytes();
        let raw = RawContentId::from_blake3_digest(digest);
        let dag = ContentId::from_dag_cbor_digest(digest);
        assert_eq!(raw.digest_bytes(), dag.digest_bytes());
        assert_eq!(raw.digest_hex(), dag.digest_hex());
        assert_ne!(raw.to_bytes(), dag.to_bytes());
        assert_ne!(raw.to_string(), dag.to_string());
        // Cross-profile ingress fails closed in both directions.
        assert!(matches!(
            RawContentId::from_bytes(&dag.to_bytes()),
            Err(ContentError::InvalidCidProfile { .. })
        ));
        assert!(matches!(
            ContentId::from_bytes(&raw.to_bytes()),
            Err(ContentError::InvalidCidProfile { .. })
        ));
        assert!(matches!(
            dag.to_string().parse::<RawContentId>(),
            Err(ContentError::InvalidCidProfile { .. })
        ));
        assert!(RawContentId::try_from(*dag.as_cid()).is_err());
        assert!(ContentId::try_from(*raw.as_cid()).is_err());
    }

    #[test]
    fn foreign_cids_are_rejected() {
        // A CIDv1 raw/sha2-256 (what a REAPI digest would wrap as).
        let mh = Multihash::wrap(0x12, &[0u8; 32]).unwrap();
        let sha = Cid::new_v1(RAW_CODEC, mh);
        assert!(matches!(
            RawContentId::try_from(sha),
            Err(ContentError::InvalidCidProfile { .. })
        ));
        assert!(matches!(
            RawContentId::from_bytes(b"not a cid"),
            Err(ContentError::InvalidCid { .. })
        ));
        assert!(matches!(
            "not a cid".parse::<RawContentId>(),
            Err(ContentError::InvalidCid { .. })
        ));
    }

    #[test]
    fn serde_human_readable_is_string_and_binary_is_link() {
        let id = RawContentId::from_content(b"serde");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(serde_json::from_str::<RawContentId>(&json).unwrap(), id);
        let cbor = crate::canonical::to_canonical_dagcbor(&id).unwrap();
        // dag-cbor tag 42 = 0xd8 0x2a, then a byte string with the 0x00 prefix.
        assert_eq!(&cbor[..2], &[0xd8, 0x2a]);
        let back: RawContentId = crate::canonical::from_canonical_dagcbor_checked(&cbor).unwrap();
        assert_eq!(back, id);
        // A dag-cbor link to a *ContentId* does not deserialize as a RawContentId.
        //
        // The VARIANT is asserted, not merely `is_err()`. `RawContentId` stores
        // the profile in its `Cid`, so a mutant `Deserialize` that dropped the
        // profile gate and rebuilt the id from the bare digest would re-serialize
        // with the raw codec `0x55` instead of the input's dag-cbor `0x71` — and
        // the checked door's stage-3 byte comparison would refuse it with
        // `LossyDecode`. `is_err()` would stay green on a genuine reintroduction
        // of profile aliasing at the serde boundary; `DecodingError` is the
        // boundary refusal this test exists to prove, and only that.
        let dag = ContentId::from_dag_cbor_digest(id.digest_bytes());
        let cbor_dag = crate::canonical::to_canonical_dagcbor(&dag).unwrap();
        let err = crate::canonical::from_canonical_dagcbor_checked::<RawContentId>(&cbor_dag)
            .expect_err("a dag-cbor link must not deserialize as a RawContentId");
        assert!(
            matches!(err, ContentError::DecodingError { .. }),
            "the profile must be refused at the serde BOUNDARY (DecodingError), not \
             caught later by the re-encode comparison, got {err:?}"
        );
    }
}
