//! [`VerifiedCid`] — a parsed, structurally-valid CID classified by profile:
//! one of the two identities this crate **mints**, or a **foreign** identity it
//! can carry and compare but will not mint.
//!
//! ```text
//!                  CIDv1 (or v0)
//!                       │
//!            ┌──────────┴──────────┐
//!         mintable              verifiable only
//!            │                       │
//!      ┌─────┴─────┐                 │
//!   dag-cbor      raw          any other codec /
//!   BLAKE3       BLAKE3        hash combination
//!      │           │                 │
//!  ContentId  RawContentId     Foreign(Cid) — sha2-256, REAPI, CIDv0, …
//! ```
//!
//! This is *algorithm agility in the verifier without algorithm ambiguity in
//! the minter* (decision record `docs/adr/0003`, question 2). A boundary that
//! receives identifiers from the world — a store index, a provenance record, a
//! capability grant — can hold any well-formed CID as a `VerifiedCid`, know
//! exactly which profile it is, and refuse to *treat* a foreign one as
//! something it minted. Comparison is by **typed CID bytes** (variant + full
//! CID), never by digest bytes alone: `Raw(x) != Content(x)` (law 6).
//!
//! # Serde
//!
//! Serializes as the inner CID — a dag-cbor tag-42 link in binary/IPLD formats,
//! the multibase string in human-readable ones — so a `VerifiedCid` field is a
//! *real link*. Deserialization re-classifies from the codec/hash, so the
//! variant is never trusted from the wire; it is derived.

use crate::content_id::ContentId;
use crate::error::ContentError;
use crate::raw_id::RawContentId;
use core::fmt;
use core::str::FromStr;
use ipld_core::cid::Cid;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A CID classified by profile. See the [module docs](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VerifiedCid {
    /// This crate's dag-cbor profile: the identity of a canonical structured
    /// value. Mintable.
    Content(ContentId),
    /// This crate's raw profile: the identity of an opaque byte string.
    /// Mintable.
    Raw(RawContentId),
    /// A structurally-valid CID of any other profile (another codec, another
    /// hash such as `sha2-256` `0x12`, another digest length, or CIDv0). Can be
    /// carried, compared, linked, and rendered — **not** minted here, and never
    /// convertible to `Content`/`Raw` without a re-hash of the actual content.
    Foreign(Cid),
}

impl VerifiedCid {
    /// Classify an already-parsed [`Cid`]. Infallible: every well-formed CID is
    /// at least [`Foreign`](Self::Foreign).
    #[must_use]
    pub fn from_cid(cid: Cid) -> Self {
        if let Ok(id) = ContentId::try_from(cid) {
            return VerifiedCid::Content(id);
        }
        if let Ok(id) = RawContentId::try_from(cid) {
            return VerifiedCid::Raw(id);
        }
        VerifiedCid::Foreign(cid)
    }

    /// Parse the CID binary envelope and classify.
    ///
    /// # Errors
    ///
    /// [`ContentError::InvalidCid`] if the bytes are not a CID at all. A CID of
    /// a foreign profile is **not** an error — it is [`Foreign`](Self::Foreign).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContentError> {
        let cid = Cid::read_bytes(bytes).map_err(|e| ContentError::InvalidCid {
            reason: e.to_string(),
            source: Box::new(e),
        })?;
        Ok(Self::from_cid(cid))
    }

    /// Borrow the underlying [`Cid`], whichever variant.
    #[must_use]
    pub fn as_cid(&self) -> &Cid {
        match self {
            VerifiedCid::Content(id) => id.as_cid(),
            VerifiedCid::Raw(id) => id.as_cid(),
            VerifiedCid::Foreign(cid) => cid,
        }
    }

    /// The full CID binary envelope, whichever variant.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.as_cid().to_bytes()
    }

    /// `true` for the two profiles this crate mints (`Content`, `Raw`).
    #[must_use]
    pub fn is_mintable(&self) -> bool {
        !matches!(self, VerifiedCid::Foreign(_))
    }

    /// The multicodec code of the CID (`0x71` dag-cbor, `0x55` raw, or whatever
    /// a foreign CID declares).
    #[must_use]
    pub fn codec(&self) -> u64 {
        self.as_cid().codec()
    }

    /// The multihash code of the CID (`0x1e` BLAKE3, `0x12` sha2-256, …).
    #[must_use]
    pub fn hash_code(&self) -> u64 {
        self.as_cid().hash().code()
    }

    /// The [`ContentId`] if this is the dag-cbor profile.
    #[must_use]
    pub fn as_content(&self) -> Option<&ContentId> {
        match self {
            VerifiedCid::Content(id) => Some(id),
            _ => None,
        }
    }

    /// The [`RawContentId`] if this is the raw profile.
    #[must_use]
    pub fn as_raw(&self) -> Option<&RawContentId> {
        match self {
            VerifiedCid::Raw(id) => Some(id),
            _ => None,
        }
    }
}

impl From<ContentId> for VerifiedCid {
    fn from(id: ContentId) -> Self {
        VerifiedCid::Content(id)
    }
}

impl From<RawContentId> for VerifiedCid {
    fn from(id: RawContentId) -> Self {
        VerifiedCid::Raw(id)
    }
}

impl From<VerifiedCid> for Cid {
    fn from(v: VerifiedCid) -> Self {
        *v.as_cid()
    }
}

impl fmt::Display for VerifiedCid {
    /// The inner CID's canonical multibase string (base32-lower for CIDv1; a
    /// foreign CIDv0 renders as its base58btc form, per the CID spec).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_cid(), f)
    }
}

impl FromStr for VerifiedCid {
    type Err = ContentError;

    /// Parse any multibase CID string and classify. Legacy dialects (kyln
    /// envelope-hex, `blake3:<hex>`, bare digest hex) are **not** accepted —
    /// use the explicit `legacy` adapters.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cid = Cid::from_str(s).map_err(|e| ContentError::InvalidCid {
            reason: e.to_string(),
            source: Box::new(e),
        })?;
        Ok(Self::from_cid(cid))
    }
}

impl Serialize for VerifiedCid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.as_cid().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for VerifiedCid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse::<VerifiedCid>()
                .map_err(<D::Error as serde::de::Error>::custom)
        } else {
            let cid = Cid::deserialize(deserializer)?;
            Ok(VerifiedCid::from_cid(cid))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipld_core::cid::multihash::Multihash;

    fn digest() -> [u8; 32] {
        *blake3::hash(b"classify me").as_bytes()
    }

    #[test]
    fn classifies_both_mintable_profiles() {
        let c = ContentId::from_dag_cbor_digest(digest());
        let r = RawContentId::from_blake3_digest(digest());
        assert_eq!(VerifiedCid::from_cid(*c.as_cid()), VerifiedCid::Content(c));
        assert_eq!(VerifiedCid::from_cid(*r.as_cid()), VerifiedCid::Raw(r));
        assert!(VerifiedCid::from(c).is_mintable());
        assert!(VerifiedCid::from(r).is_mintable());
        assert_eq!(VerifiedCid::from(c).as_content(), Some(&c));
        assert_eq!(VerifiedCid::from(r).as_raw(), Some(&r));
    }

    #[test]
    fn foreign_profiles_are_carried_not_minted() {
        let sha = Cid::new_v1(0x55, Multihash::wrap(0x12, &[7u8; 32]).unwrap());
        let v = VerifiedCid::from_cid(sha);
        assert_eq!(v, VerifiedCid::Foreign(sha));
        assert!(!v.is_mintable());
        assert_eq!(v.codec(), 0x55);
        assert_eq!(v.hash_code(), 0x12);
        assert!(v.as_content().is_none() && v.as_raw().is_none());
        // Round-trips through bytes and text without becoming mintable.
        assert_eq!(VerifiedCid::from_bytes(&v.to_bytes()).unwrap(), v);
        assert_eq!(v.to_string().parse::<VerifiedCid>().unwrap(), v);
    }

    /// Law 6 at the enum level: same digest bytes, three different identities.
    #[test]
    fn same_digest_three_identities() {
        let d = digest();
        let content = VerifiedCid::from(ContentId::from_dag_cbor_digest(d));
        let raw = VerifiedCid::from(RawContentId::from_blake3_digest(d));
        let foreign = VerifiedCid::from_cid(Cid::new_v1(0x55, Multihash::wrap(0x12, &d).unwrap()));
        assert_ne!(content, raw);
        assert_ne!(raw, foreign);
        assert_ne!(content, foreign);
        assert_ne!(content.to_bytes(), raw.to_bytes());
    }

    #[test]
    fn serde_link_reclassifies_from_the_wire() {
        let r = VerifiedCid::from(RawContentId::from_content(b"link me"));
        let cbor = crate::canonical::to_canonical_dagcbor(&r).unwrap();
        assert_eq!(&cbor[..2], &[0xd8, 0x2a], "must be a tag-42 link");
        let back: VerifiedCid = crate::canonical::from_canonical_dagcbor(&cbor).unwrap();
        assert_eq!(back, r);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<VerifiedCid>(&json).unwrap(), r);
    }

    #[test]
    fn garbage_is_an_error_not_foreign() {
        assert!(matches!(
            VerifiedCid::from_bytes(b"nope"),
            Err(ContentError::InvalidCid { .. })
        ));
        assert!(matches!(
            "nope".parse::<VerifiedCid>(),
            Err(ContentError::InvalidCid { .. })
        ));
    }
}
