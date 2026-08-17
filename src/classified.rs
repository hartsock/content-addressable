//! [`ClassifiedCid`] — a structurally-valid CID classified by profile: one of
//! the two identities this crate **mints**, or a validated [`ForeignCid`] it can
//! carry and compare but will not mint.
//!
//! ```text
//!                  CIDv1 (or v0)
//!                       │
//!            ┌──────────┴──────────┐
//!         mintable              classified only
//!            │                       │
//!      ┌─────┴─────┐                 │
//!   dag-cbor      raw          any other codec /
//!   BLAKE3       BLAKE3        hash combination
//!      │           │                 │
//!  ContentId  RawContentId      ForeignCid — sha2-256, REAPI, CIDv0, …
//! ```
//!
//! This is *algorithm agility in the classifier without algorithm ambiguity in
//! the minter* (decision record `docs/adr/0003`, question 2). A boundary that
//! receives identifiers from the world — a store index, a provenance record, a
//! capability grant — can hold any well-formed CID, know exactly which profile
//! it is, and refuse to *treat* a foreign one as something it minted.
//!
//! # Why `Classified`, not `Verified`
//!
//! This type performs **structural validation** (the bytes are a well-formed
//! CID) and **profile classification** (which of the three kinds it is). It does
//! **not** verify content against a digest — that is
//! [`RawContentId::verify`](crate::RawContentId::verify) /
//! [`ContentAddressable::verify`](crate::ContentAddressable::verify), which need
//! the bytes. Naming it "verified" would overclaim exactly the property a
//! security consumer must not assume. Renamed before the surface froze.
//!
//! # Canonical form (the invariant)
//!
//! **Every CID has exactly one representation here**, and no variant can hold a
//! CID outside its own profile:
//!
//! - [`ContentId`] admits only CIDv1 · dag-cbor `0x71` · BLAKE3 `0x1e` · 32;
//! - [`RawContentId`] admits only CIDv1 · raw `0x55` · BLAKE3 `0x1e` · 32;
//! - [`ForeignCid`] admits **only** CIDs that neither of the above accepts.
//!
//! The three profiles are pairwise disjoint and jointly total over well-formed
//! CIDs, so `ClassifiedCid::from_cid` is a bijection onto the representable
//! values: there is no way — including hand-writing an enum variant, or feeding
//! a crafted link to `Deserialize` — to build a `Foreign` that wraps a
//! recognized profile, or a `Content`/`Raw` that wraps a foreign one. Equality
//! is therefore equality of the underlying CID, and comparison is by **typed CID
//! bytes**, never by digest bytes alone: `Raw(x) != Content(x)` (law 6).
//!
//! # Serde
//!
//! Serializes as the inner CID — a dag-cbor tag-42 link in binary/IPLD formats,
//! the multibase string in human-readable ones — so a `ClassifiedCid` field is a
//! *real link*. Deserialization re-classifies from the codec/hash, so the
//! variant is never trusted from the wire; it is **derived**, which is what keeps
//! the canonical-form invariant true across a round trip.

use crate::content_id::ContentId;
use crate::error::ContentError;
use crate::raw_id::RawContentId;
use core::fmt;
use core::str::FromStr;
use ipld_core::cid::Cid;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A CID that is **not** one of this crate's two mintable profiles.
///
/// The inner [`Cid`] is private and the only constructors
/// ([`new`](Self::new), [`TryFrom<Cid>`], [`FromStr`], [`from_bytes`](Self::from_bytes),
/// `Deserialize`) reject a recognized profile, so a `ForeignCid` can never
/// alias a [`ContentId`] or [`RawContentId`]. That is what makes
/// [`ClassifiedCid`] canonical.
///
/// A `ForeignCid` can be carried, compared, linked and rendered. It cannot be
/// minted here and never becomes a `ContentId`/`RawContentId` without re-hashing
/// the actual content under a profile this crate does mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ForeignCid(Cid);

impl ForeignCid {
    /// Wrap a CID that neither mintable profile accepts.
    ///
    /// # Errors
    ///
    /// [`ContentError::InvalidCidProfile`] if `cid` **is** a recognized profile
    /// (dag-cbor/BLAKE3 or raw/BLAKE3). Such a CID is not foreign; classify it
    /// with [`ClassifiedCid::from_cid`], which returns the right variant.
    pub fn new(cid: Cid) -> Result<Self, ContentError> {
        if ContentId::try_from(cid).is_ok() {
            return Err(ContentError::InvalidCidProfile {
                reason: "CID is the dag-cbor/BLAKE3 profile (a ContentId), not foreign".into(),
            });
        }
        if RawContentId::try_from(cid).is_ok() {
            return Err(ContentError::InvalidCidProfile {
                reason: "CID is the raw/BLAKE3 profile (a RawContentId), not foreign".into(),
            });
        }
        Ok(ForeignCid(cid))
    }

    /// Borrow the underlying [`Cid`].
    #[must_use]
    pub fn as_cid(&self) -> &Cid {
        &self.0
    }

    /// The full CID binary envelope.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Parse a CID binary envelope that is not a recognized profile.
    ///
    /// # Errors
    ///
    /// [`ContentError::InvalidCid`] if the bytes are not a CID;
    /// [`ContentError::InvalidCidProfile`] if they are a recognized profile.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContentError> {
        let cid = Cid::read_bytes(bytes).map_err(|e| ContentError::InvalidCid {
            reason: e.to_string(),
            source: Box::new(e),
        })?;
        Self::new(cid)
    }

    /// The multicodec code this foreign CID declares.
    #[must_use]
    pub fn codec(&self) -> u64 {
        self.0.codec()
    }

    /// The multihash code this foreign CID declares.
    #[must_use]
    pub fn hash_code(&self) -> u64 {
        self.0.hash().code()
    }
}

impl TryFrom<Cid> for ForeignCid {
    type Error = ContentError;

    fn try_from(cid: Cid) -> Result<Self, Self::Error> {
        Self::new(cid)
    }
}

impl From<ForeignCid> for Cid {
    fn from(id: ForeignCid) -> Self {
        id.0
    }
}

impl fmt::Display for ForeignCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for ForeignCid {
    type Err = ContentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cid = Cid::from_str(s).map_err(|e| ContentError::InvalidCid {
            reason: e.to_string(),
            source: Box::new(e),
        })?;
        Self::new(cid)
    }
}

impl Serialize for ForeignCid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for ForeignCid {
    /// Validating: a link that *is* a recognized profile is rejected here rather
    /// than admitted as a foreign alias.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse::<ForeignCid>()
                .map_err(<D::Error as serde::de::Error>::custom)
        } else {
            let cid = Cid::deserialize(deserializer)?;
            ForeignCid::new(cid).map_err(<D::Error as serde::de::Error>::custom)
        }
    }
}

/// A CID classified by profile. See the [module docs](self) for the canonical
/// form invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ClassifiedCid {
    /// This crate's dag-cbor profile: the identity of a canonical structured
    /// value. Mintable.
    Content(ContentId),
    /// This crate's raw profile: the identity of an opaque byte string.
    /// Mintable.
    Raw(RawContentId),
    /// A well-formed CID of any other profile (another codec, another hash such
    /// as `sha2-256` `0x12`, another digest length, or CIDv0), validated by
    /// [`ForeignCid`] so it can never alias a recognized profile.
    Foreign(ForeignCid),
}

impl ClassifiedCid {
    /// Classify an already-parsed [`Cid`]. Infallible: every well-formed CID is
    /// exactly one of the three kinds.
    #[must_use]
    pub fn from_cid(cid: Cid) -> Self {
        if let Ok(id) = ContentId::try_from(cid) {
            return ClassifiedCid::Content(id);
        }
        if let Ok(id) = RawContentId::try_from(cid) {
            return ClassifiedCid::Raw(id);
        }
        ClassifiedCid::Foreign(ForeignCid(cid))
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
            ClassifiedCid::Content(id) => id.as_cid(),
            ClassifiedCid::Raw(id) => id.as_cid(),
            ClassifiedCid::Foreign(id) => id.as_cid(),
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
        !matches!(self, ClassifiedCid::Foreign(_))
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
            ClassifiedCid::Content(id) => Some(id),
            _ => None,
        }
    }

    /// The [`RawContentId`] if this is the raw profile.
    #[must_use]
    pub fn as_raw(&self) -> Option<&RawContentId> {
        match self {
            ClassifiedCid::Raw(id) => Some(id),
            _ => None,
        }
    }

    /// The [`ForeignCid`] if this is neither mintable profile.
    #[must_use]
    pub fn as_foreign(&self) -> Option<&ForeignCid> {
        match self {
            ClassifiedCid::Foreign(id) => Some(id),
            _ => None,
        }
    }
}

impl From<ContentId> for ClassifiedCid {
    fn from(id: ContentId) -> Self {
        ClassifiedCid::Content(id)
    }
}

impl From<RawContentId> for ClassifiedCid {
    fn from(id: RawContentId) -> Self {
        ClassifiedCid::Raw(id)
    }
}

impl From<ForeignCid> for ClassifiedCid {
    fn from(id: ForeignCid) -> Self {
        ClassifiedCid::Foreign(id)
    }
}

impl From<ClassifiedCid> for Cid {
    fn from(v: ClassifiedCid) -> Self {
        *v.as_cid()
    }
}

impl fmt::Display for ClassifiedCid {
    /// The inner CID's canonical multibase string (base32-lower for CIDv1; a
    /// foreign CIDv0 renders as its base58btc form, per the CID spec).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_cid(), f)
    }
}

impl FromStr for ClassifiedCid {
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

impl Serialize for ClassifiedCid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.as_cid().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for ClassifiedCid {
    /// Re-classifies from the wire bytes, so the variant is derived rather than
    /// trusted — a crafted link cannot land in the wrong variant.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse::<ClassifiedCid>()
                .map_err(<D::Error as serde::de::Error>::custom)
        } else {
            let cid = Cid::deserialize(deserializer)?;
            Ok(ClassifiedCid::from_cid(cid))
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

    fn sha_cid(d: [u8; 32]) -> Cid {
        Cid::new_v1(0x55, Multihash::wrap(0x12, &d).unwrap())
    }

    #[test]
    fn classifies_both_mintable_profiles() {
        let c = ContentId::from_dag_cbor_digest(digest());
        let r = RawContentId::from_blake3_digest(digest());
        assert_eq!(
            ClassifiedCid::from_cid(*c.as_cid()),
            ClassifiedCid::Content(c)
        );
        assert_eq!(ClassifiedCid::from_cid(*r.as_cid()), ClassifiedCid::Raw(r));
        assert!(ClassifiedCid::from(c).is_mintable());
        assert!(ClassifiedCid::from(r).is_mintable());
        assert_eq!(ClassifiedCid::from(c).as_content(), Some(&c));
        assert_eq!(ClassifiedCid::from(r).as_raw(), Some(&r));
        assert!(ClassifiedCid::from(c).as_foreign().is_none());
    }

    #[test]
    fn foreign_profiles_are_carried_not_minted() {
        let sha = sha_cid([7u8; 32]);
        let v = ClassifiedCid::from_cid(sha);
        assert_eq!(v, ClassifiedCid::Foreign(ForeignCid::new(sha).unwrap()));
        assert!(!v.is_mintable());
        assert_eq!(v.codec(), 0x55);
        assert_eq!(v.hash_code(), 0x12);
        assert!(v.as_content().is_none() && v.as_raw().is_none());
        assert_eq!(v.as_foreign().unwrap().hash_code(), 0x12);
        assert_eq!(ClassifiedCid::from_bytes(&v.to_bytes()).unwrap(), v);
        assert_eq!(v.to_string().parse::<ClassifiedCid>().unwrap(), v);
    }

    /// ADVERSARIAL (canonical form): a `ForeignCid` can never be built from a
    /// CID that either mintable profile accepts — through ANY door. This is the
    /// invariant that makes `ClassifiedCid` canonical: `Foreign` cannot alias
    /// `Content`/`Raw`, so one CID has exactly one representation.
    #[test]
    fn foreign_cannot_alias_a_recognized_profile_through_any_door() {
        let c = ContentId::from_dag_cbor_digest(digest());
        let r = RawContentId::from_blake3_digest(digest());
        for cid in [*c.as_cid(), *r.as_cid()] {
            assert!(matches!(
                ForeignCid::new(cid),
                Err(ContentError::InvalidCidProfile { .. })
            ));
            assert!(matches!(
                ForeignCid::try_from(cid),
                Err(ContentError::InvalidCidProfile { .. })
            ));
            assert!(matches!(
                ForeignCid::from_bytes(&cid.to_bytes()),
                Err(ContentError::InvalidCidProfile { .. })
            ));
            assert!(matches!(
                cid.to_string().parse::<ForeignCid>(),
                Err(ContentError::InvalidCidProfile { .. })
            ));
            // serde, both flavors: a crafted link/string must not deserialize
            // into a foreign alias of a recognized profile.
            let json = serde_json::to_string(&cid.to_string()).unwrap();
            assert!(serde_json::from_str::<ForeignCid>(&json).is_err());
            let cbor = crate::canonical::to_canonical_dagcbor(&cid).unwrap();
            assert!(crate::canonical::from_canonical_dagcbor::<ForeignCid>(&cbor).is_err());
        }
    }

    /// ADVERSARIAL: a foreign CID cannot enter a mintable variant either, so no
    /// variant can hold a CID outside its profile.
    #[test]
    fn mintable_variants_cannot_hold_a_foreign_cid() {
        let sha = sha_cid([3u8; 32]);
        assert!(ContentId::try_from(sha).is_err());
        assert!(RawContentId::try_from(sha).is_err());
        assert!(sha.to_string().parse::<ContentId>().is_err());
        assert!(sha.to_string().parse::<RawContentId>().is_err());
        assert!(matches!(
            ClassifiedCid::from_cid(sha),
            ClassifiedCid::Foreign(_)
        ));
    }

    /// Law 6 at the enum level: same digest bytes, three different identities.
    #[test]
    fn same_digest_three_identities() {
        let d = digest();
        let content = ClassifiedCid::from(ContentId::from_dag_cbor_digest(d));
        let raw = ClassifiedCid::from(RawContentId::from_blake3_digest(d));
        let foreign = ClassifiedCid::from_cid(sha_cid(d));
        assert_ne!(content, raw);
        assert_ne!(raw, foreign);
        assert_ne!(content, foreign);
        assert_ne!(content.to_bytes(), raw.to_bytes());
    }

    #[test]
    fn serde_link_reclassifies_from_the_wire() {
        let r = ClassifiedCid::from(RawContentId::from_content(b"link me"));
        let cbor = crate::canonical::to_canonical_dagcbor(&r).unwrap();
        assert_eq!(&cbor[..2], &[0xd8, 0x2a], "must be a tag-42 link");
        let back: ClassifiedCid = crate::canonical::from_canonical_dagcbor(&cbor).unwrap();
        assert_eq!(back, r);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<ClassifiedCid>(&json).unwrap(), r);

        // A foreign link round-trips as Foreign, and a recognized link never
        // deserializes into Foreign — the variant is derived, not trusted.
        let f = ClassifiedCid::from_cid(sha_cid([9u8; 32]));
        let f_cbor = crate::canonical::to_canonical_dagcbor(&f).unwrap();
        assert_eq!(
            crate::canonical::from_canonical_dagcbor::<ClassifiedCid>(&f_cbor).unwrap(),
            f
        );
        let c_cbor = crate::canonical::to_canonical_dagcbor(&ClassifiedCid::from(
            ContentId::from_dag_cbor_digest(digest()),
        ))
        .unwrap();
        assert!(matches!(
            crate::canonical::from_canonical_dagcbor::<ClassifiedCid>(&c_cbor).unwrap(),
            ClassifiedCid::Content(_)
        ));
    }

    #[test]
    fn garbage_is_an_error_not_foreign() {
        assert!(matches!(
            ClassifiedCid::from_bytes(b"nope"),
            Err(ContentError::InvalidCid { .. })
        ));
        assert!(matches!(
            "nope".parse::<ClassifiedCid>(),
            Err(ContentError::InvalidCid { .. })
        ));
        assert!(matches!(
            ForeignCid::from_bytes(b"nope"),
            Err(ContentError::InvalidCid { .. })
        ));
    }

    /// A CIDv0 (sha2-256, dag-pb, base58btc text) is foreign, not an error.
    #[test]
    fn cidv0_is_foreign() {
        let v0 = Cid::new_v0(Multihash::wrap(0x12, &[4u8; 32]).unwrap()).unwrap();
        let c = ClassifiedCid::from_cid(v0);
        assert!(matches!(c, ClassifiedCid::Foreign(_)));
        assert!(ForeignCid::new(v0).is_ok());
        assert_eq!(c.to_string().parse::<ClassifiedCid>().unwrap(), c);
    }
}
