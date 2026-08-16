//! [`IdentityMigration`] — a content-addressed **record that one identity was
//! superseded by another**, so an identity change is *stated*, never *implied*.
//!
//! **Feature-gated (`unstable-migration`, default OFF) and NON-FROZEN**: the
//! field names below are load-bearing for the record's own id and may change
//! until this shape's conformance vectors land.
//!
//! # Why a record, not an equality
//!
//! Moving a logical object from an old canonicalization (kyln's ciborium CBOR,
//! nessie's length-delimited encodings, a bare digest) to this crate's canonical
//! dag-cbor — or from one profile to another, or across a hash rotation — is an
//! **identity migration, not a serialization migration**. Anything that
//! referenced the old CID does not thereby reference the new one, and nothing
//! in the algebra can make it so (law 6: codec + hash + digest *are* the
//! identity). What a system *can* do is publish a signed, content-addressed
//! statement:
//!
//! ```text
//! OldIdentity ──IdentityMigration──▶ NewIdentity
//! ```
//!
//! and let provenance follow that edge explicitly (decision record
//! `docs/adr/0003`, question 4). The record is itself [`ContentAddressable`]:
//! its own [`ContentId`] is the stable name of *the claim that the migration
//! happened*, which is what a signature or an attestation set binds to. **This
//! crate owns the record's identity, not its authorization** — who may assert a
//! migration, and how it is signed, is a consumer concern (agent-mesh, kyln).
//!
//! `from` may be any [`VerifiedCid`] (foreign identities are exactly what gets
//! migrated); `to` must be one this crate mints — the constructor enforces it.

use crate::content_id::ContentId;
use crate::error::ContentError;
use crate::trait_def::ContentAddressable;
use crate::verified::VerifiedCid;
use serde::{Deserialize, Serialize};

/// Why an identity changed. Closed on purpose: a migration whose kind is not
/// one of these is a design conversation, not a new string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationKind {
    /// The same logical value, re-encoded under this crate's canonical
    /// dag-cbor (or re-chunked/re-shaped into a catalog structure). Different
    /// bytes, different digest, same meaning by the migrating system's claim.
    Recanonicalized,
    /// The same bytes under a different CID profile — e.g. a bare BLAKE3
    /// digest or a dag-cbor-stamped digest restated as the honest raw profile.
    /// Same digest, different codec, therefore a different identity (law 6).
    Reprofiled,
    /// The same content re-hashed under a different multihash algorithm (a
    /// forward-ratchet rotation, or a foreign sha2-256 identity restated as
    /// BLAKE3 after re-hashing the actual content).
    HashRotated,
}

/// A content-addressed statement that `from` was superseded by `to`.
///
/// Construct with [`IdentityMigration::new`], which refuses a foreign `to`.
/// The record's own identity is [`ContentAddressable::content_id`] over its
/// canonical dag-cbor; `from`/`to` land on the wire as real tag-42 links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityMigration {
    /// The superseded identity — any profile, including foreign.
    pub from: VerifiedCid,
    /// The superseding identity — always one this crate mints.
    pub to: VerifiedCid,
    /// Why the identity changed.
    pub reason: MigrationKind,
}

impl IdentityMigration {
    /// Build a migration record.
    ///
    /// # Errors
    ///
    /// [`ContentError::InvalidCidProfile`] if `to` is [`VerifiedCid::Foreign`]:
    /// a migration must land on a profile this crate mints, otherwise it is
    /// not a migration *onto* the shared algebra.
    pub fn new(
        from: VerifiedCid,
        to: VerifiedCid,
        reason: MigrationKind,
    ) -> Result<Self, ContentError> {
        if !to.is_mintable() {
            return Err(ContentError::InvalidCidProfile {
                reason: format!(
                    "migration target must be a mintable profile (Content or Raw), got foreign codec 0x{:x} / hash 0x{:x}",
                    to.codec(),
                    to.hash_code()
                ),
            });
        }
        Ok(IdentityMigration { from, to, reason })
    }

    /// The identity of *this record* — what a signature or attestation binds
    /// to. Shorthand for [`ContentAddressable::content_id`].
    ///
    /// # Errors
    ///
    /// Propagates the canonical-encoding error, if any.
    pub fn id(&self) -> Result<ContentId, ContentError> {
        self.content_id()
    }
}

impl ContentAddressable for IdentityMigration {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        crate::canonical::to_canonical_dagcbor(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_id::RawContentId;
    use ipld_core::cid::multihash::Multihash;
    use ipld_core::cid::Cid;

    fn sha_foreign(d: [u8; 32]) -> VerifiedCid {
        VerifiedCid::from_cid(Cid::new_v1(0x55, Multihash::wrap(0x12, &d).unwrap()))
    }

    #[test]
    fn foreign_to_raw_is_a_hash_rotation_and_has_a_stable_id() {
        let content = b"the artifact";
        let old = sha_foreign([1u8; 32]); // pretend REAPI sha2-256 identity
        let new = VerifiedCid::from(RawContentId::from_content(content));
        let m = IdentityMigration::new(old, new, MigrationKind::HashRotated).unwrap();
        let id1 = m.id().unwrap();
        let bytes = m.canonical_form().unwrap();
        let back: IdentityMigration = crate::canonical::from_canonical_dagcbor(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.id().unwrap(), id1);
        assert!(m.verify(&id1).unwrap());
    }

    #[test]
    fn reprofile_records_a_real_identity_change() {
        let d = *blake3::hash(b"x").as_bytes();
        let from = VerifiedCid::from(ContentId::from_dag_cbor_digest(d)); // the old lie
        let to = VerifiedCid::from(RawContentId::from_blake3_digest(d)); // the honest raw id
        assert_ne!(from, to, "law 6: same digest, different identity");
        let m = IdentityMigration::new(from, to, MigrationKind::Reprofiled).unwrap();
        // Different reasons => different records => different record ids.
        let m2 = IdentityMigration::new(from, to, MigrationKind::Recanonicalized).unwrap();
        assert_ne!(m.id().unwrap(), m2.id().unwrap());
    }

    #[test]
    fn foreign_target_is_refused() {
        let from = VerifiedCid::from(RawContentId::from_content(b"a"));
        let err = IdentityMigration::new(from, sha_foreign([2u8; 32]), MigrationKind::HashRotated);
        assert!(matches!(err, Err(ContentError::InvalidCidProfile { .. })));
    }

    #[test]
    fn links_are_tag42_on_the_wire() {
        let m = IdentityMigration::new(
            VerifiedCid::from(RawContentId::from_content(b"a")),
            VerifiedCid::from(RawContentId::from_content(b"b")),
            MigrationKind::Recanonicalized,
        )
        .unwrap();
        let bytes = m.canonical_form().unwrap();
        // Two tag-42 links present (0xd8 0x2a), and the reason as a text string.
        let tag42 = bytes.windows(2).filter(|w| w == &[0xd8, 0x2a]).count();
        assert_eq!(tag42, 2);
        assert!(bytes.windows(15).any(|w| w == b"recanonicalized"));
    }
}
