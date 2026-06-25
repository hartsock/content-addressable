//! The [`ContentAddressable`] trait — the one thing a type implements to gain
//! a self-certifying identity.
//!
//! A type becomes content-addressable by defining a single method,
//! [`canonical_form`](ContentAddressable::canonical_form), that produces its
//! deterministic byte representation. Everything else — computing the
//! [`ContentId`] and verifying against an expected id — is provided.

use crate::content_id::ContentId;
use crate::error::ContentError;

/// A value that can name itself by its content.
///
/// Implementors provide [`canonical_form`](Self::canonical_form); the
/// [`content_id`](Self::content_id) and [`verify`](Self::verify) methods are
/// derived from it for free.
///
/// # Implementing
///
/// For any `#[derive(serde::Serialize)]` type, the canonical form is just its
/// canonical dag-cbor encoding, so the implementation is one line:
///
/// ```
/// use content_addressable::{canonical, ContentAddressable, ContentError};
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Block {
///     parent: Option<String>,
///     payload: Vec<u8>,
/// }
///
/// impl ContentAddressable for Block {
///     fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
///         canonical::to_canonical_dagcbor(self)
///     }
/// }
///
/// let block = Block { parent: None, payload: vec![1, 2, 3] };
/// let id = block.content_id().unwrap();
/// assert!(block.verify(&id).unwrap());
/// ```
pub trait ContentAddressable {
    /// Produce the deterministic byte representation of this value.
    ///
    /// This is the *only* required method. The canonical bytes must be a
    /// function of the value alone: equal values must produce equal bytes.
    /// The recommended implementation defers to
    /// [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor) on a
    /// `Serialize` type, which guarantees that property.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError`] if the value cannot be canonically encoded.
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError>;

    /// Compute this value's [`ContentId`].
    ///
    /// Hashes the [`canonical_form`](Self::canonical_form) into a BLAKE3
    /// CIDv1. Override only if you have a faster path that is provably
    /// identical to the default.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`canonical_form`](Self::canonical_form).
    fn content_id(&self) -> Result<ContentId, ContentError> {
        Ok(ContentId::from_canonical_bytes(&self.canonical_form()?))
    }

    /// Check whether this value's content id matches an `expected` id.
    ///
    /// Returns `Ok(true)` if the recomputed id equals `expected`, `Ok(false)`
    /// otherwise. This is the integrity check at the heart of the doctrine:
    /// the value re-derives its own identity and compares it to the claim.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`content_id`](Self::content_id). A *mismatch*
    /// is not an error — it returns `Ok(false)`. Callers who want a hard
    /// failure on mismatch can map `Ok(false)` to
    /// [`ContentError::VerificationFailed`] themselves.
    fn verify(&self, expected: &ContentId) -> Result<bool, ContentError> {
        Ok(&self.content_id()? == expected)
    }
}
