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
    /// # Mismatch is `Ok(false)`, not an error (FROZEN at 0.1.0)
    ///
    /// A *mismatch* is **not** an error — it returns `Ok(false)`. A negative
    /// answer to "do these match?" is a successful, expected result, not a
    /// failure to check; forcing it through the `Err` channel would conflate "I
    /// checked, the answer is no" with "I couldn't check". The `?`-friendly
    /// `Result<bool>` also composes cleanly in boolean logic
    /// (`if a.verify(&id1)? && b.verify(&id2)? { … }`). This return contract is a
    /// **frozen** part of the `0.1.0` API surface (README gate item #8) —
    /// flipping `Ok(false)` to an `Err` arm later would be a breaking change.
    ///
    /// If you want a mismatch to short-circuit via `?`, use the strict helper
    /// [`ensure_content_id`](Self::ensure_content_id), which returns
    /// `Err(`[`ContentError::VerificationFailed`]`)` on mismatch — don't hand-roll
    /// it.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`content_id`](Self::content_id) only (i.e. an
    /// encoding failure in `canonical_form`); never an `Err` on a clean
    /// mismatch.
    fn verify(&self, expected: &ContentId) -> Result<bool, ContentError> {
        Ok(&self.content_id()? == expected)
    }

    /// Verify, returning an **error on mismatch** instead of `Ok(false)`.
    ///
    /// Like [`verify`](Self::verify), but a mismatch is reported as
    /// `Err(`[`ContentError::VerificationFailed`]`)` carrying both ids (as their
    /// [`Display`](core::fmt::Display) strings, multibase base32-lower `b…`),
    /// rather than `Ok(false)`. On a match it returns `Ok(())`. Use this when a
    /// mismatch should short-circuit through `?`; use [`verify`](Self::verify)
    /// when you want the boolean to compose in further logic.
    ///
    /// This is the strict form the crate's doctrine promises: it makes
    /// [`ContentError::VerificationFailed`] a real, reachable, tested error path
    /// rather than a name callers must construct by hand. It is a defaulted trait
    /// method, so every implementor gets it for free. Both `verify` and this
    /// helper are **frozen** for the `0.1.0` API surface (README gate item #8).
    ///
    /// # Errors
    ///
    /// - [`ContentError::VerificationFailed`] if the recomputed id differs from
    ///   `expected`.
    /// - Otherwise propagates any error from [`content_id`](Self::content_id)
    ///   (e.g. an encoding failure in `canonical_form`).
    fn ensure_content_id(&self, expected: &ContentId) -> Result<(), ContentError> {
        let computed = self.content_id()?;
        if &computed == expected {
            Ok(())
        } else {
            Err(ContentError::VerificationFailed {
                expected: expected.to_string(),
                computed: computed.to_string(),
            })
        }
    }
}
