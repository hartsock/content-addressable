//! The [`ContentAddressable`] trait — the one thing a type implements to gain
//! a self-certifying identity.
//!
//! A type becomes content-addressable by defining a single method,
//! [`canonical_form`](ContentAddressable::canonical_form), that produces its
//! deterministic byte representation. Everything else — computing the
//! [`ContentId`] and verifying against an expected id — is provided.

use serde::de::DeserializeOwned;

use crate::canonical;
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
    /// encoding failure in [`canonical_form`](Self::canonical_form)); never an `Err` on a clean
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
    /// method, so every implementor gets it for free. Both [`verify`](Self::verify) and this
    /// helper are **frozen** for the `0.1.0` API surface (README gate item #8).
    ///
    /// # Errors
    ///
    /// - [`ContentError::VerificationFailed`] if the recomputed id differs from
    ///   `expected`.
    /// - Otherwise propagates any error from [`content_id`](Self::content_id)
    ///   (e.g. an encoding failure in [`canonical_form`](Self::canonical_form)).
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

    /// **Checked ingress**: decode a value from its canonical form, proving the
    /// bytes reproduce it — a checked *partial* inverse of
    /// [`canonical_form`](Self::canonical_form).
    ///
    /// This is the door for bytes you did not produce: foreign, stored, or off
    /// the wire.
    ///
    /// # The enforced invariant
    ///
    /// On success, and unconditionally:
    ///
    /// ```
    /// # use content_addressable::{canonical, ContentAddressable, ContentError};
    /// # use serde::{Deserialize, Serialize};
    /// # #[derive(Serialize, Deserialize)] struct T { a: u64 }
    /// # impl ContentAddressable for T {
    /// #     fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
    /// #         canonical::to_canonical_dagcbor(self)
    /// #     }
    /// # }
    /// # let bytes: &[u8] = &T { a: 1 }.canonical_form()?;
    /// let value = T::from_canonical_form(bytes)?;
    /// assert_eq!(value.canonical_form()?, bytes);
    /// # Ok::<(), ContentError>(())
    /// ```
    ///
    /// That is the whole guarantee, and it is a claim about **bytes**, not about
    /// the codec: it is established by re-encoding the decoded value and
    /// comparing, not by appealing to dag-cbor being canonical. Exact byte
    /// equality is also strictly stronger than comparing two
    /// [`ContentId`]s — it assumes no collision resistance.
    ///
    /// ## Corollary for a lawful implementation
    ///
    /// Call an implementation **lawful** when its
    /// [`content_id`](Self::content_id) agrees with the trait law —
    /// `content_id() == ContentId::from_canonical_bytes(&canonical_form()?)`,
    /// which the provided default satisfies by construction. For a lawful
    /// implementation the invariant above gives:
    ///
    /// ```text
    /// value.content_id()? == ContentId::from_canonical_bytes(bytes)
    /// ```
    ///
    /// This is a **corollary, not a guarantee**. [`content_id`](Self::content_id)
    /// is overridable, and an override that is not provably identical to the
    /// default breaks the equation. Nothing here calls [`content_id`](Self::content_id), so **the
    /// crate cannot detect that**. A caller who needs the equation held rather
    /// than assumed checks it, with
    /// [`ensure_content_id`](Self::ensure_content_id):
    ///
    /// ```text
    /// value.ensure_content_id(&ContentId::from_canonical_bytes(bytes))?;
    /// ```
    ///
    /// # Partial: the domain, and which prerequisite failed
    ///
    /// It succeeds on exactly those `bytes` that are
    ///
    /// 1. **canonical dag-cbor** — otherwise [`ContentError::DecodingError`] (not
    ///    dag-cbor at all) or [`ContentError::NonCanonical`] (dag-cbor, but not
    ///    the canonical encoding). Established generically, *before* any `Self`
    ///    is constructed, so the result does not lean on this type's serde impl
    ///    being well behaved;
    /// 2. **directly deserializable as `Self`** — otherwise
    ///    [`ContentError::DecodingError`];
    /// 3. **reproduced byte-for-byte by the decoded value's [`canonical_form`](Self::canonical_form)** —
    ///    otherwise [`ContentError::LossyDecode`].
    ///
    /// Every failure names the prerequisite that was not met.
    ///
    /// # What "inverse" does and does not mean here
    ///
    /// On its accepted byte domain, decoding and re-encoding reproduces the
    /// original canonical bytes. The returned value therefore has the same
    /// canonical representation and content identity; it is **not necessarily
    /// equal to a previously encoded in-memory value** unless the type separately
    /// guarantees a value-preserving serde round trip.
    ///
    /// `Serialize + DeserializeOwned` does not establish that. A
    /// `#[serde(skip)]` or defaulted field decodes to a *different* in-memory
    /// value with **identical** canonical bytes — which this door correctly
    /// accepts, because those bytes really are that value's canonical
    /// representation. Identity is preserved; the in-memory value need not be.
    ///
    /// A second, separate limit applies to the *shape* of the type:
    ///
    /// A type may define a [`canonical_form`](Self::canonical_form) that is deliberately **not** its
    /// serde representation — an envelope, a versioned framing, a projection —
    /// and still be perfectly lawful for content addressing: its identity is
    /// well defined and reproducible. But its canonical bytes are then not
    /// directly deserializable as `Self` unless it also supplies a matching
    /// `Deserialize`, so [`from_canonical_form`](Self::from_canonical_form) on its *own* output fails
    /// prerequisite 2 with [`ContentError::DecodingError`].
    ///
    /// That is not a defect in the type and does not make its [`canonical_form`](Self::canonical_form)
    /// unlawful. It means this method is checked ingress for the common
    /// representation, not a universal inverse: a custom canonical form needs a
    /// custom decoder to match it. What the method never does is *guess* —
    /// it refuses rather than return a value the bytes do not reproduce.
    ///
    /// # Why stage 3 re-encodes through [`canonical_form`](Self::canonical_form)
    ///
    /// Deliberately, rather than through
    /// [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor):
    /// [`canonical_form`](Self::canonical_form) is the function that *defines* this type's identity, so
    /// it is the only re-encode whose equality proves the invariant. For the
    /// recommended one-line implementation the two coincide; for a type with its
    /// own canonical form they do not, and only this one is sound. It is also why
    /// the bound is `DeserializeOwned + Sized` and not also `Serialize`.
    ///
    /// For a plain `Serialize + Deserialize` value that is not
    /// [`ContentAddressable`](Self), use
    /// [`canonical::from_canonical_dagcbor_checked`], whose stage 3 is
    /// [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor) instead.
    ///
    /// # Overriding
    ///
    /// Like [`content_id`](Self::content_id), override this only if you have a
    /// path that is *provably identical*. An override that skips a stage does
    /// **not** weaken the store seam — `NodeStoreExt::get_node` (feature
    /// `unstable-store`) deliberately runs the shared body rather than this
    /// method, so a `T` cannot hand itself a pass — but it does weaken every
    /// direct caller of `T::from_canonical_form`.
    ///
    /// # Availability
    ///
    /// Added in `0.1.2` (issue #90) as a defaulted associated function, so every
    /// implementor gets it for free; it carries `where Self: Sized`, so the trait
    /// stays dyn-compatible. It is the one deliberate exception `0.1.2` makes to
    /// the otherwise frozen `0.1.x` Rust API — see `docs/STABILITY.md`.
    ///
    /// # Errors
    ///
    /// - [`ContentError::DecodingError`] — the bytes are not dag-cbor, or do not
    ///   decode as a `Self` (prerequisites 1 and 2).
    /// - [`ContentError::NonCanonical`] — the bytes are dag-cbor but not the
    ///   canonical encoding (prerequisite 1).
    /// - [`ContentError::LossyDecode`] — the decoded value's [`canonical_form`](Self::canonical_form)
    ///   differs from the input (prerequisite 3).
    /// - Anything [`canonical_form`](Self::canonical_form) itself returns,
    ///   propagated verbatim — typically [`ContentError::EncodingError`].
    fn from_canonical_form(bytes: &[u8]) -> Result<Self, ContentError>
    where
        Self: DeserializeOwned + Sized,
    {
        match checked_decode::<Self>(bytes)? {
            CheckedDecode::Value(value) => Ok(value),
            CheckedDecode::Lossy => Err(ContentError::LossyDecode),
        }
    }
}

/// The verdict of [`checked_decode`].
///
/// The lossy case is a **value, not an error**, for two reasons. It lets each
/// caller name the verdict in its own vocabulary (the store seam calls it
/// `RepresentationMismatch`, which can point at the id that lied). And it keeps a
/// [`ContentError::LossyDecode`] that came out of the *caller's own*
/// [`canonical_form`](crate::ContentAddressable::canonical_form) distinguishable from this function's own byte comparison — an
/// error value alone could not tell the two apart, and the seam would blame the
/// stored bytes for a failure inside the type's encoder.
pub(crate) enum CheckedDecode<T> {
    /// The bytes decoded as a `T` whose [`canonical_form`](crate::ContentAddressable::canonical_form) reproduces them exactly.
    Value(T),
    /// Typed round-trip mismatch: the decode succeeded, but the decoded value's
    /// [`canonical_form`](crate::ContentAddressable::canonical_form) differs from
    /// the input bytes, so those bytes are not its canonical representation.
    Lossy,
}

/// The crate's one identity-preserving decode: canonical bytes, a typed decode,
/// and a forward re-encode through the type's own [`canonical_form`](crate::ContentAddressable::canonical_form).
///
/// This is the body of [`ContentAddressable::from_canonical_form`], factored out
/// so the **store seam can run it without going through that method**.
/// [`from_canonical_form`](crate::ContentAddressable::from_canonical_form) is defaulted on an unsealed trait, so a downstream `T`
/// can override it — including with a bare, unverified decode. A seam whose
/// integrity guarantee routed through it would be handing that guarantee to `T`,
/// which is precisely the bug class this line of work exists to close. Stage 3
/// necessarily consults `T::canonical_form` (that is what identity *means* for a
/// `ContentAddressable`); stages 1 and 2 must not.
///
/// # Errors
///
/// [`ContentError::NonCanonical`], [`ContentError::DecodingError`] and
/// [`ContentError::EncodingError`] from the three stages, in that order. Whatever
/// [`canonical_form`](crate::ContentAddressable::canonical_form) returns is propagated **verbatim** — the lossy verdict
/// travels as `Ok(`[`CheckedDecode::Lossy`]`)`, never as an error.
pub(crate) fn checked_decode<T>(bytes: &[u8]) -> Result<CheckedDecode<T>, ContentError>
where
    T: DeserializeOwned + ContentAddressable,
{
    // 1. The bytes are canonical — proven generically, so this does not rely on
    //    `T::canonical_form` being a lawful (canonical) implementation.
    canonical::ensure_canonical(bytes)?;
    // 2. They decode as a `T`.
    let value: T = canonical::decode_dagcbor(bytes)?;
    // 3. …and re-encoding through the function that defines this type's identity
    //    reproduces them exactly. Inequality is decisive: the value is NOT the one
    //    these bytes name.
    if value.canonical_form()? != bytes {
        return Ok(CheckedDecode::Lossy);
    }
    Ok(CheckedDecode::Value(value))
}
