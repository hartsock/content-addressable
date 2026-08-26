//! Canonical serialization via IPLD dag-cbor.
//!
//! # dag-cbor *is* the canonical form
//!
//! This crate does not implement its own canonicalization rules. It relies on
//! the IPLD dag-cbor codec, whose encoding is **deterministic by
//! construction**:
//!
//! - **Strict map key ordering.** Map keys are emitted in a fixed, defined
//!   order, so two semantically-equal maps always produce identical bytes
//!   regardless of insertion order.
//! - **Definite-length encoding.** Arrays and maps carry an explicit length;
//!   indefinite-length ("streaming") items are forbidden.
//! - **Tag 42 for links.** A [`Cid`](ipld_core::cid::Cid) is encoded as a CBOR
//!   tag-42 byte string, the IPLD convention for a content link.
//! - **Smallest-form integers and no duplicate keys.**
//!
//! Because the codec enforces these rules, determinism is a property of the
//! *encoder*, not of caller discipline. Callers do not need to sort fields,
//! pick a field order, or avoid maps: `to_canonical_dagcbor` will always
//! produce the same bytes for the same value.
//!
//! This determinism is what makes content addressing sound: the same value
//! hashes to the same [`ContentId`](crate::ContentId), always.
//!
//! # Decoding: checked vs unchecked (issue #90)
//!
//! Encoding is safe by construction; **decoding is not**. Determinism is a
//! property of the encoder, so it says nothing about bytes that arrived from
//! somewhere else. A plain `serde` decode into a type `T` is lossy in two
//! directions at once:
//!
//! - **The bytes may not be canonical.** Valid-but-non-canonical CBOR
//!   (reordered map keys, non-minimal integers, indefinite lengths) decodes
//!   perfectly well and re-encodes to *different* bytes. Codec strictness has
//!   also drifted between `serde_ipld_dagcbor` releases, so the decoder is not
//!   the guarantee.
//! - **The type may drop what it does not name.** `serde` ignores unknown map
//!   keys by default, so a record carrying a field `T` does not have decodes
//!   with the field silently gone.
//!
//! Either way the value the caller ends up holding re-encodes to bytes that are
//! **not** the bytes it was decoded from — so it has a different
//! [`ContentId`](crate::ContentId) than its own source, and nothing said so.
//! The only sound answer is a forward re-encode comparison, which is what
//! [`from_canonical_dagcbor_checked`] performs.
//!
//! | Door | Verifies | Use when |
//! |------|----------|----------|
//! | [`from_canonical_dagcbor`] (**deprecated**) | nothing | never — see its successors |
//! | [`from_canonical_dagcbor_checked`] | canonical bytes **and** a lossless typed round trip | any `Serialize + Deserialize` value |
//! | [`ContentAddressable::from_canonical_form`](crate::ContentAddressable::from_canonical_form) | the same, re-encoding through the type's own `canonical_form` | the value is [`ContentAddressable`](crate::ContentAddressable) |
//! | [`ContentId::from_canonical_bytes_checked`](crate::ContentId::from_canonical_bytes_checked) | canonical bytes only (generic `Ipld`, no type involved) | you want the *id* of foreign bytes, not a value |
//!
//! The `_checked` suffix follows the frozen
//! [`from_canonical_bytes`](crate::ContentId::from_canonical_bytes) /
//! [`from_canonical_bytes_checked`](crate::ContentId::from_canonical_bytes_checked)
//! pairing (see `docs/STABILITY.md`): the unverified door keeps the plain name,
//! the verifying one carries the suffix.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::ContentError;

/// Encode a value to its canonical dag-cbor byte representation.
///
/// The returned bytes are deterministic: equal values always encode to equal
/// bytes (see the [module docs](self) for why). These bytes are the input to
/// [`ContentId::from_canonical_bytes`](crate::ContentId::from_canonical_bytes).
///
/// # Errors
///
/// Returns [`ContentError::EncodingError`] if the value cannot be represented
/// as dag-cbor (for example, a float that dag-cbor forbids, or an allocation
/// failure).
pub fn to_canonical_dagcbor<T: Serialize>(value: &T) -> Result<Vec<u8>, ContentError> {
    // Box the concrete `serde_ipld_dagcbor::EncodeError<…>` as a `dyn Error` so
    // the codec crate's generic does not leak into the frozen public signature
    // of `ContentError::EncodingError` (see error.rs freeze decisions).
    serde_ipld_dagcbor::to_vec(value).map_err(|source| ContentError::EncodingError {
        source: Box::new(source),
    })
}

/// Decode a value from canonical dag-cbor bytes.
///
/// # Errors
///
/// Returns [`ContentError::DecodingError`] if the bytes are not valid canonical
/// dag-cbor for the target type.
pub fn from_canonical_dagcbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ContentError> {
    decode_dagcbor(bytes)
}

/// The bare typed decode: no canonicality check, no round-trip comparison.
///
/// Crate-internal so there is exactly one place where the codec's error is
/// boxed, and so the two public doors ([`from_canonical_dagcbor`] and
/// [`from_canonical_dagcbor_checked`]) share it rather than each calling
/// `serde_ipld_dagcbor` directly.
pub(crate) fn decode_dagcbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ContentError> {
    // Box the concrete `serde_ipld_dagcbor::DecodeError<…>` as a `dyn Error` so
    // the codec crate's generic does not leak into the frozen public signature
    // of `ContentError::DecodingError` (see error.rs freeze decisions).
    serde_ipld_dagcbor::from_slice(bytes).map_err(|source| ContentError::DecodingError {
        source: Box::new(source),
    })
}

/// Assert that `bytes` are the canonical dag-cbor encoding of the value they
/// denote — **independently of any target type**.
///
/// Decodes to the generic [`Ipld`](ipld_core::ipld::Ipld) data model (which
/// preserves every map key, so no type-shaped information is lost), re-encodes
/// canonically, and requires byte equality. Because the codec emits the *unique*
/// canonical form, equality proves the input already was it.
///
/// This is the single implementation of the canonicality gate: it is what
/// [`ContentId::from_canonical_bytes_checked`](crate::ContentId::from_canonical_bytes_checked)
/// and [`from_canonical_dagcbor_checked`] both run, so the two cannot drift.
/// The gate is the same one `from_canonical_bytes_checked` has always applied —
/// hoisted here, not redefined.
///
/// # Errors
///
/// - [`ContentError::DecodingError`] if `bytes` are not dag-cbor at all.
/// - [`ContentError::NonCanonical`] if they decode but are not the canonical
///   encoding.
/// - [`ContentError::EncodingError`] if the decoded value cannot be re-encoded.
pub(crate) fn ensure_canonical(bytes: &[u8]) -> Result<(), ContentError> {
    let value: ipld_core::ipld::Ipld = decode_dagcbor(bytes)?;
    if to_canonical_dagcbor(&value)? != bytes {
        return Err(ContentError::NonCanonical);
    }
    Ok(())
}

/// Decode a value from canonical dag-cbor bytes, **proving the round trip**.
///
/// The verifying sibling of [`from_canonical_dagcbor`], and the door to reach
/// for whenever the bytes did not come from
/// [`to_canonical_dagcbor`] in this process. It
/// establishes what a bare decode does not: that the returned `T` is the value
/// those exact bytes name — so
/// `ContentId::from_canonical_bytes(bytes) == ContentId::from_canonical_bytes(to_canonical_dagcbor(&t)?)`.
///
/// Three stages, in order, each with its own error so diagnostics say *who* is
/// at fault:
///
/// 1. **Canonicality** — the bytes are the canonical
///    encoding of the value they denote. Blames the **bytes**
///    ([`ContentError::NonCanonical`]).
/// 2. **Typed decode** — the bytes decode as a `T`. Blames the **bytes/type
///    pair** ([`ContentError::DecodingError`]).
/// 3. **Forward re-encode** — `to_canonical_dagcbor(&t)` reproduces the input
///    byte-for-byte. Blames the **type** ([`ContentError::LossyDecode`]): it
///    decoded successfully but did not keep everything the bytes carried
///    (an unknown field dropped, an alias, a `#[serde(default)]`, a flattening,
///    a hand-written `Deserialize`).
///
/// Stage 3 is the one no generic check can perform:
/// [`ContentId::from_canonical_bytes_checked`](crate::ContentId::from_canonical_bytes_checked)
/// re-encodes as `Ipld`, which keeps every key, so a *typed* decode dropping a
/// field is invisible to it. Exact byte equality is also strictly stronger than
/// comparing the two [`ContentId`](crate::ContentId)s — it needs no
/// collision-resistance assumption.
///
/// The cost is one generic decode + re-encode plus one typed decode + re-encode
/// per call. Pay it when the byte provenance is not yours; when you produced the
/// bytes yourself, you already know the answer.
///
/// If `T` implements [`ContentAddressable`](crate::ContentAddressable), prefer
/// [`ContentAddressable::from_canonical_form`](crate::ContentAddressable::from_canonical_form),
/// which runs stage 3 through the type's own `canonical_form` — the function
/// that actually defines its identity.
///
/// # Examples
///
/// ```
/// use content_addressable::{canonical, ContentError};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize)]
/// struct Wire { alpha: u64, zeta: u64 }
///
/// #[derive(Serialize, Deserialize, Debug, PartialEq)]
/// struct OnlyAlpha { alpha: u64 }
///
/// let bytes = canonical::to_canonical_dagcbor(&Wire { alpha: 1, zeta: 26 })?;
///
/// // A faithful round trip is accepted.
/// let ok = canonical::to_canonical_dagcbor(&OnlyAlpha { alpha: 1 })?;
/// assert_eq!(
///     canonical::from_canonical_dagcbor_checked::<OnlyAlpha>(&ok)?,
///     OnlyAlpha { alpha: 1 },
/// );
///
/// // Decoding the two-field record into the one-field type would drop `zeta`
/// // and silently change the value's identity, so it is refused.
/// assert!(matches!(
///     canonical::from_canonical_dagcbor_checked::<OnlyAlpha>(&bytes),
///     Err(ContentError::LossyDecode),
/// ));
/// # Ok::<(), ContentError>(())
/// ```
///
/// # Errors
///
/// - [`ContentError::DecodingError`] — the bytes are not dag-cbor, or do not
///   decode as a `T`.
/// - [`ContentError::NonCanonical`] — the bytes are valid CBOR but not the
///   canonical encoding.
/// - [`ContentError::LossyDecode`] — the typed decode dropped information:
///   re-encoding the decoded value differs from the input.
/// - [`ContentError::EncodingError`] — a re-encode failed.
pub fn from_canonical_dagcbor_checked<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, ContentError> {
    // 1. The bytes are canonical — established WITHOUT trusting `T`, so the
    //    verdict does not depend on `T`'s serde impl being well behaved.
    ensure_canonical(bytes)?;
    // 2. They decode as a `T`.
    let value: T = decode_dagcbor(bytes)?;
    // 3. …and `T` kept all of it. Byte inequality here is decisive: the value is
    //    NOT the one these bytes name.
    if to_canonical_dagcbor(&value)? != bytes {
        return Err(ContentError::LossyDecode);
    }
    Ok(value)
}
