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
    serde_ipld_dagcbor::to_vec(value).map_err(|source| ContentError::EncodingError { source })
}

/// Decode a value from canonical dag-cbor bytes.
///
/// # Errors
///
/// Returns [`ContentError::DecodingError`] if the bytes are not valid canonical
/// dag-cbor for the target type.
pub fn from_canonical_dagcbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ContentError> {
    serde_ipld_dagcbor::from_slice(bytes).map_err(|source| ContentError::DecodingError { source })
}
