//! Typed errors for content-addressing operations.
//!
//! Every fallible operation in this crate returns [`ContentError`]. We use
//! [`thiserror`] (not `anyhow`) so callers can match on the exact failure mode
//! — encoding, decoding, verification, or CID parsing — and so the error type
//! stays part of the crate's public contract.

use thiserror::Error;

/// The error type returned by all fallible operations in this crate.
///
/// Variants are intentionally coarse: they describe *which stage* failed
/// (serialize, deserialize, verify, parse) rather than mirroring every
/// underlying library error one-to-one. Where a lower-level error is available
/// it is preserved in the `source` field for diagnostics.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ContentError {
    /// Canonical dag-cbor encoding of a value failed.
    #[error("failed to encode value as canonical dag-cbor: {source}")]
    EncodingError {
        /// The underlying codec error.
        #[source]
        source: serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>,
    },

    /// Decoding canonical dag-cbor bytes back into a value failed.
    #[error("failed to decode value from canonical dag-cbor: {source}")]
    DecodingError {
        /// The underlying codec error.
        #[source]
        source: serde_ipld_dagcbor::DecodeError<std::convert::Infallible>,
    },

    /// A [`crate::ContentId`] did not match the expected one during
    /// [`crate::ContentAddressable::verify`].
    ///
    /// This is the heart of the doctrine: the data did not carry the proof it
    /// claimed to. The recomputed identity differs from the expected identity.
    #[error("content verification failed: expected {expected}, computed {computed}")]
    VerificationFailed {
        /// The identity the caller expected.
        expected: String,
        /// The identity actually computed from the bytes.
        computed: String,
    },

    /// A CID could not be parsed from a string or from bytes.
    #[error("invalid CID: {reason}")]
    InvalidCid {
        /// Human-readable description of why the CID is invalid.
        reason: String,
    },
}
