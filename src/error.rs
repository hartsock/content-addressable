//! Typed errors for content-addressing operations.
//!
//! Every fallible operation in this crate returns [`ContentError`]. We use
//! [`thiserror`] (not `anyhow`) so callers can match on the exact failure mode
//! — encoding, decoding, verification, non-canonical input, or CID parsing —
//! and so the error type stays part of the crate's public contract.
//!
//! # Operation → variant map (FROZEN at 0.1.0)
//!
//! This table is the legible contract: which operation can produce which
//! variant. It is part of the frozen `0.1.0` error surface (README gate item
//! #7) — adding a *new* operation/variant pair later is allowed (the enum is
//! `#[non_exhaustive]`), but the rows below will not change meaning.
//!
//! | Operation | Variant(s) it can return |
//! |-----------|--------------------------|
//! | [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor) | [`EncodingError`](ContentError::EncodingError) |
//! | [`from_canonical_dagcbor`](crate::canonical::from_canonical_dagcbor) | [`DecodingError`](ContentError::DecodingError) |
//! | [`ContentId::from_canonical_bytes_checked`](crate::ContentId::from_canonical_bytes_checked) | [`DecodingError`](ContentError::DecodingError) (not dag-cbor), [`NonCanonical`](ContentError::NonCanonical) (valid but non-canonical), [`EncodingError`](ContentError::EncodingError) (re-encode failed) |
//! | [`ContentId::from_bytes`](crate::ContentId::from_bytes) / [`FromStr`](core::str::FromStr) | [`InvalidCid`](ContentError::InvalidCid) |
//! | [`content_id`](crate::ContentAddressable::content_id) | propagates `canonical_form`'s error only (typically [`EncodingError`](ContentError::EncodingError)) |
//! | [`verify`](crate::ContentAddressable::verify) | propagates [`content_id`](crate::ContentAddressable::content_id) only; a *mismatch* is `Ok(false)`, never an `Err` |
//! | [`ensure_content_id`](crate::ContentAddressable::ensure_content_id) | propagates [`content_id`](crate::ContentAddressable::content_id), plus [`VerificationFailed`](ContentError::VerificationFailed) on mismatch |
//! | [`from_canonical_bytes`](crate::ContentId::from_canonical_bytes) / [`from_blake3_content_digest`](crate::ContentId::from_blake3_content_digest) | infallible — never returns an error |
//!
//! # Frozen freeze decisions (0.1.0)
//!
//! - **`#[non_exhaustive]` is retained on purpose** so a future variant (e.g. an
//!   `UnsupportedCodec` / `DigestLength`) can be *added* without a major version
//!   bump. Callers already must carry a `_ => …` arm. Do **not** remove it to
//!   chase exhaustive matching — that would forfeit additive evolution.
//! - **No `#[from]` impls.** Auto-`From` conversions are deliberately *not*
//!   provided: a `#[from]` bakes the source type into the public contract just as
//!   firmly as a field, and the two codec sources are exactly the unstable
//!   `serde_ipld_dagcbor` generics we hide behind a boxed `dyn Error` (see
//!   below). Construction stays explicit via `map_err` at the call sites. Do not
//!   "helpfully" add a `#[from]` — it re-leaks the generics into the frozen API.
//! - **The codec source types are boxed.** `EncodingError`/`DecodingError` carry
//!   their `#[source]` as a `Box<dyn std::error::Error + Send + Sync + 'static>`
//!   rather than the concrete `serde_ipld_dagcbor::EncodeError<…>` /
//!   `DecodeError<…>`. This keeps `.source()`/`{source}` diagnostics while
//!   decoupling the frozen signature from a codec-crate patch bump that changes
//!   those generics.

use thiserror::Error;

/// The error type returned by all fallible operations in this crate.
///
/// Variants are intentionally coarse: they describe *which stage* failed
/// (serialize, deserialize, verify, non-canonical, parse) rather than mirroring
/// every underlying library error one-to-one. Where a lower-level error is
/// available it is preserved in the `source` field for diagnostics.
///
/// # Stability (FROZEN at 0.1.0)
///
/// This enum is `#[non_exhaustive]` as a **frozen decision**: it lets a new
/// variant be *added* in a future `0.1.x` release without a major version bump,
/// while the four (now five) names and their fields below are a stability
/// contract. See the [module docs](self) for the full freeze rationale (no
/// `#[from]`, boxed codec sources, the operation→variant map) and a compile-time
/// `Send + Sync + 'static` guard locking `ContentError`'s thread-portability.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ContentError {
    /// Canonical dag-cbor encoding of a value failed.
    ///
    /// Returned by
    /// [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor) (and so
    /// propagated by [`content_id`](crate::ContentAddressable::content_id) /
    /// [`verify`](crate::ContentAddressable::verify) via `canonical_form`). The
    /// `source` is boxed as a `dyn Error` so the concrete
    /// `serde_ipld_dagcbor::EncodeError<…>` generic does not leak into this
    /// frozen signature.
    #[error("failed to encode value as canonical dag-cbor: {source}")]
    EncodingError {
        /// The underlying codec error, type-erased.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Decoding canonical dag-cbor bytes back into a value failed.
    ///
    /// Returned by
    /// [`from_canonical_dagcbor`](crate::canonical::from_canonical_dagcbor) and
    /// by [`from_canonical_bytes_checked`](crate::ContentId::from_canonical_bytes_checked)
    /// when the input bytes are not dag-cbor at all. The `source` is boxed as a
    /// `dyn Error` so the concrete `serde_ipld_dagcbor::DecodeError<…>` generic
    /// does not leak into this frozen signature.
    #[error("failed to decode value from canonical dag-cbor: {source}")]
    DecodingError {
        /// The underlying codec error, type-erased.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// A [`crate::ContentId`] did not match the expected one.
    ///
    /// This is the heart of the doctrine: the data did not carry the proof it
    /// claimed to. The recomputed identity differs from the expected identity.
    ///
    /// # Frozen `verify` ruling (0.1.0)
    ///
    /// [`verify`](crate::ContentAddressable::verify) returns `Ok(false)` on a
    /// mismatch — a mismatch is **not** an `Err` (a negative answer to "do these
    /// match?" is a successful, expected result, not a failure to check). This
    /// is a **frozen** part of the `0.1.0` API surface (README gate item #8).
    /// This variant is the *escalation* of that boolean: it is constructed by
    /// [`ensure_content_id`](crate::ContentAddressable::ensure_content_id), the
    /// strict helper that turns a mismatch into an `Err` for `?`-propagation.
    /// Its `expected` / `computed` fields are the two ids' [`Display`] strings
    /// (multibase base32-lower `b…`).
    ///
    /// [`Display`]: core::fmt::Display
    #[error("content verification failed: expected {expected}, computed {computed}")]
    VerificationFailed {
        /// The identity the caller expected, as a [`ContentId`](crate::ContentId)
        /// [`Display`](core::fmt::Display) string.
        expected: String,
        /// The identity actually computed from the bytes, as a
        /// [`ContentId`](crate::ContentId) [`Display`](core::fmt::Display) string.
        computed: String,
    },

    /// Bytes presented as canonical dag-cbor were valid CBOR but **not
    /// canonical** dag-cbor.
    ///
    /// Returned only by the opt-in
    /// [`from_canonical_bytes_checked`](crate::ContentId::from_canonical_bytes_checked)
    /// when the input decodes as an [`Ipld`](ipld_core::ipld::Ipld) value but
    /// re-encoding it does **not** reproduce the input bytes (wrong map-key
    /// order, indefinite-length items, non-smallest integers, …). The fast
    /// [`from_canonical_bytes`](crate::ContentId::from_canonical_bytes) primitive
    /// never produces this — it trusts its precondition and only hashes.
    #[error(
        "bytes are valid CBOR but not canonical dag-cbor (re-encoding differs from the input)"
    )]
    NonCanonical,

    /// A CID could not be parsed from a string or from bytes.
    ///
    /// Returned by [`ContentId::from_bytes`](crate::ContentId::from_bytes) and
    /// the [`FromStr`](core::str::FromStr) impl. `reason` is a stable
    /// human-readable string; the underlying `cid::Error` is preserved in
    /// `source` so the error chain (`.source()`) is not stripped at this
    /// boundary.
    #[error("invalid CID: {reason}")]
    InvalidCid {
        /// Human-readable description of why the CID is invalid.
        reason: String,
        /// The underlying CID parse error, preserved for `.source()` chaining.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

#[cfg(test)]
mod tests {
    use super::ContentError;

    /// Compile-time lock: `ContentError` is `Send + Sync + 'static`, so it stays
    /// thread-portable across the freeze (README gate item #7). If a future field
    /// (e.g. a non-`Send` source) broke this, the crate would fail to compile
    /// here rather than silently narrowing the public contract.
    #[test]
    fn content_error_is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<ContentError>();
    }

    /// Regression guard against future source-stripping (README gate item #7):
    /// `EncodingError`, `DecodingError`, and `InvalidCid` must each carry a live
    /// `#[source]`, so `std::error::Error::source` returns `Some(_)` and the
    /// error chain is walkable. `VerificationFailed` / `NonCanonical` carry no
    /// source by design.
    #[test]
    fn source_chain_is_preserved_for_sourced_variants() {
        use std::error::Error as _;

        // A genuine decode error (empty input is not a complete dag-cbor item).
        let decode_err = crate::canonical::from_canonical_dagcbor::<u64>(&[])
            .expect_err("empty input must fail to decode");
        assert!(
            matches!(decode_err, ContentError::DecodingError { .. }),
            "empty bytes must decode-fail"
        );
        assert!(
            decode_err.source().is_some(),
            "DecodingError must preserve its underlying codec source"
        );

        // A genuine encode error: dag-cbor forbids non-finite floats, so NaN
        // fails to encode.
        let encode_err = crate::canonical::to_canonical_dagcbor(&f64::NAN)
            .expect_err("dag-cbor must reject NaN");
        assert!(
            matches!(encode_err, ContentError::EncodingError { .. }),
            "NaN must encode-fail"
        );
        assert!(
            encode_err.source().is_some(),
            "EncodingError must preserve its underlying codec source"
        );

        // A genuine CID parse error keeps the underlying cid::Error as a source.
        let cid_err = crate::ContentId::from_bytes(&[0xff, 0xff, 0xff])
            .expect_err("garbage must not parse as a CID");
        assert!(
            matches!(cid_err, ContentError::InvalidCid { .. }),
            "garbage must CID-parse-fail"
        );
        assert!(
            cid_err.source().is_some(),
            "InvalidCid must preserve the underlying cid::Error as a source"
        );
    }
}
