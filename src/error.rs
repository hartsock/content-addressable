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
//! Rows added since the freeze (the additive path this note reserves):
//! [`from_canonical_dagcbor_checked`](crate::canonical::from_canonical_dagcbor_checked)
//! and
//! [`ContentAddressable::from_canonical_form`](crate::ContentAddressable::from_canonical_form)
//! in `0.1.2` (issue #90), which is also what introduced
//! [`LossyDecode`](ContentError::LossyDecode) — the first exercise of the
//! `#[non_exhaustive]` decision below, and exactly the case it was kept for.
//! ([`from_canonical_form`](crate::ContentAddressable::from_canonical_form) is additionally the one deliberate stability exception
//! `0.1.2` makes to the frozen `0.1.x` Rust API; see `docs/STABILITY.md`. The
//! error surface itself is unchanged apart from the added variant.)
//!
//! | Operation | Variant(s) it can return |
//! |-----------|--------------------------|
//! | [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor) | [`EncodingError`](ContentError::EncodingError) |
//! | [`from_canonical_dagcbor`](crate::canonical::from_canonical_dagcbor) (**deprecated** `0.1.2`) | [`DecodingError`](ContentError::DecodingError) — and nothing else, which is the defect that deprecated it: it verifies neither canonicality nor the typed round trip |
//! | [`from_canonical_dagcbor_checked`](crate::canonical::from_canonical_dagcbor_checked) | [`DecodingError`](ContentError::DecodingError) (not dag-cbor, or not a `T`), [`NonCanonical`](ContentError::NonCanonical) (valid but non-canonical bytes), [`LossyDecode`](ContentError::LossyDecode) (the decoded value's [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor) differs from the input), [`EncodingError`](ContentError::EncodingError) (a re-encode failed) |
//! | [`ContentAddressable::from_canonical_form`](crate::ContentAddressable::from_canonical_form) | the same four, with the last two arising from [`canonical_form`](crate::ContentAddressable::canonical_form) rather than from [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor) — plus anything else a custom [`canonical_form`](crate::ContentAddressable::canonical_form) returns, propagated verbatim |
//! | [`ContentId::from_canonical_bytes_checked`](crate::ContentId::from_canonical_bytes_checked) | [`DecodingError`](ContentError::DecodingError) (not dag-cbor), [`NonCanonical`](ContentError::NonCanonical) (valid but non-canonical), [`EncodingError`](ContentError::EncodingError) (re-encode failed) |
//! | [`ContentId::from_bytes`](crate::ContentId::from_bytes) / [`FromStr`](core::str::FromStr) / [`TryFrom<Cid>`](crate::ContentId) / binary `Deserialize` | [`InvalidCid`](ContentError::InvalidCid) (not a CID at all) or [`InvalidCidProfile`](ContentError::InvalidCidProfile) (a valid CID that is not the frozen profile) |
//! | [`content_id`](crate::ContentAddressable::content_id) | propagates [`canonical_form`](crate::ContentAddressable::canonical_form)'s error only (typically [`EncodingError`](ContentError::EncodingError)) |
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
/// while the **seven** names and their fields below are a stability contract.
/// (Six were frozen at `0.1.0`; [`LossyDecode`](ContentError::LossyDecode) was
/// added in `0.1.2` through exactly that additive path.) See the [module docs](self) for the full freeze rationale (no
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
    /// [`verify`](crate::ContentAddressable::verify) via [`canonical_form`](crate::ContentAddressable::canonical_form)). The
    /// `source` is boxed as a `dyn Error` so the concrete
    /// `serde_ipld_dagcbor::EncodeError<…>` generic does not leak into this
    /// frozen signature.
    #[error("failed to encode value as canonical dag-cbor: {source}")]
    EncodingError {
        /// The underlying codec error, type-erased.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Decoding dag-cbor bytes back into a value failed.
    ///
    /// Returned by **every** decode path in the crate, checked or not:
    /// [`from_canonical_dagcbor`](crate::canonical::from_canonical_dagcbor) (the
    /// deprecated unchecked door),
    /// [`from_canonical_dagcbor_checked`](crate::canonical::from_canonical_dagcbor_checked),
    /// [`ContentAddressable::from_canonical_form`](crate::ContentAddressable::from_canonical_form),
    /// and [`from_canonical_bytes_checked`](crate::ContentId::from_canonical_bytes_checked).
    ///
    /// It covers two distinct situations, and the checked doors reach both: the
    /// bytes are not dag-cbor at all, or they are dag-cbor but do not decode as
    /// the target type. For a type whose [`canonical_form`](crate::ContentAddressable::canonical_form) is deliberately not its
    /// serde representation, the second is the *expected* answer for its own
    /// canonical bytes — see
    /// [`from_canonical_form`](crate::ContentAddressable::from_canonical_form).
    ///
    /// The `source` is boxed as a `dyn Error` so the concrete
    /// `serde_ipld_dagcbor::DecodeError<…>` generic does not leak into this
    /// frozen signature.
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
    /// # Frozen [`verify`](crate::ContentAddressable::verify) ruling (0.1.0)
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
    /// Returned by every door that verifies canonicality, all of which run one
    /// shared generic gate:
    /// [`from_canonical_bytes_checked`](crate::ContentId::from_canonical_bytes_checked),
    /// [`from_canonical_dagcbor_checked`](crate::canonical::from_canonical_dagcbor_checked),
    /// and
    /// [`ContentAddressable::from_canonical_form`](crate::ContentAddressable::from_canonical_form)
    /// — plus the `unstable-store` seam's strict ingest and identity-preserving
    /// read, which are those doors under other names.
    ///
    /// It means the input decoded as an [`Ipld`](ipld_core::ipld::Ipld) value but
    /// re-encoding it did **not** reproduce the input bytes (wrong map-key order,
    /// indefinite-length items, non-smallest integers, …). No target type is
    /// involved: the verdict is about the bytes alone, which is why it is
    /// established *before* any type is constructed. The fast
    /// [`from_canonical_bytes`](crate::ContentId::from_canonical_bytes) primitive
    /// never produces this — it trusts its precondition and only hashes.
    #[error(
        "bytes are valid CBOR but not canonical dag-cbor (re-encoding differs from the input)"
    )]
    NonCanonical,

    /// A **typed round-trip mismatch**: the value decoded, but re-encoding it
    /// does not reproduce the input bytes.
    ///
    /// Returned at the third stage of both checked doors —
    /// [`from_canonical_dagcbor_checked`](crate::canonical::from_canonical_dagcbor_checked)
    /// (re-encoding with
    /// [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor)) and
    /// [`ContentAddressable::from_canonical_form`](crate::ContentAddressable::from_canonical_form)
    /// (re-encoding with the type's own [`canonical_form`](crate::ContentAddressable::canonical_form)). The bytes were already
    /// proven canonical, so they are *not* at fault: the mismatch is between the
    /// input and **the target type's canonical representation of what it decoded**.
    ///
    /// Information loss is the usual cause and the one that motivated the
    /// variant: `serde` ignores unknown map keys by default, so a record carrying
    /// a field the type does not name decodes cleanly with the field gone, and
    /// for a protocol record that field may have been a required demand.
    /// `#[serde(default)]` and aliases land in the same place. It is **not the
    /// only cause**, though, and a `LossyDecode` is not by itself proof that a
    /// field was dropped: a type whose [`canonical_form`](crate::ContentAddressable::canonical_form) intentionally differs
    /// from its serde representation can decode faithfully and still re-encode to
    /// different bytes. Either way the conclusion the caller needs is the same —
    /// *these bytes are not the canonical form of this value* — which is why one
    /// variant covers both, and why the display message speaks of the mismatch
    /// rather than naming a missing field.
    ///
    /// Distinct from [`NonCanonical`](ContentError::NonCanonical) on purpose:
    /// `NonCanonical` blames the bytes (re-encode them), `LossyDecode` blames the
    /// bytes/type *pairing* (widen the type, name every field, or give the custom
    /// canonical form the custom decoder it needs). Like `NonCanonical` it is a
    /// policy rejection and carries no underlying `source` — nothing failed
    /// underneath; the comparison simply came out unequal.
    ///
    /// Two things it is **not**. It is not what a user's own [`canonical_form`](crate::ContentAddressable::canonical_form)
    /// returning an error produces — that error propagates verbatim, whatever it
    /// is. And under the `unstable-store` seam it is not what a mismatched typed
    /// read reports: `NodeStoreExt::get_node` returns its own
    /// `StoreError::RepresentationMismatch`, which names the id that lied, so a
    /// `LossyDecode` surfacing from that seam came from the user's encoder.
    ///
    /// Added in `0.1.2` (issue #90) under the enum's `#[non_exhaustive]`
    /// contract.
    #[error(
        "the typed decode dropped information: re-encoding the decoded value differs from the input"
    )]
    LossyDecode,

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

    /// A syntactically-valid CID was parsed, but it is **not** this crate's frozen
    /// profile: CIDv1 + dag-cbor (`0x71`) + BLAKE3 (`0x1e`) + a 32-byte digest.
    ///
    /// Every ingress path — [`from_bytes`](crate::ContentId::from_bytes), the
    /// [`FromStr`](core::str::FromStr) impl, [`TryFrom<Cid>`](crate::ContentId), and
    /// the binary/IPLD `Deserialize` — rejects a foreign CID with this, so *every*
    /// `ContentId` (however it entered) carries the fixed profile the presentation
    /// accessors ([`digest_bytes`](crate::ContentId::digest_bytes) etc.) rely on.
    /// A policy rejection, so — like [`NonCanonical`](ContentError::NonCanonical) —
    /// it carries no underlying `source`; `reason` names the parameter that was off.
    #[error("CID is not the content-addressable profile: {reason}")]
    InvalidCidProfile {
        /// Which profile parameter was wrong (version / codec / hash / digest length).
        reason: String,
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
    /// error chain is walkable. `VerificationFailed` / `NonCanonical` /
    /// `LossyDecode` / `InvalidCidProfile` carry no source by design — they are
    /// policy rejections, with nothing underneath that failed.
    #[test]
    fn source_chain_is_preserved_for_sourced_variants() {
        use std::error::Error as _;

        // A genuine decode error (empty input is not a complete dag-cbor item).
        let decode_err = crate::canonical::from_canonical_dagcbor_checked::<u64>(&[])
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
