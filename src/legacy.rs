//! Explicit **edge adapters** for the legacy identifier dialects still in the
//! wild, so consumers can migrate onto [`RawContentId`] / [`VerifiedCid`]
//! without those dialects ever entering the primary API.
//!
//! **Feature-gated (`unstable-legacy`, default OFF) and NON-FROZEN.** These
//! parsers exist to *end* the dialects, not to bless them: canonical output is
//! always the base32-lower multibase string, and `ContentId::from_str` /
//! `RawContentId::from_str` / `VerifiedCid::from_str` are deliberately never
//! taught these forms (decision record `docs/adr/0003`, question 3). Expect this
//! module to shrink and eventually disappear as consumers finish migrating.
//!
//! What each dialect *is*, at the byte level (verified 2026-08-16):
//!
//! | Dialect | Text | Bytes it denotes | Becomes |
//! |---|---|---|---|
//! | [`kyln`] | hex of the whole CID envelope, e.g. `01551e20…` | a spec CIDv1(raw `0x55`, blake3 `0x1e`, 32) — kyln's hand-rolled encoder emits exactly the standard octets | [`RawContentId`] |
//! | [`nessie`] | `blake3:<64 hex>` or `sha2-256:<64 hex>` | a bare multihash (no CID envelope) | `blake3` → [`VerifiedCid::Raw`]; `sha2-256` → [`VerifiedCid::Foreign`] (CIDv1 raw/sha2-256; verifiable, not mintable) |
//! | [`bare_blake3`] | 64 hex chars, no prefix (`blake3::Hash::to_hex`, agent-mesh `payload_cid`, agent-store `content_hash`) | a raw 32-byte BLAKE3 digest of opaque bytes | [`RawContentId`] |
//!
//! Note what is **not** claimed: parsing an identifier does not migrate the
//! *identity*. A kyln structured value hashed over ciborium CBOR keeps its raw
//! CID here; re-canonicalizing that value to dag-cbor is an identity change to
//! be recorded as an `IdentityMigration` (`unstable-migration`), never treated
//! as equality.

use crate::error::ContentError;
use crate::raw_id::RawContentId;
use crate::verified::VerifiedCid;
use core::fmt;
use core::str::FromStr;
use ipld_core::cid::multihash::Multihash;
use ipld_core::cid::Cid;

/// A legacy-dialect parse failure (the `source` inside
/// [`ContentError::InvalidCid`] for these adapters).
#[derive(Debug)]
struct LegacyParseError(String);

impl fmt::Display for LegacyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LegacyParseError {}

fn invalid(reason: impl Into<String>) -> ContentError {
    let reason = reason.into();
    ContentError::InvalidCid {
        source: Box::new(LegacyParseError(reason.clone())),
        reason,
    }
}

/// Decode exactly 64 lowercase/uppercase hex chars into 32 bytes.
fn decode_hex32(hex: &str) -> Result<[u8; 32], ContentError> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(invalid(format!(
            "expected 64 hex chars for a 32-byte digest, got {}",
            bytes.len()
        )));
    }
    let nibble = |c: u8| -> Result<u8, ContentError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(invalid(format!("non-hex character {:?}", c as char))),
        }
    };
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

/// kyln-core's `ContentId::to_hex()` — hex of the full CID envelope.
pub mod kyln {
    use super::*;

    /// Parse a kyln envelope-hex identifier into a [`RawContentId`].
    ///
    /// The bytes kyln's hand-rolled `Cid` emits (`[0x01, 0x55, 0x1e, 0x20,
    /// digest]`) are exactly a spec CIDv1(raw, blake3-256), so this is a pure
    /// re-parse: hex → multibase base16 (`f` prefix) → `Cid` → profile check.
    /// No re-hash, no identity change.
    ///
    /// # Errors
    ///
    /// [`ContentError::InvalidCid`] if the text is not hex / not a CID;
    /// [`ContentError::InvalidCidProfile`] if it is a CID of some other profile
    /// (kyln also has codes for sha256/sha512 — those are foreign here; use
    /// [`super::nessie`]-style handling via [`VerifiedCid`] if you meet one).
    pub fn parse(envelope_hex: &str) -> Result<RawContentId, ContentError> {
        let cid = Cid::from_str(&format!("f{envelope_hex}"))
            .map_err(|e| invalid(format!("not a hex-encoded CID envelope: {e}")))?;
        RawContentId::try_from(cid)
    }
}

/// nessie-store's `Digest` text form, `"<algo>:<hex>"` with multiformats names.
pub mod nessie {
    use super::*;

    /// Multihash code for `sha2-256` (`0x12`), the REAPI-facing algorithm.
    pub const SHA2_256_HASH_CODE: u64 = 0x12;

    /// Parse a nessie `"<algo>:<hex>"` digest into a [`VerifiedCid`].
    ///
    /// `blake3:<hex>` becomes [`VerifiedCid::Raw`] (a raw-profile identity of
    /// the bytes nessie hashed — byte-identical to
    /// [`RawContentId::from_blake3_digest`]). `sha2-256:<hex>` becomes
    /// [`VerifiedCid::Foreign`] wrapping a CIDv1(raw, sha2-256): this crate can
    /// carry, compare and link it, but will not mint sha2-256 identities.
    /// nessie's own multihash bytes (`to_multihash_bytes`) are the standard
    /// encoding, so this is lossless.
    ///
    /// # Errors
    ///
    /// [`ContentError::InvalidCid`] for an unknown algorithm name, a missing
    /// `:`, or a malformed digest.
    pub fn parse(text: &str) -> Result<VerifiedCid, ContentError> {
        let (algo, hex) = text
            .split_once(':')
            .ok_or_else(|| invalid("expected \"<algo>:<hex>\""))?;
        let digest = decode_hex32(hex)?;
        match algo {
            "blake3" => Ok(VerifiedCid::Raw(RawContentId::from_blake3_digest(digest))),
            "sha2-256" => {
                let mh = Multihash::wrap(SHA2_256_HASH_CODE, &digest)
                    .expect("32-byte digest fits a 64-byte multihash");
                Ok(VerifiedCid::from_cid(Cid::new_v1(
                    crate::raw_id::RAW_CODEC,
                    mh,
                )))
            }
            other => Err(invalid(format!(
                "unknown digest algorithm {other:?} (expected \"blake3\" or \"sha2-256\")"
            ))),
        }
    }
}

/// A bare 32-byte BLAKE3 digest of opaque bytes, as 64 hex chars — the form
/// `blake3::Hash::to_hex` emits and that agent-mesh-protocol's `payload_cid`,
/// agent-store's `content_hash`, and this crate's own `digest_hex()` use.
pub mod bare_blake3 {
    use super::*;

    /// Parse a bare BLAKE3 digest hex into a [`RawContentId`] (no re-hash).
    ///
    /// The raw profile is the honest wrapper for a digest of opaque bytes. If
    /// the digest is known to be over canonical dag-cbor, the caller should say
    /// so with `ContentId::from_dag_cbor_digest` instead — this adapter never
    /// guesses.
    ///
    /// # Errors
    ///
    /// [`ContentError::InvalidCid`] if the text is not exactly 64 hex chars.
    pub fn parse(digest_hex: &str) -> Result<RawContentId, ContentError> {
        Ok(RawContentId::from_blake3_digest(decode_hex32(digest_hex)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> [u8; 32] {
        *blake3::hash(b"legacy").as_bytes()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn kyln_envelope_hex_is_a_raw_content_id_byte_for_byte() {
        let expected = RawContentId::from_blake3_digest(digest());
        // Exactly what kyln-core's Cid::to_bytes() emits, hex-encoded.
        let mut env = vec![0x01, 0x55, 0x1e, 0x20];
        env.extend_from_slice(&digest());
        let parsed = kyln::parse(&hex(&env)).unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(parsed.to_bytes(), env);
        // Uppercase hex is fine too (multibase base16 is case-insensitive here).
        assert_eq!(kyln::parse(&hex(&env).to_uppercase()).unwrap(), expected);
    }

    #[test]
    fn kyln_rejects_non_raw_and_garbage() {
        let dag = crate::ContentId::from_dag_cbor_digest(digest());
        assert!(matches!(
            kyln::parse(&hex(&dag.to_bytes())),
            Err(ContentError::InvalidCidProfile { .. })
        ));
        assert!(matches!(
            kyln::parse("zz"),
            Err(ContentError::InvalidCid { .. })
        ));
    }

    #[test]
    fn nessie_blake3_is_raw_and_sha256_is_foreign() {
        let d = digest();
        let raw = nessie::parse(&format!("blake3:{}", hex(&d))).unwrap();
        assert_eq!(raw, VerifiedCid::Raw(RawContentId::from_blake3_digest(d)));
        let sha = nessie::parse(&format!("sha2-256:{}", hex(&d))).unwrap();
        assert!(matches!(sha, VerifiedCid::Foreign(_)));
        assert!(!sha.is_mintable());
        assert_eq!(sha.hash_code(), 0x12);
        assert_eq!(sha.codec(), 0x55);
        // nessie's multihash bytes are the standard encoding: <0x12><0x20><digest>.
        let mut mh = vec![0x12, 0x20];
        mh.extend_from_slice(&d);
        assert_eq!(sha.as_cid().hash().to_bytes(), mh);
        // Law 6 across the boundary: same digest, three identities.
        assert_ne!(raw, sha);
    }

    #[test]
    fn nessie_rejects_unknown_algo_and_bad_hex() {
        assert!(nessie::parse("md5:00").is_err());
        assert!(nessie::parse("blake3").is_err());
        assert!(nessie::parse(&format!("blake3:{}", "0".repeat(63))).is_err());
        assert!(nessie::parse(&format!("blake3:{}", "g".repeat(64))).is_err());
    }

    #[test]
    fn bare_blake3_hex_roundtrips_with_digest_hex() {
        let id = RawContentId::from_content(b"bare");
        assert_eq!(bare_blake3::parse(&id.digest_hex()).unwrap(), id);
        assert!(bare_blake3::parse("abc").is_err());
    }
}
