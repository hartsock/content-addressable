# Identity and decoding

[Back to the README](../README.md)

## Identity profiles

The crate uses the multiformats / IPLD stack and mints two profiles:

| Type | CID | Codec | Multihash | Digest | Names |
|------|-----|-------|-----------|--------|-------|
| `ContentId` | v1 | DAG-CBOR (`0x71`) | BLAKE3 (`0x1e`) | 32 bytes | a canonical structured **value** (encoding: canonical DAG-CBOR — strict key order, definite lengths, tag-42 links) |
| `RawContentId` | v1 | raw (`0x55`) | BLAKE3 (`0x1e`) | 32 bytes | an opaque **byte string** — a file, a chunk, a binary, a payload |

The codec, multihash, and digest together identify content. `ContentId` and
`RawContentId` remain distinct even when their digests match, and each parser
rejects the other's profile.

`ClassifiedCid { Content | Raw | Foreign(ForeignCid) }` carries any well-formed
CID, including CIDv0 and foreign hash algorithms, without minting foreign
profiles. Each CID has exactly one representation: `ForeignCid` rejects the
recognized profiles, and `Deserialize` derives the variant from the bytes.
Classification establishes structure and profile membership only. It does not
verify that content matches the digest. See the
[identity decision record](adr/0003-identity-profiles-and-classified-cids.md).

## Choosing a construction path

Use `content_id` for values. `from_canonical_bytes` requires the caller to
establish canonicality first.

| Use case | API (Rust / Python) | Contract |
|----------|---------------------|----------|
| Hash a normal value | `value.content_id()` / `content_id(value)` | **Preferred safe path** |
| Encode a value to bytes | `canonical::to_canonical_dagcbor(v)` / `to_canonical_dagcbor(v)` | Produces canonical DAG-CBOR |
| Accept foreign / untrusted bytes (id only) | Rust: `ContentId::from_canonical_bytes_checked(b)` · Python: `from_canonical_dagcbor_checked(b)` to validate, then `ContentId.from_canonical_bytes(b)` | Validates DAG-CBOR canonicality; errors on non-canonical. Python still has no single checked *constructor*: validate the bytes, then mint from the same bytes — do **not** re-derive the id from the decoded value, which fails for link-bearing documents (see below) |
| Hash already-trusted canonical bytes | `ContentId::from_canonical_bytes(b)` | **Unchecked** precondition: caller asserts `b` is canonical DAG-CBOR |
| Identify opaque bytes (a file, chunk, binary, payload) | `RawContentId::from_content(b)` / `RawContentId.from_content(b)` | Hashes the bytes; nothing to get wrong — the bytes *are* the content |
| Wrap an existing BLAKE3 digest **of opaque bytes** | `RawContentId::from_blake3_digest(d)` / `RawContentId.from_blake3_digest(d)` | No rehash; the honest home of the no-rehash bridge (byte-identical to kyln raw CIDs / bare `blake3` digests) |
| Wrap an existing BLAKE3 digest **known to be over canonical DAG-CBOR** | `ContentId::from_dag_cbor_digest(d)` / `ContentId.from_dag_cbor_digest(d)` | No rehash; the name asserts the precondition. `from_blake3_content_digest` is **deprecated** in its favor ([#84]): it stamped DAG-CBOR on a digest it could not know came from DAG-CBOR |
| Hold a CID you did not mint (REAPI `sha2-256`, CIDv0, …) | `ClassifiedCid::from_str` / `ClassifiedCid::from_bytes` / `ClassifiedCid::from_cid` | Classifies as `Content` / `Raw` / `Foreign`; foreign ids are carried and compared, never minted |

## Decoding foreign bytes

A plain `serde` decode can produce a value that re-encodes to different bytes
and therefore has a different content address. Two checks prevent this:

1. Check canonicality. Reordered map keys, non-minimal integers, and indefinite
   lengths can represent valid CBOR without being canonical DAG-CBOR.
2. Check the typed round trip. `serde` ignores unknown fields, so decoding into
   a type that lacks a field can silently discard it.

`from_canonical_bytes_checked` checks canonicality through generic IPLD, which
retains every key. Only a typed round trip can catch fields the type discards.

| Use case | API (Rust / Python) | Contract |
|----------|---------------------|----------|
| Decode foreign bytes into a `ContentAddressable` type | `T::from_canonical_form(b)` / — | Canonical bytes **and** `canonical_form` reproduces them: the value is provably the one `b` names |
| Decode foreign bytes into any `Serialize + Deserialize` type | `canonical::from_canonical_dagcbor_checked::<T>(b)` / `from_canonical_dagcbor_checked(b)` | Canonical bytes **and** `to_canonical_dagcbor` on the decoded value reproduces them |
| Decode bytes you just encoded yourself | `canonical::from_canonical_dagcbor(b)` / `from_canonical_dagcbor(b)` | **Deprecated (Rust, 0.1.2)** — verifies neither of the above |

`ContentError::NonCanonical` identifies non-canonical bytes.
`ContentError::LossyDecode` identifies a bytes/type pairing that cannot reproduce
its input. This includes dropped fields and types whose canonical form differs
intentionally from their serde representation. Python decodes into `dict`/`list`
and retains every key, so only the canonicality error applies ([#90]).

### Python tag-42 links

Python decodes tag-42 links into `ContentId` objects, but its encoder rejects
those objects with `TypeError`. A link-bearing document can pass the canonicality
check without its decoded value being re-encodable. Validate the input with
`from_canonical_dagcbor_checked`, then compute its id with
`ContentId.from_canonical_bytes` on the same bytes. Do not derive the id from
the decoded value. The Python tests pin this limitation; Rust supports the
round trip.

## Presentation forms

`ContentId` and `RawContentId` share these accessor names. The forms are frozen
for `ContentId` throughout `0.1.x` and fixed by the CID specification for
`RawContentId`:

| Form | Rust | Python | What it is |
|------|------|--------|------------|
| **Canonical text** | `Display` / `to_string()` | `str(id)` | multibase **base32-lower** (`b…`) — the IPLD-canonical CID string |
| **Binary envelope** | `to_bytes()` / `from_bytes()` | `to_bytes()` / `from_bytes()` | the full **CID binary** form (version + codec + multihash + digest) |
| **Bare digest** | `digest_bytes() -> [u8; 32]` | `digest_bytes() -> bytes` | the raw **32-byte BLAKE3** hash, no envelope |
| **Bare-digest-hex** | `digest_hex() -> String` | `digest_hex() -> str` | lower-hex of the 32-byte digest (64 chars, no prefix) |

`Display` and `FromStr` round-trip base32-lower text. To hex-encode the full
binary envelope, use `hex::encode(id.to_bytes())`; the crate has no second hex
accessor. See the [stability contract](STABILITY.md).

Emit base32-lower CID text and compare typed CID bytes. Never compare
`digest_hex()` across profiles or use text as identity. Legacy formats enter
through the explicit [legacy adapters](EXPERIMENTAL.md#unstable-legacy);
`from_str` accepts no legacy dialects.

[#84]: https://github.com/hartsock/content-addressable/issues/84
[#90]: https://github.com/hartsock/content-addressable/issues/90

---

Editorial refactor:

Model: not exposed by harness | Harness: Codex | Operator: Shawn Hartsock | Time: 16:56 EDT | Date: 2026-09-19
