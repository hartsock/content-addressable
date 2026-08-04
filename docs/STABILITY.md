# Stability contracts

What is **frozen** for the `0.1.x` line, and what is not. A frozen contract is a
stability guarantee: changing any of these is a **major version bump**. The
package is `0.1.0-alpha.1` — alpha *as a package* — but the contracts below are
already locked, so downstream systems can persist and link against them today.

Issue links (`#N`) provide provenance; the contract itself is stated so you do
not need to open every issue to depend on it.

## What is frozen (`0.1.x`)

### CID profile — the byte contract ([#3], [#4])

Every id is a **CIDv1** with a fixed shape, built as
`BLAKE3(bytes)` → `Multihash::wrap(0x1e, digest)` → `Cid::new_v1(0x71, mh)`:

| Field | Value | Frozen |
|-------|-------|:------:|
| CID version | v1 only | ✓ |
| Codec | DAG-CBOR, `0x71` | ✓ |
| Hash | BLAKE3, multihash `0x1e` | ✓ |
| Digest length | 32 bytes | ✓ |

The hash and codec are **fixed, not selectable** for `0.1.x`. The **serde
representation** of `ContentId` is frozen: a DAG-CBOR **tag-42 link** (binary
form) via the inner `Cid`'s serde, pinned by a full-byte golden test in
`tests/vectors.json` and asserted in both the Rust and Python gates.

### Canonical encoding

Canonical DAG-CBOR *is* the canonical form: strict map-key ordering,
definite-length arrays/maps, and tag-42 links are enforced by the codec, so
determinism is a property of the encoder, not of caller discipline. Equal values
produce equal bytes produce equal ids.

### Construction: checked vs unchecked ([#5])

`from_canonical_bytes` is the fast, **unchecked** minting primitive: it hashes
the bytes it is handed and carries a normative *precondition* that they are
canonical DAG-CBOR. Passing non-canonical bytes mints a misleading id — a logic
error, unenforced by design. The safe defaults are `content_id` /
`to_canonical_dagcbor` (which produce canonical bytes for you).

`from_canonical_bytes_checked` re-encode-validates foreign / untrusted bytes and
returns the typed `ContentError::NonCanonical` (or `DecodingError` for non-DAG-CBOR).

The pairing is frozen as `from_canonical_bytes` / `from_canonical_bytes_checked`
— the unchecked door is **not** renamed to `_unchecked`.

### Presentation contract ([#6])

A `ContentId` names four distinct presentation forms, each frozen:

| Form | Rust | Python | What it is |
|------|------|--------|------------|
| Canonical text | `Display` / `to_string()` | `str(id)` | multibase base32-lower (`b…`), the IPLD-canonical CID string |
| Binary envelope | `to_bytes()` / `from_bytes()` | `to_bytes()` / `from_bytes()` | the full CID binary form |
| Bare digest | `digest_bytes() -> [u8; 32]` | `digest_bytes() -> bytes` | the raw 32-byte BLAKE3 hash |
| Bare-digest-hex | `digest_hex() -> String` | `digest_hex() -> str` | 64-char lower-hex of the digest, no prefix |

`Display` is the inverse of `FromStr` for base32-lower; that round-trip is frozen
and tested. `FromStr`'s tolerance of *other* multibases is a documented
convenience, not a contract. Every conformance vector's `digest_hex()` is pinned
in `tests/vectors.json` and asserted in both languages, so the accessor's bytes
cannot drift across Rust and Python.

**Why there is no full-CID hex method.** Three mutually-incompatible "hex"
conventions exist for a CID in the wild:

1. **bare-digest-hex** — hex of the raw 32-byte digest; this is `digest_hex()`.
2. **full-CID-bytes-hex** — hex of `to_bytes()` (the whole envelope). Deliberately
   **not** a method: a caller who needs it writes `hex::encode(id.to_bytes())` and
   owns that choice. Blessing a `cid_hex()` would add a third "hex" that invites
   the exact confusion this contract exists to end. It can be added later
   additively without breaking anything.
3. **multibase base32-lower** — the `Display` string; the canonical text form.

### Error policy ([#7])

`ContentError` is `#[non_exhaustive]`, so variants may be **added** additively
without a major bump. The codec source types are hidden behind
`Box<dyn Error + Send + Sync + 'static>` (no `serde_ipld_dagcbor` generics leak
into the public signature); `InvalidCid` preserves the underlying `cid::Error` as
a `#[source]`. There are no `#[from]` impls (a deliberate freeze decision).
`ContentError: Send + Sync + 'static` is locked by a compile-time test, and the
`error` module documents the operation → variant map.

### Verification: `verify` vs `ensure_content_id` ([#8])

`verify` returns `Ok(false)` on a mismatch (never `Err`) — frozen. Its strict
sibling `ensure_content_id` returns `Err(ContentError::VerificationFailed)` on a
mismatch and `Ok(())` on a match, making `VerificationFailed` a real, tested
error path. Both return contracts are part of the frozen surface.

### Crate-root exports ([#9])

The public crate-root re-export surface is frozen and minimal: `ContentId`,
`ContentAddressable`, `ContentError`, and the `canonical` module (reached as
`canonical::to_canonical_dagcbor` etc., not re-exported at the root). The
codec/hash codes `DAG_CBOR_CODEC` / `BLAKE3_HASH_CODE` are `pub` in `content_id`
but deliberately **not** promoted to the crate root; `BLAKE3_DIGEST_LEN` is
private. `MerkleNode` is re-exported only under the experimental `merkle` feature;
the `store` surface only under the experimental `store` feature. Removing or
narrowing a frozen export after `0.1.0` is a major bump; *adding* one is allowed.

### MSRV & edition ([#9])

**MSRV `1.85`** (the Rust 2024 edition baseline, required transitively because
`blake3 >= 1.6` pulls `cpufeatures 0.3`, an edition-2024 crate) and **edition
`2021`** are frozen for `0.1.x`, marked as policy in `Cargo.toml`. A dedicated CI
job pins `dtolnay/rust-toolchain@1.85` so a transitive dependency cannot silently
raise the real floor; `Cargo.lock` is committed for reproducible resolution.
Bumping the MSRV or edition is an intentional, SemVer-relevant change.

### No-rehash digest bridge ([#10])

`ContentId::from_blake3_content_digest([u8; 32])` is part of the byte contract:
it emits the *same* frozen CID shape (`0x71` / `0x1e` / 32-byte digest) as
`from_canonical_bytes`, sharing one private wrapping site so the two doors are
byte-identical for the same digest. It is additive (no existing bytes change) and
**unchecked** — the caller asserts the digest is BLAKE3 over canonical DAG-CBOR.
The wrapping rule downstream BLAKE3-native systems persist and link against is
fixed for `0.1.x`.

## What is NOT frozen

### The `merkle` feature — experimental node bytes

The default-off `merkle` feature ships `MerkleNode<T>` (a `payload: T` plus
`parents: BTreeSet<ContentId>`, whose id derives from both). **Its serialized
node bytes are not frozen.** The layout depends on (a) the `ContentId` tag-42
serde repr and (b) the payload / parents field-key strings; it is pinned only
once Merkle conformance vectors land (post-`0.1.0`). Merkle vectors are
deliberately kept out of `tests/vectors.json` (the frozen cross-language
byte-parity gate). Until then, changing the node bytes is **not** a breaking
change. After `0.1.0` freezes them, it is a major bump.

### The `store` feature — experimental API

The default-off `store` feature ships the CID-addressed node store seam
(`NodeStore`, `NodeStoreExt`, `VerifiedStore`, `MemoryStore`, `AddressedBytes`,
`StoreError`, `StoreOperation`). **Its trait/API surface is not frozen** and may
change until the catalog stabilizes. The seam defines **no new wire bytes of its
own** — it stores bytes whose layout is owned elsewhere — so it adds nothing to
`tests/vectors.json`.

Its proof obligations (the seam theorems, the backend refinement laws, and the
deferred forced-collision TLA+ model tracked in [#71]) are documented in the
`store` module docs; see the README's `store` section for the trust boundary in
brief.

[#3]: https://github.com/hartsock/content-addressable/issues/3
[#4]: https://github.com/hartsock/content-addressable/issues/4
[#5]: https://github.com/hartsock/content-addressable/issues/5
[#6]: https://github.com/hartsock/content-addressable/issues/6
[#7]: https://github.com/hartsock/content-addressable/issues/7
[#8]: https://github.com/hartsock/content-addressable/issues/8
[#9]: https://github.com/hartsock/content-addressable/issues/9
[#10]: https://github.com/hartsock/content-addressable/issues/10
[#71]: https://github.com/hartsock/content-addressable/issues/71
