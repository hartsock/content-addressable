# Stability contracts

What is **frozen** for the `0.1.x` line, and what is not. A frozen contract is a
stability guarantee: changing any of these is a **breaking release outside `0.1.x`**. The
package is `0.1.0` — the first release to freeze these contracts, so downstream
systems can persist and link against them today.

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
representation** of `ContentId` is frozen: it serializes as a DAG-CBOR **tag-42
link** via the inner `Cid`'s serde. The cross-language byte gate
`tests/vectors.json` — asserted in both the Rust (`tests/conformance.rs`) and
Python conformance tests — pins the canonical DAG-CBOR bytes, the base32 CID text,
the CID **binary envelope** (`to_bytes()`), and `digest_hex`, so an id's public
byte forms cannot drift across languages.

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

**The same pairing extended to decoding** (`0.1.2`, [#90]), additively.
`canonical::from_canonical_dagcbor_checked` and the defaulted
`ContentAddressable::from_canonical_form` verify a *typed* round trip — the bytes
are canonical, and re-encoding the decoded value reproduces them exactly — so the
value a caller ends up holding provably carries the identity the bytes have.
`from_canonical_bytes_checked` cannot substitute: it re-encodes as generic IPLD,
which keeps every key, so a typed decode dropping an unknown field is structurally
invisible to it. The bare `canonical::from_canonical_dagcbor` is **deprecated**;
its behavior is unchanged for `0.1.x` and removing it is a major-version event.
`ContentError::LossyDecode` was **added** under the enum's `#[non_exhaustive]`
contract — the first use of the additive path the error policy below reserves.
Nothing above was narrowed and no behavior changed.

One caveat, stated rather than glossed: a new **defaulted trait method** is RFC
1105's *minor / possibly-breaking* category, not purely additive. A downstream
type implementing `ContentAddressable` that also gets a `from_canonical_form`
associated function from another trait in scope now fails with `error[E0034]:
multiple applicable items in scope`, and a `^0.1` dependency picks that up with
no opt-in. The method's `where Self: DeserializeOwned` clause does not remove it
as a candidate. Disambiguate with `<T as OtherTrait>::from_canonical_form(b)`.
The other `0.1.2` additions (a free function, a `#[non_exhaustive]` variant, a
Python binding) carry no such exposure.

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

### The raw profile and the profile law ([#84], added `0.1.1`)

`RawContentId` = CIDv1 · `raw` (`0x55`) · BLAKE3-256 (`0x1e`) · 32 bytes is the
identity of an opaque byte string, sibling to `ContentId` (the DAG-CBOR
profile). It is **additive**: the `ContentId` freeze above is untouched, and
`RawContentId`'s bytes are fixed by the CID specification rather than by this
crate — pinned cross-language by `tests/raw_vectors.json` (Rust gate
`tests/raw_conformance.rs`, Python gate in `tests/test_content_addressable.py`).
It carries the same four presentation forms with the same accessor names.

**Law — the profile is semantic, not cosmetic.** Codec + multihash algorithm +
digest jointly constitute identity. `RawContentId(x)` never compares equal to
`ContentId(x)` even when the digest bytes coincide: there is no `PartialEq`
across the types, no `From` in either direction, and each type's ingress
(`from_bytes`, `FromStr`, `TryFrom<Cid>`, binary `Deserialize`) rejects the
other's codec with `InvalidCidProfile`. Consumers compare identities as **typed
CID bytes**, never as `digest_hex()` (which is identical across profiles for the
same digest) and never as text. `ClassifiedCid { Content | Raw |
Foreign(ForeignCid) }` carries and compares any well-formed CID (including ones
this crate will not mint, e.g. `sha2-256`) under the same law.

**Canonical form.** The three profiles are pairwise disjoint and jointly total
over well-formed CIDs, and `ForeignCid`'s constructors (`new`, `TryFrom<Cid>`,
`FromStr`, `from_bytes`, `Deserialize`) reject a recognized profile. So every
CID has exactly one representation in `ClassifiedCid`, no variant can hold a CID
outside its profile, and `Deserialize` **derives** the variant from the bytes
rather than trusting it — a crafted link cannot land in the wrong variant. The
type is named *Classified*, not *Verified*: it proves structural validity and
profile membership, never that content matches a digest (that is
`RawContentId::verify` / `ContentAddressable::verify`, which need the bytes).

**Deprecation.** `ContentId::from_blake3_content_digest` (Rust and Python) is
deprecated: it stamped the DAG-CBOR codec on a digest it could not know came
from DAG-CBOR. Its behavior is unchanged for `0.1.x`. The explicit successors
are `RawContentId::from_blake3_digest` (a digest of opaque bytes — the honest
profile, byte-identical to kyln raw CIDs and bare `blake3` digests) and
`ContentId::from_dag_cbor_digest` (a digest known to be over canonical DAG-CBOR;
byte-identical to the deprecated door). Removal is a major-version event.

**Text.** Emitted identifiers are base32-lower only. Legacy dialects are read
solely through the default-off `unstable-legacy` adapters
(`legacy::kyln`, `legacy::nessie`, `legacy::bare_blake3`), which exist to end
those dialects and are expected to shrink; `from_str` never learns them.

### Error policy ([#7])

`ContentError` is `#[non_exhaustive]`, so variants may be **added** additively
without a breaking release outside `0.1.x`. The codec source types are hidden behind
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
`ContentAddressable`, `ContentError`, `RawContentId`, `ClassifiedCid` and
`ForeignCid` (the latter three added by [#84]), and the `canonical` module (reached as
`canonical::to_canonical_dagcbor` etc., not re-exported at the root). The
codec/hash codes `DAG_CBOR_CODEC` / `BLAKE3_HASH_CODE` are `pub` in `content_id`
but deliberately **not** promoted to the crate root; `BLAKE3_DIGEST_LEN` is
private. `MerkleNode` is re-exported only under the experimental `unstable-merkle` feature;
the `store` surface only under the experimental `unstable-store` feature. Removing or
narrowing a frozen export after `0.1.0` is a breaking release outside `0.1.x`; *adding* one is allowed.

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

### The `unstable-merkle` feature — experimental node bytes

The default-off `unstable-merkle` feature ships `MerkleNode<T>` (a `payload: T` plus
`parents: BTreeSet<ContentId>`, whose id derives from both). **Its serialized
node bytes are not frozen.** The layout depends on (a) the `ContentId` tag-42
serde repr and (b) the payload / parents field-key strings; it is pinned only
once Merkle conformance vectors land (post-`0.1.0`). Merkle vectors are
deliberately kept out of `tests/vectors.json` (the frozen cross-language
byte-parity gate). Until then, changing the node bytes is **not** a breaking
change. After `0.1.0` freezes them, it is a breaking release outside `0.1.x`.

### The `unstable-store` feature — experimental API

The default-off `unstable-store` feature ships the CID-addressed node store seam
(`NodeStore`, `NodeStoreExt`, `VerifiedStore`, `MemoryStore`, `AddressedBytes`,
`StoreError`, `StoreOperation`). **Its trait/API surface is not frozen** and may
change until the catalog stabilizes. The seam defines **no new wire bytes of its
own** — it stores bytes whose layout is owned elsewhere — so it adds nothing to
`tests/vectors.json`.

Its proof obligations (the seam theorems, the backend refinement laws, and the
deferred forced-collision TLA+ model tracked in [#71]) are documented in the
`store` module docs; see the README's `store` section for the trust boundary in
brief.

### The `unstable-legacy` feature — experimental API, parse-only

The default-off `unstable-legacy` feature ships the edge adapters for the legacy
identifier dialects (`legacy::kyln`, `legacy::nessie`, `legacy::bare_blake3`).
**Its API surface is not frozen** — these adapters exist to *end* those dialects
and are expected to shrink and then go away, so treat them as a migration ramp
rather than a contract.

It defines **no new wire bytes of its own**: every adapter is parse-only and
returns an ordinary `RawContentId` / `ClassifiedCid`, whose bytes are already
frozen above. What *is* pinned is the mapping from each dialect to that result —
`tests/legacy_vectors.json` (Rust gate `tests/legacy_conformance.rs`; the Python
gate re-derives the SHA-256 rows with `hashlib`, so those rows are interop data
rather than restated shapes). The adapters are deliberately **Rust-only**: a
Python legacy-parsing face would widen exactly the surface [#84] narrows, so the
vectors carry the portability instead.

The frozen guarantee that *does* apply here is negative and stated above under
the profile law: canonical `FromStr` never learns a legacy dialect, so enabling
this feature cannot change how canonical text parses.

### The `unstable-migration` feature — experimental API **and wire bytes**

The default-off `unstable-migration` feature ships `IdentityMigration` /
`MigrationKind` ([#84]): a content-addressed record stating that one identity
superseded another. Construction and both serde ingresses are validating —
private fields, a single `new` that rejects a non-mintable `to` and a
self-migration, and a `Deserialize` that decodes a private wire shape with
`deny_unknown_fields` and re-runs that constructor.

**Neither its API nor its bytes are frozen.** The record is itself
`ContentAddressable`, so its field names and their order are load-bearing for
its own id: renaming a field moves the id of every migration record ever
written. That is exactly why it stays unfrozen **until golden migration vectors
land** and make its content-addressed representation explicit and reproducible
across languages, the same bar `tests/vectors.json` and `tests/raw_vectors.json`
already meet for the two mintable profiles. Until then it is deliberately absent
from the vector set, and downstream systems should not persist these records as
long-lived identity claims.

[#3]: https://github.com/hartsock/content-addressable/issues/3
[#4]: https://github.com/hartsock/content-addressable/issues/4
[#5]: https://github.com/hartsock/content-addressable/issues/5
[#6]: https://github.com/hartsock/content-addressable/issues/6
[#7]: https://github.com/hartsock/content-addressable/issues/7
[#8]: https://github.com/hartsock/content-addressable/issues/8
[#9]: https://github.com/hartsock/content-addressable/issues/9
[#10]: https://github.com/hartsock/content-addressable/issues/10
[#71]: https://github.com/hartsock/content-addressable/issues/71
[#84]: https://github.com/hartsock/content-addressable/issues/84
[#90]: https://github.com/hartsock/content-addressable/issues/90
