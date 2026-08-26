# Changelog

All notable changes to `content-addressable` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
uses [Semantic Versioning](https://semver.org/) (Rust SemVer on crates.io, the
equivalent PEP 440 spelling on PyPI).

Two distributions ship from this one repository and share a version:

| | Registry | Package name | Import / crate name |
| --- | --- | --- | --- |
| Rust core | crates.io | `content-addressable` | `content_addressable` (crate) |
| Python | PyPI | `content-addressable` | `import content_addressable` |

The PyPI **distribution** name is `content-addressable` (hyphen); the **import**
name is `content_addressable` (underscore).

## [0.1.2] — the decode side of the contract

Additive: the frozen `0.1.0` core contract is **untouched**, every golden vector
is byte-identical, and identifiers minted under `0.1.0` / `0.1.1` remain valid.
This release closes the hole on the *other* side of the codec — decoding ([#90]).

**The defect.** `canonical::from_canonical_dagcbor` was a bare
`serde_ipld_dagcbor::from_slice`. It never compared the bytes it was handed
against the canonical encoding of the value it returned, so a decoded value could
re-encode to **different** bytes and therefore carry a **different** `ContentId`
than its own source — silently. Two independent causes: the bytes may not have
been canonical (reordered map keys, non-minimal integers — all of which decode
fine), or the target type may have dropped a field it does not name (`serde`
ignores unknown map keys by default; for a protocol record that field may have
been a required demand). `ContentId::from_canonical_bytes_checked` catches the
first but *structurally cannot* catch the second: it re-encodes as generic IPLD,
which keeps every key. Only a **typed** round trip sees it.

### Added

- **`canonical::from_canonical_dagcbor_checked<T: DeserializeOwned + Serialize>`**
  — decode, then prove the round trip. Three stages, each naming a different
  party: the bytes are canonical (`NonCanonical` blames the **bytes**), they
  decode as a `T` (`DecodingError`), and re-encoding the value reproduces them
  byte-for-byte (`LossyDecode` blames the **type**). Exact byte equality is
  stronger than comparing the two ids — it assumes no collision resistance.
- **`ContentAddressable::from_canonical_form`** — the same guarantee as a
  defaulted trait method, so the ergonomic path is the safe one. It re-encodes
  through the type's own `canonical_form` (the function that *defines* its
  identity), not through `to_canonical_dagcbor`, which is why its bound is
  `DeserializeOwned + Sized` and not also `Serialize`. It carries
  `where Self: Sized`, so the trait stays dyn-compatible. The guarantee, stated:
  `T::from_canonical_form(b)?.content_id()? == ContentId::from_canonical_bytes(b)`.
- **`ContentError::LossyDecode`** — added under the enum's `#[non_exhaustive]`
  contract, which the `0.1.0` error policy kept for exactly this. It carries no
  `source`, like `NonCanonical`: nothing failed underneath, a comparison simply
  came out unequal. The `error` module's operation → variant map gains a row
  (rows may be *added* per its own freeze note).
- **Python: `from_canonical_dagcbor_checked`** — delegating to the same core
  function the Rust face calls, so the two languages cannot disagree about what is
  canonical. Python had no canonicality gate of any kind before this. The
  `LossyDecode` half has no Python analogue and cannot: Python decodes into the
  generic model, which keeps every key, so no field can be dropped. The test
  suite pins that as a property rather than leaving it assumed.

### Deprecated

- **`canonical::from_canonical_dagcbor`** — it verifies neither canonical form
  nor a lossless typed decode, and its name says otherwise. Behavior is
  **unchanged** for `0.1.x`; removal is a major-version event. Successors:
  `from_canonical_dagcbor_checked`, or `ContentAddressable::from_canonical_form`
  when the type is `ContentAddressable`. Deprecation rather than a silent fix so
  that a consumer under a zero-warnings policy is told, at the call site, that
  they are on the unverified path. The Python `from_canonical_dagcbor` keeps its
  behavior as the deliberate mirror of that door.

### Fixed

- **The Python `from_canonical_dagcbor` docstring claimed a check that never
  ran** — "Raises ValueError if the bytes are not valid canonical dag-cbor". It
  did not verify canonicality. The docstring now states what the function does
  and points at the checked door.
- **One canonicality implementation, not two.** The gate
  `ContentId::from_canonical_bytes_checked` applies is now a single shared
  function, and `NodeStoreExt::get_node` — which had open-coded exactly the three
  stages `ContentAddressable::from_canonical_form` performs — delegates to it,
  keeping only its own vocabulary for the verdict (`RepresentationMismatch`).
  Behavior is unchanged in both; they can no longer drift apart.

### Notes

- No wire bytes changed. `tests/vectors.json`, `tests/raw_vectors.json` and
  `tests/legacy_vectors.json` are untouched, and every vector in the DAG-CBOR set
  is now additionally asserted to survive the checked decoder and come back naming
  the pinned id — a gate that refuses bad bytes is only worth having if it accepts
  everything the crate itself calls canonical.
- The raw and legacy vector sets are deliberately **not** run through it: they pin
  the identities of opaque byte strings and of legacy identifier text, neither of
  which is a DAG-CBOR document. The profile law is that the codec is part of the
  identity.

[#90]: https://github.com/hartsock/content-addressable/issues/90

## [0.1.1] — the identity/classification layer

Additive: the frozen `0.1.0` core contract is **untouched**, every golden vector
is byte-identical, and identifiers minted under `0.1.0` remain valid. This
release makes *foreign* content identity representable without ever minting it
([#84], [ADR 0003]).

### Added — frozen for `0.1.x`

- **`RawContentId`** — CIDv1 · `raw` (`0x55`) · BLAKE3-256 (`0x1e`) · 32 bytes:
  the identity of an opaque byte string, sibling to `ContentId` (the DAG-CBOR
  profile). Same four presentation forms, same accessor names. Its bytes are
  fixed by the CID specification, not by this crate, and pinned cross-language
  by `tests/raw_vectors.json`. Rust **and** Python.
- **`ClassifiedCid { Content | Raw | Foreign(ForeignCid) }`** — classification of
  any well-formed CID. The three variants are **pairwise disjoint and jointly
  total**: `ForeignCid`'s every constructor rejects a recognized profile, so each
  CID has exactly one representation, and `Deserialize` *derives* the variant
  from the wire bytes rather than trusting it.
- **The profile law.** Codec + multihash algorithm + digest jointly constitute
  identity. `RawContentId(x)` never equals `ContentId(x)` even when the digest
  bytes coincide — no cross-type `PartialEq`, no `From` either way, and each
  ingress rejects the other's codec. Compare identities as typed CID bytes,
  never as `digest_hex()` (identical across profiles for the same digest).
- **`ContentId::from_dag_cbor_digest`** — the honest no-rehash door for a digest
  the caller knows is over canonical DAG-CBOR.

### Deprecated

- **`ContentId::from_blake3_content_digest`** (Rust and Python) — it stamped the
  DAG-CBOR codec on a digest it could not know came from DAG-CBOR. Behavior is
  unchanged for `0.1.x`; removal is a major-version event. Successors:
  `RawContentId::from_blake3_digest` for opaque bytes,
  `ContentId::from_dag_cbor_digest` for known-DAG-CBOR digests.

### Added — experimental (NOT frozen), opt-in, default-off

- **`unstable-legacy`** — parse-only edge adapters for the dialects still in the
  wild (`legacy::kyln` envelope-hex, `legacy::nessie` `<algo>:<hex>`,
  `legacy::bare_blake3`), pinned by `tests/legacy_vectors.json`. Rust-only by
  design. Canonical `FromStr` **never** learns a legacy dialect, so enabling
  this cannot change how canonical text parses.
- **`unstable-migration`** — `IdentityMigration` / `MigrationKind`, a
  content-addressed record stating that one identity superseded another.
  Construction and both serde ingresses validate (non-mintable `to` and
  self-migration are refused; `deny_unknown_fields` on a private wire shape).
  **Its API and its bytes are both unfrozen until golden migration vectors
  land** — its field names are load-bearing for its own id. Do not persist these
  records as long-lived identity claims yet.

### Notes

- `ClassifiedCid` is named *Classified*, not *Verified*: it proves structural
  validity and profile membership, never that content matches a digest. Content
  verification remains `verify` / `ensure_content_id` (and `VerifiedStore`,
  which does check bytes on read).
- Canonical emitted text is still base32-lower only.

[#84]: https://github.com/hartsock/content-addressable/issues/84
[ADR 0003]: docs/adr/0003-identity-profiles-and-classified-cids.md

## [0.1.0] — first stable-contract release

The first release to **freeze the core content-addressing contract** for the
whole `0.1.x` line. Downstream systems can persist identifiers and link against
the byte/wire and API surface below; changing any frozen item is a breaking
release outside `0.1.x`.

### Frozen for `0.1.x` (the stable contract)

- **IPLD-native CIDv1 identifiers.** A `ContentId` is a CID version 1 with the
  fixed profile: **dag-cbor** codec (`0x71`), **BLAKE3** multihash (`0x1e`), and
  a **32-byte** digest. Canonical string form is multibase base32-lower
  (`bafyr4i…`).
- **Canonical dag-cbor.** `to_canonical_dagcbor` / `from_canonical_dagcbor`
  produce and parse the one canonical DAG-CBOR encoding (deterministic map key
  ordering, definite lengths), so equal values always yield equal bytes and
  equal ids regardless of input field order.
- **Frozen presentation forms, Rust and Python.** The CID string form, the full
  binary CID envelope (`to_bytes` / `from_bytes`), and the bare-digest accessors
  (`digest_bytes` = 32 bytes, `digest_hex` = 64 hex chars) are identical across
  both languages.
- **Golden cross-language vectors.** `tests/vectors.json` pins the byte-exact
  Rust↔Python parity; both test suites verify against the same vectors.
- **Fail-closed CID profile validation at every ingress.** `FromStr`,
  `TryFrom<Cid>`, `from_bytes` (CID binary), and serde (human-readable and
  binary) all reject any CID outside the frozen profile with
  `ContentError::InvalidCidProfile`. The Python `parse` / `from_bytes` route
  through the same checks. An off-profile `ContentId` cannot be constructed.
- **Checked and unchecked canonical-byte constructors.** `from_canonical_bytes`
  hashes canonical bytes into the fixed profile (always on-profile);
  `from_canonical_bytes_checked` additionally re-derives and compares;
  `from_blake3_content_digest` is the documented **unchecked** no-rehash door
  (the caller asserts the digest is BLAKE3 over canonical DAG-CBOR) and still
  emits the fixed profile envelope.
- **Verification.** The `ContentAddressable` trait exposes `content_id`,
  `verify` (recompute and compare), and `ensure_content_id`; `verify` surfaces
  the underlying encoding error rather than a bare boolean.
- **MSRV Rust `1.85`** (Rust 2024-edition baseline), enforced by a dedicated CI
  job so a transitive dependency cannot silently raise the floor.
- **Python `3.9+`, abi3.** One `abi3-py39` wheel per platform (Linux x86_64 /
  aarch64, macOS universal2, Windows x64) plus an sdist; forward-compatible with
  newer CPython without a per-version rebuild.

### Experimental (NOT frozen) — opt-in, default-off

- **`unstable-merkle`** — `MerkleNode<T>` content-addressed DAG nodes. The
  **serialized node bytes are not frozen** and may change within `0.1.x` until
  Merkle conformance vectors land.
- **`unstable-store`** — the CID-addressed node-store seam (`NodeStore`,
  `NodeStoreExt`, `VerifiedStore`, `MemoryStore`, `AddressedBytes`,
  `StoreError`, `StoreOperation`). The **trait/API surface is not frozen** and
  defines no new wire bytes of its own.

  These are not production-ready and are named to say so. See
  [`docs/STABILITY.md`](docs/STABILITY.md).

### Migration from `0.1.0-alpha.1`

- **Feature rename (breaking for feature users):** the experimental cargo
  features were renamed to carry their stability at the call site —
  `merkle` → **`unstable-merkle`**, `store` → **`unstable-store`**. There are
  **no compatibility aliases**. If you enabled `features = ["merkle"]` /
  `["store"]`, switch to `["unstable-merkle"]` / `["unstable-store"]`. The Rust
  **module** paths (`content_addressable::merkle`, `::store`) and type names are
  unchanged — only the feature *flags* moved. Users of the default (frozen core)
  feature set are unaffected.
- The frozen core byte/wire contract is **unchanged** from `0.1.0-alpha.1`:
  every golden vector is byte-identical, so identifiers minted under the alpha
  remain valid.

### Compatibility

- **The abandoned SHA3-256 / `pickle` Python sibling is incompatible.** An
  earlier, unrelated Python implementation that hashed with SHA3-256 over a
  `pickle` serialization produces **different, non-interoperable** identifiers.
  It is not this package; do not mix identifiers between the two.

### Known limitations

- The Merkle catalog is incomplete and experimental (`unstable-*`); its bytes
  and API may change within `0.1.x`.
- `from_blake3_content_digest` is unchecked by design — it trusts the caller's
  digest provenance.
- Non-integer floats are outside the canonical vector set (DAG-CBOR float rules
  are handled per-language, not in the shared cross-language gate).

[0.1.1]: https://github.com/hartsock/content-addressable/releases/tag/v0.1.1
[0.1.0]: https://github.com/hartsock/content-addressable/releases/tag/v0.1.0
