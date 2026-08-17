# content-addressable

**Data carries its own proof of integrity, intrinsically.**

A content address is not a name assigned to data by some authority — it is
*derived from the data itself*. Hand someone the bytes and the address, and
they can recompute the address and know, with no trusted third party, that
the bytes are exactly what the address names. The proof travels with the
data. That is the whole idea, and this crate is the smallest honest tool for
it.

## IPLD-native

This crate does not invent its own identifier format or its own
canonicalization. It speaks the multiformats / IPLD stack so its artifacts
interoperate with the wider content-addressed world:

- [`ContentId`] wraps an IPLD [`Cid`](ipld_core::cid::Cid) — a real CIDv1.
- Identities are **BLAKE3** multihashes (code `0x1e`).
- The codec is **canonical dag-cbor** (`0x71`): deterministic by
  construction (see [`canonical`]).

## Usage

Implement [`ContentAddressable`] by providing `canonical_form`; you get
`content_id` and `verify` for free:

```
use content_addressable::{canonical, ContentAddressable, ContentError};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
struct Record {
    name: String,
    attrs: BTreeMap<String, u64>,
}

impl ContentAddressable for Record {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        canonical::to_canonical_dagcbor(self)
    }
}

let r = Record { name: "alpha".into(), attrs: BTreeMap::new() };
let id = r.content_id().unwrap();
assert!(r.verify(&id).unwrap());
```

## Stability

This is `0.1.0`, the first release to freeze the core contract. The byte/wire
"must-fix gate" items are **frozen** — a stability contract across the `0.1.x`
line, where changing them is a major version bump:

- The [`ContentId`] serde representation (binary dag-cbor tag-42 link +
  multibase base32-lower text form) and the CID parameters (CIDv1, dag-cbor
  `0x71`, BLAKE3 `0x1e`, 32-byte digest).
- **Non-canonical input behavior** (gate #6):
  [`ContentId::from_canonical_bytes`] stays the fast, *unchecked* primitive
  with a normative "MUST pass canonical dag-cbor" precondition; the opt-in
  [`ContentId::from_canonical_bytes_checked`] re-encode-validates foreign
  bytes and errors with [`ContentError::NonCanonical`].
- **Error-variant stability** (gate #7): [`ContentError`] is frozen
  `#[non_exhaustive]` with boxed codec sources and a sourced `InvalidCid`;
  see the [`error`] module docs for the operation→variant map.
- **`verify` mismatch contract** (gate #8): both the return contracts of
  [`ContentAddressable::verify`] (`Ok(false)` on mismatch, never an `Err`)
  and its strict sibling [`ContentAddressable::ensure_content_id`]
  (`Err(`[`ContentError::VerificationFailed`]`)` on mismatch) are part of the
  frozen `0.1.0` API surface — distinct from, but alongside, the byte/wire
  gate.

The last two byte/wire gate items are now also settled: the **crate-root
re-export surface** and the **MSRV/edition policy** (gate items #9/#10 — see
the [public API surface](#public-api-surface-frozen-at-010) section below).
The frozen bytes are pinned by `tests/vectors.json` and the in-crate golden
tests.

# Public API surface (FROZEN at 0.1.0)

The crate-root re-export surface is itself a **stability contract** for the
`0.1.x` line, just like the wire bytes (gate item #9). Once `0.1.0` ships,
removing or narrowing any of these is a **SemVer-breaking** event (a major
bump); *adding* a new re-export is allowed additively. The frozen crate-root
surface is exactly:

- [`ContentId`] — the self-certifying identity of a canonical structured
  value (re-exported from [`content_id`]).
- [`RawContentId`] — the identity of an opaque byte string, the *raw* profile
  (CIDv1 · raw `0x55` · BLAKE3), from [`raw_id`]; and [`ClassifiedCid`] /
  [`ForeignCid`] — any well-formed CID classified as `Content` / `Raw` /
  `Foreign`, from [`classified`], where the classification is canonical (no CID
  has two representations, and `Deserialize` derives the variant rather than
  trusting it). Added by issue #84 as **additive** re-exports;
  the raw profile's bytes are fixed by the CID spec and pinned by
  `tests/raw_vectors.json`. The profile is part of the identity: a
  `RawContentId` and a `ContentId` over the same digest are different ids and
  never compare equal.
- [`ContentAddressable`] — the one trait a type implements (from
  [`trait_def`]).
- [`ContentError`] — the crate's error type (from [`error`]).
- the [`canonical`] module — `to_canonical_dagcbor` /
  `from_canonical_dagcbor` are reached as [`canonical::to_canonical_dagcbor`]
  etc., **not** re-exported at the root (one name per function, matching the
  doctests above and the PyO3 face).
- `IdentityMigration` / `MigrationKind` — re-exported **only** under the
  default-off, experimental `unstable-migration` feature (see the `migration`
  module); the `legacy` adapters live under `unstable-legacy` (the `legacy`
  module) and are not re-exported at the root.
- [`MerkleNode`] — re-exported **only** when the default-off, experimental
  `unstable-merkle` feature is enabled; its bytes are not yet frozen (see [`merkle`]).

The default-off, experimental **`unstable-store`** feature adds a further set of
re-exports (`NodeStore`, `NodeStoreExt`, `MemoryStore`, `VerifiedStore`,
`AddressedBytes`, `StoreError`, `StoreOperation` — see [`store`]). Like `MerkleNode`, these are **not part of the frozen `0.1.0`
surface**: the seam's trait API may change until the catalog stabilizes, so
it is enumerated here for completeness but explicitly excluded from the
stability contract above.

The codec/hash codes [`DAG_CBOR_CODEC`](content_id::DAG_CBOR_CODEC) /
[`BLAKE3_HASH_CODE`](content_id::BLAKE3_HASH_CODE) stay `pub` inside
[`content_id`] (so `content_addressable::content_id::DAG_CBOR_CODEC`
resolves) but are **deliberately not re-exported at the crate root**:
promoting their numeric codes to the root would signal a permanence the
crate has not committed to, and the conservative default at a freeze is the
smaller surface. `BLAKE3_DIGEST_LEN` stays private. The newer public items
([`ContentId::from_canonical_bytes_checked`], [`ContentId::digest_bytes`],
[`ContentId::digest_hex`], [`ContentId::from_dag_cbor_digest`] (and its
deprecated predecessor `from_blake3_content_digest`),
[`ContentAddressable::ensure_content_id`]) are intentional and individually
documented at their definitions.

# MSRV / edition policy (FROZEN at 0.1.0)

- **MSRV: Rust `1.85`** (gate item #10). 1.85 is the Rust 2024 edition
  baseline, pulled in transitively because `blake3 >= 1.6` depends on
  `cpufeatures 0.3` (an edition2024 crate). It is declared as
  `rust-version = "1.85"` in `Cargo.toml` and pinned by a dedicated CI job
  (`dtolnay/rust-toolchain@1.85`,
  build + test) so a transitive dependency cannot raise the real floor while
  CI stays green. A bump is an **intentional, documented, SemVer-relevant**
  change, never a silent side effect of `cargo update`.
- **Edition: `2021`** (gate item #10). The crate stays on the 2021 edition
  for the `0.1.x` line; an edition jump is a deliberate minor/major decision,
  not an alpha change.
