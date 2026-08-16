# content-addressable

> **Data carries its own proof of integrity, intrinsically.**

IPLD-native content addressing for Rust and Python. A content address is
*derived from the data itself*, not assigned by an authority — give someone the
bytes and the address, and they can recompute the address and know, with no
trusted third party, that the bytes are exactly what the address names. The
proof travels with the data.

This crate is deliberately small and honest: it is the instrument, not the sky.

It speaks the multiformats / IPLD stack, so its artifacts interoperate with the
wider content-addressed world (IPFS, IPLD, libp2p). The crate **mints exactly
two profiles**, and the Rust/Python *type* says which:

| Type | CID | Codec | Multihash | Digest | Names |
|------|-----|-------|-----------|--------|-------|
| `ContentId` | v1 | DAG-CBOR (`0x71`) | BLAKE3 (`0x1e`) | 32 bytes | a canonical structured **value** (encoding: canonical DAG-CBOR — strict key order, definite lengths, tag-42 links) |
| `RawContentId` | v1 | raw (`0x55`) | BLAKE3 (`0x1e`) | 32 bytes | an opaque **byte string** — a file, a chunk, a binary, a payload |

**The profile is semantic, not cosmetic.** Codec + multihash + digest jointly
constitute identity: `RawContentId(x)` and `ContentId(x)` are *different
identities* even when their 32 digest bytes are the same, they never compare
equal, and each type's parsers reject the other's CIDs. A third type,
`VerifiedCid { Content | Raw | Foreign(Cid) }`, can *carry and compare* any
well-formed CID (a `sha2-256` REAPI digest, a CIDv0, …) without this crate ever
*minting* one — algorithm agility in the verifier, no algorithm ambiguity in the
minter. Decision record: [`docs/adr/0003`](docs/adr/0003-identity-profiles-and-verified-cids.md).

Rust is the core implementation; the Python package is a PyO3 binding over that
**same Rust core**, so an id computed in Python is byte-identical to the one Rust
computes for the same canonical IPLD value.

## Status & stability

The package is **`0.1.0`** — the first release that freezes the core contract.
The core byte/wire and API contracts are locked for the whole `0.1.x` line
(changing any is a breaking release outside `0.1.x`), while the optional
`unstable-merkle` / `unstable-store` features are explicitly still moving and are
named to say so.

| Surface | Default | Stability |
|---------|:-------:|-----------|
| `ContentId`, canonical encoding, core errors, presentation, MSRV | Yes | **Frozen for `0.1.x`** — changing any is a breaking release outside `0.1.x` |
| `RawContentId`, `VerifiedCid` (added `0.1.1`, [#84]) | Yes | **Stable, additive** — the raw profile's bytes are fixed by the CID spec (CIDv1 · raw · BLAKE3-256) and pinned cross-language by `tests/raw_vectors.json`; the `ContentId` freeze is untouched |
| Python core parity | Separate package | Same core byte profiles |
| `unstable-merkle` feature | No | **Experimental** — serialized node bytes NOT frozen |
| `unstable-store` feature | No | **Experimental** — trait/API surface NOT frozen (no new wire format of its own) |
| `unstable-legacy` feature | No | **Experimental, shrinking** — explicit edge parsers for legacy identifier dialects (kyln envelope-hex, nessie `<algo>:<hex>`, bare BLAKE3 hex); exist to *end* those dialects |
| `unstable-migration` feature | No | **Experimental** — `IdentityMigration` record (from → to, reason); field names NOT frozen |

[#84]: https://github.com/hartsock/content-addressable/issues/84

Details and rationale: [`docs/STABILITY.md`](docs/STABILITY.md).

## Installation

Rust:

```toml
[dependencies]
content-addressable = "0.1.0"
```

With the optional (default-off) features:

```toml
content-addressable = { version = "0.1.0", features = ["unstable-merkle"] }
content-addressable = { version = "0.1.0", features = ["unstable-store"] }
content-addressable = { version = "0.1.0", features = ["unstable-merkle", "unstable-store"] }
```

Python:

```bash
pip install content-addressable
```

The PyPI *distribution* is `content-addressable` (hyphen); the *import* name is
`content_addressable` (underscore):

```python
import content_addressable
```

## Rust quick start

Implement `ContentAddressable` by providing `canonical_form`; `content_id`,
`verify`, and `ensure_content_id` come for free:

```rust
use content_addressable::{canonical, ContentAddressable, ContentError};
use serde::Serialize;

#[derive(Serialize)]
struct Record {
    name: String,
}

impl ContentAddressable for Record {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        canonical::to_canonical_dagcbor(self)
    }
}

let record = Record { name: "alpha".into() };

let id = record.content_id()?;          // a CIDv1 (DAG-CBOR + BLAKE3)
assert!(record.verify(&id)?);           // self-certifying: re-derive and compare
println!("{id}");                       // "bafyr4i…" — the canonical text form
# Ok::<(), ContentError>(())
```

`verify` returns `Ok(false)` on a mismatch; its strict sibling
`ensure_content_id` returns `Err(ContentError::VerificationFailed)` instead. The
secondary digest and binary presentation forms are in
[Presentation forms](#presentation-forms).

## Python quick start

The Python face exposes the same byte profile, but **not** the Rust
`ContentAddressable` trait or `verify` — you canonicalize a native Python value
and take its `content_id` directly. This block is mirrored by
`tests/test_readme.py` (every call identical), so CI's `python` job proves it
still works:

```python
from content_addressable import (
    ContentId, content_id,
    to_canonical_dagcbor, from_canonical_dagcbor,
)

# A value's content id (CIDv1, DAG-CBOR + BLAKE3). Key order is irrelevant.
record = {"name": "alpha", "attrs": {}}
cid = content_id(record)

assert str(cid).startswith("b")                # base32-lower multibase text
assert len(cid.digest_hex()) == 64             # 64-char bare-digest-hex
assert isinstance(to_canonical_dagcbor(record), bytes)

# Canonical bytes round-trip; equal values -> equal bytes -> equal ids.
raw = to_canonical_dagcbor(record)
assert content_id(record) == ContentId.from_canonical_bytes(raw)
assert from_canonical_dagcbor(raw) == record
assert content_id({"attrs": {}, "name": "alpha"}) == cid  # order-independent

# Parse an id back from its text / binary forms.
assert ContentId.parse(str(cid)) == cid
assert ContentId.from_bytes(cid.to_bytes()) == cid

# Wrap an already-computed 32-byte BLAKE3 digest with NO re-hash.
assert ContentId.from_blake3_content_digest(cid.digest_bytes()) == cid
assert len(cid.digest_bytes()) == 32           # the raw BLAKE3 hash
```

`ContentId` implements `__eq__` / `__hash__`, so an id is usable as a `dict` key
or `set` member.

## Choosing a construction path

Prefer the safe path. `from_canonical_bytes` is fast but carries a real
precondition — it is **not** universally safe.

| Use case | API (Rust / Python) | Contract |
|----------|---------------------|----------|
| Hash a normal value | `value.content_id()` / `content_id(value)` | **Preferred safe path** |
| Encode a value to bytes | `canonical::to_canonical_dagcbor(v)` / `to_canonical_dagcbor(v)` | Produces canonical DAG-CBOR |
| Accept foreign / untrusted bytes | Rust: `ContentId::from_canonical_bytes_checked(b)` · Python: *no single checked constructor yet* | Validates DAG-CBOR canonicality; errors on non-canonical |
| Hash already-trusted canonical bytes | `ContentId::from_canonical_bytes(b)` | **Unchecked** precondition: caller asserts `b` is canonical DAG-CBOR |
| Identify opaque bytes (a file, chunk, binary, payload) | `RawContentId::from_content(b)` / `RawContentId.from_content(b)` | Hashes the bytes; nothing to get wrong — the bytes *are* the content |
| Wrap an existing BLAKE3 digest **of opaque bytes** | `RawContentId::from_blake3_digest(d)` / `RawContentId.from_blake3_digest(d)` | No rehash; the honest home of the no-rehash bridge (byte-identical to kyln raw CIDs / bare `blake3` digests) |
| Wrap an existing BLAKE3 digest **known to be over canonical DAG-CBOR** | `ContentId::from_dag_cbor_digest(d)` / `ContentId.from_dag_cbor_digest(d)` | No rehash; the name asserts the precondition. `from_blake3_content_digest` is **deprecated** in its favor ([#84]): it stamped DAG-CBOR on a digest it could not know came from DAG-CBOR |
| Hold a CID you did not mint (REAPI `sha2-256`, CIDv0, …) | `VerifiedCid::from_str` / `VerifiedCid::from_bytes` | Classifies as `Content` / `Raw` / `Foreign`; foreign ids are carried and compared, never minted |

## Presentation forms

`ContentId` and `RawContentId` each name the same four presentation forms, with
the same accessor names meaning the same things, so callers can't confuse them;
each is frozen for `ContentId` (changing any is a breaking release outside
`0.1.x`) and fixed by the CID spec for `RawContentId`:

| Form | Rust | Python | What it is |
|------|------|--------|------------|
| **Canonical text** | `Display` / `to_string()` | `str(id)` | multibase **base32-lower** (`b…`) — the IPLD-canonical CID string |
| **Binary envelope** | `to_bytes()` / `from_bytes()` | `to_bytes()` / `from_bytes()` | the full **CID binary** form (version + codec + multihash + digest) |
| **Bare digest** | `digest_bytes() -> [u8; 32]` | `digest_bytes() -> bytes` | the raw **32-byte BLAKE3** hash, no envelope |
| **Bare-digest-hex** | `digest_hex() -> String` | `digest_hex() -> str` | lower-hex of the 32-byte digest (64 chars, no prefix) |

`Display` is the inverse of `FromStr` for base32-lower, and that round-trip is
frozen and tested. Full CID bytes can be hex-encoded by a caller directly
(`hex::encode(id.to_bytes())`) — the crate deliberately does not bless a second
"hex" method; see [`docs/STABILITY.md`](docs/STABILITY.md) for why.

Two rules follow from "the profile is semantic": **emit only the canonical text
form** (base32-lower `b…`), and **compare identities as typed CID bytes** —
never as `digest_hex()` (identical across the two profiles for the same digest)
and never as text. Legacy dialects (kyln envelope-hex, nessie `blake3:<hex>` /
`sha2-256:<hex>`, bare BLAKE3 hex) are *read* only through the explicit
`unstable-legacy` adapters (`legacy::kyln::parse`, `legacy::nessie::parse`,
`legacy::bare_blake3::parse`) at a system's edge; `from_str` never learns them.

## Experimental features

All `unstable-*` features are **default-off** and exercised in CI via
`--all-features`. Do not depend on the `unstable-merkle` node bytes yet.

### `unstable-legacy` — edge adapters that end the old dialects

`legacy::kyln::parse(envelope_hex) -> RawContentId` (kyln's hand-rolled CIDv1 is
byte-identical to CIDv1 raw/BLAKE3), `legacy::nessie::parse("<algo>:<hex>")
-> VerifiedCid` (`blake3` → `Raw`, `sha2-256` → `Foreign`), and
`legacy::bare_blake3::parse(hex) -> RawContentId`. Parsers only — canonical
output stays base32-lower. Expected to shrink as consumers migrate.

### `unstable-migration` — identity changes are stated, never implied

`IdentityMigration { from: VerifiedCid, to: VerifiedCid, reason: MigrationKind }`
is a content-addressed record that one identity superseded another
(`Recanonicalized` / `Reprofiled` / `HashRotated`); `to` must be a profile this
crate mints. Re-canonicalizing a value or re-profiling a digest is an *identity
migration*, and the record — not an equality — is what provenance follows. Who
may assert one, and how it is signed, is a consumer concern.

### `merkle` — content-addressed DAG nodes

`MerkleNode<T>` is a `payload: T` plus `parents: BTreeSet<ContentId>`; its id is
derived from **both** the payload and the parent links, so a root id plus the
node bytes determines the whole DAG. Because parents are a `BTreeSet`, they are
deduplicated and ordered by content-derived `Ord` — equal parent sets always
produce equal bytes regardless of insertion order, and each parent serializes as
a real DAG-CBOR tag-42 link.

```rust
use content_addressable::merkle::MerkleNode; // feature = "unstable-merkle"

let root = MerkleNode::genesis("hello");
let root_id = root.id()?;
let child = MerkleNode::new("world", [root_id]);
assert!(child.parents().contains(&root_id));
# Ok::<(), content_addressable::ContentError>(())
```

**The serialized node layout is experimental and NOT frozen** — pinning it
(Merkle conformance vectors) is post-`0.1.0` work.

### `store` — the CID-addressed node store seam

A narrow, backend-agnostic seam: `get`/`put` by `ContentId`, with a verified
read path the extension-trait implementation establishes. The pieces:

- **`NodeStore`** — the raw backend seam (two dumb ops: `get_unverified`,
  `insert`). Backends implement only this.
- **`NodeStoreExt`** — blanket-implemented, sealed-by-coherence verified
  operations (`get`, `get_node`, `put`, `put_checked`, …). A backend cannot
  *re-implement* them.
- **`VerifiedStore<B>`** — the recommended capability-safe facade: it exposes
  only the verified operations (dispatched via UFCS), so a backend's own inherent
  method cannot intercept a call made through it. **Use this** unless you have a
  reason to drop to raw ops.
- **`MemoryStore`** — the grow-only in-memory reference backend.
- **`AddressedBytes`** — an unforgeable, address-consistent `(id, bytes)` pair;
  it is the only thing `insert` accepts, so a backend can't be handed a
  mismatched pair.

Typed writes/reads are the strict doors:

```rust
use content_addressable::store::{MemoryStore, VerifiedStore};
use content_addressable::{canonical, ContentAddressable, ContentError};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Record {
    name: String,
}

impl ContentAddressable for Record {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        canonical::to_canonical_dagcbor(self)
    }
}

let mut store = VerifiedStore::new(MemoryStore::new());
let record = Record { name: "alpha".into() };

let id = store.put_node(&record)?;               // strict: rejects non-canonical
let recovered: Record = store.get_node(&id)?;    // identity-preserving typed read
assert_eq!(record, recovered);
# Ok::<(), content_addressable::store::StoreError>(())
```

- `put_node` strictly validates canonical DAG-CBOR before insertion; `put` is
  unchecked with respect to canonicality (`put_checked` / `put_node` are the
  strict doors).
- `get_node` performs an identity-preserving typed read (decode, re-encode, and
  require the value to be the one named by the id). Raw `get` proves only that
  the returned bytes hash to the requested CID — not that they are canonical.

**Trust boundary.** The seam derives addresses on write and verifies them on read
(*seam theorems*). Successful persistence, durability, no-rebind, and grow-only
behavior are **backend obligations** (*backend refinement laws*), not seam
theorems — `MemoryStore` discharges its documented in-memory obligations. The
formal Lean/TLA+ artifacts are **deferred proof targets** (tracked in
[#71](https://github.com/hartsock/content-addressable/issues/71)); the `store`
module docs in [`src/store.rs`](src/store.rs) carry the full proof-obligation
catalog. **The `store` trait/API is experimental and NOT frozen.**

## Stability details

The frozen `0.1.x` contracts — CID profile, presentation, serde representation,
error policy, `verify`/`ensure_content_id`, crate-root exports, MSRV/edition, the
no-rehash digest bridge, and the experimental-feature exclusions — are recorded
in [`docs/STABILITY.md`](docs/STABILITY.md), with issue provenance. Treat the
frozen surfaces as durable.

## Development

```bash
just check            # the local gate: fmt + clippy + test + docs + leaf-deps
```

A pre-push hook runs the same checks; the individual `cargo fmt` / `cargo clippy`
/ `cargo test --all-features` steps work directly too.

## Releasing

Tag-driven; see [`RELEASING.md`](RELEASING.md) for the wheel matrix, PyPI Trusted
Publishing, and crates.io steps.

## License

Apache-2.0.
