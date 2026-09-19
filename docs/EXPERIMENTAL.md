# Experimental features

[Back to the README](../README.md)

All `unstable-*` features are off by default. CI exercises them with
`--all-features`, but their APIs and applicable wire formats may change.
Enable the features you need in `Cargo.toml`, for example:

```toml
content-addressable = { version = "0.1.0", features = ["unstable-merkle", "unstable-store"] }
```

## `unstable-legacy`

The adapters parse legacy identifiers at system boundaries:

- `legacy::kyln::parse(envelope_hex) -> RawContentId`: the legacy envelope is
  byte-identical to CIDv1 raw/BLAKE3.
- `legacy::nessie::parse("<algo>:<hex>") -> ClassifiedCid`: `blake3` becomes
  `Raw`; `sha2-256` becomes `Foreign`.
- `legacy::bare_blake3::parse(hex) -> RawContentId`: bare BLAKE3 hex.

The adapters only read legacy forms. Output stays base32-lower, and the
adapters are expected to shrink as consumers migrate.

## `unstable-migration`

`IdentityMigration { from: ClassifiedCid, to: ClassifiedCid, reason: MigrationKind }`
records an identity change: `Recanonicalized`, `Reprofiled`, or `HashRotated`.
The record connects distinct identities without equating them. Consumers decide
who may assert a migration and how to sign it.

`IdentityMigration::new` requires a mintable destination and `from != to`.
Its fields are private. `Deserialize` uses the same constructor and rejects
unknown fields. The record's field names are not frozen.

## `unstable-merkle`

`MerkleNode<T>` combines `payload: T` with `parents: BTreeSet<ContentId>` and
derives its id from both. The parent set deduplicates and sorts links by
content-derived `Ord`, so insertion order cannot affect the node's bytes.
Each parent serializes as a DAG-CBOR tag-42 link.

```rust
use content_addressable::merkle::MerkleNode; // feature = "unstable-merkle"

let root = MerkleNode::genesis("hello");
let root_id = root.id()?;
let child = MerkleNode::new("world", [root_id]);
assert!(child.parents().contains(&root_id));
# Ok::<(), content_addressable::ContentError>(())
```

The serialized node layout is not frozen. Merkle conformance vectors remain
future work.

## `unstable-store`

Use `VerifiedStore<B>` for verified reads and writes. It exposes only verified
operations and dispatches them via UFCS, preventing a backend's inherent methods
from intercepting them.

- `NodeStore` defines the backend operations `get_unverified` and `insert`.
- `NodeStoreExt` supplies verified operations through a blanket implementation
  that backends cannot replace.
- `MemoryStore` supplies a grow-only in-memory backend.
- `AddressedBytes` binds an id to matching bytes. `insert` accepts only this
  type, preventing callers from supplying mismatched pairs.

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

`put_node` and `put_checked` validate canonical DAG-CBOR before insertion;
`put` leaves that check to the caller. `get_node` checks that decoding and
re-encoding reproduce the bytes named by the id. Raw `get` checks only that
the returned bytes hash to the requested CID. It does not check canonicality.

The store interface derives addresses on write and verifies them on read.
Backends must provide successful persistence, durability, no-rebind, and
grow-only behavior; the interface cannot guarantee these. `MemoryStore`
satisfies its documented in-memory obligations.

The [store module](../src/store.rs) lists the proof obligations. Formal Lean
and TLA+ proofs remain deferred ([#71](https://github.com/hartsock/content-addressable/issues/71)).
The store trait and API are not frozen.

---

Editorial refactor:

Model: not exposed by harness | Harness: Codex | Operator: Shawn Hartsock | Time: 16:56 EDT | Date: 2026-09-19
