# content-addressable

Content addressing for Rust and Python: derive an address from data so anyone
with the bytes and address can verify that they match.

The crate uses IPLD content identifiers (CIDs) with BLAKE3. The Python package
binds the Rust core, so both languages produce the same identifier when a value
encodes to the same canonical DAG-CBOR bytes.

## Use the right identity

`ContentId` identifies canonical DAG-CBOR values. `RawContentId` identifies
bytes without interpreting them. Both use CIDv1 and a 32-byte BLAKE3 digest,
but their codecs differ and make them distinct identities even for the same
digest. Compare typed CIDs, never bare digests. Emit base32-lower CID text.

Before constructing a `ContentId` from untrusted bytes, check that they are
canonical DAG-CBOR.
`ContentId::from_canonical_bytes` assumes this without checking. Use checked
construction or checked decoding to validate canonicality; typed checked
decoding also catches fields the target type discards.

See [identity and decoding](docs/IDENTITY.md) for construction APIs, checked
reads, presentation forms, foreign CIDs, and the Python tag-42 link limitation.

## Installation

Rust (1.85 or later):

```toml
[dependencies]
content-addressable = "0.1.0"
```

Python:

```bash
pip install content-addressable
```

Import the Python package as `content_addressable`.

## Rust quick start

Implement `canonical_form` to give your type the `ContentAddressable` trait
methods `content_id`, `verify`, and `ensure_content_id`:

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

`verify` returns `Ok(false)` on a mismatch. `ensure_content_id` returns
`Err(ContentError::VerificationFailed)`.

## Python quick start

Call `content_id` on a native Python value. Python exposes neither the Rust
`ContentAddressable` trait nor its `verify` method.

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

`ContentId` supports equality and hashing for use as a `dict` key or `set`
member.

## Stability and optional features

The core contracts are stable throughout `0.1.x`, with
[one documented exception in 0.1.2](docs/STABILITY.md#the-one-012-stability-exception)
for Rust trait-method name resolution. See the [stability contract](docs/STABILITY.md)
for frozen bytes, APIs, and compatibility details.

All `unstable-*` features are off by default and may change:

- `unstable-merkle`: content-addressed DAG nodes.
- `unstable-store`: verified storage operations and an in-memory backend.
- `unstable-legacy`: parsers for legacy identifier formats.
- `unstable-migration`: records of identity changes.

See [experimental features](docs/EXPERIMENTAL.md) for examples and storage
guarantees.

## Development

```bash
just install-hooks
just check            # fmt + clippy + test + docs + leaf-deps
```

See [RELEASING.md](RELEASING.md) for tag-driven releases.

## License

[Apache-2.0](LICENSE).
