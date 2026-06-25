# content-addressable

> **Data carries its own proof of integrity, intrinsically.**

A foundational Rust crate for content addressing. A content address is not a
name assigned to data by an authority — it is *derived from the data itself*.
Give someone the bytes and the address, and they can recompute the address and
know, with no trusted third party, that the bytes are exactly what the address
names. The proof travels with the data.

This crate is deliberately small and honest: it is the instrument, not the sky.

## IPLD-native

This crate does **not** roll its own identifier format or canonicalization. It
speaks the multiformats / IPLD stack, so its artifacts interoperate with the
wider content-addressed world (IPFS, IPLD, libp2p, and friends):

- **`ContentId`** is a newtype over a real IPLD [`Cid`] (CID **v1**), from the
  [`cid`] crate re-exported by [`ipld-core`].
- Identities are **BLAKE3** multihashes (multihash code `0x1e`), via the
  [`multihash`] crate.
- The codec is **canonical dag-cbor** (`0x71`), via [`serde_ipld_dagcbor`].
  dag-cbor *is* the canonical form: strict map key ordering, definite-length
  arrays/maps, and tag-42 links are enforced by the codec — so determinism is a
  property of the encoder, not of caller discipline.

The CID is built explicitly: `BLAKE3(bytes)` → `Multihash::wrap(0x1e, digest)`
→ `Cid::new_v1(0x71, mh)`.

[`Cid`]: https://docs.rs/cid
[`cid`]: https://crates.io/crates/cid
[`ipld-core`]: https://crates.io/crates/ipld-core
[`multihash`]: https://crates.io/crates/multihash
[`serde_ipld_dagcbor`]: https://crates.io/crates/serde_ipld_dagcbor

## Usage

Implement `ContentAddressable` by providing `canonical_form`; you get
`content_id` and `verify` for free:

```rust
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
let id = r.content_id().unwrap();          // a CIDv1 (dag-cbor + BLAKE3)
assert!(r.verify(&id).unwrap());           // self-certifying
println!("{id}");                          // base32-lower multibase string
```

## Alpha status — bytes are NOT frozen

This is **`0.1.0-alpha.1`**, an explicitly **non-frozen** alpha. The exact
bytes this crate emits are **not a stability contract yet**. There is an open
byte/wire **"must-fix gate"** with **10 items** to settle before `0.1.0`,
including (non-exhaustive):

1. The frozen serde representation of `ContentId` (currently a dag-cbor tag-42
   link via the inner `Cid`'s serde).
2. The default multibase used by `Display` / `FromStr`.
3. Whether the hash function (BLAKE3) and codec (dag-cbor) are fixed forever or
   selectable.
4. Multihash digest length policy.
5. CID version policy (v1 only?).
6. Behavior on non-canonical input passed to `from_canonical_bytes`.
7. Error variant stability (`ContentError` is `#[non_exhaustive]`).
8. Whether `verify` mismatch should ever be an `Err` vs `Ok(false)`.
9. The public re-export surface from the crate root.
10. MSRV floor and edition policy.

Until `0.1.0`, **do not treat alpha output as a durable on-disk format.**

### Not compatible with the pre-alpha Python sibling

This crate is **not byte-compatible** with the earlier pre-alpha Python
`content-addressable` sibling, which used **SHA3-256 + `pickle`**. That design
is abandoned here in favor of the IPLD-native stack (BLAKE3 + CIDv1 +
canonical dag-cbor). Addresses produced by the two are unrelated.

## Development

```sh
just check          # fmt + clippy + test (the full local gate)
just install-hooks  # install .githooks/pre-push (mirrors CI)
```

Or directly:

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt -- --check
```

The pre-push hook (`.githooks/pre-push`) mirrors `.github/workflows/ci.yml`.
Do not bypass it with `--no-verify`.

## License

Apache-2.0. See [LICENSE](LICENSE).
