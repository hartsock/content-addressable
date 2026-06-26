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

`ContentId` exposes two mint sites for this shape:

- **`from_canonical_bytes(&[u8])`** — the normal door: hashes the canonical
  dag-cbor bytes for you.
- **`from_blake3_content_digest([u8; 32])`** — a guarded, **no-rehash** escape
  hatch for BLAKE3-native upstreams that already hashed their content and hold
  only the 32-byte digest (a signature, an address), not the original bytes. It
  wraps the digest directly, with **no second hash** (the wrapping rule is the
  *same frozen tail* both doors share, so they emit byte-identical CIDs for the
  same digest). It is **unchecked**: the caller asserts the digest is BLAKE3
  over canonical dag-cbor; a digest computed any other way names content nothing
  hashed. If you have the bytes, use `from_canonical_bytes`. (The Python face
  mirrors this as `ContentId.from_blake3_content_digest(bytes)`, validating the
  32-byte length and raising `ValueError` otherwise.)

### Presentation contract (FROZEN)

Whatever forms a `ContentId` prints and emits become a byte/wire contract at
`0.1.0`. The crate names **four** distinct presentation forms so callers can't
confuse them, and freezes each (changing any is a major version bump):

| Form | Method (Rust / Python) | What it is |
|------|------------------------|------------|
| **Canonical text** | `Display` / `to_string()` · `str(id)` | multibase **base32-lower** (`b…`) — the IPLD-canonical CID string |
| **Binary envelope** | `to_bytes()` / `from_bytes()` · `to_bytes()` / `from_bytes()` | the full **CID binary** form (version + codec + multihash + digest) |
| **Bare digest** | `digest_bytes() -> [u8; 32]` · `digest_bytes() -> bytes` | the raw **32-byte BLAKE3** hash — no envelope |
| **Bare-digest-hex** | `digest_hex() -> String` · `digest_hex() -> str` | lower-hex of the 32-byte digest (**64 chars, no prefix**) |

There are **three mutually-incompatible "hex" conventions** for a CID in the
wild; the crate names them to end the ambiguity:

1. **bare-digest-hex** — hex of the raw 32-byte digest. This is what
   `digest_hex()` returns (the "swarm" / kyln `to_hex()` form: shortest, hash
   only).
2. **full-CID-bytes-hex** — hex of `to_bytes()` (the whole envelope as base16).
   **Deliberately not a method.** It is just `hex::encode(id.to_bytes())`;
   blessing it as `cid_hex()` would add a third "hex" that invites exactly the
   confusion this contract exists to end. A caller who truly needs it
   hex-encodes `to_bytes()` and owns that choice. (Recorded so it is not
   re-litigated; it can be added later additively.)
3. **multibase base32-lower** — the `Display` string; the canonical text form.

`Display` is the inverse of `FromStr` for base32-lower, and that round-trip is
frozen and tested. The `digest_hex()` of every conformance vector is pinned in
`tests/vectors.json` and asserted in **both** the Rust and Python gates, so the
new accessor's bytes cannot drift across languages.

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
println!("{id}");                          // base32-lower multibase string (Display)
let _digest: [u8; 32] = id.digest_bytes(); // the raw BLAKE3 hash (no envelope)
let _hex: String = id.digest_hex();        // 64-char bare-digest-hex (no prefix)
```

## Python

The same primitives ship as a PyO3 binding on PyPI, backed by the **exact same
Rust core** — so a `ContentId` computed in Python is **byte-identical** to the
one Rust computes for the same value. Install it with:

```sh
pip install content-addressable          # PyPI: 0.1.0a1 (alpha — bytes NOT frozen)
```

> **Import name vs. distribution name.** The PyPI *distribution* is
> `content-addressable` (hyphen); the *import* name is `content_addressable`
> (underscore). You `pip install content-addressable` but
> `import content_addressable`.

The Python face has **no `ContentAddressable` trait and no `verify`** (the Rust
example above doesn't translate). Instead you canonicalize a native Python value
and take its `content_id` directly:

```python
from content_addressable import (
    ContentId, content_id,
    to_canonical_dagcbor, from_canonical_dagcbor,
)

# A value's content id (CIDv1, dag-cbor + BLAKE3). Key order is irrelevant:
record = {"name": "alpha", "attrs": {}}
cid = content_id(record)
print(cid)                                   # base32-lower multibase string, 'b…'
print(cid.digest_hex())                      # 64-char bare-digest-hex, no prefix
print(to_canonical_dagcbor(record).hex())    # the canonical dag-cbor bytes, as hex

# Canonical bytes round-trip; equal values -> equal bytes -> equal ids.
raw = to_canonical_dagcbor(record)
assert content_id(record) == ContentId.from_canonical_bytes(raw)
assert from_canonical_dagcbor(raw) == record                   # decode round-trip
assert content_id({"attrs": {}, "name": "alpha"}) == cid       # order-independent

# Parse an id back from its string / binary forms.
assert ContentId.parse(str(cid)) == cid
assert ContentId.from_bytes(cid.to_bytes()) == cid

# Wrap an already-computed 32-byte BLAKE3 digest as an id, with NO re-hash
# (the Python mirror of the Rust no-rehash door). The 32-byte length is
# validated; a wrong length raises ValueError.
assert ContentId.from_blake3_content_digest(cid.digest_bytes()) == cid
```

`ContentId` also exposes `digest_bytes()` (the raw 32-byte BLAKE3 hash) and
`__eq__` / `__hash__`, so an id is usable as a `dict` key or `set` member.

The alpha **"bytes are NOT frozen"** caveat below applies *identically* to
Python output — read the [Alpha status](#alpha-status--bytes-are-not-frozen)
section before treating any `0.1.0a1` bytes as durable.

## Alpha status — bytes are NOT frozen

This is **`0.1.0-alpha.1`**, working toward `0.1.0`. All 10 **"must-fix gate"**
items are now **frozen** — a stability contract across the `0.1.x` line, where
changing any of them is a major version bump:

1. **SETTLED ([#3]).** The serde representation of `ContentId` is frozen: a
   dag-cbor **tag-42 link** (binary form) via the inner `Cid`'s serde, pinned
   by a full-byte golden test.
2. **SETTLED ([#6]).** The **presentation surface** is frozen. `Display` /
   `to_string()` is multibase **base32-lower** (the `b…` CIDv1 string), the
   canonical text form; `to_bytes()` / `from_bytes()` is the CID **binary
   envelope**. `FromStr` is the inverse of `Display` for base32-lower (that
   round-trip is frozen); its tolerance of other multibases is a documented
   *convenience, not a contract*. Two named raw-digest accessors are added and
   frozen: **`digest_bytes()`** (the bare 32-byte BLAKE3 hash) and
   **`digest_hex()`** (its 64-char lower-hex, the "bare-digest-hex"
   convention). The redundant `cid_hex()` is **deliberately not added** —
   `hex::encode(id.to_bytes())` covers it without a third ambiguous "hex". See
   the **presentation contract** below.
3. **SETTLED ([#4]).** The hash function (BLAKE3) and codec (dag-cbor) are
   **fixed forever** for the `0.1.x` line, not selectable.
4. **SETTLED ([#4]).** Multihash digest length is **32 bytes, fixed**.
5. **SETTLED ([#4]).** CID version policy: **v1 only**.
6. **SETTLED ([#5]).** Behavior on non-canonical input to `from_canonical_bytes`
   is frozen: it stays the **fast, unchecked** minting primitive carrying a
   **normative** "MUST pass canonical dag-cbor" precondition (passing
   non-canonical bytes mints a misleading id — a logic error, unenforced by
   design), with `content_id` / `to_canonical_dagcbor` as the documented safe
   default. An opt-in **`from_canonical_bytes_checked()`** re-encode-validates
   foreign/untrusted bytes and returns the new typed
   **`ContentError::NonCanonical`** (or `DecodingError` for non-dag-cbor). The
   name is **not** changed to `_unchecked`; `from_canonical_bytes` /
   `from_canonical_bytes_checked` is the frozen pairing.
7. **SETTLED ([#7]).** `ContentError` is **frozen** as `#[non_exhaustive]` (so
   variants can be *added* later without a major bump). The codec source types
   are hidden behind `Box<dyn Error + Send + Sync + 'static>` (no
   `serde_ipld_dagcbor` generics in the public signature); `InvalidCid` now
   preserves the underlying `cid::Error` as a `#[source]`; **no `#[from]`**
   impls (a deliberate freeze decision); `ContentError: Send + Sync + 'static`
   is locked by a compile-time test. The error module documents the
   operation→variant map.
8. **SETTLED ([#8]).** `verify` returns **`Ok(false)`** on a mismatch (never an
   `Err`) — frozen. A strict sibling **`ensure_content_id()`** returns
   **`Err(ContentError::VerificationFailed)`** on mismatch (and `Ok(())` on
   match), making `VerificationFailed` a real, tested error path. Both return
   contracts are part of the frozen `0.1.0` API surface.
9. **SETTLED ([#9]).** The **public crate-root re-export surface** is frozen and
   minimal: `ContentId`, `ContentAddressable`, `ContentError`, and the
   `canonical` module (its functions reached as `canonical::to_canonical_dagcbor`
   etc., **not** re-exported at the root). The codec/hash codes
   `DAG_CBOR_CODEC` / `BLAKE3_HASH_CODE` were **demoted off the crate root**
   (still `pub` in `content_id`) so promoting their numeric codes to the root
   doesn't signal a permanence gate item #3 hasn't committed to;
   `BLAKE3_DIGEST_LEN` stays private. `MerkleNode` is re-exported only under the
   experimental `merkle` feature. Removing or narrowing any frozen export after
   `0.1.0` is a major bump; *adding* one is allowed additively. See the
   crate-root docs (`src/lib.rs`).
10. **SETTLED ([#9]).** **MSRV `1.85`** (the Rust 2024 edition baseline, required
    transitively because `blake3 >= 1.6` pulls `cpufeatures 0.3`, an edition2024
    crate) and **edition `2021`** are frozen for the `0.1.x` line, marked as policy in
    `Cargo.toml`. A dedicated CI job pins `dtolnay/rust-toolchain@1.85`
    (build + test) so a transitive dependency can't raise the real floor while
    CI stays green; `Cargo.lock` is committed for reproducible resolution across
    that job and the byte-contract tests. Bumping the MSRV or edition is an
    intentional, SemVer-relevant change, never a silent `cargo update` effect.

**SETTLED for the freeze ([#10]).** The **no-rehash digest bridge** —
`ContentId::from_blake3_content_digest([u8; 32])` — is part of the byte
contract: it emits the *same* frozen CID shape (`0x71` / `0x1e` / 32-byte
digest) as `from_canonical_bytes`, sharing one private wrapping site so the two
doors are byte-identical for the same digest. It is an additive constructor (no
existing bytes change); the wrapping rule downstream BLAKE3-native systems
(e.g. kyln #303, kyln-lore) persist and link against is now fixed for `0.1.x`.

[#3]: https://github.com/hartsock/content-addressable/issues/3
[#4]: https://github.com/hartsock/content-addressable/issues/4
[#5]: https://github.com/hartsock/content-addressable/issues/5
[#6]: https://github.com/hartsock/content-addressable/issues/6
[#7]: https://github.com/hartsock/content-addressable/issues/7
[#8]: https://github.com/hartsock/content-addressable/issues/8
[#9]: https://github.com/hartsock/content-addressable/issues/9
[#10]: https://github.com/hartsock/content-addressable/issues/10

With all 10 gate items settled the byte/wire and API/MSRV contracts are frozen
for the `0.1.x` line; the remaining work toward `0.1.0` is the Merkle
conformance vectors (the `merkle` feature's bytes are still NON-frozen — see
below) and the final release cut. Treat the *frozen* surfaces as durable; do
**not** yet depend on the experimental `merkle` node bytes.

### The `merkle` feature — experimental, bytes NOT frozen

A default-**off** cargo feature, `merkle`, gates `src/merkle.rs`, which ships a
generic content-addressed Merkle-DAG node helper:

```rust
use content_addressable::merkle::MerkleNode;   // needs feature = "merkle"
use content_addressable::ContentAddressable;

let root = MerkleNode::genesis("hello");        // a node with no parents
let root_id = root.id().unwrap();
let child = MerkleNode::new("world", [root_id]); // links root as a parent
assert!(child.parents().contains(&root_id));     // root is recoverable as a link
```

`MerkleNode<T>` is a `payload: T` plus `parents: BTreeSet<ContentId>`, and its
id (`ContentAddressable::content_id`, aliased as `.id()`) is derived from
**both** the payload and the parent links — exactly the agent-mesh
conversation-event shape (event id = the `ContentId` of the canonical event
*including its parent cids*). The `BTreeSet` deduplicates parents and orders
them by `ContentId`'s content-derived `Ord`, so equal parent sets always
produce equal bytes regardless of insertion order; each parent serializes as a
dag-cbor **tag-42 link**, so a node's parents are real IPLD links.

> ⚠️ **Its serialized bytes are NOT frozen.** Unlike the `ContentId` /
> `canonical` surface above, this feature is experimental. The node's byte
> layout is pinned only once **Merkle conformance vectors** land (a follow-up
> toward `0.1.0-rc1`); it depends on (a) the `ContentId` tag-42 serde repr
> (must-fix gate item 1) and (b) the `payload` / `parents` field key strings.
> Until those vectors freeze it, changing the node's bytes is **allowed and is
> not a breaking change** — and merkle vectors are deliberately **kept out of
> `tests/vectors.json`** (the frozen cross-language byte-parity gate). After
> `0.1.0`, changing them is a major version bump.

Enable it with `--features merkle` (or `--all-features`):

```sh
cargo test --features merkle      # compile + run the merkle module's tests
```

CI and the pre-push hook run `--all-features`, so the feature is exercised on
every push while the plain `cargo test` keeps the default surface green (and
proves `merkle` stays off by default).

#### Byte-parity gate (`tests/vectors.json`)

A single shared golden-vector file, `tests/vectors.json`, is generated *from the
Rust core* (the authority) and consumed verbatim by **both** the Rust gate
(`tests/conformance.rs`) and the Python gate (`tests/test_content_addressable.py`),
so any future byte drift — a dependency bump, an encoder change — fails loudly in
*both* languages. It pins only the **currently-stable, JSON-expressible** dag-cbor
subset (null, bool, integers, strings, lists, maps with string keys, and byte
strings via the `{"$bytes": "<hex>"}` escape). Floats, and any value depending on
the not-yet-frozen `ContentId` serde representation (must-fix-gate item 1), are
**deliberately excluded**; they will *extend* the vectors once those items freeze.
Regenerate after an intentional byte change (the reviewable signal that a major
bump is due) with:

```sh
cargo test --test gen_vectors -- --ignored gen_vectors
```

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
