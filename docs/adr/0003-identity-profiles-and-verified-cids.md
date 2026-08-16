# ADR 0003 — Two mintable identity profiles, one verifier, and the profile law

- Status: **Accepted** (2026-08-16), issue [#84](https://github.com/hartsock/content-addressable/issues/84)
- Numbering: 0001 (representation method) and 0002 (`MerkleNode` causal-set
  exemplar) are reserved by [#40](https://github.com/hartsock/content-addressable/issues/40)
  and may land after this record; this ADR does not depend on them.

## Context

Four BLAKE3 identifier conventions coexist across the workspace: this crate's
`ContentId` (real CIDv1, dag-cbor `0x71`, BLAKE3 `0x1e`, base32-lower text);
kyln-core's hand-rolled CID (`[0x01, 0x55, 0x1e, 0x20, digest]`, hex of the
whole envelope as text, ciborium CBOR for structured values); nessie-store's
`Digest` (`"<algo>:<hex>"`, multihash bytes, BLAKE3 **and** SHA-256
first-class for REAPI); and bare 32-byte digests (agent-mesh-protocol envelope
`payload_cid`, agent-store `content_hash`).

Verified 2026-08-16 at the byte level: these are **not four incompatible
systems** — they are four *policies* on essentially compatible multiformats
machinery. kyln's envelope is a spec-conformant CIDv1(raw, blake3-256) octet
for octet; nessie's multihash bytes are spec multihash; a bare digest is a
multihash payload. What differs is codec semantics, canonicalization, textual
presentation, and minting policy. So this crate can become the shared
**identity algebra** without becoming the shared **storage implementation** —
which is the boundary we want.

Meanwhile agent-bridle is about to put content identity into capability grants
and evidence (agent-bridle ADR 0028). Once grants carry artifact identities,
changing what those identities *mean* becomes expensive. This decision lands
first.

## Decision

### D1 — Two first-class, typed, mintable profiles

```text
ContentId     = CIDv1(dag-cbor 0x71, blake3-256 0x1e, 32)   identity of a canonical structured value
RawContentId  = CIDv1(raw      0x55, blake3-256 0x1e, 32)   identity of an opaque byte string / artifact
```

Forcing artifacts through dag-cbor (`CID(dag-cbor, blake3(encode(ChunkLeaf
{ kind, data })))`) is tidy but semantically wrong: it is the identity of a
*representation containing* the artifact, not of the artifact. When a
capability system says "authority X permits artifact Y", Y must identify the
thing whose authority is discussed. `RawContentId` is that identity, and it
makes every BLAKE3-native identifier already in the wild a byte-identical
`RawContentId` with no re-hash.

`RawContentId` mirrors `ContentId`'s presentation contract exactly (same
accessor names, same meanings: `Display`/`FromStr` base32-lower,
`to_bytes`/`from_bytes` envelope, `digest_bytes`/`digest_hex` bare digest, serde
tag-42 link / string). Its hashing constructor is `from_content` — *not*
`from_bytes` — so that across both profiles `from_bytes`/`to_bytes` always mean
the CID envelope. Every ingress path validates the raw profile.

**This does not violate FREEZE-MINIMALLY.** The frozen statement "`ContentId`
means CIDv1 + dag-cbor + BLAKE3-256" remains exactly true; we add a second
theorem, "`RawContentId` means CIDv1 + raw + BLAKE3-256". Explicitly rejected:
a codec-polymorphic `ContentId { codec, hash }` — that moves semantics from the
type into runtime state.

### D2 — One verifier: `VerifiedCid { Content | Raw | Foreign(Cid) }`

```text
                 CIDv1 (or v0)
                       │
            ┌──────────┴──────────┐
         mintable              verifiable only
            │                       │
      ┌─────┴─────┐                 │
   dag-cbor      raw          any other codec / hash
   BLAKE3       BLAKE3        (sha2-256, REAPI, CIDv0, …)
      │           │                 │
  ContentId  RawContentId       Foreign(Cid)
```

Any structurally valid CID can be parsed, classified, carried, compared, linked
and rendered; only the two profiles are minted. The variant is *derived* from
codec + hash on every ingress (including deserialization), never trusted from
the wire. Algorithm agility in the verifier; no algorithm ambiguity in the
minter.

### D3 — Text: canonical output only; liberal verified input at the edges

Emitted identifiers are multibase base32-lower `b…` only. Legacy readers exist
solely as **explicit adapters** behind the default-off `unstable-legacy`
feature — `legacy::kyln::parse` (envelope-hex → `RawContentId`),
`legacy::nessie::parse` (`blake3:` → `Raw`, `sha2-256:` → `Foreign`),
`legacy::bare_blake3::parse` (bare hex → `RawContentId`). `ContentId::from_str`
/ `RawContentId::from_str` / `VerifiedCid::from_str` are never taught these
dialects. Migration conveniences must not become permanent wire protocol; the
module is expected to shrink.

### D4 — Canonicalization: standardize dag-cbor + vectors; do NOT absorb domain schemas

Dependency direction stays `content-addressable ← {kyln, nessie, agent-mesh}
← agent-bridle`. This crate owns the algebra of identity, canonical
serialization primitives/profiles, parsing, verification, and conformance
vectors. Generic DAG shapes (`DirNode`/`FileNode`, #53) are defensible here;
nessie's `ActionResult` and kyln's `ProvenanceLink` are not — they stay in
their domains. Otherwise this crate wakes up as `libgilamonster`.

The hard part is named honestly: moving a logical object from an old
canonicalization to canonical dag-cbor is an **identity migration, not a
serialization migration** — anything referencing CID A does not reference CID
B. Model it explicitly (`unstable-migration`):

```rust
IdentityMigration { from: VerifiedCid, to: VerifiedCid /* mintable */, reason: MigrationKind }
// MigrationKind ∈ { Recanonicalized, Reprofiled, HashRotated }
```

The record is itself `ContentAddressable`; its id is what a signature or
attestation binds to. This crate owns the record's identity, not its
authorization.

### D5 — `from_blake3_content_digest` is deprecated

It stamped `dag-cbor` on a digest it could not know came from dag-cbor.
Successors: `RawContentId::from_blake3_digest` (a digest of opaque bytes — the
honest profile) and the explicit, lower-level `ContentId::from_dag_cbor_digest`
(asserts dag-cbor semantics in its name; byte-identical to the deprecated
door). Behavior is unchanged for `0.1.x`; removal is a major-version event.
The normal API remains `value.content_id()` / `RawContentId::from_content`,
so callers rarely inject digests.

### D6 — Law: the CID profile is semantic, not cosmetic

> Codec + multihash algorithm + digest jointly constitute identity. Different
> profiles never compare equal merely because their digest bytes match:
> `RawContentId(x) ≠ ContentId(x)`.

Enforced by the type system (no cross-type `PartialEq`, no `From` in either
direction, each ingress rejects the other codec) and pinned by
`tests/raw_vectors.json` (`content_id_of_same_digest_str` ≠
`raw_content_id_str` for every vector, in both languages). Corollary for
consumers, especially at an OCAP boundary: authorization compares **typed,
normalized CID bytes** (`ArtifactRef<RawContentId>` → canonical CID bytes),
never text and never `digest_hex()`. This closes the whole "same digest,
different interpretation" bug family.

## Consequences

- **Additive to the `0.1.x` freeze.** `RawContentId`, `VerifiedCid`, and
  `ContentId::from_dag_cbor_digest` are new; nothing frozen changed. Ships as
  `0.1.1`.
- **Cross-language parity** extends to the raw profile via
  `tests/raw_vectors.json` (Rust `tests/raw_conformance.rs`, Python
  `tests/test_content_addressable.py`), generated by Rust
  (`tests/gen_raw_vectors.rs`). The `empty` vector's digest equals nessie's own
  `blake3:af1349b9…` test vector — the byte-identity claim, checked.
- **Per-consumer migration checklist** (each ends with `content-addressable` as
  its only identity dependency and `IdentityMigration` records where identities
  move): kyln-core (`ContentId`/`Cid` → `RawContentId`; ciborium → dag-cbor is
  a `Recanonicalized` migration), nessie-store (`Digest` → `VerifiedCid`;
  BLAKE3 → `Raw`, SHA-256 → `Foreign`), agent-mesh-protocol envelope
  (`payload_cid` → `RawContentId`), agent-store (`content_hash` →
  `RawContentId`).
- **agent-bridle ADR 0028** consumes this record as its identity contract and
  mints nothing of its own.

## Alternatives considered

- **One profile, artifacts as dag-cbor `ChunkLeaf` nodes.** Rejected (D1):
  names the wrapper, not the artifact; makes every foreign raw CID foreign
  forever.
- **Codec-polymorphic `ContentId`.** Rejected (D1): entropy through the
  basement window.
- **Teach `from_str` the legacy dialects.** Rejected (D3): today's convenience
  is tomorrow's wire protocol.
- **Absorb nessie/kyln domain schemas to ease migration.** Rejected (D4):
  wrong dependency direction.
- **Treat re-canonicalization as an equivalence.** Rejected (D4): it is an
  identity change; record it.
