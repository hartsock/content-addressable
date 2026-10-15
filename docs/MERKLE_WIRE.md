# MerkleNode wire format

The byte-level contract for `MerkleNode<T>`. An implementer in any language
should be able to produce these bytes and CIDs from this page alone. The Rust
serializer is *not* the definition; `tests/merkle_vectors.json` and
`tests/merkle_adversarial.rs` (an encoder written from this page) are the checks.

## 1. Logical node

A node is `(payload, parents)`: one payload value and a **set** of parent CIDs.
Two nodes are equal when their payloads are equal and their parent *sets* are
equal. Insertion order and repeats of a parent are not part of the node.

## 2. Bytes

The node serializes as a canonical DAG-CBOR map of exactly two entries:

```
a2                           map(2)
  67 "parents"               text(7)
  <array>                    definite-length array, see below
  67 "payload"               text(7)
  <payload>                  canonical DAG-CBOR of the payload, see §4
```

- **Key order.** DAG-CBOR sorts map keys by length, then bytewise. Both keys are
  7 bytes and `"pare…" < "payl…"` (`r` < `y`), so `parents` always comes first.
- **Parents array.** Major type 4, definite length, minimal header for the
  count `n`: `0x80|n` for n < 24; `98 nn` for n < 256; `99 nnnn` for n < 65536;
  `9a nnnnnnnn` for n < 2^32; `9b nnnnnnnnnnnnnnnn` beyond (big-endian). There
  is no upper limit on `n`. The 24/256 boundaries are pinned by vectors; the
  larger ones by header tests in both languages and a 65536-parent node.
  Elements are sorted **ascending by the CID's binary bytes** (unsigned
  lexicographic), with exact duplicates removed. All parent CIDs share the same
  four-byte prefix, so this is digest order.
- **Each parent** is a DAG-CBOR link: tag 42 (`d8 2a`) over a byte string
  (`58 25`, 37 bytes) whose first byte is `00` followed by the 36-byte binary
  CIDv1: `01` `71` `1e` `20` + 32-byte BLAKE3 digest.
  So one link is `d8 2a 58 25 00 01 71 1e 20 <32 bytes>`.

## 3. Node CID

`CID = CIDv1(codec 0x71 dag-cbor, multihash 0x1e blake3-256, digest = BLAKE3-256(node bytes))`,
rendered as multibase base32 lower with the `b` prefix. It covers exactly the
bytes of §2: the parents and the payload, nothing else.

## 4. Payload

The payload is encoded by the canonical DAG-CBOR rules: definite lengths,
minimal integers, map keys text-only and sorted length-first then bytewise, no
duplicate keys. A link inside the payload is an ordinary DAG-CBOR
tag-42 link carrying its own CID bytes (`d8 2a`, a byte string of `1 + len(cid)`
bytes starting `00`, then the CID), in **any** supported CID profile. The
fixed 36-byte dag-cbor/BLAKE3 profile of §2 is a rule for `parents` only. Cross-language vectors use null, bool, integers,
text, bytes, lists, maps. Floats are outside the cross-language subset.

## 5. What is frozen

| Frozen (a change is a major version bump) | Not promised |
|---|---|
| The envelope: the two keys, their order, the parent array encoding and sort rule, the link form, the CID derivation | Arbitrary Rust `T`. `MerkleNode<T>` is generic; only payloads whose canonical form is already frozen (`Ipld`, and types serializing to the §4 data model) carry the guarantee |
| Payload bytes for payloads within the §4 data model | A `T` whose `Serialize` changes, or emits non-canonical or non-DAG-CBOR-model values |

## 6. Who rejects what

Tested in `tests/merkle_adversarial.rs`, through
`canonical::from_canonical_dagcbor_checked::<MerkleNode<Ipld>>`. "Twin" means
the plain decoder `from_canonical_dagcbor` accepts the same bytes, so the
refusal is the checked door's.

| Input | Refused by | Error |
|---|---|---|
| Truncated link / bytes | decoder | `DecodingError` |
| Link missing the leading `00` | decoder | `DecodingError` |
| **Parent** link to a CID outside the dag-cbor/BLAKE3 profile | decoder (`ContentId` profile) | `DecodingError` |
| A link in the *payload* to any supported profile (raw, SHA-256, …) | accepted; it is payload data | n/a |
| Keys out of canonical order (twin) | checked door, canonicality stage | `NonCanonical` |
| Non-minimal integer (twin) | checked door, canonicality stage | `NonCanonical` |
| Duplicate map key | decoder | `DecodingError` |
| Missing `payload` / `parents` | decoder | `DecodingError` |
| Extra top-level field (twin) | checked door, typed round trip | `LossyDecode` |
| Parents unsorted or duplicated (twin) | checked door, typed round trip | `LossyDecode` |
| Bytes whose CID is not the claimed CID | **verification**, not decoding: `ContentAddressable::verify(&cid)` returns `false` | n/a |

Decoding never sees a "claimed CID"; a CID is only checked by recomputing it.
A reader holding bytes from an untrusted source uses the checked door **and**
`verify` against the CID it was told.

## 7. Identity is the canonical form

A node's identity is the CID of its canonical form, always recomputed, never
taken from the bytes it arrived as.

- **Order.** `parents` is a set. Decoding parents in any order yields the same
  logical node, so the same canonical bytes and CID. Plain serde decoding
  normalizes on purpose. The checked door additionally refuses input that was
  not already canonical for the typed node (§6), for readers that need the received bytes to be the
  hashed bytes.
- **Repeats.** `parents` has set semantics (§1). A repeated parent adds no
  edge, so dedup loses nothing.
- **Cycles are not checked here.** Decoding and verification never resolve a
  parent: they don't establish that it exists, that it is a `MerkleNode`, or
  that the graph is acyclic. Those are application invariants. A cycle of
  content links would need a hash fixed point, but traversals must not rely on
  that: keep a visited set (see the reconstruction example in `tests/store.rs`).
- **Back-references.** Any CID in the payload is hashed into the node's CID
  just as parents are, so it cannot name a node that is built from this one. A
  reference that may close a cycle (a symlink, say) is stored as something
  other than a content link, such as its target path, and a parent-edge
  traversal does not follow it. That is consumer policy; this crate has no
  generic traversal that enforces it.
