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
- **Parents array.** Major type 4, definite length, minimal header
  (`0x80|n` for n < 24, `98 nn` for n < 256, `99 nnnn` beyond; both boundaries
  are pinned by the 24- and 256-parent vectors).
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
duplicate keys, links as in §2. Cross-language vectors use null, bool, integers,
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
| Link to a CID outside the crate profile | decoder (`ContentId` profile) | `DecodingError` |
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
