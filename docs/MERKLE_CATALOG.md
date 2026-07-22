# The Merkle Structure Catalog

> The exhaustive catalog of Merkle / authenticated data structures this crate
> implements or plans to implement — the map behind the mission of being the
> **one-stop-shop for Merkle data structures in Rust + Python**, and the
> high-quality, high-performance option.
>
> The live, actionable tracker is **epic #30**; this document is the durable
> plain-text record: what each structure is, how its nodes relate to the
> crate's identity layer, and which researched variants were folded where.

## The identity layer every structure shares

Every node of every structure below is identified by a [`ContentId`](../src/content_id.rs)
— a CIDv1 (dag-cbor `0x71`, BLAKE3 `0x1e`, 32-byte digest) minted over the
node's canonical dag-cbor bytes via the [`ContentAddressable`](../src/trait_def.rs)
trait. Links between nodes are dag-cbor tag-42 CID links. A structure is
therefore **discoverable from its root CID**: root id + any store holding the
bytes fully determines (and proves) the whole structure. The causal-set node
shape [`MerkleNode`](../src/merkle.rs) covers DAGs whose links are a
deduplicated set; structures needing positional / order-significant / duplicate
links introduce sibling node shapes through the same trait.

## Issue index

| # | Structure | Tier | Phase |
|---|-----------|------|-------|
| [#31](https://github.com/hartsock/content-addressable/issues/31) | CID-addressed node store seam | core | Phase 0 |
| [#32](https://github.com/hartsock/content-addressable/issues/32) | Shared verifiable-proof API (inclusion/exclusion/consistency/range) | core | Phase 0 |
| [#33](https://github.com/hartsock/content-addressable/issues/33) | Merkle conformance vectors (separate, freezes structure bytes at rc1) | core | Phase 0 |
| [#34](https://github.com/hartsock/content-addressable/issues/34) | PyO3 exposure policy: every Merkle structure in content-addressable-py | core | Phase 0 |
| [#35](https://github.com/hartsock/content-addressable/issues/35) | Language-agnostic conformance + TS/Dart/Java byte-identity strategy | core | Phase 0 |
| [#36](https://github.com/hartsock/content-addressable/issues/36) | Quality bar: proptest + fuzz + coverage + differential | core | Phase 0 |
| [#37](https://github.com/hartsock/content-addressable/issues/37) | Criterion + comparative benchmarks | core | Phase 0 |
| [#38](https://github.com/hartsock/content-addressable/issues/38) | Lean 4 representations + proof obligations for Merkle structures | core | Phase 1 |
| [#39](https://github.com/hartsock/content-addressable/issues/39) | TLA+ models for Merkle structure protocols | advanced | Phase 1 |
| [#40](https://github.com/hartsock/content-addressable/issues/40) | Algebraic representation search: laws -> most efficient Rust encoding | advanced | Phase 1 |
| [#41](https://github.com/hartsock/content-addressable/issues/41) | merkle-reference (Gozala) spec conformance + interop | advanced | Phase 1 |
| [#42](https://github.com/hartsock/content-addressable/issues/42) | Generic Merkle DAG (generalizes MerkleNode) | core | Phase 2 |
| [#43](https://github.com/hartsock/content-addressable/issues/43) | Hash chain / Merkle linked list (folds skipchains, signed feeds, AAOSL) | core | Phase 2 |
| [#44](https://github.com/hartsock/content-addressable/issues/44) | Chunked-file verification tree — BLAKE3/Bao (folds flat hash list, THEX) | core | Phase 2 |
| [#45](https://github.com/hartsock/content-addressable/issues/45) | Merkle Mountain Range (MMR) | core | Phase 2 |
| [#46](https://github.com/hartsock/content-addressable/issues/46) | RFC 6962 verifiable log (folds Crosby-Wallach history tree, compact ranges) | core | Phase 2 |
| [#47](https://github.com/hartsock/content-addressable/issues/47) | Merkle radix trie: hexary Patricia (MPT) + binary EIP-7864 (folds NOMT engine) | core | Phase 2 |
| [#48](https://github.com/hartsock/content-addressable/issues/48) | Sparse Merkle Tree (folds compact variants, Poseidon zk-SMT, Jellyfish/JMT) | core | Phase 2 |
| [#49](https://github.com/hartsock/content-addressable/issues/49) | Merkle Search Tree (folds G-tree framework) | core | Phase 2 |
| [#50](https://github.com/hartsock/content-addressable/issues/50) | Prolly Tree (probabilistic B-tree) | core | Phase 2 |
| [#51](https://github.com/hartsock/content-addressable/issues/51) | Merkle B+-tree (MB-tree / EMB-tree) | core | Phase 2 |
| [#52](https://github.com/hartsock/content-addressable/issues/52) | Git object model (commit DAG over nested trees) | core | Phase 2 |
| [#53](https://github.com/hartsock/content-addressable/issues/53) | UnixFS-style chunked file + HAMT-sharded directory DAG | core | Phase 2 |
| [#54](https://github.com/hartsock/content-addressable/issues/54) | Nested Merkle trees (tree-of-trees composition) | core | Phase 2 |
| [#55](https://github.com/hartsock/content-addressable/issues/55) | Merkle forest with cross-referenced roots (folds CAR packaging) | core | Phase 2 |
| [#56](https://github.com/hartsock/content-addressable/issues/56) | Merkle Clock / Merkle-CRDT event DAG (folds hashgraph-style gossip DAGs) | advanced | Phase 3 |
| [#57](https://github.com/hartsock/content-addressable/issues/57) | Hash accumulators: Utreexo forest (folds Reyzin-Yakoubov async, CHKO strong) | advanced | Phase 3 |
| [#58](https://github.com/hartsock/content-addressable/issues/58) | Annotated Merkle trees: sum / aggregate / range / spatial (folds MS-SMT, DAPOL+, IntegriDB, MR-tree) | advanced | Phase 3 |
| [#59](https://github.com/hartsock/content-addressable/issues/59) | Verifiable log-backed maps & key transparency (Trillian, CONIKS/SEEMless/Parakeet, Merkle-squared) | advanced | Phase 3 |
| [#60](https://github.com/hartsock/content-addressable/issues/60) | zk-friendly append-only trees: frontier IMT + LeanIMT + indexed Merkle tree | advanced | Phase 3 |
| [#61](https://github.com/hartsock/content-addressable/issues/61) | Persistent Authenticated Dictionary — balanced-BST family (folds auth red-black/2-3, IAVL, treap/CMT, auth skip list) | advanced | Phase 3 |
| [#62](https://github.com/hartsock/content-addressable/issues/62) | Verkle trees + maintainable VC proof trees (adjacent; folds Hyperproofs/BalanceProofs) | advanced | Phase 3 |
| [#63](https://github.com/hartsock/content-addressable/issues/63) | Entangled Merkle trees / entangled forests (Snarl + version forests) | exotic | Phase 4 |
| [#64](https://github.com/hartsock/content-addressable/issues/64) | SeqHash (uniquely-represented sequence Merkle tree) | exotic | Phase 4 |
| [#65](https://github.com/hartsock/content-addressable/issues/65) | Persistent Merkle Vector (CID-RRB vector) [INVENTED] | invented | Phase 4 |
| [#66](https://github.com/hartsock/content-addressable/issues/66) | CID Indirection Atlas — cyclic-graph encoding for a DAG-only store [INVENTED] | invented | Phase 4 |
| [#67](https://github.com/hartsock/content-addressable/issues/67) | Merkle Time-Series Ring — retention-proof circular log [INVENTED] | invented | Phase 4 |

## Structures

### Phase 2 — Core structures

#### Generic Merkle DAG (generalizes MerkleNode) — [#42](https://github.com/hartsock/content-addressable/issues/42)

The foundational hash-linked object graph: immutable dag-cbor nodes whose edges are CIDs, so one root CID authenticates the entire reachable graph and identical subgraphs deduplicate automatically. Framed here as the GENERALIZATION of the existing causal-set MerkleNode: child links become ordered, optionally named, duplicate-bearing lists rather than an unordered parent set.

**Key points:**

- Generalizes existing causal-set MerkleNode: children as an ordered list of (optional name, CID) pairs, duplicates allowed — supersets the parent-set special case
- Node = canonical dag-cbor; links via CID (tag 42); parent bytes embed child CIDs verbatim so the root commits to all descendants; cycles structurally impossible
- Operations: put/get, path resolution, DFS/BFS walk with selectors, reachability pin/GC, structural diff that skips shared CIDs
- Inclusion proof = root-to-target block chain, O(depth x block size); no compact sibling proofs, no ordering/exclusion/consistency — those come from the specialized structures layered on top
- Substrate for every other entry in this list; must land first

**CID linkage:** Direct: this IS the CID layer. Every field may hold a CID link; discovery from a root CID is plain traversal (fetch, decode, recurse); GC is reachability over the same links.

**References:** <https://ipld.io/docs/data-model/> · <https://ipld.io/specs/codecs/dag-cbor/spec/> · <https://docs.ipfs.tech/concepts/merkle-dag/>

#### Hash chain / Merkle linked list (folds skipchains, signed feeds, AAOSL) — [#43](https://github.com/hartsock/content-addressable/issues/43)

The simplest append-only authenticated structure: each entry embeds its predecessor's CID, so the head commits to the whole history with O(1) append and single-CID state. Folds the doubly-linked skipchain variant, SSB/hypercore-style signed feeds, and the authenticated append-only skip list (AAOSL), which upgrades precedence proofs from O(n) to O(log n).

**Key points:**

- Node = dag-cbor {prev: CID|null, payload: CID|inline, seq}; O(1) append, total order, fork detection by head comparison; inclusion/precedence O(n) in the plain chain
- Forward links cannot live in immutable content-addressed nodes (child CID would change the parent) — doubly-linked behavior needs a separate index chain or mutable-pointer layer
- Folded: skipchains (Chainiac) and SSB/hypercore signed logs
- Folded: authenticated append-only skip list (Maniatis-Baker AAOSL) — deterministic tower heights = trailing zeros of seq give back-links to 2^j-earlier nodes, O(log n) membership/precedence hop paths, and timeline entanglement across mutually distrusting logs; formally verified in Agda (CPP 2021)
- Consistency between heads = ancestor check; no exclusion or range proofs

**CID linkage:** Head CID is the authenticator; walking prev (or AAOSL back[]) links reaches genesis, making full history discoverable from one CID. AAOSL linkage is computable from seq alone, so hop paths are self-verifying CAS fetches.

#### Chunked-file verification tree — BLAKE3/Bao (folds flat hash list, THEX) — [#44](https://github.com/hartsock/content-addressable/issues/44)

BLAKE3 is itself a binary Merkle tree over 1 KiB chunks, and Bao exposes that interior tree so any byte range of a blob verifies against the blob's ordinary BLAKE3 CID — the streaming-verification tree comes free from the hash the store already computes. Folds the flat hash list (BitTorrent v1 piece list) as the degenerate one-level case and THEX/Tiger-tree as the historical domain-separated binary variant.

**Key points:**

- One CID = both content address and verified-streaming root; encodings: combined (interleaved) vs outboard (beside untouched file); slice proofs for arbitrary byte ranges, O(log n) memory decode; chunk groups (iroh bao-tree) shrink outboard size
- Critical subtlety: interior chaining values are chunk-counter-keyed and lack the ROOT flag, so a chunk's standalone BLAKE3 CID != its CV inside a larger tree — CVs must be carried as data in outboard nodes {left/right: CID|null, left_cv/right_cv: 32B}
- Folded: flat hash list — root node {chunk_size, total_length, pieces: [CID...]}; O(n) proof but O(1) per-chunk self-verification; still the right profile for small manifests
- Folded: THEX/Tiger tree — origin of 0x00/0x01 leaf/interior domain separation (inherited by RFC 6962); in CID form, raw-codec leaves vs dag-cbor interiors supply the separation natively
- Every read verified incrementally before release — no unverified byte reaches the caller

**CID linkage:** Blob CID -> outboard root node -> subtree nodes -> raw chunk blocks: a two-way link between the plain BLAKE3 CID and the proof tree, so a store can serve verified slices of any blob discoverable purely from its content CID.

**References:** <https://github.com/n0-computer/bao-tree>

#### Merkle Mountain Range (MMR) — [#45](https://github.com/hartsock/content-addressable/issues/45)

A forest of perfect binary peaks whose sizes follow the binary representation of the element count; appends merge equal-height peaks and never rewrite existing nodes, and the peaks are bagged into a single root. The append-only-witness property (later proofs are supersets of earlier ones) was recently proven optimal for append-only accumulators.

**Key points:**

- Append: O(1) amortized new nodes, zero mutation of old ones (~2n total hashes); internal nodes {left: CID, right: CID}, bag node {size: n, peaks: [CID...]}
- Inclusion: leaf-to-peak path plus other peak CIDs, O(log n); consistency between sizes m<n by comparing peak-CID decompositions, O(log n)
- Perfect structural sharing in a CAS: every historical bag shares almost all subtree CIDs with successors; rewind/prune to any earlier size from stored peak CIDs
- No exclusion proofs — pair with a sorted structure
- Production: Grin/Tari chain state, OpenTimestamps calendars, Polkadot BEEFY light-client bridging

**CID linkage:** The bag node's CID is the accumulator value for size n; peaks -> internal nodes -> leaf payload CIDs make the entire history discoverable from one CID, and consistency checks are pure CID-set comparisons.

**References:** <https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md> · <https://docs.grin.mw/wiki/chain-state/merkle-mountain-range/> · <https://docs.rs/tari_mmr>

#### RFC 6962 verifiable log (folds Crosby-Wallach history tree, compact ranges) — [#46](https://github.com/hartsock/content-addressable/issues/46)

The standardized append-only Merkle tree behind Certificate Transparency, Rekor, and Go's sumdb: left subtree = largest power of two < n, with two proof types — inclusion and consistency — that make a log publicly auditable. Folds its ancestor (the Crosby-Wallach versioned history tree) and its underlying algebra (binary numeral trees / compact ranges).

**Key points:**

- Nodes {left: CID, right: CID}; raw-codec leaf CIDs vs dag-cbor interior CIDs supply the 0x00/0x01 domain separation natively; signed tree heads chain as {size, root: CID, prev_head: CID, sig}
- Proofs: inclusion O(log n) audit path; consistency O(log n) between any two sizes — a demonstration that the old root's subtree decomposition appears verbatim (same CIDs) under the new root
- Folded: Crosby-Wallach history tree — versioned formulation with frozen subtrees, membership proofs against ANY historical commitment, and safe payload pruning while keeping frozen hashes
- Folded: binary numeral trees / compact ranges — any [L,R) decomposes into O(log n) maximal perfect subtrees; range nodes {begin, end, roots: [CID]} merge associatively, enabling streaming O(log n)-memory builds, distributed/parallel construction, and range proofs; flat-tree numbering (hypercore) is the same algebra
- Completed subtrees are immutable, so successive sizes share node CIDs automatically in a CAS

**CID linkage:** Both roots of any two sizes resolve to overlapping node CIDs in the store; the head chain is itself a hash chain of CIDs, so the full log, all historical heads, and every proof are discoverable from the latest head CID.

**References:** <https://github.com/transparency-dev/merkle>

#### Merkle radix trie: hexary Patricia (MPT) + binary EIP-7864 (folds NOMT engine) — [#47](https://github.com/hartsock/content-addressable/issues/47)

The authenticated key-value trie family, folded per the binary-vs-n-ary rule: Ethereum's hexary Merkle Patricia Trie (branch/extension/leaf nodes, path compression) and its successor binary radix trie (EIP-7864 unified binary tree) are arity variants of one structure. Also folds NOMT-style page-packed trie engines as the physical-layout profile.

**Key points:**

- Node kinds: branch (16 child slots + optional value), extension {path, child: CID}, leaf {path, value|CID}; binary variant: {left: CID|null, right: CID|null} with bitpath compression and 31-byte stem nodes carrying 256 slots
- Proofs: inclusion = node path root->leaf (hexary ~few KB; binary ~4x smaller, 1 sibling/level); exclusion = path to divergence point (null slot or mismatching extension/leaf); multiproofs share upper paths
- Ethereum's 'inline nodes < 32 bytes' rule must be dropped or made a deterministic canonicalization rule — inlining changes parent bytes and thus CIDs
- EIP-7864 draft uses BLAKE3, so CIDv1+BLAKE3 node CIDs can literally double as the tree's commitment hashes
- Folded: NOMT/QMDB page-packed engines — a complete depth-6 binary subtrie (64 exit slots) per 4 KB page-object; one CAS fetch materializes six proof levels; page CID doubles as cache/transfer unit (~43k updates/s/thread reported)

**CID linkage:** State root CID reaches the full keyspace by resolving child CIDs recursively; empty subtrees are null (or a zero-CID sentinel) so only non-empty nodes materialize; page-native profile gives the DAG fanout <=64 per object and depth/6 hops.

**References:** <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/> · <https://eips.ethereum.org/EIPS/eip-7864> · <https://www.rob.tech/blog/introducing-nomt/> · <https://arxiv.org/pdf/2504.14069>

#### Sparse Merkle Tree (folds compact variants, Poseidon zk-SMT, Jellyfish/JMT) — [#48](https://github.com/hartsock/content-addressable/issues/48)

A conceptually complete depth-|H| binary tree where every key has a fixed leaf position given by its hash bits and empty subtrees hash to derivable per-level defaults — the structure that buys efficient non-interactive exclusion proofs. Folds the compact/cached variants, the Poseidon-hashed zk profile, and the Jellyfish Merkle Tree as the versioned LSM-engineered profile.

**Key points:**

- Internal {left: CID|EMPTY(d), right: CID|EMPTY(d)}; EMPTY(d) from a derivable 256-entry default table, never stored; compact variants (Haider, Dahlberg caching, Celestia smt) collapse single-leaf subtrees to stored depth ~log n
- Proofs: inclusion AND exclusion both ~256 siblings uncompressed, bitmap-compressed to ~log n real hashes; parallelizes well (Angela) since key positions never move; no range proofs (hashing destroys key order)
- Folded: Poseidon/algebraic zk-SMT (iden3, Polygon zkEVM) — dual-digest pattern: every node carries both the dag-cbor CID (store identity) and the Poseidon field digest (circuit identity), bound at the root by {poseidon_root, root: CID}; leaf domain separation Poseidon(k,v,1)
- Folded: Jellyfish Merkle Tree (Diem/Aptos/Penumbra) — versioned SMT with radix-16 physical nodes over 4-level binary subtrees; in a CAS its (version, nibble-path) addressing collapses to content addressing, stale-node indices become root-reachability GC, and version snapshots {version, root: CID, parent: CID} share unchanged subtree CIDs for free; adds range proofs for state-sync restore
- Use cases: revocation/nullifier sets, rollup state, map layers of transparency systems

**CID linkage:** Root CID -> full map discovery by resolving only non-default links; default CIDs are computed constants; JMT profile chains version snapshot objects so historical roots stay reachable.

**References:** <https://eprint.iacr.org/2016/683> · <https://github.com/celestiaorg/smt> · <https://developers.diem.com/papers/jellyfish-merkle-tree/2021-01-14.pdf>

#### Merkle Search Tree (folds G-tree framework) — [#49](https://github.com/hartsock/content-addressable/issues/49)

A deterministic, history-independent B-tree-like search tree where each key's layer derives from its hash, so the tree shape is a pure function of the key set and replicas converge to identical root CIDs — the AT Protocol/Bluesky repo index and the classic CRDT anti-entropy primitive. Folds the G-tree (geometric search tree) framework that generalizes MST/prolly/zip-trees.

**Key points:**

- Node = {layer, entries: [{keySuffix (prefix-compressed), value: CID|inline, subtree: CID|null}], leftmostSubtree: CID|null}; prefix compression must be part of the canonical encoding or identical logical nodes diverge in CID
- O(log n) insert/delete/lookup, ordered iteration and range scans; O(1) set/map equality via root CID; anti-entropy diff walks only subtrees whose CIDs differ
- Exclusion proofs are natural: deterministic shape fixes the unique node where a key would reside, shown absent between ordered neighbors
- Folded: G-tree framework (Farmer & Meyer) — geometric rank = f(hash(item)) subsumes MST, prolly, zip/skip-trees in one canonical construction; the (k,2)-zip-tree instantiation offers tunable node width with non-probabilistic boundaries and is a candidate greenfield design; pairs with range-based set reconciliation; keyed rank hash mitigates grinding
- Production: Bluesky signed data repositories

**CID linkage:** One root CID makes the entire ordered map discoverable by BFS; two independently built replicas of the same set produce byte-identical block DAGs, so reconciliation descends only into unequal child CIDs.

**References:** <https://atproto.com/specs/repository>

#### Prolly Tree (probabilistic B-tree) — [#50](https://github.com/hartsock/content-addressable/issues/50)

A B-tree-shaped Merkle tree whose node boundaries come from content-defined chunking over the sorted entry stream, making the tree canonical with high probability and edits O(log n) block churn. The storage engine of Noms/Dolt, and the reference design for git-like diff and three-way merge over big sorted datasets.

**Key points:**

- Leaf chunk = canonical dag-cbor array of sorted (key, value|CID) pairs; internal node = (lastKeyOfChild, child CID) pairs; chunker config (rolling hash, target size) MUST be pinned in the format for cross-writer convergence
- Structural diff and three-way merge proportional to the delta — shared chunk CIDs short-circuit; every root CID is a full immutable snapshot
- Proofs: inclusion O(log n); exclusion via the leaf chunk spanning the missing key (ordered neighbors); range proofs with completeness from ordering
- Canonical-form claims are w.h.p., not absolute (chunker-dependent) — contrast with MST's exact determinism
- Distinct from MST by balancing rule: rolling-hash boundaries vs layer-by-key-hash; keep both, they occupy different design points

**CID linkage:** Root CID -> internal nodes -> leaf chunks reaches the whole ordered index; values above a threshold are CID links to blob trees; cross-version dedup is automatic since unchanged chunks keep their CIDs.

**References:** <https://docs.dolthub.com/architecture/storage-engine/prolly-tree> · <https://github.com/attic-labs/noms>

#### Merkle B+-tree (MB-tree / EMB-tree) — [#51](https://github.com/hartsock/content-addressable/issues/51)

The classic authenticated database index (SIGMOD 2006): a disk-oriented B+-tree with each child pointer paired to the child's hash, serving range queries with verification objects that guarantee completeness. Folds the embedded EMB-tree and the vector-commitment-fanout variant.

**Key points:**

- Internal node = {keys: [bytes], children: [CID]} (len children = len keys + 1); classic leaf sibling 'next' pointer must be dropped — forward CID links are unconstructible bottom-up; parent ordering supplies leaf iteration
- Range completeness: VO includes the two boundary tuples just outside the range plus covering paths, so dropped rows are detectable; exclusion via bracketing adjacent keys
- Folded: EMB-tree — nested inner Merkle tree per node cuts VO to O(log n) total hashes; folded: vector-commitment fanout (q-mercurial/KZG) — O(1)-per-level openings at the cost of trusted setup
- High fanout = shallow trees and I/O efficiency; shape is insertion-order-dependent (not history-independent) — use MST/prolly when canonical roots are required
- No native cross-version consistency; link successive roots externally

**CID linkage:** Root CID reaches every node and value; a manifest block pairs the root CID with fanout parameters and a publisher signature for the outsourced-database trust model.

#### Git object model (commit DAG over nested trees) — [#52](https://github.com/hartsock/content-addressable/issues/52)

Two composed Merkle structures: a multi-parent commit history DAG plus a nested tree-of-trees filesystem snapshot per commit, with unchanged subtrees shared byte-for-byte across commits. The archetype every versioned CAS descends from, and directly relevant to kyln/P4-Git provenance work.

**Key points:**

- Commit = {tree: CID, parents: [CID...], author, message}; tree = sorted {name, mode, link: CID} entries; blob = raw leaf — canonical sorting is what makes same-content => same-CID hold across writers
- Ancestry, reachability, and merge-base are DAG queries; fetch/push = DAG completion (send blocks the other side's heads cannot reach)
- Proofs: file-at-path-in-commit = commit + tree path + blob, O(path depth) blocks; ancestry = commit chain; signed commits/tags bind identity to a root CID
- Append-only is social/replica-enforced, not structural — no exclusion or global-consistency proofs
- Three-way merge and structural diff prune shared CIDs

**CID linkage:** A branch head is one commit CID from which the entire history (parents links) and every snapshot (tree links, named entries) is discoverable; refs/tags are single nodes holding a target CID.

**References:** <https://git-scm.com/book/en/v2/Git-Internals-Git-Objects> · <https://ipld.io/specs/codecs/dag-pb/spec/>

#### UnixFS-style chunked file + HAMT-sharded directory DAG — [#53](https://github.com/hartsock/content-addressable/issues/53)

How large files and huge directories become Merkle DAGs: files chunk (fixed-size or content-defined) into raw leaves under balanced or trickle layout trees with size-annotated links; directories hold name->CID entries and transparently switch to HAMT sharding at scale. Restores dedup, seek, and partial verification that a single flat hash denies.

**Key points:**

- Interior file node = {type: file, links: [{cid, byte_size}...]} — size annotations give seek(offset) in O(depth); balanced layout for random access, trickle for streaming
- Directory = {name -> CID}; HAMT shard = {fanout, bitmap, links} keyed by hash-of-name digits — million-entry directories stay O(log n) per lookup/update, with exclusion proofs for absent names (empty slot in terminating shard)
- Byte-range proofs: O(depth) interior nodes prove 'these bytes are exactly offsets [a,b) of the file with this root CID'
- CDC (Rabin) parameters must be pinned for convergent adds; identical chunks dedup across files automatically
- Complementary to the Bao entry: explicit in-band layout DAG vs hash-native interior tree — both belong in the crate

**CID linkage:** From one root CID resolve /path/to/file then any byte offset purely by following size-annotated CID links, every hop independently verifiable.

**References:** <https://github.com/ipfs/specs/blob/main/UNIXFS.md> · <https://ipld.io/specs/codecs/dag-pb/spec/> · <https://docs.ipfs.tech/concepts/file-systems/>

#### Nested Merkle trees (tree-of-trees composition) — [#54](https://github.com/hartsock/content-addressable/issues/54)

First-class composition pattern (explicitly requested): a leaf or field of an outer authenticated structure commits to the root of an inner structure, so one outer root CID authenticates a structure of structures and proofs compose by concatenation. Instances: git commit->tree, Ethereum header->tries, epoch logs over map roots, manifest trees over shard roots.

**Key points:**

- Seam must be typed: {kind: 'subtree-root', root: CID, structure: 'mst|log|hamt|...'} — untagged bare hashes invite cross-layer domain-confusion/second-preimage forgeries; verifier checks the tag at every seam
- Composed inclusion proof = outer proof O(log n) ++ inner proof O(log m); exclusion and consistency compose the same way when both layers support them
- Each layer picks the structure optimized for its own query: chronological outer, keyed inner, etc.
- Update = install new inner root CID and bubble up the outer path; layered diff recurses only into changed inner roots
- Shared child trees dedup across outer versions automatically since inner roots are ordinary CID links

**CID linkage:** Traversal descends the outer structure to a leaf, dereferences the inner root CID, and continues inside the inner structure; arbitrarily deep nesting works identically.

**References:** <https://eprint.iacr.org/2021/453> · <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/> · <https://git-scm.com/book/en/v2/Git-Internals-Git-Objects>

#### Merkle forest with cross-referenced roots (folds CAR packaging) — [#55](https://github.com/hartsock/content-addressable/issues/55)

Composition pattern (explicitly requested): independent trees whose roots reference each other via anchor records — trust is braided while structures stay operationally separate, enabling federation (log witnessing, per-dataset trees under an org audit tree, kyln-style derived-repo anchoring source-repo roots). Folds the CAR archive as the packaged-forest transport format.

**Key points:**

- Anchor record = {anchored_root: CID, tree_id/type, size_or_head_position, sig?, timestamp} committed as a leaf of the anchoring tree; mutual/periodic anchoring builds a DAG of roots with cycles impossible (hash acyclicity) — a temporal partial order over the forest
- Chained proofs: inclusion of X in B plus inclusion of B's root in A = 'A commits to X' at O(log|A| + log|B|); anchors double as ordering/freshness evidence
- Distinct from nesting: trees remain separately maintained; only cross-links' inclusion proofs are added
- Folded: CAR archive (CARv1/v2) — header {roots: [CID...]} + (CID, block) sections; a container, NOT an authenticated structure: order unspecified, blocks may be absent/extraneous, CARv2 index untrusted — always verify by re-hashing and walking from declared roots; a minimal CAR carrying just root-to-target blocks is the standard self-contained proof envelope for ANY structure in this list
- Forest-wide GC/pinning = multi-root reachability

**CID linkage:** Every root is a CID, so cross-references are ordinary links: from whichever root you trust, traverse to the anchor record, dereference anchored_root, and continue inside the foreign tree — the whole forest is discoverable from one CID.

**References:** <https://research.swtch.com/tlog> · <https://github.com/transparency-dev/witness> · <https://ipld.io/specs/transport/car/carv1/> · <https://ipld.io/specs/transport/car/carv2/>

### Phase 3 — Advanced structures

#### Merkle Clock / Merkle-CRDT event DAG (folds hashgraph-style gossip DAGs) — [#56](https://github.com/hartsock/content-addressable/issues/56)

A grow-only DAG where each event hash-links the current heads, embedding causal order directly in link structure (A before B iff A reachable from B); attaching CRDT payloads makes replica merge a DAG union with convergence guaranteed. The closest published relative of the existing causal-set MerkleNode. Folds hashgraph-style two-parent gossip DAGs as the disciplined, consensus-bearing variant.

**Key points:**

- Event node = {parents: [CID...], payload: CID|inline, sig?}; replica state = its head/frontier CID set — the root of trust is the frontier, not a fixed root; anti-entropy = exchange heads, fetch unknown ancestors, stop at shared CIDs
- Replaces version vectors: no membership knowledge, unbounded anonymous replicas over gossip/DHT; cost = unbounded history growth
- Proofs: happened-before = link path from B back to A, self-verifying; NO exclusion/completeness — a replica can withhold branches undetectably (the availability trade; transparency logs fix it)
- Folded: hashgraph-style event DAGs (Swirlds; Narwhal/Aleph kin) — fixed two-parent shape {creator, self_parent: CID, other_parent: CID, txs, sig} records gossip-about-gossip; virtual voting derives BFT total order from structure alone; ancestry/'strongly-see' proofs are parent-link paths plus signature checks
- Natural first composition target over the generic Merkle-DAG entry

**CID linkage:** Discovery anchor is the head set walking backward; genesis events have empty parents; a bottom event CID doubles as a stable identity for the replicated object; shared ancestors dedup by CID and terminate sync traversal.

**References:** <https://arxiv.org/abs/2004.00107> · <https://research.protocol.ai/publications/merkle-crdts-merkle-dags-meet-crdts/> · <https://www.swirlds.com/downloads/SWIRLDS-TR-2016-01.pdf> · <https://arxiv.org/abs/2105.11827>

#### Hash accumulators: Utreexo forest (folds Reyzin-Yakoubov async, CHKO strong) — [#57](https://github.com/hartsock/content-addressable/issues/57)

Dynamic set accumulators built from forests of perfect binary Merkle trees where verifiers keep only O(log n) roots: Utreexo (add/delete for stateless UTXO validation), folded with the Reyzin-Yakoubov asynchronous accumulator (add-only, version-skew-tolerant witnesses) and the CHKO strong universal accumulator (untrusted-manager add/delete with published update proofs).

**Key points:**

- Utreexo: adds merge equal-height trees like a binary-counter increment; delete-with-proof swaps and restructures to keep trees perfect; state node {num_leaves, roots: [CID|null], prev: CID}; inclusion O(log n) siblings; batch proofs dedup shared interior nodes; no exclusion, no compact consistency (replay per-block update data; held proofs refresh per batch)
- Folded: Reyzin-Yakoubov async accumulator — add-only means old roots remain live subtree addresses forever (merging creates parents, never rewrites children); witnesses verify across accumulator/witness version skew and need only O(log n) refreshes total; MMR-style constructions proven optimal (CRYPTO 2025)
- Folded: CHKO strong accumulator — sorted-leaf Merkle search tree adds non-membership (adjacent-pair) AND per-op update proofs {op, before_root: CID, after_root: CID, touched path}; the untrusted-manager property becomes 'replay the op-record CID chain from genesis'
- In a shared CAS, wire proofs collapse to CAS paths from a root CID; untouched subtrees share CIDs across states
- Use: stateless validation, offline-holder credential sets, auditable revocation registries

**CID linkage:** Accumulator state nodes chain via prev: CID; every root (current or historical, in the async variant) is a resolvable CAS address, making version-skewed verification a plain graph-reachability fact.

#### Annotated Merkle trees: sum / aggregate / range / spatial (folds MS-SMT, DAPOL+, IntegriDB, MR-tree) — [#58](https://github.com/hartsock/content-addressable/issues/58)

One implementation seam, many structures: trees whose nodes carry annotations (sums, counts, min/max, interval bounds, MBRs) INSIDE the hashed bytes, so verifiers recombine child annotations at every exposed link and aggregate answers become provable. Folds Merkle-sum/proof-of-liabilities trees, the MS-SMT (Taproot Assets), authenticated segment/interval trees (IntegriDB), and Merkle R-trees/quadtrees.

**Key points:**

- Core rule: child annotations MUST be in the parent's hash preimage — hashing only aggregates enables the known sum-splitting attack; with CID linkage this is structural (parent bytes embed each child's full node bytes)
- Sum trees (Maxwell PoL, DAPOL+): root commits map + conserved total; per-user O(log n) (hash,sum) path proofs; DAPOL+ adds Pedersen commitments + Bulletproofs range proofs (no negative balances) and padding for user-count privacy
- Folded: MS-SMT (Taproot Assets) — SMT x sum annotation: exclusion proofs double as proof-of-no-hidden-balance; conservation (parent.sum == l.sum + r.sum) locally checkable during any CAS walk
- Folded: segment/interval trees (Martel et al., IntegriDB) — verifiable COUNT/SUM/MIN/MAX over [a,b] via the O(log n) canonical covering; completeness from committed bounds; d-dimensional = nested trees linked by CID, O(log^d n)
- Folded: spatial MR-tree/MR*-tree and Merkle quadtree/KD-tree — window/kNN completeness VOs from committed MBRs (verifier checks no pruned region intersects the query); quadtree/KD with pinned split rules are history-independent (canonical roots) while R-trees are insertion-order-dependent
- Generalizes to any monoid — implement the annotation seam once, instantiate sum/aggregate/spatial profiles

**CID linkage:** Annotations live in canonical dag-cbor node bytes so the CID itself commits to them; sums/bounds act as verifiable aggregate indexes over the DAG, checkable node-locally without fetching whole subtrees.

**References:** <https://github.com/Roasbeef/bips/blob/bip-taro/bip-taro-ms-smt.mediawiki>

#### Verifiable log-backed maps & key transparency (Trillian, CONIKS/SEEMless/Parakeet, Merkle-squared) — [#59](https://github.com/hartsock/content-addressable/issues/59)

The transparency-composition family: an authenticated map driven by an append-only mutation log with a signed head chain (Trillian's verifiable map), plus the privacy-preserving key-transparency lineage (CONIKS VRF prefix trees, SEEMless/Parakeet aZKS as deployed in WhatsApp), and Merkle-squared's log-of-embedded-prefix-trees that makes monitoring polylog and epoch-free.

**Key points:**

- Trillian recipe: SMT map + mutation log + map-head log; SignedMapHead = {revision, mapRoot: CID, mutationLogRoot: CID, prevHead: CID, sig} — current contents, full history, and the exact mutation sequence between revisions all reachable from one head CID; equivocation detected by comparing signed heads; full-map correctness by replay
- Folded: CONIKS/SEEMless/Parakeet — leaf positions = VRF(username) so CAS contents leak no identities; epoch STR hash chain; append-only (aZKS) claims become 'old CIDs still reachable' via structural sharing across epochs
- Folded: Merkle-squared — every chronological-tree node carries a prefix-tree root over its leaf span ({left: CID, right: CID, prefix_root: CID}): lookup O(log^2 n), total monitoring cost O(log^2 n), no epoch batching; the canonical log-of-trees exemplar
- Proof menu: per-key inclusion/exclusion (compressed SMT/prefix path), log inclusion + consistency O(log n), append-only proofs between epochs
- The flagship application of the nested-trees composition entry

**CID linkage:** Three linked DAGs under one head object; appends mint O(log n) new log nodes each bundling a new prefix-tree root while sharing unchanged prefix subtrees by CID — the dedup is what keeps storage near-linear.

**References:** <https://github.com/google/trillian/blob/master/docs/VerifiableDataStructures-Latest.md> · <https://github.com/facebook/akd>

#### zk-friendly append-only trees: frontier IMT + LeanIMT + indexed Merkle tree — [#60](https://github.com/hartsock/content-addressable/issues/60)

The circuit-oriented append-only tree family: fixed-depth incremental Merkle trees maintained from an O(depth) frontier with precomputed zero-subtree constants (Ethereum deposit contract, Semaphore, Tornado), the LeanIMT successor with dynamic depth, and Aztec's indexed Merkle tree whose sorted linked leaves make exclusion proofs one membership proof instead of a 254-level sparse path.

**Key points:**

- Frontier IMT: state = {depth, next_index, frontier: [CID per level]}; append O(depth) touching only the frontier; constant-shape O(depth) inclusion proofs (circuit-friendly); recent-roots ring buffer lets slightly-stale proofs verify; no update/delete — spent-ness via external nullifiers
- CAS-native win: each zero-subtree of height k is ONE universal node stored once and shared by CID across every tree of every application at that depth
- Folded: LeanIMT (Semaphore v4) — single-child parent adopts child value verbatim, depth grows with leaf count; CAS mirror: parent slot holds the child CID directly, keeping CID DAG and digest tree isomorphic
- Folded: indexed Merkle tree (Aztec nullifier tree) — leaves (value, next_index, next_value) thread a sorted linked list; exclusion = one 'low leaf' inclusion + 2 comparisons; depth tracks element count not keyspace; the list MUST use logical (index, value) pointers, never next-CID links (successor CID churn would cascade rewrites)
- Dual-digest pattern throughout: Poseidon/keccak digest in-circuit, CID in-store, bound per node

**CID linkage:** Frontier/state nodes chained by prev: CID give an audit history; appends share every untouched subtree CID with the previous state — structural persistence for free; root-state node binds size, root CID, and digest world.

**References:** <https://eth2book.info/latest/part2/deposits-withdrawals/contract/>

#### Persistent Authenticated Dictionary — balanced-BST family (folds auth red-black/2-3, IAVL, treap/CMT, auth skip list) — [#61](https://github.com/hartsock/content-addressable/issues/61)

Path-copying persistence over hash-annotated search trees: every update mints O(log n) new nodes and a new root CID while all versions share unchanged subtrees — the structure a CAS natively wants to be, with provable queries against every historical version. Folds authenticated red-black/2-3 trees, Cosmos IAVL, the deterministic Merkleized treap (Cartesian Merkle Tree), and the rank-augmented authenticated skip list.

**Key points:**

- Node = {key, value: CID|inline, balance metadata, left: CID|null, right: CID|null}; balance metadata must be in the hashed bytes so verifiers can check tree validity; version-index chain {version, root: CID, prev} makes every snapshot reachable
- Proofs: inclusion and exclusion (adjacent-keys) O(log n) at ANY version; cross-version diff by parallel descent pruning equal subtree CIDs — O(changes x log n)
- Folded: authenticated red-black/2-3 trees (Naor-Nissim; AGT ISC 2001) — worst-case O(log n) bounds but rotation-driven shape is insertion-order-dependent: NOT history-independent, replicas with equal sets can have different root CIDs
- Folded: IAVL/IAVL+ (Cosmos production) — persistent AVL with ordered range scans and ICS-23 proofs; CID-native profile should drop the creating version from node bytes to restore structural dedup
- Folded: Merkleized treap / Cartesian Merkle Tree — priority = hash(key), recomputed by verifiers, never stored: canonical shape, root CID = set fingerprint, expected O(log n) split/join set algebra; key adversarial-grinding mitigated by keyed hashing
- Folded: Goodrich-Tamassia rank-augmented skip list (DPDP engine) — position-addressed (select/rank) proofs; determinize tower heights from hash(key) for unique representation; shares less across versions than tree shapes

**CID linkage:** Path copying IS CAS structural sharing: each update writes O(log n) blocks mixing new CIDs and shared old CIDs; with the deterministic-treap profile, set equality upgrades to plain root-CID comparison.

**References:** <https://github.com/cosmos/iavl>

#### Verkle trees + maintainable VC proof trees (adjacent; folds Hyperproofs/BalanceProofs) — [#62](https://github.com/hartsock/content-addressable/issues/62)

The vector-commitment branch of the design space: high-arity tries whose nodes commit to children with Pedersen/IPA or KZG commitments, replacing per-level sibling hashes with single openings and aggregating multi-key witnesses to ~100-150 bytes/key. Explicitly ADJACENT for a hash-CAS crate (curve ops, trusted setup, not post-quantum) but cataloged as the proof-size benchmark and for one directly transferable idea.

**Key points:**

- Identity splits in two: the commitment (curve point, what proofs open against) vs the CID (node bytes, retrieval) — a CAS must carry both; verifiers additionally check each child's stored commitment matches the parent's opening at that index
- Node shapes: internal {commitment, children: map index->CID (sparse, <=256)}; stem node {stem: 31B, commitment, suffixCommitments, slots}; root object {rootCommitment, root: CID}
- Homomorphic delta updates: change one child without recomputing others; not PQ-safe — why Ethereum pivoted to EIP-7864 binary trees
- Folded: Hyperproofs / BalanceProofs / Pointproofs — maintainable proof trees (all n position-proofs updated in O(log n) or O(sqrt(n) log n) per write) with sublinear aggregation; pairing-based and out-of-band from the CAS
- Transferable to hash trees: the memoized sibling-path cache — a maintained proof-serving layer updated O(log n) per write, serving any inclusion proof in O(1) — implement this for the RFC 6962/SMT entries

**CID linkage:** The children map makes the tree walkable from the root CID exactly like a hash trie; a head node {scheme, params: CID (SRS), commitment, proof_root: CID, data_root: CID} binds the algebraic world to the CAS world.

**References:** <https://vitalik.eth.limo/general/2021/06/18/verkle.html> · <https://eips.ethereum.org/EIPS/eip-6800>

### Phase 4 — Exotic & invented

#### Entangled Merkle trees / entangled forests (Snarl + version forests) — [#63](https://github.com/hartsock/content-addressable/issues/63)

Composition pattern (explicitly requested), two senses folded: Snarl weaves alpha-entanglement parity codes through a file's Merkle tree so missing interior nodes or leaves are repairable from lattice neighbors without full replication; node-sharing entangled version forests entangle a file's whole version history into one forest via shared subtree CIDs for efficient multi-version auditing.

**Key points:**

- Snarl-style: chunks XOR-entangled into strands; entanglement manifest {strands: [{parity: CID, covers: [CID...]}], lattice_params(alpha, s, p)} linked from the root manifest — layout tree AND repair lattice discoverable from one CID
- Repair correctness is self-proving in a CAS: a reconstructed block must re-hash to its known CID
- Version-forest sense: per-version roots share unchanged node CIDs (free in a CAS); version-chain node {version_n: CID, prev: CID} walks the forest; shared CIDs are cheap cross-version non-modification evidence
- Standard O(log n) inclusion proofs per tree; availability-aware fetch planning chooses data-or-parity paths
- Target use: resilient archives where losing interior nodes must not orphan leaves; multi-version file auditing

**CID linkage:** Both senses are pure CID-link graphs: parity blocks and covered chunks are addressed by CID from the manifest; version forests are ordinary trees whose sharing is literal CID identity.

**References:** <https://www.researchgate.net/publication/356759481_Snarl_entangled_merkle_trees_for_improved_file_availability_and_storage_utilization> · <https://www.researchgate.net/figure/Entangled-Merkle-Forest-Architecture_fig1_373016284>

#### SeqHash (uniquely-represented sequence Merkle tree) — [#64](https://github.com/hartsock/content-addressable/issues/64)

A deterministically shaped hash tree over a position-ordered sequence (VerSum, CCS 2014): merge rounds decided purely by a deterministic function of child hashes, so any two parties holding the same sequence build bit-identical trees — root-CID equality means sequence equality, with O(log n) concatenation and splitting. Fills the canonical-sequence niche no keyed structure (MST/prolly) covers.

**Key points:**

- Blocks: leaf {item: CID|inline}; internal {round, size, children: [CID]}; merge decisions recomputed by verifiers from child hashes — no randomness or builder state stored
- O(log n) concat and split (only 'seam' blocks minted); O(1) equality via root; append = concat with singleton (the VerSum log workload)
- Proofs: position-i inclusion O(log n); slice = covering canopy + boundary paths with positions authenticated by committed size annotations; extension consistency = shared canopy
- Common subsequences share interior CIDs across versions — automatic CAS dedup
- Prior art anchor for the invented persistent-merkle-vector entry (canonical but no radix indexing/splice)

**CID linkage:** Root CID reaches every element in order via size-guided descent; independent builders of equal sequences produce byte-identical block DAGs.

**References:** <https://dl.acm.org/doi/10.1145/2660267.2660327>

#### Persistent Merkle Vector (CID-RRB vector) [INVENTED] — [#65](https://github.com/hartsock/content-addressable/issues/65)

NOVEL/SPECULATIVE: an authenticated relaxed-radix-balanced (RRB) persistent vector — every node a canonical dag-cbor block with up to 32 child CIDs and size tables committed into the hash — giving the crate a general-purpose verifiable 'Vec' with O(log32 n) access proofs and O(log n) verifiable concat/slice/splice. RRB vectors are well studied but no published variant is authenticated; no known Merkle sequence supports efficient verifiable splice.

**Key points:**

- Node kinds: interior {level, children: [CID; <=32], sizes: [u64] only when relaxed, count}; leaf {values: [inline|CID; <=32]}; root header {root: CID, tail: CID, count} for O(1) amortized push_back
- Proofs: index inclusion = ceil(log32 n) node path with radix/size-table navigation replayed by the verifier; range = subtree frontier; out-of-range refuted by committed count (no exclusion machinery needed)
- Transition proofs: the O(log n) new spine plus reused child CIDs prove the new root differs from the old only as claimed (update/push/concat)
- Concat/slice preserve structural sharing — operations unixfs-style chunk DAGs cannot do without rewriting the index
- Foundation primitive: deque/priority-queue/recency-spine variants derive by swapping the committed monoid annotation; cite SeqHash and RRB literature as prior art in the issue

**CID linkage:** All children are CID links so the whole vector walks from the root CID; version diff short-circuits on equal subtree CIDs; most snapshots share most blocks.

**References:** <https://dl.acm.org/doi/10.1145/3110260> · <https://github.com/clojure/core.rrb-vector/blob/master/doc/rrb-tree-notes.md> · <https://github.com/arazabishov/pvec-rs>

#### CID Indirection Atlas — cyclic-graph encoding for a DAG-only store [INVENTED] — [#66](https://github.com/hartsock/content-addressable/issues/66)

NOVEL/SPECULATIVE: a two-layer encoding that stores arbitrary — including cyclic — graphs in a CAS that only permits DAGs: node blocks name out-edges by local ordinals (never by CIDs that could point back), and one atlas block binds ordinal->CID for the component, so the wire structure stays acyclic while full graph semantics (doubly-linked lists, dependency cycles, state machines) are restored. Addresses a real IPLD limitation with no principled published solution.

**Key points:**

- Content node = {payload: CID|inline, out_edges: [{label, target: ordinal}]} — contains no CIDs of graph peers, so its hash is independent of any cycle it participates in; atlas = {bindings: [CID; n], entry_points, canonicalization: policy CID}
- Wire shape is a two-level DAG (atlas -> nodes -> payloads; nothing links the atlas); graph root CID = atlas CID
- Canonical ordinal assignment (deterministic labeling; creation-order for mutable graphs) makes isomorphic graphs converge to one CID — graph equality = CID equality under the committed policy
- Proofs: node inclusion = binding lookup (shard the atlas as a Merkle vector for O(log n) mutation and proof cost); non-edge proven by a node's committed exhaustive out_edges list alone; cycles provable by a path returning to its start ordinal
- Shared subgraphs between atlases reuse the same node-block CIDs

**CID linkage:** Edge traversal = look up ordinal in bindings, fetch that CID; everything (nodes, edges, payloads) is discoverable from the atlas CID while every individual block remains an ordinary immutable CAS object.

**References:** <https://ipld.io/docs/data-model/> · <https://ipld.io/design/> · <https://soc1024.ece.illinois.edu/gpads/gpads-full.pdf>

#### Merkle Time-Series Ring — retention-proof circular log [INVENTED] — [#67](https://github.com/hartsock/content-addressable/issues/67)

NOVEL/SPECULATIVE: a fixed-capacity ring of B time-bucketed Merkle subtrees plus a 'retirement MMR' accumulating the root CID of every evicted bucket — making circular-overwrite semantics part of the commitment. Proves both presence within the retention window and that data was retained its full window then evicted on schedule ('provably gone, commitment survives'); the natural shape for flight recorders and GDPR-style bounded retention.

**Key points:**

- Ring root = {capacity B, bucket_span, head_index, epoch, buckets: [CID; B], retired_mmr: CID, retention_policy: CID}; bucket = small Merkle tree over samples {t, payload: CID|inline, source}
- Rotation is one atomic root transition: seal current bucket, append its root CID + epoch to the retirement MMR, advance head — transition proof = old root, new root, sealed bucket root, MMR append path O(log total_epochs)
- In-window inclusion: committed head/epoch arithmetic selects the bucket + sample path, O(log samples_per_bucket); eviction proof: timestamp maps to epoch older than head - B plus retirement-MMR inclusion of that epoch's bucket root
- Retirement MMR gives transparency-log-style append-only consistency across ring states; evicted buckets' blocks are GC-able from the CAS while their commitments remain
- Downsample-on-evict: link an aggregate summary CID beside the retired root; no published structure commits fixed-capacity overwrite semantics

**CID linkage:** Everything live is reachable from the ring root CID; everything ever evicted is reachable as a commitment (bucket root CID + eviction epoch) via the retired_mmr link — presence and absence are both CID-graph facts.

**References:** <https://arxiv.org/pdf/2210.11702> · <https://datatracker.ietf.org/doc/html/rfc6962> · <https://arxiv.org/html/2605.00065>


## Cross-cutting seams and gates (Phases 0–1)

### Phase 0 — Foundations

- **CID-addressed node store seam** — [#31](https://github.com/hartsock/content-addressable/issues/31)
- **Shared verifiable-proof API (inclusion/exclusion/consistency/range)** — [#32](https://github.com/hartsock/content-addressable/issues/32)
- **Merkle conformance vectors (separate, freezes structure bytes at rc1)** — [#33](https://github.com/hartsock/content-addressable/issues/33)
- **PyO3 exposure policy: every Merkle structure in content-addressable-py** — [#34](https://github.com/hartsock/content-addressable/issues/34)
- **Language-agnostic conformance + TS/Dart/Java byte-identity strategy** — [#35](https://github.com/hartsock/content-addressable/issues/35)
- **Quality bar: proptest + fuzz + coverage + differential** — [#36](https://github.com/hartsock/content-addressable/issues/36)
- **Criterion + comparative benchmarks** — [#37](https://github.com/hartsock/content-addressable/issues/37)

### Phase 1 — Formal spine

- **Lean 4 representations + proof obligations for Merkle structures** — [#38](https://github.com/hartsock/content-addressable/issues/38)
- **TLA+ models for Merkle structure protocols** — [#39](https://github.com/hartsock/content-addressable/issues/39)
- **Algebraic representation search: laws -> most efficient Rust encoding** — [#40](https://github.com/hartsock/content-addressable/issues/40)
- **merkle-reference (Gozala) spec conformance + interop** — [#41](https://github.com/hartsock/content-addressable/issues/41)


## Appendix A — full researched catalog (57 raw variants)

Everything the research sweep surfaced, before dedup/merge. Variants without
their own issue were folded into a listed structure (the fold target is named
in each issue's title/body) or judged out of scope for now.

| Variant | Tier | One-liner |
|---------|------|-----------|
| Generic Merkle DAG (IPLD-style content-addressed object graph) (aka Merkle DAG, IPLD dag-cbor graph, hash-linked object graph) | core | The foundational structure of every content-addressed store: an acyclic graph whose nodes are immutable byte blocks and whose edges are hashes (CIDs) of the target node's bytes. Because a link commits to the child's e... |
| Git object model (commit history DAG over nested trees) (aka git DAG, commit/tree/blob model) | core | Git composes two Merkle structures: a history DAG of commit objects (each commit hash-links its parent commits) and, hanging off every commit, a nested tree-of-trees (tree objects linking subtree and blob hashes) snap... |
| UnixFS / dag-pb chunked file and sharded directory DAG (aka UnixFS, dag-pb, balanced/trickle file DAG, HAMT directory sharding) | core | IPFS's answer to 'how do large files and huge directories become Merkle DAGs': files are chunked (fixed-size or content-defined/Rabin) into leaf blocks, then assembled under interior nodes in a balanced DAG (good rand... |
| Merkle Clock / Merkle-CRDT (DAG as logical clock + convergent replication) (aka Merkle clocks, Merkle-CRDTs, CRDT over Merkle-DAG (Sanjuán/Pöyhtäri/Teixeira/Psaras)) | advanced | A Merkle clock is a grow-only DAG where each new event node hash-links the CIDs of the current heads, so causal order is literally embedded in the link structure: A happened-before B iff A is reachable from B. A Merkl... |
| Hashgraph-style event DAG (gossip-about-gossip) (aka hashgraph, event DAG, DAG-based BFT mempool (Narwhal-style relatives)) | advanced | Each participant emits event nodes that hash-link exactly two parents: its own previous event (self-parent) and the latest event it received from the peer it just gossiped with (other-parent). The DAG therefore record... |
| Nested Merkle trees (tree-of-trees composition) (aka nested trees, multi-dimensional Merkle structure, root-as-leaf pattern) | core | A first-class composition pattern: a leaf (or internal field) of an outer authenticated structure commits to the root of a complete inner structure, so one outer root CID authenticates a structure of structures. Insta... |
| Merkle² (chronological log of embedded prefix trees) (aka Merkle^2, MerkleSquare, log-of-trees transparency structure) | advanced | Hu, Hooshmand, Kalidhindi, Yang & Popa (IEEE S&P 2021) nest two Merkle structures the opposite way from a simple log-of-roots: the outer layer is an append-only chronological Merkle tree over log entries, and every in... |
| Merkle forest with cross-referenced roots (aka Merkle forest, root cross-linking, multi-tree anchoring, witness cosigning graph) | advanced | A composition pattern of independent Merkle trees/DAGs whose roots reference each other: tree A embeds tree B's root CID as a leaf, a checkpoint record, or an anchor, without A and B sharing internal structure. This i... |
| Entangled Merkle trees / entangled Merkle forests (aka Snarl entangled Merkle trees, alpha-entangled Merkle DAG, node-sharing entangled Merkle forest) | exotic | Two related exotica share the name. (1) Snarl (Nygaard, Estrada-Galiñanes, Meling — Middleware 2021) weaves alpha entanglement codes through a file's Merkle tree in decentralized storage (Swarm): every chunk is XOR-en... |
| CAR archive (Content Addressable aRchive) as a packaged forest (aka CAR, CARv1, CARv2, .car file) | core | The transport/at-rest form of a Merkle forest: a CAR file is a dag-cbor header declaring an array of root CIDs, followed by a sequence of (CID, block bytes) pairs containing some or all blocks of the DAGs under those ... |
| Merkle Patricia Trie (Ethereum MPT) (aka MPT, Modified Merkle Patricia Trie, hexary Patricia trie) | core | A radix-16 trie over nibble-encoded keys with three node types: branch nodes (16 child slots plus an optional value), extension nodes (a shared nibble-path prefix plus one child), and leaf nodes (remaining path plus v... |
| Binary Merkle Radix Trie / Unified Binary Tree (EIP-7864) (aka binary radix trie, binary state tree, EIP-7864 unified binary tree, bit-trie) | core | A radix-2 trie over the bits of (hashed) keys: each internal node has at most two children, and single-child runs are path-compressed. Binary arity makes proofs minimal — one sibling hash per level instead of up to 15... |
| Sparse Merkle Tree (SMT) + compact/cached variants (aka SMT, Compact Sparse Merkle Tree (Haider), Efficient SMT (Dahlberg-Pulls-Peeters caching), optimized SMT (Celestia/LazyLedger), Angela (concurrent SMT)) | core | A conceptually complete binary tree of depth \|H\| (e.g., 256) where every possible key has a fixed leaf position given by its hash bits; almost all leaves are empty, and empty subtrees hash to precomputable per-level d... |
| Jellyfish Merkle Tree (JMT) (aka JMT, Diem/Aptos Jellyfish, penumbra-zone/jmt) | advanced | Diem's (now Aptos/Sui/Penumbra-lineage) versioned sparse Merkle tree engineered for LSM-tree key-value backends: logically a 256-bit SMT where any subtree with 0 or 1 leaves collapses to a placeholder or a single leaf... |
| IAVL / IAVL+ Tree (Cosmos) (aka IAVL, immutable AVL, IAVL v2) | advanced | A persistent (immutable, copy-on-write) AVL-balanced binary search tree where all values live at leaf nodes and inner nodes hold routing keys — the Cosmos SDK's authenticated state store. Because it is a search tree o... |
| Verkle Tree (aka vector-commitment trie, Pedersen/IPA trie, KZG trie) | advanced | A high-arity (typically 256-child) trie in which each internal node commits to its children with a polynomial/vector commitment (Pedersen+IPA in Ethereum's design, KZG in others) instead of a hash of concatenated chil... |
| Merkle-Sum Sparse Merkle Tree (MS-SMT) (aka MS-SMT, Taproot Assets tree, Taro tree, merkle sum tree over SMT) | exotic | An SMT augmented so every node carries a numeric sum alongside its hash: leaves hold (value, sum) and each branch hashes (leftHash, leftSum, rightHash, rightSum) while its own sum is leftSum+rightSum. The root therefo... |
| NOMT (Nearly Optimal Merkle Trie) and page-packed trie engines (aka NOMT, nearly-optimal merklization, page-aligned binary trie, kin: QMDB, RISEDB/versioned Merkle tree, LETUS) | advanced | A modern trie *engine* (Thrum/Sovereign + Habermeier) whose thesis is that authenticated-store performance comes from aligning the structure's physical layout with SSD characteristics: a binary Merkle trie (smallest p... |
| Verifiable Log-Backed Map (Trillian) (aka verifiable map, log-backed map, Trillian map mode, Revision-based map + map-root log) | advanced | Google Trillian's composite structure: a verifiable map (an SMT over the full key space) whose successive revisions are driven by an append-only verifiable log of mutations, with each published map root also appended ... |
| Key-Transparency Prefix Trees (CONIKS / SEEMless / Parakeet / Merkle²) (aka CONIKS Merkle prefix tree, aZKS (append-only zero-knowledge set), SEEMless, Parakeet / WhatsApp Auditable Key Directory (AKD), Merkle² (Merkle-squared)) | advanced | The privacy-preserving branch of verifiable maps: CONIKS stores user→key bindings in a binary Merkle prefix tree whose leaf positions are VRF(username) — hiding who is in the directory — and publishes a hash-chained S... |
| Merkle Rope (aka Authenticated rope, Weight-annotated hash rope, Verifiable text rope) | invented | NOVEL/SPECULATIVE: an authenticated version of the classic rope (balanced binary tree over text chunks) where every node is a canonical dag-cbor block addressed by its CID and internal nodes carry committed weight ann... |
| Persistent Merkle Vector (CID-RRB Vector) (aka Authenticated RRB-tree, Merkle relaxed-radix vector, Content-addressed persistent vector) | invented | NOVEL/SPECULATIVE: an RRB (relaxed-radix-balanced) persistent vector in which every node is a canonical dag-cbor block and children are CID links, with per-node size tables committed into the hash. It gives content-ad... |
| Merkle Deque (aka Authenticated finger-tree deque, Verifiable FIFO/queue, Merkle 2-3 finger tree) | invented | NOVEL/SPECULATIVE: a persistent 2-3 finger tree whose digits, spine, and 2-3 nodes are all canonical dag-cbor blocks linked by CID, with monoid measure annotations (count, and optionally priority-min or byte-size) com... |
| Merkle Heap (aka Verifiable priority queue, Authenticated Braun heap, Extract-min-provable heap) | invented | NOVEL/SPECULATIVE: a persistent binary min-heap in Braun-tree shape where every node {key, value CID, left CID, right CID, size} is a canonical dag-cbor block, so the heap invariant (parent key <= child keys) is local... |
| Merkle Tensor Chunk-Grid (aka Verifiable Zarr, Authenticated tensor tile tree, Merkle k-d chunk tree, Checkpoint diff tree) | invented | NOVEL/SPECULATIVE: an axis-aware k-dimensional chunk grid (Zarr/HDF5-style tiling) whose tiles are raw BLAKE3 blocks and whose index is a Merkle k-d tree with shape, dtype, endianness, and chunk-shape committed in eve... |
| Merkle Time-Series Ring (aka Verifiable ring buffer, Retention-proof circular log, Flight-recorder ring) | invented | NOVEL/SPECULATIVE: a fixed-capacity ring of B time-bucketed Merkle subtrees whose root commits the bucket CID array, head position, and epoch counter, paired with a 'retirement MMR' that accumulates the root CID of ev... |
| CID Indirection Atlas (Cyclic-Graph Encoding) (aka Acyclic-on-the-wire graph atlas, Ordinal-binding table, Merkle graph closure, Cycle-safe adjacency structure) | invented | NOVEL/SPECULATIVE: a two-layer encoding that stores arbitrary — including cyclic — graphs in a store that only permits DAGs: content-layer node blocks carry their payload and out-edges named by local ordinals (never b... |
| Verifiable LRU Cache Ledger (aka Authenticated cache, Eviction-provable LRU, Merkle cache with policy proofs) | invented | NOVEL/SPECULATIVE: a composite structure — a Merkle map (key -> entry) plus a sequence-annotated Merkle recency spine (a persistent Merkle vector/deque ordered by last-access sequence number) under one root {map_root,... |
| Hash chain / Merkle linked list (aka blockchain header chain, tamper-evident log chain, Haber-Stornetta timestamp chain, skipchain (double-linked variant), SSB feed / hypercore-style signed log) | core | The simplest append-only authenticated structure: each entry embeds the hash of its predecessor, so the newest entry's hash commits to the entire history. It exists because it gives O(1) append with a single-hash stat... |
| Flat hash list (piece list) (aka BitTorrent v1 pieces list, hash list, segment digest list) | core | A single node containing the hashes of all fixed-size chunks of a file; the hash of that list is the root commitment. It exists because it allows random-access verification of any chunk after one fetch of the list, wi... |
| THEX / Tiger Tree Hash (aka TTH, Tree Hash EXchange format, Merkle Hash Tree with leaf/node domain separation) | advanced | An early (2003) full binary Merkle tree over fixed 1024-byte file segments, historically instantiated with the Tiger hash and used by Gnutella2 and Direct Connect (DC++) for multi-source swarm downloads. Its lasting c... |
| Authenticated append-only skip list (aka AAOSL (Maniatis-Baker), authenticated skip list (Goodrich-Tamassia), deterministic skip list log) | advanced | A skip list whose towers carry hashes, giving a linked-list-shaped log with polylogarithmic proofs. Goodrich-Tamassia's original authenticated dictionary used randomized heights and commutative hashing; Maniatis-Baker... |
| Merkle Mountain Range (MMR) (aka MMR, Peter Todd mountain range, bagged-peaks accumulator, flat-stored binary numeral forest) | core | A forest of perfect binary Merkle trees ('peaks') whose sizes follow the binary representation of the element count; appending fills right-to-left and merges equal-height peaks, and the peaks are 'bagged' (folded righ... |
| RFC 6962 verifiable log (Certificate Transparency Merkle tree) (aka CT log tree, RFC 9162 tree, Merkle Tree Head log, Trillian log / Rekor / sum.golang.org tree) | core | The standardized append-only Merkle tree: for size n, the left subtree is the largest power of two < n and the right subtree recursively covers the rest, with 0x00/0x01 leaf/node domain separation. It exists to make a... |
| Crosby-Wallach history tree (aka versioned Merkle log tree, tamper-evident history tree, frozen-subtree log) | advanced | The 2009 USENIX Security structure that introduced efficient tamper-evident logging: a versioned append-only binary Merkle tree where each append produces a new commitment, and subtrees that can no longer change becom... |
| Binary numeral tree / compact range decomposition (aka compact ranges (Trillian/transparency-dev), binary numeral trees (Champine), flat-tree / in-order pre-order numbering (hypercore), perfect-subtree range decomposition) | advanced | Not a distinct tree so much as the algebra underlying all append-only Merkle structures: any contiguous range [L,R) of leaves decomposes uniquely into O(log n) maximal perfect subtrees, mirroring the binary numeral re... |
| Frontier-based incremental Merkle tree (fixed depth, zero-padded) (aka Ethereum deposit contract tree, incremental Merkle tree (Semaphore/TornadoCash IMT), zero-hash padded append tree, LeanIMT (variable-depth successor)) | advanced | A fixed-depth (e.g., 32) binary Merkle tree whose empty positions hold precomputed 'zero hashes' (Z_0 = 0, Z_{k+1} = H(Z_k, Z_k)); appending left-to-right requires storing only the 'frontier' — one node per level on t... |
| BLAKE3/Bao verified-streaming tree (aka Bao encoding (combined/outboard), bao-tree (iroh chunk groups), BLAKE3 interior tree / chaining-value tree, abao) | core | BLAKE3 is itself a binary Merkle tree over 1024-byte chunks (left subtree = largest power-of-two chunks), and Bao (BLAKE3 spec §6.4) exposes that interior tree so any byte range of a blob can be verified against the b... |
| Merkle Search Tree (MST) (aka MST, AT Protocol repo tree, Bluesky MST) | core | A deterministic, history-independent B-tree-like search tree in which each key's layer is derived from its hash (e.g., number of leading zero digits of hash(key) in base B), so the tree shape is a pure function of the... |
| Prolly Tree (Probabilistic B-tree) (aka probabilistic B-tree, Noms tree, Dolt index tree) | core | A B-tree-shaped Merkle tree whose node boundaries are chosen by a content-defined chunking function (rolling hash over the sorted entry stream), not by insertion order or fill factor — so the tree is (with high probab... |
| Merkle B+-tree (MB-tree / Embedded MB-tree) (aka MB-tree, EMB-tree, authenticated B+-tree, Verkle-style B-tree (vector-commitment variant)) | core | The classic authenticated database index: a disk-oriented B+-tree where each child pointer is paired with the hash of the child node, and the signed root authenticates the whole index (Li, Hadjieleftheriou, Kollios, S... |
| Authenticated Red-Black Tree (Persistent Authenticated Dictionary) (aka Merkle red-black tree, persistent authenticated dictionary, authenticated 2-3 tree (Naor–Nissim lineage)) | advanced | A balanced binary search tree (red-black, AVL, or 2-3) with a hash of each child stored alongside the pointer, made persistent by path copying: every update allocates O(log n) new nodes and yields a new root hash whil... |
| Merkleized Treap (Cartesian Merkle Tree) (aka CMT, hash treap, deterministic treap, Merkle set (Bram Cohen/Chia lineage)) | advanced | A treap (BST by key, heap by priority) where priority = hash(key), which removes the randomness and makes the tree shape a unique canonical function of the key set — a strongly history-independent authenticated dictio... |
| Authenticated Skip List (rank-augmented) (aka Merkle skip list, commutative-hashing skip list, rank-based authenticated skip list (DPDP)) | advanced | Goodrich & Tamassia's authenticated dictionary built on a skip list, hashing each tower node from its right and down neighbors (originally with commutative hashing to simplify verification). The rank-augmented variant... |
| SeqHash (uniquely-represented sequence Merkle tree) (aka VerSum SeqHash, history-independent sequence hashing, hashsplit sequence tree (relative)) | exotic | A deterministically shaped hash tree over a *sequence* (ordered by position, not by key), from van den Hooff, Kaashoek & Zeldovich's VerSum (CCS 2014). The tree is built in merge rounds: adjacent nodes merge or not ba... |
| Authenticated Range / Segment / Interval Tree (aka Merkle segment tree, authenticated interval tree (IntegriDB), aggregate Merkle tree, authenticated multi-dimensional range tree) | advanced | The family of Merkleized range-query structures: a segment/range tree whose internal nodes carry, inside their hashed bytes, the interval bounds and aggregate values (COUNT/SUM/MIN/MAX) of their subtree, so a server c... |
| Merkle R-tree (MR-tree) and Merkle Quadtree / KD-tree (aka MR-tree, MR*-tree, authenticated R-tree, Merkle quadtree, Merkle KD-tree, verifiable spatial index) | advanced | Spatial merkleizations: the MR-tree (Yang, Papadias, Papadopoulos, Kalnis, VLDB J. 2009) embeds child-subtree hashes next to each MBR in an R-tree so an outsourced spatial server can prove window/kNN query results sou... |
| G-tree (Geometric Search Tree) (aka geometric search tree, k-zip-tree, (k,2)-zip-tree, unified MST/prolly/zip-tree framework) | exotic | Farmer & Meyer's 2024 framework of randomized search trees that assign each item a geometrically distributed rank computed as a pseudorandom function of the item itself (e.g., trailing zeros of hash(item)), then place... |
| Utreexo accumulator forest (aka Utreexo, dynamic hash-based accumulator, UTXO set accumulator, Merkle forest accumulator) | advanced | A dynamic set accumulator represented as a forest of perfectly-full binary Merkle trees — one tree per set bit in the binary representation of the leaf count, so the full accumulator state is just O(log n) root hashes... |
| Merkle-sum tree (proof-of-liabilities / proof-of-reserves) (aka sum tree, Maxwell proof-of-liabilities tree, DAPOL / DAPOL+ sparse Merkle sum tree, monoid-annotated Merkle tree) | advanced | A Merkle tree in which every node carries, in addition to its hash, an additive annotation (a balance sum): node_hash = H(l.hash, l.sum, r.hash, r.sum) and node_sum = l.sum + r.sum. It exists so a prover (e.g. an exch... |
| Poseidon-hashed sparse Merkle tree (zk-friendly SMT) (aka circomlib SMT, iden3 sparse Merkle tree, Hermez/Polygon zkEVM state tree, algebraic-hash SMT) | advanced | A fixed-depth binary trie keyed by the bits of a field element, hashed with a SNARK-friendly algebraic permutation (Poseidon over BN254/BLS12-381 scalars) instead of a bit-oriented hash, so membership and non-membersh... |
| Incremental Merkle tree (frontier IMT) and LeanIMT (aka Tornado Cash tree, Semaphore IMT, Ethereum deposit-contract tree, filled-subtrees / frontier tree, LeanIMT (Semaphore v4)) | advanced | An append-only, fixed-depth Merkle tree engineered so an on-chain contract (or circuit) maintains the root with O(depth) storage: it keeps only the 'frontier' — one filled-subtree digest per level — plus a precomputed... |
| Indexed Merkle tree (linked-leaf non-membership tree) (aka Aztec nullifier tree, indexed MT, sorted linked-leaf Merkle tree) | advanced | An append-only Merkle tree whose leaves form a sorted linked list threaded through the tree: each leaf is (value, next_index, next_value). Non-membership of x is proven by inclusion of the single 'low leaf' that strad... |
| Asynchronous Merkle-forest accumulator (Reyzin–Yakoubov) (aka asynchronous accumulator, low-update-frequency accumulator, distributed-PKI accumulator) | exotic | An additive (append-only) accumulator built, like Utreexo, as O(log n) perfect Merkle tree roots — but designed for asynchrony: it has 'old-accumulator compatibility' (a witness verifies even against an accumulator va... |
| Strong universal hash accumulator (Camacho–Hevia–Kiwi–Opazo) (aka CHKO accumulator, strong accumulator from collision-resistant hashing, untrusted-manager universal accumulator) | exotic | A dynamic universal accumulator (membership AND non-membership witnesses, adds AND deletes) built purely from collision-resistant hashing: a Merkle tree over the sorted element set, where non-membership of y is an adj... |
| Persistent authenticated dictionary (PAD) (aka PAD, versioned authenticated dictionary, path-copying Merkle search tree, history-independent treap PAD) | exotic | An authenticated key-value dictionary that answers provable queries against every historical version, not just the latest: each update path-copies (Sarnak–Tarjan persistence) the O(log n) spine of a hash-annotated sea... |
| Maintainable vector-commitment proof trees (Hyperproofs / BalanceProofs) — adjacent (aka Hyperproofs, BalanceProofs, Pointproofs, aggregatable VC trees, PST proof tree) | exotic | The vector-commitment design space beyond Verkle: Hyperproofs arranges multilinear (PST) commitment proofs into a tree so that all n position-proofs are maintainable — one leaf change updates the whole proof tree in O... |

## Appendix B — merkle-reference (Gozala) spec findings

Feeds issue #41 (spec conformance + interop).

Gozala's merkle-reference spec (docs/spec.md) defines "Merkle References": identifying structured data by the root of a deterministic binary merkle tree ("reference tree") derived from the data STRUCTURE itself, rather than from any serialized byte encoding. Its motivation section is an explicit critique of CIDs: (1) the Encoding Problem — the same value gets different CIDs in DAG-JSON vs DAG-CBOR; (2) the Partitioning Problem — externalizing a sub-structure behind an IPLD Link changes the identifier; (3) the Sizing Problem — the ~2MiB block limit forces producers to bake a partitioning strategy into identity. Goals: same identifier regardless of encoding AND regardless of how parts are stored (inline vs external).

Mechanism: every value maps to an "abstract data format" — a list whose first node is an OPERATOR (a hashed type/format tag) and whose remaining nodes are OPERANDS. Operands are combined by "merkle fold" (a BAO-inspired binary merkle tree: parent = H(left || right); odd node at a level is raised unchanged to the level above; fold of one leaf is the leaf itself; fold of zero leaves is H(empty byte string)). The operator hash is then folded with the operand subtree to give the reference tree root. Scalars are two-node trees: root = H( H(utf8-tag) || payload-bytes ) — note the payload leaf is concatenated RAW, not pre-hashed. Type tags (domain separation): "merkle-structure:null" (payload = empty), "merkle-structure:boolean/byte" (0x00/0x01), "merkle-structure:integer/leb128" (signed LEB128, minimal), "merkle-structure:float/double-precision" (8-byte IEEE-754 binary64; little-endian per the spec's worked example and the JS impl's native-endian Float64Array), "merkle-structure:string/utf-8", "merkle-structure:bytes/raw", "merkle-structure:list/item/ref-tree" (right node = fold of element reference-tree roots), "merkle-structure:map/k+v/ref-tree" (right node = fold of attributes sorted by "natural sort", each attribute = fold(key ref-tree, value ref-tree); keys may be arbitrary structures, not just strings). There is deliberately NO link type: "IPLD Link is obsolete" — in the reference implementation, a Reference embedded in a structure digests to exactly the digest of the value it names (digest(ref(X)) == digest(X)), which is what makes identity partition-invariant. Every interior tree address is itself a valid identifier, giving free sub-structure inclusion proofs, incremental/streaming verification, and choose-your-own-granularity indexing and transport packing.

The spec is deliberately hash-agnostic and silent on serialization of the final reference; the reference implementation (same repo, src/) pins: SHA-256 (32-byte digest), reference bytes = [0x07 merkle-reference multicodec (PROPOSED in multiformats/multicodec PR #357, not in the registered table), 0x12 sha2-256, 0x20 length, 32-byte digest], optionally prefixed with 0x01 so the 37-byte form parses as a CIDv1 with codec 0x07 ("Merkle reference when prefixed with CIDv1 prefix can be interpreted as valid IPLD Link"). toString() is multibase base32-lower of the 35-byte form WITHOUT the 0x01 version byte — so the familiar-looking "b…" strings (e.g. refer({hello:"world"}) → ba4jcbvpq3k5sooggkwwosy6sqd3fhr5md7hroyf3bq3vrambqm4xkkus) are NOT parseable CID strings. The spec's mermaid diagrams double as informal test vectors: null → bgcw577y…3xtq, true → bd5gsrlu…jmaa, false → bl6afhkt…3gca, "hello world" → b2ip5bcm…v2tq, 1985 (LEB128 0xC1 0x0F) → b4ob7njt…hx4q, 18.033 → bmjrgvd7…27fa, bytes 01020304 → b65rbugt…fc5q, [1,2,3] → bwwooaxi…uupa, [] → begdjb2j…t7uq, and the nested {message:{from,to,payload}} map example.

**Key requirements:**

- Merkle fold: parent = H(left_digest || right_digest); with an odd node count at a level the rightmost node is raised unchanged; fold of 1 leaf = the leaf itself; fold of 0 leaves = H(empty byte string) (tree.js fold(), lines 110-137).
- Scalar rule: reference root = H( H(utf8(tag-string)) || payload-bytes ) — the tag is hashed, the payload leaf is concatenated RAW (tree.js digest(): raw byte leaves are pushed un-hashed).
- Exact tag strings (domain separation, byte-exact): merkle-structure:null, merkle-structure:boolean/byte, merkle-structure:integer/leb128, merkle-structure:float/double-precision, merkle-structure:string/utf-8, merkle-structure:bytes/raw, merkle-structure:list/item/ref-tree, merkle-structure:map/k+v/ref-tree.
- Payload encodings: null = empty byte array; boolean = single byte 0x00/0x01; integer = SIGNED LEB128 minimal encoding (integer.js implements sleb128 with the 0x40 sign-bit termination rule — negative numbers supported); float = IEEE-754 binary64, little-endian in practice (spec example 18.033 = 9C C4 20 … 08 32 40; impl uses platform-native Float64Array — an interop layer must pin LE explicitly); string = UTF-8 as-given (NO unicode normalization specified); bytes = raw.
- List: [tag, fold(reference-tree of each element, in order)]; empty list's right node = H(empty).
- Map: [tag, fold(sorted attributes)] where attribute = fold(key-ref-tree, value-ref-tree). Sort rule per the implementation (spec only says 'natural sort'): order key = utf8 bytes of the key when it is a string, else the DIGEST of the key's reference tree; bytewise memcmp ascending (map.js attributes()). Map keys may be arbitrary structures. JS impl also folds Set as {member: true} maps and integral Numbers as integers (Number.isInteger) — so 2.0 and 2 are IDENTICAL references.
- References are transparent: a Reference value embedded in a structure contributes the digest of the value it names — digest(ref(X)) == digest(X) — giving partition/inlining invariance (tree.js digest(), Reference.is branch). There is no separate link type.
- Identifier serialization (reference implementation profile; the spec itself is silent): [0x07 merkle-reference multicodec (proposed, multicodec PR #357), 0x12 sha2-256, 0x20 digest-size, 32-byte digest]; prefix 0x01 to pun as CIDv1(codec=0x07); canonical string = multibase base32-lower of the 35-byte form WITHOUT the 0x01 — not a valid CID string (reference.js lines 9-49, 77).
- Hash function is a PROFILE parameter, not a law: the spec says only 'cryptographic hash'; the shipped profile is SHA-256/32. An alternate profile (e.g. BLAKE3) is spec-conformant but yields a disjoint identifier universe and must change the multihash byte in the serialized form.
- Conformance evidence: use the spec's embedded base32 ids as golden vectors (null bgcw577y…, true bd5gsrlu…, "hello world" b2ip5bcm…, 1985 b4ob7njt…, [1,2,3] bwwooaxi…, [] begdjb2j…, {hello:"world"} ba4jcbvpq3k5…) plus edge vectors an implementation must decide and pin: 2 vs 2.0, -0.0 vs 0.0, NaN payload bits, 64-bit boundary and negative integers, empty map, non-string map keys, and single-element lists (fold-of-one = element ref-tree root, so [x]'s right node equals ref(x)).

**Relation to this crate:** The two systems sit at opposite ends of a deliberate design axis, and merkle-reference's motivation section is essentially a critique of exactly what the content-addressable crate does on purpose. The crate (src/canonical.rs, src/content_id.rs) says "dag-cbor IS the canonical form": identity = CIDv1(codec 0x71, multihash BLAKE3 0x1e) over one frozen canonical BYTE STREAM, with determinism delegated to serde_ipld_dagcbor's encoder (RFC 8949 core-deterministic: sorted map keys, minimal ints, definite lengths, tag-42 links). merkle-reference says no byte stream is canonical: identity = the root of a structural hash tree, and the derivation algorithm itself is the canonicalization.

WHERE THEY AGREE: (1) Determinism as an encoder/algorithm property, not caller discipline — both sort map entries and pin number encodings so equal values give equal ids. (2) Multiformats framing — both self-describe the id (crate: real CIDv1 0x71/0x1e; merkle-reference: multicodec 0x07 + multihash header, CIDv1-punnable with a 0x01 prefix). This matches the workspace MULTIHASH-over-specific-algos doctrine: merkle-reference names properties in the law layer (any cryptographic hash) and pins the algorithm in a profile (SHA-256) — same shape as the crate's frozen-for-0.1.x pins. (3) Domain separation — the crate declares content type in the CID codec; merkle-reference hashes a per-type tag into every node. (4) Both support integers, floats, strings, bytes, lists, maps with string keys; for that shared subset a value-level bijection exists.

WHERE THEY DIVERGE (fundamental, not cosmetic): (1) Identity function: H(canonical bytes) vs merkle fold over structure — the same value ALWAYS has two different, underivable-from-each-other ids; you can only map between them with the data in hand. (2) Link semantics — the deepest split: the crate's tag-42 ContentId link hashes DIFFERENTLY from the inlined value, and MerkleNode (src/merkle.rs) depends on that: parents are part of the hashed body, which is what makes the event DAG tamper-evident and gives causal-history-binding identity. merkle-reference erases the distinction (digest(ref(X)) == digest(X)) to get partition-invariance. These are different theorems: the crate's id binds VALUE + CHOSEN STRUCTURE OF REFERENCE; merkle-reference's id binds value only. Neither is wrong; an interop layer must not pretend they commute. (3) Hash: BLAKE3 0x1e vs SHA-256 0x12 (reference profile). (4) Codec: 0x71 (registered, frozen) vs 0x07 (proposed in multicodec PR #357, unmerged — emitting it into CID-consuming ecosystems is an interop hazard). (5) Canonicalization details differ everywhere the same concept appears: dag-cbor sorts map keys length-first-then-bytewise over the ENCODED key and restricts keys to strings; merkle-reference sorts by raw UTF-8 bytes (no length-first) and allows arbitrary keys ordered by key-tree digest. Integers: CBOR major-type minimal encoding vs signed LEB128. Floats: dag-cbor 64-bit big-endian on the wire vs merkle-reference little-endian binary64 payloads; the JS impl also collapses 2.0 into integer 2, which dag-cbor's typed model would keep distinct — conformance vectors must pin this. (6) String form: the crate's Display is the IPLD-canonical base32 CID string; merkle-reference's toString drops the 0x01 version byte, so its strings look like CIDs but do not parse as CIDs. (7) Capability gap: merkle-reference gets O(log n) sub-structure inclusion proofs, streaming verification, and size-independent transfer for free; the crate's flat H(bytes) verifies all-or-nothing per block (the Sizing Problem the spec calls out) — but is drastically simpler, byte-freezable, and cross-language-vector-testable, which is exactly the crate's frozen tests/vectors.json gate.

WHAT AN INTEROP/CONFORMANCE LAYER WOULD NEED: (1) A dual-id index mapping CIDv1(0x71/0x1e) <-> merkle-reference for stored values, computed at write time — neither id derives from the other. (2) A pinned merkle-reference PROFILE document fixing everything the spec leaves open: hash (SHA-256 to match Gozala's ids, or a BLAKE3 profile to share the crate's hash at the cost of a disjoint id universe — per the freeze-minimally/forward-ratchet doctrine this should be a rotatable profile pin, self-described in the multihash byte), map sort rule, float endianness (declare LE), signed-LEB128 minimality, and an int/float distinction policy (the crate's typed Rust model distinguishes; the JS impl does not — pick one and vector-test 2 vs 2.0, -0.0, NaN). (3) A link-boundary policy: a tag-42 ContentId inside data being merkle-referenced is NOT transparent — the layer must either resolve links to values before folding (recovering partition-invariance, losing the crate's structure-binding) or fold the 37-byte CID as bytes/raw or a new tag (preserving structure-binding, losing invariance); conversely a merkle-reference can ride inside crate data as a tag-42 CIDv1 with codec 0x07 only if the crate relaxes its frozen 0x71-only invariant, so realistically it should be wrapped as bytes. (4) Golden vectors both directions over one shared corpus — the spec's embedded base32 ids (ba4jcbvpq3k5… for {hello:"world"}, etc.) as the merkle side, mirroring the crate's frozen tests/vectors.json byte-parity gate, plus divergence vectors proving the two ids of one value and documenting the inline-vs-link inequality on the crate side vs equality on the merkle side. (5) A statement of which id is authoritative where: for the crate's telescope — trust, tamper-evident event DAGs with causal parents in the hash — the CIDv1 stays authoritative; merkle references are best adopted as a SECONDARY, encoding-independent equivalence key (dedup across encodings, partial-transfer verification), not as a replacement identity.

**References:** <https://github.com/Gozala/merkle-reference/blob/main/docs/spec.md (fetched raw from main)> · <https://github.com/Gozala/merkle-reference — Readme.md (refer() API, base32 example, CIDv1-prefix compatibility claim)> · <https://github.com/multiformats/multicodec/pull/357 (proposed 0x07 merkle-reference code, cited by src/reference.js)> · <https://github.com/oconnor663/bao/blob/master/docs/spec.md (BAO, the merkle-fold inspiration)> · <https://ipld.io/specs/codecs/dag-cbor/spec/ (canonical dag-cbor rules the crate delegates to)>
