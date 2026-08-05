# Merkle Catalog Roadmap — one-stop-shop for Merkle data structures in Rust + Python

> Plain-text home of the project plan. The live tracker is
> [epic #30](https://github.com/hartsock/content-addressable/issues/30);
> when they disagree, the epic is current and this file needs a PR.

## Mission

Make `content-addressable` the **one-stop-shop for Merkle data structures**: the high-quality, high-performance option in Rust *and* Python. Every structure in the catalog gets:

- a content-addressed node shape whose identity is a [`ContentId`](../src/content_id.rs) (frozen CIDv1 / dag-cbor `0x71` / BLAKE3 `0x1e`), minted through the one `ContentAddressable` trait — no bespoke hashing anywhere;
- **discoverability by root CID**: a root `ContentId` plus a node store fully determines the structure — hand someone the root and any store holding the bytes and they can reconstruct and *verify* every node (the [`MerkleNode`](../src/merkle.rs) pattern, generalized);
- at least one verifiable proof kind (inclusion / exclusion / consistency / range) with O(log n) proof sizes where the literature supports it;
- a minimal law set with machine-checked proof obligations (Lean 4 for data laws, TLA+ for protocol laws) — **law minimalism**: nothing enters the law layer without a proof obligation;
- Python exposure through `content-addressable-py`, distributed on **crates.io + PyPI** in lockstep via the existing tag-driven pipeline;
- benchmarks, property tests, and conformance vectors before its bytes freeze.

**Telescope, not sky:** the catalog is not about hash trees. It is about what adopters need to *see through* them — provenance, tamper-evidence, verifiable sync, and proofs that travel.

## Relationship to #17

Epic #17 freezes the identity layer (`ContentId` bytes, canonical dag-cbor, the presentation surface) and ships `MerkleNode` experimentally. **This epic builds the structure layer on top of that frozen contract.** Every structure here follows the posture #17 established: default-**off** cargo feature, bytes explicitly **NON-FROZEN** until its conformance vectors land (freeze minimally), and graduation to frozen happens through the Merkle-vectors gate — never as a side effect.

## Design laws (apply to every issue below)

1. **One structure, one module, one feature flag, one PR-sized MVP.** Soft cap 2,500 lines per new file. Non-goals stated explicitly.
2. **`MerkleNode` is the causal-set shape, not the universal shape.** Its `BTreeSet<ContentId>` parents dedup and content-order links. Structures needing positional, order-significant, or duplicate-bearing links (sequences, chunk lists, tree children) introduce sibling node shapes (`Vec<ContentId>` / named links) deriving ids through the same `ContentAddressable` trait. Each issue states which case it is.
3. **Structures never own storage.** All traversal goes through the node-store seam; verify-on-read is structural, not optional.
4. **Laws name properties; profiles pin algorithms.** The CID self-describes codec + hash; no structure introduces hash configuration.
5. **Quality and performance are measured claims.** The quality bar (proptest/fuzz/coverage/differential) and the benchmark harness gate the "high quality, high performance" positioning.

## Project plan

### Phase 0 — Foundations (everything else depends on these)

- [ ] #31 — feat(store): CID-addressed node store seam (get/put by ContentId)
- [ ] #32 — feat(proof): shared proof envelope (inclusion/exclusion/consistency)
- [ ] #33 — feat(merkle): conformance vectors freeze structure bytes at rc1
- [ ] #34 — feat(py): PyO3 exposure policy for every Merkle structure
- [ ] #35 — feat(conformance): portable vectors + TS/Dart/Java byte-identity
- [ ] #36 — test: property/fuzz/coverage quality bar for the Merkle catalog
- [ ] #37 — bench: criterion suite + comparative harness vs Rust Merkle crates

### Phase 1 — Formal spine (parallel with Phase 2)

- [ ] #38 — feat(formal): Lean 4 proof scaffolding + CI for Merkle structures
- [ ] #39 — feat(formal): TLA+ protocol models and TLC CI gate for Merkle layer
- [ ] #40 — feat(formal): algebra-of-laws encoding decision records (ADRs)
- [ ] #41 — feat(merkle): merkle-reference (Gozala) conformance + dual-id interop

### Phase 2 — Core structures

- [ ] #42 — feat(dag): generic Merkle DAG node, walk, and inclusion proofs
- [ ] #43 — feat(merkle): hash-chain — append-only log under a single head CID
- [ ] #44 — feat(merkle): BLAKE3/Bao verified-streaming tree (folds flat list)
- [ ] #45 — feat(merkle): Merkle Mountain Range (MMR) append-only accumulator
- [ ] #46 — feat(merkle): RFC 6962 verifiable log (inclusion proofs over CIDs)
- [ ] #47 — feat(merkle): Merkle radix trie - binary-first authenticated KV map
- [ ] #48 — feat(merkle): sparse Merkle tree map with exclusion proofs
- [ ] #49 — feat(merkle): Merkle Search Tree — history-independent ordered map
- [ ] #50 — feat(prolly): Prolly Tree ordered index behind default-off feature
- [ ] #51 — feat(merkle): Merkle B+-tree with range-completeness proofs
- [ ] #52 — feat(merkle): git object model — commit DAG over nested trees
- [ ] #53 — feat(chunked-dag): chunked file + directory DAG (sized links)
- [ ] #54 — feat(merkle): nested Merkle trees via typed subtree-root seam
- [ ] #55 — feat(merkle): Merkle forest — anchored roots, chained proofs, CAR

### Phase 3 — Advanced structures

- [ ] #56 — feat(merkle): Merkle-Clock event DAG (Merkle-CRDT causal layer)
- [ ] #57 — feat(utreexo): accumulator forest for O(log n) stateless verification
- [ ] #58 — feat(merkle): annotated Merkle trees (sum/aggregate/range/spatial)
- [ ] #59 — feat(merkle): verifiable-map head chain (key transparency spine)
- [ ] #60 — feat(imt): zk-friendly append-only trees — frontier IMT MVP
- [ ] #61 — feat(merkle): persistent authenticated dictionary (treap-profile MVP)
- [ ] #62 — feat(verkle): vector-commitment carrier nodes + CAS walk

### Phase 4 — Exotic & invented (speculative, explicitly marked)

- [ ] #63 — feat(merkle): entangled Merkle forest (Snarl parity + version chain)
- [ ] #64 — feat(merkle): SeqHash uniquely-represented sequence tree (VerSum)
- [ ] #65 — feat(merkle): persistent Merkle vector (CID-RRB) — verifiable Vec
- [ ] #66 — feat(atlas): CID Indirection Atlas — cyclic graphs in a DAG-only CAS
- [ ] #67 — feat(merkle): Merkle Time-Series Ring — retention-proof circular log

## Sequencing

- Phase 0 lands first; the node-store seam and proof API are hard prerequisites for every structure PR.
- Phases 1 and 2 proceed in parallel: each structure issue declares its laws; the Lean/TLA+ toolkits give them a home; the algebra issue turns declared laws into encoding decisions (and identifies shared kernels — e.g. MST and Prolly trees as one parameterized chunker).
- Phases 3–4 start as core structures prove the seams. Invented structures (label `speculative`) may be re-scoped or closed on evidence — they are hypotheses, not commitments.
- A structure's bytes freeze **only** when its vectors land in the Merkle-vectors gate. Until then its layout may change without a breaking-change ceremony.

## Release ladder & audit cadence (approved 2026-07-21; ladder re-mapped 2026-08 at 0.1.0)

**Careful and deeply tested — audit passes are built into the process, not appended to it.**

> **Superseded framing.** The "`0.1.0` = catalog complete" line below (and the
> `0.0.x` micro-release channel it depended on) is **superseded**: `0.1.0`
> shipped as the **frozen core contract**, not catalog-completeness. What
> actually happened: `0.1.0-alpha.1` (prerelease) → `0.1.0` (frozen `ContentId`
> byte/wire + API contract, Rust↔Python parity). The Merkle catalog rides the
> `0.1.x` line as **experimental, default-off** `unstable-merkle` /
> `unstable-store` features. The remaining ladder rungs (sister languages,
> hardening, `1.0.0`) still apply.

- **`0.1.0` = frozen core contract** (shipped): the `ContentId` byte/wire + API contract and Rust↔Python parity are frozen for the whole `0.1.x` line. The Merkle catalog ships behind the experimental, default-off `unstable-merkle` / `unstable-store` features whose bytes/API are explicitly *not* frozen.
- **`0.1.x` catalog line**: each catalog slice lands behind the `unstable-*` features; a structure's bytes freeze **only** when its cross-language vectors land in the Merkle-vectors gate (#17). Catalog-completeness is a later milestone, **not** a `0.1.0` gate.
- **`0.1.x` → `0.999.x`**: sister languages (TypeScript, Dart, Java — #35) plus hardening, until the fundamentals are fully baked and invariant.
- **`1.0.0` = rock solid.** Nothing ships in 1.0.0 that hasn't survived the full audit cadence below.

**Audit cadence:**
1. **Per PR** — adversarial audit pass (independent review agents: correctness, security, simplification) *before* review is requested; findings fixed or explicitly waived in the PR body.
2. **Per release (each 0.0.x)** — full `just check` + property suites + vector parity + benchmark smoke; release notes name what froze, if anything.
3. **Per phase boundary** — catalog-wide audit: documentation audit against code reality, security review, coverage ratchet check, and a "what's missing" completeness critic.
4. **Per version-line boundary (0.1.0, 1.0.0)** — external-quality bar: fuzz corpora replayed, cross-language vectors replayed on every supported target, formal obligations (Lean/TLA+) all green.

## Exit criteria

- [ ] Every Phase 0–2 issue closed; Phase 3 issues closed or explicitly re-scoped.
- [ ] Every shipped structure: feature-gated module + store-seam traversal + ≥1 proof kind + proptests + Lean/TLA+ obligations discharged + Python parity + vectors landed.
- [ ] `docs/MERKLE_CATALOG.md` (full catalog) and `docs/MERKLE_ROADMAP.md` (this plan, in plain text) merged and current.
- [ ] Comparative benchmarks published in `docs/BENCHMARKS.md` supporting the performance claim.
- [ ] Wheels + crate publishing green across the catalog surface (tag-driven, no manual uploads).

## Full catalog

The complete researched catalog (57 raw variants merged into the 26 structure issues below, with the fold decisions recorded) lives in `docs/MERKLE_CATALOG.md` once the docs PR lands; the issue list below is the actionable subset.

