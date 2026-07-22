//! The Merkle structure catalog — the sub-manifest that keeps the crate root
//! bounded as the catalog grows (epic #30).
//!
//! # Invariant: adding a structure never touches `src/lib.rs`
//!
//! Each catalog structure (Merkle Mountain Range, hash chain, sparse Merkle
//! tree, Merkle-clock, …) is a feature-gated module declared **here**, in a
//! sibling file `src/structures/<name>.rs`. The crate root carries a single
//! `pub mod structures;` line and nothing per structure, so `lib.rs` stays a
//! fixed-size manifest while this file absorbs the O(N) growth of the catalog.
//!
//! Structures are reached at their path
//! (`content_addressable::structures::mmr::Mmr`) and are **not** flattened into
//! the frozen crate-root facade — the minimal-surface principle applied to the
//! public API, so the root's stable spine does not grow with the catalog.
//!
//! See `WORKSPACE_RULES.md` → "Composition roots are manifests, not members".
//!
//! Members land here as their issues do — the first is #45 (Merkle Mountain
//! Range), then #56 (Merkle-clock), and the rest of the Phase 2+ catalog. Until
//! the first lands this is an intentionally empty manifest: the scaffold that
//! lets structure #1 register with a one-line edit to *this* file, never the
//! crate root.
//!
//! ```text
//! // when #45 lands, it adds exactly one line here:
//! #[cfg(feature = "mmr")]
//! pub mod mmr;
//! ```
