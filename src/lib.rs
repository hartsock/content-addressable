#![doc = include_str!("lib.md")]
#![warn(missing_docs)]

// -------------------------------------------------------------------------
// This file is a MANIFEST, not a member. It contains only composition: crate
// attributes, the crate doc (in `lib.md`, included above), module declarations,
// and the public re-export facade — no item definitions, no logic, no tests.
// Growth delegates DOWN: catalog structures register in `src/structures.rs`,
// never here, so the root stays a fixed-size manifest as the catalog grows.
// See WORKSPACE_RULES.md -> "Composition roots are manifests, not members".
// -------------------------------------------------------------------------

// --- Spine: the minimal, stable, always-on surface. ---
pub mod canonical;
pub mod classified;
pub mod content_id;
pub mod error;
pub mod raw_id;
pub mod trait_def;

// --- Seams the catalog builds on (feature-gated infrastructure). ---
#[cfg(feature = "unstable-legacy")]
pub mod legacy;
#[cfg(feature = "unstable-merkle")]
pub mod merkle;
#[cfg(feature = "unstable-migration")]
pub mod migration;
#[cfg(feature = "unstable-store")]
pub mod store;

// --- The catalog: ONE line. The sub-manifest owns the members. ---
pub mod structures;

// FROZEN crate-root re-export surface (gate item #9) — see the "Public API
// surface (FROZEN at 0.1.0)" section in `lib.md`. Keep this set minimal and
// explicit: it is the stable SPINE only. Catalog structures are reached at their
// `structures::…` path and are deliberately NOT flattened here (freeze-minimally
// applied to the public surface), so this list does not grow with the catalog.
// Removing or narrowing an entry is a major version bump.
pub use classified::{ClassifiedCid, ForeignCid};
pub use content_id::ContentId;
pub use error::ContentError;
#[cfg(feature = "unstable-merkle")]
pub use merkle::MerkleNode;
#[cfg(feature = "unstable-migration")]
pub use migration::{IdentityMigration, MigrationKind};
pub use raw_id::RawContentId;
#[cfg(feature = "unstable-store")]
pub use store::{
    AddressedBytes, MemoryStore, NodeStore, NodeStoreExt, StoreError, StoreOperation, VerifiedStore,
};
pub use trait_def::ContentAddressable;
