//! A content-addressed Merkle-DAG node — payload plus ordered parent links,
//! identified by the [`ContentId`] of the whole (payload **and** parents).
//!
//! # Why this exists
//!
//! The "conversation = Merkle DAG of content-addressed events" design (and any
//! tamper-evident event log built on this crate) needs one shared node shape:
//! a payload, the set of causal parent links, and a self-derived id over both.
//! Each event's identity is the [`ContentId`] of the *canonical node including
//! its parent ids*, so the parent links are part of the hashed body. That is
//! what makes the DAG tamper-evident: you cannot alter a parent's bytes without
//! changing its id, which changes every descendant's id.
//!
//! Without a shared type, every downstream (agent-mesh, kyln, future callers)
//! re-derives the same shape by hand and risks diverging on the one thing that
//! must be uniform: *how parents serialize and order*. [`MerkleNode`] ships that
//! building block once, correctly:
//!
//! - Parents live in a [`BTreeSet<ContentId>`], so they are **deduplicated** and
//!   **deterministically ordered** by [`ContentId`]'s content-derived [`Ord`].
//!   Equal parent sets always produce equal bytes regardless of insertion order.
//! - Each parent serializes as a dag-cbor **tag-42 link** (the frozen
//!   [`ContentId`] serde form), so a node's parents are real IPLD links.
//! - The id is derived through the existing [`ContentAddressable`] trait via
//!   [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor) — no
//!   bespoke canonicalization.
//!
//! # ⚠️ BYTES ARE NON-FROZEN (experimental, default-off feature)
//!
//! Unlike the frozen [`ContentId`] / [`canonical`](crate::canonical) surface,
//! **a [`MerkleNode`]'s exact serialized bytes are NOT frozen.** This module is
//! gated behind the experimental, default-**off** `merkle` cargo feature, and
//! its byte layout is pinned only once Merkle conformance vectors land (a
//! follow-up toward `0.1.0-rc1`). The node's bytes depend on two things that are
//! not yet jointly frozen:
//!
//! 1. **The [`ContentId`] tag-42 serde representation** — README must-fix gate
//!    item 1. Each parent link is encoded through it, so the node inherits its
//!    status. (That repr is itself now frozen, but the *node* layout that embeds
//!    it is not yet covered by cross-language vectors.)
//! 2. **The `payload` / `parents` field key strings.** dag-cbor sorts map keys
//!    on the wire, so field *declaration* order does not matter — but the key
//!    *strings* are load-bearing for the hash. Renaming a field changes every
//!    node's id.
//!
//! Until the Merkle conformance vectors freeze these, changing the node's bytes
//! is **allowed and does not constitute a breaking change**. Do **not** add
//! merkle vectors to `tests/vectors.json` — that file is the frozen,
//! cross-language byte-parity gate and deliberately excludes this experimental
//! surface. After `0.1.0`, changing these bytes is a major version bump.

use std::collections::BTreeSet;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::content_id::ContentId;
use crate::error::ContentError;
use crate::trait_def::ContentAddressable;

/// A content-addressed node in a Merkle DAG: a `payload` plus the set of causal
/// `parents`, identified by the [`ContentId`] of the whole.
///
/// `MerkleNode<T>` is generic over a [`Serialize`] payload `T`. Its id —
/// [`content_id`](ContentAddressable::content_id), exposed here as
/// [`id`](Self::id) — is derived from **both** the payload and the parent links,
/// so it is exactly the agent-mesh conversation-event id (the [`ContentId`] of
/// the canonical event including its parent cids).
///
/// # Parents are an ordered set, not a list
///
/// `parents` is a [`BTreeSet<ContentId>`] rather than a `Vec<ContentId>` on
/// purpose. A `BTreeSet` gives:
///
/// - **free deduplication** — a parent listed twice is one link, and
/// - **deterministic order** — iteration follows [`ContentId`]'s content-derived
///   [`Ord`], so the same parent multiset always serializes to the same bytes,
///   regardless of the order the caller inserted them.
///
/// `serde` encodes the set as a CBOR array, and each element serializes as a
/// dag-cbor **tag-42 link** via [`ContentId`]'s frozen serde — so a node's
/// parents land on the wire as a deterministically-ordered array of real IPLD
/// links. A `Vec<ContentId>` is rejected precisely because it would let two
/// semantically-equal nodes hash differently by parent order, breaking the
/// content-address contract.
///
/// # Self-derived id
///
/// `MerkleNode<T>` implements [`ContentAddressable`] with the one-line
/// [`canonical_form`](ContentAddressable::canonical_form) deferring to
/// [`to_canonical_dagcbor`](crate::canonical::to_canonical_dagcbor), so
/// `content_id` / `verify` come for free and the id is over the *whole* node
/// including its parent links.
///
/// # ⚠️ Non-frozen bytes
///
/// The exact serialized bytes of a `MerkleNode` are **NOT frozen** — see the
/// [module docs](self#-bytes-are-non-frozen-experimental-default-off-feature).
/// They depend on (a) the [`ContentId`] tag-42 serde repr (must-fix gate item 1)
/// and (b) the `payload` / `parents` field key strings. A follow-up "Merkle
/// conformance vectors" issue freezes them for `0.1.0-rc1`; until then they may
/// change without it being a breaking change.
///
/// # Examples
///
/// ```
/// use content_addressable::merkle::MerkleNode;
/// use content_addressable::ContentAddressable;
///
/// // A genesis node: no parents.
/// let root = MerkleNode::genesis("hello");
/// let root_id = root.id().unwrap();
///
/// // A child node linking the root as its parent. Its id binds both the
/// // payload and the parent link.
/// let child = MerkleNode::new("world", [root_id]);
/// assert!(child.parents().contains(&root_id));
/// assert!(child.verify(&child.id().unwrap()).unwrap());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: DeserializeOwned"))]
pub struct MerkleNode<T> {
    /// The node's content.
    ///
    /// The field *key string* `"payload"` is load-bearing for the node's id and
    /// part of the (non-frozen) byte layout — see the [module docs](self).
    pub payload: T,
    /// The causal parent links, as a deterministically-ordered, deduplicated
    /// set of [`ContentId`]s.
    ///
    /// Each element serializes as a dag-cbor tag-42 link. The field *key string*
    /// `"parents"` is load-bearing for the node's id and part of the
    /// (non-frozen) byte layout — see the [module docs](self).
    pub parents: BTreeSet<ContentId>,
}

impl<T> MerkleNode<T> {
    /// Build a node from a payload and an iterator of parent ids.
    ///
    /// The parents are collected into a [`BTreeSet`], so duplicate ids collapse
    /// and insertion order does not affect the node's bytes or its
    /// [`id`](Self::id). Pass an empty iterator (e.g. `[]`) for a node with no
    /// parents, or use [`genesis`](Self::genesis) for clarity.
    pub fn new(payload: T, parents: impl IntoIterator<Item = ContentId>) -> Self {
        Self {
            payload,
            parents: parents.into_iter().collect(),
        }
    }

    /// Build a genesis (root) node — a node with no parents.
    ///
    /// Equivalent to [`new`](Self::new) with an empty parent set, named for the
    /// common DAG-root case. A genesis node's id differs from the id of a
    /// same-payload node that *has* a parent, because the parent links are part
    /// of the hashed body.
    pub fn genesis(payload: T) -> Self {
        Self {
            payload,
            parents: BTreeSet::new(),
        }
    }

    /// Borrow the node's payload.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Borrow the node's parent link set.
    ///
    /// The set is ordered by [`ContentId`]'s content-derived [`Ord`].
    pub fn parents(&self) -> &BTreeSet<ContentId> {
        &self.parents
    }
}

impl<T: Serialize> MerkleNode<T> {
    /// The node's content id — the [`ContentId`] of the whole node, payload and
    /// parent links together.
    ///
    /// A convenience alias for [`ContentAddressable::content_id`]; this is the
    /// agent-mesh conversation-event id.
    ///
    /// # Errors
    ///
    /// Propagates any error from
    /// [`canonical_form`](ContentAddressable::canonical_form) (i.e. an encoding
    /// failure).
    pub fn id(&self) -> Result<ContentId, ContentError> {
        self.content_id()
    }
}

impl<T: Serialize> ContentAddressable for MerkleNode<T> {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        canonical::to_canonical_dagcbor(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small concrete payload exercising the `T: Serialize + DeserializeOwned`
    /// path (a node carrying a map-bearing struct).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Event {
        author: String,
        body: String,
    }

    fn event(author: &str, body: &str) -> Event {
        Event {
            author: author.to_string(),
            body: body.to_string(),
        }
    }

    /// A stand-in parent id, minted from canonical bytes the same way the rest
    /// of the crate does. The exact bytes don't matter — only that it is a real
    /// `ContentId` that serializes as a tag-42 link.
    fn id_for(payload: &str) -> ContentId {
        MerkleNode::genesis(payload.to_string()).id().unwrap()
    }

    #[test]
    fn content_id_is_deterministic() {
        // Same payload + same parents => same id (and same bytes).
        let p = id_for("parent");
        let a = MerkleNode::new(event("alice", "hi"), [p]);
        let b = MerkleNode::new(event("alice", "hi"), [p]);
        assert_eq!(
            a.id().unwrap(),
            b.id().unwrap(),
            "equal nodes must produce equal ids"
        );
        assert_eq!(
            a.canonical_form().unwrap(),
            b.canonical_form().unwrap(),
            "equal nodes must produce equal canonical bytes"
        );
    }

    #[test]
    fn different_payload_changes_id() {
        // The id binds the payload: changing it changes the id.
        let p = id_for("parent");
        let a = MerkleNode::new(event("alice", "hi"), [p]);
        let b = MerkleNode::new(event("alice", "bye"), [p]);
        assert_ne!(
            a.id().unwrap(),
            b.id().unwrap(),
            "a different payload must change the node id"
        );
    }

    #[test]
    fn different_parents_change_id() {
        // The id binds the parent links: changing/adding/removing one changes it.
        let payload = event("alice", "hi");
        let p1 = id_for("p1");
        let p2 = id_for("p2");

        let one = MerkleNode::new(payload.clone(), [p1]);
        let other = MerkleNode::new(payload.clone(), [p2]);
        assert_ne!(
            one.id().unwrap(),
            other.id().unwrap(),
            "changing a parent id must change the node id"
        );

        let with_two = MerkleNode::new(payload.clone(), [p1, p2]);
        assert_ne!(
            one.id().unwrap(),
            with_two.id().unwrap(),
            "adding a parent must change the node id"
        );
    }

    #[test]
    fn genesis_differs_from_node_with_parent() {
        // A genesis (no-parent) node and a same-payload node WITH a parent have
        // different ids, because parent links are part of the hashed body.
        let payload = event("alice", "hi");
        let g = MerkleNode::genesis(payload.clone());
        assert!(g.parents().is_empty(), "genesis node has no parents");

        let parent = id_for("parent");
        let child = MerkleNode::new(payload.clone(), [parent]);
        assert_ne!(
            g.id().unwrap(),
            child.id().unwrap(),
            "a genesis node must differ from a same-payload node with a parent"
        );

        // And `new` with an empty parent iterator equals `genesis`.
        let g2 = MerkleNode::new(payload, std::iter::empty());
        assert_eq!(
            g.id().unwrap(),
            g2.id().unwrap(),
            "new(payload, []) must equal genesis(payload)"
        );
    }

    #[test]
    fn parents_encode_as_tag42_links() {
        // Each parent must serialize as a dag-cbor tag-42 link: the 0xd8 0x2a
        // tag head appears exactly once per parent in the canonical bytes.
        // (Mirrors lib.rs's content_id_serializes_as_dagcbor_link golden.)
        let p1 = id_for("p1");
        let p2 = id_for("p2");
        let node = MerkleNode::new(event("alice", "hi"), [p1, p2]);
        let bytes = node.canonical_form().unwrap();

        let tag_count = bytes.windows(2).filter(|w| *w == [0xd8, 0x2a]).count();
        assert_eq!(
            tag_count, 2,
            "each of the two parents must be a dag-cbor tag-42 link"
        );

        // A genesis node has no links at all.
        let g = MerkleNode::genesis(event("alice", "hi"));
        let g_bytes = g.canonical_form().unwrap();
        let g_count = g_bytes.windows(2).filter(|w| *w == [0xd8, 0x2a]).count();
        assert_eq!(g_count, 0, "a genesis node carries no tag-42 links");
    }

    #[test]
    fn btreeset_ordering_makes_id_insertion_order_independent() {
        // Building a node with parents inserted in opposite orders yields the
        // same id and the same canonical bytes — the BTreeSet sorts them.
        let p1 = id_for("p1");
        let p2 = id_for("p2");
        let p3 = id_for("p3");

        let forward = MerkleNode::new(event("alice", "hi"), [p1, p2, p3]);
        let reverse = MerkleNode::new(event("alice", "hi"), [p3, p2, p1]);
        assert_eq!(
            forward.id().unwrap(),
            reverse.id().unwrap(),
            "parent insertion order must not affect the node id"
        );
        assert_eq!(
            forward.canonical_form().unwrap(),
            reverse.canonical_form().unwrap(),
            "parent insertion order must not affect the canonical bytes"
        );

        // Duplicates collapse, too.
        let dup = MerkleNode::new(event("alice", "hi"), [p1, p1, p2, p3, p2]);
        assert_eq!(
            forward.id().unwrap(),
            dup.id().unwrap(),
            "duplicate parents must collapse in the BTreeSet"
        );
    }

    #[test]
    fn small_dag_b_references_a() {
        // The agent-mesh conversation-event shape: node B references node A's id
        // as a parent. B's id is stable, and A is recoverable as a link inside
        // B's parents.
        let a = MerkleNode::genesis(event("alice", "first"));
        let a_id = a.id().unwrap();

        let b = MerkleNode::new(event("bob", "reply"), [a_id]);
        let b_id_1 = b.id().unwrap();
        let b_id_2 = b.id().unwrap();
        assert_eq!(b_id_1, b_id_2, "B's id is stable");

        // A is recoverable as a link from B.
        assert!(
            b.parents().contains(&a_id),
            "A's id must be present in B's parent links"
        );
        assert_eq!(b.parents().len(), 1, "B has exactly one parent link (A)");
    }

    #[test]
    fn roundtrip_and_verify() {
        // A node survives to_canonical_dagcbor -> from_canonical_dagcbor for a
        // concrete payload, and verify() returns Ok(true) against its own id.
        let parent = id_for("parent");
        let node = MerkleNode::new(event("alice", "hi"), [parent]);
        let id = node.id().unwrap();

        assert!(
            node.verify(&id).unwrap(),
            "a node must verify against its own id"
        );

        let bytes = node.canonical_form().unwrap();
        let back: MerkleNode<Event> = canonical::from_canonical_dagcbor(&bytes).unwrap();
        assert_eq!(node, back, "a node must survive a dag-cbor roundtrip");
        assert!(
            back.verify(&id).unwrap(),
            "the round-tripped node must still verify against the original id"
        );
    }
}
