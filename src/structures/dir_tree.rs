//! A content-addressed directory tree: one root [`ContentId`] names a whole
//! directory of files, and a path inside it resolves to a file's id with an
//! O(depth) proof that needs only the root to check.
//!
//! # Shape
//!
//! A [`DirNode`] maps entry names to [`Link`]s. A link is either a file
//! (`RawContentId` of its bytes plus its size) or a subdirectory (the
//! [`ContentId`] of its own node). The map is a [`BTreeMap`], so entry order is
//! deterministic by construction, and the id is minted through
//! [`ContentAddressable`] / [`to_canonical_dagcbor`](canonical::to_canonical_dagcbor)
//! — no encoding of our own. A `MerkleNode` does not fit: its links are a
//! deduplicated causal *set*, while a directory has *named* links.
//!
//! # What is stored
//!
//! [`snapshot`] puts only the dag-cbor directory nodes in the [`NodeStore`].
//! File **bytes are not stored**; a file is cited by its [`RawContentId`] and
//! the caller keeps the bytes (check them with [`Proof::verify_file`]).
//!
//! # ⚠️ BYTES ARE NON-FROZEN (experimental, default-off feature)
//!
//! This module sits behind the default-**off** `dir-tree` cargo feature. A
//! node's serialized bytes are not pinned by `tests/vectors.json` and may
//! change until conformance vectors land (#33). The load-bearing strings are
//! the `entries` field key, the lowercase variant keys `file` / `dir`, and the
//! `id` / `size` field keys; renaming any of them changes every id.
//!
//! # Names
//!
//! An entry name is non-empty UTF-8 with no `/`, not `.` or `..`, and no `\0`
//! (a NUL cannot occur in a filesystem name). The rule is applied at build time
//! *and* to every node decoded while resolving or verifying: an untrusted
//! author can mint a node with a bad name and its id still verifies.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::content_id::ContentId;
use crate::error::ContentError;
use crate::raw_id::RawContentId;
use crate::store::{NodeStore, NodeStoreExt, StoreError};
use crate::trait_def::ContentAddressable;

/// Everything that can go wrong building, resolving or verifying a tree.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DirTreeError {
    /// An entry name breaks the name rule.
    #[error("invalid entry name {name:?}")]
    InvalidName {
        /// The offending name (lossy for non-UTF-8 filesystem names).
        name: String,
    },
    /// Two entries share a name.
    #[error("duplicate entry name {name:?}")]
    DuplicateName {
        /// The repeated name.
        name: String,
    },
    /// The snapshot met a symlink; symlinks are refused.
    #[error("symlink refused: {path}")]
    Symlink {
        /// Where it was found.
        path: PathBuf,
    },
    /// The snapshot met a fifo, socket or device.
    #[error("unsupported file type: {path}")]
    UnsupportedFileType {
        /// Where it was found.
        path: PathBuf,
    },
    /// A path component names no entry.
    #[error("not found: {path}")]
    NotFound {
        /// The path up to and including the missing component.
        path: String,
    },
    /// A path descends through a file.
    #[error("not a directory: {path}")]
    NotADirectory {
        /// The path up to and including the file.
        path: String,
    },
    /// The path's last component is a directory.
    #[error("not a file: {path}")]
    NotAFile {
        /// The full path.
        path: String,
    },
    /// A proof does not hold against the given root, path or bytes.
    #[error("proof does not verify")]
    ProofMismatch,
    /// A filesystem read failed.
    #[error("i/o error at {path}: {source}")]
    Io {
        /// The path being read.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A node-store failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A content-integrity failure.
    #[error(transparent)]
    Content(#[from] ContentError),
}

/// An entry's target: a file or a subdirectory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Link {
    /// A file: the id of its bytes and their length.
    File {
        /// Id of the file's bytes.
        id: RawContentId,
        /// Length of the file in bytes.
        size: u64,
    },
    /// A subdirectory: the id of its [`DirNode`].
    Dir {
        /// Id of the subdirectory's node.
        id: ContentId,
    },
}

/// One directory: entry name → [`Link`], ordered by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirNode {
    entries: BTreeMap<String, Link>,
}

/// The single home of the name rule.
fn validate_name(name: &str) -> Result<(), DirTreeError> {
    // `\0` is rejected because no filesystem can hold it in a name.
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(DirTreeError::InvalidName {
            name: name.to_owned(),
        });
    }
    Ok(())
}

impl DirNode {
    /// Build a node, validating every name and rejecting duplicates.
    ///
    /// # Errors
    ///
    /// [`DirTreeError::InvalidName`] or [`DirTreeError::DuplicateName`].
    pub fn new(entries: impl IntoIterator<Item = (String, Link)>) -> Result<Self, DirTreeError> {
        let mut map = BTreeMap::new();
        for (name, link) in entries {
            validate_name(&name)?;
            if map.contains_key(&name) {
                return Err(DirTreeError::DuplicateName { name });
            }
            map.insert(name, link);
        }
        Ok(Self { entries: map })
    }

    /// The entries, ordered by name.
    pub fn entries(&self) -> &BTreeMap<String, Link> {
        &self.entries
    }

    /// Re-check names on a node that came from untrusted bytes.
    fn validate(&self) -> Result<(), DirTreeError> {
        self.entries.keys().try_for_each(|n| validate_name(n))
    }
}

impl ContentAddressable for DirNode {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        canonical::to_canonical_dagcbor(self)
    }
}

/// Snapshot the directory at `path` into `store`, returning the root id.
///
/// Symlinks are refused, as are fifos, sockets and devices; empty directories
/// are fine. File bytes are hashed, not stored.
///
/// # Errors
///
/// See [`DirTreeError`].
pub fn snapshot<S: NodeStore + ?Sized>(
    store: &mut S,
    path: &Path,
) -> Result<ContentId, DirTreeError> {
    let meta = fs::symlink_metadata(path).map_err(|e| io_err(path, e))?;
    if meta.file_type().is_symlink() {
        return Err(DirTreeError::Symlink {
            path: path.to_owned(),
        });
    }
    if !meta.is_dir() {
        return Err(DirTreeError::UnsupportedFileType {
            path: path.to_owned(),
        });
    }
    snapshot_dir(store, path)
}

fn io_err(path: &Path, source: io::Error) -> DirTreeError {
    DirTreeError::Io {
        path: path.to_owned(),
        source,
    }
}

fn snapshot_dir<S: NodeStore + ?Sized>(
    store: &mut S,
    dir: &Path,
) -> Result<ContentId, DirTreeError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|n| DirTreeError::InvalidName {
                name: n.to_string_lossy().into_owned(),
            })?;
        let ty = fs::symlink_metadata(&path)
            .map_err(|e| io_err(&path, e))?
            .file_type();
        let link = if ty.is_symlink() {
            return Err(DirTreeError::Symlink { path });
        } else if ty.is_dir() {
            Link::Dir {
                id: snapshot_dir(store, &path)?,
            }
        } else if ty.is_file() {
            let bytes = fs::read(&path).map_err(|e| io_err(&path, e))?;
            Link::File {
                id: RawContentId::from_content(&bytes),
                size: bytes.len() as u64,
            }
        } else {
            return Err(DirTreeError::UnsupportedFileType { path });
        };
        entries.push((name, link));
    }
    Ok(store.put_node(&DirNode::new(entries)?)?)
}

/// A path's file link plus the canonical bytes of each directory node on the
/// way, root first. `nodes.len()` equals the path depth.
///
/// Fields are public: a proof is a plain value, and [`verify`](Self::verify)
/// trusts none of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The path components, root-relative.
    pub path: Vec<String>,
    /// Canonical bytes of each node walked, root first.
    pub nodes: Vec<Vec<u8>>,
    /// The file link found at the end.
    pub file: Link,
}

/// Resolve `path` (`/`-separated) under `root` to a file, with its proof.
///
/// # Errors
///
/// [`DirTreeError::NotFound`], [`DirTreeError::NotADirectory`],
/// [`DirTreeError::NotAFile`], [`DirTreeError::InvalidName`], or a store error.
pub fn resolve<S: NodeStore + ?Sized>(
    store: &S,
    root: &ContentId,
    path: &str,
) -> Result<Proof, DirTreeError> {
    let parts: Vec<&str> = path.split('/').collect();
    parts.iter().try_for_each(|p| validate_name(p))?;
    let mut nodes = Vec::with_capacity(parts.len());
    let mut current = *root;
    for (i, part) in parts.iter().enumerate() {
        let so_far = parts[..=i].join("/");
        let bytes = store.get(&current)?;
        let node: DirNode = store.get_node(&current)?;
        node.validate()?;
        nodes.push(bytes);
        let link = *node.entries.get(*part).ok_or(DirTreeError::NotFound {
            path: so_far.clone(),
        })?;
        match (link, i + 1 == parts.len()) {
            (Link::Dir { id }, false) => current = id,
            (Link::File { .. }, true) => {
                return Ok(Proof {
                    path: parts.iter().map(|p| (*p).to_owned()).collect(),
                    nodes,
                    file: link,
                })
            }
            (Link::File { .. }, false) => return Err(DirTreeError::NotADirectory { path: so_far }),
            (Link::Dir { .. }, true) => return Err(DirTreeError::NotAFile { path: so_far }),
        }
    }
    unreachable!("split always yields at least one component")
}

impl Proof {
    /// Check the proof against `root` alone; returns the file's id and size.
    ///
    /// # Errors
    ///
    /// [`DirTreeError::ProofMismatch`] if any hop fails.
    pub fn verify(&self, root: &ContentId) -> Result<(RawContentId, u64), DirTreeError> {
        let mismatch = || DirTreeError::ProofMismatch;
        if self.path.is_empty() || self.nodes.len() != self.path.len() {
            return Err(mismatch());
        }
        let mut expected = *root;
        for (i, (bytes, name)) in self.nodes.iter().zip(&self.path).enumerate() {
            if ContentId::from_canonical_bytes(bytes) != expected {
                return Err(mismatch());
            }
            let node = DirNode::from_canonical_form(bytes)?;
            node.validate()?;
            let link = *node.entries.get(name).ok_or_else(mismatch)?;
            match (link, i + 1 == self.nodes.len()) {
                (Link::Dir { id }, false) => expected = id,
                (Link::File { id, size }, true) if link == self.file => return Ok((id, size)),
                _ => return Err(mismatch()),
            }
        }
        Err(mismatch())
    }

    /// [`verify`](Self::verify), then check `bytes` against the file link.
    ///
    /// # Errors
    ///
    /// [`DirTreeError::ProofMismatch`] if the proof or the bytes do not match.
    pub fn verify_file(&self, root: &ContentId, bytes: &[u8]) -> Result<(), DirTreeError> {
        let (id, size) = self.verify(root)?;
        if size != bytes.len() as u64 || !id.verify(bytes) {
            return Err(DirTreeError::ProofMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn file(b: &[u8]) -> Link {
        Link::File {
            id: RawContentId::from_content(b),
            size: b.len() as u64,
        }
    }

    fn node(entries: &[(&str, Link)]) -> DirNode {
        DirNode::new(entries.iter().map(|(n, l)| (n.to_string(), *l))).unwrap()
    }

    /// Put a two-level tree: `{a.txt, sub/{b.txt}}`; returns (root, sub).
    fn two_level(store: &mut MemoryStore, a: &[u8], b: &[u8]) -> (ContentId, ContentId) {
        let sub = store.put_node(&node(&[("b.txt", file(b))])).unwrap();
        let root = node(&[("a.txt", file(a)), ("sub", Link::Dir { id: sub })]);
        (store.put_node(&root).unwrap(), sub)
    }

    #[test]
    fn insertion_order_does_not_change_the_id() {
        // acceptance 1
        let (x, y) = (file(b"x"), file(b"y"));
        let fwd = DirNode::new([("a".into(), x), ("b".into(), y)]).unwrap();
        let rev = DirNode::new([("b".into(), y), ("a".into(), x)]).unwrap();
        assert_eq!(fwd.content_id().unwrap(), rev.content_id().unwrap());
    }

    #[test]
    fn change_rename_move_alter_root_but_untouched_subtree_keeps_id() {
        // acceptance 2
        let mut s = MemoryStore::new();
        let (base, sub) = two_level(&mut s, b"A", b"B");
        let (changed, sub2) = two_level(&mut s, b"A!", b"B");
        assert_ne!(base, changed, "one changed byte");
        assert_eq!(sub, sub2, "untouched subtree keeps its id");

        let renamed = node(&[("z.txt", file(b"A")), ("sub", Link::Dir { id: sub })]);
        assert_ne!(base, s.put_node(&renamed).unwrap(), "rename");
    }

    #[test]
    fn rename_with_no_sort_change_alters_the_root() {
        // A one-entry directory: `a` -> `b` cannot reorder anything, so only
        // an encoding that carries the NAME can tell the roots apart.
        let mut s = MemoryStore::new();
        let before = s.put_node(&node(&[("a", file(b"same"))])).unwrap();
        let after = s.put_node(&node(&[("b", file(b"same"))])).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn moving_a_file_between_dirs_alters_the_root_and_spares_the_rest() {
        let mut s = MemoryStore::new();
        let mut tree = |x: &[(&str, Link)], y: &[(&str, Link)]| {
            let x = s.put_node(&node(x)).unwrap();
            let y = s.put_node(&node(y)).unwrap();
            let z = s.put_node(&node(&[("g", file(b"untouched"))])).unwrap();
            let root = node(&[
                ("x", Link::Dir { id: x }),
                ("y", Link::Dir { id: y }),
                ("z", Link::Dir { id: z }),
            ]);
            (s.put_node(&root).unwrap(), z)
        };
        let f = file(b"moved bytes");
        let (before, z_before) = tree(&[("f", f)], &[]);
        let (after, z_after) = tree(&[], &[("f", f)]);
        assert_ne!(before, after, "same bytes, x/f -> y/f");
        assert_eq!(z_before, z_after, "untouched subtree keeps its id");
    }

    #[test]
    fn invalid_names_and_duplicates_are_typed_errors() {
        // acceptance 4 (names)
        for bad in ["", ".", "..", "a/b", "a\0b"] {
            let r = DirNode::new([(bad.to_string(), file(b"x"))]);
            assert!(
                matches!(r, Err(DirTreeError::InvalidName { .. })),
                "{bad:?}"
            );
        }
        let dup = DirNode::new([("a".into(), file(b"1")), ("a".into(), file(b"2"))]);
        assert!(matches!(dup, Err(DirTreeError::DuplicateName { .. })));
    }

    #[test]
    fn proof_verifies_with_only_the_root_and_rejects_any_tamper() {
        // acceptance 3
        let mut s = MemoryStore::new();
        let (root, _) = two_level(&mut s, b"A", b"hello");
        let p = resolve(&s, &root, "sub/b.txt").unwrap();
        assert_eq!(p.nodes.len(), 2);
        let (id, size) = p.verify(&root).unwrap();
        assert_eq!((id, size), (RawContentId::from_content(b"hello"), 5));
        p.verify_file(&root, b"hello").unwrap();

        // wrong file bytes (same length, and different length)
        assert!(p.verify_file(&root, b"hellO").is_err());
        assert!(p.verify_file(&root, b"hell").is_err());
        // wrong root
        let (other, _) = two_level(&mut s, b"A", b"hellO");
        assert!(p.verify(&other).is_err());
        // altered file link
        let mut q = p.clone();
        q.file = file(b"hellO");
        assert!(q.verify(&root).is_err());
        // any single byte of any node
        for n in 0..p.nodes.len() {
            for i in 0..p.nodes[n].len() {
                let mut q = p.clone();
                q.nodes[n][i] ^= 1;
                assert!(q.verify(&root).is_err(), "node {n} byte {i}");
            }
        }
        // altered path
        let mut q = p.clone();
        q.path[1] = "a.txt".into();
        assert!(q.verify(&root).is_err());
    }

    #[test]
    fn resolve_reports_typed_path_errors() {
        let mut s = MemoryStore::new();
        let (root, _) = two_level(&mut s, b"A", b"B");
        let e = |p| resolve(&s, &root, p).unwrap_err();
        assert!(matches!(e("nope"), DirTreeError::NotFound { .. }));
        assert!(matches!(e("a.txt/x"), DirTreeError::NotADirectory { .. }));
        assert!(matches!(e("sub"), DirTreeError::NotAFile { .. }));
        assert!(matches!(e("sub//b.txt"), DirTreeError::InvalidName { .. }));
        assert!(matches!(e("../a.txt"), DirTreeError::InvalidName { .. }));
    }

    /// Same shape and key strings as [`DirNode`], but built without
    /// `DirNode::new`, so it can carry names the name rule forbids.
    #[derive(Serialize)]
    struct Unchecked {
        entries: BTreeMap<String, Link>,
    }

    impl ContentAddressable for Unchecked {
        fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
            canonical::to_canonical_dagcbor(self)
        }
    }

    /// A correctly addressed, canonical node that holds a bad name beside a
    /// good one (`a`). Returns (id, canonical bytes).
    fn malformed(store: &mut MemoryStore, bad: &str) -> (ContentId, Vec<u8>) {
        let entries = BTreeMap::from([("a".to_owned(), file(b"x")), (bad.to_owned(), file(b"y"))]);
        let n = Unchecked { entries };
        let bytes = n.canonical_form().unwrap();
        (store.put_node(&n).unwrap(), bytes)
    }

    #[test]
    fn resolve_rejects_a_decoded_node_with_a_bad_name() {
        for bad in ["..", "a/b", ".", ""] {
            let mut s = MemoryStore::new();
            let (root, _) = malformed(&mut s, bad);
            let r = resolve(&s, &root, "a");
            assert!(
                matches!(r, Err(DirTreeError::InvalidName { .. })),
                "{bad:?}: {r:?}"
            );
        }
    }

    #[test]
    fn verify_rejects_a_decoded_node_with_a_bad_name() {
        for bad in ["..", "a/b", ".", ""] {
            let mut s = MemoryStore::new();
            let (root, bytes) = malformed(&mut s, bad);
            let proof = Proof {
                path: vec!["a".into()],
                nodes: vec![bytes],
                file: file(b"x"),
            };
            let r = proof.verify(&root);
            assert!(
                matches!(r, Err(DirTreeError::InvalidName { .. })),
                "{bad:?}: {r:?}"
            );
        }
    }

    #[test]
    fn a_wrong_size_in_an_authentic_link_is_caught_by_verify_file() {
        // The link carries the CORRECT content id but the wrong size, and the
        // node is correctly addressed, so `verify` honestly returns the claim.
        let real = b"hello";
        let lie = Link::File {
            id: RawContentId::from_content(real),
            size: 99,
        };
        let mut s = MemoryStore::new();
        let root = s.put_node(&node(&[("f", lie)])).unwrap();
        let proof = resolve(&s, &root, "f").unwrap();
        assert_eq!(
            proof.verify(&root).unwrap(),
            (RawContentId::from_content(real), 99)
        );
        assert!(matches!(
            proof.verify_file(&root, real),
            Err(DirTreeError::ProofMismatch)
        ));
    }
}
