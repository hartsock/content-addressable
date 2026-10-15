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
//! # Multiple digests
//!
//! A file link may carry `also`: foreign digests (SHA-256, MD5, …) of the same
//! bytes, as raw-codec CIDs. They are part of the hashed node, so adding or
//! swapping one changes the root. [`Proof::verify_file`] requires **all** of
//! them to match, never any one: an any-match rule would make the link exactly
//! as weak as its weakest digest (MD5). BLAKE3 stays the only minted identity
//! (ADR-0003); `also` is agility in what we *verify*, not in what we mint. A
//! digest this build cannot compute is [`DirTreeError::UnsupportedDigest`],
//! never skipped. Computing SHA-256/MD5 needs the default-off `multi-digest`
//! feature; carrying and validating them does not.
//!
//! # Names
//!
//! An entry name is non-empty UTF-8 with no `/`, not `.` or `..`, and no `\0`
//! (a NUL cannot occur in a filesystem name). The rule is applied at build time
//! *and* to every node decoded while resolving or verifying: an untrusted
//! author can mint a node with a bad name and its id still verifies.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::classified::ForeignCid;
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
    /// An `also` digest is malformed: not raw-codec, or its hash code repeats.
    #[error("invalid digest {cid}: {reason}")]
    InvalidDigest {
        /// The offending digest.
        cid: String,
        /// Which rule it breaks.
        reason: &'static str,
    },
    /// An `also` digest uses a hash this build cannot compute.
    #[error("unsupported digest (multihash code {code:#x})")]
    UnsupportedDigest {
        /// The multihash code.
        code: u64,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Link {
    /// A file: the id of its bytes, their length, and any extra digests.
    File {
        /// Id of the file's bytes.
        id: RawContentId,
        /// Length of the file in bytes.
        size: u64,
        /// Further digests of the same bytes, ALL of which must match. Empty
        /// is omitted from the wire; an explicit empty array is non-canonical.
        #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
        also: BTreeSet<ForeignCid>,
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

/// Raw codec: what a digest of file bytes is a CID *of*.
const RAW_CODEC: u64 = 0x55;
#[cfg(feature = "multi-digest")]
const SHA2_256: u64 = 0x12;
#[cfg(feature = "multi-digest")]
const MD5: u64 = 0xd5;

/// The single home of the `also` rule: raw codec, one digest per hash code.
fn validate_link(link: &Link) -> Result<(), DirTreeError> {
    let Link::File { also, .. } = link else {
        return Ok(());
    };
    let mut seen = BTreeSet::new();
    for d in also {
        let reason = if d.codec() != RAW_CODEC {
            "codec is not raw (0x55)"
        } else if !seen.insert(d.hash_code()) {
            "hash code appears more than once"
        } else {
            continue;
        };
        return Err(DirTreeError::InvalidDigest {
            cid: d.to_string(),
            reason,
        });
    }
    Ok(())
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
            validate_link(&link)?;
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
        self.entries.keys().try_for_each(|n| validate_name(n))?;
        self.entries.values().try_for_each(validate_link)
    }
}

impl ContentAddressable for DirNode {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        canonical::to_canonical_dagcbor(self)
    }
}

/// A digest [`file_link`] can carry beside BLAKE3.
#[cfg(feature = "multi-digest")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlg {
    /// SHA-256 (multihash `0x12`).
    Sha256,
    /// MD5 (multihash `0xd5`): a legacy bridge, collision-broken.
    Md5,
}

#[cfg(feature = "multi-digest")]
impl DigestAlg {
    fn foreign_cid(self, bytes: &[u8]) -> ForeignCid {
        use md5::Md5;
        use sha2::{Digest, Sha256};
        let (code, digest) = match self {
            Self::Sha256 => (SHA2_256, Sha256::digest(bytes).to_vec()),
            Self::Md5 => (MD5, Md5::digest(bytes).to_vec()),
        };
        let mh = ipld_core::cid::multihash::Multihash::wrap(code, &digest)
            .expect("a 16/32-byte digest fits the multihash");
        ForeignCid::new(ipld_core::cid::Cid::new_v1(RAW_CODEC, mh))
            .expect("sha2-256/md5 are never the BLAKE3 profile")
    }
}

fn plain_link(bytes: &[u8]) -> Link {
    Link::File {
        id: RawContentId::from_content(bytes),
        size: bytes.len() as u64,
        also: BTreeSet::new(),
    }
}

/// The file link for `bytes`: BLAKE3 identity and size, plus each digest in
/// `also`. An empty `also` is the plain link.
#[cfg(feature = "multi-digest")]
#[must_use]
pub fn file_link(bytes: &[u8], also: &[DigestAlg]) -> Link {
    let Link::File { id, size, .. } = plain_link(bytes) else {
        unreachable!("plain_link is a file")
    };
    Link::File {
        id,
        size,
        also: also.iter().map(|a| a.foreign_cid(bytes)).collect(),
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
    snapshot_root(store, path, &plain_link)
}

/// [`snapshot`], carrying each digest in `also` on every file link.
///
/// # Errors
///
/// See [`DirTreeError`].
#[cfg(feature = "multi-digest")]
pub fn snapshot_with<S: NodeStore + ?Sized>(
    store: &mut S,
    path: &Path,
    also: &[DigestAlg],
) -> Result<ContentId, DirTreeError> {
    snapshot_root(store, path, &|b| file_link(b, also))
}

/// Builds the link for a file's bytes.
type LinkFn<'a> = &'a dyn Fn(&[u8]) -> Link;

fn snapshot_root<S: NodeStore + ?Sized>(
    store: &mut S,
    path: &Path,
    mk: LinkFn<'_>,
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
    snapshot_dir(store, path, mk)
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
    mk: LinkFn<'_>,
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
                id: snapshot_dir(store, &path, mk)?,
            }
        } else if ty.is_file() {
            let bytes = fs::read(&path).map_err(|e| io_err(&path, e))?;
            mk(&bytes)
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
        let link = node
            .entries
            .get(*part)
            .ok_or_else(|| DirTreeError::NotFound {
                path: so_far.clone(),
            })?;
        match (link, i + 1 == parts.len()) {
            (Link::Dir { id }, false) => current = *id,
            (Link::File { .. }, true) => {
                return Ok(Proof {
                    path: parts.iter().map(|p| (*p).to_owned()).collect(),
                    nodes,
                    file: link.clone(),
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
            let link = node.entries.get(name).ok_or_else(mismatch)?;
            match (link, i + 1 == self.nodes.len()) {
                (Link::Dir { id }, false) => expected = *id,
                (Link::File { id, size, .. }, true) if *link == self.file => {
                    return Ok((*id, *size))
                }
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
        // `verify` proved `self.file` is the link in the tree.
        if let Link::File { also, .. } = &self.file {
            also.iter().try_for_each(|d| verify_digest(d, bytes))?;
        }
        Ok(())
    }
}

/// Check one `also` digest. A code this build cannot compute is an error.
fn verify_digest(d: &ForeignCid, bytes: &[u8]) -> Result<(), DirTreeError> {
    #[cfg(feature = "multi-digest")]
    {
        let alg = match d.hash_code() {
            SHA2_256 => Some(DigestAlg::Sha256),
            MD5 => Some(DigestAlg::Md5),
            _ => None,
        };
        if let Some(alg) = alg {
            return if alg.foreign_cid(bytes) == *d {
                Ok(())
            } else {
                Err(DirTreeError::ProofMismatch)
            };
        }
    }
    let _ = bytes;
    Err(DirTreeError::UnsupportedDigest {
        code: d.hash_code(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classified::ForeignCid;
    use crate::store::{MemoryStore, StoreError};

    fn file(b: &[u8]) -> Link {
        Link::File {
            id: RawContentId::from_content(b),
            size: b.len() as u64,
            also: BTreeSet::new(),
        }
    }

    /// `file(b)` carrying the given foreign digests.
    fn file_also(b: &[u8], also: &[ForeignCid]) -> Link {
        Link::File {
            id: RawContentId::from_content(b),
            size: b.len() as u64,
            also: also.iter().copied().collect(),
        }
    }

    /// A foreign CID built from a codec, a multihash code and digest bytes.
    fn foreign(codec: u64, code: u64, digest: &[u8]) -> ForeignCid {
        let mh = ipld_core::cid::multihash::Multihash::wrap(code, digest).unwrap();
        ForeignCid::new(ipld_core::cid::Cid::new_v1(codec, mh)).unwrap()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 6234 / RFC 1321 digests of `b"abc"`, as raw-codec CIDs.
    fn abc_sha256() -> ForeignCid {
        let d = hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        foreign(0x55, 0x12, &d)
    }
    fn abc_md5() -> ForeignCid {
        foreign(0x55, 0xd5, &hex("900150983cd24fb0d6963f7d28e17f72"))
    }

    fn node(entries: &[(&str, Link)]) -> DirNode {
        DirNode::new(entries.iter().map(|(n, l)| (n.to_string(), l.clone()))).unwrap()
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
        let fwd = DirNode::new([("a".into(), x.clone()), ("b".into(), y.clone())]).unwrap();
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
        let (before, z_before) = tree(&[("f", f.clone())], &[]);
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
            also: BTreeSet::new(),
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

    // ---- multi-digest (#107) ----

    /// Same key strings as [`Link::File`] but `also` is ALWAYS written, so it
    /// can put an explicit empty array (or any `also`) on the wire.
    #[derive(Serialize)]
    #[serde(rename_all = "lowercase")]
    enum WireLink {
        File {
            id: RawContentId,
            size: u64,
            also: Vec<ForeignCid>,
        },
    }

    #[derive(Serialize)]
    struct WireNode {
        entries: BTreeMap<String, WireLink>,
    }

    impl ContentAddressable for WireNode {
        fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
            canonical::to_canonical_dagcbor(self)
        }
    }

    /// Store a correctly addressed node whose only entry `f` carries `also`
    /// verbatim; returns (root, canonical bytes).
    fn wire(store: &mut MemoryStore, b: &[u8], also: Vec<ForeignCid>) -> (ContentId, Vec<u8>) {
        let link = WireLink::File {
            id: RawContentId::from_content(b),
            size: b.len() as u64,
            also,
        };
        let n = WireNode {
            entries: BTreeMap::from([("f".to_owned(), link)]),
        };
        let bytes = n.canonical_form().unwrap();
        (store.put_node(&n).unwrap(), bytes)
    }

    #[test]
    fn empty_also_keeps_the_pre_107_root() {
        // Captured on main (d73010f) BEFORE `also` existed.
        let root = node(&[("a", file(b"abc")), ("e", file(b""))])
            .content_id()
            .unwrap();
        assert_eq!(
            root.to_string(),
            "bafyr4igvpbbq3rya5jit6cirnlfvq3k6hx3lde2k4hzfyroggjxhhr2zsy"
        );
    }

    #[test]
    fn an_explicit_empty_also_array_is_rejected_as_non_canonical() {
        let mut s = MemoryStore::new();
        let (root, _) = wire(&mut s, b"x", vec![]);
        let r = resolve(&s, &root, "f");
        assert!(
            matches!(
                r,
                Err(DirTreeError::Store(
                    StoreError::RepresentationMismatch { .. }
                ))
            ),
            "{r:?}"
        );
    }

    #[test]
    fn adding_or_swapping_an_also_digest_changes_the_root() {
        let id = |l: Link| node(&[("f", l)]).content_id().unwrap();
        let none = id(file(b"abc"));
        let sha = id(file_also(b"abc", &[abc_sha256()]));
        let md5 = id(file_also(b"abc", &[abc_md5()]));
        let both = id(file_also(b"abc", &[abc_sha256(), abc_md5()]));
        let all = [none, sha, md5, both];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn a_non_raw_codec_is_invalid_on_build_and_on_decode() {
        // dag-cbor (0x71) codec on a sha2-256 digest
        let bad = foreign(0x71, 0x12, &[0u8; 32]);
        let r = DirNode::new([("f".to_string(), file_also(b"x", &[bad]))]);
        assert!(
            matches!(r, Err(DirTreeError::InvalidDigest { .. })),
            "{r:?}"
        );

        let mut s = MemoryStore::new();
        let (root, bytes) = wire(&mut s, b"x", vec![bad]);
        let r = resolve(&s, &root, "f");
        assert!(
            matches!(r, Err(DirTreeError::InvalidDigest { .. })),
            "{r:?}"
        );
        let proof = Proof {
            path: vec!["f".into()],
            nodes: vec![bytes],
            file: file(b"x"),
        };
        let r = proof.verify(&root);
        assert!(
            matches!(r, Err(DirTreeError::InvalidDigest { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn two_digests_with_one_hash_code_are_invalid_on_build_and_on_decode() {
        let (a, b) = (
            foreign(0x55, 0x12, &[1u8; 32]),
            foreign(0x55, 0x12, &[2u8; 32]),
        );
        let r = DirNode::new([("f".to_string(), file_also(b"x", &[a, b]))]);
        assert!(
            matches!(r, Err(DirTreeError::InvalidDigest { .. })),
            "{r:?}"
        );

        let mut s = MemoryStore::new();
        let (root, bytes) = wire(&mut s, b"x", vec![a, b]);
        let r = resolve(&s, &root, "f");
        assert!(
            matches!(r, Err(DirTreeError::InvalidDigest { .. })),
            "{r:?}"
        );
        let proof = Proof {
            path: vec!["f".into()],
            nodes: vec![bytes],
            file: file(b"x"),
        };
        let r = proof.verify(&root);
        assert!(
            matches!(r, Err(DirTreeError::InvalidDigest { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn a_digest_code_this_build_cannot_compute_is_unsupported_not_skipped() {
        // sha2-512 (0x13) is never computable here, feature or not.
        let sha512 = foreign(0x55, 0x13, &[0u8; 64]);
        let mut s = MemoryStore::new();
        let root = s
            .put_node(&node(&[("f", file_also(b"abc", &[sha512]))]))
            .unwrap();
        let p = resolve(&s, &root, "f").unwrap();
        let r = p.verify_file(&root, b"abc");
        assert!(
            matches!(r, Err(DirTreeError::UnsupportedDigest { code: 0x13 })),
            "{r:?}"
        );
    }

    #[cfg(not(feature = "multi-digest"))]
    #[test]
    fn without_the_feature_even_sha256_is_unsupported() {
        let mut s = MemoryStore::new();
        let root = s
            .put_node(&node(&[("f", file_also(b"abc", &[abc_sha256()]))]))
            .unwrap();
        let p = resolve(&s, &root, "f").unwrap();
        let r = p.verify_file(&root, b"abc");
        assert!(
            matches!(r, Err(DirTreeError::UnsupportedDigest { code: 0x12 })),
            "{r:?}"
        );
    }

    #[cfg(feature = "multi-digest")]
    mod multi {
        use super::*;

        fn proof_for(link: Link) -> (Proof, ContentId) {
            let mut s = MemoryStore::new();
            let root = s.put_node(&node(&[("f", link)])).unwrap();
            (resolve(&s, &root, "f").unwrap(), root)
        }

        #[test]
        fn file_link_matches_the_rfc_vectors_for_abc() {
            let l = file_link(b"abc", &[DigestAlg::Sha256, DigestAlg::Md5]);
            assert_eq!(l, file_also(b"abc", &[abc_sha256(), abc_md5()]));
            // and no digests requested means the plain link
            assert_eq!(file_link(b"abc", &[]), file(b"abc"));
        }

        #[test]
        fn verify_file_passes_when_every_digest_matches() {
            let (p, root) = proof_for(file_link(b"abc", &[DigestAlg::Sha256, DigestAlg::Md5]));
            p.verify_file(&root, b"abc").unwrap();
        }

        #[test]
        fn verify_file_fails_if_any_one_digest_mismatches() {
            // BLAKE3 + size + sha256 are right; only the md5 is of other bytes.
            let md5_other = foreign(0x55, 0xd5, &hex("4911e516e5aa21d327512e0c8b197616")); // md5("abd")
            for also in [
                [abc_sha256(), md5_other],
                // sha256 wrong, md5 right
                [foreign(0x55, 0x12, &[9u8; 32]), abc_md5()],
            ] {
                let (p, root) = proof_for(file_also(b"abc", &also));
                let r = p.verify_file(&root, b"abc");
                assert!(matches!(r, Err(DirTreeError::ProofMismatch)), "{r:?}");
            }
        }

        #[test]
        fn digests_are_checked_against_the_bytes_not_just_the_link() {
            let (p, root) = proof_for(file_link(b"abc", &[DigestAlg::Sha256]));
            assert!(p.verify_file(&root, b"abd").is_err());
        }
    }
}
