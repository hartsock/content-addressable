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
//! [`snapshot`] puts the root [`Link`] in the [`NodeStore`], and for a
//! directory also each dag-cbor [`DirNode`] under it.
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
    /// [`DirTreeError::InvalidName`], [`DirTreeError::DuplicateName`], or
    /// [`DirTreeError::InvalidDigest`] if a file link's `also` holds a
    /// non-raw-codec digest or two digests with one hash code. The same rules
    /// are re-applied to nodes decoded by [`resolve`] and [`Proof::verify`],
    /// which return the same error.
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

/// A root is a [`Link`]: its externally tagged wire form (`file` / `dir`) says
/// which kind of thing the id names.
impl ContentAddressable for Link {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        canonical::to_canonical_dagcbor(self)
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

/// Snapshot the file or directory at `path` into `store`, returning the root
/// [`Link`]. Cite it by `link.content_id()`, which is also stored, so
/// [`resolve`] can fetch it.
///
/// A regular file is a [`Link::File`]; a directory is a [`Link::Dir`] naming
/// its [`DirNode`]. Symlinks are refused, as are fifos, sockets and devices;
/// empty directories are fine. File bytes are hashed, not stored.
///
/// # Errors
///
/// See [`DirTreeError`].
pub fn snapshot<S: NodeStore + ?Sized>(store: &mut S, path: &Path) -> Result<Link, DirTreeError> {
    snapshot_root(store, path, &plain_link)
}

/// [`snapshot`], carrying each digest in `also` on every file link (the root
/// itself, for a single file).
///
/// # Errors
///
/// See [`DirTreeError`].
#[cfg(feature = "multi-digest")]
pub fn snapshot_with<S: NodeStore + ?Sized>(
    store: &mut S,
    path: &Path,
    also: &[DigestAlg],
) -> Result<Link, DirTreeError> {
    snapshot_root(store, path, &|b| file_link(b, also))
}

/// Builds the link for a file's bytes.
type LinkFn<'a> = &'a dyn Fn(&[u8]) -> Link;

fn snapshot_root<S: NodeStore + ?Sized>(
    store: &mut S,
    path: &Path,
    mk: LinkFn<'_>,
) -> Result<Link, DirTreeError> {
    let meta = fs::symlink_metadata(path).map_err(|e| io_err(path, e))?;
    if meta.file_type().is_symlink() {
        return Err(DirTreeError::Symlink {
            path: path.to_owned(),
        });
    }
    let link = if meta.is_dir() {
        Link::Dir {
            id: snapshot_dir(store, path, mk)?,
        }
    } else if meta.is_file() {
        mk(&fs::read(path).map_err(|e| io_err(path, e))?)
    } else {
        return Err(DirTreeError::UnsupportedFileType {
            path: path.to_owned(),
        });
    };
    validate_link(&link)?;
    store.put_node(&link)?;
    Ok(link)
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

/// A path's file link plus the canonical bytes of the root [`Link`] and then
/// each directory node on the way. `nodes.len()` is the path depth plus one;
/// a single-file root has an empty `path` and one node.
///
/// Fields are public: a proof is a plain value, and [`verify`](Self::verify)
/// trusts none of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The path components, root-relative.
    pub path: Vec<String>,
    /// Canonical bytes of the root link, then each directory node walked.
    pub nodes: Vec<Vec<u8>>,
    /// The file link found at the end.
    pub file: Link,
}

/// Resolve `path` (`/`-separated) under `root` to a file, with its proof.
///
/// `root` is the id of a [`Link`] (see [`snapshot`]). A file root takes the
/// empty path and proves itself; a directory root takes a non-empty path.
///
/// # Errors
///
/// [`DirTreeError::NotFound`], [`DirTreeError::NotADirectory`] (a path under a
/// file, root included), [`DirTreeError::NotAFile`] (empty path on a directory
/// root, or a path ending at a directory), [`DirTreeError::InvalidName`],
/// [`DirTreeError::InvalidDigest`] (a decoded link breaks the `also` rules), or
/// a store error.
pub fn resolve<S: NodeStore + ?Sized>(
    store: &S,
    root: &ContentId,
    path: &str,
) -> Result<Proof, DirTreeError> {
    let parts: Vec<&str> = if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').collect()
    };
    parts.iter().try_for_each(|p| validate_name(p))?;
    let root_link: Link = store.get_node(root)?;
    validate_link(&root_link)?;
    let mut nodes = vec![store.get(root)?];
    let mut current = match root_link {
        Link::File { .. } if parts.is_empty() => {
            return Ok(Proof {
                path: Vec::new(),
                nodes,
                file: root_link,
            })
        }
        Link::File { .. } => {
            return Err(DirTreeError::NotADirectory {
                path: parts[0].to_owned(),
            })
        }
        Link::Dir { .. } if parts.is_empty() => {
            return Err(DirTreeError::NotAFile {
                path: String::new(),
            })
        }
        Link::Dir { id } => id,
    };
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
    /// [`DirTreeError::ProofMismatch`] if any hop fails, including `nodes[0]`
    /// not being the root's link, or a file root carrying a path;
    /// [`DirTreeError::InvalidName`] / [`DirTreeError::InvalidDigest`] if a
    /// decoded link or node breaks the name or `also` rules.
    pub fn verify(&self, root: &ContentId) -> Result<(RawContentId, u64), DirTreeError> {
        let mismatch = || DirTreeError::ProofMismatch;
        let first = self.nodes.first().ok_or_else(mismatch)?;
        if ContentId::from_canonical_bytes(first) != *root {
            return Err(mismatch());
        }
        let root_link = Link::from_canonical_form(first)?;
        validate_link(&root_link)?;
        let mut expected = match root_link {
            Link::File { id, size, .. } => {
                return if self.path.is_empty() && self.nodes.len() == 1 && root_link == self.file {
                    Ok((id, size))
                } else {
                    Err(mismatch())
                }
            }
            Link::Dir { id } => id,
        };
        if self.path.is_empty() || self.nodes.len() != self.path.len() + 1 {
            return Err(mismatch());
        }
        let hops = self.nodes[1..].iter().zip(&self.path);
        for (i, (bytes, name)) in hops.enumerate() {
            if ContentId::from_canonical_bytes(bytes) != expected {
                return Err(mismatch());
            }
            let node = DirNode::from_canonical_form(bytes)?;
            node.validate()?;
            let link = node.entries.get(name).ok_or_else(mismatch)?;
            match (link, i + 1 == self.path.len()) {
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
    /// [`DirTreeError::ProofMismatch`] if the proof, the size, BLAKE3 or any
    /// `also` digest does not match. [`DirTreeError::UnsupportedDigest`] if
    /// `also` holds a hash this build cannot compute: every code other than
    /// SHA-256 (`0x12`) and MD5 (`0xd5`), and **all** codes when the
    /// `multi-digest` feature is off. Such a digest is never skipped.
    /// [`DirTreeError::InvalidDigest`] as for [`verify`](Self::verify).
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

    /// Store `dir` and a root [`Link::Dir`] over it; returns the root id.
    fn dir_root(store: &mut MemoryStore, dir: &DirNode) -> ContentId {
        let id = store.put_node(dir).unwrap();
        store.put_node(&Link::Dir { id }).unwrap()
    }

    /// Put a two-level tree: `{a.txt, sub/{b.txt}}`; returns (root link, sub).
    fn two_level(store: &mut MemoryStore, a: &[u8], b: &[u8]) -> (ContentId, ContentId) {
        let sub = store.put_node(&node(&[("b.txt", file(b))])).unwrap();
        let root = node(&[("a.txt", file(a)), ("sub", Link::Dir { id: sub })]);
        (dir_root(store, &root), sub)
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
        assert_eq!(p.nodes.len(), 3, "root link + two dirs");
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
    /// good one (`a`), under a root link. Returns (root, proof nodes).
    fn malformed(store: &mut MemoryStore, bad: &str) -> (ContentId, Vec<Vec<u8>>) {
        let entries = BTreeMap::from([("a".to_owned(), file(b"x")), (bad.to_owned(), file(b"y"))]);
        let n = Unchecked { entries };
        let bytes = n.canonical_form().unwrap();
        let id = store_id(store, &n);
        let (root, link) = dir_link(store, id);
        (root, vec![link, bytes])
    }

    fn store_id<T: ContentAddressable>(store: &mut MemoryStore, n: &T) -> ContentId {
        store.put_node(n).unwrap()
    }

    /// Put a root [`Link::Dir`] over `id`; returns (root, its canonical bytes).
    fn dir_link(store: &mut MemoryStore, id: ContentId) -> (ContentId, Vec<u8>) {
        root_of(store, &Link::Dir { id })
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
            let (root, nodes) = malformed(&mut s, bad);
            let proof = Proof {
                path: vec!["a".into()],
                nodes,
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
        let root = dir_root(&mut s, &node(&[("f", lie)]));
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

    // ---- single-file roots (#109) ----

    /// Put `link` as a root; returns (root id, its canonical bytes).
    fn root_of(store: &mut MemoryStore, link: &Link) -> (ContentId, Vec<u8>) {
        (
            store.put_node(link).unwrap(),
            link.canonical_form().unwrap(),
        )
    }

    #[test]
    fn a_file_root_and_a_dir_root_over_the_same_bytes_differ() {
        let mut s = MemoryStore::new();
        let (f, _) = root_of(&mut s, &file(b"same"));
        let dir = s.put_node(&node(&[("f", file(b"same"))])).unwrap();
        let (d, _) = root_of(&mut s, &Link::Dir { id: dir });
        assert_ne!(f, d);
    }

    #[test]
    fn a_file_root_resolves_empty_path_to_its_own_proof() {
        let mut s = MemoryStore::new();
        let (root, bytes) = root_of(&mut s, &file(b"abc"));
        let p = resolve(&s, &root, "").unwrap();
        assert_eq!((p.path.len(), p.nodes.clone()), (0, vec![bytes]));
        assert_eq!(p.file, file(b"abc"));
        p.verify_file(&root, b"abc").unwrap();
        assert!(p.verify_file(&root, b"abd").is_err());
    }

    #[test]
    fn a_file_root_with_a_path_is_not_a_directory() {
        let mut s = MemoryStore::new();
        let (root, _) = root_of(&mut s, &file(b"abc"));
        let r = resolve(&s, &root, "x");
        assert!(
            matches!(r, Err(DirTreeError::NotADirectory { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn a_dir_root_with_an_empty_path_is_not_a_file() {
        let mut s = MemoryStore::new();
        let root = dir_root(&mut s, &node(&[("f", file(b"x"))]));
        let r = resolve(&s, &root, "");
        assert!(matches!(r, Err(DirTreeError::NotAFile { .. })), "{r:?}");
    }

    #[test]
    fn tampering_nodes_zero_is_a_proof_mismatch() {
        let mut s = MemoryStore::new();
        let (root, _) = two_level(&mut s, b"A", b"hello");
        let p = resolve(&s, &root, "sub/b.txt").unwrap();
        for i in 0..p.nodes[0].len() {
            let mut q = p.clone();
            q.nodes[0][i] ^= 1;
            assert!(q.verify(&root).is_err(), "root link byte {i}");
        }
        let mut q = p.clone();
        q.nodes.remove(0);
        assert!(matches!(q.verify(&root), Err(DirTreeError::ProofMismatch)));
    }

    #[test]
    fn a_file_link_root_with_a_path_in_the_proof_is_refused() {
        let mut s = MemoryStore::new();
        let (root, bytes) = root_of(&mut s, &file(b"abc"));
        let p = Proof {
            path: vec!["x".into()],
            nodes: vec![bytes.clone(), bytes],
            file: file(b"abc"),
        };
        assert!(matches!(p.verify(&root), Err(DirTreeError::ProofMismatch)));
        let p = Proof {
            path: vec!["x".into()],
            nodes: vec![p.nodes[0].clone()],
            file: file(b"abc"),
        };
        assert!(matches!(p.verify(&root), Err(DirTreeError::ProofMismatch)));
    }

    #[test]
    fn a_file_root_with_a_swapped_file_link_is_refused() {
        let mut s = MemoryStore::new();
        let (root, bytes) = root_of(&mut s, &file(b"abc"));
        let p = Proof {
            path: vec![],
            nodes: vec![bytes],
            file: file(b"abd"),
        };
        assert!(matches!(p.verify(&root), Err(DirTreeError::ProofMismatch)));
    }

    #[test]
    fn a_file_root_with_a_malformed_also_is_invalid_digest_on_resolve_and_verify() {
        // #109 review: root links are decoded from untrusted bytes too.
        let non_raw = foreign(0x71, 0x12, &[0u8; 32]);
        let dup = [
            foreign(0x55, 0x12, &[1u8; 32]),
            foreign(0x55, 0x12, &[2u8; 32]),
        ];
        for also in [&[non_raw][..], &dup[..]] {
            let link = file_also(b"x", also);
            let mut s = MemoryStore::new();
            let (root, bytes) = root_of(&mut s, &link);
            let r = resolve(&s, &root, "");
            assert!(
                matches!(r, Err(DirTreeError::InvalidDigest { .. })),
                "{r:?}"
            );
            let proof = Proof {
                path: vec![],
                nodes: vec![bytes],
                file: link,
            };
            let r = proof.verify(&root);
            assert!(
                matches!(r, Err(DirTreeError::InvalidDigest { .. })),
                "{r:?}"
            );
        }
    }

    #[test]
    fn a_file_root_proof_with_a_surplus_node_is_refused() {
        let mut s = MemoryStore::new();
        let (root, bytes) = root_of(&mut s, &file(b"abc"));
        let p = Proof {
            path: vec![],
            nodes: vec![bytes.clone(), bytes],
            file: file(b"abc"),
        };
        assert!(matches!(p.verify(&root), Err(DirTreeError::ProofMismatch)));
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
    /// verbatim; returns (root link, proof nodes).
    fn wire(store: &mut MemoryStore, b: &[u8], also: Vec<ForeignCid>) -> (ContentId, Vec<Vec<u8>>) {
        let link = WireLink::File {
            id: RawContentId::from_content(b),
            size: b.len() as u64,
            also,
        };
        let n = WireNode {
            entries: BTreeMap::from([("f".to_owned(), link)]),
        };
        let bytes = n.canonical_form().unwrap();
        let id = store_id(store, &n);
        let (root, link) = dir_link(store, id);
        (root, vec![link, bytes])
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
    fn dir_node_bytes_are_pinned_across_the_link_root_change() {
        // #109: DirNode bytes must not change. Captured on 21ffa61, BEFORE
        // single-file roots; a nested tree so a Dir link is covered too.
        let sub = node(&[("b", file(b"bee"))]).content_id().unwrap();
        let root = node(&[("a", file(b"abc")), ("sub", Link::Dir { id: sub })]);
        assert_eq!(
            root.content_id().unwrap().to_string(),
            "bafyr4idqcqizht5j4m53lpnfy3wnnmxr3iazj2hp5trcdphbdxt6xelm2m"
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
        let (root, nodes) = wire(&mut s, b"x", vec![bad]);
        let r = resolve(&s, &root, "f");
        assert!(
            matches!(r, Err(DirTreeError::InvalidDigest { .. })),
            "{r:?}"
        );
        let proof = Proof {
            path: vec!["f".into()],
            nodes,
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
        let (root, nodes) = wire(&mut s, b"x", vec![a, b]);
        let r = resolve(&s, &root, "f");
        assert!(
            matches!(r, Err(DirTreeError::InvalidDigest { .. })),
            "{r:?}"
        );
        let proof = Proof {
            path: vec!["f".into()],
            nodes,
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
        let root = dir_root(&mut s, &node(&[("f", file_also(b"abc", &[sha512]))]));
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
        let root = dir_root(&mut s, &node(&[("f", file_also(b"abc", &[abc_sha256()]))]));
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
            let root = dir_root(&mut s, &node(&[("f", link)]));
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
    }
}
