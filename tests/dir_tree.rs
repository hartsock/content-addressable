//! Filesystem and property tests for the directory tree (#105).
#![cfg(feature = "dir-tree")]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use content_addressable::store::MemoryStore;
use content_addressable::structures::dir_tree::{resolve, snapshot, DirTreeError, Link};
#[cfg(feature = "multi-digest")]
use content_addressable::structures::dir_tree::{snapshot_with, DigestAlg};
use content_addressable::ContentAddressable;
#[cfg(feature = "multi-digest")]
use content_addressable::ForeignCid;
use proptest::prelude::*;

/// A unique scratch dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "ca-dir-tree-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, bytes).unwrap();
}

#[test]
fn snapshot_is_stable_and_sensitive() {
    let (a, b) = (Scratch::new(), Scratch::new());
    // same content, written in opposite orders
    write(&a.0, "x/one.txt", b"1");
    write(&a.0, "two.txt", b"2");
    write(&b.0, "two.txt", b"2");
    write(&b.0, "x/one.txt", b"1");
    let mut s = MemoryStore::new();
    let ra = snapshot(&mut s, &a.0).unwrap();
    assert_eq!(ra, snapshot(&mut s, &b.0).unwrap());
    write(&b.0, "x/one.txt", b"1!");
    assert_ne!(ra, snapshot(&mut s, &b.0).unwrap());
}

#[test]
fn a_single_file_snapshots_to_a_file_link_that_resolves_and_verifies() {
    // #109: a regular file is a root; the cited id is the Link's id.
    let d = Scratch::new();
    write(&d.0, "f.txt", b"hello");
    let mut s = MemoryStore::new();
    let link = snapshot(&mut s, &d.0.join("f.txt")).unwrap();
    assert!(matches!(&link, Link::File { size: 5, .. }), "{link:?}");
    let root = link.content_id().unwrap();
    let p = resolve(&s, &root, "").unwrap();
    p.verify_file(&root, b"hello").unwrap();
    assert!(p.verify_file(&root, b"hellO").is_err());
    assert!(matches!(
        resolve(&s, &root, "x"),
        Err(DirTreeError::NotADirectory { .. })
    ));

    // the same bytes as a one-file directory get a different root
    let dir = snapshot(&mut s, &d.0).unwrap();
    assert!(matches!(dir, Link::Dir { .. }));
    assert_ne!(dir.content_id().unwrap(), root);
}

#[cfg(feature = "multi-digest")]
#[test]
fn a_single_file_root_carries_and_verifies_extra_digests() {
    let d = Scratch::new();
    write(&d.0, "f", b"abc");
    let mut s = MemoryStore::new();
    let link = snapshot_with(&mut s, &d.0.join("f"), &[DigestAlg::Sha256, DigestAlg::Md5]).unwrap();
    let Link::File { also, .. } = &link else {
        panic!("not a file")
    };
    assert_eq!(also.len(), 2);
    let root = link.content_id().unwrap();
    let p = resolve(&s, &root, "").unwrap();
    p.verify_file(&root, b"abc").unwrap();
    assert!(p.verify_file(&root, b"abd").is_err());
    assert_ne!(
        root,
        snapshot(&mut s, &d.0.join("f"))
            .unwrap()
            .content_id()
            .unwrap()
    );
}

#[cfg(unix)]
#[test]
fn symlinks_and_fifos_are_refused() {
    let d = Scratch::new();
    write(&d.0, "real.txt", b"r");
    std::os::unix::fs::symlink(d.0.join("real.txt"), d.0.join("link")).unwrap();
    let mut s = MemoryStore::new();
    assert!(matches!(
        snapshot(&mut s, &d.0),
        Err(DirTreeError::Symlink { .. })
    ));
    assert!(matches!(
        snapshot(&mut s, &d.0.join("link")),
        Err(DirTreeError::Symlink { .. })
    ));

    let f = Scratch::new();
    let fifo = f.0.join("pipe");
    let ok = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map(|st| st.success())
        .unwrap_or(false);
    if ok {
        assert!(matches!(
            snapshot(&mut s, &fifo),
            Err(DirTreeError::UnsupportedFileType { .. })
        ));
        assert!(matches!(
            snapshot(&mut s, &f.0),
            Err(DirTreeError::UnsupportedFileType { .. })
        ));
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_names_are_refused() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let d = Scratch::new();
    // Some filesystems (e.g. macOS APFS) refuse to create such a name; skip there.
    if fs::write(d.0.join(OsStr::from_bytes(b"\xff")), b"x").is_err() {
        return;
    }
    let r = snapshot(&mut MemoryStore::new(), &d.0);
    assert!(matches!(r, Err(DirTreeError::InvalidName { .. })), "{r:?}");
}

#[test]
fn empty_dirs_are_allowed() {
    let d = Scratch::new();
    fs::create_dir(d.0.join("empty")).unwrap();
    snapshot(&mut MemoryStore::new(), &d.0).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// acceptance 5: build -> resolve -> verify round-trips for every file.
    #[test]
    fn random_trees_round_trip(
        files in proptest::collection::btree_map(
            proptest::collection::vec("[a-z]{1,3}", 1..4).prop_map(|v| v.join("/")),
            proptest::collection::vec(any::<u8>(), 0..16),
            1..12,
        )
    ) {
        // A path that is both a file and a directory prefix cannot exist on disk.
        let paths: Vec<&String> = files.keys().collect();
        prop_assume!(!paths.iter().any(|p| paths.iter().any(|q| q.starts_with(&format!("{p}/")))));

        let d = Scratch::new();
        for (p, b) in &files {
            write(&d.0, p, b);
        }
        let mut s = MemoryStore::new();
        let root = snapshot(&mut s, &d.0).unwrap().content_id().unwrap();
        let expected: BTreeMap<_, _> = files.iter().collect();
        for (p, b) in expected {
            let proof = resolve(&s, &root, p).unwrap();
            prop_assert_eq!(proof.nodes.len(), p.split('/').count() + 1);
            prop_assert!(proof.verify(&root).is_ok());
            prop_assert!(proof.verify_file(&root, b).is_ok());
            let mut bad = b.clone();
            bad.push(0);
            prop_assert!(proof.verify_file(&root, &bad).is_err());
        }
    }
}

#[cfg(feature = "multi-digest")]
#[test]
fn snapshot_with_carries_digests_that_verify_file_checks() {
    let d = Scratch::new();
    write(&d.0, "x/f.txt", b"abc");
    let mut s = MemoryStore::new();
    let plain = snapshot(&mut s, &d.0).unwrap().content_id().unwrap();
    let multi = snapshot_with(&mut s, &d.0, &[DigestAlg::Sha256, DigestAlg::Md5])
        .unwrap()
        .content_id()
        .unwrap();
    assert_ne!(plain, multi, "also is part of the hashed node");
    assert_eq!(
        plain,
        snapshot_with(&mut s, &d.0, &[])
            .unwrap()
            .content_id()
            .unwrap()
    );

    let p = resolve(&s, &multi, "x/f.txt").unwrap();
    // Exactly the two RFC digests of "abc" (6234 / 1321): dropping either fails.
    let cid = |code: u64, hex: &str| {
        let d: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mh = ipld_core::cid::multihash::Multihash::wrap(code, &d).unwrap();
        ForeignCid::new(ipld_core::cid::Cid::new_v1(0x55, mh)).unwrap()
    };
    let want = [
        cid(
            0x12,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        cid(0xd5, "900150983cd24fb0d6963f7d28e17f72"),
    ];
    let Link::File { also, .. } = &p.file else {
        panic!("not a file")
    };
    assert_eq!(also.iter().copied().collect::<Vec<_>>().len(), 2);
    assert!(want.iter().all(|w| also.contains(w)), "{also:?}");
    p.verify_file(&multi, b"abc").unwrap();
    assert!(p.verify_file(&multi, b"abd").is_err());
}
