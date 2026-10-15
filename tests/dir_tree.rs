//! Filesystem and property tests for the directory tree (#105).
#![cfg(feature = "dir-tree")]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use content_addressable::store::MemoryStore;
use content_addressable::structures::dir_tree::{resolve, snapshot, DirTreeError};
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

    let f = Scratch::new();
    let fifo = f.0.join("pipe");
    let ok = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map(|st| st.success())
        .unwrap_or(false);
    if ok {
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
        let root = snapshot(&mut s, &d.0).unwrap();
        let expected: BTreeMap<_, _> = files.iter().collect();
        for (p, b) in expected {
            let proof = resolve(&s, &root, p).unwrap();
            prop_assert_eq!(proof.nodes.len(), p.split('/').count());
            prop_assert!(proof.verify(&root).is_ok());
            prop_assert!(proof.verify_file(&root, b).is_ok());
            let mut bad = b.clone();
            bad.push(0);
            prop_assert!(proof.verify_file(&root, &bad).is_err());
        }
    }
}
