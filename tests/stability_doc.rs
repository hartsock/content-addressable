//! Every `unstable-*` feature must carry a stability statement.
//!
//! # The gap this closes
//!
//! `docs/STABILITY.md` is the crate's answer to "may I persist this?" — the
//! whole reason it has a **What is NOT frozen** section. Two default-off
//! features (`unstable-legacy`, `unstable-migration`) shipped with their
//! non-frozen status recorded only in a `Cargo.toml` comment and a module doc,
//! so a consumer consulting the document that owns stability found nothing and
//! had to infer. For `unstable-migration` that inference is expensive in the
//! wrong direction: the record is itself content-addressed, so its field names
//! are load-bearing for its own id, and a consumer who assumed the bytes were
//! settled would persist identity claims that a later rename invalidates.
//!
//! A prose fix alone would rot on the next feature. This is the ratchet: adding
//! an `unstable-*` feature without documenting its stability fails here.
//!
//! Deliberately *not* asserting anything about what the prose says — a test
//! cannot judge whether a stability statement is correct, only that the surface
//! was not shipped unmentioned. The wording stays a review concern.

use std::path::Path;

/// The `unstable-*` feature names declared in `[features]`.
///
/// Hand-parsed rather than pulling a TOML dev-dependency: the shape is one
/// `name = [...]` per line, and this file is the only consumer.
fn declared_unstable_features(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_features = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_features = trimmed == "[features]";
            continue;
        }
        if !in_features || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, rest)) = trimmed.split_once('=') {
            let name = name.trim();
            if name.starts_with("unstable-") && rest.trim_start().starts_with('[') {
                out.push(name.to_string());
            }
        }
    }
    out
}

#[test]
fn every_unstable_feature_has_a_stability_statement() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    let stability =
        std::fs::read_to_string(root.join("docs/STABILITY.md")).expect("read docs/STABILITY.md");

    let features = declared_unstable_features(&manifest);
    assert!(
        !features.is_empty(),
        "parsed no unstable-* features out of [features] — the parser drifted from the manifest, \
         which would make this whole guard vacuous"
    );

    // Everything after the heading is the not-frozen half of the document.
    let (_frozen, not_frozen) = stability
        .split_once("## What is NOT frozen")
        .expect("docs/STABILITY.md must keep its `## What is NOT frozen` section");

    let missing: Vec<&String> = features
        .iter()
        .filter(|f| !not_frozen.contains(&format!("`{f}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "these features ship default-off but are not mentioned under \
         `## What is NOT frozen` in docs/STABILITY.md: {missing:?}.\n\
         A default-off surface with no stability statement leaves consumers to \
         guess whether its bytes are settled. Add a subsection saying what is \
         unfrozen (API, wire bytes, or both) and the condition that would \
         freeze it."
    );
}

#[test]
fn the_parser_finds_the_features_and_ignores_prose() {
    // A miniature manifest: comments, a non-features table, and a feature whose
    // value is not a list (a dep-activating feature) must all be skipped.
    let sample = "\
[package]\n\
unstable-decoy = [\"not in features\"]\n\
\n\
[features]\n\
# unstable-commented = []\n\
unstable-real = []\n\
default = []\n\
unstable-with-deps = [\"dep:serde\"]\n\
\n\
[dependencies]\n\
unstable-also-decoy = [\"nope\"]\n";
    assert_eq!(
        declared_unstable_features(sample),
        vec![
            "unstable-real".to_string(),
            "unstable-with-deps".to_string()
        ],
        "the parser must take unstable-* list-valued keys from [features] only"
    );
}
