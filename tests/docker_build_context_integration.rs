//! Guards the Dockerfile's build context against drifting out of sync with
//! Cargo.toml.
//!
//! The v0.10.0 release container build failed in 20 seconds with exit code 101
//! because `Cargo.toml` gained `[workspace] members = ["tools/loadgen"]` and
//! eight `[[bench]]` targets, while the Dockerfile still copied only
//! `Cargo.toml`, `Cargo.lock` and `src/` into the image.
//!
//! The subtlety that made this easy to miss: cargo resolves workspace members
//! and validates every declared target path when it *parses* the manifest, not
//! when it decides what to compile. `default-members = ["."]` therefore does
//! not save you — `cargo build --release` still hard-fails on a missing
//! `tools/loadgen/Cargo.toml` or a missing `benches/<name>.rs`.
//!
//! This test reproduces that check cheaply, without invoking Docker: it asserts
//! that every path cargo will insist on is actually copied into the builder
//! stage. `docker_build_succeeds` below is the real end-to-end proof, but it is
//! `#[ignore]`d because it needs a Docker daemon and takes minutes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Source paths copied into the builder stage, relative to the build context.
///
/// `COPY --from=<stage>` lines are excluded: they pull from an earlier image
/// layer, not from the build context, so they say nothing about which repo
/// files are available.
fn builder_stage_copy_sources(dockerfile: &str) -> BTreeSet<String> {
    let mut sources = BTreeSet::new();

    for line in dockerfile.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("COPY ") else {
            continue;
        };
        if rest.contains("--from=") {
            continue;
        }

        let tokens: Vec<&str> = rest
            .split_whitespace()
            .filter(|t| !t.starts_with("--"))
            .collect();

        // Final token is the destination; everything before it is a source.
        if let Some((_dest, srcs)) = tokens.split_last() {
            sources.extend(srcs.iter().map(|s| s.to_string()));
        }
    }

    sources
}

/// True when `required` is copied, either directly or as part of a copied
/// directory (`COPY benches ./benches` covers `benches/foo.rs`).
fn is_covered(required: &str, copy_sources: &BTreeSet<String>) -> bool {
    copy_sources.iter().any(|src| {
        let src = src.trim_start_matches("./");
        required == src || required.starts_with(&format!("{src}/"))
    })
}

/// Paths that `cargo build` will refuse to start without, derived from
/// Cargo.toml rather than hardcoded, so new members and benches are caught
/// automatically.
fn paths_cargo_requires(manifest: &toml::Value, root: &Path) -> Vec<String> {
    let mut required = Vec::new();

    if let Some(members) = manifest
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
    {
        for member in members.iter().filter_map(|m| m.as_str()) {
            required.push(format!("{member}/Cargo.toml"));
        }
    }

    if let Some(benches) = manifest.get("bench").and_then(|b| b.as_array()) {
        for bench in benches {
            if let Some(path) = bench.get("path").and_then(|p| p.as_str()) {
                required.push(path.to_string());
                continue;
            }

            let Some(name) = bench.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            // Cargo accepts either layout; require whichever one is on disk.
            let nested = format!("benches/{name}/main.rs");
            if root.join(&nested).exists() {
                required.push(nested);
            } else {
                required.push(format!("benches/{name}.rs"));
            }
        }
    }

    required
}

#[test]
fn dockerfile_copies_every_path_cargo_requires() {
    let root = repo_root();
    let manifest: toml::Value = std::fs::read_to_string(root.join("Cargo.toml"))
        .expect("read Cargo.toml")
        .parse()
        .expect("parse Cargo.toml");
    let dockerfile = std::fs::read_to_string(root.join("Dockerfile")).expect("read Dockerfile");

    let copy_sources = builder_stage_copy_sources(&dockerfile);
    let required = paths_cargo_requires(&manifest, &root);

    assert!(
        !required.is_empty(),
        "derived no required paths from Cargo.toml — the manifest parsing above \
         has drifted and this test is no longer guarding anything"
    );

    let missing: Vec<&String> = required
        .iter()
        .filter(|path| !is_covered(path, &copy_sources))
        .collect();

    assert!(
        missing.is_empty(),
        "Cargo.toml declares paths the Dockerfile never copies into the build \
         context, so `cargo build --release` will fail at manifest-parse time \
         inside the image (this is exactly what broke the v0.10.0 release).\n\
         Missing: {missing:?}\n\
         Dockerfile COPY sources: {copy_sources:?}\n\
         Fix by adding the appropriate `COPY` to the builder stage."
    );
}

/// Every path the manifest declares should also exist in the repo. Catches the
/// inverse drift: a bench renamed or deleted without updating Cargo.toml, which
/// breaks the container build for the same manifest-parse reason.
#[test]
fn every_path_cargo_requires_exists_in_repo() {
    let root = repo_root();
    let manifest: toml::Value = std::fs::read_to_string(root.join("Cargo.toml"))
        .expect("read Cargo.toml")
        .parse()
        .expect("parse Cargo.toml");

    let missing: Vec<String> = paths_cargo_requires(&manifest, &root)
        .into_iter()
        .filter(|path| !root.join(path).exists())
        .collect();

    assert!(
        missing.is_empty(),
        "Cargo.toml declares paths that do not exist in the repo: {missing:?}"
    );
}

#[test]
fn copy_source_parsing_handles_dockerfile_forms() {
    let sources = builder_stage_copy_sources(
        "FROM rust AS builder\n\
         COPY Cargo.toml Cargo.lock ./\n\
         COPY src ./src\n\
         COPY --chown=1000:1000 benches ./benches\n\
         RUN cargo build --release\n\
         FROM debian\n\
         COPY --from=builder /app/target/release/logthing /usr/local/bin/logthing\n",
    );

    let expected: BTreeSet<String> = ["Cargo.toml", "Cargo.lock", "src", "benches"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(sources, expected, "--from= copies must be excluded");
}

#[test]
fn coverage_matches_directories_but_not_prefixes() {
    let sources: BTreeSet<String> = ["src", "./benches"].iter().map(|s| s.to_string()).collect();

    assert!(is_covered("src", &sources));
    assert!(is_covered("benches/syslog_parse_recv_path.rs", &sources));
    // `src` must not be read as covering a sibling that merely shares a prefix.
    assert!(!is_covered("src_extra/lib.rs", &sources));
    assert!(!is_covered("tools/loadgen/Cargo.toml", &sources));
}

/// The real thing: build the image the way release.yml does. Ignored by default
/// because it needs a Docker daemon and takes several minutes.
///
///   cargo test --test docker_build_context_integration -- --ignored
#[test]
#[ignore = "requires a Docker daemon; takes minutes"]
fn docker_build_succeeds() {
    let root = repo_root();
    let output = Command::new("docker")
        .args([
            "build",
            "--target",
            "builder",
            "-t",
            "logthing-ci-check",
            ".",
        ])
        .current_dir(&root)
        .output()
        .expect("run docker build (is Docker installed and running?)");

    assert!(
        output.status.success(),
        "docker build of the builder stage failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
