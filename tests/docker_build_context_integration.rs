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
//! that every path cargo will insist on is actually copied into the stage that
//! runs `cargo build`. `docker_build_succeeds` below is the real end-to-end
//! proof, but it is `#[ignore]`d because it needs a Docker daemon and takes
//! minutes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Dockerfile instructions as logical lines, with backslash continuations
/// joined and comments/blanks dropped, so each entry starts with its keyword.
fn logical_lines(dockerfile: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = String::new();

    for raw in dockerfile.lines() {
        let trimmed = raw.trim();
        if pending.is_empty() && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }

        match trimmed.strip_suffix('\\') {
            Some(head) => {
                pending.push_str(head.trim_end());
                pending.push(' ');
            }
            None => {
                pending.push_str(trimmed);
                lines.push(std::mem::take(&mut pending));
            }
        }
    }

    // A trailing continuation with nothing after it; keep it rather than
    // silently dropping an instruction.
    if !pending.is_empty() {
        lines.push(pending);
    }

    lines
}

/// Source paths copied into the stage that runs `cargo build`, relative to the
/// build context.
///
/// Scoping to that one stage is the whole point: a `COPY` sitting in the
/// runtime stage puts nothing in front of cargo, so crediting it would let
/// exactly the regression this file guards against slip through.
///
/// `COPY --from=<stage>` lines are excluded: they pull from an earlier image
/// layer, not from the build context, so they say nothing about which repo
/// files are available.
///
/// Only the plain `COPY <src>... <dest>` form is understood. The JSON-array
/// form is valid Dockerfile syntax but would be mis-read, so it panics loudly
/// rather than under-reporting coverage and failing a legitimate release with a
/// confusing "missing path" error.
fn copy_sources_for_cargo_build_stage(dockerfile: &str) -> BTreeSet<String> {
    let mut per_stage: Vec<(BTreeSet<String>, bool)> = Vec::new();

    for line in logical_lines(dockerfile) {
        let keyword = line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let rest = line[keyword.len()..].trim();

        if keyword == "FROM" {
            per_stage.push((BTreeSet::new(), false));
            continue;
        }

        // Instructions before the first FROM (ARG) belong to no stage.
        let Some((sources, runs_cargo_build)) = per_stage.last_mut() else {
            continue;
        };

        match keyword.as_str() {
            "RUN" if rest.contains("cargo build") => *runs_cargo_build = true,
            "COPY" => {
                if rest.contains("--from=") {
                    continue;
                }
                assert!(
                    !rest.starts_with('['),
                    "Dockerfile uses the JSON-array COPY form ({line:?}), which \
                     this guard does not parse. Use the plain \
                     `COPY <src>... <dest>` form, or teach the parser."
                );

                let tokens: Vec<&str> = rest
                    .split_whitespace()
                    .filter(|t| !t.starts_with("--"))
                    .collect();

                // Final token is the destination; everything before it is a source.
                if let Some((_dest, srcs)) = tokens.split_last() {
                    sources.extend(srcs.iter().map(|s| s.to_string()));
                }
            }
            _ => {}
        }
    }

    let mut building: Vec<BTreeSet<String>> = per_stage
        .into_iter()
        .filter(|(_, runs_cargo_build)| *runs_cargo_build)
        .map(|(sources, _)| sources)
        .collect();

    assert_eq!(
        building.len(),
        1,
        "expected exactly one Dockerfile stage running `cargo build`, found {}. \
         This guard needs to know which stage's build context cargo parses.",
        building.len()
    );

    building.remove(0)
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

    let copy_sources = copy_sources_for_cargo_build_stage(&dockerfile);
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

fn sources(dockerfile: &str) -> BTreeSet<String> {
    copy_sources_for_cargo_build_stage(dockerfile)
}

#[test]
fn copy_source_parsing_handles_dockerfile_forms() {
    let parsed = sources(
        "# a comment\n\
         FROM rust AS builder\n\
         COPY Cargo.toml Cargo.lock ./\n\
         copy src ./src\n\
         COPY --chown=1000:1000 --link benches ./benches\n\
         RUN apt-get update && apt-get install -y \\\n\
             pkg-config \\\n\
             libssl-dev\n\
         RUN cargo build --release\n\
         FROM debian\n\
         COPY --from=builder /app/target/release/logthing /usr/local/bin/logthing\n\
         COPY logthing.toml /etc/logthing/config.toml\n",
    );

    let expected: BTreeSet<String> = ["Cargo.toml", "Cargo.lock", "src", "benches"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        parsed, expected,
        "expected lowercase `copy`, flag-prefixed COPY and multi-source COPY to \
         parse, and --from= plus runtime-stage copies to be excluded"
    );
}

/// The regression this scoping exists to catch: files copied only into the
/// runtime stage are never in front of cargo, so they must not count.
#[test]
fn runtime_stage_copies_do_not_count_as_coverage() {
    let parsed = sources(
        "FROM rust AS builder\n\
         COPY src ./src\n\
         RUN cargo build --release\n\
         FROM debian\n\
         COPY tools ./tools\n\
         COPY benches ./benches\n",
    );

    assert!(
        !is_covered("tools/loadgen/Cargo.toml", &parsed),
        "a COPY in the runtime stage puts nothing in front of cargo and must \
         not be credited as build-context coverage"
    );
    assert!(!is_covered("benches/wef_to_record_batch.rs", &parsed));
    assert!(is_covered("src", &parsed));
}

/// Continuation lines must not be mistaken for instructions in their own right.
#[test]
fn logical_lines_joins_continuations() {
    let joined = logical_lines(
        "RUN apt-get update && apt-get install -y \\\n    pkg-config \\\n    libssl-dev\nCOPY src ./src\n",
    );

    assert_eq!(
        joined,
        vec![
            "RUN apt-get update && apt-get install -y pkg-config libssl-dev",
            "COPY src ./src",
        ]
    );
}

#[test]
#[should_panic(expected = "JSON-array COPY form")]
fn json_array_copy_form_fails_loudly() {
    sources(
        "FROM rust AS builder\n\
         COPY [\"src\", \"./src\"]\n\
         RUN cargo build --release\n",
    );
}

#[test]
#[should_panic(expected = "exactly one Dockerfile stage running `cargo build`")]
fn ambiguous_build_stage_fails_loudly() {
    sources(
        "FROM rust AS a\n\
         RUN cargo build --release\n\
         FROM rust AS b\n\
         RUN cargo build --release\n",
    );
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
