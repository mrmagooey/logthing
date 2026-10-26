//! Integration test for `scripts/check-jemalloc-symbols.sh`, the guard `binaries.yml` runs
//! before and after the release build. It must fail for a binary without jemalloc markers.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-jemalloc-symbols.sh")
}

fn run(args: &[&str]) -> Output {
    Command::new("bash")
        .arg(script())
        .args(args)
        .output()
        .expect("run check-jemalloc-symbols.sh")
}

fn write_fake(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn test_script_passes_when_jemalloc_symbols_present() {
    let dir = tempfile::tempdir().unwrap();
    let mut body = b"\x7fELF\0\0/etc/_rjem_malloc.conf\0".to_vec();
    for i in 0..12 {
        body.extend_from_slice(format!("<jemalloc>: message {i}\0").as_bytes());
    }
    let fake = write_fake(dir.path(), "with", &body);
    let out = run(&[fake.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_script_fails_when_jemalloc_symbols_absent() {
    let dir = tempfile::tempdir().unwrap();
    let fake = write_fake(dir.path(), "without", b"\x7fELF\0\0malloc\0free\0");
    let out = run(&[fake.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("_rjem_malloc.conf"));
}

#[test]
fn test_script_fails_when_only_the_config_marker_is_present() {
    let dir = tempfile::tempdir().unwrap();
    let fake = write_fake(
        dir.path(),
        "partial",
        b"\x7fELF\0\0/etc/_rjem_malloc.conf\0",
    );
    let out = run(&[fake.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("<jemalloc>:"));
}

#[test]
fn test_script_exits_2_for_unknown_second_argument() {
    let dir = tempfile::tempdir().unwrap();
    let fake = write_fake(dir.path(), "any", b"\x7fELF\0\0");
    let out = run(&[fake.to_str().unwrap(), "--rnu"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
}

#[test]
fn test_script_exits_2_for_missing_file_or_no_argument() {
    assert_eq!(run(&["/nonexistent/logthing"]).status.code(), Some(2));
    assert_eq!(run(&[]).status.code(), Some(2));
}

#[test]
fn test_script_matches_the_real_binary_allocator() {
    // Default gnu build: system allocator, no jemalloc markers. `--features jemalloc` (or a musl
    // test build): symbols present AND the binary actually starts and logs allocator=jemalloc.
    let bin = env!("CARGO_BIN_EXE_logthing");
    if cfg!(any(feature = "jemalloc", target_env = "musl")) {
        let out = run(&[bin, "--run"]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    } else {
        assert_eq!(run(&[bin]).status.code(), Some(1));
    }
}
