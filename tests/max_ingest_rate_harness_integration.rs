//! Integration coverage for `scripts/max-ingest-rate.sh`.
//!
//! The harness's pure logic is covered by its own `SELFTEST=1` mode; this
//! test covers the parts that only appear when it drives a real server:
//! that a run produces a verdict at all, that it leaves the two TRACKED
//! config files untouched (the defect its predecessor shipped with), and that
//! the OTLP + gzip + redaction path starts a real server and reports 503s.
//!
//! Both tests below invoke the harness against a real server on fixed ports
//! (see `start_server`/`METRICS_PORT` in the script) and must never run
//! concurrently with each other or with any other harness invocation, or
//! the runs will contaminate each other's metrics. `cargo test` in this
//! crate runs test functions from the same binary on multiple threads by
//! default, so this file deliberately has only the one test that drives the
//! harness against a real server (`short_run_...`); `harness_selftest_passes`
//! never touches a server or a port, so it cannot contend with it.

use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The harness's own self-test must pass before any run is trusted.
#[test]
fn harness_selftest_passes() {
    let out = Command::new("bash")
        .arg("scripts/max-ingest-rate.sh")
        .env("SELFTEST", "1")
        .current_dir(repo_root())
        .output()
        .expect("run harness self-test");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("SELFTEST PASS"),
        "harness self-test failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

const VERDICT_TOKENS: [&str; 5] = [
    "PASS",
    "FAIL-LOSS",
    "FAIL-BACKPRESSURE",
    "GENERATOR-LIMITED",
    "HARD-FAILURE",
];

/// Run the harness with `envs`; returns (exit ok, stdout, stderr).
fn run_harness(root: &std::path::Path, envs: &[(&str, &str)]) -> (bool, String, String) {
    let mut cmd = Command::new("bash");
    cmd.arg("scripts/max-ingest-rate.sh").current_dir(root);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run harness");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// measure_rate prints the rate-level AGGREGATE verdict as a bare, standalone line on
/// stderr; per-run table rows are tab-separated and never just the token on their own.
fn aggregate_verdict(stderr: &str) -> Option<&str> {
    stderr
        .lines()
        .map(str::trim)
        .rev()
        .find(|&l| VERDICT_TOKENS.contains(&l))
}

/// Two sequential real runs (one test only: fixed ports, so real-server runs must never
/// overlap). `#[ignore]`d because plain `cargo test` (CI builds debug only) has no release
/// binaries; run it explicitly with
/// `cargo build --release --bin logthing && cargo build --release -p loadgen &&
/// cargo test --test max_ingest_rate_harness_integration -- --ignored --test-threads=1`.
/// Once explicitly run, missing release binaries FAIL it with the build commands -- an
/// explicit `--ignored` run can never silently pass without having run anything.
///
/// Run 1: ipfix, `SHAPE=real`, fixed `RATE=1000`, `DURATION=10` (the harness rejects real
/// runs shorter than twice its 5s flush interval, and any DURATION under 10). Fixed-rate
/// mode discards `measure_rate`'s stdout, so the aggregate verdict is asserted as a
/// standalone stderr line (see `aggregate_verdict`), not as vocabulary anywhere in the
/// combined output, which per-run rows would satisfy even if the aggregate were swallowed.
///
/// Run 2: `FORMAT=otlp GZIP=1 REDACTION=1`: proves `[otlp.local]` + `[otlp.redaction]`
/// are accepted by the real server (a `hash_key_env` / missing-sink error would make the
/// harness FATAL "server did not start") and that the `503 total:` line is emitted.
///
/// HARD-FAILURE is a verdict token but never an acceptable outcome here: it means the
/// measurement broke, not that a rate was measured.
#[test]
#[ignore = "needs release builds; run: cargo build --release --bin logthing && cargo build --release -p loadgen && cargo test --test max_ingest_rate_harness_integration -- --ignored --test-threads=1"]
fn short_run_emits_a_verdict_and_restores_tracked_configs() {
    let root = repo_root();
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    assert!(
        target.join("release/logthing").exists() && target.join("release/loadgen").exists(),
        "release binaries are required: run `cargo build --release --bin logthing && \
         cargo build --release -p loadgen` first (this test must not pass without them)"
    );

    let before_main = std::fs::read(root.join("logthing.toml")).expect("read logthing.toml");
    let before_admin = std::fs::read(root.join("logthing.admin.toml")).ok();
    let assert_configs_restored = |label: &str| {
        assert_eq!(
            before_main,
            std::fs::read(root.join("logthing.toml")).expect("logthing.toml still exists"),
            "{label}: harness must restore logthing.toml byte-for-byte"
        );
        assert_eq!(
            before_admin,
            std::fs::read(root.join("logthing.admin.toml")).ok(),
            "{label}: harness must restore logthing.admin.toml if present (the predecessor rm'd it)"
        );
    };

    // ---- run 1: ipfix, fixed rate ----
    let (ok, stdout, stderr) = run_harness(
        &root,
        &[
            ("FORMAT", "ipfix"),
            ("SHAPE", "real"),
            ("RATE", "1000"),
            ("DURATION", "10"),
            ("RUNS", "2"),
        ],
    );
    let combined = format!("{stdout}{stderr}");
    assert!(ok, "ipfix harness failed:\n{combined}");
    let verdict = aggregate_verdict(&stderr);
    assert!(
        verdict.is_some(),
        "no standalone aggregate verdict line in stderr (only per-run table rows?):\n{combined}"
    );
    assert_ne!(
        verdict,
        Some("HARD-FAILURE"),
        "ipfix run hard-failed:\n{combined}"
    );
    assert_configs_restored("after ipfix run");

    // ---- run 2: otlp + gzip + redaction ----
    let (ok, stdout, stderr) = run_harness(
        &root,
        &[
            ("FORMAT", "otlp"),
            ("GZIP", "1"),
            ("REDACTION", "1"),
            ("EVENTS_PER_REQUEST", "20"),
            ("RATE", "2000"),
            ("DURATION", "10"),
            ("RUNS", "1"),
        ],
    );
    let combined = format!("{stdout}{stderr}");
    assert!(ok, "otlp harness failed:\n{combined}");
    let verdict = aggregate_verdict(&stderr);
    assert!(
        verdict.is_some(),
        "no standalone aggregate verdict line in otlp run stderr:\n{combined}"
    );
    assert_ne!(
        verdict,
        Some("HARD-FAILURE"),
        "otlp run hard-failed:\n{combined}"
    );
    assert!(
        stderr.contains("503 total:"),
        "otlp run stderr lacks the `503 total:` line:\n{combined}"
    );
    assert!(
        stderr.contains("# run 1: 503s="),
        "otlp run lacks the per-run `# run <id>: 503s=` line:\n{combined}"
    );
    assert!(
        !combined.contains("hash_key_env") && !combined.contains("server did not start"),
        "server rejected the redaction config:\n{combined}"
    );
    assert_configs_restored("after otlp run");
}
