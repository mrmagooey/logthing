//! Integration coverage for `scripts/max-ingest-rate.sh`.
//!
//! The harness's pure logic is covered by its own `SELFTEST=1` mode; this
//! test covers the parts that only appear when it drives a real server:
//! that a run produces a verdict at all, and that it leaves the two TRACKED
//! config files untouched (the defect its predecessor shipped with).
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

/// One short real run: a verdict is emitted, and both tracked config files
/// come back byte-identical. Requires release binaries; skips (rather than
/// fails) if they are absent, so `cargo test` on a fresh checkout is green.
///
/// Uses `SHAPE=real` (not `trivial`): the property under test -- that
/// `logthing.admin.toml` is moved aside and restored -- only has teeth when
/// the run actually exercises the writer/config path the harness built that
/// dance for. `DURATION=10` (not the brief's original `3`): the harness now
/// hard-rejects real-shape runs shorter than twice its local-sink
/// `flush_interval_secs` (5s), so 3s aborts in milliseconds with a `FATAL`
/// before ever starting a server. 10s is the minimum that clears the guard.
///
/// `RATE=1000` (fixed-rate mode, not a ramp) matters for a second, less
/// obvious reason: in fixed-rate mode the harness sends `measure_rate`'s
/// own stdout to `/dev/null` (per-run table rows go to stderr instead --
/// see the harness's own comment above `measure_rate`). `measure_rate`
/// duplicates the rate-level aggregate verdict to stderr for exactly this
/// reason, so it lands somewhere visible in fixed-rate mode instead of
/// being silently discarded along with the rest of that redirected stdout.
/// The aggregate verdict therefore appears only in stderr here, never in
/// stdout -- the check below looks for it as a standalone line in stderr
/// (see `find_aggregate_verdict` below), not merely for verdict vocabulary
/// anywhere in the combined output, since per-run table rows also end in a
/// verdict column and would otherwise make this assertion pass even if the
/// aggregate line were swallowed again.
#[test]
fn short_run_emits_a_verdict_and_restores_tracked_configs() {
    let root = repo_root();
    if !root.join("target/release/logthing").exists()
        || !root.join("target/release/loadgen").exists()
    {
        eprintln!("skipping: release binaries not built");
        return;
    }

    let before_main = std::fs::read(root.join("logthing.toml")).expect("read logthing.toml");
    let before_admin = std::fs::read(root.join("logthing.admin.toml")).ok();

    let out = Command::new("bash")
        .arg("scripts/max-ingest-rate.sh")
        .env("FORMAT", "ipfix")
        .env("SHAPE", "real")
        .env("RATE", "1000")
        .env("DURATION", "10")
        .env("RUNS", "2")
        .current_dir(&root)
        .output()
        .expect("run harness");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        out.status.success(),
        "harness exited {:?}:\n{stdout}\n{stderr}",
        out.status.code()
    );

    // measure_rate prints the rate-level AGGREGATE verdict as a bare,
    // standalone line on stderr (`echo "$verdict" >&2` in the harness) --
    // unlike the per-run table rows, which are tab-separated and end in a
    // verdict column but are never *just* the token on their own line.
    // Matching on that shape verifies the aggregate verdict specifically:
    // if the harness ever went back to only writing it to the stdout that
    // fixed-rate mode redirects to /dev/null (the bug this test guards
    // against), this line-shaped search would find nothing even though the
    // per-run rows still carry the same PASS/FAIL-LOSS/etc vocabulary --
    // whereas a plain substring search over combined output would keep
    // passing "incidentally" on those per-run rows alone.
    let verdict_tokens = ["PASS", "FAIL-LOSS", "GENERATOR-LIMITED", "HARD-FAILURE"];
    let aggregate_verdict = stderr
        .lines()
        .map(str::trim)
        .rev()
        .find(|&l| verdict_tokens.contains(&l));
    assert!(
        aggregate_verdict.is_some(),
        "no standalone aggregate verdict line in stderr (only per-run table rows?):\n{combined}"
    );

    // HARD-FAILURE is a real verdict token (server wouldn't start, the
    // /proc/net/snmp reconciliation disagreed, the writer-liveness check
    // fired) so it counts for "a verdict was emitted" -- but it is not an
    // acceptable *outcome* for this test. It means the measurement itself
    // broke, not that a rate was measured; letting the test pass on it
    // would hollow it out exactly where it matters most (this is the one
    // test that exercises the real server, so it is the one place that can
    // catch this class of failure). Fail loudly instead.
    assert_ne!(
        aggregate_verdict,
        Some("HARD-FAILURE"),
        "harness reported HARD-FAILURE (an infrastructure failure, not a measurement) \
         on a run that was expected to succeed:\n{combined}"
    );

    assert_eq!(
        before_main,
        std::fs::read(root.join("logthing.toml")).expect("logthing.toml still exists"),
        "harness must restore logthing.toml byte-for-byte"
    );
    assert_eq!(
        before_admin,
        std::fs::read(root.join("logthing.admin.toml")).ok(),
        "harness must restore logthing.admin.toml (it is tracked; the predecessor rm'd it)"
    );
}
