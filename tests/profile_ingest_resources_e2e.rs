//! End-to-end check of the resource figures `scripts/profile-ingest.sh` adds to each format's
//! `summary.json` (peak RSS, server CPU seconds, CPU microseconds per record) and of
//! `scripts/perf-summary.py --ingest` rendering them. Runs one real syslog load (about 20 s).
//! The verdict is FAIL here (a non-pprof binary writes no profile metadata); that is expected
//! and deliberately not asserted.

use std::path::{Path, PathBuf};
use std::process::Command;

fn release_loadgen() -> Option<PathBuf> {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target"));
    let p = target.join("release/loadgen");
    p.exists().then_some(p)
}

#[test]
fn test_profile_ingest_records_rss_and_cpu_and_summary_renders_row() {
    let Some(loadgen) = release_loadgen() else {
        eprintln!("SKIP: no release loadgen; run `cargo build --release -p loadgen`");
        return;
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(root.join("scripts/profile-ingest.sh"));
    cmd.arg("syslog")
        .env("SKIP_PPROF_CHECK", "1")
        .env("DURATION", "10")
        .env("DELAY", "1")
        .env("RATE_SYSLOG", "2000")
        .env("OUT", out.path())
        .env("BIN", env!("CARGO_BIN_EXE_logthing"))
        .env("LOADGEN", loadgen);
    let res = cmd.output().expect("run profile-ingest.sh");
    let stdout = String::from_utf8_lossy(&res.stdout);
    let raw = std::fs::read_to_string(out.path().join("syslog/summary.json"))
        .unwrap_or_else(|e| panic!("no summary.json: {e}\n{stdout}"));
    let s: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(s["peak_rss_kb"].as_i64().unwrap() > 0, "{raw}");
    assert!(s["server_cpu_secs"].as_f64().unwrap() > 0.0, "{raw}");
    assert!(s["cpu_us_per_record"].as_f64().is_some(), "{raw}");

    let md = Command::new("python3")
        .arg(root.join("scripts/perf-summary.py"))
        .arg("--ingest")
        .arg(out.path())
        .output()
        .unwrap();
    assert!(md.status.success());
    let md = String::from_utf8(md.stdout).unwrap();
    assert!(md.contains("| syslog |"), "{md}");
    assert!(md.contains("formats passed"), "{md}");
}
