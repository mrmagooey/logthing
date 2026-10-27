//! Tests for `scripts/perf-summary.py`, run as a subprocess against fixture directories. For a
//! script this subprocess level is the unit level: no Rust function sits behind it.

use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/perf-summary.py");
    Command::new("python3")
        .arg(script)
        .args(args)
        .output()
        .expect("run python3")
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn summary(fmt: &str, verdict: &str) -> serde_json::Value {
    json!({
        "format": fmt, "verdict": verdict,
        "reasons": if verdict == "PASS" { vec![] } else { vec!["written/sent 0.50 < 0.9", "x|y"] },
        "offered_rate": 10000.0, "achieved_rate": 9876.5,
        "loadgen_sent_records": 250000, "records_written": 249000,
        "peak_rss_kb": 204800, "cpu_us_per_record": 12.345,
        "host": "ci-host", "cpu": "Test CPU",
    })
}

fn ingest(dir: &Path) -> String {
    let o = run(&["--ingest", dir.to_str().unwrap()]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    stdout(&o)
}

fn row<'a>(md: &'a str, fmt: &str) -> &'a str {
    md.lines()
        .find(|l| l.starts_with(&format!("| {fmt} |")))
        .unwrap_or_else(|| panic!("no {fmt} row in:\n{md}"))
}

#[test]
fn test_ingest_pass_and_fail_rows() {
    let d = tempfile::tempdir().unwrap();
    write(
        d.path(),
        "syslog/summary.json",
        &summary("syslog", "PASS").to_string(),
    );
    write(
        d.path(),
        "zeek/summary.json",
        &summary("zeek", "FAIL").to_string(),
    );
    let md = ingest(d.path());
    assert!(
        md.contains("1/2 formats passed (ci-host / Test CPU)"),
        "{md}"
    );
    assert_eq!(
        row(&md, "syslog"),
        "| syslog | PASS | 10,000 | 9,876 | 249,000/250,000 | 200.0 | 12.35 | - |"
    );
    let z = row(&md, "zeek");
    assert!(z.contains("| FAIL |"));
    assert!(z.contains("written/sent 0.50 < 0.9; x\\|y"), "{z}");
}

#[test]
fn test_ingest_null_fields_render_dash() {
    let d = tempfile::tempdir().unwrap();
    let s = json!({"verdict": "FAIL", "reasons": ["server did not come up"],
        "offered_rate": 5000.0, "achieved_rate": null, "loadgen_sent_records": null,
        "records_written": null, "peak_rss_kb": null, "cpu_us_per_record": null});
    write(d.path(), "otlp/summary.json", &s.to_string());
    let md = ingest(d.path());
    assert_eq!(
        row(&md, "otlp"),
        "| otlp | FAIL | 5,000 | - | - | - | - | server did not come up |"
    );
}

#[test]
fn test_ingest_malformed_json_is_error_row_and_exit_0() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "sflow/summary.json", "{not json");
    write(
        d.path(),
        "wef/summary.json",
        &summary("wef", "PASS").to_string(),
    );
    let md = ingest(d.path());
    let r = row(&md, "sflow");
    assert!(
        r.contains("| ERROR |") && r.contains("unreadable summary.json"),
        "{r}"
    );
    assert!(md.contains("1/2 formats passed"), "{md}");
}

#[test]
fn test_ingest_rows_follow_script_format_order_then_unknown_sorted() {
    let d = tempfile::tempdir().unwrap();
    for f in ["wef", "zzz", "syslog", "aaa", "hec", "generic"] {
        write(
            d.path(),
            &format!("{f}/summary.json"),
            &summary(f, "PASS").to_string(),
        );
    }
    let md = ingest(d.path());
    let order: Vec<&str> = md
        .lines()
        .filter_map(|l| l.strip_prefix("| "))
        .filter_map(|l| l.split(" |").next())
        .filter(|c| !["format", "---"].contains(c))
        .collect();
    assert_eq!(order, ["syslog", "hec", "generic", "wef", "aaa", "zzz"]);
}

#[test]
fn test_missing_dirs_exit_0_with_no_results() {
    let d = tempfile::tempdir().unwrap();
    let gone = d.path().join("nope");
    let g = gone.to_str().unwrap();
    for flag in ["--ingest", "--criterion"] {
        let o = run(&[flag, g]);
        assert!(o.status.success());
        assert!(stdout(&o).contains("No results found"), "{}", stdout(&o));
    }
    // An existing but empty directory is also "no results".
    assert!(ingest(d.path()).contains("No results found"));
}

fn estimates(median: f64, lo: f64, hi: f64) -> String {
    json!({"median": {"point_estimate": median,
        "confidence_interval": {"lower_bound": lo, "upper_bound": hi}}})
    .to_string()
}

#[test]
fn test_criterion_reads_named_baseline_and_formats_units() {
    let d = tempfile::tempdir().unwrap();
    let est = |dir: &str, b: &str, m, lo, hi| {
        write(
            d.path(),
            &format!("{dir}/{b}/estimates.json"),
            &estimates(m, lo, hi),
        )
    };
    est("grp/a", "ci-abc", 1234.0, 1200.0, 1300.0);
    est("grp/a", "new", 9.0, 9.0, 9.0);
    est("grp/b", "ci-abc", 2_500_000.0, 2_400_000.0, 2_600_000.0);
    est("grp/c", "ci-abc", 3.2e9, 3.1e9, 3.3e9);
    est("grp/d", "ci-abc", 12.0, 11.0, 13.0);
    est("grp/a/report", "ci-abc", 1.0, 1.0, 1.0); // report dirs are skipped
    est("grp/other", "new", 5.0, 5.0, 5.0); // no ci-abc baseline: not listed
    let o = run(&[
        "--criterion",
        d.path().to_str().unwrap(),
        "--baseline",
        "ci-abc",
    ]);
    assert!(o.status.success());
    let md = stdout(&o);
    assert!(
        md.contains("| grp/a | 1.23 \u{b5}s | 1.20 \u{b5}s - 1.30 \u{b5}s |"),
        "{md}"
    );
    assert!(
        md.contains("| grp/b | 2.50 ms | 2.40 ms - 2.60 ms |"),
        "{md}"
    );
    assert!(md.contains("| grp/c | 3.20 s | 3.10 s - 3.30 s |"), "{md}");
    assert!(
        md.contains("| grp/d | 12.0 ns | 11.0 ns - 13.0 ns |"),
        "{md}"
    );
    assert!(!md.contains("report") && !md.contains("grp/other"), "{md}");
    // default baseline is `new`
    let o = run(&["--criterion", d.path().to_str().unwrap()]);
    let md = stdout(&o);
    assert!(
        md.contains("| grp/a | 9.00 ns |") && md.contains("| grp/other |"),
        "{md}"
    );
}

#[test]
fn test_both_sections_and_unknown_args() {
    let d = tempfile::tempdir().unwrap();
    let p: PathBuf = d.path().join("x");
    let g = p.to_str().unwrap();
    let md = stdout(&run(&["--ingest", g, "--criterion", g]));
    assert!(md.contains("### Ingest formats") && md.contains("### Criterion benchmarks"));
    for args in [&["--bogus"][..], &[][..], &["--ingest"][..]] {
        let o = run(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("usage"));
    }
}
