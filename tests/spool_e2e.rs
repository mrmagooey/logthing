//! E2E: the real binary with `[spool]` against an in-process fake S3 (no Docker). Exercises
//! the process-global spool install, the startup order (spool gauges on `/metrics`), the
//! shutdown drain and replay after a restart, and the Object Lock headers on the wire.
//!
//! The binary runs with `AWS_MAX_ATTEMPTS=1` (passed to the child only, no `set_var` here) so
//! an outage costs one request per attempt instead of SDK-internal retries.

mod common;

use bytes::Bytes;
use common::fake_s3::FakeS3;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");
const ENVS: [(&str, &str); 1] = [("AWS_MAX_ATTEMPTS", "1")];
const WAIT: Duration = Duration::from_secs(40);
const REQ: Duration = Duration::from_secs(10);

/// Per-test knobs for the config skeleton.
struct Opts<'a> {
    endpoint: &'a str,
    metrics_port: u16,
    spool_max_bytes: u64,
    /// Extra lines appended to `[hec.s3]` (buffering policy, Object Lock).
    hec_s3_extra: &'a str,
    /// Extra lines appended to `[iceberg.s3]` (descriptor sink).
    desc_s3_extra: &'a str,
}

fn toml(o: &Opts) -> String {
    let Opts {
        endpoint,
        metrics_port,
        spool_max_bytes,
        hec_s3_extra,
        desc_s3_extra,
    } = o;
    format!(
        r#"
bind_address = "127.0.0.1:{{HTTP}}"
[tls]
enabled = false
[syslog]
enabled = false
[metrics]
enabled = true
port = {metrics_port}
[hec]
enabled = true
token = "tok"
[hec.s3]
endpoint = "{endpoint}"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"
prefix = "hec"
{hec_s3_extra}
[iceberg.s3]
endpoint = "{endpoint}"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"
prefix = "desc"
{desc_s3_extra}
[spool]
dir = "{{DIR}}/spool"
max_bytes = {spool_max_bytes}
"#
    )
}

/// One record per flush, flushed immediately.
const FLUSH_EACH: &str =
    "max_buffer_rows = 1\nflush_threshold_bytes = 1\nflush_interval_secs = 3600";
/// Records stay in memory until shutdown.
const FLUSH_NEVER: &str =
    "max_buffer_rows = 100000\nflush_threshold_bytes = 100000000\nflush_interval_secs = 3600";

async fn post_event(p: &common::Proc, n: u32) {
    let resp = timeout(
        REQ,
        reqwest::Client::new()
            .post(format!("{}/services/collector/event", p.base()))
            .header("Authorization", "Splunk tok")
            .json(&serde_json::json!({"sourcetype": "app", "event": {"n": n}}))
            .send(),
    )
    .await
    .expect("request timed out")
    .expect("request failed");
    assert_eq!(resp.status(), 200);
}

async fn metrics(port: u16) -> String {
    timeout(REQ, async {
        reqwest::get(format!("http://127.0.0.1:{port}/metrics"))
            .await
            .expect("scrape")
            .text()
            .await
            .expect("metrics body")
    })
    .await
    .expect("metrics scrape timed out")
}

/// Names of files in `<dir>/spool` ending in `.ext`.
fn spool_files(dir: &Path, ext: &str) -> Vec<String> {
    let suffix = format!(".{ext}");
    std::fs::read_dir(dir.join("spool"))
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(&suffix))
                .collect()
        })
        .unwrap_or_default()
}

fn keys_with(fake: &FakeS3, prefix: &str, suffix: &str) -> Vec<String> {
    fake.put_keys()
        .into_iter()
        .filter(|k| k.starts_with(prefix) && k.ends_with(suffix))
        .collect()
}

/// Rows across every delivered `hec/` Parquet object.
fn delivered_rows(fake: &FakeS3) -> usize {
    keys_with(fake, "hec/", ".parquet")
        .iter()
        .map(|k| parquet_rows(fake.body(k).unwrap()))
        .sum()
}

fn parquet_rows(bytes: Vec<u8>) -> usize {
    ParquetRecordBatchReaderBuilder::try_new(Bytes::from(bytes))
        .expect("parquet footer")
        .build()
        .expect("parquet reader")
        .map(|b| b.expect("batch").num_rows())
        .sum()
}

#[tokio::test]
async fn test_s3_outage_then_recovery_delivers_spooled_data_without_restart() {
    let fake = FakeS3::start().await;
    fake.set_failing(true);
    let mport = common::free_port();
    let cfg = toml(&Opts {
        endpoint: &fake.endpoint(),
        metrics_port: mport,
        spool_max_bytes: 104_857_600,
        hec_s3_extra: FLUSH_EACH,
        desc_s3_extra: "",
    });
    let mut p = common::Proc::spawn(BIN, &cfg, &ENVS);
    p.wait_healthy().await;

    // Startup order: the global spool installed after the metrics recorder, so its gauges
    // exist before any traffic.
    let m = metrics(mport).await;
    assert!(m.contains("spool_bytes"), "no spool_bytes gauge:\n{m}");
    assert!(m.contains("spool_entries"), "no spool_entries gauge:\n{m}");

    for n in 0..3 {
        post_event(&p, n).await;
    }
    assert!(
        common::wait_until(WAIT, || !spool_files(p.dir(), "meta").is_empty()).await,
        "nothing reached the spool:\n{}",
        p.logs()
    );
    assert_eq!(fake.put_count(), 0, "S3 is down; nothing may have landed");

    fake.set_failing(false);
    assert!(
        common::wait_until(WAIT, || {
            delivered_rows(&fake) == 3
                && !keys_with(&fake, "desc/", ".json").is_empty()
                && spool_files(p.dir(), "meta").is_empty()
        })
        .await,
        "spool never drained after recovery; keys={:?} meta={:?} rows={}\n{}",
        fake.put_keys(),
        spool_files(p.dir(), "meta"),
        delivered_rows(&fake),
        p.logs()
    );
    assert_eq!(delivered_rows(&fake), 3);
    // The counter is bumped just after the entry is deleted; poll rather than scrape once.
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        let m = metrics(mport).await;
        if m.contains("spool_uploaded") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no spool_uploaded:\n{m}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn test_failed_final_flush_at_shutdown_survives_restart_and_replays() {
    let fake = FakeS3::start().await;
    fake.set_failing(true);
    let cfg = toml(&Opts {
        endpoint: &fake.endpoint(),
        metrics_port: common::free_port(),
        spool_max_bytes: 104_857_600,
        hec_s3_extra: FLUSH_NEVER,
        desc_s3_extra: "",
    });
    let mut p = common::Proc::spawn(BIN, &cfg, &ENVS);
    p.wait_healthy().await;
    post_event(&p, 1).await;
    post_event(&p, 2).await;
    assert!(
        spool_files(p.dir(), "meta").is_empty(),
        "records must still be buffered in memory"
    );

    let st = p.terminate(Duration::from_secs(15));
    assert!(st.success(), "graceful shutdown expected, got {st}");
    assert_eq!(fake.put_count(), 0, "S3 was down for the whole run");
    let dir = p.into_dir();
    assert!(!spool_files(dir.path(), "meta").is_empty(), "no .meta");
    assert!(
        !spool_files(dir.path(), "parquet").is_empty(),
        "no .parquet"
    );

    // Restart on the same directory with S3 healthy: startup replay delivers the entry.
    fake.set_failing(false);
    let cfg = toml(&Opts {
        endpoint: &fake.endpoint(),
        metrics_port: common::free_port(),
        spool_max_bytes: 104_857_600,
        hec_s3_extra: FLUSH_NEVER,
        desc_s3_extra: "",
    });
    let mut p2 = common::Proc::spawn_in(BIN, &cfg, &ENVS, dir, common::free_port());
    p2.wait_healthy().await;
    assert!(
        common::wait_until(WAIT, || {
            !keys_with(&fake, "hec/", ".parquet").is_empty()
                && !keys_with(&fake, "desc/", ".json").is_empty()
                && spool_files(p2.dir(), "meta").is_empty()
        })
        .await,
        "replay did not deliver; keys={:?}\n{}",
        fake.put_keys(),
        p2.logs()
    );
    assert_eq!(
        delivered_rows(&fake),
        2,
        "both buffered events must be delivered"
    );
    for ext in ["meta", "parquet", "json"] {
        assert!(spool_files(p2.dir(), ext).is_empty(), "left .{ext} behind");
    }
}

#[tokio::test]
async fn test_spool_full_does_not_lose_data_when_s3_is_healthy() {
    let fake = FakeS3::start().await;
    let mport = common::free_port();
    let cfg = toml(&Opts {
        endpoint: &fake.endpoint(),
        metrics_port: mport,
        spool_max_bytes: 1,
        hec_s3_extra: FLUSH_EACH,
        desc_s3_extra: "",
    });
    let mut p = common::Proc::spawn(BIN, &cfg, &ENVS);
    p.wait_healthy().await;
    post_event(&p, 1).await;
    assert!(
        common::wait_until(WAIT, || {
            !keys_with(&fake, "hec/", ".parquet").is_empty()
                && !keys_with(&fake, "desc/", ".json").is_empty()
        })
        .await,
        "direct-upload fallback never delivered parquet + descriptor:\n{}",
        p.logs()
    );
    assert!(
        spool_files(p.dir(), "meta").is_empty(),
        "spool must be bypassed"
    );
    let m = metrics(mport).await;
    assert!(
        m.lines()
            .any(|l| l.starts_with("spool_rejected") && l.contains("reason=\"full\"")),
        "no spool_rejected{{reason=full}}:\n{m}"
    );
}

#[test]
fn test_startup_fails_on_invalid_spool_config() {
    let cfg = toml(&Opts {
        endpoint: "http://127.0.0.1:1",
        metrics_port: common::free_port(),
        spool_max_bytes: 0,
        hec_s3_extra: FLUSH_EACH,
        desc_s3_extra: "",
    })
    .replace("{HTTP}", &common::free_port().to_string())
    .replace("{DIR}", "/nonexistent-logthing-e2e");
    let (status, stderr) = common::run_to_exit(BIN, &cfg, &ENVS);
    assert!(!status.success(), "must exit non-zero");
    assert!(stderr.contains("spool.max_bytes"), "stderr:\n{stderr}");
}

#[tokio::test]
async fn test_object_lock_headers_are_sent_when_configured() {
    // The descriptor sink (`[iceberg.s3]`) has its own connection config and is locked too.
    const LOCK: &str = "object_lock_mode = \"GOVERNANCE\"\nobject_lock_retain_days = 1";
    let fake = FakeS3::start().await;
    let extra = format!("{FLUSH_EACH}\n{LOCK}");
    let cfg = toml(&Opts {
        endpoint: &fake.endpoint(),
        metrics_port: common::free_port(),
        spool_max_bytes: 104_857_600,
        hec_s3_extra: &extra,
        desc_s3_extra: LOCK,
    });
    let mut p = common::Proc::spawn(BIN, &cfg, &ENVS);
    p.wait_healthy().await;
    post_event(&p, 1).await;
    assert!(
        common::wait_until(WAIT, || {
            !keys_with(&fake, "hec/", ".parquet").is_empty()
                && !keys_with(&fake, "desc/", ".json").is_empty()
        })
        .await,
        "no parquet + descriptor delivered:\n{}",
        p.logs()
    );
    for key in [
        keys_with(&fake, "hec/", ".parquet").remove(0),
        keys_with(&fake, "desc/", ".json").remove(0),
    ] {
        let headers = fake.put_headers(&key);
        let get = |n: &str| {
            headers
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            get("x-amz-object-lock-mode"),
            Some("GOVERNANCE"),
            "{key}: {headers:?}"
        );
        assert!(
            get("x-amz-object-lock-retain-until-date").is_some_and(|v| !v.is_empty()),
            "{key}: {headers:?}"
        );
        assert!(
            get("x-amz-checksum-sha256").is_some()
                || get("x-amz-sdk-checksum-algorithm") == Some("SHA256"),
            "{key}: {headers:?}"
        );
    }
}
