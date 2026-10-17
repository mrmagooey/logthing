//! E2E: the real binary, HEC -> Parquet on an in-process fake S3 (no Docker). Proves the
//! writer's age flush is checked at sub-interval cadence (a lone batch of events lands within
//! roughly one flush interval, not two) and that a failing S3 is retried with backoff rather
//! than on every arriving event, with all rows delivered once S3 recovers.
//!
//! The binary runs with `AWS_MAX_ATTEMPTS=1` (child only) so one writer attempt is one PUT.

mod common;

use bytes::Bytes;
use common::fake_s3::FakeS3;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::time::{Duration, Instant};
use tokio::time::timeout;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");
const ENVS: [(&str, &str); 1] = [("AWS_MAX_ATTEMPTS", "1")];
const REQ: Duration = Duration::from_secs(10);
const FLUSH_INTERVAL_SECS: u64 = 8;

fn toml(endpoint: &str) -> String {
    format!(
        r#"
bind_address = "127.0.0.1:{{HTTP}}"
[tls]
enabled = false
[syslog]
enabled = false
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
max_buffer_rows = 100
flush_threshold_bytes = 100000000
flush_interval_secs = {FLUSH_INTERVAL_SECS}
"#
    )
}

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

fn delivered_rows(fake: &FakeS3) -> usize {
    fake.puts()
        .into_iter()
        .filter(|(k, _)| k.starts_with("hec/") && k.ends_with(".parquet"))
        .map(|(_, body)| {
            ParquetRecordBatchReaderBuilder::try_new(Bytes::from(body))
                .expect("parquet footer")
                .build()
                .expect("parquet reader")
                .map(|b| b.expect("batch").num_rows())
                .sum::<usize>()
        })
        .sum()
}

/// Send `n` events, then return how long until `rows` rows are delivered in total.
async fn time_to_deliver(p: &common::Proc, fake: &FakeS3, n: u32, rows: usize) -> Duration {
    let start = Instant::now();
    for i in 0..n {
        post_event(p, i).await;
    }
    assert!(
        common::wait_until(Duration::from_secs(30), || delivered_rows(fake) >= rows).await,
        "rows never arrived ({} of {rows})\n{}",
        delivered_rows(fake),
        p.logs()
    );
    start.elapsed()
}

#[tokio::test]
async fn test_idle_buffer_flushes_within_one_interval_plus_tick_and_failures_back_off() {
    let fake = FakeS3::start().await;
    let mut p = common::Proc::spawn(BIN, &toml(&fake.endpoint()), &ENVS);
    p.wait_healthy().await;

    // Round 1 lands at a tick instant; round 2 then starts ~1.5 s after a tick, the phase
    // where a tick period of one full interval would delay it to ~1.8 intervals.
    let limit = Duration::from_secs(FLUSH_INTERVAL_SECS + 3); // interval + tick (2 s) + slack
    let first = time_to_deliver(&p, &fake, 10, 10).await;
    assert!(first <= limit * 2, "first flush took {first:?}");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let second = time_to_deliver(&p, &fake, 10, 20).await;
    assert!(
        second <= limit,
        "idle buffer took {second:?} to flush (limit {limit:?})"
    );

    // S3 down: a size-triggered flush fails, then 20 more events arrive. Without backoff
    // every arriving event would start another attempt.
    fake.set_failing(true);
    let before = fake.request_count();
    for i in 0..120 {
        post_event(&p, i).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let attempts = fake.request_count() - before;
    assert!(
        (1..=3).contains(&attempts),
        "expected 1-3 PUT attempts in the outage window, got {attempts}"
    );

    // Recovery: every row arrives, none lost to the backoff.
    fake.set_failing(false);
    assert!(
        common::wait_until(Duration::from_secs(30), || delivered_rows(&fake) == 140).await,
        "rows after recovery: {} of 140\n{}",
        delivered_rows(&fake),
        p.logs()
    );
}
