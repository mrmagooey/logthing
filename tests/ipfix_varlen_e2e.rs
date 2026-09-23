//! End-to-end test: RFC 7011 §7 variable-length field decoding across a
//! *real* `logthing` process.
//!
//! `ipfix_varlen_integration.rs` drives a real `IpfixListener` in-process.
//! This test instead spawns the actual compiled binary
//! (`env!("CARGO_BIN_EXE_logthing")`) against a real `logthing.toml` — the
//! only way to prove the fix reaches all the way from a raw UDP datagram,
//! through `main.rs`'s wiring, to the `ipfix_flows_decoded` counter on the
//! real `/metrics` endpoint. Pattern: `tests/listener_ip_whitelist_e2e.rs`
//! (toml in a tempdir, `ChildGuard`, `wait_for_metrics`/`wait_for_udp`).
//!
//! No `[security]` section is set: `allowed_ips` defaults to empty, which
//! allows all sources, so this test doesn't need the loopback-alias dance
//! `listener_ip_whitelist_e2e.rs` uses to keep `/metrics` reachable.
//!
//! Mutation-check (see task report): with the `allow_varlen` dispatch
//! removed from `parse_ipfix_data_set`, the varlen template's declared
//! record length is `0xFFFF` (65535) bytes, so the fixed-length loop never
//! decodes a record from either datagram sent below and
//! `ipfix_flows_decoded` stays at 0 -- this test times out and fails.

use std::fs::File;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::sleep;

/// Overall budget for "wait until ready"/"wait until decoded" polling loops.
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Kills and reaps the spawned `logthing` process on drop -- including
/// during a panicking assertion -- so a failing test never leaves an
/// orphaned daemon holding ports.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn ephemeral_tcp_port() -> u16 {
    let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tmp.local_addr().unwrap().port();
    drop(tmp);
    port
}

async fn ephemeral_udp_port() -> u16 {
    let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = tmp.local_addr().unwrap().port();
    drop(tmp);
    port
}

async fn wait_for_udp(port: u16, deadline: Instant, what: &str) {
    let addr = format!("127.0.0.1:{port}");
    loop {
        match UdpSocket::bind(&addr).await {
            Ok(sock) => drop(sock),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return,
            Err(e) => panic!("unexpected error probing {what} (UDP {port}): {e}"),
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for {what} (UDP {port}) to be bound");
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_metrics(client: &reqwest::Client, url: &str, deadline: Instant) {
    loop {
        if let Ok(resp) = client.get(url).send().await
            && resp.status().is_success()
        {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for metrics endpoint {url} to come up");
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Poll `/metrics` until unlabelled counter `name` reads at least `min`, or
/// panic with the last scrape body once `deadline` passes. Used in place of
/// a fixed sleep to know the template set was actually decoded and cached
/// before the data set (which depends on it) is sent.
async fn wait_for_counter_at_least(
    client: &reqwest::Client,
    url: &str,
    name: &str,
    min: u64,
    deadline: Instant,
) {
    loop {
        let rendered = client
            .get(url)
            .send()
            .await
            .expect("scrape metrics")
            .text()
            .await
            .expect("read metrics body");
        let value = logthing::profiling::parse_counter(&rendered, name);
        if value.is_some_and(|v| v >= min) {
            return;
        }
        if Instant::now() > deadline {
            panic!(
                "timed out waiting for {name} >= {min} on {url}, got {value:?}\n\
                 full metrics dump:\n{rendered}"
            );
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// IPFIX message #1: a template set declaring template 256 with one
/// variable-length field (IE 97 -- not in `ie_info`'s curated table).
/// Message header (16) + template set (12) = 28 bytes total.
const TEMPLATE_MSG: &[u8] = &[
    0x00, 0x0A, // version = 10
    0x00, 0x1C, // total length = 28
    0x67, 0x5C, 0xB0, 0x20, // export_time
    0x00, 0x00, 0x00, 0x01, // sequence
    0x00, 0x00, 0x00, 0x00, // observation domain id = 0
    // Template Set (12 bytes: 4 hdr + 8 body)
    0x00, 0x02, // set id = 2 (Template Set)
    0x00, 0x0C, // length = 12
    0x01, 0x00, // template id = 256
    0x00, 0x01, // field count = 1
    0x00, 0x61, 0xFF, 0xFF, // ie 97, length 0xFFFF (variable-length)
];

/// IPFIX message #2: a data set for template 256 with 2 records, each a
/// 1-byte-length varlen value `"abc"`.
/// Message header (16) + data set (12) = 28 bytes total.
const DATA_MSG: &[u8] = &[
    0x00, 0x0A, // version = 10
    0x00, 0x1C, // total length = 28
    0x67, 0x5C, 0xB0, 0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    // Data Set (12 bytes: 4 hdr + 8 body)
    0x01, 0x00, // set id = 256
    0x00, 0x0C, // length = 12
    0x03, b'a', b'b', b'c', // record 1: len=3, "abc"
    0x03, b'a', b'b', b'c', // record 2: len=3, "abc"
];

/// A third datagram: one record whose varlen value is 1000 raw bytes --
/// well over `ipfix::decoder::MAX_EXTRA_VALUE_BYTES` (128). RFC 7011 §7
/// encodes a length >= 255 as a 0xFF marker followed by a 2-byte length.
fn long_varlen_data_msg() -> Vec<u8> {
    const BODY_LEN: usize = 1000;
    let mut record_bytes = vec![0xFFu8];
    record_bytes.extend_from_slice(&(BODY_LEN as u16).to_be_bytes());
    record_bytes.extend(std::iter::repeat_n(0x5Au8, BODY_LEN));

    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x00, 0x0A]); // version = 10
    let total_len = 16 + 4 + record_bytes.len();
    msg.extend_from_slice(&(total_len as u16).to_be_bytes());
    msg.extend_from_slice(&[
        0x67, 0x5C, 0xB0, 0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    ]);
    msg.extend_from_slice(&[0x01, 0x00]); // set id = 256
    msg.extend_from_slice(&((4 + record_bytes.len()) as u16).to_be_bytes());
    msg.extend_from_slice(&record_bytes);
    msg
}

#[tokio::test]
async fn ipfix_varlen_records_increment_flows_decoded_on_real_process() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let http_port = ephemeral_tcp_port().await;
    let metrics_port = ephemeral_tcp_port().await;
    let ipfix_port = ephemeral_udp_port().await;
    // `[ipfix.local]` needs only `directory` -- everything else defaults
    // (`IpfixLocalConfig`, `src/config/mod.rs`). `max_buffer_rows = 1` and a
    // 1-byte `flush_threshold_bytes` flush the Parquet writer on the very
    // first pushed row, so the on-disk assertion below doesn't need to wait
    // out `flush_interval_secs`.
    let ipfix_dir = tmp.path().join("ipfix-out");

    let toml = format!(
        r#"
bind_address = "127.0.0.1:{http_port}"

[tls]
enabled = false

[metrics]
enabled = true
port = {metrics_port}

# Disabled: it defaults to a privileged port (bind fails without root) and
# would otherwise take down the whole process on startup -- this test only
# cares about the IPFIX listener.
[syslog]
enabled = false

[ipfix]
enabled = true
udp_port = {ipfix_port}

[ipfix.local]
directory = {ipfix_dir:?}
max_buffer_rows = 1
flush_threshold_bytes = 1
flush_interval_secs = 3600
"#,
    );
    std::fs::write(tmp.path().join("logthing.toml"), toml).expect("write logthing.toml");

    let stdout_log = File::create(tmp.path().join("stdout.log")).unwrap();
    let stderr_log = File::create(tmp.path().join("stderr.log")).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_logthing"))
        .current_dir(tmp.path())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .spawn()
        .expect("spawn logthing binary");
    let _guard = ChildGuard(child);

    let deadline = Instant::now() + READY_TIMEOUT;
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let metrics_client = reqwest::Client::new();

    wait_for_metrics(&metrics_client, &metrics_url, deadline).await;
    wait_for_udp(ipfix_port, deadline, "IPFIX").await;

    // Send the template set first, then the data set with 2 varlen records.
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ipfix_addr: SocketAddr = format!("127.0.0.1:{ipfix_port}").parse().unwrap();
    sender.send_to(TEMPLATE_MSG, ipfix_addr).await.unwrap();
    // Wait for the template to actually be decoded and cached, rather than
    // a fixed sleep, before sending the data set that depends on it.
    wait_for_counter_at_least(
        &metrics_client,
        &metrics_url,
        "ipfix_templates_received",
        1,
        deadline,
    )
    .await;
    sender.send_to(DATA_MSG, ipfix_addr).await.unwrap();

    // Poll /metrics until ipfix_flows_decoded >= 2 (deadline 15s).
    let scrape_deadline = Instant::now() + READY_TIMEOUT;
    let (last_rendered, last_value) = loop {
        let rendered = metrics_client
            .get(&metrics_url)
            .send()
            .await
            .expect("scrape metrics")
            .text()
            .await
            .expect("read metrics body");
        let value = logthing::profiling::parse_counter(&rendered, "ipfix_flows_decoded");
        if value.is_some_and(|v| v >= 2) || Instant::now() > scrape_deadline {
            break (rendered, value);
        }
        sleep(POLL_INTERVAL).await;
    };

    assert!(
        last_value.is_some_and(|v| v >= 2),
        "expected ipfix_flows_decoded >= 2 within {READY_TIMEOUT:?}, got {last_value:?}\n\
         full metrics dump:\n{last_rendered}"
    );

    // Wait for the first flush (the 2 short records) to actually land on
    // disk before sending the long-value record below. `BufferedWriter`
    // (`src/forwarding/buffered_writer.rs`) only re-checks its flush
    // trigger on the *next* push while a flush is already in-flight
    // (`try_flush_partition_async`'s `in_flight` guard) -- a push landing
    // mid-flush just buffers and waits. With only one push left to send in
    // this test, racing the first flush would leave the long-value record
    // buffered forever with nothing left to re-trigger it. Waiting for row
    // 2 here (rather than relying on timing) makes sure `in_flight` is
    // clear before the next push arrives.
    let flush_deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if read_extra_values(&ipfix_dir).len() >= 2 || Instant::now() > flush_deadline {
            break;
        }
        sleep(POLL_INTERVAL).await;
    }

    // Round-4 regression: send one more record whose varlen value is 1000
    // raw bytes -- well over MAX_EXTRA_VALUE_BYTES (128) -- and prove it
    // reaches the real binary's Parquet output truncated, with
    // ie97_original_len recording the true length, not just that the
    // decoder's flow count went up.
    sender
        .send_to(&long_varlen_data_msg(), ipfix_addr)
        .await
        .unwrap();

    let scrape_deadline = Instant::now() + READY_TIMEOUT;
    let (last_rendered, last_value) = loop {
        let rendered = metrics_client
            .get(&metrics_url)
            .send()
            .await
            .expect("scrape metrics")
            .text()
            .await
            .expect("read metrics body");
        let value = logthing::profiling::parse_counter(&rendered, "ipfix_flows_decoded");
        if value.is_some_and(|v| v >= 3) || Instant::now() > scrape_deadline {
            break (rendered, value);
        }
        sleep(POLL_INTERVAL).await;
    };
    assert!(
        last_value.is_some_and(|v| v >= 3),
        "expected ipfix_flows_decoded >= 3 within {READY_TIMEOUT:?}, got {last_value:?}\n\
         full metrics dump:\n{last_rendered}"
    );

    // `max_buffer_rows = 1` flushes on every push, but the writer task still
    // needs a moment to materialize each file; poll until all 3 pushed rows
    // (2 short + 1 long) show up on disk, rather than stopping at the first
    // file that appears (which would just be the first 2 rows' flush,
    // racing the third).
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    fn read_extra_values(ipfix_dir: &std::path::Path) -> Vec<String> {
        let parquet_files = walk_all_files(ipfix_dir)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "parquet"))
            .collect::<Vec<_>>();
        let mut extra_values = Vec::new();
        for file_path in &parquet_files {
            let bytes = std::fs::read(file_path).expect("read parquet file");
            let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
                .expect("parquet builder");
            let reader = builder.build().expect("parquet reader");
            for batch in reader {
                let batch = batch.expect("batch ok");
                use arrow::array::{Array, StringArray};
                let extra_col = batch
                    .column_by_name("extra")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .unwrap();
                for i in 0..extra_col.len() {
                    extra_values.push(extra_col.value(i).to_string());
                }
            }
        }
        extra_values
    }

    let file_deadline = Instant::now() + READY_TIMEOUT;
    let extra_values = loop {
        let values = read_extra_values(&ipfix_dir);
        if values.len() >= 3 || Instant::now() > file_deadline {
            break values;
        }
        sleep(POLL_INTERVAL).await;
    };
    assert!(
        extra_values.len() >= 3,
        "expected at least 3 Parquet rows under {ipfix_dir:?} within {READY_TIMEOUT:?}; \
         got: {extra_values:?}"
    );

    let long_value_extra = extra_values
        .iter()
        .find_map(|raw| {
            let extra: serde_json::Value = serde_json::from_str(raw).ok()?;
            extra.get("ie97_original_len")?;
            Some(extra)
        })
        .unwrap_or_else(|| {
            panic!(
                "expected one Parquet row with an \"ie97_original_len\" key (the truncated \
                 1000-byte value); got extras: {extra_values:?}"
            )
        });
    let hex_val = long_value_extra["ie97"]
        .as_str()
        .expect("ie97 must be a hex string");
    assert_eq!(
        hex_val.len(),
        128 * 2,
        "ie97 must be truncated to 256 hex chars (128 bytes) in the real binary's Parquet \
         output; got {hex_val:?} in extra: {long_value_extra}"
    );
    assert_eq!(
        long_value_extra["ie97_original_len"],
        serde_json::json!(1000),
        "Parquet output must record the true original value length; got: {long_value_extra}"
    );
}

fn walk_all_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}
