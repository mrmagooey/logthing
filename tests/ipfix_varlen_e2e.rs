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

#[tokio::test]
async fn ipfix_varlen_records_increment_flows_decoded_on_real_process() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let http_port = ephemeral_tcp_port().await;
    let metrics_port = ephemeral_tcp_port().await;
    let ipfix_port = ephemeral_udp_port().await;

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
    sleep(Duration::from_millis(100)).await;
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
}
