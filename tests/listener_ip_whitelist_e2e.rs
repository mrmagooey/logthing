//! End-to-end test: `security.allowed_ips` enforcement across a *real*
//! `logthing` process.
//!
//! `listener_ip_whitelist_integration.rs` drives two listeners in-process
//! via their public `start_with_shutdown` entry points. This test instead
//! spawns the actual compiled binary (`env!("CARGO_BIN_EXE_logthing")`)
//! against a real `logthing.toml`, which is the only way to prove that
//! `main.rs` actually wires `.with_allowed_ips(...)` into all five listener
//! construction sites — a missed call there would compile cleanly and start
//! cleanly, and only show up as a silent bypass at runtime.
//!
//! `Config::load()` resolves `config::File::with_name("logthing")` relative
//! to the process's current working directory, so the config is placed in a
//! temp dir and the child is spawned with `current_dir` set to it.
//!
//! All five wire-protocol listeners are enabled on ephemeral high ports with
//! no S3/local sinks configured, so each falls back to its `Default*Handler`
//! — no AWS credentials needed. TLS is explicitly disabled (it defaults to
//! *on* and would otherwise require a cert/key). `security.allowed_ips` is
//! set to a range that excludes 127.0.0.1, so every probe sent from
//! 127.0.0.1 below must be rejected.
//!
//! The metrics server (`start_metrics_server`, `src/server/mod.rs`) is a
//! separate axum `Router` with no `IpWhitelist` layer attached, so it stays
//! scrapable from 127.0.0.1 even though the listeners block 127.0.0.1 —
//! that asymmetry is exactly what lets this test observe the rejection
//! counters from outside.

use std::fs::File;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::sleep;

/// Overall budget for "wait until the process is ready" polling loops.
/// The binary binds five listeners plus an HTTP router plus a metrics
/// server, non-deterministically ordered across tokio tasks, so a fixed
/// sleep can't stand in for this.
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Kills and reaps the spawned `logthing` process on drop — including
/// during a panicking assertion — so a failing test never leaves an
/// orphaned daemon holding ports.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Ephemeral ports needed by the test config, allocated together (all
/// sockets held open simultaneously, then dropped as a batch) so none of
/// them can collide with each other during allocation.
struct Ports {
    http: u16,
    metrics: u16,
    syslog_udp: u16,
    syslog_tcp: u16,
    ipfix_udp: u16,
    sflow_udp: u16,
    zeek_tcp: u16,
    suricata_tcp: u16,
}

async fn alloc_ports() -> Ports {
    let tcp_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_metrics = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_syslog = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_zeek = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_suricata = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp_syslog = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_ipfix = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_sflow = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    Ports {
        http: tcp_http.local_addr().unwrap().port(),
        metrics: tcp_metrics.local_addr().unwrap().port(),
        syslog_tcp: tcp_syslog.local_addr().unwrap().port(),
        zeek_tcp: tcp_zeek.local_addr().unwrap().port(),
        suricata_tcp: tcp_suricata.local_addr().unwrap().port(),
        syslog_udp: udp_syslog.local_addr().unwrap().port(),
        ipfix_udp: udp_ipfix.local_addr().unwrap().port(),
        sflow_udp: udp_sflow.local_addr().unwrap().port(),
    }
    // All eight sockets/listeners drop together here, releasing every port
    // at once for the child process to bind.
}

/// Poll until a TCP port accepts a connection, or panic with a clear
/// message once `deadline` passes.
async fn wait_for_tcp(port: u16, deadline: Instant, what: &str) {
    let addr = format!("127.0.0.1:{port}");
    loop {
        if TcpStream::connect(&addr).await.is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for {what} (TCP {port}) to start accepting connections");
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Poll until a UDP port is bound by the child process. Since UDP has no
/// handshake to probe, this instead tries to bind the same address itself:
/// as long as *we* can bind it, nothing else owns it yet; once our bind
/// fails with `AddrInUse`, the child has claimed it.
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

/// Poll the metrics endpoint until it answers with HTTP 200, or panic once
/// `deadline` passes.
async fn wait_for_metrics(url: &str, deadline: Instant) {
    loop {
        if let Ok(resp) = reqwest::get(url).await
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

/// Sum every label-set of an unlabelled-lookup counter. Reuses the same
/// parser the binary itself uses for its shutdown-drain queue readout, so
/// this test doesn't reinvent Prometheus-text parsing.
fn received_counter(rendered: &str, name: &str) -> Option<u64> {
    logthing::profiling::parse_counter(rendered, name)
}

/// Read the value of `metric{label_key="label_value"}` from rendered
/// Prometheus exposition text. `listener_source_rejected` only ever carries
/// one label (`protocol`), so an exact `name{key="value"}` prefix match is
/// unambiguous — no need for a general label parser.
fn labeled_counter(
    rendered: &str,
    metric: &str,
    label_key: &str,
    label_value: &str,
) -> Option<u64> {
    let needle = format!("{metric}{{{label_key}=\"{label_value}\"}}");
    for line in rendered.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(&needle)
            && let Ok(v) = rest.trim().parse::<f64>()
        {
            return Some(v as u64);
        }
    }
    None
}

#[tokio::test]
async fn allowed_ips_blocks_all_five_listeners_over_a_real_process() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ports = alloc_ports().await;

    let toml = format!(
        r#"
bind_address = "127.0.0.1:{http}"

[tls]
enabled = false

[security]
allowed_ips = ["10.99.99.0/24"]

[metrics]
enabled = true
port = {metrics}

[syslog]
enabled = true
udp_port = {syslog_udp}
tcp_port = {syslog_tcp}

[ipfix]
enabled = true
udp_port = {ipfix_udp}

[sflow]
enabled = true
udp_port = {sflow_udp}

[zeek]
enabled = true
tcp_port = {zeek_tcp}

[suricata]
enabled = true
tcp_port = {suricata_tcp}
"#,
        http = ports.http,
        metrics = ports.metrics,
        syslog_udp = ports.syslog_udp,
        syslog_tcp = ports.syslog_tcp,
        ipfix_udp = ports.ipfix_udp,
        sflow_udp = ports.sflow_udp,
        zeek_tcp = ports.zeek_tcp,
        suricata_tcp = ports.suricata_tcp,
    );

    std::fs::write(tmp.path().join("logthing.toml"), toml).expect("write logthing.toml");

    // Redirect the child's stdout/stderr to files instead of pipes: a piped
    // child can deadlock the parent if its output buffer fills and nobody
    // drains it, and we don't need to watch the stream live.
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
    let metrics_url = format!("http://127.0.0.1:{}/metrics", ports.metrics);

    // Wait for every listener plus the metrics server to actually be bound
    // before probing — no fixed sleep, since bind order across the five
    // listener tasks, the HTTP router and the metrics server is not
    // deterministic.
    wait_for_metrics(&metrics_url, deadline).await;
    wait_for_udp(ports.syslog_udp, deadline, "syslog UDP").await;
    wait_for_tcp(ports.syslog_tcp, deadline, "syslog TCP").await;
    wait_for_udp(ports.ipfix_udp, deadline, "IPFIX").await;
    wait_for_udp(ports.sflow_udp, deadline, "sFlow").await;
    wait_for_tcp(ports.zeek_tcp, deadline, "Zeek").await;
    wait_for_tcp(ports.suricata_tcp, deadline, "Suricata").await;

    // --- Probe all five listeners from 127.0.0.1, which allowed_ips blocks ---

    // UDP: a single datagram each. Content is irrelevant — the whitelist
    // guard runs before any decoding, so these never reach the decoder.
    let udp_probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_probe
        .send_to(
            b"<134>e2e blocked syslog udp\n",
            ("127.0.0.1", ports.syslog_udp),
        )
        .await
        .unwrap();
    udp_probe
        .send_to(
            b"e2e blocked ipfix datagram",
            ("127.0.0.1", ports.ipfix_udp),
        )
        .await
        .unwrap();
    udp_probe
        .send_to(
            b"e2e blocked sflow datagram",
            ("127.0.0.1", ports.sflow_udp),
        )
        .await
        .unwrap();

    // TCP: connect *and send a payload*. A connect-only probe would leave
    // the "received counter stayed at zero" assertion trivially true
    // whether or not the guard works — the payload is what would have
    // produced a real "received" increment had the connection been let
    // through.
    async fn send_tcp(port: u16, payload: &[u8]) {
        // The whitelist guard runs at `accept()`, before any read, so the
        // connection may be reset immediately — a write error here just
        // means the rejection already happened, which is the point.
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)).await {
            use tokio::io::AsyncWriteExt;
            let _ = stream.write_all(payload).await;
        }
    }
    send_tcp(ports.syslog_tcp, b"<134>e2e blocked syslog tcp\n").await;
    send_tcp(ports.zeek_tcp, b"{\"_path\":\"conn\"}\n").await;
    send_tcp(ports.suricata_tcp, b"{\"event_type\":\"alert\"}\n").await;

    // --- Scrape metrics and assert every one of the six protocol labels
    //     shows a non-zero rejection count. This is the load-bearing
    //     assertion: it is the only thing that proves all five wiring
    //     sites in `main.rs` actually attached the whitelist. A missed
    //     `.with_allowed_ips()` call would compile and start cleanly and
    //     would only show up here, as a missing or zero label. ---
    let protocols = [
        "syslog_udp",
        "syslog_tcp",
        "ipfix",
        "sflow",
        "zeek",
        "suricata",
    ];
    let scrape_deadline = Instant::now() + READY_TIMEOUT;
    let last_rendered;
    loop {
        let rendered = reqwest::get(&metrics_url)
            .await
            .expect("scrape metrics")
            .text()
            .await
            .expect("read metrics body");
        let all_present = protocols.iter().all(|p| {
            labeled_counter(&rendered, "listener_source_rejected", "protocol", p)
                .is_some_and(|v| v > 0)
        });
        if all_present {
            last_rendered = rendered;
            break;
        }
        if Instant::now() > scrape_deadline {
            last_rendered = rendered;
            break;
        }
        sleep(POLL_INTERVAL).await;
    }

    for protocol in protocols {
        let value = labeled_counter(
            &last_rendered,
            "listener_source_rejected",
            "protocol",
            protocol,
        );
        assert!(
            value.is_some_and(|v| v > 0),
            "expected listener_source_rejected{{protocol=\"{protocol}\"}} > 0, got {value:?}\n\
             full metrics dump:\n{last_rendered}"
        );
    }

    // --- The blocked traffic must never have reached a handler: every
    //     "*_received"-style counter for a probed protocol must be absent
    //     (never incremented) rather than merely small. ---
    assert_eq!(
        received_counter(&last_rendered, "syslog_messages_received"),
        None,
        "syslog_messages_received must not increment for a source outside allowed_ips"
    );
    assert_eq!(
        received_counter(&last_rendered, "ipfix_datagrams_received"),
        None,
        "ipfix_datagrams_received must not increment for a source outside allowed_ips"
    );
    assert_eq!(
        received_counter(&last_rendered, "sflow_datagrams_received"),
        None,
        "sflow_datagrams_received must not increment for a source outside allowed_ips"
    );
    assert_eq!(
        received_counter(&last_rendered, "zeek_records_received"),
        None,
        "zeek_records_received must not increment for a source outside allowed_ips"
    );
    assert_eq!(
        received_counter(&last_rendered, "suricata_records_received"),
        None,
        "suricata_records_received must not increment for a source outside allowed_ips"
    );
}
