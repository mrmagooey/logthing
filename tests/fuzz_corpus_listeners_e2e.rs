//! End-to-end test: replay every committed fuzz seed and regression file
//! through the REAL `logthing` binary's listeners (not the in-process
//! harness `tests/fuzz_corpus_replay_integration.rs` uses), then prove the
//! process is still alive and no spawned task panicked.
//!
//! `src/fuzz_harness.rs` replays each input against the library function
//! directly, which only proves the mapping code itself doesn't panic. It
//! can't catch a panic in the listener/handler plumbing around that
//! function (framing, dispatch, the `SyslogHandler` chain, HTTP routing,
//! ...), because none of that code runs when calling the harness function
//! directly. This test closes that gap by driving a real child process over
//! the wire.
//!
//! Modeled on `tests/sigterm_graceful_shutdown_e2e.rs` (`ChildGuard`,
//! `wait_for_metrics`, ephemeral ports allocated together, stdout/stderr
//! redirected to files) — test files here don't share modules, so the
//! helpers are copied in rather than imported.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::sleep;

const READY_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Deadline for the post-corpus probe phase (task requirement: 10s).
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Kills and reaps the child on drop — including during a panicking
/// assertion — so a failing test never leaves an orphaned daemon.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Every listener port the child binds, allocated together so none can
/// collide with another. `syslog.tcp_port` must be pinned to an ephemeral
/// port explicitly: its config default (601) is privileged and binding it
/// fails with EACCES unprivileged.
struct Ports {
    http: u16,
    metrics: u16,
    syslog_udp: u16,
    syslog_tcp: u16,
    ipfix: u16,
    sflow: u16,
    zeek: u16,
    suricata: u16,
}

async fn allocate_ports() -> Ports {
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let syslog_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let syslog_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ipfix = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sflow = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let zeek = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let suricata = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ports = Ports {
        http: http.local_addr().unwrap().port(),
        metrics: metrics.local_addr().unwrap().port(),
        syslog_udp: syslog_udp.local_addr().unwrap().port(),
        syslog_tcp: syslog_tcp.local_addr().unwrap().port(),
        ipfix: ipfix.local_addr().unwrap().port(),
        sflow: sflow.local_addr().unwrap().port(),
        zeek: zeek.local_addr().unwrap().port(),
        suricata: suricata.local_addr().unwrap().port(),
    };
    // Every listener socket above is dropped here, freeing the ports for
    // the child to bind.
    ports
}

fn config_toml(p: &Ports, out: &Path) -> String {
    format!(
        r#"
bind_address = "127.0.0.1:{http}"

[tls]
enabled = false

[metrics]
enabled = true
port = {metrics}

[syslog]
enabled = true
udp_port = {syslog_udp}
tcp_port = {syslog_tcp}
[syslog.local]
directory = "{out}/syslog"

[ipfix]
enabled = true
udp_port = {ipfix}
bind_address = "127.0.0.1"
[ipfix.local]
directory = "{out}/ipfix"

[sflow]
enabled = true
udp_port = {sflow}
bind_address = "127.0.0.1"
[sflow.local]
directory = "{out}/sflow"

[zeek]
enabled = true
tcp_port = {zeek}
bind_address = "127.0.0.1"
[zeek.local]
directory = "{out}/zeek"

[suricata]
enabled = true
tcp_port = {suricata}
bind_address = "127.0.0.1"
[suricata.local]
directory = "{out}/suricata"

[hec]
enabled = true
token = "fuzz-e2e"
# Also the sink for OTLP: IngestState is built from hec.{{s3,local}} only.
[hec.local]
directory = "{out}/hec"

[otlp]
enabled = true
"#,
        http = p.http,
        metrics = p.metrics,
        syslog_udp = p.syslog_udp,
        syslog_tcp = p.syslog_tcp,
        ipfix = p.ipfix,
        sflow = p.sflow,
        zeek = p.zeek,
        suricata = p.suricata,
        out = out.display(),
    )
}

async fn wait_for_metrics(url: &str, deadline: Instant) {
    loop {
        if let Ok(resp) = reqwest::get(url).await
            && resp.status().is_success()
        {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for metrics endpoint {url}");
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Poll until the child owns a UDP port. UDP has no handshake, so this
/// probes by trying to bind the same address: once our bind fails with
/// `AddrInUse`, the child has claimed it.
async fn wait_for_udp(port: u16, deadline: Instant) {
    let addr = format!("127.0.0.1:{port}");
    loop {
        match UdpSocket::bind(&addr).await {
            Ok(sock) => drop(sock),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return,
            Err(e) => panic!("unexpected error probing UDP {port}: {e}"),
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for UDP {port} to be bound");
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Poll until the child accepts TCP connections on `port`.
async fn wait_for_tcp(port: u16, deadline: Instant) {
    let addr = format!("127.0.0.1:{port}");
    loop {
        if TcpStream::connect(&addr).await.is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for TCP {port} to accept connections");
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn read_counter(url: &str, name: &str) -> u64 {
    let Ok(resp) = reqwest::get(url).await else {
        return 0;
    };
    let Ok(body) = resp.text().await else {
        return 0;
    };
    logthing::profiling::parse_counter(&body, name).unwrap_or(0)
}

/// Poll the metrics endpoint until counter `name` exceeds `baseline`.
async fn wait_for_metric_above(url: &str, name: &str, baseline: u64, deadline: Instant) {
    loop {
        let val = read_counter(url, name).await;
        if val > baseline {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for {name} > {baseline}, last saw {val}");
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Split `data` into datagrams, each prefixed by its big-endian u16 length.
/// Copied from the private `length_prefixed` in `src/fuzz_harness.rs` — see
/// that file for the framing this mirrors.
fn length_prefixed(mut data: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        let (len, rest) = data.split_first_chunk::<2>()?;
        let (dgram, rest) = rest.split_at(usize::from(u16::from_be_bytes(*len)).min(rest.len()));
        data = rest;
        Some(dgram)
    })
}

/// Every file (sorted) directly under `dir`. A missing directory (no
/// `fuzz/regressions/<target>` yet committed) is treated as empty rather
/// than an error.
fn files(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<_> = rd
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .collect();
    v.sort();
    v
}

/// Every seed plus every regression file for one fuzz target, as raw bytes.
fn corpus(fuzz_root: &Path, target: &str) -> Vec<Vec<u8>> {
    files(&fuzz_root.join("seeds").join(target))
        .into_iter()
        .chain(files(&fuzz_root.join("regressions").join(target)))
        .map(|p| std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display())))
        .collect()
}

/// Send every datagram in `packets` to `addr` on `socket`, with a 1ms sleep
/// every 50 packets so the kernel's receive buffer doesn't drop the tail of
/// a burst (including the readiness probe sent right after).
async fn send_udp_all<'a>(socket: &UdpSocket, addr: &str, packets: impl Iterator<Item = &'a [u8]>) {
    for (i, pkt) in packets.enumerate() {
        socket.send_to(pkt, addr).await.expect("send udp datagram");
        if (i + 1) % 50 == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    }
}

/// One TCP connection per file: write the bytes, a trailing `\n`, then
/// shut down the write half. A connect failure (the process may have
/// crashed on a prior file) is logged, not panicked on — the final
/// assertions are what should fail in that case, with `stderr.log` showing
/// why.
async fn send_tcp_file(addr: &str, bytes: &[u8]) {
    match TcpStream::connect(addr).await {
        Ok(mut stream) => {
            let _ = AsyncWriteExt::write_all(&mut stream, bytes).await;
            let _ = AsyncWriteExt::write_all(&mut stream, b"\n").await;
            let _ = AsyncWriteExt::shutdown(&mut stream).await;
        }
        Err(e) => eprintln!(
            "tcp connect to {addr} failed (file len {}): {e}",
            bytes.len()
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_fuzz_corpus_listeners_binary_survives_every_committed_input() {
    let fuzz_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz");
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp.path().join("out");

    let ports = allocate_ports().await;
    std::fs::write(
        tmp.path().join("logthing.toml"),
        config_toml(&ports, &out_dir),
    )
    .expect("write logthing.toml");

    let stdout_log = std::fs::File::create(tmp.path().join("stdout.log")).unwrap();
    let stderr_log = std::fs::File::create(tmp.path().join("stderr.log")).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_logthing"))
        .current_dir(tmp.path())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .spawn()
        .expect("spawn logthing binary");
    let mut guard = ChildGuard(child);

    let ready_deadline = Instant::now() + READY_TIMEOUT;
    let metrics_url = format!("http://127.0.0.1:{}/metrics", ports.metrics);
    let health_url = format!("http://127.0.0.1:{}/health", ports.http);
    wait_for_metrics(&metrics_url, ready_deadline).await;
    wait_for_udp(ports.syslog_udp, ready_deadline).await;
    wait_for_udp(ports.ipfix, ready_deadline).await;
    wait_for_udp(ports.sflow, ready_deadline).await;
    wait_for_tcp(ports.syslog_tcp, ready_deadline).await;
    wait_for_tcp(ports.zeek, ready_deadline).await;
    wait_for_tcp(ports.suricata, ready_deadline).await;

    // --- Phase 1: send every seed + regression file to its real listener ---

    let syslog_addr = format!("127.0.0.1:{}", ports.syslog_udp);
    let ipfix_addr = format!("127.0.0.1:{}", ports.ipfix);
    let sflow_addr = format!("127.0.0.1:{}", ports.sflow);
    let zeek_addr = format!("127.0.0.1:{}", ports.zeek);
    let suricata_addr = format!("127.0.0.1:{}", ports.suricata);
    let http_base = format!("http://127.0.0.1:{}", ports.http);
    let http_client = reqwest::Client::new();

    // syslog: one file per UDP datagram.
    let syslog_corpus = corpus(&fuzz_root, "syslog");
    let syslog_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_udp_all(
        &syslog_socket,
        &syslog_addr,
        syslog_corpus.iter().map(Vec::as_slice),
    )
    .await;

    // ipfix: split each file with the u16 length-prefix framing, each
    // datagram sent as its own UDP packet, sharing one exporter/template
    // cache the way the real listener does.
    let ipfix_corpus = corpus(&fuzz_root, "ipfix");
    let ipfix_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ipfix_datagrams: Vec<&[u8]> = ipfix_corpus
        .iter()
        .flat_map(|bytes| length_prefixed(bytes))
        .collect();
    send_udp_all(&ipfix_socket, &ipfix_addr, ipfix_datagrams.into_iter()).await;

    // sflow: one file per UDP datagram.
    let sflow_corpus = corpus(&fuzz_root, "sflow");
    let sflow_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_udp_all(
        &sflow_socket,
        &sflow_addr,
        sflow_corpus.iter().map(Vec::as_slice),
    )
    .await;

    // zeek / suricata: one TCP connection per file, trailing `\n`, then
    // shutdown — the NDJSON framing the real listener expects.
    for bytes in corpus(&fuzz_root, "zeek") {
        send_tcp_file(&zeek_addr, &bytes).await;
    }
    for bytes in corpus(&fuzz_root, "suricata") {
        send_tcp_file(&suricata_addr, &bytes).await;
    }

    // hec: byte 0 picks the route (`% 3`: 0=event, 1=raw, 2=ndjson); the
    // rest of the file is the body.
    for bytes in corpus(&fuzz_root, "hec") {
        let Some((&route, body)) = bytes.split_first() else {
            continue;
        };
        let path = match route % 3 {
            0 => "/services/collector/event",
            1 => "/services/collector/raw",
            _ => "/ingest",
        };
        let _ = http_client
            .post(format!("{http_base}{path}"))
            .header("Authorization", "Splunk fuzz-e2e")
            .body(body.to_vec())
            .send()
            .await;
    }

    // otlp: byte 0 picks the content type (`% 2`: even=protobuf,
    // odd=json). Sent unconditionally — when the crate is built without the
    // `otlp` feature the route simply isn't mounted and this 404s, which is
    // not a crash. No otlp-feature-gated symbol is referenced here, so this
    // test needs no `#[cfg(feature = "otlp")]` of its own.
    for bytes in corpus(&fuzz_root, "otlp") {
        let Some((&ct, body)) = bytes.split_first() else {
            continue;
        };
        let content_type = if ct % 2 == 0 {
            "application/x-protobuf"
        } else {
            "application/json"
        };
        let _ = http_client
            .post(format!("{http_base}/v1/logs"))
            .header("Content-Type", content_type)
            .body(body.to_vec())
            .send()
            .await;
    }

    // wef_envelope: the raw HTTP body WEF's `/wsman/events` receives.
    for bytes in corpus(&fuzz_root, "wef_envelope") {
        let _ = http_client
            .post(format!("{http_base}/wsman/events"))
            .body(bytes)
            .send()
            .await;
    }

    // wef_event is harness-only: its selector byte picks a *configured
    // parser id* (`sorted_event_ids()` in `src/fuzz_harness.rs`), which has
    // no equivalent on the wire — nothing sends a bare parser index over
    // HTTP. There is no listener to replay it against, so it's skipped here
    // (it's still covered by `src/fuzz_harness.rs`'s own tests and the
    // stable corpus replay in `tests/fuzz_corpus_replay_integration.rs`).

    // --- Phase 2: one known-good probe per listener that has a received-
    // --- record metric, and confirm the counters move and /health is up.

    let baseline_syslog = read_counter(&metrics_url, "syslog_messages_received").await;
    let baseline_ipfix = read_counter(&metrics_url, "ipfix_datagrams_received").await;
    let baseline_sflow = read_counter(&metrics_url, "sflow_datagrams_received").await;
    let baseline_zeek = read_counter(&metrics_url, "zeek_records_received").await;
    let baseline_suricata = read_counter(&metrics_url, "suricata_records_received").await;

    let syslog_probe = b"<134>Jan 15 10:30:45 host-e2e probe: still alive\n";
    syslog_socket
        .send_to(syslog_probe, &syslog_addr)
        .await
        .expect("send syslog probe");

    // Re-send a known-good ipfix seed's first datagram as the probe.
    let ipfix_probe_file = std::fs::read(fuzz_root.join("seeds/ipfix/v5_single_flow.bin"))
        .expect("read ipfix probe seed");
    let ipfix_probe = length_prefixed(&ipfix_probe_file)
        .next()
        .expect("ipfix probe seed has at least one datagram")
        .to_vec();
    ipfix_socket
        .send_to(&ipfix_probe, &ipfix_addr)
        .await
        .expect("send ipfix probe");

    let sflow_probe = std::fs::read(fuzz_root.join("seeds/sflow/sampled_ipv4.bin"))
        .expect("read sflow probe seed");
    sflow_socket
        .send_to(&sflow_probe, &sflow_addr)
        .await
        .expect("send sflow probe");

    let zeek_probe =
        std::fs::read(fuzz_root.join("seeds/zeek/mixed.ndjson")).expect("read zeek probe seed");
    send_tcp_file(&zeek_addr, &zeek_probe).await;

    let suricata_probe = std::fs::read(fuzz_root.join("seeds/suricata/mixed.ndjson"))
        .expect("read suricata probe seed");
    send_tcp_file(&suricata_addr, &suricata_probe).await;

    let probe_deadline = Instant::now() + PROBE_TIMEOUT;
    wait_for_metric_above(
        &metrics_url,
        "syslog_messages_received",
        baseline_syslog,
        probe_deadline,
    )
    .await;
    wait_for_metric_above(
        &metrics_url,
        "ipfix_datagrams_received",
        baseline_ipfix,
        probe_deadline,
    )
    .await;
    wait_for_metric_above(
        &metrics_url,
        "sflow_datagrams_received",
        baseline_sflow,
        probe_deadline,
    )
    .await;
    wait_for_metric_above(
        &metrics_url,
        "zeek_records_received",
        baseline_zeek,
        probe_deadline,
    )
    .await;
    wait_for_metric_above(
        &metrics_url,
        "suricata_records_received",
        baseline_suricata,
        probe_deadline,
    )
    .await;

    let health = reqwest::get(&health_url).await.expect("GET /health");
    assert!(
        health.status().is_success(),
        "/health returned {} after the fuzz corpus",
        health.status()
    );

    // --- Phase 3: the process must still be running, and nothing panicked. ---

    assert_eq!(
        guard.0.try_wait().expect("try_wait"),
        None,
        "the logthing process exited during the fuzz corpus replay"
    );

    let stderr = std::fs::read_to_string(tmp.path().join("stderr.log")).unwrap_or_default();
    assert!(
        !stderr.contains("panicked at"),
        "stderr contains a panic (a panicking spawned task leaves the process alive, so \
         try_wait() alone can't catch this):\n{stderr}"
    );
}
