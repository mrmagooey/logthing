//! End-to-end test: a real `logthing` process flushes its buffered records
//! to disk when it receives SIGTERM.
//!
//! Before the fix, `main.rs` installed only `tokio::signal::ctrl_c()`
//! (SIGINT), so SIGTERM never reached the graceful-shutdown sequence and
//! every record buffered since the last periodic flush was lost on pod
//! termination.
//!
//! The config below sets `max_buffer_rows = 100000` and
//! `flush_interval_secs = 3600`, so neither the row threshold nor the age
//! ticker can fire inside the test window — the shutdown drain
//! (`buffered_writer.rs`'s channel-close arm, which runs
//! `drain_pending_flushes()` then `flush_all()`) is the only path that can
//! produce a Parquet file here.
//!
//! NOTE: the child is an ordinary process, not PID 1, so this does not
//! reproduce the kernel's PID-1 signal-discard behaviour. Against the
//! unfixed binary SIGTERM simply kills the child outright. That is why the
//! exit assertion checks the process was *not* signal-terminated rather than
//! merely that it exited.

mod common;

use std::fs::File;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::sleep;

const READY_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Must clear the binary's own 10s writer-flush deadline
/// (`await_handles_with_deadline` in `src/main.rs`) with margin.
const EXIT_TIMEOUT: Duration = Duration::from_secs(45);

const MESSAGE_COUNT: usize = 25;

/// Kills and reaps the child on drop — including during a panicking
/// assertion — so a failing test never leaves an orphaned daemon.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn walk_all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_all_files(&path, out);
        } else {
            out.push(path);
        }
    }
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

/// Poll until the child owns the UDP port. UDP has no handshake, so this
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
            panic!("timed out waiting for syslog UDP {port} to be bound");
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Poll the metrics endpoint until `syslog_messages_received` reaches
/// `want`, so the test never signals the child before its records are
/// actually in the writer's buffer.
async fn wait_for_received(url: &str, want: u64, deadline: Instant) {
    let mut last = 0;
    loop {
        if let Ok(resp) = reqwest::get(url).await
            && let Ok(body) = resp.text().await
        {
            last =
                logthing::profiling::parse_counter(&body, "syslog_messages_received").unwrap_or(0);
            if last >= want {
                return;
            }
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for syslog_messages_received >= {want}, last saw {last}");
        }
        sleep(POLL_INTERVAL).await;
    }
}

#[tokio::test]
async fn sigterm_flushes_buffered_records_to_disk() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp.path().join("syslog-out");

    // Allocate all ports together so they cannot collide with each other.
    // `syslog.tcp_port` must be pinned to an ephemeral port explicitly: its
    // config default (601) is a privileged port and binding it fails with
    // EACCES when the test (and CI) run unprivileged, which would abort the
    // syslog listener startup before this test ever gets to send SIGTERM.
    let (http_port, metrics_port, syslog_udp_port, syslog_tcp_port) = {
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let metrics = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        (
            http.local_addr().unwrap().port(),
            metrics.local_addr().unwrap().port(),
            udp.local_addr().unwrap().port(),
            tcp.local_addr().unwrap().port(),
        )
    };

    let toml = format!(
        r#"
bind_address = "127.0.0.1:{http_port}"

[tls]
enabled = false

[metrics]
enabled = true
port = {metrics_port}

[syslog]
enabled = true
udp_port = {syslog_udp_port}
tcp_port = {syslog_tcp_port}

[syslog.local]
directory = "{out_dir}"
prefix = "syslog"
max_buffer_rows = 100000
flush_interval_secs = 3600
"#,
        out_dir = out_dir.display(),
    );
    std::fs::write(tmp.path().join("logthing.toml"), toml).expect("write logthing.toml");

    // Redirect child output to files: a piped child can deadlock the parent
    // if its output buffer fills and nobody drains it.
    let stdout_log = File::create(tmp.path().join("stdout.log")).unwrap();
    let stderr_log = File::create(tmp.path().join("stderr.log")).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_logthing"))
        .current_dir(tmp.path())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .spawn()
        .expect("spawn logthing binary");
    let pid = child.id();
    let mut guard = ChildGuard(child);

    let deadline = Instant::now() + READY_TIMEOUT;
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    wait_for_metrics(&metrics_url, deadline).await;
    wait_for_udp(syslog_udp_port, deadline).await;

    // Send the records.
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..MESSAGE_COUNT {
        let msg = format!("<134>Jan 15 10:30:45 host-e2e sigterm-test: record {i}\n");
        probe
            .send_to(msg.as_bytes(), ("127.0.0.1", syslog_udp_port))
            .await
            .expect("send syslog datagram");
    }
    wait_for_received(&metrics_url, MESSAGE_COUNT as u64, deadline).await;

    // Nothing may have been written yet — only the shutdown drain can flush.
    let mut before = Vec::new();
    walk_all_files(&out_dir, &mut before);
    assert!(
        before
            .iter()
            .all(|p| p.extension().is_none_or(|e| e != "parquet")),
        "a Parquet file existed before shutdown, so this test cannot \
         attribute the post-shutdown file to the drain: {before:?}"
    );

    // --- The actual trigger under test ---
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("run kill(1)");
    assert!(status.success(), "kill -TERM {pid} failed");

    // Poll for exit rather than blocking, so we can bound the wait.
    let exit_deadline = Instant::now() + EXIT_TIMEOUT;
    let exit_status = loop {
        match guard.0.try_wait().expect("try_wait") {
            Some(status) => break status,
            None => {
                if Instant::now() > exit_deadline {
                    panic!(
                        "child {pid} did not exit within {EXIT_TIMEOUT:?} of SIGTERM \
                         — the signal was ignored"
                    );
                }
                sleep(POLL_INTERVAL).await;
            }
        }
    };

    // Assertion 1: exited on its own, NOT killed by the signal. Checking only
    // that it exited would be vacuous — the unfixed binary also exits
    // promptly, by dying.
    assert!(
        exit_status.signal().is_none(),
        "child was terminated by signal {:?} instead of shutting down \
         gracefully — SIGTERM reached default disposition, meaning no handler \
         was installed",
        exit_status.signal()
    );
    assert!(
        exit_status.success(),
        "child exited uncleanly: {exit_status:?}"
    );

    // Assertion 2: the drain actually wrote the records.
    let mut after = Vec::new();
    walk_all_files(&out_dir, &mut after);
    let parquet: Vec<_> = after
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    assert!(
        !parquet.is_empty(),
        "no Parquet file under {} after SIGTERM — the shutdown drain never ran, \
         so the buffered records were lost. Files present: {after:?}",
        out_dir.display()
    );

    let mut rows = 0usize;
    for path in &parquet {
        let file = File::open(path).expect("open parquet");
        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)
            .expect("parquet reader")
            .build()
            .expect("build reader");
        for batch in reader {
            rows += batch.expect("read batch").num_rows();
        }
    }
    assert_eq!(
        rows, MESSAGE_COUNT,
        "expected all {MESSAGE_COUNT} buffered records to be flushed by the \
         shutdown drain, found {rows}"
    );
}

/// Config for one TCP listener (`syslog` or `zeek`) writing to a local sink that only the
/// shutdown drain can flush, plus a metrics endpoint to observe ingestion.
fn tcp_listener_toml(kind: &str, tcp_port: u16, metrics_port: u16) -> String {
    // The syslog listener is on by default and its default TCP port (601) is privileged.
    let extra = if kind == "syslog" {
        format!("udp_port = {}\n", common::free_port())
    } else {
        "\n[syslog]\nenabled = false\n".to_string()
    };
    format!(
        r#"
bind_address = "127.0.0.1:{{HTTP}}"

[tls]
enabled = false

[metrics]
enabled = true
port = {metrics_port}

[{kind}]
enabled = true
tcp_port = {tcp_port}
bind_address = "127.0.0.1"
{extra}
[{kind}.local]
directory = "{{DIR}}/out"
max_buffer_rows = 100000
flush_interval_secs = 3600
"#
    )
}

/// A TCP connection that stays open and idle (never closed by the client) after sending
/// `LINES` complete lines plus half a line must not stop SIGTERM from flushing the complete
/// lines: the process exits 0 within the deadline and the lines are on disk.
///
/// The child process receives the signal, not the test process, so these tests do not share
/// signal-handler state and can live in separate test functions.
async fn idle_tcp_connection_sigterm_case(kind: &str, line: impl Fn(usize) -> String, half: &str) {
    use tokio::io::AsyncWriteExt;

    const LINES: usize = 5;
    // `spawn_healthy` only retries a clash on the HTTP port. A clash on the listener or metrics
    // port (the probe port was taken between `free_port()` and the child's bind) leaves the
    // child "healthy" but with that listener dead, and the connect below then reaches whatever
    // else owns the port. So also require the metrics endpoint to answer and the child's logs
    // to be free of bind failures, and start over on fresh ports otherwise.
    let mut attempt = 0;
    let (mut proc, tcp_port, metrics_port) = loop {
        attempt += 1;
        let tcp_port = common::free_port();
        let mut metrics_port = common::free_port();
        while metrics_port == tcp_port {
            metrics_port = common::free_port();
        }
        let toml = tcp_listener_toml(kind, tcp_port, metrics_port);
        let proc = common::Proc::spawn_healthy(env!("CARGO_BIN_EXE_logthing"), &toml, &[]).await;
        let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
        let up_deadline = Instant::now() + Duration::from_secs(10);
        let mut metrics_up = false;
        while Instant::now() < up_deadline {
            if reqwest::get(&metrics_url)
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                metrics_up = true;
                break;
            }
            sleep(POLL_INTERVAL).await;
        }
        let logs = proc.logs().to_lowercase();
        if metrics_up && !logs.contains("address already in use") && !logs.contains("panicked") {
            break (proc, tcp_port, metrics_port);
        }
        assert!(
            attempt < common::START_ATTEMPTS,
            "listener/metrics startup failed {attempt} times; last child logs:\n{}",
            proc.logs()
        );
    };

    let mut conn = loop {
        match tokio::net::TcpStream::connect(("127.0.0.1", tcp_port)).await {
            Ok(c) => break c,
            Err(_) => sleep(POLL_INTERVAL).await,
        }
    };
    for i in 0..LINES {
        conn.write_all(line(i).as_bytes()).await.unwrap();
    }
    conn.write_all(half.as_bytes()).await.unwrap();
    conn.flush().await.unwrap();

    // Wait until the server has actually read the complete lines (connection stays open).
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let counter = if kind == "syslog" {
        "syslog_messages_received"
    } else {
        "zeek_records_received"
    };
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Ok(resp) = reqwest::get(&metrics_url).await
            && let Ok(body) = resp.text().await
            && logthing::profiling::parse_counter(&body, counter).unwrap_or(0) >= LINES as u64
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{counter} never reached {LINES}; child logs:\n{}",
            proc.logs()
        );
        sleep(POLL_INTERVAL).await;
    }
    let out_dir = proc.dir().join("out");
    assert!(
        common::parquet_files(&out_dir).is_empty(),
        "a Parquet file existed before shutdown; only the drain may flush here"
    );

    // 12 s: just above the binary's own 10 s writer-flush deadline, so a connection task
    // that keeps the writer channel open (the bug) cannot pass by waiting out the deadline.
    let started = Instant::now();
    let status = proc.terminate(Duration::from_secs(12));
    // A connection task that ignores shutdown is only reaped by the listener's bounded
    // drain (several seconds); honouring shutdown makes the exit near-immediate.
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "shutdown took {:?}; the open connection task did not stop on shutdown:\n{}",
        started.elapsed(),
        proc.logs()
    );
    assert!(
        status.success(),
        "unclean exit: {status:?}\n{}",
        proc.logs()
    );

    // Deterministic evidence that the connection task itself saw the shutdown with the
    // half line still buffered (rather than being reaped by a deadline-driven abort).
    assert!(
        proc.logs().contains("dropped partial line"),
        "the connection task never reported the partial line at shutdown:\n{}",
        proc.logs()
    );

    let rows: usize = common::read_all(&out_dir)
        .iter()
        .map(|b| b.num_rows())
        .sum();
    assert_eq!(
        rows,
        LINES,
        "the {LINES} complete lines must be flushed, not the partial one:\n{}",
        proc.logs()
    );
    drop(conn);
}

#[tokio::test]
async fn sigterm_flushes_lines_from_idle_open_syslog_tcp_connection() {
    idle_tcp_connection_sigterm_case(
        "syslog",
        |i| format!("<134>Jan 15 10:30:45 host-e2e idle-tcp: record {i}\n"),
        "<134>Jan 15 10:30:45 host-e2e idle-tcp: par",
    )
    .await;
}

#[tokio::test]
async fn sigterm_flushes_lines_from_idle_open_zeek_tcp_connection() {
    idle_tcp_connection_sigterm_case(
        "zeek",
        |i| format!("{{\"_path\":\"conn\",\"uid\":\"C{i}\"}}\n"),
        "{\"_path\":\"conn\",\"ui",
    )
    .await;
}

/// A plain-HTTP HEC client that sent events and then idles on a kept-alive connection must not
/// stop SIGTERM from flushing: the server task is drained (closing idle connections and
/// dropping the HEC writer's senders) before the writers are awaited, so the writer sees
/// end-of-stream and flushes well inside its own 10 s deadline.
#[tokio::test]
async fn sigterm_flushes_hec_events_with_idle_keepalive_client() {
    const EVENTS: usize = 6;
    let toml = "bind_address = \"127.0.0.1:{HTTP}\"\n[tls]\nenabled = false\n\
                [syslog]\nenabled = false\n[metrics]\nenabled = false\n\
                [hec]\nenabled = true\ntoken = \"\"\n\
                [hec.local]\ndirectory = \"{DIR}/hec\"\nmax_buffer_rows = 100000\n\
                flush_interval_secs = 3600\n";
    let mut proc = common::Proc::spawn_healthy(env!("CARGO_BIN_EXE_logthing"), toml, &[]).await;

    // One client, one pooled keep-alive connection; it stays alive (idle) until the test ends.
    let client = reqwest::Client::new();
    let mut body = String::new();
    for i in 0..EVENTS {
        body.push_str(&format!("{{\"event\":{{\"n\":{i}}}}}\n"));
    }
    let resp = client
        .post(format!("{}/services/collector/event", proc.base()))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "logs:\n{}", proc.logs());
    let _ = resp.bytes().await.unwrap();

    let out_dir = proc.dir().join("hec");
    assert!(
        common::parquet_files(&out_dir).is_empty(),
        "a Parquet file existed before shutdown; only the drain may flush here"
    );

    let started = Instant::now();
    let status = proc.terminate(Duration::from_secs(12));
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "shutdown took {:?} with an idle keep-alive client:\n{}",
        started.elapsed(),
        proc.logs()
    );
    assert!(
        status.success(),
        "unclean exit: {status:?}\n{}",
        proc.logs()
    );

    let rows: usize = common::read_all(&out_dir)
        .iter()
        .map(|b| b.num_rows())
        .sum();
    assert_eq!(rows, EVENTS, "logs:\n{}", proc.logs());
    drop(client);
}
