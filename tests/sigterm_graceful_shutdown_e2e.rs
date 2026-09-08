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
            last = logthing::profiling::parse_counter(&body, "syslog_messages_received")
                .unwrap_or(0);
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
        before.iter().all(|p| p.extension().is_none_or(|e| e != "parquet")),
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
        let reader =
            parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)
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
