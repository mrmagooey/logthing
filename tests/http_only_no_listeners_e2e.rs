//! End-to-end test: a real `logthing` process with ONLY HTTP ingest enabled
//! (HEC, no syslog/IPFIX/Zeek/Suricata/sFlow listener) must stay up and keep
//! serving, not exit seconds after startup.
//!
//! Root cause: `listener_handles` (the wire-protocol listener JoinHandles) is
//! empty for this deployment shape. The H-3 supervision arm in `main.rs`'s
//! top-level `tokio::select!` polled `FuturesUnordered::next()` on that empty
//! set, which resolves immediately with `None` — so the arm won on the very
//! first poll and the process fell straight through into the graceful
//! shutdown sequence, with no error logged. A legitimate HTTP-only collector
//! configuration was completely broken.
//!
//! This test spawns the real binary with only `[hec]` enabled, confirms it is
//! still running well past the old bug's near-instant exit, proves ingest
//! actually works end to end (`POST /services/collector/event` +
//! `hec_events_received` on `/metrics`), then confirms SIGTERM still shuts it
//! down cleanly. See tests/sigterm_graceful_shutdown_e2e.rs and
//! tests/early_listener_exit_e2e.rs for the sibling scenarios this harness
//! shape is shared with.

use std::fs::File;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::time::sleep;

const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Long enough to prove this isn't just a slow success on the old buggy
/// binary — before the fix the process was gone within milliseconds.
const STILL_RUNNING_WINDOW: Duration = Duration::from_secs(5);
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Kills and reaps the child on drop — including during a panicking
/// assertion — so a failing test never leaves an orphaned daemon.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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

#[tokio::test]
async fn http_only_deployment_stays_up_and_serves_hec() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let (http_port, metrics_port) = {
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let metrics = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        (
            http.local_addr().unwrap().port(),
            metrics.local_addr().unwrap().port(),
        )
    };

    // No [syslog]/[ipfix]/[zeek]/[suricata]/[sflow] sections at all — every
    // one of those defaults to disabled except syslog, which is explicitly
    // turned off here so `listener_handles` really is empty. Only [hec] is
    // enabled, the deployment shape this bug broke.
    let toml = format!(
        r#"
bind_address = "127.0.0.1:{http_port}"

[tls]
enabled = false

[metrics]
enabled = true
port = {metrics_port}

[syslog]
enabled = false

[hec]
enabled = true
token = "e2e-token"
"#,
    );
    std::fs::write(tmp.path().join("logthing.toml"), toml).expect("write logthing.toml");

    // Redirect child output to files: a piped child can deadlock the parent
    // if its output buffer fills and nobody drains it.
    let stdout_path = tmp.path().join("stdout.log");
    let stdout_log = File::create(&stdout_path).unwrap();
    let stderr_path = tmp.path().join("stderr.log");
    let stderr_log = File::create(&stderr_path).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_logthing"))
        .current_dir(tmp.path())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .spawn()
        .expect("spawn logthing binary");
    let pid = child.id();
    let mut guard = ChildGuard(child);

    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let ready_deadline = Instant::now() + Duration::from_secs(20);
    wait_for_metrics(&metrics_url, ready_deadline).await;

    // Assertion 1: still running well past the old bug's near-instant exit.
    sleep(STILL_RUNNING_WINDOW).await;
    assert!(
        guard.0.try_wait().expect("try_wait").is_none(),
        "child exited within {STILL_RUNNING_WINDOW:?} of startup with only HEC \
         enabled and no wire-protocol listeners — the empty-listener-handles \
         bug regressed. stdout:\n{}\nstderr:\n{}",
        std::fs::read_to_string(&stdout_path).unwrap_or_default(),
        std::fs::read_to_string(&stderr_path).unwrap_or_default(),
    );

    // Assertion 2: it actually serves HTTP ingest — a real POST to the real
    // HEC endpoint, then the real /metrics counter.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "http://127.0.0.1:{http_port}/services/collector/event"
        ))
        .header("Authorization", "Splunk e2e-token")
        .json(&serde_json::json!({
            "event": {"msg": "http-only e2e"},
            "sourcetype": "e2e_test",
        }))
        .send()
        .await
        .expect("POST to HEC endpoint must succeed while the server is up");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let metrics_body = reqwest::get(&metrics_url)
        .await
        .expect("GET /metrics must succeed")
        .text()
        .await
        .expect("metrics body must be readable");
    let received =
        logthing::profiling::parse_counter(&metrics_body, "hec_events_received").unwrap_or(0);
    assert!(
        received >= 1,
        "hec_events_received should be >= 1 after one POST, got {received}"
    );

    // Assertion 3: SIGTERM still shuts it down cleanly rather than needing a
    // kill -9 (which is what an infinitely-hung select! would otherwise need).
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("run kill(1)");
    assert!(status.success(), "kill -TERM {pid} failed");

    let exit_deadline = Instant::now() + EXIT_TIMEOUT;
    let exit_status = loop {
        match guard.0.try_wait().expect("try_wait") {
            Some(status) => break status,
            None => {
                if Instant::now() > exit_deadline {
                    panic!("child {pid} did not exit within {EXIT_TIMEOUT:?} of SIGTERM");
                }
                sleep(POLL_INTERVAL).await;
            }
        }
    };

    assert!(
        exit_status.signal().is_none(),
        "child was terminated by signal {:?} instead of shutting down gracefully",
        exit_status.signal()
    );
    assert!(
        exit_status.success(),
        "child exited uncleanly: {exit_status:?}"
    );
}
