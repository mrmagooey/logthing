//! End-to-end: `src/main.rs` startup, failure and shutdown paths through the real binary.
//!
//! Covers what the happy-path binary tests do not: fatal startup errors (bad
//! `WEF_WORKER_THREADS`, unusable spool directory, HTTP port already taken), a listener that
//! cannot bind (each of the five wire-protocol sources), a local sink that cannot be created
//! (the source falls back to its default handler and aggregation is switched off), the
//! single-target and non-targeted-aggregation handler wiring, the insecure-config warning with
//! the pretty log format, the 10 s writer-flush deadline, and the spool drain at shutdown.
//!
//! Every child is stopped with SIGTERM (or exits by itself) so its coverage data is written.

mod common;

use common::{Proc, fake_s3::FakeS3};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_logthing");
const ENVS: [(&str, &str); 1] = [("AWS_MAX_ATTEMPTS", "1")];

/// Outcome of a run-to-exit: status plus both captured streams.
struct Exited {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

/// Run the binary with `toml` as `./logthing.toml` and wait (max 30 s) for it to exit by itself.
fn run_until_exit(toml: &str, envs: &[(&str, &str)]) -> Exited {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("logthing.toml"), toml).unwrap();
    let out = dir.path().join("stdout.log");
    let err = dir.path().join("stderr.log");
    let mut cmd = Command::new(BIN);
    cmd.current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::fs::File::create(&out).unwrap()))
        .stderr(Stdio::from(std::fs::File::create(&err).unwrap()));
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn logthing");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "logthing did not exit; stdout:\n{}\nstderr:\n{}",
                std::fs::read_to_string(&out).unwrap_or_default(),
                std::fs::read_to_string(&err).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Exited {
        status,
        stdout: std::fs::read_to_string(&out).unwrap_or_default(),
        stderr: std::fs::read_to_string(&err).unwrap_or_default(),
    }
}

/// A regular file at `<tmp>/blocker`; any path below it cannot be created as a directory.
fn blocker() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("blocker");
    std::fs::write(&file, b"not a directory").unwrap();
    let under = file.join("sub").display().to_string();
    (dir, under)
}

#[test]
fn test_invalid_worker_threads_env_is_a_fatal_startup_error() {
    let r = run_until_exit("", &[("WEF_WORKER_THREADS", "zero-ish")]);
    assert_eq!(r.status.code(), Some(1), "stderr: {}", r.stderr);
    assert!(
        r.stderr
            .contains("WEF_WORKER_THREADS must be a positive integer"),
        "stderr was: {}",
        r.stderr
    );
}

#[test]
fn test_unusable_spool_directory_stops_startup() {
    let (_guard, under) = blocker();
    let toml = format!(
        "bind_address = \"127.0.0.1:{}\"\n[tls]\nenabled = false\n[syslog]\nenabled = false\n\
         [spool]\ndir = \"{under}\"\n",
        common::free_port()
    );
    let r = run_until_exit(&toml, &[]);
    assert_eq!(r.status.code(), Some(1), "stdout: {}", r.stdout);
    assert!(
        r.stderr.contains("opening spool at"),
        "stderr: {}",
        r.stderr
    );
}

#[test]
fn test_invalid_profile_activity_metric_warns_and_startup_continues() {
    let (_guard, under) = blocker();
    let toml = format!(
        "bind_address = \"127.0.0.1:{}\"\n[tls]\nenabled = false\n[syslog]\nenabled = false\n\
         [spool]\ndir = \"{under}\"\n",
        common::free_port()
    );
    let prof = tempfile::tempdir().unwrap();
    let r = run_until_exit(
        &toml,
        &[
            ("LOGTHING_PROFILE_SECS", "1"),
            ("LOGTHING_PROFILE_DIR", prof.path().to_str().unwrap()),
            ("LOGTHING_PROFILE_ACTIVITY_METRIC", "bad-name"),
        ],
    );
    let all = format!("{}{}", r.stdout, r.stderr);
    // Startup got past the profiling hook and failed later, at the (unusable) spool.
    assert!(all.contains("opening spool at"), "{all}");
    assert!(
        all.contains("LOGTHING_PROFILE_ACTIVITY_METRIC is not a valid metric name"),
        "{all}"
    );
    #[cfg(not(feature = "pprof"))]
    assert!(all.contains("built without the `pprof` feature"), "{all}");
}

#[test]
fn test_http_port_already_taken_fails_with_a_nonzero_exit() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port();
    let toml = format!(
        "bind_address = \"127.0.0.1:{port}\"\n[tls]\nenabled = false\n[syslog]\nenabled = false\n"
    );
    let r = run_until_exit(&toml, &[]);
    assert_eq!(r.status.code(), Some(1), "stdout: {}", r.stdout);
    let all = format!("{}{}", r.stdout, r.stderr);
    assert!(
        all.to_lowercase().contains("address already in use"),
        "expected an AddrInUse failure, got:\n{all}"
    );
}

/// Config enabling only `source` on a port that something else already holds.
fn listener_toml(source: &str, port: u16) -> String {
    let body = match source {
        "syslog" => {
            let udp = common::free_port();
            format!("[syslog]\nenabled = true\nudp_port = {udp}\ntcp_port = {port}\n")
        }
        "zeek" | "suricata" => {
            format!("[{source}]\nenabled = true\ntcp_port = {port}\nbind_address = \"127.0.0.1\"\n")
        }
        _ => {
            format!("[{source}]\nenabled = true\nudp_port = {port}\nbind_address = \"127.0.0.1\"\n")
        }
    };
    let off = if source == "syslog" {
        ""
    } else {
        "[syslog]\nenabled = false\n"
    };
    format!(
        "bind_address = \"127.0.0.1:{}\"\n[tls]\nenabled = false\n{off}{body}",
        common::free_port()
    )
}

#[test]
fn test_listener_that_cannot_bind_fails_the_process_for_every_source() {
    let sources = [
        ("syslog", "Syslog listener error"),
        ("ipfix", "IPFIX listener error"),
        ("zeek", "Zeek listener error"),
        ("suricata", "Suricata listener error"),
        ("sflow", "sFlow listener error"),
    ];
    for (source, marker) in sources {
        let tcp = matches!(source, "syslog" | "zeek" | "suricata");
        // Hold the port on every address the listener may use (syslog binds 0.0.0.0). The UDP
        // holder is a plain socket on purpose: the UDP listeners bind with SO_REUSEPORT, which
        // Linux only lets sockets share when ALL of them set it, so the bind fails with
        // EADDRINUSE. Making the holder reuseport too would silently break this test.
        let (_tcp_hold, _udp_hold, port);
        if tcp {
            let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
            port = l.local_addr().unwrap().port();
            _tcp_hold = Some(l);
            _udp_hold = None;
        } else {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            port = s.local_addr().unwrap().port();
            _udp_hold = Some(s);
            _tcp_hold = None;
        }
        let r = run_until_exit(&listener_toml(source, port), &[]);
        assert_eq!(r.status.code(), Some(1), "{source}: stdout: {}", r.stdout);
        assert!(
            r.stdout.contains(marker),
            "{source}: missing {marker:?} in:\n{}",
            r.stdout
        );
        assert!(
            r.stderr.contains("listener exited unexpectedly"),
            "{source}: stderr: {}",
            r.stderr
        );
    }
}

#[tokio::test]
async fn test_unusable_local_sinks_fall_back_to_defaults_and_disable_aggregation() {
    let (_guard, under) = blocker();
    let toml = format!(
        r#"
bind_address = "127.0.0.1:{{HTTP}}"
[tls]
enabled = false
[iceberg.local]
directory = "{under}/desc"
[syslog]
enabled = true
udp_port = {su}
tcp_port = {st}
parse_payloads = true
[syslog.local]
directory = "{under}/syslog"
[zeek]
enabled = true
tcp_port = {z}
bind_address = "127.0.0.1"
[zeek.local]
directory = "{under}/zeek"
[suricata]
enabled = true
tcp_port = {s}
bind_address = "127.0.0.1"
[suricata.local]
directory = "{under}/suricata"
[ipfix]
enabled = true
udp_port = {i}
bind_address = "127.0.0.1"
[ipfix.local]
directory = "{under}/ipfix"
[sflow]
enabled = true
udp_port = {f}
bind_address = "127.0.0.1"
[sflow.local]
directory = "{under}/sflow"
[aggregate]
enabled = true
[aggregate.local]
directory = "{under}/agg"
[[aggregate.rules]]
name = "r"
source = "zeek"
group_by = ["query"]
"#,
        su = common::free_port(),
        st = common::free_port(),
        z = common::free_port(),
        s = common::free_port(),
        i = common::free_port(),
        f = common::free_port(),
    );
    let mut p = Proc::spawn_healthy(BIN, &toml, &[]).await;
    let st = p.terminate(Duration::from_secs(30));
    assert!(
        st.success(),
        "graceful exit expected, got {st}:\n{}",
        p.logs()
    );
    let logs = p.logs();
    for expected in [
        "Failed to construct Iceberg descriptor sink, descriptors disabled",
        "Failed to create LocalDiskSink for aggregation",
        "Failed to create LocalDiskSink for syslog persistence",
        "Failed to create LocalDiskSink for Zeek persistence",
        "Failed to create LocalDiskSink for Suricata persistence",
        "Failed to create LocalDiskSink for IPFIX persistence",
        "Failed to create LocalDiskSink for sFlow persistence",
        "Aggregation is configured with 1 rule(s) but no destination could be created",
    ] {
        assert!(logs.contains(expected), "missing {expected:?} in:\n{logs}");
    }
    assert!(
        !logs.contains("Aggregation enabled"),
        "aggregation must stay off:\n{logs}"
    );
}

#[tokio::test]
async fn test_single_local_targets_and_untargeted_sources_with_pretty_logs() {
    // One local target per source (the single-handler arm), one aggregation rule that only
    // targets zeek (every other source keeps its undecorated handler), default pretty logs,
    // and an empty-token HEC so the insecure-config warning fires.
    let toml = format!(
        r#"
bind_address = "127.0.0.1:{{HTTP}}"
[tls]
enabled = false
[hec]
enabled = true
token = ""
[hec.local]
directory = "{{DIR}}/hec"
[syslog]
enabled = true
udp_port = {su}
tcp_port = {st}
[syslog.local]
directory = "{{DIR}}/syslog"
[zeek]
enabled = true
tcp_port = {z}
bind_address = "127.0.0.1"
[zeek.local]
directory = "{{DIR}}/zeek"
[suricata]
enabled = true
tcp_port = {s}
bind_address = "127.0.0.1"
[suricata.local]
directory = "{{DIR}}/suricata"
[ipfix]
enabled = true
udp_port = {i}
bind_address = "127.0.0.1"
[ipfix.local]
directory = "{{DIR}}/ipfix"
[sflow]
enabled = true
udp_port = {f}
bind_address = "127.0.0.1"
[sflow.local]
directory = "{{DIR}}/sflow"
[aggregate]
enabled = true
flush_interval_secs = 1
[aggregate.local]
directory = "{{DIR}}/agg"
[[aggregate.rules]]
name = "zeek_dns"
source = "zeek"
group_by = ["query"]
"#,
        su = common::free_port(),
        st = common::free_port(),
        z = common::free_port(),
        s = common::free_port(),
        i = common::free_port(),
        f = common::free_port(),
    );
    let mut p = Proc::spawn_healthy(BIN, &toml, &[]).await;
    let st = p.terminate(Duration::from_secs(30));
    assert!(
        st.success(),
        "graceful exit expected, got {st}:\n{}",
        p.logs()
    );
    let logs = p.logs();
    assert!(
        logs.contains("hec.enabled = true but hec.token is empty"),
        "missing insecure-config warning:\n{logs}"
    );
    assert!(
        logs.contains("Aggregation enabled: 1 rule(s), 1s window"),
        "{logs}"
    );
    // Pretty format is multi-line (`field: value` on indented lines), unlike JSON.
    let stdout = std::fs::read_to_string(p.dir().join("stdout.log")).unwrap();
    assert!(
        !stdout.lines().any(|l| l.starts_with('{')),
        "pretty format must not emit JSON objects:\n{stdout}"
    );
}

fn hec_s3_toml(endpoint: &str, metrics_port: u16, extra: &str) -> String {
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
max_buffer_rows = 100000
flush_threshold_bytes = 100000000
flush_interval_secs = 3600
{extra}
"#
    )
}

async fn post_hec_event(p: &Proc) {
    let resp = reqwest::Client::new()
        .post(format!("{}/services/collector/event", p.base()))
        .header("Authorization", "Splunk tok")
        .json(&serde_json::json!({"sourcetype": "app", "event": {"n": 1}}))
        .send()
        .await
        .expect("post event");
    assert_eq!(resp.status(), 200);
}

fn spool_has(dir: &Path, ext: &str) -> bool {
    std::fs::read_dir(dir.join("spool"))
        .map(|rd| {
            rd.flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(ext))
        })
        .unwrap_or(false)
}

#[tokio::test]
async fn test_spool_left_undrained_at_shutdown_is_warned_about_and_kept() {
    let fake = FakeS3::start().await;
    fake.set_failing(true);
    let toml = hec_s3_toml(
        &fake.endpoint(),
        common::free_port(),
        "[spool]\ndir = \"{DIR}/spool\"\nmax_bytes = 104857600\n",
    );
    let mut p = Proc::spawn_healthy(BIN, &toml, &ENVS).await;
    post_hec_event(&p).await;
    let st = p.terminate(Duration::from_secs(40));
    assert!(
        st.success(),
        "graceful exit expected, got {st}:\n{}",
        p.logs()
    );
    assert_eq!(fake.put_count(), 0, "S3 was down for the whole run");
    let logs = p.logs();
    assert!(
        logs.contains("spool not fully drained at shutdown; replays on next start"),
        "missing drain warning:\n{logs}"
    );
    assert!(
        spool_has(p.dir(), ".parquet"),
        "spooled entry must be kept for replay"
    );
}

#[tokio::test]
async fn test_writer_flush_that_hangs_hits_the_ten_second_deadline() {
    // An S3 endpoint that accepts connections and never answers: the shutdown flush hangs.
    let black_hole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", black_hole.local_addr().unwrap());
    let holder = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = black_hole.accept().await {
            held.push(s);
        }
    });
    let toml = hec_s3_toml(&endpoint, common::free_port(), "");
    let mut p = Proc::spawn_healthy(BIN, &toml, &ENVS).await;
    post_hec_event(&p).await;
    let started = Instant::now();
    let st = p.terminate(Duration::from_secs(60));
    let elapsed = started.elapsed();
    holder.abort();
    assert!(
        st.success(),
        "graceful exit expected, got {st}:\n{}",
        p.logs()
    );
    assert!(
        elapsed >= Duration::from_secs(9),
        "returned too fast: {elapsed:?}"
    );
    let logs = p.logs();
    assert!(
        logs.contains("S3 writer flush timed out after 10s"),
        "missing flush-timeout warning:\n{logs}"
    );
    assert!(logs.contains("Shutdown complete"), "{logs}");
}
