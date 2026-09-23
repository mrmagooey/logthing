//! End-to-end test: a real, compiled `logthing` process, starved of file
//! descriptors by a low `RLIMIT_NOFILE`, must not busy-spin its TCP accept
//! loop once it runs out of fds to `accept()` new connections with.
//!
//! `accept_backoff_emfile_integration.rs` proves the same property
//! in-process against `AcceptBackoff` directly. This test instead proves it
//! end to end: that `syslog/listener.rs`'s real accept sites (wired through
//! `main.rs`, inside a real `tokio::select!` alongside the UDP receive and
//! shutdown arms) actually use `AcceptBackoff`, and that a real process
//! genuinely stays near-idle instead of pegging a CPU core once fd
//! exhaustion hits. `main.rs` wiring a *different* accept path (e.g. a
//! future refactor bypassing `AcceptBackoff`) would compile and start
//! cleanly and only show up here.
//!
//! Only `[syslog]` (its TCP arm) and `[metrics]` are enabled — every other
//! listener defaults to disabled — to keep the fd budget this test manages
//! small and predictable.
//!
//! The spawned child needs its own `RLIMIT_NOFILE` lowered *after* fork but
//! *before* exec, so `Command::pre_exec` (async-signal-safe: only a single
//! `libc::setrlimit` call, no allocation) is used rather than setting the
//! limit in this test process itself (which would starve the test harness,
//! not just the child).

use std::fs::File;
use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::sleep;

/// The child's lowered `RLIMIT_NOFILE` soft/hard limit. Must be large enough
/// for the binary to boot (config read, syslog UDP+TCP binds, the HTTP
/// router bind, the metrics server bind, plus whatever transient fds
/// start-up needs) but small enough that a few hundred held TCP connections
/// exhausts it quickly. 256 was verified below (boot is checked explicitly
/// via `wait_for_tcp`/`wait_for_metrics`) to boot reliably on this machine;
/// `MAX_SYSLOG_TCP_CONNECTIONS` (1024, see `src/syslog/listener.rs`) is well
/// above it, so this limit -- not the connection semaphore -- is what stops
/// accepts.
const CHILD_FD_LIMIT: libc::rlim_t = 256;

/// Upper bound on how many client connections this test opens while probing
/// for fd exhaustion. Comfortably above `CHILD_FD_LIMIT` plus a typical
/// Linux listen backlog, so the loop either hits a real connect failure
/// (backlog also full) or is stopped by this cap -- either way the child
/// has long since run out of fds to `accept()` with.
const MAX_CONNECT_ATTEMPTS: usize = 1500;

const READY_TIMEOUT: Duration = Duration::from_secs(20);
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

struct Ports {
    http: u16,
    metrics: u16,
    syslog_udp: u16,
    syslog_tcp: u16,
}

async fn alloc_ports() -> Ports {
    let tcp_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_metrics = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_syslog = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp_syslog = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    Ports {
        http: tcp_http.local_addr().unwrap().port(),
        metrics: tcp_metrics.local_addr().unwrap().port(),
        syslog_tcp: tcp_syslog.local_addr().unwrap().port(),
        syslog_udp: udp_syslog.local_addr().unwrap().port(),
    }
    // All four sockets drop together here, releasing every port at once for
    // the child process to bind.
}

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

fn received_counter(rendered: &str, name: &str) -> Option<u64> {
    logthing::profiling::parse_counter(rendered, name)
}

/// Sum of `utime` + `stime` (fields 14 and 15, 1-indexed) from
/// `/proc/<pid>/stat`, in clock ticks. `comm` (field 2) is parenthesized and
/// may itself contain spaces or parentheses, so this splits on the *last*
/// `)` rather than assuming a fixed field position from the start of the
/// line -- every field from `state` (field 3) onward is then a simple
/// whitespace-separated tail.
fn read_cpu_ticks(pid: u32) -> u64 {
    let content =
        std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read /proc/<pid>/stat");
    let after_comm = content
        .rsplit_once(')')
        .expect("/proc/<pid>/stat must contain a parenthesized comm field")
        .1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // fields[0] is `state` (overall field 3); utime is overall field 14
    // (index 11 here), stime is overall field 15 (index 12).
    let utime: u64 = fields[11].parse().expect("utime field");
    let stime: u64 = fields[12].parse().expect("stime field");
    utime + stime
}

fn clock_ticks_per_sec() -> f64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    assert!(ticks > 0, "sysconf(_SC_CLK_TCK) returned {ticks}");
    ticks as f64
}

#[tokio::test]
async fn accept_backoff_keeps_a_fd_starved_listener_near_idle() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ports = alloc_ports().await;

    let toml = format!(
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
"#,
        http = ports.http,
        metrics = ports.metrics,
        syslog_udp = ports.syslog_udp,
        syslog_tcp = ports.syslog_tcp,
    );
    std::fs::write(tmp.path().join("logthing.toml"), toml).expect("write logthing.toml");

    let stdout_log = File::create(tmp.path().join("stdout.log")).unwrap();
    let stderr_log = File::create(tmp.path().join("stderr.log")).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_logthing"));
    cmd.current_dir(tmp.path())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log));
    // SAFETY: the closure only calls `libc::setrlimit`, which is
    // async-signal-safe and does not allocate -- the only two properties
    // `pre_exec`'s contract requires of code that runs between `fork` and
    // `exec` in the child.
    unsafe {
        cmd.pre_exec(|| {
            let rlimit = libc::rlimit {
                rlim_cur: CHILD_FD_LIMIT,
                rlim_max: CHILD_FD_LIMIT,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().expect("spawn logthing binary");
    let pid = child.id();
    let _guard = ChildGuard(child);

    let deadline = Instant::now() + READY_TIMEOUT;
    let metrics_url = format!("http://127.0.0.1:{}/metrics", ports.metrics);
    let metrics_client = reqwest::Client::new();

    // Prove the child actually booted under the lowered fd limit -- binds
    // its syslog TCP listener and serves /metrics -- before starving it
    // further. If CHILD_FD_LIMIT is too tight to boot, these time out.
    wait_for_metrics(&metrics_client, &metrics_url, deadline).await;
    wait_for_tcp(ports.syslog_tcp, deadline, "syslog TCP").await;

    // --- Open TCP connections until the process's fd budget is exhausted.
    // The kernel completes each handshake into its own accept backlog
    // regardless of whether the server has an fd free to `accept()` it
    // with, so `connect()` succeeding is not proof the server accepted --
    // it just guarantees the server's accept loop has plenty of pending
    // work to spin on once it does run out of fds.
    let syslog_addr: SocketAddr = format!("127.0.0.1:{}", ports.syslog_tcp).parse().unwrap();
    let mut held_connections: Vec<StdTcpStream> = Vec::new();
    for _ in 0..MAX_CONNECT_ATTEMPTS {
        match StdTcpStream::connect_timeout(&syslog_addr, Duration::from_millis(200)) {
            Ok(s) => held_connections.push(s),
            Err(_) => break, // backlog full too -- connects have stopped being accepted
        }
    }
    assert!(
        held_connections.len() > CHILD_FD_LIMIT as usize,
        "expected to open more connections ({}) than the child's fd limit ({}) -- otherwise fd \
         exhaustion was never actually reached",
        held_connections.len(),
        CHILD_FD_LIMIT
    );

    // Let the server finish draining whatever it could legitimately accept
    // out of the connect burst above -- each of the (up to fd-limit) accepts
    // that succeeded spawns a handling task, and on a loaded machine that
    // burst of real, useful work can still be running when the connect loop
    // above returns. That's not the spin this test is guarding against, so
    // rather than guess a fixed settle time, poll short CPU-usage windows
    // until they drop back down (bounded, so a genuine regression here — the
    // server never settling — still fails instead of hanging).
    let clk_tck = clock_ticks_per_sec();
    let settle_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let before = read_cpu_ticks(pid);
        let window_start = Instant::now();
        sleep(Duration::from_millis(300)).await;
        let window_elapsed = window_start.elapsed().as_secs_f64();
        let after = read_cpu_ticks(pid);
        let frac = (after - before) as f64 / clk_tck / window_elapsed;
        if frac < 0.5 {
            break;
        }
        assert!(
            Instant::now() < settle_deadline,
            "server never finished draining the connect burst (still {:.0}% CPU) within 5s",
            frac * 100.0
        );
    }

    // --- Sample the child's CPU usage over a 2s window while it's starved.
    // Before the fix this is ~100% (a busy accept spin); with AcceptBackoff
    // pausing between accept errors, it must stay well below one full core.
    let ticks_before = read_cpu_ticks(pid);
    let wall_start = Instant::now();
    sleep(Duration::from_secs(2)).await;
    let wall_elapsed = wall_start.elapsed().as_secs_f64();
    let ticks_after = read_cpu_ticks(pid);

    let cpu_seconds = (ticks_after - ticks_before) as f64 / clk_tck;
    let cpu_fraction = cpu_seconds / wall_elapsed;
    assert!(
        cpu_fraction < 0.25,
        "expected the fd-starved listener to use < 25% CPU over {wall_elapsed:.2}s, used \
         {cpu_fraction:.2} ({cpu_seconds:.2} CPU-seconds) -- a busy accept spin looks like \
         ~100% here"
    );

    // --- Free the held connections and confirm the listener actually
    // recovers: a fresh connection is accepted and a syslog line sent over
    // it is processed (`syslog_messages_received` increases) within 5s.
    let before = {
        let rendered = metrics_client
            .get(&metrics_url)
            .send()
            .await
            .expect("scrape metrics")
            .text()
            .await
            .expect("read metrics body");
        received_counter(&rendered, "syslog_messages_received").unwrap_or(0)
    };
    drop(held_connections);

    let recovery_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", ports.syslog_tcp)).await {
            use tokio::io::AsyncWriteExt;
            let _ = stream.write_all(b"<134>e2e recovery syslog tcp\n").await;
        }
        let rendered = metrics_client
            .get(&metrics_url)
            .send()
            .await
            .expect("scrape metrics")
            .text()
            .await
            .expect("read metrics body");
        let now = received_counter(&rendered, "syslog_messages_received").unwrap_or(0);
        if now > before {
            break;
        }
        if Instant::now() > recovery_deadline {
            panic!(
                "listener did not recover and process a fresh syslog line within 5s of fds \
                 being freed; syslog_messages_received stayed at {before}"
            );
        }
        sleep(POLL_INTERVAL).await;
    }
}
