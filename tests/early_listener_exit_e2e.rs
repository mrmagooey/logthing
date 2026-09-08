//! End-to-end test: a listener task that exits early (e.g. a port bind
//! failure) must not crash the whole process during shutdown.
//!
//! Root cause: the H-3 supervision arm in `main.rs`'s top-level
//! `tokio::select!` polls `&mut` borrows of the listener `JoinHandle`s to
//! detect an early exit. When that arm wins, the graceful-shutdown drain
//! loop used to poll the SAME handles again, by value — and tokio panics
//! with "JoinHandle polled after completion" on a handle that has already
//! resolved. Before the fix, ANY listener failing to bind (a port
//! collision in production, not just a privileged port) turned one
//! recoverable listener failure into a whole-process panic that skipped
//! the entire buffered-writer flush.
//!
//! This test triggers the early exit deterministically and independent of
//! privileges: it binds and HOLDS a TCP listener on a port, then points
//! `[syslog] tcp_port` at that same port. The child's bind fails with
//! `AddrInUse` (not `EACCES`, so this reproduces identically whether or
//! not the test — or CI — runs as root), the syslog listener task returns
//! early, and the H-3 arm fires.

use std::fs::File;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::sleep;

const POLL_INTERVAL: Duration = Duration::from_millis(50);
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

#[tokio::test]
async fn early_listener_exit_does_not_panic_the_process() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Allocate all ports together so none can collide with each other,
    // except the syslog TCP one, which is held open for the whole test —
    // that's the deliberate bind conflict under test.
    // `SyslogListenerConfig::bind_address` is hardcoded to "0.0.0.0" in
    // `main.rs` regardless of what the toml says, so the held listener
    // must also bind 0.0.0.0 to guarantee the collision.
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let syslog_udp_probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let held_syslog_tcp = TcpListener::bind("0.0.0.0:0").await.unwrap();

    let http_port = http_listener.local_addr().unwrap().port();
    let syslog_udp_port = syslog_udp_probe.local_addr().unwrap().port();
    let syslog_tcp_port = held_syslog_tcp.local_addr().unwrap().port();

    // Release everything except the held TCP listener, which must stay
    // bound so the child collides with it.
    drop(http_listener);
    drop(syslog_udp_probe);

    let toml = format!(
        r#"
bind_address = "127.0.0.1:{http_port}"

[tls]
enabled = false

[syslog]
enabled = true
udp_port = {syslog_udp_port}
tcp_port = {syslog_tcp_port}
"#,
    );
    std::fs::write(tmp.path().join("logthing.toml"), toml).expect("write logthing.toml");

    // Redirect child output to files: a piped child can deadlock the parent
    // if its output buffer fills and nobody drains it.
    let stdout_log = File::create(tmp.path().join("stdout.log")).unwrap();
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

    // The bound-but-held TCP listener makes the child's syslog TCP bind
    // fail with AddrInUse almost immediately on startup — well before any
    // other part of the process (e.g. the metrics server) would become
    // reachable, so there is nothing to poll for readiness on. That failure
    // makes the syslog listener task return early, the H-3 supervision arm
    // in `main.rs` fires, and the graceful-shutdown sequence begins on its
    // own — no signal needed. The process should exit cleanly rather than
    // panicking.
    let exit_deadline = Instant::now() + EXIT_TIMEOUT;
    let exit_status = loop {
        match guard.0.try_wait().expect("try_wait") {
            Some(status) => break status,
            None => {
                if Instant::now() > exit_deadline {
                    panic!(
                        "child {pid} did not exit within {EXIT_TIMEOUT:?} of the \
                         syslog TCP bind failure — the H-3 supervision arm never \
                         fired or shutdown never completed"
                    );
                }
                sleep(POLL_INTERVAL).await;
            }
        }
    };

    // Keep the collision in place until the child has actually exited, so
    // it can't disappear out from under the test.
    drop(held_syslog_tcp);

    let stderr = std::fs::read_to_string(&stderr_path).expect("read stderr.log");

    // Load-bearing assertion: before the fix, this exact message appears
    // and the process dies mid-shutdown.
    assert!(
        !stderr.contains("JoinHandle polled after completion"),
        "child hit the double-poll panic — the H-3 arm's handle was awaited \
         a second time by the drain loop:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "child panicked during shutdown:\n{stderr}"
    );

    // A panic does not raise a signal, so this check alone would not catch
    // the bug — it rules out the signal being what actually ended the
    // child, so the stderr checks above are attributable to the real
    // shutdown path rather than to something else killing the process.
    assert!(
        exit_status.signal().is_none(),
        "child was terminated by signal {:?} instead of shutting down on its own",
        exit_status.signal()
    );
    assert!(
        exit_status.success(),
        "child exited uncleanly: {exit_status:?}\nstderr:\n{stderr}"
    );
}
