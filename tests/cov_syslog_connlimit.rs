//! Syslog TCP connection-limit rejection, for every accept path.
//!
//! `MAX_SYSLOG_TCP_CONNECTIONS` is a `const` (1024) with no config knob, so the only way to
//! reach the "limit reached" branch is to really hold 1024 connections and open one more.
//! That is about 2050 fds per variant, so this lives in its own test binary (no interference
//! with sleep-based unit tests) and runs its variants strictly one after another.
//! Each accept path has its own copy of the rejection code: the inline single-recv and
//! batched-recv loops of `start_with_shutdown`, the fan-out accept loop, and `start()`'s
//! `run_with_listener`.

use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{
    MAX_SYSLOG_TCP_CONNECTIONS, SyslogHandler, SyslogListener, SyslogListenerConfig,
};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

struct NullHandler;

#[async_trait::async_trait]
impl SyslogHandler for NullHandler {
    async fn handle_message(&self, _message: SyslogMessage, _source: SocketAddr) {}
}

/// Panics with a clear message unless the soft RLIMIT_NOFILE can hold both ends of 1025
/// loopback connections plus overhead.
fn require_fd_limit() {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit struct.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    assert_eq!(rc, 0, "getrlimit(RLIMIT_NOFILE) failed");
    assert!(
        lim.rlim_cur >= 2200,
        "this test holds ~2050 sockets: soft RLIMIT_NOFILE is {} - run with `ulimit -n 4096`",
        lim.rlim_cur
    );
}

fn rejected(snap: &Snapshotter) -> u64 {
    snap.snapshot()
        .into_vec()
        .into_iter()
        .filter(|(ck, _, _, _)| ck.key().name() == "syslog_tcp_connections_rejected")
        .map(|(_, _, _, v)| match v {
            DebugValue::Counter(c) => c,
            _ => 0,
        })
        .sum()
}

async fn connect(addr: SocketAddr) -> TcpStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(s) => return s,
            Err(e) => {
                assert!(std::time::Instant::now() < deadline, "connect failed: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

/// Fill the semaphore, then one more connection must be closed by the server and counted.
async fn assert_limit_enforced(addr: SocketAddr, snap: &Snapshotter) -> Vec<TcpStream> {
    let mut held = Vec::with_capacity(MAX_SYSLOG_TCP_CONNECTIONS);
    for _ in 0..MAX_SYSLOG_TCP_CONNECTIONS {
        held.push(connect(addr).await);
    }
    // Accepts are sequential, so the extra connection is processed after all 1024 permits
    // are taken.
    let mut extra = connect(addr).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while rejected(snap) < 1 {
        assert!(std::time::Instant::now() < deadline, "no rejection counted");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut sink = Vec::new();
    // A read error (e.g. RST) also means the server dropped the socket, so treat it as a close.
    let n = tokio::time::timeout(Duration::from_secs(5), extra.read_to_end(&mut sink))
        .await
        .expect("rejected connection must be closed by the server")
        .unwrap_or(0);
    assert_eq!(n, 0);
    assert_eq!(rejected(snap), 1, "exactly the one over-limit connection");
    held
}

async fn free_ports() -> (u16, u16) {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    (
        udp.local_addr().unwrap().port(),
        tcp.local_addr().unwrap().port(),
    )
}

fn config(udp_port: u16, tcp_port: u16, recv_tasks: usize, batch: usize) -> SyslogListenerConfig {
    SyslogListenerConfig {
        udp_port,
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
        recv_tasks,
        recv_batch_size: batch,
        ..SyslogListenerConfig::default()
    }
}

async fn shutdown_variant(recv_tasks: usize, batch: usize) {
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let (udp, tcp) = free_ports().await;
    let listener = SyslogListener::new(config(udp, tcp, recv_tasks, batch), Arc::new(NullHandler));
    let (tx, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { listener.start_with_shutdown(rx).await });
    let held = assert_limit_enforced(format!("127.0.0.1:{tcp}").parse().unwrap(), &snap).await;
    drop(held);
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("listener must stop after shutdown")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_tcp_connection_limit_rejects_extra_connection_on_every_accept_path() {
    require_fd_limit();
    // Inline loop, single-recv_from UDP arm.
    shutdown_variant(1, 1).await;
    // Inline loop, batched UDP arm.
    shutdown_variant(1, 32).await;
    // Fan-out accept loop (recv_tasks > 1; the batch size does not affect TCP).
    shutdown_variant(4, 1).await;

    // `start()` -> run_with_listener (no shutdown signal).
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let (udp, tcp) = free_ports().await;
    let listener = SyslogListener::new(config(udp, tcp, 1, 1), Arc::new(NullHandler));
    let task = tokio::spawn(async move {
        listener.start().await.ok();
    });
    let held = assert_limit_enforced(format!("127.0.0.1:{tcp}").parse().unwrap(), &snap).await;
    drop(held);
    task.abort();
}
