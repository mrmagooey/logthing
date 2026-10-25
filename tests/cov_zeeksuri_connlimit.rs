//! Zeek and Suricata TCP connection-limit rejection, for both accept paths.
//!
//! `MAX_*_TCP_CONNECTIONS` are `const`s (1024) with no config knob, so the only way to reach
//! the "limit reached" branches is to really hold 1024 connections and open one more (~2050
//! fds per variant, ~1025 live connections). Own test binary; variants run strictly in turn.

use logthing::suricata::SuricataRecord;
use logthing::suricata::listener::{
    MAX_SURICATA_TCP_CONNECTIONS, SuricataHandler, SuricataListener, SuricataListenerConfig,
};
use logthing::zeek::ZeekRecord;
use logthing::zeek::listener::{
    MAX_ZEEK_TCP_CONNECTIONS, ZeekHandler, ZeekListener, ZeekListenerConfig,
};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

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

fn rejected(snap: &Snapshotter, name: &str) -> u64 {
    snap.snapshot()
        .into_vec()
        .into_iter()
        .filter(|(ck, _, _, _)| ck.key().name() == name)
        .map(|(_, _, _, v)| match v {
            DebugValue::Counter(c) => c,
            _ => 0,
        })
        .sum()
}

async fn connect<T>(addr: SocketAddr, task: &tokio::task::JoinHandle<T>) -> TcpStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        match TcpStream::connect(addr).await {
            Ok(s) => return s,
            Err(e) => {
                assert!(
                    !task.is_finished(),
                    "listener task exited early (lost the free-port race?): {e}"
                );
                assert!(std::time::Instant::now() < deadline, "connect failed: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

/// Fill the semaphore with `limit` connections, then one more must be closed by the server and
/// counted under `metric`.
async fn assert_limit_enforced<T>(
    addr: SocketAddr,
    snap: &Snapshotter,
    task: &tokio::task::JoinHandle<T>,
    limit: usize,
    metric: &str,
) -> Vec<TcpStream> {
    let mut held = Vec::with_capacity(limit);
    for _ in 0..limit {
        held.push(connect(addr, task).await);
    }
    // Accepts are sequential, so the extra connection is processed after all permits are taken.
    let mut extra = connect(addr, task).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while rejected(snap, metric) < 1 {
        assert!(std::time::Instant::now() < deadline, "no rejection counted");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut sink = Vec::new();
    // A read error (e.g. RST) also means the server dropped the socket, so treat it as a close.
    let n = tokio::time::timeout(Duration::from_secs(15), extra.read_to_end(&mut sink))
        .await
        .expect("rejected connection must be closed by the server")
        .unwrap_or(0);
    assert_eq!(n, 0);
    assert_eq!(
        rejected(snap, metric),
        1,
        "exactly the one over-limit connection"
    );
    held
}

async fn free_port() -> u16 {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    tcp.local_addr().unwrap().port()
}

struct ZeekNull;

#[async_trait::async_trait]
impl ZeekHandler for ZeekNull {
    async fn handle_record(&self, _record: ZeekRecord, _source: SocketAddr) {}
}

fn zeek_config(tcp_port: u16) -> ZeekListenerConfig {
    ZeekListenerConfig {
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
    }
}

async fn zeek_both_paths() {
    let metric = "zeek_tcp_connections_rejected";
    // `start_with_shutdown` inline accept loop.
    {
        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let port = free_port().await;
        let listener = ZeekListener::new(zeek_config(port), Arc::new(ZeekNull));
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(rx).await });
        let addr = format!("127.0.0.1:{port}").parse().unwrap();
        let held =
            assert_limit_enforced(addr, &snap, &task, MAX_ZEEK_TCP_CONNECTIONS, metric).await;
        drop(held);
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("listener must stop after shutdown")
            .unwrap()
            .unwrap();
    }
    // `start()` -> run_with_listener (no shutdown signal).
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let port = free_port().await;
    let listener = ZeekListener::new(zeek_config(port), Arc::new(ZeekNull));
    let task = tokio::spawn(async move {
        listener.start().await.ok();
    });
    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    let held = assert_limit_enforced(addr, &snap, &task, MAX_ZEEK_TCP_CONNECTIONS, metric).await;
    drop(held);
    task.abort();
}

struct SuricataNull;

#[async_trait::async_trait]
impl SuricataHandler for SuricataNull {
    async fn handle_record(&self, _record: SuricataRecord, _source: SocketAddr) {}
}

fn suricata_config(tcp_port: u16) -> SuricataListenerConfig {
    SuricataListenerConfig {
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
    }
}

async fn suricata_both_paths() {
    let metric = "suricata_tcp_connections_rejected";
    // `start_with_shutdown` inline accept loop.
    {
        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let port = free_port().await;
        let listener = SuricataListener::new(suricata_config(port), Arc::new(SuricataNull));
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { listener.start_with_shutdown(rx).await });
        let addr = format!("127.0.0.1:{port}").parse().unwrap();
        let held =
            assert_limit_enforced(addr, &snap, &task, MAX_SURICATA_TCP_CONNECTIONS, metric).await;
        drop(held);
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("listener must stop after shutdown")
            .unwrap()
            .unwrap();
    }
    // `start()` -> run_with_listener (no shutdown signal).
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let port = free_port().await;
    let listener = SuricataListener::new(suricata_config(port), Arc::new(SuricataNull));
    let task = tokio::spawn(async move {
        listener.start().await.ok();
    });
    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    let held =
        assert_limit_enforced(addr, &snap, &task, MAX_SURICATA_TCP_CONNECTIONS, metric).await;
    drop(held);
    task.abort();
}

#[tokio::test]
async fn test_tcp_connection_limit_rejects_extra_connection_zeek_and_suricata() {
    require_fd_limit();
    zeek_both_paths().await;
    suricata_both_paths().await;
}
