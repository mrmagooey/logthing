//! Integration test: a Zeek TCP connection held open (idle) at shutdown must not keep the
//! writer's channel open. The listener stops its connection task, which dispatches the
//! complete lines it already read and drops its handler, so the real `BufferedWriter`
//! flushes everything to local disk without waiting for the client to hang up.

mod common;

use logthing::config::ZeekLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::zeek_s3::{MultiZeekHandler, zeek_local_start};
use logthing::zeek::listener::{ZeekHandler, ZeekListener, ZeekListenerConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const LINES: usize = 5;

fn conn_line(uid: &str) -> String {
    format!("{{\"_path\":\"conn\",\"ts\":1700000000.0,\"uid\":\"{uid}\",\"proto\":\"tcp\"}}\n")
}

async fn run_case(drop_sender_instead_of_signalling: bool) {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let zeek_port = probe.local_addr().unwrap().port();
    drop(probe);

    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    // Neither the row threshold nor the age ticker can fire: only the shutdown flush writes.
    let cfg = ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 100_000,
        flush_threshold_bytes: 100_000_000,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };
    let (zeek_handler, writer_task) = zeek_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );
    let handler: Arc<dyn ZeekHandler> = Arc::new(MultiZeekHandler(vec![Arc::new(zeek_handler)]));

    let listener = ZeekListener::new(
        ZeekListenerConfig {
            tcp_port: zeek_port,
            bind_address: "127.0.0.1".to_string(),
        },
        handler.clone(),
    );
    let (tx, rx) = tokio::sync::watch::channel(false);
    let listener_task = tokio::spawn(async move {
        listener
            .start_with_shutdown(rx)
            .await
            .expect("listener run");
    });

    let mut conn = None;
    for _ in 0..50 {
        match TcpStream::connect(("127.0.0.1", zeek_port)).await {
            Ok(s) => {
                conn = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let mut conn = conn.expect("zeek listener did not accept in time");
    for i in 0..LINES {
        conn.write_all(conn_line(&format!("C{i}")).as_bytes())
            .await
            .unwrap();
    }
    // Half a line, then stay connected and idle.
    conn.write_all(b"{\"_path\":\"conn\",\"ui").await.unwrap();
    conn.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The caller's own handler reference goes away first (as in the real shutdown
    // sequence); only the listener and its connection task can keep the channel open.
    drop(handler);

    let started = Instant::now();
    if drop_sender_instead_of_signalling {
        drop(tx);
    } else {
        tx.send(true).unwrap();
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        listener_task.await.expect("listener task");
        writer_task.await.expect("writer task");
    })
    .await
    .expect("listener and writer must finish within 3 s while the connection is still open");
    assert!(started.elapsed() < Duration::from_secs(3));

    let rows: usize = common::read_all(dir.path())
        .iter()
        .map(|b| b.num_rows())
        .sum();
    assert_eq!(
        rows, LINES,
        "the complete lines must be on disk, the partial one not"
    );
    drop(conn);
}

#[tokio::test]
async fn zeek_open_connection_does_not_block_writer_flush_on_shutdown_signal() {
    run_case(false).await;
}

#[tokio::test]
async fn zeek_open_connection_does_not_block_writer_flush_when_sender_dropped() {
    run_case(true).await;
}
