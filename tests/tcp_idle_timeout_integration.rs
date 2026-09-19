//! A TCP client that connects and then sends nothing must be disconnected
//! rather than holding a connection-semaphore permit indefinitely. Without a
//! timeout, 1024 silent sockets exhaust any of the three listeners (syslog,
//! zeek, suricata all share the same `handle_tcp_connection` shape).
//!
//! This test drives the syslog TCP listener over a real socket via its
//! public `start_with_shutdown` entry point (the same one `main.rs` calls) —
//! the same harness pattern as `listener_ip_whitelist_integration.rs`. The
//! production idle timeout is 300s, far too long to sleep through in a
//! test, so `SyslogListenerConfig::tcp_idle_timeout` is set to a short
//! value here; this is the real config field `main.rs` would populate with
//! `syslog::listener::TCP_IDLE_TIMEOUT` in production, so exercising it
//! from this external crate proves the injection mechanism actually works,
//! not just that it compiles.

use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{SyslogHandler, SyslogListener, SyslogListenerConfig};
use std::net::SocketAddr;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::time::{Duration, timeout};

/// Short enough to keep the test fast; long enough to comfortably separate
/// "the listener closed it on purpose" from "the connection raced ahead of
/// the accept loop starting up".
const TEST_IDLE_TIMEOUT: Duration = Duration::from_millis(300);

/// No-op handler — this test never sends a valid syslog line, so
/// `handle_message` is never called.
struct NoopHandler;

#[async_trait::async_trait]
impl SyslogHandler for NoopHandler {
    async fn handle_message(&self, _message: SyslogMessage, _source: SocketAddr) {}
}

#[tokio::test]
async fn idle_tcp_connection_is_closed_by_the_listener() {
    // Bind ephemeral UDP/TCP ports, then drop them so start_with_shutdown
    // can rebind the same addresses — same pattern used throughout this
    // crate's other listener integration tests.
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    drop(tcp_listener);

    let config = SyslogListenerConfig {
        udp_port,
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
        tcp_idle_timeout: TEST_IDLE_TIMEOUT,
        ..SyslogListenerConfig::default()
    };
    let listener = SyslogListener::new(config, std::sync::Arc::new(NoopHandler));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let listener_task = tokio::spawn(async move {
        listener.start_with_shutdown(shutdown_rx).await.ok();
    });

    // Give the listener time to bind and enter its accept loop.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let addr: SocketAddr = format!("127.0.0.1:{tcp_port}").parse().unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");

    // Send nothing. The listener must close the connection once
    // TEST_IDLE_TIMEOUT elapses. read() returning Ok(0) means the peer
    // (the listener) closed its write half.
    let mut buf = [0u8; 1];
    let closed = timeout(TEST_IDLE_TIMEOUT * 5, stream.read(&mut buf)).await;

    match closed {
        Ok(Ok(0)) => {} // listener closed it — correct
        Ok(other) => panic!("expected the listener to close the idle connection, got {other:?}"),
        Err(_) => panic!("listener never closed an idle connection within the timeout"),
    }

    let _ = shutdown_tx.send(true);
    let _ = listener_task.await;
}
