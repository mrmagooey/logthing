// tests/syslog_panic_resilience_e2e.rs
//! E2E regression: a syslog UDP datagram whose 100th byte falls inside a
//! multi-byte UTF-8 character must not panic the receive task.
//!
//! Before the fix, `&msg[..100.min(msg.len())]` in the parse-error `warn!`
//! arm panicked on a non-char-boundary index. The panicking task was one of
//! N SO_REUSEPORT receive tasks, and its parent discarded the JoinError, so
//! the socket was silently never drained again.
//!
//! Harness mirrors `tests/syslog_payload_e2e.rs`: spawn a real
//! `SyslogListener` in-process on ephemeral ports with a counting handler.

use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{SyslogHandler, SyslogListener, SyslogListenerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{Duration, sleep};

/// A SyslogHandler that just counts how many messages it was handed.
struct CountingHandler {
    count: AtomicUsize,
}

impl CountingHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            count: AtomicUsize::new(0),
        })
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl SyslogHandler for CountingHandler {
    async fn handle_message(&self, _message: SyslogMessage, _source: SocketAddr) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

/// 98 ASCII bytes then a 4-byte emoji: byte index 100 lands mid-character.
/// The content parses as neither RFC3164 nor RFC5424, so it reaches the
/// parse-error `warn!` arm.
fn boundary_straddling_datagram() -> Vec<u8> {
    let mut v = vec![b'x'; 98];
    v.extend_from_slice("\u{1F600}".as_bytes());
    v
}

/// A well-formed RFC3164 message used as the liveness probe.
const GOOD: &[u8] = b"<34>Oct 11 22:14:15 testhost app: liveness probe";

#[tokio::test]
async fn malformed_datagram_does_not_kill_the_receive_task() {
    // The parse-error `warn!` call site under test only evaluates its
    // format arguments -- including the panicking slice -- when tracing
    // has an active subscriber at WARN or below. With no subscriber (or
    // `tracing_subscriber::fmt::try_init()`'s default of ERROR-only when
    // `RUST_LOG` is unset), the callsite interest cache is `never` and the
    // arguments are never evaluated, so the bug would not reproduce. Set an
    // explicit max level in code so this test doesn't depend on `RUST_LOG`.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);

    // Reserve a separate ephemeral port for TCP so the TCP bind in start()
    // cannot collide with anything.
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    drop(tcp_listener);

    let handler = CountingHandler::new();

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
        recv_batch_size: 1,
        ..SyslogListenerConfig::default()
    };

    let listener = SyslogListener::new(cfg, handler.clone());
    let task = tokio::spawn(async move {
        listener.start().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    let listener_addr = format!("127.0.0.1:{udp_port}");

    // 1. hostile datagram — must not panic the task.
    sock.send_to(&boundary_straddling_datagram(), &listener_addr)
        .await
        .expect("send hostile");
    sleep(Duration::from_millis(200)).await;

    // 2. liveness probe — proves the task is still draining the socket.
    sock.send_to(GOOD, &listener_addr).await.expect("send good");
    sleep(Duration::from_millis(200)).await;

    task.abort();

    assert_eq!(
        handler.count(),
        1,
        "receive task died on the malformed datagram; the good message that \
         followed was never processed"
    );
}
