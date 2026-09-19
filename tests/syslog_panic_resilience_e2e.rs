// tests/syslog_panic_resilience_e2e.rs
//! E2E regression: a syslog UDP datagram whose Nth byte falls inside a
//! multi-byte UTF-8 character must not panic a receive task, and if a recv
//! task does die abnormally its parent must notice and report it rather
//! than silently leaving the socket undrained forever.
//!
//! Three tests, each driving a *different* code path in
//! `src/syslog/listener.rs` -- `SyslogListener` has two independent start
//! entry points and it matters which one a test exercises:
//!
//! - `malformed_datagram_does_not_kill_the_receive_task` drives `start()`,
//!   which calls `start_udp_listener()` directly via `tokio::select!` --
//!   one inline loop, no `tokio::spawn`, no `JoinError` handling. This is
//!   a real path (used by tests elsewhere in this suite) but not the one
//!   `main.rs` uses in production.
//! - `malformed_datagram_on_the_fan_out_path_does_not_kill_the_socket`
//!   drives `start_with_shutdown()` -- the actual production entry point,
//!   called from `src/main.rs:360` -- with the default `recv_tasks` (8),
//!   so the datagram is handled by `syslog_udp_recv_loop`, spawned per
//!   `SO_REUSEPORT` socket and joined by the loop at
//!   `src/syslog/listener.rs:558-566`. This is the exact scenario the
//!   security brief describes: "a few spoofable UDP packets stop ingestion
//!   until restart".
//! - `a_panicking_receive_task_increments_the_failure_counter_and_is_logged`
//!   proves the `JoinError`-handling fix itself. The `truncate_for_log` fix
//!   in this same change removed the only known external trigger for a
//!   recv-task panic, so there is no longer a way to exercise that handling
//!   honestly end-to-end from outside the crate; this test instead injects
//!   a deliberately-panicking test-only handler to make one recv task die
//!   and asserts the parent observes and reports it.

use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{SyslogHandler, SyslogListener, SyslogListenerConfig};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{Duration, sleep};
use tracing_subscriber::layer::SubscriberExt;

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

/// A SyslogHandler that always panics.
///
/// Test-only: used to drive one spawned `syslog_udp_recv_loop` task into a
/// genuine panic so `start_with_shutdown`'s `JoinError`-handling loop gets
/// exercised. No production handler (the various `*S3Handler`s) ever
/// panics here -- this exists solely because this task's own fix removed
/// the only known real trigger.
struct PanickingHandler;

#[async_trait::async_trait]
impl SyslogHandler for PanickingHandler {
    async fn handle_message(&self, _message: SyslogMessage, _source: SocketAddr) {
        panic!("test-injected panic to exercise JoinError handling");
    }
}

/// Collects `(level, formatted message)` for every tracing event emitted
/// while this capture is the default subscriber. Pattern reused from
/// `tests/drop_log_integration.rs`.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<(tracing::Level, String)>>>);

impl<S> tracing_subscriber::Layer<S> for Capture
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct V(String);
        impl tracing::field::Visit for V {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={:?} ", f.name(), v));
            }
        }
        let mut v = V(String::new());
        event.record(&mut v);
        self.0
            .lock()
            .unwrap()
            .push((*event.metadata().level(), v.0));
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

/// Bind two ephemeral, unbound ports (UDP then TCP) suitable for
/// `SyslogListenerConfig`. Sockets are dropped immediately after
/// allocation, same pattern as `tests/syslog_payload_e2e.rs`.
async fn alloc_udp_tcp_ports() -> (u16, u16) {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    drop(udp_socket);

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    drop(tcp_listener);

    (udp_port, tcp_port)
}

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

    let (udp_port, tcp_port) = alloc_udp_tcp_ports().await;
    let handler = CountingHandler::new();

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
        recv_batch_size: 1,
        ..SyslogListenerConfig::default()
    };

    // `start()` -> `start_udp_listener()`: one inline recv loop, no
    // `tokio::spawn`, no `JoinError` handling. Aborting `task` below stops
    // this loop directly, since it *is* the receive loop, not a spawner of
    // detached children.
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

#[tokio::test]
async fn malformed_datagram_on_the_fan_out_path_does_not_kill_the_socket() {
    // This is the production path: `start_with_shutdown` is what
    // `src/main.rs:360` calls, and the default `recv_tasks` (8, left
    // untouched below) is what puts the datagram through
    // `syslog_udp_recv_loop`, spawned per `SO_REUSEPORT` socket and joined
    // by the `JoinError`-handling loop this task also fixed.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    let (udp_port, tcp_port) = alloc_udp_tcp_ports().await;
    let handler = CountingHandler::new();

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
        recv_batch_size: 1,
        // recv_tasks intentionally left at SyslogListenerConfig::default()'s
        // production value (8) -- see module doc comment.
        ..SyslogListenerConfig::default()
    };

    let listener = SyslogListener::new(cfg, handler.clone());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let outer = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });

    sleep(Duration::from_millis(100)).await;

    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    let listener_addr = format!("127.0.0.1:{udp_port}");

    // Both datagrams come from the same client socket/source port, so the
    // kernel's SO_REUSEPORT hash sends both to the same recv task --
    // see `SyslogListenerConfig::recv_tasks`'s doc comment.
    sock.send_to(&boundary_straddling_datagram(), &listener_addr)
        .await
        .expect("send hostile");
    sleep(Duration::from_millis(200)).await;

    sock.send_to(GOOD, &listener_addr).await.expect("send good");
    sleep(Duration::from_millis(200)).await;

    // Graceful shutdown rather than `abort()`: aborting the outer task
    // would not cancel the detached per-socket tasks it spawned, leaking
    // them for the rest of the process.
    let _ = shutdown_tx.send(true);
    let outer_result = tokio::time::timeout(Duration::from_secs(5), outer)
        .await
        .expect("start_with_shutdown did not return after shutdown")
        .expect("outer task panicked or was cancelled");
    assert!(
        outer_result.is_ok(),
        "start_with_shutdown returned an error: {outer_result:?}"
    );

    assert_eq!(
        handler.count(),
        1,
        "a receive task died on the malformed datagram on the fan-out path; \
         the good message that followed was never processed"
    );
}

#[tokio::test]
async fn a_panicking_receive_task_increments_the_failure_counter_and_is_logged() {
    let cap = Capture::default();
    let sub = tracing_subscriber::registry().with(cap.clone());
    let _guard = tracing::subscriber::set_default(sub);

    // A real global Prometheus recorder, not `DebuggingRecorder`: the
    // counter increment happens inside a `tokio::spawn`ed task, and
    // `DebuggingRecorder` has a documented cross-thread visibility gap on
    // a multi_thread runtime (see `tests/zeek_backpressure_e2e.rs`'s module
    // doc comment). This test uses the default `current_thread` flavor, so
    // that gap would not bite here regardless, but the same recorder is
    // used for consistency with the rest of the suite.
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    metrics::set_global_recorder(recorder).expect("install prometheus recorder");

    let (udp_port, tcp_port) = alloc_udp_tcp_ports().await;
    let handler: Arc<dyn SyslogHandler> = Arc::new(PanickingHandler);

    let cfg = SyslogListenerConfig {
        udp_port,
        tcp_port,
        bind_address: "127.0.0.1".to_string(),
        parse_dns_logs: false,
        recv_tasks: 2,
        recv_batch_size: 1,
        ..SyslogListenerConfig::default()
    };

    let listener = SyslogListener::new(cfg, handler);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let outer = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });

    sleep(Duration::from_millis(100)).await;

    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    sock.send_to(GOOD, format!("127.0.0.1:{udp_port}"))
        .await
        .expect("send good message to trigger the panicking handler");

    // Give the panicking task time to unwind and be caught by tokio.
    sleep(Duration::from_millis(200)).await;

    // The sequential `for task in tasks { task.await }` join loop in
    // `start_with_shutdown` can't observe the panicked task's `JoinError`
    // until every task *before* it in the vec has resolved. Shut down the
    // survivors so the loop can drain through to it, regardless of which
    // SO_REUSEPORT socket the datagram happened to hash onto.
    let _ = shutdown_tx.send(true);

    let outer_result = tokio::time::timeout(Duration::from_secs(5), outer)
        .await
        .expect("start_with_shutdown did not return after shutdown")
        .expect("outer task panicked or was cancelled");
    assert!(
        outer_result.is_ok(),
        "start_with_shutdown itself returned an error: {outer_result:?}"
    );

    let rendered = metrics_handle.render();
    let failed = logthing::profiling::parse_counter(&rendered, "syslog_recv_task_failed");
    assert_eq!(
        failed,
        Some(1),
        "expected syslog_recv_task_failed == 1, got {failed:?}\nfull metrics dump:\n{rendered}"
    );

    let logs = cap.0.lock().unwrap();
    assert!(
        logs.iter()
            .any(|(level, msg)| *level == tracing::Level::ERROR
                && msg.contains("a receive task terminated abnormally")),
        "expected an ERROR log containing 'a receive task terminated abnormally', got: {:?}",
        *logs
    );
}
