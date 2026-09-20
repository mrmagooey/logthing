//! Integration test: a `security.allowed_ips` change must apply LIVE — to
//! both the main HTTP router and the wire-protocol listeners — with no
//! process restart.
//!
//! Before this fix, `IpWhitelist` was baked into `Server::create_router`
//! (and each wire listener) by value at construction time: an admin who
//! tightened or loosened `security.allowed_ips` via `PUT /config` got a
//! `200 OK` and a `CONFIG_UPDATED` audit entry, but the change did nothing
//! until the process restarted. The fix makes `IpWhitelist` internally
//! mutable (`Arc<RwLock<Vec<IpNet>>>`) and shares ONE instance across every
//! consumer, so `IpWhitelist::set_networks` (what the admin API calls after
//! a validated config swap — see
//! `logthing::admin::config_api::apply_live_security_settings`) is visible
//! everywhere immediately.
//!
//! This test proves that property directly: it starts a real `Server`
//! (HTTP) and a real syslog TCP listener, both holding a `Clone` of the
//! SAME `IpWhitelist`, and shows one `set_networks` call flips the verdict
//! for both without touching either.

use logthing::config::{Config, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{SyslogHandler, SyslogListener, SyslogListenerConfig};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep, timeout};

struct CapturingSyslogHandler {
    messages: Mutex<Vec<SyslogMessage>>,
}

impl CapturingSyslogHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            messages: Mutex::new(Vec::new()),
        })
    }
    fn count(&self) -> usize {
        self.messages.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl SyslogHandler for CapturingSyslogHandler {
    async fn handle_message(&self, message: SyslogMessage, _source: SocketAddr) {
        self.messages.lock().unwrap().push(message);
    }
}

async fn reserve_tcp_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

/// `SyslogListenerConfig::default()`'s `udp_port` is the privileged port
/// 514 — binding it without root fails, which aborts `start_with_shutdown`
/// before it ever reaches the TCP bind (both sockets are set up in the same
/// call). Must always be overridden to an ephemeral port in tests.
async fn reserve_udp_port() -> u16 {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

async fn send_syslog_line(port: u16) {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
        let _ = stream
            .write_all(b"<134>Jan 15 10:30:45 host app: test message\n")
            .await;
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
    }
}

#[tokio::test]
async fn allowed_ips_update_applies_live_to_http_router_and_syslog_listener() {
    // One shared `IpWhitelist`, starting restrictive: 127.0.0.1 (every
    // client in this test) is NOT in 10.0.0.0/8, so both consumers must
    // start out rejecting it.
    let ip_whitelist = IpWhitelist::new(vec!["10.0.0.0/8".to_string()]).unwrap();

    // --- HTTP side: a real `Server::run`. ---
    let http_port = reserve_tcp_port().await;
    let config = Config {
        bind_address: format!("127.0.0.1:{http_port}").parse().unwrap(),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        ..Config::default()
    };
    let shared_config = Arc::new(RwLock::new(config.clone()));
    let server = Server::new(
        config,
        shared_config,
        Arc::new(ThroughputStats::new()),
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
        ip_whitelist.clone(),
    )
    .await
    .expect("Server::new must succeed with no S3/local targets configured");

    let (http_shutdown_tx, http_shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move {
        server
            .run(http_shutdown_rx)
            .await
            .expect("server run must not error");
    });

    // --- Wire-listener side: a real syslog TCP listener sharing the SAME
    // `IpWhitelist` clone. ---
    let syslog_port = reserve_tcp_port().await;
    let syslog_udp_port = reserve_udp_port().await;
    let syslog_config = SyslogListenerConfig {
        tcp_port: syslog_port,
        udp_port: syslog_udp_port,
        bind_address: "127.0.0.1".to_string(),
        ..SyslogListenerConfig::default()
    };
    let syslog_handler = CapturingSyslogHandler::new();
    let syslog_listener = SyslogListener::new(syslog_config, syslog_handler.clone())
        .with_allowed_ips(ip_whitelist.clone());
    let (syslog_shutdown_tx, syslog_shutdown_rx) = tokio::sync::watch::channel(false);
    let syslog_task = tokio::spawn(async move {
        syslog_listener
            .start_with_shutdown(syslog_shutdown_rx)
            .await
            .ok();
    });

    sleep(Duration::from_millis(300)).await;

    let health_url = format!("http://127.0.0.1:{http_port}/health");
    let client = reqwest::Client::new();

    // --- Before: both consumers reject 127.0.0.1. ---
    let resp = client
        .get(&health_url)
        .send()
        .await
        .expect("HTTP listener must be reachable (then reject)");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "127.0.0.1 must be rejected before the live update"
    );

    send_syslog_line(syslog_port).await;
    sleep(Duration::from_millis(150)).await;
    assert_eq!(
        syslog_handler.count(),
        0,
        "127.0.0.1 must be rejected by the syslog listener before the live update"
    );

    // --- The live update: exactly what `apply_live_security_settings` does
    // after a validated `PUT /config` / `/config/reload` swap. ---
    ip_whitelist
        .set_networks(&["127.0.0.1".to_string()])
        .expect("valid CIDR");

    // --- After: both consumers accept 127.0.0.1 — no restart, no
    // re-construction of either the router or the listener. ---
    let resp = client
        .get(&health_url)
        .send()
        .await
        .expect("HTTP listener must be reachable");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "127.0.0.1 must be accepted immediately after the live update, no restart"
    );

    send_syslog_line(syslog_port).await;
    sleep(Duration::from_millis(150)).await;
    assert_eq!(
        syslog_handler.count(),
        1,
        "127.0.0.1 must be accepted by the syslog listener immediately after the live \
         update, no restart"
    );

    let _ = http_shutdown_tx.send(true);
    let _ = syslog_shutdown_tx.send(true);
    let _ = timeout(Duration::from_secs(5), server_task).await;
    let _ = timeout(Duration::from_secs(5), syslog_task).await;
}
