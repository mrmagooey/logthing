//! Integration test: an env-var override on `ipfix.udp_port` /
//! `ipfix.bind_address` reaches a real OS-level socket bind, not just a
//! parsed `Config` struct. Ipfix is the representative listener because it
//! has both a port and a bind-address field; syslog/zeek/suricata/sflow all
//! use byte-for-byte identical `format!("{bind}:{port}").parse() -> bind()`
//! wiring (verified in the design spec), so this one listener's live-bind
//! check stands in for all five without duplicating the same proof five times.

use logthing::config::Config;
use logthing::ipfix::listener::{DefaultIpfixHandler, IpfixListener, IpfixListenerConfig};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Duration, sleep, timeout};

#[tokio::test]
async fn env_var_override_binds_ipfix_listener_on_overridden_address_and_port() {
    // Obtain a free ephemeral port on 127.0.0.1, then release it immediately
    // so the listener can bind it — same TOCTOU-avoidance idiom already used
    // by this crate's own listener tests (see
    // `src/ipfix/listener.rs::start_with_shutdown_exits_on_signal`).
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    unsafe {
        std::env::set_var("LOGTHING__IPFIX__UDP_PORT", port.to_string());
        std::env::set_var("LOGTHING__IPFIX__BIND_ADDRESS", "127.0.0.1");
        // Regression guard for the WEF -> logthing rename: the legacy `WEF__`
        // prefix was dropped outright with no fallback, so this must be
        // ignored. Set in the same process as the live override above rather
        // than in its own #[test] — env vars are process-global and the two
        // would race under the parallel test harness.
        std::env::set_var("WEF__ZEEK__TCP_PORT", "14776");
    }
    let cfg = Config::load().expect("config loads with env overrides");
    unsafe {
        std::env::remove_var("LOGTHING__IPFIX__UDP_PORT");
        std::env::remove_var("LOGTHING__IPFIX__BIND_ADDRESS");
        std::env::remove_var("WEF__ZEEK__TCP_PORT");
    }

    assert_eq!(
        cfg.zeek.tcp_port, 47760,
        "legacy WEF__ prefix must no longer override config; it was removed \
         without a compatibility fallback in the logthing rename"
    );

    assert_eq!(
        cfg.ipfix.udp_port, port,
        "env override did not reach Config"
    );
    assert_eq!(
        cfg.ipfix.bind_address, "127.0.0.1",
        "env override did not reach Config"
    );

    let listener_config = IpfixListenerConfig {
        udp_port: cfg.ipfix.udp_port,
        bind_address: cfg.ipfix.bind_address.clone(),
    };
    let listener = IpfixListener::new(listener_config, Arc::new(DefaultIpfixHandler));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        listener.start_with_shutdown(shutdown_rx).await.ok();
    });

    // Give the listener time to bind and enter its receive loop.
    sleep(Duration::from_millis(100)).await;

    // While the listener holds the port, a second bind on the exact same
    // 127.0.0.1:<port> must fail with AddrInUse — this is the proof the
    // override reached a real OS socket, not just a Config field.
    let second_bind = UdpSocket::bind(format!("127.0.0.1:{port}")).await;
    assert!(
        second_bind.is_err(),
        "expected AddrInUse binding {port} a second time while the listener holds it; \
         override did not actually reach a live socket bind"
    );

    // Shut the listener down and confirm the port is released afterward.
    shutdown_tx.send(true).unwrap();
    let result = timeout(Duration::from_secs(2), task).await;
    assert!(
        result.is_ok(),
        "listener did not exit after shutdown signal"
    );

    let rebind = UdpSocket::bind(format!("127.0.0.1:{port}")).await;
    assert!(
        rebind.is_ok(),
        "port {port} should be free again after listener shutdown"
    );
}
