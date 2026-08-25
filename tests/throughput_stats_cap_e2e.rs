//! End-to-end test for the `/stats/throughput` event-type cap.
//!
//! Spins up the REAL `Server` (`logthing::server::Server::new` +
//! `Server::run`), the same entry point `main.rs` uses, on a real TCP
//! listener. Drives event ingestion through the outermost HTTP interface —
//! `POST /wsman/events` with real WEF XML bodies, exactly what a Windows
//! event forwarder would send — with more distinct `Provider:EventID`
//! combinations than the event-type cap allows, then reads
//! `GET /stats/throughput` over a real HTTP connection and asserts the
//! reported event-type count stays bounded rather than growing one row per
//! distinct (attacker-controlled) provider/event-id pair.
//!
//! No S3/MinIO wired (`[wef.s3]`/`[wef.local]` both absent in the default
//! config), so events are accepted, counted, and dropped — this test
//! validates the HTTP + stats-capping path only. No external dependency
//! required.

use logthing::config::{Config, MetricsConfig, TlsConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Mirror of `stats::MAX_EVENT_TYPES` (private to that module).
const MAX_EVENT_TYPES: usize = 1024;

fn wef_events_envelope(provider: &str, event_id: u32) -> String {
    format!(
        r#"
        <Envelope>
          <Body>
            <Events>
              <Event>
                <System>
                  <Provider>{provider}</Provider>
                  <EventID>{event_id}</EventID>
                  <Level>4</Level>
                  <TimeCreated>2024-01-01T00:00:00Z</TimeCreated>
                  <Computer>host</Computer>
                </System>
                <EventData>
                  <Data Name="TargetUserName">alice</Data>
                </EventData>
              </Event>
            </Events>
          </Body>
        </Envelope>
        "#
    )
}

#[tokio::test]
async fn throughput_endpoint_stays_bounded_under_a_flood_of_distinct_event_types() {
    // Reserve an ephemeral port up front (bind, read the port, drop the
    // listener) since `Server::run` binds its own listener internally and
    // doesn't return the bound address. Small, accepted TOCTOU race, same
    // pattern used by tests/admin_flush_interval_e2e.rs.
    let port = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };

    let config = Config {
        bind_address: format!("127.0.0.1:{port}").parse().unwrap(),
        // Server::run always serves plain HTTP regardless, but keep config honest.
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        // Avoid binding a second, unneeded port.
        metrics: MetricsConfig {
            enabled: false,
            ..MetricsConfig::default()
        },
        ..Config::default()
    };

    let shared_config = Arc::new(RwLock::new(config.clone()));
    let throughput = Arc::new(ThroughputStats::new());
    let server = Server::new(
        config,
        shared_config,
        throughput,
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
    )
    .await
    .expect("Server::new must succeed with no S3/local targets configured");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move {
        server
            .run(shutdown_rx)
            .await
            .expect("server run must not error");
    });

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{port}");

    // Wait for the server to actually be listening.
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(format!("{base_url}/health")).send().await
            && resp.status() == reqwest::StatusCode::OK
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(ready, "server did not become ready in time");

    // Post more distinct provider/event-id combinations than the cap
    // allows, each via a real HTTP POST to the real /wsman/events route —
    // exactly the caller-controlled key space (`describe_event_type`) the
    // cap exists to bound.
    let distinct_events = MAX_EVENT_TYPES + 200;
    for i in 0..distinct_events {
        let body = wef_events_envelope(&format!("Provider-{i}"), 4624);
        let resp = client
            .post(format!("{base_url}/wsman/events"))
            .body(body)
            .send()
            .await
            .expect("POST /wsman/events must succeed");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "event {i} must be accepted"
        );
    }

    let snapshot: Vec<serde_json::Value> = client
        .get(format!("{base_url}/stats/throughput"))
        .send()
        .await
        .expect("GET /stats/throughput must succeed")
        .json()
        .await
        .expect("/stats/throughput must return valid JSON");

    assert!(
        snapshot.len() <= MAX_EVENT_TYPES + 1,
        "throughput endpoint reported {} distinct event-type rows for {} distinct providers \
         posted; expected at most {} (cap {} plus one _other row)",
        snapshot.len(),
        distinct_events,
        MAX_EVENT_TYPES + 1,
        MAX_EVENT_TYPES
    );
    let has_other = snapshot.iter().any(|row| row["event_type"] == "_other");
    assert!(
        has_other,
        "expected an _other row once distinct providers exceeded the cap"
    );

    // Clean shutdown.
    shutdown_tx.send(true).expect("shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must join after shutdown")
        .expect("server task must not panic");
}
