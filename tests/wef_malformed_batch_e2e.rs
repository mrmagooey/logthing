//! End-to-end test: a WEF batch with a malformed MIDDLE event, POSTed to
//! the real `/wsman/events` HTTP endpoint of a real `logthing::server::Server`
//! with a `[wef.local]` destination wired up — proving the resync fix in
//! `WefParser::parse_events` (src/protocol/mod.rs) end to end: the HTTP
//! response is still 200 (so the Windows forwarder does not resend), the
//! `wef_xml_parse_errors` counter increments on the real `/metrics` scrape,
//! and the well-formed events on BOTH sides of the malformed one still
//! reach Parquet on local disk (proving resync actually resumes parsing
//! after the error, rather than folding everything after it into one
//! unparsed fragment). Also asserts
//! `parquet_s3_records_skipped{source="wef",target="local"} == 1` — the
//! malformed event's raw fragment (no `.parsed` data) reaches the WEF
//! local writer and is skipped there, exactly once, making this the real
//! outer-interface trigger for that counter (see the `#4` fix in
//! `docs/superpowers/specs/2026-09-22-review-fixes-design.md`).
//!
//! Template: `tests/field_cardinality_metric_wef_e2e.rs` for the overall
//! shape (real `Server`, `metrics.enabled = true`, `reserve_port`, real
//! `POST /wsman/events`) and `tests/wef_local_integration.rs` for the
//! `[wef.local]` config shape and how to read the resulting Parquet back.
//! `main.rs`'s shutdown sequence (`take_wef_worker_handles` before
//! `Server::run` consumes `self`, then await those handles after the
//! shutdown signal so the WEF worker's channel-close flush completes) is the
//! pattern this test's shutdown follows.
//!
//! This MUST be the only `#[tokio::test]` in this binary — `Server::run`
//! installs the real Prometheus recorder, a process-global, install-once
//! call.

use bytes::Bytes;
use logthing::config::{Config, MetricsConfig, TlsConfig, WefConfig, WefLocalConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

async fn reserve_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

/// Well-formed `<Event>` for event number `n`, matching real WEF shape —
/// same helper shape as the unit tests in `src/protocol/mod.rs`.
fn wef_event(n: u32) -> String {
    format!(
        "<Event><System><Provider>P</Provider><EventID>{n}</EventID><Level>4</Level>\
         </System></Event>"
    )
}

/// Malformed `<Event>`: a stray `</Mismatch>` end tag inside `<System>`
/// trips quick-xml's default `check_end_names` and returns `Err` from
/// `read_event_into`.
fn wef_malformed_event() -> &'static str {
    "<Event><System><Provider>P</Provider></Mismatch><EventID>99</EventID>\
     <Level>4</Level></System></Event>"
}

fn find_metric_value(body: &str, exact_prefix: &str) -> Option<f64> {
    body.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        l.strip_prefix(exact_prefix)
            .map(|rest| rest.trim())
            .and_then(|v| v.parse::<f64>().ok())
    })
}

#[tokio::test]
async fn malformed_batch_returns_200_counts_the_error_and_keeps_the_good_events() {
    let http_port = reserve_port().await;
    let metrics_port = reserve_port().await;
    let tmp = tempfile::tempdir().unwrap();

    let config = Config {
        bind_address: format!("127.0.0.1:{http_port}").parse().unwrap(),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        metrics: MetricsConfig {
            enabled: true,
            port: metrics_port,
            ..MetricsConfig::default()
        },
        wef: WefConfig {
            s3: None,
            local: Some(WefLocalConfig {
                directory: tmp.path().to_path_buf(),
                prefix: "".to_string(),
                flush_threshold_bytes: usize::MAX,
                flush_interval_secs: 3600,
                channel_capacity: 256,
                max_buffer_rows: 100_000,
            }),
        },
        ..Config::default()
    };

    let shared_config = Arc::new(RwLock::new(config.clone()));
    let mut server = Server::new(
        config,
        shared_config,
        Arc::new(ThroughputStats::new()),
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
        IpWhitelist::empty(),
        Vec::new(),
    )
    .await
    .expect("Server::new must succeed with a local WEF destination configured");

    // Must be taken before `server.run` consumes `self` — same ordering
    // `main.rs` uses so the handle can be awaited during shutdown.
    let wef_worker_handles = server.take_wef_worker_handles();
    assert_eq!(
        wef_worker_handles.len(),
        1,
        "exactly one WEF worker for the configured [wef.local] destination"
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move {
        server
            .run(shutdown_rx)
            .await
            .expect("server run must not error");
    });

    let base_url = format!("http://127.0.0.1:{http_port}");
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    let client = reqwest::Client::new();

    let mut ready = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(format!("{base_url}/health")).send().await
            && resp.status() == reqwest::StatusCode::OK
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "server did not become ready in time");

    let body = format!(
        "<Envelope><Body><Events>{}{}{}</Events></Body></Envelope>",
        wef_event(1),
        wef_malformed_event(),
        wef_event(3)
    );

    let resp = client
        .post(format!("{base_url}/wsman/events"))
        .body(body)
        .send()
        .await
        .expect("POST /wsman/events must succeed");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "a malformed middle event must not fail the whole batch response — the forwarder \
         must not be told to resend"
    );

    // Scrape /metrics until both wef_xml_parse_errors AND
    // parquet_s3_records_skipped{source="wef",target="local"} show up —
    // the latter is incremented asynchronously by the WEF local writer
    // task once it receives and rejects the malformed event's unparsed
    // fragment, so it can lag slightly behind the HTTP response.
    const SKIPPED_PREFIX: &str = "parquet_s3_records_skipped{source=\"wef\",target=\"local\"} ";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let scrape = loop {
        if let Ok(resp) = reqwest::get(&metrics_url).await
            && let Ok(text) = resp.text().await
            && find_metric_value(&text, "wef_xml_parse_errors ") == Some(1.0)
            && find_metric_value(&text, SKIPPED_PREFIX) == Some(1.0)
        {
            break text;
        }
        if tokio::time::Instant::now() >= deadline {
            break reqwest::get(&metrics_url)
                .await
                .ok()
                .unwrap()
                .text()
                .await
                .unwrap_or_default();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(
        find_metric_value(&scrape, "wef_xml_parse_errors "),
        Some(1.0),
        "wef_xml_parse_errors never reached 1 on the real /metrics endpoint within 15s. Full \
         scrape body:\n{scrape}"
    );
    assert_eq!(
        find_metric_value(&scrape, SKIPPED_PREFIX),
        Some(1.0),
        "parquet_s3_records_skipped{{source=\"wef\",target=\"local\"}} never reached 1 on the \
         real /metrics endpoint within 15s — the malformed event's unparsed fragment must reach \
         the WEF local writer and be counted as skipped there. Full scrape body:\n{scrape}"
    );

    // --- Clean shutdown: signal, join the server task (drops AppState,
    // closing the WEF worker's channel), then await the WEF worker itself so
    // its channel-close flush completes before we read the Parquet files. ---
    shutdown_tx.send(true).expect("shutdown signal must send");
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must join after shutdown")
        .expect("server task must not panic");

    for handle in wef_worker_handles {
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("WEF worker task must join after shutdown")
            .expect("WEF worker task must not panic");
    }

    // --- Read the Parquet files back and check the good events landed. ---
    let mut all_files = Vec::new();
    let mut stack = vec![tmp.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                all_files.push(path);
            }
        }
    }
    let parquet_files: Vec<_> = all_files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();

    use arrow::array::{Array, StringArray};
    let mut total_rows = 0usize;
    let mut found_event_id_1 = false;
    let mut found_event_id_3 = false;
    for path in &parquet_files {
        let raw = std::fs::read(path).unwrap();
        let buf = Bytes::from(raw);
        let builder = ParquetRecordBatchReaderBuilder::try_new(buf).unwrap();
        let reader = builder.build().unwrap();
        for rb in reader {
            let rb = rb.unwrap();
            total_rows += rb.num_rows();
            let event_data = rb
                .column_by_name("event_data")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..event_data.len() {
                if event_data.value(i).contains("<EventID>1</EventID>") {
                    found_event_id_1 = true;
                }
                if event_data.value(i).contains("<EventID>3</EventID>") {
                    found_event_id_3 = true;
                }
            }
        }
    }

    assert_eq!(
        total_rows, 2,
        "only the 2 well-formed events must land as Parquet rows; the malformed middle event \
         has no parsed data and is skipped by WefSink, matching pre-existing behavior"
    );
    assert!(
        found_event_id_1,
        "the event BEFORE the malformed one must be in Parquet"
    );
    assert!(
        found_event_id_3,
        "the event AFTER the malformed one must be in Parquet too — proves the resync actually \
         reached it instead of folding it into the malformed fragment"
    );
}
