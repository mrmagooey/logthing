//! WEF `[[filter.rules]]` against an in-process `Server`: a filtered event is acknowledged
//! (200, not 503), advances the stored bookmark, and never reaches the Parquet sink.

mod common;

use arrow::array::{Array, UInt32Array};
use logthing::config::{Config, MetricsConfig, TlsConfig, WefConfig, WefLocalConfig};
use logthing::forwarding::flush_registry::FlushIntervalRegistry;
use logthing::middleware::IpWhitelist;
use logthing::server::Server;
use logthing::stats::{SourceHourlyStats, ThroughputStats};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

const MACHINE: &str = "win10.example.com";

struct Harness {
    base: String,
    dir: tempfile::TempDir,
    client: reqwest::Client,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

fn build_config(wef_toml: &str, port: u16, dir: &std::path::Path) -> Config {
    let parsed = toml::from_str::<Config>(wef_toml).unwrap();
    let wef: WefConfig = parsed.wef;
    Config {
        bind_address: format!("127.0.0.1:{port}").parse().unwrap(),
        tls: TlsConfig {
            enabled: false,
            ..TlsConfig::default()
        },
        metrics: MetricsConfig {
            enabled: false,
            ..MetricsConfig::default()
        },
        wef: WefConfig {
            local: Some(WefLocalConfig {
                directory: dir.to_path_buf(),
                prefix: "".to_string(),
                flush_threshold_bytes: usize::MAX,
                flush_interval_secs: 3600,
                channel_capacity: 256,
                max_buffer_rows: 100_000,
            }),
            ..wef
        },
        filter: parsed.filter,
        ..Config::default()
    }
}

async fn new_server(config: Config) -> anyhow::Result<Server> {
    let shared = Arc::new(RwLock::new(config.clone()));
    Server::new(
        config,
        shared,
        Arc::new(ThroughputStats::new()),
        Arc::new(SourceHourlyStats::new()),
        FlushIntervalRegistry::new(),
        IpWhitelist::empty(),
        Vec::new(),
    )
    .await
}

impl Harness {
    /// Start a server whose config is `common::wef_toml` transformed by `tweak`.
    async fn start(tweak: impl Fn(String) -> String) -> Harness {
        Self::start_with_url(None, tweak).await
    }

    /// Like [`Harness::start`], advertising `collector_url` (when given) instead of the bound
    /// address. Requests still go to the bound port via `self.base`.
    async fn start_with_url(
        collector_url: Option<&str>,
        tweak: impl Fn(String) -> String,
    ) -> Harness {
        for _ in 0..common::START_ATTEMPTS {
            // free_port() is racy; if the server loses the bind race, retry on a fresh port.
            let port = common::free_port();
            let base = format!("http://127.0.0.1:{port}");
            let advertised = collector_url.unwrap_or(&base).to_string();
            let dir = tempfile::tempdir().unwrap();
            let config = build_config(&tweak(common::wef_toml(&advertised)), port, dir.path());
            let mut server = new_server(config).await.expect("Server::new");
            let workers = server.take_wef_worker_handles();
            let (shutdown, rx) = tokio::sync::watch::channel(false);
            let task = common::spawn_server(server.run(rx));
            let client = reqwest::Client::new();
            if common::await_ready(&client, &format!("{base}/health"), &task).await {
                return Harness {
                    base,
                    dir,
                    client,
                    shutdown,
                    task: task.handle,
                    workers,
                };
            }
        }
        panic!("server never bound a free port");
    }

    /// POST a UTF-16 envelope; returns (status, decoded body, raw content-type, body len).
    async fn post(
        &self,
        url: &str,
        envelope: &str,
        sldc: bool,
    ) -> (reqwest::StatusCode, String, Option<String>, usize) {
        let mut req = self.client.post(url);
        let body = if sldc {
            req = req.header("Content-Encoding", "SLDC");
            common::sldc_literals(&common::utf16(envelope))
        } else {
            common::utf16(envelope)
        };
        let resp = req
            .header("Content-Type", "application/soap+xml;charset=UTF-16")
            .body(body)
            .send()
            .await
            .expect("POST");
        let status = resp.status();
        let ct = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = resp.bytes().await.unwrap();
        let text = if bytes.is_empty() {
            String::new()
        } else {
            assert_eq!(
                &bytes[..2],
                &[0xFF, 0xFE],
                "response must start with a UTF-16LE BOM"
            );
            common::decode_utf16(&bytes)
        };
        (status, text, ct, bytes.len())
    }

    /// Shut down, flush the sink and return the Parquet batches written.
    async fn finish(self) -> Vec<arrow::record_batch::RecordBatch> {
        self.shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("server joins")
            .expect("server task");
        for h in self.workers {
            tokio::time::timeout(Duration::from_secs(5), h)
                .await
                .expect("worker joins")
                .expect("worker task");
        }
        common::read_all(self.dir.path())
    }
}

fn rows(batches: &[arrow::record_batch::RecordBatch]) -> usize {
    batches.iter().map(|b| b.num_rows()).sum()
}

fn event_ids(batches: &[arrow::record_batch::RecordBatch]) -> Vec<u32> {
    batches
        .iter()
        .flat_map(|b| {
            let a = b
                .column_by_name("event_id")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt32Array>()
                .unwrap();
            (0..a.len()).map(|i| a.value(i)).collect::<Vec<_>>()
        })
        .collect()
}

const DROP_4624: &str = "\n[[filter.rules]]\nname = \"drop-4624\"\nsource = \"wef\"\n\
                         match = { event_id = 4624 }\n";

#[tokio::test]
async fn test_all_filtered_batch_is_acked_and_advances_bookmark() {
    let h = Harness::start(|t| t + DROP_4624).await;
    let wsman = format!("{}/wsman", h.base);
    let url = format!("{}/wsman/subscriptions/{}", h.base, common::TEST_SUB_UUID);

    let ev = common::wef_fixture("security_4624");
    let mid = "c1";
    let (st, body, _, _) = h
        .post(
            &url,
            &common::events_envelope(mid, MACHINE, 4242, &[&ev]),
            false,
        )
        .await;
    assert_eq!(
        st, 200,
        "a fully filtered batch must not be answered 503: {body}"
    );
    assert!(common::acks(&body, mid), "{body}");

    let (_, again, _, _) = h
        .post(&wsman, &common::enumerate_envelope("c2", MACHINE), false)
        .await;
    assert!(
        again.contains("<Bookmark Channel=\"Security\" RecordId=\"4242\""),
        "bookmark must advance past filtered events: {again}"
    );

    let batches = h.finish().await;
    assert_eq!(rows(&batches), 0, "filtered events must not be stored");
}

#[tokio::test]
async fn test_mixed_batch_stores_only_unfiltered_events() {
    let h = Harness::start(|t| t + DROP_4624).await;
    let url = format!("{}/wsman/subscriptions/{}", h.base, common::TEST_SUB_UUID);
    let fixtures = ["security_4624", "security_4625"].map(common::wef_fixture);
    let refs: Vec<&str> = fixtures.iter().map(String::as_str).collect();
    let (st, _, _, _) = h
        .post(
            &url,
            &common::events_envelope("d1", MACHINE, 77, &refs),
            false,
        )
        .await;
    assert_eq!(st, 200);
    let batches = h.finish().await;
    assert_eq!(event_ids(&batches), vec![4625]);
}
