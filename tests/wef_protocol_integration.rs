//! Integration tests of the Windows-shaped WEF protocol flow (Enumerate, Heartbeat, Events,
//! SubscriptionEnd) against an in-process `Server` with a local Parquet sink and
//! `allow_unauthenticated = true` over plain HTTP. Metrics stay disabled, so several servers
//! may live in this binary.

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
    let wef: WefConfig = toml::from_str::<Config>(wef_toml).unwrap().wef;
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
        let port = common::free_port();
        let base = format!("http://127.0.0.1:{port}");
        let advertised = collector_url.unwrap_or(&base).to_string();
        let dir = tempfile::tempdir().unwrap();
        let config = build_config(&tweak(common::wef_toml(&advertised)), port, dir.path());
        let mut server = new_server(config).await.expect("Server::new");
        let workers = server.take_wef_worker_handles();
        let (shutdown, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            server.run(rx).await.expect("server run");
        });
        let client = reqwest::Client::new();
        for _ in 0..100 {
            if let Ok(r) = client.get(format!("{base}/health")).send().await
                && r.status().is_success()
            {
                return Harness {
                    base,
                    dir,
                    client,
                    shutdown,
                    task,
                    workers,
                };
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server did not become ready");
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

fn column_strings(batches: &[arrow::record_batch::RecordBatch], col: &str) -> Vec<String> {
    batches
        .iter()
        .flat_map(|b| {
            let a = common::str_col(b, col);
            (0..a.len())
                .map(|i| a.value(i).to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[tokio::test]
async fn test_full_flow_enumerate_heartbeat_events_subscription_end() {
    let h = Harness::start(|t| t).await;
    let wsman = format!("{}/wsman", h.base);

    // Enumerate
    let mid = "11111111-0000-4000-8000-000000000001";
    let (st, body, ct, _) = h
        .post(&wsman, &common::enumerate_envelope(mid, MACHINE), false)
        .await;
    assert_eq!(st, 200);
    assert_eq!(ct.as_deref(), Some("application/soap+xml;charset=UTF-16"));
    assert!(
        body.contains(&format!("<a:RelatesTo>uuid:{mid}</a:RelatesTo>")),
        "{body}"
    );
    let url = common::notify_to(&body);
    assert_eq!(
        url,
        format!("{}/wsman/subscriptions/{}", h.base, common::TEST_SUB_UUID)
    );

    // Heartbeat (SLDC-compressed) against the advertised address
    let mid = "11111111-0000-4000-8000-000000000002";
    let (st, body, _, _) = h
        .post(&url, &common::heartbeat_envelope(mid, MACHINE), true)
        .await;
    assert_eq!(st, 200);
    assert!(common::acks(&body, mid), "{body}");

    // Events: three real fixtures, SLDC + UTF-16
    let fixtures = ["security_4624", "security_4625", "sysmon_1"].map(common::wef_fixture);
    let refs: Vec<&str> = fixtures.iter().map(String::as_str).collect();
    let mid = "11111111-0000-4000-8000-000000000003";
    let (st, body, _, _) = h
        .post(
            &url,
            &common::events_envelope(mid, MACHINE, 1742, &refs),
            true,
        )
        .await;
    assert_eq!(st, 200);
    assert!(common::acks(&body, mid), "{body}");

    // SubscriptionEnd: 200 with an empty body and no Content-Type
    let end = common::heartbeat_envelope("11111111-0000-4000-8000-000000000004", MACHINE).replace(
        "http://schemas.dmtf.org/wbem/wsman/1/wsman/Heartbeat",
        "http://schemas.xmlsoap.org/ws/2004/08/eventing/SubscriptionEnd",
    );
    let (st, body, ct, len) = h.post(&url, &end, false).await;
    assert_eq!(st, 200);
    assert!(body.is_empty() && len == 0 && ct.is_none(), "{body}");

    let batches = h.finish().await;
    assert_eq!(rows(&batches), 3);
    let mut ids = event_ids(&batches);
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 4624, 4625]);
    assert!(
        column_strings(&batches, "subscription_id")
            .iter()
            .all(|s| s == "security")
    );
    let data = column_strings(&batches, "event_data").join("\n");
    for needle in [
        "Microsoft-Windows-Security-Auditing",
        "Microsoft-Windows-Sysmon",
        "<EventRecordID>227443</EventRecordID>",
        "<EventRecordID>319457832</EventRecordID>",
        "<EventRecordID>1742</EventRecordID>",
    ] {
        assert!(data.contains(needle), "missing {needle}");
    }
}

#[tokio::test]
async fn test_bookmark_replayed_on_reenumerate() {
    let h = Harness::start(|t| t).await;
    let wsman = format!("{}/wsman", h.base);
    let url = format!("{}/wsman/subscriptions/{}", h.base, common::TEST_SUB_UUID);

    let (_, first, _, _) = h
        .post(&wsman, &common::enumerate_envelope("a1", MACHINE), false)
        .await;
    assert!(!first.contains("RecordId=\"4242\""));

    let ev = common::wef_fixture("security_4624");
    let (st, _, _, _) = h
        .post(
            &url,
            &common::events_envelope("a2", MACHINE, 4242, &[&ev]),
            false,
        )
        .await;
    assert_eq!(st, 200);

    let (_, again, _, _) = h
        .post(&wsman, &common::enumerate_envelope("a3", MACHINE), false)
        .await;
    assert!(
        again
            .contains("<w:Bookmark><BookmarkList><Bookmark Channel=\"Security\" RecordId=\"4242\""),
        "{again}"
    );
    // A different machine must not receive this machine's bookmark.
    let (_, other, _, _) = h
        .post(
            &wsman,
            &common::enumerate_envelope("a4", "other.example.com"),
            false,
        )
        .await;
    assert!(!other.contains("RecordId=\"4242\""), "{other}");
    h.finish().await;
}

#[tokio::test]
async fn test_version_changes_after_config_change() {
    // The advertised collector_url is part of the version hash, so pin it across runs: only
    // the channel list may differ.
    const URL: &str = "http://wec.example.com:5985";
    let mut versions = Vec::new();
    for channel in ["Security", "System", "Security"] {
        let h = Harness::start_with_url(Some(URL), |t| {
            t.replace(
                "channels = [\"Security\"]",
                &format!("channels = [\"{channel}\"]"),
            )
        })
        .await;
        let (_, body, _, _) = h
            .post(
                &format!("{}/wsman", h.base),
                &common::enumerate_envelope("b1", MACHINE),
                false,
            )
            .await;
        versions.push(common::subscription_version(&body));
        h.finish().await;
    }
    assert_eq!(
        versions[0], versions[2],
        "same config and URL must give an equal version"
    );
    assert_ne!(
        versions[0], versions[1],
        "query change must change m:Version"
    );
}

#[tokio::test]
async fn test_startup_fails_without_auth_or_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    let port = common::free_port();
    let toml = common::wef_toml(&format!("http://127.0.0.1:{port}")).replace(
        "allow_unauthenticated = true",
        "allow_unauthenticated = false",
    );
    let err = new_server(build_config(&toml, port, dir.path()))
        .await
        .err()
        .expect("Server::new must refuse an unauthenticated WEF topology");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(
            "WEF subscriptions require authentication: enable [security.kerberos] (built with \
             --features kerberos-auth) or TLS with require_client_cert, or set \
             wef.allow_unauthenticated = true"
        ),
        "{msg}"
    );
}

#[tokio::test]
async fn test_malformed_event_in_batch_others_ingested() {
    let h = Harness::start(|t| t).await;
    let url = format!("{}/wsman/subscriptions/{}", h.base, common::TEST_SUB_UUID);
    let (a, b) = (
        common::wef_fixture("security_4672"),
        common::wef_fixture("system_7045"),
    );
    let bad = "<Event><System><Provider>P</Provider></Mismatch></System></Event>";
    let mid = "22222222-0000-4000-8000-000000000001";
    let (st, body, _, _) = h
        .post(
            &url,
            &common::events_envelope(mid, MACHINE, 9, &[&a, bad, &b]),
            true,
        )
        .await;
    assert_eq!(st, 200);
    assert!(
        common::acks(&body, mid),
        "batch must still be acked: {body}"
    );
    let batches = h.finish().await;
    assert_eq!(rows(&batches), 2);
    let mut ids = event_ids(&batches);
    ids.sort_unstable();
    assert_eq!(ids, vec![4672, 7045]);
}
